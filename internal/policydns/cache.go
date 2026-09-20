package policydns

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

type cacheEntry struct {
	key      string
	response []byte
	weight   int
	stored   time.Time
	expires  time.Time
	staleAt  time.Time
}

type responseCache struct {
	mu        sync.Mutex
	limit     int
	byteLimit int
	used      int
	staleTTL  time.Duration
	entries   map[string]*list.Element
	order     *list.List
}

func newResponseCache(limit, byteLimit int, staleTTL time.Duration) *responseCache {
	return &responseCache{
		limit:     limit,
		byteLimit: byteLimit,
		staleTTL:  staleTTL,
		entries:   make(map[string]*list.Element, limit),
		order:     list.New(),
	}
}

func (cache *responseCache) get(key string, queryID []byte, now time.Time) ([]byte, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.entries[key]
	if element == nil {
		return nil, false
	}
	entry := element.Value.(*cacheEntry)
	if !now.Before(entry.expires) {
		if !now.Before(entry.staleAt) {
			cache.used -= entry.weight
			cache.order.Remove(element)
			delete(cache.entries, key)
		}
		return nil, false
	}
	cache.order.MoveToFront(element)
	return cachedResponse(entry.response, queryID, now.Sub(entry.stored), 0), true
}

func (cache *responseCache) getStale(key string, queryID []byte, now time.Time) ([]byte, bool) {
	if cache.staleTTL <= 0 {
		return nil, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.entries[key]
	if element == nil {
		return nil, false
	}
	entry := element.Value.(*cacheEntry)
	if now.Before(entry.expires) || !now.Before(entry.staleAt) {
		return nil, false
	}
	cache.order.MoveToFront(element)
	return cachedResponse(entry.response, queryID, 0, 30), true
}

// putOwned stores response without copying it.  The caller transfers ownership
// and must not mutate the slice afterwards.
func (cache *responseCache) putOwned(key string, response []byte, ttl time.Duration, now time.Time) {
	const approximateEntryOverhead = 128
	weight := approximateEntryOverhead + len(key) + len(response)
	if cache.limit <= 0 || cache.byteLimit <= 0 || weight > cache.byteLimit || ttl <= 0 || len(response) < 2 {
		return
	}
	response[0], response[1] = 0, 0
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if existing := cache.entries[key]; existing != nil {
		entry := existing.Value.(*cacheEntry)
		cache.used -= entry.weight
		entry.response = response
		entry.weight = weight
		entry.stored = now
		entry.expires = now.Add(ttl)
		entry.staleAt = now.Add(ttl + cache.staleTTL)
		cache.used += weight
		cache.order.MoveToFront(existing)
	} else {
		element := cache.order.PushFront(&cacheEntry{
			key: key, response: response, weight: weight, stored: now, expires: now.Add(ttl), staleAt: now.Add(ttl + cache.staleTTL),
		})
		cache.entries[key] = element
		cache.used += weight
	}
	for cache.order.Len() > cache.limit || cache.used > cache.byteLimit {
		oldest := cache.order.Back()
		entry := oldest.Value.(*cacheEntry)
		cache.used -= entry.weight
		delete(cache.entries, entry.key)
		cache.order.Remove(oldest)
	}
}

func cachedResponse(response []byte, queryID []byte, age time.Duration, overrideTTL uint32) []byte {
	result := responseWithID(response, queryID)
	adjustResponseTTLs(result, uint32(age/time.Second), overrideTTL)
	return result
}

type flight struct {
	done     chan struct{}
	response []byte
	err      error
}

type flightGroup struct {
	mu      sync.Mutex
	flights map[string]*flight
}

func (group *flightGroup) do(
	ctx context.Context,
	key string,
	resolve func() ([]byte, error),
) ([]byte, error) {
	group.mu.Lock()
	if group.flights == nil {
		group.flights = make(map[string]*flight)
	}
	if active := group.flights[key]; active != nil {
		group.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-active.done:
			return active.response, active.err
		}
	}
	active := &flight{done: make(chan struct{})}
	group.flights[key] = active
	group.mu.Unlock()

	active.response, active.err = resolve()
	group.mu.Lock()
	delete(group.flights, key)
	close(active.done)
	group.mu.Unlock()
	return active.response, active.err
}

func normalizedQueryKey(laneID string, query []byte) (string, error) {
	if len(query) < 12 {
		return "", errors.New("short DNS query")
	}
	key := make([]byte, len(laneID)+1+len(query))
	copy(key, laneID)
	copy(key[len(laneID)+1:], query)
	key[len(laneID)+1], key[len(laneID)+2] = 0, 0
	return string(key), nil
}

func responseWithID(response []byte, queryID []byte) []byte {
	result := append([]byte(nil), response...)
	if len(result) >= 2 && len(queryID) >= 2 {
		copy(result[:2], queryID[:2])
	}
	return result
}

func responseTTL(message []byte) time.Duration {
	if len(message) < 12 {
		return 0
	}
	rcode := binary.BigEndian.Uint16(message[2:4]) & 0x000f
	if rcode != 0 && rcode != 3 {
		return 0
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	authorities := int(binary.BigEndian.Uint16(message[8:10]))
	additionals := int(binary.BigEndian.Uint16(message[10:12]))
	offset := 12
	for index := 0; index < questions; index++ {
		next, ok := skipName(message, offset)
		if !ok || next+4 > len(message) {
			return 0
		}
		offset = next + 4
	}
	minimum, offset, ok := minimumRecordTTL(message, offset, answers, false)
	if !ok {
		return 0
	}
	if answers == 0 {
		minimum, offset, ok = minimumRecordTTL(message, offset, authorities, true)
		if !ok {
			return 0
		}
		// Negative responses are deliberately shorter-lived than successful
		// answers so policy and upstream changes converge quickly.
		if minimum > 60 {
			minimum = 60
		}
	} else {
		_, offset, ok = minimumRecordTTL(message, offset, authorities, false)
		if !ok {
			return 0
		}
	}
	if _, _, ok = minimumRecordTTL(message, offset, additionals, false); !ok {
		return 0
	}
	if minimum == 0 {
		return 0
	}
	if minimum > 300 {
		minimum = 300
	}
	return time.Duration(minimum) * time.Second
}

func minimumRecordTTL(message []byte, offset, records int, negativeSOA bool) (uint32, int, bool) {
	var minimum uint32
	found := false
	for index := 0; index < records; index++ {
		next, ok := skipName(message, offset)
		if !ok || next+10 > len(message) {
			return 0, 0, false
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
		size := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		dataStart := next + 10
		offset = dataStart + size
		if offset > len(message) {
			return 0, 0, false
		}
		if recordType == 41 { // OPT stores flags, not a resource-record TTL.
			continue
		}
		if negativeSOA && recordType != 6 {
			continue
		}
		if negativeSOA && size < 20 {
			continue
		}
		if negativeSOA {
			soaMinimum := binary.BigEndian.Uint32(message[offset-4 : offset])
			if soaMinimum < ttl {
				ttl = soaMinimum
			}
		}
		if !found || ttl < minimum {
			minimum = ttl
			found = true
		}
	}
	return minimum, offset, true
}

func adjustResponseTTLs(message []byte, age, override uint32) {
	if len(message) < 12 {
		return
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	records := int(binary.BigEndian.Uint16(message[6:8])) + int(binary.BigEndian.Uint16(message[8:10])) + int(binary.BigEndian.Uint16(message[10:12]))
	offset := 12
	for index := 0; index < questions; index++ {
		next, ok := skipName(message, offset)
		if !ok || next+4 > len(message) {
			return
		}
		offset = next + 4
	}
	for index := 0; index < records; index++ {
		next, ok := skipName(message, offset)
		if !ok || next+10 > len(message) {
			return
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		ttlOffset := next + 4
		size := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		offset = next + 10 + size
		if offset > len(message) {
			return
		}
		if recordType == 41 {
			continue
		}
		ttl := binary.BigEndian.Uint32(message[ttlOffset : ttlOffset+4])
		if override > 0 {
			ttl = override
		} else if age >= ttl {
			ttl = 0
		} else {
			ttl -= age
		}
		binary.BigEndian.PutUint32(message[ttlOffset:ttlOffset+4], ttl)
	}
}

func skipName(message []byte, offset int) (int, bool) {
	for {
		if offset >= len(message) {
			return 0, false
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			return offset, true
		}
		if length&0xC0 == 0xC0 {
			if offset >= len(message) {
				return 0, false
			}
			return offset + 1, true
		}
		if length > 63 || offset+length > len(message) {
			return 0, false
		}
		offset += length
	}
}
