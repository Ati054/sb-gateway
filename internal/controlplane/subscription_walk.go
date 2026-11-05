package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type subscriptionWalkOptions struct {
	MaxNodes      int // Zero means no count quota; positive quotas count supported URI lines.
	MaxBytes      int // Bounds both encoded input and decoded text; at most 8 MiB.
	MaxLineBytes  int // Explicit single-link resource protection, independent of count.
	MaxIndexBytes int // Bounds pointer-free identity and used-ID backing arrays.
}

type subscriptionWalkStats struct {
	SupportedLines int
	ValidNodes     int
	SkippedNodes   int
	EmittedNodes   int
	DecodedBytes   int
}

type subscriptionSource struct {
	body     []byte
	encoding *base64.Encoding
}

func (source subscriptionSource) reader(ctx context.Context) io.Reader {
	var reader io.Reader = subscriptionContextReader{ctx: ctx, reader: bytes.NewReader(source.body)}
	if source.encoding != nil {
		reader = base64.NewDecoder(source.encoding, &subscriptionWhitespaceReader{reader: reader})
	}
	return subscriptionContextReader{ctx: ctx, reader: reader}
}

type subscriptionContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader subscriptionContextReader) Read(p []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(p)
}

// Match the legacy base64 whitespace handling without compacting the full body.
type subscriptionWhitespaceReader struct{ reader io.Reader }

func (reader *subscriptionWhitespaceReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := reader.reader.Read(p)
		out := 0
		for _, value := range p[:n] {
			if value != ' ' && value != '\t' && value != '\r' && value != '\n' {
				p[out] = value
				out++
			}
		}
		if out > 0 || err != nil {
			return out, err
		}
	}
}

func subscriptionResourceError() error {
	return &subscriptionParseError{code: "too_large", message: "Subscription exceeds a resource limit."}
}

func subscriptionContentError() error {
	return &subscriptionParseError{code: "invalid_content", message: "Subscription is empty, invalid UTF-8, or invalid base64 text."}
}

func asciiSchemeAt(body []byte, offset int, scheme string) bool {
	if len(body)-offset < len(scheme) {
		return false
	}
	for index := range scheme {
		value := body[offset+index]
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		if value != scheme[index] {
			return false
		}
	}
	return true
}

func subscriptionPlainText(body []byte) bool {
	for index, value := range body {
		if (value == 'v' || value == 'V') && asciiSchemeAt(body, index, "vless://") {
			return true
		}
		if (value == 'h' || value == 'H') && (asciiSchemeAt(body, index, "hy2://") || asciiSchemeAt(body, index, "hysteria2://")) {
			return true
		}
	}
	return false
}

// Validate the complete decoded tail before allowing any publication callback.
func subscriptionDecodedSize(ctx context.Context, source subscriptionSource, maximum int) (int, error) {
	reader := source.reader(ctx)
	var buffer [16<<10 + utf8.UTFMax]byte
	carry, total := 0, 0
	for {
		n, err := reader.Read(buffer[carry : len(buffer)-utf8.UTFMax])
		total += n
		if total > maximum {
			return 0, subscriptionResourceError()
		}
		end := carry + n
		position := 0
		for position < end {
			if !utf8.FullRune(buffer[position:end]) {
				break
			}
			value, size := utf8.DecodeRune(buffer[position:end])
			if value == utf8.RuneError && size == 1 {
				return 0, subscriptionContentError()
			}
			position += size
		}
		carry = copy(buffer[:], buffer[position:end])
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if !errors.Is(err, io.EOF) || carry != 0 {
				return 0, subscriptionContentError()
			}
			return total, nil
		}
	}
}

func prepareSubscriptionSource(ctx context.Context, body []byte, maximum int) (subscriptionSource, int, error) {
	if err := ctx.Err(); err != nil {
		return subscriptionSource{}, 0, err
	}
	if len(body) > maximum {
		return subscriptionSource{}, 0, subscriptionResourceError()
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || !utf8.Valid(body) {
		return subscriptionSource{}, 0, subscriptionContentError()
	}
	source := subscriptionSource{body: body}
	if subscriptionPlainText(body) {
		return source, len(body), ctx.Err()
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		source.encoding = encoding
		size, err := subscriptionDecodedSize(ctx, source, maximum)
		if err == nil {
			return source, size, nil
		}
		if ctx.Err() != nil {
			return subscriptionSource{}, 0, ctx.Err()
		}
	}
	return subscriptionSource{}, 0, subscriptionContentError()
}

func splitSubscriptionLine(body []byte, atEOF bool) (int, []byte, error) {
	if index := bytes.IndexAny(body, "\r\n"); index >= 0 {
		return index + 1, body[:index], nil
	}
	if atEOF && len(body) > 0 {
		return len(body), body, nil
	}
	return 0, nil, nil
}

func walkSubscriptionLines(ctx context.Context, source subscriptionSource, lineMaximum int, visit func(string, int) error) error {
	scanner := bufio.NewScanner(source.reader(ctx))
	scanner.Buffer(make([]byte, min(4096, lineMaximum+2)), lineMaximum+2)
	scanner.Split(splitSubscriptionLine)
	ordinal := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(scanner.Bytes()) > lineMaximum {
			return subscriptionResourceError()
		}
		link := strings.TrimSpace(string(scanner.Bytes()))
		if !strings.EqualFold(subscriptionPrefix(link, 8), "vless://") && !strings.EqualFold(subscriptionPrefix(link, 6), "hy2://") && !strings.EqualFold(subscriptionPrefix(link, 12), "hysteria2://") {
			continue
		}
		ordinal++
		if err := visit(link, ordinal); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return subscriptionResourceError()
		}
		return subscriptionContentError()
	}
	return nil
}

func subscriptionPrefix(value string, length int) string { return value[:min(len(value), length)] }

func parseSubscriptionLine(link string, ordinal int) (map[string]any, error) {
	if strings.EqualFold(subscriptionPrefix(link, 8), "vless://") {
		return parseSubscriptionVLESSLink(link, ordinal)
	}
	return parseSubscriptionHysteria2Link(link, ordinal)
}

type subscriptionIdentityKey [12]byte

func subscriptionNodeIdentityKey(node map[string]any) subscriptionIdentityKey {
	var key subscriptionIdentityKey
	_, _ = hex.Decode(key[:], []byte(stableSubscriptionIdentity(node)))
	return key
}

// In-place heapsort gives cancellation a bounded check point without a second
// all-record backing array or panic-based cancellation from a sort comparator.
func sortSubscriptionIdentities(ctx context.Context, keys []subscriptionIdentityKey) error {
	sift := func(root, end int) error {
		for root*2+1 < end {
			if err := ctx.Err(); err != nil {
				return err
			}
			child := root*2 + 1
			if child+1 < end && bytes.Compare(keys[child][:], keys[child+1][:]) < 0 {
				child++
			}
			if bytes.Compare(keys[root][:], keys[child][:]) >= 0 {
				break
			}
			keys[root], keys[child] = keys[child], keys[root]
			root = child
		}
		return nil
	}
	for root := len(keys)/2 - 1; root >= 0; root-- {
		if err := sift(root, len(keys)); err != nil {
			return err
		}
	}
	for end := len(keys) - 1; end > 0; end-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		keys[0], keys[end] = keys[end], keys[0]
		if err := sift(0, end); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func repeatedSubscriptionIdentity(keys []subscriptionIdentityKey, key subscriptionIdentityKey) bool {
	low, high := 0, len(keys)
	for low < high {
		middle := low + (high-low)/2
		if bytes.Compare(keys[middle][:], key[:]) < 0 {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low+1 < len(keys) && keys[low] == key && keys[low+1] == key
}

type subscriptionIDSlot struct {
	key  [32]byte
	next uint32 // Zero is empty; otherwise the next legacy duplicate suffix.
}

type subscriptionIDRegistry []subscriptionIDSlot

func (registry subscriptionIDRegistry) slot(key [32]byte) *subscriptionIDSlot {
	position := (uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24) & uint64(len(registry)-1)
	for {
		entry := &registry[position]
		if entry.next == 0 || entry.key == key {
			return entry
		}
		position = (position + 1) & uint64(len(registry)-1)
	}
}

func (registry subscriptionIDRegistry) assign(ctx context.Context, base string) (string, error) {
	baseKey := sha256.Sum256([]byte(base))
	entry := registry.slot(baseKey)
	if entry.next == 0 {
		entry.key, entry.next = baseKey, 2
		return base, nil
	}
	for suffix := entry.next; ; suffix++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		candidate := base + "-" + strconv.FormatUint(uint64(suffix), 10)
		key := sha256.Sum256([]byte(candidate))
		occupied := registry.slot(key)
		if occupied.next == 0 {
			occupied.key, occupied.next = key, 2
			entry.next = suffix + 1
			return candidate, nil
		}
	}
}

// walkProxySubscription retains only bounded fixed-hash indexes between passes.
// body must remain immutable. emit owns each node map; the parser does not retain
// it. A callback failure/cancellation may follow earlier callbacks: callers must
// abort their unpublished staging generation, never publish the partial stream.
func walkProxySubscription(ctx context.Context, body []byte, options subscriptionWalkOptions, emit func(map[string]any) error) (subscriptionWalkStats, error) {
	var stats subscriptionWalkStats
	if options.MaxBytes == 0 {
		options.MaxBytes = defaultSubscriptionBytes
	}
	if options.MaxLineBytes == 0 {
		options.MaxLineBytes = options.MaxBytes
	}
	if options.MaxIndexBytes == 0 {
		options.MaxIndexBytes = 64 << 20
	}
	if options.MaxNodes < 0 || options.MaxBytes < 1 || options.MaxBytes > defaultSubscriptionBytes || options.MaxLineBytes < 1 || options.MaxLineBytes > options.MaxBytes || options.MaxIndexBytes < 1 || emit == nil {
		return stats, &subscriptionParseError{code: "invalid_limit", message: "Subscription parser limits are invalid."}
	}
	source, size, err := prepareSubscriptionSource(ctx, body, options.MaxBytes)
	if err != nil {
		return stats, err
	}
	stats.DecodedBytes = size
	// Every accepted line contains a supported scheme of at least six bytes.
	capacity := size/6 + 1
	if options.MaxNodes > 0 {
		capacity = min(capacity, options.MaxNodes)
	}
	indexBytes := int64(capacity) * 12
	if indexBytes > int64(options.MaxIndexBytes) {
		return stats, subscriptionResourceError()
	}
	keys := make([]subscriptionIdentityKey, 0, capacity)
	var firstError error
	err = walkSubscriptionLines(ctx, source, options.MaxLineBytes, func(link string, ordinal int) error {
		stats.SupportedLines = ordinal
		if options.MaxNodes > 0 && ordinal > options.MaxNodes {
			return &subscriptionParseError{code: "too_many_nodes", message: "Subscription contains too many nodes."}
		}
		node, err := parseSubscriptionLine(link, ordinal)
		if err != nil {
			stats.SkippedNodes++
			if firstError == nil {
				firstError = err
			}
			return nil
		}
		if len(keys) == cap(keys) {
			return subscriptionResourceError()
		}
		keys = append(keys, subscriptionNodeIdentityKey(node))
		stats.ValidNodes++
		return nil
	})
	if err != nil {
		return stats, err
	}
	if stats.ValidNodes == 0 {
		if firstError != nil {
			return stats, firstError
		}
		return stats, &subscriptionParseError{code: "unsupported_nodes", message: "Subscription contains no supported proxy nodes."}
	}
	if err := sortSubscriptionIdentities(ctx, keys); err != nil {
		return stats, err
	}
	registrySize := 2
	for int64(stats.ValidNodes)*8 > int64(registrySize)*7 {
		registrySize *= 2
	}
	// The slot is exactly a 32-byte hash and a uint32 counter (no pointers).
	if indexBytes+int64(registrySize)*36 > int64(options.MaxIndexBytes) {
		return stats, subscriptionResourceError()
	}
	used := make(subscriptionIDRegistry, registrySize)
	err = walkSubscriptionLines(ctx, source, options.MaxLineBytes, func(link string, ordinal int) error {
		node, err := parseSubscriptionLine(link, ordinal)
		if err != nil {
			return nil // First pass already recorded legacy invalid-line semantics.
		}
		if repeatedSubscriptionIdentity(keys, subscriptionNodeIdentityKey(node)) {
			body, _ := canonicalJSON([]any{node["_uuid"], node["_password"], node["_obfs_password"]})
			digest := sha256.Sum256(body)
			node["credential_identity"] = hex.EncodeToString(digest[:])[:24]
			setSubscriptionNodeID(node, 0)
		}
		id, err := used.assign(ctx, fmt.Sprint(node["id"]))
		if err != nil {
			return err
		}
		node["id"] = id
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(node); err != nil {
			return err
		}
		stats.EmittedNodes++
		return nil
	})
	return stats, err
}
