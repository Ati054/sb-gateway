package policydns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/domainset"
)

const maxDNSMessage = 65535

type managedIngressConfig struct {
	Listeners []managedListenerConfig `json:"listeners"`
	Rules     []managedSourceConfig   `json:"rules"`
}

type managedListenerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type managedSourceConfig struct {
	SourceCIDRs []string `json:"source_cidrs"`
	LaneID      string   `json:"lane_id"`
}

type managedSource struct {
	prefixes []netip.Prefix
	laneID   string
}

type managedIngress struct {
	listeners []managedListenerConfig
	rules     []managedSource
}

type rawConfig struct {
	ManagedIngress    *managedIngressConfig    `json:"managed_ingress"`
	LaneLayoutVersion int                      `json:"lane_layout_version"`
	DomainSets        map[string]domainset.Set `json:"domain_sets"`
	Version           int                      `json:"version"`
	Servers           map[string]serverConfig  `json:"servers"`
	Lanes             []laneConfig             `json:"lanes"`
	TimeoutSeconds    float64                  `json:"timeout_seconds"`
}

type serverConfig struct {
	Type        string `json:"type"`
	Server      string `json:"server"`
	ServerPort  int    `json:"server_port"`
	Path        string `json:"path"`
	ServerName  string `json:"server_name"`
	TunnelHost  string `json:"tunnel_host"`
	TunnelPort  int    `json:"tunnel_port"`
	Detour      string `json:"detour"`
	DoTFallback bool   `json:"dot_fallback"`
}

type laneConfig struct {
	ID    string       `json:"id"`
	Host  string       `json:"host"`
	Port  int          `json:"port"`
	Final string       `json:"final"`
	Rules []ruleConfig `json:"rules"`
}

type ruleConfig struct {
	DomainSet    string   `json:"domain_set"`
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
	Action       string   `json:"action"`
	Server       string   `json:"server"`
}

type ruleDecision struct {
	order  int
	reject bool
	server string
}

type lane struct {
	shared       *domainset.Index
	setDecisions map[uint32]ruleDecision
	id           string
	host         string
	port         int
	final        string
	exact        map[string]ruleDecision
	suffix       map[string]ruleDecision
}

type runtime struct {
	managed       *managedIngress
	servers       map[string]upstream
	lanes         map[string]*lane
	ordered       []*lane
	serverConfigs map[string]serverConfig
	routeProfiles map[string]*routeProfile
	timeout       time.Duration
	cache         *responseCache
	flights       flightGroup
}

func loadRuntime(path string, cacheEntries, cacheBytes int, staleTTL time.Duration) (*runtime, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer file.Close()
	raw, err := decodeRuntimeConfig(file)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if raw.Version < 0 || raw.Version > 2 {
		return nil, errors.New("unsupported policy DNS schema")
	}
	if raw.ManagedIngress != nil && raw.LaneLayoutVersion != 2 {
		return nil, errors.New("managed DNS ingress requires lane layout 2")
	}
	if len(raw.Lanes) == 0 {
		return nil, errNoLanes
	}
	timeout := time.Duration(raw.TimeoutSeconds * float64(time.Second))
	if timeout < time.Second {
		timeout = 5 * time.Second
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	runtime := &runtime{
		servers:       make(map[string]upstream, len(raw.Servers)),
		serverConfigs: raw.Servers,
		lanes:         make(map[string]*lane, len(raw.Lanes)),
		timeout:       timeout,
		cache:         newResponseCache(cacheEntries, cacheBytes, staleTTL),
	}
	for tag, config := range raw.Servers {
		server, err := newUpstream(config, timeout)
		if err != nil {
			runtime.close()
			return nil, fmt.Errorf("server %q: %w", tag, err)
		}
		runtime.servers[tag] = server
	}
	shared, ids, err := domainset.Compile(raw.DomainSets)
	if err != nil {
		runtime.close()
		return nil, err
	}
	for _, rawLane := range raw.Lanes {
		compiled, err := compileLaneWithSets(rawLane, shared, ids)
		if err != nil {
			runtime.close()
			return nil, err
		}
		if _, exists := runtime.lanes[compiled.id]; exists {
			runtime.close()
			return nil, fmt.Errorf("duplicate policy DNS lane %q", compiled.id)
		}
		runtime.lanes[compiled.id] = compiled
		runtime.ordered = append(runtime.ordered, compiled)
	}
	managed, err := compileManagedIngress(raw.ManagedIngress, runtime.lanes)
	if err != nil {
		runtime.close()
		return nil, err
	}
	runtime.managed = managed
	return runtime, nil
}

// ValidateFile parses and compiles the complete policy DNS configuration
// without opening listeners or making network requests.
func ValidateFile(path string, options Options) error {
	candidate, err := loadRuntime(path, options.CacheEntries, options.CacheBytes, options.StaleTTL)
	if err != nil {
		return err
	}
	candidate.close()
	return nil
}

// ProbeListeners checks every configured TCP listener exactly once. The
// candidate was already compiled before publication, so this path decodes only
// the small listener list and does not allocate upstream clients or caches.
func ProbeListeners(ctx context.Context, path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Version           int                   `json:"version"`
		LaneLayoutVersion int                   `json:"lane_layout_version"`
		ManagedIngress    *managedIngressConfig `json:"managed_ingress"`
		Lanes             []struct {
			ID   string `json:"id"`
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"lanes"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	if len(raw.Lanes) == 0 {
		return errNoLanes
	}
	if raw.Version < 0 || raw.Version > 2 || (raw.ManagedIngress != nil && raw.LaneLayoutVersion != 2) {
		return errors.New("unsupported managed DNS listener schema")
	}
	lanes := make(map[string]*lane, len(raw.Lanes))
	for _, value := range raw.Lanes {
		compiled, err := compileLane(laneConfig{ID: value.ID, Host: value.Host, Port: value.Port})
		if err != nil {
			return err
		}
		if lanes[compiled.id] != nil {
			return errors.New("duplicate policy DNS lane")
		}
		lanes[compiled.id] = compiled
	}
	managed, err := compileManagedIngress(raw.ManagedIngress, lanes)
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	for _, lane := range raw.Lanes {
		address := net.JoinHostPort(lane.Host, strconv.Itoa(lane.Port))
		connection, dialErr := dialer.DialContext(ctx, "tcp", address)
		if dialErr != nil {
			return fmt.Errorf("policy DNS lane %q: %w", lane.ID, dialErr)
		}
		_ = connection.Close()
	}
	if managed != nil {
		for _, endpoint := range managed.listeners {
			connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)))
			if err != nil {
				return fmt.Errorf("managed DNS listener: %w", err)
			}
			_ = connection.Close()
		}
	}
	return nil
}

var errNoLanes = errors.New("policy DNS config has no lanes yet")

func compileLane(raw laneConfig) (*lane, error) {
	return compileLaneWithSets(raw, nil, nil)
}

func compileLaneWithSets(raw laneConfig, shared *domainset.Index, ids map[string]uint32) (*lane, error) {
	if raw.ID == "" {
		return nil, errors.New("policy DNS lane has no id")
	}
	if raw.Host != "127.0.0.1" && raw.Host != "::1" {
		return nil, fmt.Errorf("policy DNS lane %q is not loopback", raw.ID)
	}
	if raw.Port < 1024 || raw.Port > 65535 {
		return nil, fmt.Errorf("policy DNS lane %q has unsafe port", raw.ID)
	}
	result := &lane{
		shared:       shared,
		setDecisions: make(map[uint32]ruleDecision),
		id:           raw.ID,
		host:         raw.Host,
		port:         raw.Port,
		final:        raw.Final,
		exact:        make(map[string]ruleDecision),
		suffix:       make(map[string]ruleDecision),
	}
	if result.final == "" {
		result.final = "reject"
	}
	for index, rule := range raw.Rules {
		server := rule.Server
		if server == "" {
			server = "reject"
		}
		decision := ruleDecision{
			order:  index,
			reject: rule.Action == "reject",
			server: server,
		}
		if rule.DomainSet != "" {
			id, exists := ids[rule.DomainSet]
			if !exists {
				return nil, errors.New("DNS rule references a missing shared domain set")
			}
			if _, exists := result.setDecisions[id]; !exists {
				result.setDecisions[id] = decision
			}
		}
		for _, value := range rule.Domain {
			name := strings.ToLower(value)
			if name == "" {
				continue
			}
			if _, exists := result.exact[name]; !exists {
				result.exact[name] = decision
			}
		}
		for _, value := range rule.DomainSuffix {
			suffix := strings.ToLower(strings.Trim(value, "."))
			if suffix == "" {
				continue
			}
			if _, exists := result.suffix[suffix]; !exists {
				result.suffix[suffix] = decision
			}
		}
	}
	return result, nil
}

func (lane *lane) target(name string) (string, bool) {
	decision, found := lane.exact[name]
	for suffix := name; suffix != ""; {
		candidate, exists := lane.suffix[suffix]
		if exists && (!found || candidate.order < decision.order) {
			decision = candidate
			found = true
		}
		separator := strings.IndexByte(suffix, '.')
		if separator < 0 {
			break
		}
		suffix = suffix[separator+1:]
	}
	// Shared membership never owns the server/reject decision of a lane.
	lane.shared.Match(name, func(id uint32) {
		if candidate, exists := lane.setDecisions[id]; exists && (!found || candidate.order < decision.order) {
			decision, found = candidate, true
		}
	})
	if !found {
		return lane.final, lane.final == "reject"
	}
	return decision.server, decision.reject
}

func (runtime *runtime) topology() string {
	values := make([]string, 0, len(runtime.ordered))
	for _, lane := range runtime.ordered {
		values = append(values, fmt.Sprintf("%s|%s|%d", lane.id, lane.host, lane.port))
	}
	if runtime.managed != nil {
		for _, endpoint := range runtime.managed.listeners {
			values = append(values, fmt.Sprintf("managed|%s|%d", endpoint.Host, endpoint.Port))
		}
	}
	sort.Strings(values)
	return strings.Join(values, "\n")
}

func (runtime *runtime) close() {
	for tag, server := range runtime.servers {
		if profile := runtime.routeProfiles[tag]; profile != nil {
			profile.close()
		} else {
			server.close()
		}
	}
}

// Match the compiler's ordered source rules; an unknown source has no default lane.
func compileManagedIngress(raw *managedIngressConfig, lanes map[string]*lane) (*managedIngress, error) {
	occupied := make(map[netip.AddrPort]bool, len(lanes))
	for _, lane := range lanes {
		address, err := netip.ParseAddr(lane.host)
		if err != nil {
			return nil, errors.New("invalid DNS lane endpoint")
		}
		endpoint := netip.AddrPortFrom(address.Unmap(), uint16(lane.port))
		if occupied[endpoint] {
			return nil, errors.New("duplicate DNS lane endpoint")
		}
		occupied[endpoint] = true
	}
	if raw == nil {
		return nil, nil
	}
	if len(raw.Listeners) == 0 {
		return nil, errors.New("managed DNS ingress has no listener")
	}
	result := &managedIngress{listeners: make([]managedListenerConfig, 0, len(raw.Listeners)), rules: make([]managedSource, 0, len(raw.Rules))}
	for _, listener := range raw.Listeners {
		address, err := netip.ParseAddr(listener.Host)
		if err != nil || address.Zone() != "" {
			return nil, errors.New("managed DNS listener requires a literal unicast address")
		}
		address = address.Unmap()
		if !(address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()) || listener.Port < 1024 || listener.Port > 65535 {
			return nil, errors.New("invalid managed DNS listener endpoint")
		}
		endpoint := netip.AddrPortFrom(address, uint16(listener.Port))
		if occupied[endpoint] {
			return nil, errors.New("managed DNS listener collides with another listener")
		}
		occupied[endpoint] = true
		result.listeners = append(result.listeners, managedListenerConfig{Host: address.String(), Port: listener.Port})
	}
	for _, rule := range raw.Rules {
		if lanes[rule.LaneID] == nil || len(rule.SourceCIDRs) == 0 {
			return nil, errors.New("managed DNS source requires known lane and CIDRs")
		}
		compiled := managedSource{laneID: rule.LaneID, prefixes: make([]netip.Prefix, 0, len(rule.SourceCIDRs))}
		for _, text := range rule.SourceCIDRs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, errors.New("invalid managed DNS source CIDR")
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, errors.New("ambiguous mapped managed DNS source CIDR")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			compiled.prefixes = append(compiled.prefixes, prefix.Masked())
		}
		result.rules = append(result.rules, compiled)
	}
	return result, nil
}

func (runtime *runtime) managedLane(address netip.Addr) (string, bool) {
	if runtime.managed == nil || !address.IsValid() {
		return "", false
	}
	address = address.WithZone("").Unmap()
	for _, rule := range runtime.managed.rules {
		for _, prefix := range rule.prefixes {
			if prefix.Contains(address) {
				return rule.laneID, true
			}
		}
	}
	return "", false
}

func managedPeer(address net.Addr) netip.Addr {
	switch peer := address.(type) {
	case *net.UDPAddr:
		if peer != nil {
			return peer.AddrPort().Addr().Unmap()
		}
	case *net.TCPAddr:
		if peer != nil {
			return peer.AddrPort().Addr().Unmap()
		}
	}
	return netip.Addr{}
}
