package policydns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxDNSMessage = 65535

type rawConfig struct {
	Version        int                     `json:"version"`
	Servers        map[string]serverConfig `json:"servers"`
	Lanes          []laneConfig            `json:"lanes"`
	TimeoutSeconds float64                 `json:"timeout_seconds"`
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
	id     string
	host   string
	port   int
	final  string
	exact  map[string]ruleDecision
	suffix map[string]ruleDecision
}

type runtime struct {
	servers map[string]upstream
	lanes   map[string]*lane
	ordered []*lane
	timeout time.Duration
	cache   *responseCache
	flights flightGroup
}

func loadRuntime(path string, cacheEntries, cacheBytes int, staleTTL time.Duration) (*runtime, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var raw rawConfig
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
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
		servers: make(map[string]upstream, len(raw.Servers)),
		lanes:   make(map[string]*lane, len(raw.Lanes)),
		timeout: timeout,
		cache:   newResponseCache(cacheEntries, cacheBytes, staleTTL),
	}
	for tag, config := range raw.Servers {
		server, err := newUpstream(config, timeout)
		if err != nil {
			runtime.close()
			return nil, fmt.Errorf("server %q: %w", tag, err)
		}
		runtime.servers[tag] = server
	}
	for _, rawLane := range raw.Lanes {
		compiled, err := compileLane(rawLane)
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
	var raw rawConfig
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	if len(raw.Lanes) == 0 {
		return errNoLanes
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
	return nil
}

var errNoLanes = errors.New("policy DNS config has no lanes yet")

func compileLane(raw laneConfig) (*lane, error) {
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
		id:     raw.ID,
		host:   raw.Host,
		port:   raw.Port,
		final:  raw.Final,
		exact:  make(map[string]ruleDecision),
		suffix: make(map[string]ruleDecision),
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
	sort.Strings(values)
	return strings.Join(values, "\n")
}

func (runtime *runtime) close() {
	for _, server := range runtime.servers {
		server.close()
	}
}
