// geoipbench compares isolated real-core GeoIP configurations. It never connects
// to a gateway API: all listeners, destinations and API calls use loopback.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
	"github.com/sb-gateway/sb-gateway/internal/geoiprefresh"
	"google.golang.org/protobuf/encoding/protowire"
)

type metrics struct {
	Phase        string `json:"phase"`
	Milliseconds int64  `json:"milliseconds"`
	CoreRSS      int64  `json:"core_peak_rss_bytes"`
	XrayRSS      int64  `json:"xray_processes_peak_rss_bytes"`
	Cgroup       int64  `json:"cgroup_peak_bytes"`
}
type result struct {
	Mode               string      `json:"mode"`
	Rules              int         `json:"rules"`
	Prefixes           int         `json:"prefixes"`
	InputSHA           string      `json:"input_sha256"`
	CoreSHA            string      `json:"xray_sha256"`
	JSONBytes          int         `json:"config_bytes"`
	DatBytes           int         `json:"database_bytes"`
	Runs               [][]metrics `json:"runs"`
	ContinuityRequests int         `json:"continuity_requests"`
	Failure            string      `json:"failure,omitempty"`
}

func main() {
	mode := flag.String("mode", "inline", "inline, binary or managed (production publication/activation/cleanup)")
	root := flag.String("root", "/bench", "isolated fixture directory")
	binary := flag.String("xray", "/usr/local/bin/xray", "pinned executable")
	rules := flag.Int("rules", 5, "number of source-specific rules")
	repeat := flag.Int("repeat", 3, "fresh-core repetitions")
	flag.Parse()
	if (*mode != "inline" && *mode != "binary" && *mode != "managed") || *rules < 1 || *rules > 32 || *repeat < 1 || *repeat > 10 {
		panic("invalid benchmark arguments")
	}
	r := result{Mode: *mode, Rules: *rules}
	if err := benchmark(*root, *binary, *repeat, &r); err != nil {
		r.Failure = err.Error()
	}
	output, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		panic(err)
	}
	name := filepath.Join(*root, fmt.Sprintf("result-%s-%d.json", *mode, *rules))
	if err := os.WriteFile(name, output, 0600); err != nil {
		panic(err)
	}
	fmt.Println(string(output))
	if r.Failure != "" {
		os.Exit(1)
	}
}

func benchmark(root, binary string, repeat int, r *result) error {
	body, err := os.ReadFile(filepath.Join(root, "geoip-ru.json"))
	if err != nil {
		return err
	}
	inputHash := sha256.Sum256(body)
	r.InputSHA = hex.EncodeToString(inputHash[:])
	coreHash, err := fileSHA256(binary)
	if err != nil {
		return err
	}
	r.CoreSHA = coreHash
	var pack struct {
		Rules []struct {
			CIDRs []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &pack); err != nil {
		return err
	}
	if len(pack.Rules) != 1 || len(pack.Rules[0].CIDRs) == 0 {
		return fmt.Errorf("expected one public GeoIP CIDR list")
	}
	base := pack.Rules[0].CIDRs
	for _, s := range base {
		if _, err := netip.ParsePrefix(s); err != nil {
			return err
		}
	}
	r.Prefixes = len(base)
	a := append(append([]string(nil), base...), "198.18.0.1/32")
	b := append(append([]string(nil), base...), "198.18.0.2/32")
	for _, version := range []struct {
		name  string
		cidrs []string
	}{{"a", a}, {"b", b}} {
		dat, err := encodeGeoIP(version.cidrs)
		if err != nil {
			return err
		}
		r.DatBytes = len(dat)
		if err := os.WriteFile(filepath.Join(root, "geo-"+version.name+".dat"), dat, 0600); err != nil {
			return err
		}
	}
	match, err := echoMarker('M')
	if err != nil {
		return err
	}
	defer match.Close()
	miss, err := echoMarker('N')
	if err != nil {
		return err
	}
	defer miss.Close()
	for i := 0; i < repeat; i++ {
		api, err := freePort()
		if err != nil {
			return err
		}
		ports := make([]int, r.Rules)
		for j := range ports {
			ports[j], err = freePort()
			if err != nil {
				return err
			}
		}
		config := func(version string, cidrs []string) map[string]any {
			ips := cidrs
			if r.Mode == "binary" {
				ips = []string{"ext:geo-" + version + ".dat:ru"}
			}
			if r.Mode == "managed" && version != "bad" {
				pack, _ := json.Marshal(map[string]any{"version": 3, "rules": []any{map[string]any{"ip_cidr": cidrs}}})
				reference, err := geoipasset.Publish(root, "geoip-ru", pack)
				if err != nil {
					panic(err)
				}
				ips = []string{reference}
			}
			inbounds := []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": api, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}}
			routing := []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api", "ruleTag": "api"}}
			for j, p := range ports {
				tag := fmt.Sprintf("probe-%d", j)
				inbounds = append(inbounds, map[string]any{"tag": tag, "listen": "127.0.0.1", "port": p, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}})
				ruleTag := tag
				if r.Mode == "managed" {
					ruleTag = fmt.Sprintf("sb-geoip-geoip-ru-1-%d", j)
				}
				routing = append(routing, map[string]any{"type": "field", "inboundTag": []string{tag}, "source": []string{"127.0.0.1/32"}, "ip": ips, "outboundTag": "match", "ruleTag": ruleTag})
			}
			routing = append(routing, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "miss", "ruleTag": "default"})
			return map[string]any{"log": map[string]any{"loglevel": "none"}, "api": map[string]any{"tag": "api", "services": []string{"RoutingService"}}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"bufferSize": 128}}}, "inbounds": inbounds, "outbounds": []any{map[string]any{"tag": "match", "protocol": "freedom", "settings": map[string]any{"redirect": match.Addr().String()}}, map[string]any{"tag": "miss", "protocol": "freedom", "settings": map[string]any{"redirect": miss.Addr().String()}}}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": routing}}
		}
		paths := map[string]string{}
		for _, item := range []struct {
			name  string
			cidrs []string
		}{{"a", a}, {"b", b}, {"bad", []string{"not-a-prefix"}}} {
			v := config(item.name, item.cidrs)
			encoded, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err
			}
			if item.name == "a" {
				r.JSONBytes = len(encoded)
			}
			path := filepath.Join(root, fmt.Sprintf("%s-%d-%d-%s.json", r.Mode, r.Rules, i, item.name))
			paths[item.name] = path
			if err := os.WriteFile(path, encoded, 0600); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		var managed *managedRun
		if r.Mode == "managed" {
			managed = &managedRun{root: root, a: a, b: b}
		}
		rows, count, err := runCore(ctx, binary, paths, api, ports[len(ports)-1], managed)
		cancel()
		r.Runs = append(r.Runs, rows)
		r.ContinuityRequests += count
		if err != nil {
			return err
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type managedRun struct {
	root  string
	a, b  []string
	extra string
}

func runCore(ctx context.Context, binary string, paths map[string]string, api, socks int, managed *managedRun) ([]metrics, int, error) {
	var rows []metrics
	measure := func(phase string, pid int, fn func() error) error {
		m, err := sample(phase, pid, fn)
		rows = append(rows, m)
		return err
	}
	command := func(args ...string) error {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "GOGC=150", "GOMEMLIMIT=192MiB", "XRAY_LOCATION_ASSET="+filepath.Dir(paths["a"]))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("xray %s: %w: %.1200s", args[0], err, out)
		}
		return nil
	}
	if err := measure("check", 0, func() error { return command("run", "-test", "-config", paths["a"]) }); err != nil {
		return rows, 0, err
	}
	process := exec.CommandContext(ctx, binary, "run", "-config", paths["a"])
	process.Env = append(os.Environ(), "GOGC=150", "GOMEMLIMIT=192MiB", "XRAY_LOCATION_ASSET="+filepath.Dir(paths["a"]))
	logFile, err := os.Create(paths["a"] + ".log")
	if err != nil {
		return rows, 0, err
	}
	defer logFile.Close()
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		return rows, 0, err
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	pid := process.Process.Pid
	probe := func(address string, want byte) error {
		conn, err := socksDial(socks, address)
		if err != nil {
			return err
		}
		defer conn.Close()
		return marker(conn, want)
	}
	if err := measure("startup", pid, func() error {
		for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if err := probe("198.18.0.1", 'M'); err == nil {
				return nil
			}
		}
		return fmt.Errorf("startup routing not ready")
	}); err != nil {
		return rows, 0, err
	}
	if err := probe("198.18.0.2", 'N'); err != nil {
		return rows, 0, err
	}
	stable, err := socksDial(socks, "198.18.0.1")
	if err != nil {
		return rows, 0, err
	}
	defer stable.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	var continuityErr error
	var count atomic.Int64
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := marker(stable, 'M'); err != nil {
				continuityErr = err
				return
			}
			count.Add(1)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	var once sync.Once
	join := func() { once.Do(func() { close(stop); <-done }) }
	defer join()
	apply := func(version string) error {
		return command("api", "adrules", "-s=127.0.0.1:"+strconv.Itoa(api), "-t=300", paths[version])
	}
	var options geoiprefresh.Options
	state := &geoiprefresh.State{}
	if managed != nil {
		ready := filepath.Join(managed.root, "managed-ready")
		if err := os.WriteFile(ready, []byte(strconv.Itoa(pid)), 0600); err != nil {
			return rows, 0, err
		}
		options = geoiprefresh.Options{XrayConfig: paths["a"], RulesetDir: managed.root, ReadyFile: ready, XrayBinary: binary, APIServer: "127.0.0.1:" + strconv.Itoa(api), CandidateDir: filepath.Join(managed.root, "candidates")}
		apply = func(version string) error {
			prefixes := managed.a
			if version == "b" {
				prefixes = managed.b
				if managed.extra != "" {
					prefixes = append(append([]string(nil), prefixes...), managed.extra)
				}
			}
			if version == "bad" {
				prefixes = []string{"not-a-prefix"}
			}
			pack, _ := json.Marshal(map[string]any{"version": 3, "rules": []any{map[string]any{"ip_cidr": prefixes}}})
			if err := os.WriteFile(filepath.Join(managed.root, "geoip-ru.json"), pack, 0600); err != nil {
				return err
			}
			_, err := geoiprefresh.Activate(ctx, options, state)
			return err
		}
	}
	for _, stage := range []struct {
		phase, version string
		a, b           byte
	}{{"reload-b", "b", 'N', 'M'}, {"rollback-a", "a", 'M', 'N'}} {
		if err := measure(stage.phase, pid, func() error { return apply(stage.version) }); err != nil {
			return rows, int(count.Load()), err
		}
		if err := probe("198.18.0.1", stage.a); err != nil {
			return rows, int(count.Load()), fmt.Errorf("%s A: %w", stage.phase, err)
		}
		if err := probe("198.18.0.2", stage.b); err != nil {
			return rows, int(count.Load()), fmt.Errorf("%s B: %w", stage.phase, err)
		}
		if managed != nil && stage.version == "b" {
			if err := measure("eight-unique-generations-and-cleanup", pid, func() error {
				for generation := 1; generation <= 8; generation++ {
					managed.extra = fmt.Sprintf("198.18.1.%d/32", generation)
					if err := apply("b"); err != nil {
						return err
					}
					if err := probe(strings.TrimSuffix(managed.extra, "/32"), 'M'); err != nil {
						return err
					}
					ref, err := geoipasset.Ensure(managed.root, "geoip-ru")
					if err != nil {
						return err
					}
					entries, err := os.ReadDir(managed.root)
					if err != nil {
						return err
					}
					old := time.Now().Add(-time.Hour)
					for _, entry := range entries {
						if geoipasset.IsManagedName(entry.Name()) {
							if err := os.Chtimes(filepath.Join(managed.root, entry.Name()), old, old); err != nil {
								return err
							}
						}
					}
					live, _ := json.Marshal(map[string]any{"ip": []string{ref}})
					if _, err := geoipasset.Prune(managed.root, []string{paths["a"]}, nil, live, time.Now()); err != nil {
						return err
					}
					entries, err = os.ReadDir(managed.root)
					if err != nil {
						return err
					}
					count := 0
					for _, entry := range entries {
						if geoipasset.IsManagedName(entry.Name()) {
							count++
						}
					}
					if count != 2 {
						return fmt.Errorf("GeoIP assets accumulated: %d", count)
					}
				}
				return nil
			}); err != nil {
				return rows, int(count.Load()), err
			}
			if err := measure("readback-failure-rollback-b", pid, func() error {
				options.Run = func(call context.Context, executable string, args ...string) ([]byte, error) {
					if len(args) > 1 && args[1] == "lsrules" {
						return []byte(`{"rules":[]}`), nil
					}
					cmd := exec.CommandContext(call, executable, args...)
					cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+managed.root, "GOGC=150", "GOMEMLIMIT=192MiB")
					return cmd.CombinedOutput()
				}
				err := apply("a")
				options.Run = nil
				if err == nil {
					return fmt.Errorf("bad readback accepted")
				}
				if err := probe("198.18.0.1", 'N'); err != nil {
					return err
				}
				if err := probe("198.18.0.2", 'M'); err != nil {
					return err
				}
				return probe(strings.TrimSuffix(managed.extra, "/32"), 'M')
			}); err != nil {
				return rows, int(count.Load()), err
			}
		}
	}
	if err := measure("bad-candidate", pid, func() error {
		if err := apply("bad"); err == nil {
			return fmt.Errorf("bad candidate accepted")
		}
		return nil
	}); err != nil {
		return rows, int(count.Load()), err
	}
	if err := probe("198.18.0.1", 'M'); err != nil {
		return rows, int(count.Load()), fmt.Errorf("bad candidate changed live routing: %w", err)
	}
	if managed != nil {
		if err := measure("obsolete-assets-cleanup", pid, func() error {
			orphan, err := geoipasset.Publish(managed.root, "geoip-ru", []byte(`{"rules":[{"ip_cidr":["198.18.0.3/32"]}]}`))
			if err != nil {
				return err
			}
			name, _ := geoipasset.ReferenceName(orphan)
			old := time.Now().Add(-time.Hour)
			entries, err := os.ReadDir(managed.root)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if geoipasset.IsManagedName(entry.Name()) {
					if err := os.Chtimes(filepath.Join(managed.root, entry.Name()), old, old); err != nil {
						return err
					}
				}
			}
			removed, err := geoipasset.Prune(managed.root, []string{paths["a"]}, nil, nil, time.Now())
			if err != nil || removed < 2 {
				return fmt.Errorf("obsolete assets were not removed: %d %v", removed, err)
			}
			if _, err := os.Stat(filepath.Join(managed.root, name)); !os.IsNotExist(err) {
				return fmt.Errorf("orphan asset remains")
			}
			// Existing streams and new connections still use the compiled IP set.
			return probe("198.18.0.1", 'M')
		}); err != nil {
			return rows, int(count.Load()), err
		}
	}
	if err := measure("settled", pid, func() error { time.Sleep(3 * time.Second); return nil }); err != nil {
		return rows, int(count.Load()), err
	}
	// Join before reading the goroutine-owned counters.
	join()
	if continuityErr != nil {
		return rows, int(count.Load()), fmt.Errorf("established stream: %w", continuityErr)
	}
	if err := process.Process.Signal(syscall.Signal(0)); err != nil {
		return rows, int(count.Load()), fmt.Errorf("core PID changed: %w", err)
	}
	return rows, int(count.Load()), nil
}

func encodeGeoIP(cidrs []string) ([]byte, error) {
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "RU")
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		p = p.Masked()
		cidr := protowire.AppendTag(nil, 1, protowire.BytesType)
		cidr = protowire.AppendBytes(cidr, p.Addr().AsSlice())
		cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
		cidr = protowire.AppendVarint(cidr, uint64(p.Bits()))
		entry = protowire.AppendTag(entry, 2, protowire.BytesType)
		entry = protowire.AppendBytes(entry, cidr)
	}
	list := protowire.AppendTag(nil, 1, protowire.BytesType)
	return protowire.AppendBytes(list, entry), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func echoMarker(value byte) (net.Listener, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 1)
				for {
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					if _, err := c.Write([]byte{value}); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l, nil
}
func socksDial(port int, address string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	b := make([]byte, 2)
	if _, err = io.ReadFull(c, b); err != nil {
		return fail(err)
	}
	if b[0] != 5 || b[1] != 0 {
		return fail(fmt.Errorf("SOCKS authentication failed"))
	}
	ip := net.ParseIP(address).To4()
	request := append([]byte{5, 1, 0, 1}, ip...)
	request = append(request, 0, 80)
	if _, err = c.Write(request); err != nil {
		return fail(err)
	}
	b = make([]byte, 4)
	if _, err = io.ReadFull(c, b); err != nil {
		return fail(err)
	}
	if b[1] != 0 {
		return fail(fmt.Errorf("SOCKS connect failed %d", b[1]))
	}
	var n int
	switch b[3] {
	case 1:
		n = 6
	case 4:
		n = 18
	default:
		return fail(fmt.Errorf("unexpected SOCKS address"))
	}
	if _, err = io.ReadFull(c, make([]byte, n)); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
func marker(c net.Conn, want byte) error {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{'x'}); err != nil {
		return err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if b[0] != want {
		return fmt.Errorf("route marker %c, want %c", b[0], want)
	}
	return nil
}

func sample(phase string, pid int, fn func() error) (metrics, error) {
	m := metrics{Phase: phase}
	started := time.Now()
	done := make(chan struct{})
	joined := make(chan struct{})
	var mu sync.Mutex
	collect := func() {
		var core, total int64
		entries, _ := os.ReadDir("/proc")
		for _, entry := range entries {
			n, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			body, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
			if err != nil {
				continue
			}
			s := string(body)
			if !strings.Contains(s, "Name:\txray") {
				continue
			}
			for _, line := range strings.Split(s, "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					v, _ := strconv.ParseInt(fields[1], 10, 64)
					total += v * 1024
					if n == pid {
						core = v * 1024
					}
				}
			}
		}
		body, _ := os.ReadFile("/sys/fs/cgroup/memory.current")
		cg, _ := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
		mu.Lock()
		m.CoreRSS = max(m.CoreRSS, core)
		m.XrayRSS = max(m.XrayRSS, total)
		m.Cgroup = max(m.Cgroup, cg)
		mu.Unlock()
	}
	go func() {
		defer close(joined)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			collect()
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	err := fn()
	close(done)
	<-joined
	m.Milliseconds = time.Since(started).Milliseconds()
	return m, err
}
