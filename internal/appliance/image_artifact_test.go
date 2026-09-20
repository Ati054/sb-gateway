package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var generatedNonSourceDirectories = map[string]bool{
	".cache-release": true, ".git": true, ".lab": true, ".next": true, ".tmp": true, ".venv": true,
	// This generated tool cache is excluded from the production Docker context.
	".npm-cache": true, "dist": true, "node_modules": true, "work": true,
}

func readOptionalLabArtifact(t *testing.T, path ...string) []byte {
	t.Helper()
	helper, err := os.ReadFile(filepath.Join(path...))
	if os.IsNotExist(err) {
		t.Skip("lab-only artifact is intentionally excluded from the production Docker context")
	}
	if err != nil {
		t.Fatal(err)
	}
	return helper
}

func TestProductionImageUsesNativeGoApplianceWithoutPython(t *testing.T) {
	root := filepath.Join("..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	entrypoint, err := os.ReadFile(filepath.Join(root, "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	image := string(dockerfile)
	runtimeIndex := strings.Index(image, "FROM ${RUNTIME_IMAGE} AS runtime")
	if runtimeIndex < 0 {
		t.Fatal("production Dockerfile has no native runtime stage")
	}
	runtimeImage := image[runtimeIndex:]
	for _, prohibited := range []string{"PYTHON_IMAGE", "pip install", "requirements.lock", "supervisord", "uvicorn", "COPY app ./app"} {
		if strings.Contains(runtimeImage, prohibited) {
			t.Fatalf("production Dockerfile still contains %q", prohibited)
		}
	}
	for _, required := range []string{"FROM ${RUNTIME_IMAGE} AS runtime", "alpine:3.23", "COPY --from=sb-gateway-build /out/sb-gateway"} {
		if !strings.Contains(image, required) {
			t.Fatalf("production Dockerfile is missing %q", required)
		}
	}
	if !strings.Contains(string(entrypoint), "exec /usr/local/bin/sb-gateway appliance") {
		t.Fatal("entrypoint does not hand PID 1 to the native Go appliance")
	}
	for _, required := range []string{
		`export SB_RUNTIME_CANDIDATE_DIR="${SB_RUNTIME_CANDIDATE_DIR:-/state/runtime-candidates}"`,
		`lkg="${SB_NGINX_LKG_CONFIG:-${SB_RUNTIME_CANDIDATE_DIR}/runtime-lkg/nginx.conf}"`,
	} {
		if !strings.Contains(string(entrypoint), required) {
			t.Fatalf("entrypoint does not restore the committed runtime from %q", required)
		}
	}
	if strings.Contains(string(entrypoint), "/data/last-known-good/nginx.conf") {
		t.Fatal("entrypoint still reads the obsolete nginx last-known-good path")
	}
}

func TestRepositoryContainsNoPythonSources(t *testing.T) {
	root := filepath.Join("..", "..")
	sources, err := repositoryPythonSources(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		t.Errorf("Python source remains in the maintained tree: %s", source)
	}
}

func TestRepositoryPythonHygieneSkipsGeneratedCaches(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{".npm-cache", ".cache-release"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, directory, "cached.py"), []byte("cached"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "maintained.py"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources, err := repositoryPythonSources(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0] != "maintained.py" {
		t.Fatalf("unexpected Python sources: %v", sources)
	}
}

func TestWebLintSkipsGeneratedReleaseCache(t *testing.T) {
	root := filepath.Join("..", "..")
	manifest, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "--ignore-pattern .cache-release") {
		t.Fatal("Web lint can traverse generated release worktrees and caches")
	}
}

func repositoryPythonSources(root string) ([]string, error) {
	var sources []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && path != root && generatedNonSourceDirectories[entry.Name()] {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".py") {
			relative, _ := filepath.Rel(root, path)
			sources = append(sources, relative)
		}
		return nil
	})
	return sources, err
}

func TestProductionInputsExcludeLabRules(t *testing.T) {
	root := filepath.Join("..", "..")
	ignore, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	normalizedIgnore := "\n" + strings.ReplaceAll(string(ignore), "\r", "") + "\n"
	if !strings.Contains(normalizedIgnore, "\n.lab\n") {
		t.Fatal("lab directory must be excluded from Docker context")
	}
	for _, line := range strings.Split(normalizedIgnore, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "!.lab") {
			t.Fatalf("lab directory must not be re-included in Docker context: %s", line)
		}
	}
	for _, required := range []string{"!routeros/*.go", "!routeros/watchdog.rsc"} {
		if !strings.Contains(string(ignore), required) {
			t.Fatalf("Docker context excludes embedded RouterOS sources: missing %s", required)
		}
	}
	for _, input := range []string{"templates", "scripts", "routeros", "Dockerfile", "entrypoint.sh"} {
		err := filepath.WalkDir(filepath.Join(root, input), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, marker := range []string{"LAB-ONLY", "SB-GATEWAY-LAB", "HAP-MIRROR", "CHR_test", "lab-chr-public"} {
				if strings.Contains(string(body), marker) {
					t.Errorf("lab marker %q leaked into production input %s", marker, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestLabCHRPublicSubscriptionIngressPreservesOriginPortAndGcoreACL(t *testing.T) {
	root := filepath.Join("..", "..")
	helper := readOptionalLabArtifact(t, root, ".lab", "scripts", "routeros-chr-public-test.sh")
	body := string(helper)
	for _, required := range []string{
		`[/system/identity/get name] != "sb-gateway-lab-chr"`,
		`Gcore IPv4 allowlist is empty`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("lab subscription ingress is missing %q", required)
		}
	}
	var ingressRule string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "/ip/firewall/nat/add") && strings.Contains(line, `comment="LAB-ONLY CHR public CDN and subscription TLS"`) {
			ingressRule = line
			break
		}
	}
	if ingressRule == "" {
		t.Fatal("lab subscription ingress rule is missing")
	}
	for _, required := range []string{
		`in-interface=CHR_test`,
		`dst-address=10.15.0.3`,
		`dst-port=18443`,
		`to-addresses=172.30.80.2`,
		`to-ports=18443`,
		`src-address-list=SB_CDN_GCORE_V4`,
	} {
		if !strings.Contains(ingressRule, required) {
			t.Errorf("lab subscription ingress rule is missing %q", required)
		}
	}
}

func TestLabCHRPublicDirectIngressMatchesCurrentFixturePorts(t *testing.T) {
	root := filepath.Join("..", "..")
	helper := readOptionalLabArtifact(t, root, ".lab", "scripts", "routeros-chr-public-test.sh")
	body := string(helper)
	assertRule := func(comment string, required ...string) {
		t.Helper()
		var rule string
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, "/ip/firewall/nat/add") && strings.Contains(line, `comment="`+comment+`"`) {
				rule = line
				break
			}
		}
		if rule == "" {
			t.Fatalf("lab rule %q is missing", comment)
		}
		for _, field := range required {
			if !strings.Contains(rule, field) {
				t.Errorf("lab rule %q is missing %q", comment, field)
			}
		}
	}
	assertRule(
		"LAB-ONLY CHR public Reality TCP",
		`protocol=tcp`, `dst-port=2443,443,8443`, `to-addresses=172.30.80.2`,
	)
	assertRule(
		"LAB-ONLY CHR public Hysteria UDP",
		`protocol=udp`, `dst-port=20443`, `to-addresses=172.30.80.2`, `to-ports=20443`,
	)
	for _, required := range []string{
		`dst-port=2443,443,8443,18443`,
		`/ip/firewall/mangle/set $udpMark dst-port=20443`,
		`/ip/firewall/nat/set $tcpNat dst-port=2443,443,8443`,
		`/ip/firewall/nat/set $udpNat dst-port=20443 to-ports=20443`,
		`CHR_PUBLIC_TRANSPORTS_RECONCILED`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("lab transport reconcile is missing %q", required)
		}
	}
	probe, err := os.ReadFile(filepath.Join(root, ".lab", "scripts", "chr-public-ingress-probe.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"for port in 2443 443 8443", "/dev/udp/10.15.0.3/20443"} {
		if !strings.Contains(string(probe), required) {
			t.Errorf("lab ingress probe is missing %q", required)
		}
	}
}
