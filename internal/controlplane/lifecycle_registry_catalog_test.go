package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
)

type registryCatalogFixtureObject struct {
	body     []byte
	kind     string
	status   int
	redirect string
}
type registryCatalogFixture struct {
	server                                       *httptest.Server
	objects                                      map[string]registryCatalogFixtureObject
	reference, version, manifestPath, configPath string
	mu                                           sync.Mutex
	paths                                        []string
	auth                                         bool
	challengeScope, challengeRealm               string
	tokenRequests                                atomic.Int64
	tokenRedirect                                string
	block                                        bool
}

func registryCatalogFixtureDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func registryCatalogFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func registryCatalogFixtureConfig(t *testing.T, schema *string) []byte {
	t.Helper()
	labels := map[string]string{
		"org.opencontainers.image.title": "sb-gateway", "org.opencontainers.image.version": "9.8.7",
		releasecontract.LifecycleVersionLabel: releasecontract.LifecycleVersion,
		releasecontract.ConfigSchemaLabel:     "1", releasecontract.MinimumConfigSchemaLabel: "1",
	}
	if schema != nil {
		labels[releasecontract.SubscriptionCatalogSchemaLabel] = *schema
	}
	return registryCatalogFixtureJSON(t, map[string]any{"architecture": "arm64", "os": "linux", "config": map[string]any{"Labels": labels}})
}

func newRegistryCatalogFixture(t *testing.T, config []byte, index bool) *registryCatalogFixture {
	t.Helper()
	fixture := &registryCatalogFixture{objects: make(map[string]registryCatalogFixtureObject), version: "9.8.7", challengeScope: "repository:team/image:pull"}
	configDigest := registryCatalogFixtureDigest(config)
	fixture.configPath = "/v2/team/image/blobs/" + configDigest
	fixture.objects[fixture.configPath] = registryCatalogFixtureObject{body: config, kind: registryOCIConfig}
	manifest := registryCatalogFixtureJSON(t, map[string]any{"schemaVersion": 2, "mediaType": registryOCIManifest, "config": map[string]any{"mediaType": registryOCIConfig, "digest": configDigest, "size": len(config)}, "layers": []any{}})
	manifestDigest := registryCatalogFixtureDigest(manifest)
	fixture.manifestPath = "/v2/team/image/manifests/" + manifestDigest
	fixture.objects[fixture.manifestPath] = registryCatalogFixtureObject{body: manifest, kind: registryOCIManifest}
	rootDigest := manifestDigest
	if index {
		root := registryCatalogFixtureJSON(t, map[string]any{"schemaVersion": 2, "mediaType": registryOCIIndex, "manifests": []any{
			map[string]any{"mediaType": registryOCIManifest, "digest": "sha256:" + strings.Repeat("1", 64), "size": 1, "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
			map[string]any{"mediaType": registryOCIManifest, "digest": manifestDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}},
			map[string]any{"mediaType": "application/unknown", "digest": "sha256:" + strings.Repeat("2", 64), "size": 1, "platform": map[string]any{"os": "unknown", "architecture": "unknown"}},
		}})
		rootDigest = registryCatalogFixtureDigest(root)
		fixture.objects["/v2/team/image/manifests/"+rootDigest] = registryCatalogFixtureObject{body: root, kind: registryOCIIndex}
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.paths = append(fixture.paths, r.URL.Path)
		blocked, auth, realm, scope, tokenRedirect := fixture.block, fixture.auth, fixture.challengeRealm, fixture.challengeScope, fixture.tokenRedirect
		object, found := fixture.objects[r.URL.Path]
		fixture.mu.Unlock()
		if blocked {
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/token" {
			fixture.tokenRequests.Add(1)
			if r.Header.Get("Authorization") != "" || r.URL.Query().Get("scope") != "repository:team/image:pull" || r.URL.Query().Get("service") != "fixture" || r.URL.Query().Get("offline_token") != "" {
				t.Error("token request broadened scope or forwarded credentials")
			}
			if tokenRedirect != "" {
				http.Redirect(w, r, tokenRedirect, http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"synthetic-token"}`))
			return
		}
		if auth && r.Header.Get("Authorization") != "Bearer synthetic-token" {
			if realm == "" {
				realm = fixture.server.URL + "/token"
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture",scope=%q`, realm, scope))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !found {
			t.Error("unexpected registry path; layer or wrong platform was requested")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if object.redirect != "" {
			http.Redirect(w, r, object.redirect, http.StatusTemporaryRedirect)
			return
		}
		if object.kind != "" {
			w.Header().Set("Content-Type", object.kind)
		}
		if object.status != 0 {
			w.WriteHeader(object.status)
		}
		_, _ = w.Write(object.body)
	}))
	fixture.reference = strings.TrimPrefix(fixture.server.URL, "https://") + "/team/image@" + rootDigest
	t.Cleanup(fixture.server.Close)
	return fixture
}

func TestRegistryCatalogCapabilityVerifiesDigestChainAndLabels(t *testing.T) {
	for _, schema := range []string{"absent", "0", "1"} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema-%s/index-%t", schema, indexed), func(t *testing.T) {
				var label *string
				if schema != "absent" {
					label = &schema
				}
				fixture := newRegistryCatalogFixture(t, registryCatalogFixtureConfig(t, label), indexed)
				actual, err := inspectRegistryImageCatalogSchemaWithClient(context.Background(), fixture.reference, fixture.version, fixture.server.Client())
				want := 0
				if schema == "1" {
					want = 1
				}
				if err != nil || actual != want {
					t.Fatalf("schema=%d want=%d err=%v", actual, want, err)
				}
				fixture.mu.Lock()
				defer fixture.mu.Unlock()
				requests := 2
				if indexed {
					requests = 3
				}
				if len(fixture.paths) != requests {
					t.Fatalf("metadata requests=%d want=%d", len(fixture.paths), requests)
				}
			})
		}
	}
}

func TestRegistryCatalogCapabilityRejectsUnverifiedMetadata(t *testing.T) {
	for _, scenario := range []string{"root-digest", "child-digest", "config-digest", "descriptor-size", "wrong-platform", "wrong-version", "unknown-schema", "invalid-schema", "empty-schema", "contract", "oversized", "ambiguous-index", "nested-index", "missing-arm64"} {
		t.Run(scenario, func(t *testing.T) {
			one := "1"
			config := registryCatalogFixtureConfig(t, &one)
			if scenario == "wrong-platform" {
				config = []byte(strings.Replace(string(config), `"architecture":"arm64"`, `"architecture":"amd64"`, 1))
			}
			if scenario == "wrong-version" {
				config = []byte(strings.Replace(string(config), `9.8.7`, `9.8.6`, 1))
			}
			if scenario == "unknown-schema" || scenario == "invalid-schema" {
				value := "2"
				if scenario == "invalid-schema" {
					value = "1 "
				}
				config = registryCatalogFixtureConfig(t, &value)
			}
			if scenario == "empty-schema" {
				value := ""
				config = registryCatalogFixtureConfig(t, &value)
			}
			if scenario == "contract" {
				config = []byte(strings.Replace(string(config), `"io.sb-gateway.lifecycle.version":"1"`, `"io.sb-gateway.lifecycle.version":"2"`, 1))
			}
			indexed := scenario == "child-digest" || scenario == "ambiguous-index" || scenario == "nested-index" || scenario == "missing-arm64"
			fixture := newRegistryCatalogFixture(t, config, indexed)
			rootDigest := strings.Split(fixture.reference, "@")[1]
			rootPath := "/v2/team/image/manifests/" + rootDigest
			fixture.mu.Lock()
			switch scenario {
			case "root-digest", "child-digest", "config-digest", "oversized":
				path := rootPath
				if scenario == "child-digest" {
					path = fixture.manifestPath
				}
				if scenario == "config-digest" {
					path = fixture.configPath
				}
				object := fixture.objects[path]
				object.body = append(append([]byte(nil), object.body...), byte(' '))
				if scenario == "oversized" {
					object.body = make([]byte, registryCatalogMetadataLimit+1)
				}
				fixture.objects[path] = object
			case "descriptor-size":
				var document map[string]any
				_ = json.Unmarshal(fixture.objects[rootPath].body, &document)
				document["config"].(map[string]any)["size"] = 1
				fixture.replaceRoot(t, rootPath, document)
			case "ambiguous-index", "nested-index", "missing-arm64":
				var document map[string]any
				_ = json.Unmarshal(fixture.objects[rootPath].body, &document)
				manifests := document["manifests"].([]any)
				if scenario == "ambiguous-index" {
					document["manifests"] = append(manifests, manifests[1])
				}
				if scenario == "nested-index" {
					manifests[1].(map[string]any)["mediaType"] = registryOCIIndex
				}
				if scenario == "missing-arm64" {
					manifests[1].(map[string]any)["platform"].(map[string]any)["architecture"] = "arm"
				}
				fixture.replaceRoot(t, rootPath, document)
			}
			fixture.mu.Unlock()
			if _, err := inspectRegistryImageCatalogSchemaWithClient(context.Background(), fixture.reference, fixture.version, fixture.server.Client()); err == nil {
				t.Fatal("unverified capability accepted")
			}
		})
	}
}

func (fixture *registryCatalogFixture) replaceRoot(t *testing.T, oldPath string, value any) {
	t.Helper()
	object := fixture.objects[oldPath]
	object.body = registryCatalogFixtureJSON(t, value)
	digest := registryCatalogFixtureDigest(object.body)
	fixture.objects["/v2/team/image/manifests/"+digest] = object
	fixture.reference = strings.Split(fixture.reference, "@")[0] + "@" + digest
}

func TestRegistryCatalogAnonymousBearerIsScopedAndMemoryOnly(t *testing.T) {
	one := "1"
	fixture := newRegistryCatalogFixture(t, registryCatalogFixtureConfig(t, &one), true)
	fixture.mu.Lock()
	fixture.auth = true
	fixture.mu.Unlock()
	actual, err := inspectRegistryImageCatalogSchemaWithClient(context.Background(), fixture.reference, fixture.version, fixture.server.Client())
	if err != nil || actual != 1 || fixture.tokenRequests.Load() != 1 {
		t.Fatalf("anonymous auth schema=%d token requests=%d err=%v", actual, fixture.tokenRequests.Load(), err)
	}
}

func TestRegistryCatalogRejectsForeignRealmAndScope(t *testing.T) {
	for _, scenario := range []string{"foreign-realm", "scope", "token-redirect", "manifest-redirect", "blob-redirect"} {
		t.Run(scenario, func(t *testing.T) {
			var foreign atomic.Int64
			outside := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign.Add(1); w.WriteHeader(http.StatusOK) }))
			defer outside.Close()
			one := "1"
			fixture := newRegistryCatalogFixture(t, registryCatalogFixtureConfig(t, &one), false)
			fixture.mu.Lock()
			fixture.auth = scenario != "manifest-redirect" && scenario != "blob-redirect"
			switch scenario {
			case "foreign-realm":
				fixture.challengeRealm = outside.URL + "/token"
			case "scope":
				fixture.challengeScope = "repository:other/image:pull,push"
			case "token-redirect":
				fixture.tokenRedirect = outside.URL + "/token"
			default:
				path := fixture.manifestPath
				if scenario == "blob-redirect" {
					path = fixture.configPath
				}
				object := fixture.objects[path]
				object.redirect = outside.URL + "/metadata"
				fixture.objects[path] = object
			}
			fixture.mu.Unlock()
			_, err := inspectRegistryImageCatalogSchemaWithClient(context.Background(), fixture.reference, fixture.version, fixture.server.Client())
			if err == nil || foreign.Load() != 0 {
				t.Fatalf("external auth/redirect accepted: err=%v foreign=%d", err, foreign.Load())
			}
			if strings.Contains(err.Error(), "synthetic-token") || strings.Contains(err.Error(), fixture.reference) {
				t.Fatal("inspection error exposed metadata or token")
			}
		})
	}
}

func TestRegistryCatalogDeadlineAndImmutableReference(t *testing.T) {
	one := "1"
	fixture := newRegistryCatalogFixture(t, registryCatalogFixtureConfig(t, &one), false)
	for _, reference := range []string{"ghcr.io/team/image:latest", "https://registry.example/team/image@sha256:" + strings.Repeat("1", 64), "registry.example/../image@sha256:" + strings.Repeat("1", 64)} {
		if _, err := inspectRegistryImageCatalogSchemaWithClient(context.Background(), reference, fixture.version, fixture.server.Client()); err == nil {
			t.Fatal("mutable or malformed reference accepted")
		}
	}
	fixture.mu.Lock()
	requests := len(fixture.paths)
	fixture.mu.Unlock()
	if requests != 0 {
		t.Fatal("invalid references made HTTP requests")
	}
	fixture.mu.Lock()
	fixture.block = true
	fixture.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := inspectRegistryImageCatalogSchemaWithClient(ctx, fixture.reference, fixture.version, fixture.server.Client()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline lost: %v", err)
	}
}

func TestRegistryCatalogPublicAuthMappingAndChallengeParser(t *testing.T) {
	parse := func(value string) *url.URL {
		t.Helper()
		result, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	origin := parse("https://registry-1.docker.io")
	if !registryCatalogTokenRealmAllowed(origin, parse("https://auth.docker.io/token")) {
		t.Fatal("standard Docker Hub mapping rejected")
	}
	for _, target := range []string{"http://auth.docker.io/token", "https://auth.docker.io/other", "https://auth.docker.io.evil.example/token", "https://user@auth.docker.io/token", "https://auth.docker.io/token#fragment"} {
		if registryCatalogTokenRealmAllowed(origin, parse(target)) {
			t.Fatal("unapproved public token realm accepted")
		}
	}
	for _, challenge := range []string{`Basic realm="registry"`, `Bearer realm="https://registry.example/token", realm="https://other.example/token"`, `Bearer realm="unterminated`, `Bearer realm="https://registry.example/token",`} {
		if _, err := parseRegistryCatalogChallenge(challenge); err == nil {
			t.Fatal("ambiguous challenge accepted")
		}
	}
}
