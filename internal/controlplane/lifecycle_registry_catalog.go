package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
)

const registryCatalogInspectionBudget = 30 * time.Second
const registryCatalogMetadataLimit = 4 << 20
const registryCatalogTokenLimit = 64 << 10
const registryOCIManifest = "application/vnd.oci.image.manifest.v1+json"
const registryOCIIndex = "application/vnd.oci.image.index.v1+json"
const registryDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
const registryDockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json"
const registryOCIConfig = "application/vnd.oci.image.config.v1+json"
const registryDockerConfig = "application/vnd.docker.container.image.v1+json"

var errRegistryCatalogCapability = errors.New("registry image capability could not be verified; use a verified TAR image")
var registryCatalogRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var registryCatalogBearerPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

type registryCatalogDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string   `json:"architecture"`
		OS           string   `json:"os"`
		Variant      string   `json:"variant"`
		OSFeatures   []string `json:"os.features"`
	} `json:"platform"`
}

type registryCatalogManifest struct {
	SchemaVersion int                         `json:"schemaVersion"`
	MediaType     string                      `json:"mediaType"`
	Config        registryCatalogDescriptor   `json:"config"`
	Manifests     []registryCatalogDescriptor `json:"manifests"`
}

type registryCatalogLocation struct {
	origin             *url.URL
	repository, digest string
}
type registryCatalogFetcher struct {
	client     *http.Client
	blobClient *http.Client
	location   registryCatalogLocation
	token      string
	challenged bool
}

// inspectRegistryImageCatalogSchema verifies the immutable OCI/Docker metadata
// chain, not image layers or runtime health. No registry credentials are read.
// Private, redirected or otherwise unsupported endpoints fail closed to TAR.
func inspectRegistryImageCatalogSchema(ctx context.Context, immutableReference, expectedVersion string) (int, error) {
	transport := &http.Transport{
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DisableCompression: true, ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	return inspectRegistryImageCatalogSchemaWithClient(ctx, immutableReference, expectedVersion, &http.Client{Transport: transport})
}

// The injected transport exists for synthetic TLS fixtures. Redirect and cookie
// policy are still forced here, independently of the supplied client's defaults.
func inspectRegistryImageCatalogSchemaWithClient(ctx context.Context, reference, expectedVersion string, supplied *http.Client) (int, error) {
	return inspectRegistryImageCatalogSchemaWithClients(ctx, reference, expectedVersion, supplied, nil)
}

// The optional second client is a test seam for synthetic CDN responses. The
// production path always constructs the public-address-pinned blob transport.
func inspectRegistryImageCatalogSchemaWithClients(ctx context.Context, reference, expectedVersion string, supplied, blobClient *http.Client) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, registryCatalogInspectionBudget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	location, err := parseRegistryCatalogLocation(reference)
	if err != nil || supplied == nil || !lifecycleVersionPattern.MatchString(expectedVersion) {
		return 0, errRegistryCatalogCapability
	}
	client := *supplied
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fetcher := &registryCatalogFetcher{client: &client, blobClient: blobClient, location: location}
	defer func() {
		if fetcher.blobClient != nil {
			fetcher.blobClient.CloseIdleConnections()
		}
	}()
	body, kind, err := fetcher.metadata(ctx, "manifests", location.digest, -1)
	if err != nil {
		return 0, registryCatalogInspectionError(ctx)
	}
	manifest, err := decodeRegistryCatalogManifest(body, kind)
	if err != nil {
		return 0, err
	}
	if registryCatalogIndexType(manifest.MediaType) {
		var selected *registryCatalogDescriptor
		for index := range manifest.Manifests {
			descriptor := &manifest.Manifests[index]
			platform := descriptor.Platform
			if platform == nil || platform.OS != "linux" || platform.Architecture != "arm64" || platform.Variant != "" && platform.Variant != "v8" || len(platform.OSFeatures) != 0 {
				continue
			}
			if selected != nil || !registryCatalogImageType(descriptor.MediaType) || !validRegistryCatalogDescriptor(*descriptor) {
				return 0, errRegistryCatalogCapability
			}
			selected = descriptor
		}
		if selected == nil {
			return 0, errRegistryCatalogCapability
		}
		body, kind, err = fetcher.metadata(ctx, "manifests", selected.Digest, selected.Size)
		if err != nil {
			return 0, registryCatalogInspectionError(ctx)
		}
		manifest, err = decodeRegistryCatalogManifest(body, kind)
		if err != nil || manifest.MediaType != selected.MediaType {
			return 0, errRegistryCatalogCapability
		}
	}
	if !registryCatalogImageType(manifest.MediaType) || !validRegistryCatalogDescriptor(manifest.Config) || manifest.Config.MediaType != registryOCIConfig && manifest.Config.MediaType != registryDockerConfig {
		return 0, errRegistryCatalogCapability
	}
	body, _, err = fetcher.metadata(ctx, "blobs", manifest.Config.Digest, manifest.Config.Size)
	if err != nil {
		return 0, registryCatalogInspectionError(ctx)
	}
	var config dockerImageConfig
	if json.Unmarshal(body, &config) != nil {
		return 0, errRegistryCatalogCapability
	}
	labels := config.Config.Labels
	_, _, compatible := releasecontract.Compatible(labels, currentSchemaVersion)
	if config.OS != "linux" || config.Architecture != "arm64" && config.Architecture != "aarch64" || !compatible || labels["org.opencontainers.image.version"] != expectedVersion {
		return 0, errRegistryCatalogCapability
	}
	schema, known := releasecontract.CatalogSchema(labels)
	if !known {
		return 0, errRegistryCatalogCapability
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return schema, nil
}

func registryCatalogInspectionError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errRegistryCatalogCapability
}

func registryCatalogImageType(kind string) bool {
	return kind == registryOCIManifest || kind == registryDockerManifest
}
func registryCatalogIndexType(kind string) bool {
	return kind == registryOCIIndex || kind == registryDockerIndex
}
func registryCatalogDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && safeRevision(strings.TrimPrefix(value, "sha256:"))
}
func validRegistryCatalogDescriptor(value registryCatalogDescriptor) bool {
	return registryCatalogDigest(value.Digest) && value.Size > 0 && value.Size <= registryCatalogMetadataLimit
}

func parseRegistryCatalogLocation(reference string) (registryCatalogLocation, error) {
	var result registryCatalogLocation
	if len(reference) > 512 || strings.TrimSpace(reference) != reference || strings.Count(reference, "@") != 1 {
		return result, errRegistryCatalogCapability
	}
	name, digest, _ := strings.Cut(reference, "@")
	if !registryCatalogDigest(digest) || strings.ContainsAny(name, "?#\\") {
		return result, errRegistryCatalogCapability
	}
	host, repository := "registry-1.docker.io", name
	first, rest, slash := strings.Cut(name, "/")
	if slash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, repository = strings.ToLower(first), rest
	}
	if host == "docker.io" || host == "index.docker.io" {
		host = "registry-1.docker.io"
	}
	if host == "registry-1.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	if len(repository) == 0 || len(repository) > 255 || !registryCatalogRepositoryPattern.MatchString(repository) {
		return result, errRegistryCatalogCapability
	}
	origin, err := url.Parse("https://" + host)
	if err != nil || origin.Host != host || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return result, errRegistryCatalogCapability
	}
	if port := origin.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return result, errRegistryCatalogCapability
		}
	}
	result.origin, result.repository, result.digest = origin, repository, digest
	return result, nil
}

func decodeRegistryCatalogManifest(body []byte, headerType string) (registryCatalogManifest, error) {
	var manifest registryCatalogManifest
	if json.Unmarshal(body, &manifest) != nil || manifest.SchemaVersion != 2 {
		return manifest, errRegistryCatalogCapability
	}
	if manifest.MediaType == "" {
		manifest.MediaType = headerType
	}
	if !registryCatalogImageType(manifest.MediaType) && !registryCatalogIndexType(manifest.MediaType) {
		return manifest, errRegistryCatalogCapability
	}
	if headerType != "" && headerType != "application/json" && headerType != manifest.MediaType {
		return manifest, errRegistryCatalogCapability
	}
	return manifest, nil
}

func (fetcher *registryCatalogFetcher) metadata(ctx context.Context, endpoint, digest string, expectedSize int64) ([]byte, string, error) {
	if !registryCatalogDigest(digest) {
		return nil, "", errRegistryCatalogCapability
	}
	address := *fetcher.location.origin
	address.Path = "/v2/" + fetcher.location.repository + "/" + endpoint + "/" + digest
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
		if err != nil {
			return nil, "", errRegistryCatalogCapability
		}
		request.Header.Set("Accept", strings.Join([]string{registryOCIManifest, registryOCIIndex, registryDockerManifest, registryDockerIndex}, ", "))
		if endpoint == "blobs" {
			request.Header.Set("Accept", strings.Join([]string{registryOCIConfig, registryDockerConfig, "application/octet-stream"}, ", "))
		}
		request.Header.Set("Accept-Encoding", "identity")
		if fetcher.token != "" {
			request.Header.Set("Authorization", "Bearer "+fetcher.token)
		}
		response, err := fetcher.client.Do(request)
		if err != nil {
			return nil, "", errRegistryCatalogCapability
		}
		if response.StatusCode == http.StatusUnauthorized && !fetcher.challenged {
			challenge := response.Header.Values("WWW-Authenticate")
			_ = response.Body.Close()
			fetcher.challenged = true
			if len(challenge) != 1 {
				return nil, "", errRegistryCatalogCapability
			}
			token, err := fetcher.anonymousToken(ctx, challenge[0])
			if err != nil {
				return nil, "", errRegistryCatalogCapability
			}
			fetcher.token = token
			continue
		}
		if endpoint == "blobs" && registryCatalogRedirectStatus(response.StatusCode) {
			locationHeader := response.Header.Get("Location")
			location, locationErr := request.URL.Parse(locationHeader)
			_ = response.Body.Close()
			if locationErr != nil || locationHeader == "" {
				return nil, "", errRegistryCatalogCapability
			}
			response, err = fetcher.redirectedBlob(ctx, location)
			if err != nil {
				return nil, "", errRegistryCatalogCapability
			}
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, "", errRegistryCatalogCapability
		}
		body, err := readRegistryCatalogBody(response, registryCatalogMetadataLimit)
		if err != nil || expectedSize >= 0 && int64(len(body)) != expectedSize {
			return nil, "", errRegistryCatalogCapability
		}
		sum := sha256.Sum256(body)
		if "sha256:"+hex.EncodeToString(sum[:]) != digest {
			return nil, "", errRegistryCatalogCapability
		}
		if reported := response.Header.Get("Docker-Content-Digest"); reported != "" && reported != digest {
			return nil, "", errRegistryCatalogCapability
		}
		kind := ""
		if header := response.Header.Get("Content-Type"); header != "" {
			kind, _, err = mime.ParseMediaType(header)
			if err != nil {
				return nil, "", errRegistryCatalogCapability
			}
		}
		return body, kind, nil
	}
	return nil, "", errRegistryCatalogCapability
}

func readRegistryCatalogBody(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	if response.ContentLength > limit || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, errRegistryCatalogCapability
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errRegistryCatalogCapability
	}
	return body, nil
}

func (fetcher *registryCatalogFetcher) anonymousToken(ctx context.Context, challenge string) (string, error) {
	parameters, err := parseRegistryCatalogChallenge(challenge)
	if err != nil {
		return "", err
	}
	wantScope := "repository:" + fetcher.location.repository + ":pull"
	if parameters["scope"] != wantScope || parameters["service"] == "" || len(parameters["service"]) > 255 {
		return "", errRegistryCatalogCapability
	}
	realm, err := url.Parse(parameters["realm"])
	if err != nil || !registryCatalogTokenRealmAllowed(fetcher.location.origin, realm) {
		return "", errRegistryCatalogCapability
	}
	query := make(url.Values)
	query.Set("scope", wantScope)
	query.Set("service", parameters["service"])
	query.Del("offline_token")
	query.Del("account")
	query.Del("client_id")
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", errRegistryCatalogCapability
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := fetcher.client.Do(request)
	if err != nil {
		return "", errRegistryCatalogCapability
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return "", errRegistryCatalogCapability
	}
	body, err := readRegistryCatalogBody(response, registryCatalogTokenLimit)
	if err != nil {
		return "", err
	}
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &result) != nil || result.Token != "" && result.AccessToken != "" && result.Token != result.AccessToken {
		return "", errRegistryCatalogCapability
	}
	token := result.Token
	if token == "" {
		token = result.AccessToken
	}
	if len(token) == 0 || len(token) > 16<<10 || !registryCatalogBearerPattern.MatchString(token) {
		return "", errRegistryCatalogCapability
	}
	return token, nil
}

func registryCatalogTokenRealmAllowed(origin, realm *url.URL) bool {
	if realm == nil || realm.Scheme != "https" || realm.User != nil || realm.Fragment != "" || realm.Opaque != "" || realm.Hostname() == "" {
		return false
	}
	canonicalHost := func(value *url.URL) string {
		port := value.Port()
		if port == "" {
			port = "443"
		}
		return strings.ToLower(value.Hostname()) + ":" + port
	}
	if canonicalHost(origin) == canonicalHost(realm) {
		return true
	}
	return canonicalHost(origin) == "registry-1.docker.io:443" && canonicalHost(realm) == "auth.docker.io:443" && realm.Path == "/token" && realm.RawQuery == ""
}

// Only one Bearer challenge is supported. Duplicate attributes, control bytes,
// multiple schemes and malformed quoted strings are rejected, not guessed.
func parseRegistryCatalogChallenge(header string) (map[string]string, error) {
	if len(header) > 16<<10 {
		return nil, errRegistryCatalogCapability
	}
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, errRegistryCatalogCapability
	}
	parameters := make(map[string]string)
	for strings.TrimSpace(rest) != "" {
		rest = strings.TrimSpace(rest)
		key, after, ok := strings.Cut(rest, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || strings.ContainsAny(key, " ,\t\r\n\"") {
			return nil, errRegistryCatalogCapability
		}
		if _, duplicate := parameters[key]; duplicate {
			return nil, errRegistryCatalogCapability
		}
		after = strings.TrimSpace(after)
		var value strings.Builder
		if strings.HasPrefix(after, "\"") {
			after = after[1:]
			closed := false
			for len(after) > 0 {
				character := after[0]
				after = after[1:]
				if character == '"' {
					closed = true
					break
				}
				if character == '\\' {
					if len(after) == 0 {
						return nil, errRegistryCatalogCapability
					}
					character = after[0]
					after = after[1:]
				}
				if character < 32 || character == 127 {
					return nil, errRegistryCatalogCapability
				}
				value.WriteByte(character)
			}
			if !closed {
				return nil, errRegistryCatalogCapability
			}
		} else {
			part, remaining, comma := strings.Cut(after, ",")
			value.WriteString(strings.TrimSpace(part))
			after = ""
			if comma {
				after = "," + remaining
			}
		}
		parameters[key] = value.String()
		after = strings.TrimSpace(after)
		if after == "" {
			rest = ""
		} else if strings.HasPrefix(after, ",") {
			rest = after[1:]
			if strings.TrimSpace(rest) == "" {
				return nil, errRegistryCatalogCapability
			}
		} else {
			return nil, errRegistryCatalogCapability
		}
	}
	return parameters, nil
}
