package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

const (
	apiPrefix                = "/api/v1"
	maxRequestBytes          = 2 << 20
	controlPlaneReadTimeout  = 10 * time.Minute
	controlPlaneWriteTimeout = 7 * time.Minute
)

type Options struct {
	Host         string
	Port         int
	StateDir     string
	SecretsDir   string
	DataDir      string
	AdminUser    string
	SecureCookie bool
	Runtime      RuntimeOptions
	Controller   RuntimeController
}

func OptionsFromEnvironment() Options {
	return Options{
		Host:         envOr("SB_GATEWAY_API_HOST", "127.0.0.1"),
		Port:         boundedEnvInt("SB_GATEWAY_API_PORT", 8080, 1, 65535),
		StateDir:     envOr("SB_GATEWAY_STATE_DIR", "/state/control-plane"),
		SecretsDir:   envOr("SB_GATEWAY_SECRETS_DIR", "/config/secrets"),
		DataDir:      envOr("SB_GATEWAY_DATA_DIR", "/data"),
		AdminUser:    envOr("SB_GATEWAY_ADMIN_USERNAME", "admin"),
		SecureCookie: envBool("SB_GATEWAY_COOKIE_SECURE", true),
		Runtime:      RuntimeOptionsFromEnvironment(),
	}
}

type Server struct {
	opts                      Options
	repository                *stateRepository
	secrets                   *secretStore
	sessions                  *sessionCodec
	login                     *loginGuard
	mux                       *http.ServeMux
	now                       func() time.Time
	trafficReadyAfter         time.Time
	mu                        sync.RWMutex
	passwordMu                sync.Mutex
	recoveryMu                sync.Mutex
	recoveryBeforeSnapshot    func(int)
	recoveryCleanupSnapshot   func(string) error
	lifecycleMu               sync.Mutex
	configMu                  sync.Mutex
	acmeMu                    sync.Mutex
	acmeProgressMu            sync.Mutex
	acmeProgress              acmeProgressState
	tlsTransferMu             sync.Mutex
	issueACME                 acmeIssueFunc
	acmeDNSLookup             func(context.Context, string) (string, error)
	acmeRoots                 *x509.CertPool
	validationMu              sync.Mutex
	validationRevision        string
	validationResult          configValidation
	subscriptionMu            sync.Mutex
	subscriptionWake          chan struct{}
	xrayLoggingWake           chan struct{}
	syncSubscriptionEndpoints func(context.Context, map[string]any, []string, bool) error
	servicePackMu             sync.Mutex
	fetchSubscription         subscriptionFetchFunc
	fetchViaProxy             subscriptionProxyFetchFunc
	selectUpdateExit          subscriptionExitSelector
	routeSimulator            *routeSimulator
	probeTLS                  tlsProbeFunc
	refreshServicePack        servicePackRefreshFunc
	discoverRouterOS          routerOSDiscoveryFunc
	discoverRouterOSContainer routerOSDiscoveryFunc
	checkPersistentMounts     func() (bool, []string)
	runtime                   runtimeApplier
	applyRouterOS             routerOSApplyFunc
	fetchCDNFeed              cdnfeed.Fetcher
	syncCDNFeed               cdnSourceSync

	connectionAddressCache connectionAddressCache
}

func NewServer(opts Options) (*Server, error) {
	repository, err := newStateRepository(opts.StateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize state repository: %w", err)
	}
	if err := repository.reconcileCommitPointers(); err != nil {
		return nil, fmt.Errorf("reconcile committed state: %w", err)
	}
	secrets, err := newSecretStore(opts.SecretsDir)
	if err != nil {
		return nil, fmt.Errorf("initialize secret store: %w", err)
	}
	key, err := signingKey(secrets)
	if err != nil {
		return nil, fmt.Errorf("load session key: %w", err)
	}
	sessions, err := newSessionCodec(key)
	if err != nil {
		return nil, err
	}
	routeSimulator, err := newRouteSimulator()
	if err != nil {
		return nil, fmt.Errorf("initialize route simulator: %w", err)
	}
	server := &Server{
		opts:                  opts,
		repository:            repository,
		secrets:               secrets,
		sessions:              sessions,
		login:                 newLoginGuard(5, 5*time.Minute),
		mux:                   http.NewServeMux(),
		now:                   time.Now,
		trafficReadyAfter:     time.Now().UTC(),
		fetchSubscription:     newSubscriptionFetcher(),
		subscriptionWake:      make(chan struct{}, 1),
		xrayLoggingWake:       make(chan struct{}, 1),
		fetchViaProxy:         newSubscriptionProxyFetcher(),
		routeSimulator:        routeSimulator,
		probeTLS:              probeTLSEndpoint,
		checkPersistentMounts: appliancePersistentMountsWritable,
		fetchCDNFeed:          cdnfeed.NewFetcher(),
		refreshServicePack: func(pack rulesets.ServicePack, root string) (map[string]any, error) {
			return rulesets.RefreshPack(pack, root, rulesets.HTTPFetch(rulesets.OptionsFromEnvironment().Timeout))
		},
	}
	server.selectUpdateExit = server.selectSubscriptionUpdateExit
	server.discoverRouterOS = server.fetchRouterOSDiscovery
	server.discoverRouterOSContainer = server.fetchRouterOSContainer
	if opts.Controller != nil {
		runtime, runtimeErr := newNativeRuntime(opts.Runtime, secrets, opts.Controller)
		if runtimeErr != nil {
			return nil, fmt.Errorf("initialize native runtime: %w", runtimeErr)
		}
		server.runtime = runtime
	}
	server.applyRouterOS = server.runRouterOSApply
	server.syncSubscriptionEndpoints = server.runSubscriptionEndpointSync
	server.syncCDNFeed = server.syncRouterOSCDNFeed
	if err := cleanupRecoverySnapshotDirectories(server.recoveryArchiveSnapshotRoot()); err != nil {
		return nil, fmt.Errorf("clean recovery archive staging: %w", err)
	}
	server.routes()
	return server, nil
}

func Run(ctx context.Context, opts Options) error {
	server, err := NewServer(opts)
	if err != nil {
		return err
	}
	_, websiteServer, websiteListener, err := startWebsiteProxy(server.repository)
	if err != nil {
		return fmt.Errorf("start website masquerade helper: %w", err)
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	defer websiteListener.Close()
	go server.runSubscriptionScheduler(runContext)
	go server.runRouterOSLiveNetworkScheduler(runContext)
	go server.runCDNFeedScheduler(runContext)
	go server.runACMEScheduler(runContext)
	if server.runtime != nil {
		go server.runXrayLoggingScheduler(runContext)
	}
	httpServer := &http.Server{
		Addr:              net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)),
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		// Image and recovery archives are streamed through nginx without
		// request buffering. Keep the server-level body deadline outside the
		// longest supported upload; per-route size limits still bound storage.
		ReadTimeout: controlPlaneReadTimeout,
		// Authenticated Apply, lifecycle and subscription refresh operations
		// have their own bounded deadlines and may legitimately exceed 30s,
		// especially while RouterOS is under load. Keep the connection alive
		// long enough to return their structured result instead of an nginx 502.
		WriteTimeout:   controlPlaneWriteTimeout,
		IdleTimeout:    90 * time.Second,
		MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context {
			return runContext
		},
	}
	websiteServer.BaseContext = func(net.Listener) context.Context {
		return runContext
	}
	errorChannel := make(chan error, 2)
	go func() {
		log.Printf("control-plane: listening on %s", httpServer.Addr)
		errorChannel <- httpServer.ListenAndServe()
	}()
	go func() {
		errorChannel <- websiteServer.Serve(websiteListener)
	}()
	shutdown := func() error {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer shutdownCancel()
		shutdownErr := errors.Join(websiteServer.Shutdown(shutdownCtx), httpServer.Shutdown(shutdownCtx))
		closeServer := func(value *http.Server) error {
			err := value.Close()
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
		return errors.Join(shutdownErr, closeServer(websiteServer), closeServer(httpServer))
	}
	select {
	case <-ctx.Done():
		return shutdown()
	case err := <-errorChannel:
		shutdownErr := shutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return shutdownErr
		}
		return errors.Join(err, shutdownErr)
	}
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := request.Header.Get("X-Request-ID")
	if requestID == "" {
		bytes := make([]byte, 12)
		if _, err := rand.Read(bytes); err == nil {
			requestID = hex.EncodeToString(bytes)
		} else {
			requestID = strconv.FormatInt(server.now().UnixNano(), 16)
		}
	}
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if request.ContentLength > maxRequestBytes && request.URL.Path != apiPrefix+"/lifecycle/image-upload" && request.URL.Path != apiPrefix+"/recovery/backups/upload" {
		server.writeError(response, requestID, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds the allowed safety limit.")
		return
	}
	if request.URL.Path == apiPrefix+"/lifecycle/image-upload" || request.URL.Path == apiPrefix+"/recovery/backups/upload" {
		controller := http.NewResponseController(response)
		_ = controller.SetReadDeadline(server.now().Add(controlPlaneReadTimeout))
		_ = controller.SetWriteDeadline(server.now().Add(10 * time.Minute))
	} else if request.URL.Path == apiPrefix+"/lifecycle/image-update" {
		// The recovery archive is a bounded local stream and must complete before
		// the RouterOS scheduler can be created.
		controller := http.NewResponseController(response)
		_ = controller.SetWriteDeadline(server.now().Add(lifecycleImageUpdateResponseTimeout))
	} else if request.URL.Path == apiPrefix+"/drafts/apply" || request.URL.Path == apiPrefix+"/drafts/rollback" {
		// The transaction is detached from a lost browser connection and bounded
		// independently. Extend only these authenticated operation responses.
		controller := http.NewResponseController(response)
		_ = controller.SetWriteDeadline(server.now().Add(applyResponseTimeout))
	} else if isSubscriptionRefreshRequest(request) {
		// A refresh is bounded by its own 30-second context. Keep the HTTP
		// response deadline outside that bound so an upstream timeout is returned
		// as a structured API error instead of being truncated into proxy 504.
		controller := http.NewResponseController(response)
		_ = controller.SetWriteDeadline(server.now().Add(subscriptionRefreshResponseTimeout))
	}
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, requestID))
	server.mux.ServeHTTP(response, request)
}

type requestIDKey struct{}

func (server *Server) routes() {
	server.mux.HandleFunc("GET /api/health/live", server.healthLive)
	server.mux.HandleFunc("GET /api/health/ready", server.readiness)
	server.mux.HandleFunc("GET /api/health/router-ready", server.routerReadiness)
	server.mux.HandleFunc("GET /api/health/traffic-ready", server.trafficReadiness)
	server.mux.HandleFunc("GET /{token}", server.publicRemoteSubscription)
	server.mux.HandleFunc("GET "+apiPrefix+"/health/live", server.healthLive)
	server.mux.HandleFunc("GET "+apiPrefix+"/health/ready", server.readiness)
	server.mux.HandleFunc("GET "+apiPrefix+"/auth/session", server.authSession)
	server.mux.HandleFunc("POST "+apiPrefix+"/auth/login", server.authLogin)
	server.mux.HandleFunc("POST "+apiPrefix+"/auth/login-form", server.authLoginForm)
	server.mux.HandleFunc("POST "+apiPrefix+"/auth/bootstrap", server.authBootstrap)
	server.mux.HandleFunc("POST "+apiPrefix+"/auth/password", server.authPassword)
	server.mux.HandleFunc("POST "+apiPrefix+"/auth/logout", server.authLogout)
	server.mux.HandleFunc("GET "+apiPrefix+"/status", server.status)
	server.mux.HandleFunc("GET "+apiPrefix+"/overview", server.overview)
	server.mux.HandleFunc("GET "+apiPrefix+"/bootstrap-state", server.bootstrapState)
	server.mux.HandleFunc("GET "+apiPrefix+"/lifecycle", server.lifecycleStatus)
	server.mux.HandleFunc("POST "+apiPrefix+"/lifecycle/image-upload/preflight", server.preflightLifecycleImageUpload)
	server.mux.HandleFunc("PUT "+apiPrefix+"/lifecycle/image-upload", server.uploadLifecycleImage)
	server.mux.HandleFunc("POST "+apiPrefix+"/lifecycle/image-update", server.scheduleLifecycleImageUpdate)
	server.mux.HandleFunc("GET "+apiPrefix+"/lifecycle/uninstall", server.uninstallPreview)
	server.mux.HandleFunc("POST "+apiPrefix+"/lifecycle/uninstall", server.scheduleFullUninstall)
	server.mux.HandleFunc("GET "+apiPrefix+"/client-telemetry", server.clientTelemetry)
	server.mux.HandleFunc("GET "+apiPrefix+"/drafts/current", server.currentDraft)
	server.mux.HandleFunc("PUT "+apiPrefix+"/drafts/current", server.putDraft)
	server.mux.HandleFunc("PATCH "+apiPrefix+"/drafts/current", server.patchDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/drafts/check", server.checkDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/drafts/plan", server.planDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/drafts/apply", server.applyDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/drafts/rollback", server.rollbackDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/drafts/reset", server.resetDraft)
	server.mux.HandleFunc("POST "+apiPrefix+"/route/simulate", server.simulateRoute)
	server.mux.HandleFunc("POST "+apiPrefix+"/network/tls-probe", server.probeTLSEndpoint)
	server.mux.HandleFunc("GET "+apiPrefix+"/tls-profiles/{entity}/acme", server.acmeStatus)
	server.mux.HandleFunc("POST "+apiPrefix+"/tls-profiles/{entity}/acme", server.configureACME)
	server.mux.HandleFunc("POST "+apiPrefix+"/tls-profiles/acme-dns/check", server.checkACMEDNSDelegations)
	server.mux.HandleFunc("POST "+apiPrefix+"/tls-profiles/{entity}/export", server.exportTLSProfile)
	server.mux.HandleFunc("POST "+apiPrefix+"/tls-profiles/import", server.importTLSProfile)
	server.mux.HandleFunc("POST "+apiPrefix+"/diagnostics", server.diagnostics)
	server.mux.HandleFunc("GET "+apiPrefix+"/runtime/xray-logs", server.xrayLogs)
	server.mux.HandleFunc("GET "+apiPrefix+"/runtime/system-logs", server.systemLogs)
	server.mux.HandleFunc("POST "+apiPrefix+"/service-packs/resolve", server.resolveServicePack)
	server.mux.HandleFunc("POST "+apiPrefix+"/routeros/credentials", server.provisionRouterOSCredentials)
	server.mux.HandleFunc("POST "+apiPrefix+"/routeros/import", server.importRouterOSExport)
	server.mux.HandleFunc("GET "+apiPrefix+"/routeros/discover", server.routerOSDiscover)
	server.mux.HandleFunc("GET "+apiPrefix+"/routeros/container-status", server.routerOSContainerStatus)
	server.mux.HandleFunc("POST "+apiPrefix+"/runtime/watchdog", server.recordWatchdog)
	server.mux.HandleFunc("GET "+apiPrefix+"/reverse-vless-exits/{exit}/client-config", server.reverseVLESSClientConfig)
	server.mux.HandleFunc("GET "+apiPrefix+"/subscriptions/{subscription}/url", server.revealSubscriptionURL)
	server.mux.HandleFunc("POST "+apiPrefix+"/subscriptions/{subscription}/refresh", server.refreshSubscription)
	server.mux.HandleFunc("GET "+apiPrefix+"/subscriptions/{subscription}/nodes", server.subscriptionNodes)
	server.mux.HandleFunc("POST "+apiPrefix+"/transports/{transport}/http-path/reveal", server.revealTransportHTTPPath)
	server.mux.HandleFunc("POST "+apiPrefix+"/remote-users/{user}/subscription-link", server.remoteSubscriptionLink)
	server.mux.HandleFunc("POST "+apiPrefix+"/remote-users/{user}/subscription-link/rotate", server.rotateRemoteSubscriptionLink)
	server.mux.HandleFunc("GET "+apiPrefix+"/remote-users/{user}/exports", server.remoteUserExportMetadata)
	server.mux.HandleFunc("POST "+apiPrefix+"/remote-users/{user}/exports/download", server.downloadRemoteUserExports)
	server.mux.HandleFunc("GET "+apiPrefix+"/recovery/backups", server.recoveryBackups)
	server.mux.HandleFunc("POST "+apiPrefix+"/recovery/backups", server.createRecoveryBackup)
	server.mux.HandleFunc("GET "+apiPrefix+"/recovery/backups/{name}/download", server.downloadRecoveryBackup)
	server.mux.HandleFunc("PUT "+apiPrefix+"/recovery/backups/upload", server.uploadRecoveryBackup)
	server.mux.HandleFunc("POST "+apiPrefix+"/recovery/restore", server.restoreRecoveryBackup)
	server.mux.HandleFunc("GET "+apiPrefix+"/{collection}", server.listCollection)
	server.mux.HandleFunc("POST "+apiPrefix+"/{collection}", server.createCollectionItem)
	server.mux.HandleFunc("GET "+apiPrefix+"/{collection}/{entity}", server.getCollectionItem)
	server.mux.HandleFunc("PUT "+apiPrefix+"/{collection}/{entity}", server.updateCollectionItem)
	server.mux.HandleFunc("DELETE "+apiPrefix+"/{collection}/{entity}", server.deleteCollectionItem)
}

func (server *Server) healthLive(response http.ResponseWriter, _ *http.Request) {
	server.writeJSON(response, http.StatusOK, map[string]any{"live": true, "service": "sb-gateway-control-plane"})
}

func (server *Server) authSession(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.session(request)
	if !ok {
		server.writeJSON(response, http.StatusOK, map[string]any{
			"authenticated":      false,
			"user":               nil,
			"csrf_token":         nil,
			"bootstrap_required": !server.secrets.exists("admin-password-hash"),
		})
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"authenticated":      true,
		"user":               map[string]any{"username": payload["sub"], "role": "administrator"},
		"csrf_token":         payload["csrf_token"],
		"expires_at":         payload["exp"],
		"bootstrap_required": false,
	})
}

type loginFailure struct {
	status  int
	code    string
	message string
}

func (server *Server) authenticateAdministrator(request *http.Request, username, password string) (string, string, *loginFailure) {
	remote, _, _ := net.SplitHostPort(request.RemoteAddr)
	if remote == "" {
		remote = "unknown"
	}
	if !server.login.allowed(remote, server.now()) {
		return "", "", &loginFailure{http.StatusTooManyRequests, "login_rate_limited", "Too many login attempts; try again later."}
	}
	encoded, err := server.secrets.read("admin-password-hash", false)
	if err != nil {
		return "", "", &loginFailure{http.StatusServiceUnavailable, "secret_not_provisioned", "A required secret is unavailable or has unsafe permissions."}
	}
	if encoded == "" {
		return "", "", &loginFailure{http.StatusConflict, "bootstrap_required", "Create the first administrator through the protected bootstrap flow."}
	}
	if !hmac.Equal([]byte(username), []byte(server.opts.AdminUser)) || !verifyPassword(password, encoded) {
		server.login.failure(remote, server.now())
		server.audit(request, usernameOrAnonymous(username), "auth.login", "denied", map[string]any{"remote": remote})
		return "", "", &loginFailure{http.StatusUnauthorized, "invalid_credentials", "Username or password is invalid."}
	}
	server.login.success(remote)
	if _, err := server.ensureRecoveryProtection(password); err != nil {
		return "", "", &loginFailure{http.StatusInternalServerError, "recovery_protection_failed", "Encrypted recovery protection could not be initialized."}
	}
	token, csrf, err := server.sessions.issue(username, server.now())
	if err != nil {
		return "", "", &loginFailure{http.StatusInternalServerError, "internal_error", "The request could not be completed."}
	}
	server.audit(request, username, "auth.login", "ok", map[string]any{"remote": remote})
	return token, csrf, nil
}

func (server *Server) authLogin(response http.ResponseWriter, request *http.Request) {
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	token, csrf, failure := server.authenticateAdministrator(request, username, password)
	if failure != nil {
		server.writeErrorResponse(response, request, failure.status, failure.code, failure.message)
		return
	}
	server.setSessionCookie(response, token)
	server.writeJSON(response, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          map[string]any{"username": username, "role": "administrator"},
		"csrf_token":    csrf,
		"expires_in":    int64(server.sessions.ttl.Seconds()),
	})
}

func (server *Server) authLoginForm(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	if err := request.ParseForm(); err != nil {
		code := "invalid_form"
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			code = "request_too_large"
		}
		http.Redirect(response, request, "/?login_error="+code, http.StatusSeeOther)
		return
	}
	username := request.PostForm.Get("username")
	password := request.PostForm.Get("password")
	token, _, failure := server.authenticateAdministrator(request, username, password)
	if failure != nil {
		http.Redirect(response, request, "/?login_error="+failure.code, http.StatusSeeOther)
		return
	}
	server.setSessionCookie(response, token)
	http.Redirect(response, request, "/#/overview", http.StatusSeeOther)
}

func (server *Server) authBootstrap(response http.ResponseWriter, request *http.Request) {
	if !server.managementBearer(request) {
		server.writeErrorResponse(response, request, http.StatusUnauthorized, "management_bearer_required", "Management bootstrap authentication is required.")
		return
	}
	if server.secrets.exists("admin-password-hash") {
		server.writeErrorResponse(response, request, http.StatusConflict, "bootstrap_disabled", "Administrator bootstrap is permanently disabled after first use.")
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	username, _ := body["username"].(string)
	if username == "" {
		username = server.opts.AdminUser
	}
	password, _ := body["password"].(string)
	confirmation, _ := body["password_confirmation"].(string)
	if username != server.opts.AdminUser {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_bootstrap_user", fmt.Sprintf("The bootstrap username must be %q.", server.opts.AdminUser))
		return
	}
	if utf8.RuneCountInString(password) < 12 || strings.ContainsRune(password, '\x00') || password != confirmation {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "weak_bootstrap_password", "Password must contain at least 12 characters and match confirmation.")
		return
	}
	encoded, err := makePasswordHash(password, nil)
	if err != nil || server.secrets.write("admin-password-hash", encoded, false) != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	if _, err := server.ensureRecoveryProtection(password); err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "recovery_protection_failed", "Encrypted recovery protection could not be initialized.")
		return
	}
	token, csrf, err := server.sessions.issue(username, server.now())
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	server.setSessionCookie(response, token)
	server.audit(request, username, "auth.bootstrap", "ok", map[string]any{"one_time": true})
	server.writeJSON(response, http.StatusOK, map[string]any{
		"authenticated":      true,
		"bootstrap_required": false,
		"user":               map[string]any{"username": username, "role": "administrator"},
		"csrf_token":         csrf,
		"expires_in":         int64(server.sessions.ttl.Seconds()),
	})
}

func (server *Server) authPassword(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	server.passwordMu.Lock()
	defer server.passwordMu.Unlock()

	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	currentPassword, _ := body["current_password"].(string)
	newPassword, _ := body["new_password"].(string)
	confirmation, _ := body["password_confirmation"].(string)
	encoded, err := server.secrets.read("admin-password-hash", false)
	if err != nil || encoded == "" || !verifyPassword(currentPassword, encoded) {
		server.writeErrorResponse(response, request, http.StatusForbidden, "administrator_password_invalid", "Current administrator password is invalid.")
		return
	}
	if utf8.RuneCountInString(newPassword) < 12 || strings.ContainsRune(newPassword, '\x00') || newPassword != confirmation {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "weak_administrator_password", "New password must contain at least 12 characters and match confirmation.")
		return
	}
	if verifyPassword(newPassword, encoded) {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "administrator_password_unchanged", "Choose a password different from the current one.")
		return
	}
	newHash, err := makePasswordHash(newPassword, nil)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	newSigningKey := make([]byte, 32)
	if _, err := rand.Read(newSigningKey); err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	codec, err := newSessionCodec(newSigningKey)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	token, csrf, err := codec.issue(server.opts.AdminUser, server.now())
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	if _, err := server.rewrapRecoveryProtection(currentPassword, newPassword); err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "recovery_protection_failed", "Encrypted recovery protection could not be updated.")
		return
	}
	if err := server.secrets.write("admin-password-hash", newHash, true); err != nil {
		_, _ = server.rewrapRecoveryProtection(newPassword, currentPassword)
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	if err := server.secrets.write("session-signing-key", base64.RawURLEncoding.EncodeToString(newSigningKey), true); err != nil {
		_ = server.secrets.write("admin-password-hash", encoded, true)
		_, _ = server.rewrapRecoveryProtection(newPassword, currentPassword)
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	server.mu.Lock()
	server.sessions = codec
	server.mu.Unlock()
	server.setSessionCookie(response, token)
	server.audit(request, fmt.Sprint(payload["sub"]), "auth.password_changed", "ok", map[string]any{"all_other_sessions_invalidated": true})
	server.writeJSON(response, http.StatusOK, map[string]any{
		"authenticated": true,
		"user": map[string]any{
			"username": server.opts.AdminUser,
			"role":     "administrator",
		},
		"csrf_token":                     csrf,
		"expires_in":                     int64(codec.ttl.Seconds()),
		"all_other_sessions_invalidated": true,
	})
}

func (server *Server) authLogout(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: server.opts.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
	server.audit(request, fmt.Sprint(payload["sub"]), "auth.logout", "ok", nil)
	server.writeJSON(response, http.StatusOK, map[string]any{"authenticated": false})
}

func (server *Server) session(request *http.Request) (map[string]any, bool) {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	server.mu.RLock()
	codec := server.sessions
	server.mu.RUnlock()
	return codec.decode(cookie.Value, server.now())
}

func (server *Server) requireSession(response http.ResponseWriter, request *http.Request) (map[string]any, bool) {
	payload, ok := server.session(request)
	if !ok {
		server.writeErrorResponse(response, request, http.StatusUnauthorized, "authentication_required", "Authentication is required.")
	}
	return payload, ok
}

func (server *Server) requireCSRF(response http.ResponseWriter, request *http.Request) (map[string]any, bool) {
	payload, ok := server.requireSession(response, request)
	if !ok {
		return nil, false
	}
	server.mu.RLock()
	valid := server.sessions.verifyCSRF(payload, request.Header.Get(csrfHeader))
	server.mu.RUnlock()
	if !valid {
		server.writeErrorResponse(response, request, http.StatusForbidden, "csrf_failed", "A valid X-CSRF-Token header is required.")
		return nil, false
	}
	return payload, true
}

func (server *Server) managementBearer(request *http.Request) bool {
	authorization := request.Header.Get("Authorization")
	if len(authorization) < 8 || !strings.EqualFold(authorization[:7], "Bearer ") {
		return false
	}
	expected, err := server.secrets.read("management-api-token", false)
	return err == nil && expected != "" && hmac.Equal([]byte(strings.TrimSpace(authorization[7:])), []byte(expected))
}

func (server *Server) setSessionCookie(response http.ResponseWriter, token string) {
	http.SetCookie(response, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(server.sessions.ttl.Seconds()),
		HttpOnly: true, Secure: server.opts.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func (server *Server) readObject(response http.ResponseWriter, request *http.Request, limit int64) (map[string]any, bool) {
	limited := http.MaxBytesReader(response, request.Body, limit)
	decoder := json.NewDecoder(limited)
	decoder.UseNumber()
	value := map[string]any{}
	if err := decoder.Decode(&value); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			server.writeErrorResponse(response, request, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds the allowed safety limit.")
			return nil, false
		}
		server.writeErrorResponse(response, request, http.StatusBadRequest, "invalid_json", "JSON body is required.")
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		server.writeErrorResponse(response, request, http.StatusBadRequest, "invalid_json", "Request body must contain one JSON object.")
		return nil, false
	}
	return value, true
}

func (server *Server) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	encoder := json.NewEncoder(response)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func (server *Server) writeErrorResponse(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	requestID, _ := request.Context().Value(requestIDKey{}).(string)
	server.writeError(response, requestID, status, code, message)
}

func (server *Server) writeError(response http.ResponseWriter, requestID string, status int, code, message string) {
	server.writeJSON(response, status, map[string]any{"error": map[string]any{
		"code": code, "message": message, "details": []any{}, "request_id": requestID,
	}})
}

func (server *Server) audit(request *http.Request, actor, action, outcome string, details map[string]any) {
	requestID, _ := request.Context().Value(requestIDKey{}).(string)
	_ = server.repository.appendAudit(map[string]any{
		"timestamp": server.now().UTC().Format(time.RFC3339Nano),
		"actor":     actor, "action": action, "outcome": outcome,
		"request_id": requestID, "details": detailsOrEmpty(details),
	})
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	return value != "0" && value != "false" && value != "no"
}

func boundedEnvInt(name string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func usernameOrAnonymous(value string) string {
	if value == "" {
		return "anonymous"
	}
	return value
}

func detailsOrEmpty(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func touch(path string) {
	now := time.Now()
	if err := os.Chtimes(path, now, now); err == nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_ = file.Close()
	}
}

type loginGuard struct {
	mu       sync.Mutex
	attempts int
	window   time.Duration
	events   map[string][]time.Time
}

func newLoginGuard(attempts int, window time.Duration) *loginGuard {
	return &loginGuard{attempts: attempts, window: window, events: make(map[string][]time.Time)}
}

func (guard *loginGuard) allowed(key string, now time.Time) bool {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.prune(key, now)
	return len(guard.events[key]) < guard.attempts
}

func (guard *loginGuard) failure(key string, now time.Time) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.prune(key, now)
	guard.events[key] = append(guard.events[key], now)
}

func (guard *loginGuard) success(key string) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	delete(guard.events, key)
}

func (guard *loginGuard) prune(key string, now time.Time) {
	values := guard.events[key]
	cutoff := now.Add(-guard.window)
	first := 0
	for first < len(values) && !values[first].After(cutoff) {
		first++
	}
	guard.events[key] = values[first:]
}
