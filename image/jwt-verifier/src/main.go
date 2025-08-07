// Package main implements a JWT token verification service that validates tokens from both Azure AD
// and Curity authentication providers. It supports automatic key rotation and provides metrics
// for monitoring token validation operations.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.elastic.co/ecszerolog"
)

// JwkAutoRefresh interface defines methods for automatic key refresh operations
type JwkAutoRefresh interface {
	Configure(url string, options ...jwk.AutoRefreshOption)
	Fetch(ctx context.Context, url string) (jwk.Set, error)
	Refresh(ctx context.Context, url string) (jwk.Set, error)
	ErrorSink(ch chan jwk.AutoRefreshError)
}

const (
	service = "JwtVerifier"
)

var (
	// Context name for logging
	ctxName string = fmt.Sprintf("%s.%s-%s", os.Getenv("NAMESPACE"), service, xid.New().String())

	// Logger instance with context
	logger zerolog.Logger = ecszerolog.New(os.Stdout).With().Str("ctx", ctxName).Logger()

	// Key set auto-refresh interface
	keySetAutoRefresh JwkAutoRefresh

	// Atomic boolean to track if keys are loaded
	keysLoaded atomic.Bool

	// Mutex for forced refresh operations
	forceRefreshLock sync.Mutex

	// Timestamp of last forced refresh
	lastForcedRefresh time.Time

	// Minimum time between forced refreshes
	forcedRefreshThreshold time.Duration = 5 * time.Minute

	// Global context and configuration
	cancellableContext   context.Context
	jwksUrl              string //jwks url of ms azure ad
	keySetAutoRefreshMap map[string]JwkAutoRefresh
)

// Prometheus metrics for monitoring
var (
	// Counter to keep track of no of invalid jwt tokens received. Requests with no tokens are also counted.
	invalidJwtTokenCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "invalid_jwt_token_requests",
			Help: "No of invalid jwt tokens received",
		},
	)

	// Counter to keep track of no of forced key refreshes
	forcedKeyRefreshCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "forced_key_refreshes",
			Help: "No of forced key refreshes",
		},
	)

	// Counter to keep track of key not found errors
	keyNotFoundErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "key_not_found_errors",
			Help: "No of key not found errors",
		},
	)

	// Counter to keep track of key fetch errors
	keyFetchErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "key_fetch_errors",
			Help: "No of key fetch errors",
		},
	)

	// Counter for total requests
	totalRequestsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "total_jwt_token_requests",
			Help: "Total no of jwt tokens received",
		},
	)
)

// fetches the JWKS from the sidecar for Curity tokens
func fetchJWKS(token, tenant string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/jwks?tenant_id=%s", getEnv("AUTH_RESOLVER_URL"), tenant)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: received status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// getEnv retrieves an environment variable with an optional fallback value
func getEnv(key string, fallback ...string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	logger.Fatal().Msg(fmt.Sprintf("Environment variable %s is not set", key))
	return ""
}

// setupKeysListener configures automatic key refresh for JWKS for Azure tokens
func setupKeysListener(jwksUrl string) {

	refreshMinutes := safeStringToInt(getEnv("KEY_FETCH_REFRESH_MINUTES", "60"), 60)

	if refreshMinutes < 5 {
		logger.Warn().Msg("KEY_FETCH_REFRESH_MINUTES cannot be lower than 5 minutes. Defaulting to 5 minutes")
		refreshMinutes = 5
	}

	keySetAutoRefresh = jwk.NewAutoRefresh(cancellableContext)
	keySetAutoRefresh.Configure(
		jwksUrl,
		jwk.WithRefreshInterval(time.Duration(refreshMinutes)*time.Minute),
		jwk.WithFetchBackoff(backoff.Exponential()),
	)

	var err error

	// create an error channel to listen for errors
	errorChn := make(chan jwk.AutoRefreshError)

	keySetAutoRefresh.ErrorSink(errorChn)

	// create a go routine to read the error channel and log any errors
	go func() {
		for {
			select {
			case <-cancellableContext.Done():
				return
			case err := <-errorChn:
				logger.Error().Msgf("Error fetching jwks: %v", err)
				keyFetchErrorCounter.Inc()
			}
		}
	}()

	startupTime := time.Now()
	timeout := time.Duration(safeStringToInt(getEnv("KEY_FETCH_TIMEOUT_SECONDS", "60"), 60)) * time.Second

	lastForcedRefresh = time.Now().Add(-forcedRefreshThreshold * 2)

	for time.Since(startupTime) < timeout {
		_, err = keySetAutoRefresh.Fetch(cancellableContext, jwksUrl)

		if err != nil {
			logger.Error().Msgf("Unable to fetch jwk. Error is %v", err)
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}

	if err != nil {
		logger.Fatal().Msg("timed out fetching jwks.")
	}

	keysLoaded.Store(true)

	logger.Info().
		Str("service", service).
		Msg("Service ready")
}

// router sets up the HTTP routes and handlers
func router(expectedClaims map[string]string, expectedIssuer string) *mux.Router {

	prometheus.MustRegister(invalidJwtTokenCounter)
	prometheus.MustRegister(totalRequestsCounter)

	r := mux.NewRouter()
	r.HandleFunc("/", handleAuth(expectedClaims, expectedIssuer)).Methods("GET")
	r.HandleFunc("/{name:_external-auth-[A-Za-z0-9_-]+}", handleAuth(expectedClaims, expectedIssuer)).Methods("GET")
	r.HandleFunc("/healthz", healthz).Methods("GET")
	r.HandleFunc("/readyz", readyz()).Methods("GET")
	r.Handle("/metrics", promhttp.Handler())
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		logger.Info().
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Str("uri", r.RequestURI).
			Msg("Not found")
	})

	return r
}

// checkToken validates a JWT token and its claims
// Here it will check the token is from azure ad or curity
func checkToken(token string, expectedClaims map[string]string, expectedIssuer string, reqLogger zerolog.Logger, jwksUrl string) (bool, error) {
	if len(token) == 0 {
		return false, fmt.Errorf("empty or no token in request")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode payload: %v", err)
	}

	var claimsMap map[string]any
	if err := json.Unmarshal(payload, &claimsMap); err != nil {
		return false, fmt.Errorf("failed to parse JSON payload: %v", err)
	}

	iss, ok := claimsMap["iss"].(string)
	if !ok {
		return false, fmt.Errorf("issuer (iss) claim missing or not a string")
	}

	// Branch logic based on issuer
	if !strings.Contains(iss, "https://sts.windows.net") {
		return validateCurityToken(token, parts, claimsMap, expectedClaims, expectedIssuer, jwksUrl, reqLogger)
	} else {
		return validateAzureToken(token, expectedClaims, expectedIssuer, jwksUrl, reqLogger)
	}
}

// validateCurityToken validates tokens issued by Curity
func validateCurityToken(token string, parts []string, claimsMap map[string]any, expectedClaims map[string]string, expectedIssuer string, jwksUrl string, reqLogger zerolog.Logger) (bool, error) {
	// For Curity tokens
	if claimsMap["tenant_id"] == nil {
		reqLogger.Info().Msg("Missing tenant claim in token")
		return false, fmt.Errorf("missing tenant claim")
	}

	reqLogger.Debug().Msg("Fetching JWKS from sidecar for Curity token validation")
	// Fetch JWKS from sidecar
	jwksBytes, err := fetchJWKS(token, claimsMap["tenant_id"].(string))
	if err != nil {
		reqLogger.Error().Err(err).Msg("Failed to fetch JWKS from sidecar")
		return false, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	// Parse JWKS response
	keySet, err := jwk.Parse(jwksBytes)
	if err != nil {
		reqLogger.Error().Err(err).Msg("Failed to parse JWKS as key set")
		return false, fmt.Errorf("failed to parse JWKS as key set: %v", err)
	}

	// Parse and verify token signature using JWKS
	t, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.InferAlgorithmFromKey(true))
	if err != nil {
		if strings.Contains(err.Error(), "failed to find key with key ID") || strings.Contains(err.Error(), "failed to match any of the keys") {
			reqLogger.Warn().Err(err).Msg("Key not found for token validation")
			keyNotFoundErrorCounter.Inc()
		}
		reqLogger.Error().Err(err).Msg("Failed to verify token signature")
		return false, fmt.Errorf("failed to verify token signature: %v", err)
	}

	// Check required claims
	for key, value := range expectedClaims {
		claim, exists := t.Get(key)
		if !exists {
			reqLogger.Info().Str("claim", key).Msg("Required claim does not exist")
			return false, fmt.Errorf("claim %s does not exist", key)
		}
		if claim.(string) != value {
			return false, fmt.Errorf("claim %s does not match expected value %s. Got %s", key, value, claim)
		}
	}

	return true, nil
}

// validateAzureToken validates tokens issued by Azure AD
func validateAzureToken(token string, expectedClaims map[string]string, expectedIssuer string, jwksUrl string, reqLogger zerolog.Logger) (bool, error) {
	keySet, err := keySetAutoRefresh.Fetch(cancellableContext, jwksUrl)
	if err != nil {
		reqLogger.Fatal().Msgf("Unable to fetch jwk. Error is %v", err)
	}

	t, err := jwt.ParseString(token, jwt.WithKeySet(keySet), jwt.InferAlgorithmFromKey(true))

	if err != nil {
		if strings.Contains(err.Error(), "failed to find key with key ID") || strings.Contains(err.Error(), "failed to match any of the keys") {
			succeeded := false
			keyNotFoundErrorCounter.Inc()
			func() {
				forceRefreshLock.Lock()
				defer forceRefreshLock.Unlock()
				if time.Since(lastForcedRefresh) < forcedRefreshThreshold {
					reqLogger.Info().Msg("keys updated recently, skipping forced refresh")
					succeeded = false
					return
				}
				reqLogger.Warn().Msg("Forcing key refresh..")
				lastForcedRefresh = time.Now()
				keySet, err = keySetAutoRefresh.Refresh(cancellableContext, jwksUrl)
				if err != nil {
					reqLogger.Fatal().Msgf("Unable to fetch keys. Error is %v", err)
				}
				succeeded = true
				forcedKeyRefreshCounter.Inc()
			}()

			if !succeeded {
				return false, nil
			}

			t, err = jwt.ParseString(token, jwt.WithKeySet(keySet), jwt.InferAlgorithmFromKey(true))

			if err != nil {
				reqLogger.Info().Err(err).Msg("failed to parse token")
				return false, err
			}
		} else {
			reqLogger.Info().Err(err).Msg("failed to parse token")
			return false, err
		}
	}

	if err := jwt.Validate(t, jwt.WithIssuer(expectedIssuer), jwt.WithAcceptableSkew(5*time.Minute)); err != nil {
		reqLogger.Info().Err(err).Msg("failed to validate token")
		return false, fmt.Errorf("token is invalid")
	}

	reqLogger.Debug().Msg("Signature is valid, checking claims..")

	for key, value := range expectedClaims {
		claim, exists := t.Get(key)
		if !exists {
			return false, fmt.Errorf("claim %s does not exist", key)
		}
		if claim.(string) != value {
			return false, fmt.Errorf("claim %s does not match expected value %s. Got %s", key, value, claim)
		}
	}

	return true, nil
}

// getBearerToken extracts the Bearer token from the Authorization header
func getBearerToken(r *http.Request, reqLogger zerolog.Logger) string {
	header := r.Header.Get("Authorization")

	if header == "" {
		reqLogger.Info().Msg("No Authorization header found..")
		return ""
	}

	reqLogger.Debug().
		Str("header", header).
		Msg("Authorization header found..")
	if !strings.HasPrefix(header, "Bearer ") {
		reqLogger.Info().Msg("Authorization header does not start with 'Bearer '")
		return ""
	}

	token := header[7:]
	if len(token) == 0 {
		reqLogger.Info().Msg("Empty token after Bearer prefix")
		return ""
	}

	return token
}

// handleAuth processes authentication requests
func handleAuth(expectedClaims map[string]string, expectedIssuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if !keysLoaded.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		reqLogger := logger.With().
			Str("trace.id", r.Header.Get("X-Request-Id")).
			Logger()

		reqLogger.Debug().
			Msg("Checking token..")

		tokenValid, err := checkToken(
			getBearerToken(r, reqLogger),
			expectedClaims,
			expectedIssuer,
			reqLogger,
			jwksUrl,
		)

		//Return all http headers back to the client
		for key, values := range r.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		if tokenValid {
			reqLogger.Debug().
				Msg("Token is valid")
			w.WriteHeader(http.StatusOK)
		} else {
			invalidJwtTokenCounter.Inc()
			w.WriteHeader(http.StatusUnauthorized)
			reqLogger.Warn().
				Err(err).
				Msg("Authentication failed")
		}
		totalRequestsCounter.Inc()
	}
}

// healthz handles health check requests
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// readyz handles readiness check requests
func readyz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !keysLoaded.Load() {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// getShutdownTimeout gets the shutdown timeout duration
func getShutdownTimeout(timeout string) time.Duration {
	iTimeout := safeStringToInt(timeout, 2)
	return time.Duration(iTimeout)
}

// getPort gets the server port number
func getPort(port string) int {
	return safeStringToInt(port, 8080)
}

// safeStringToInt safely converts a string to an integer with a default value
func safeStringToInt(value string, defaultValue int) int {
	intValue, err := strconv.Atoi(value)
	if err != nil {
		logger.Warn().Msg(fmt.Sprintf("Invalid value '%s', defaulting to %d", value, defaultValue))
		return defaultValue
	}
	return intValue
}

// configGoGC configures Go's garbage collector based on available memory
func configGoGC() {
	var memory uint64
	if cgroups.Mode() != cgroups.Unified {
		logger.Debug().Msg("V1 cgroups")
		control, err := cgroups.Load(cgroups.V1, cgroups.StaticPath("/"))

		if err == nil {
			logger.Debug().Msg("cgroup loaded")
			metrics, err := control.Stat(cgroups.IgnoreNotExist)

			if err == nil {
				memory = metrics.Memory.Usage.Limit
				logger.Info().Msgf("Available memory %d bytes", memory)
			} else {
				logger.Error().Err(err).Msg("Failed to stat cgroup")
			}
		}
	} else {
		logger.Info().Msg("V2 cgroups")
		control, err := cgroup2.Load("/")

		if err == nil {
			logger.Info().Msg("cgroup loaded")
			metrics, err := control.Stat()

			if err == nil {
				memory = metrics.Memory.UsageLimit
				logger.Info().Msgf("Available memory %d bytes", memory)
			} else {
				logger.Error().Err(err).Msg("Failed to stat cgroup")
			}
		}
	}

	osMemBytes := int64(safeStringToInt(getEnv("MEM_BYTES", "20000000"), 20000000)) // defaults to 20MB
	osMemEnv := os.Getenv("OSMEMBYTES")
	if osMemEnv != "" {
		value, err := strconv.ParseInt(osMemEnv, 10, 64)

		if err == nil {
			osMemBytes = value
		}
	}

	memLimit := os.Getenv("GOMEMLIMIT")
	if memLimit == "" && memory != 0 {
		limit := int64(memory) - osMemBytes
		logger.Info().Msgf("Setting memory limit automatically to %d bytes", limit)
		debug.SetMemoryLimit(limit) // subtract 10MB for system
	} else {
		logger.Info().Msgf("Memory limit set to %s", memLimit)
	}

	str := os.Getenv("GOGC")
	if str != "" {
		logger.Info().Msgf("GC percentage set to %s", str)
	}
}

// main is the entry point of the application
func main() {

	var cancelFn context.CancelFunc

	cancellableContext, cancelFn = context.WithCancel(context.Background())
	defer cancelFn()

	logLevel, err := zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel // default to INFO
	}
	zerolog.SetGlobalLevel(logLevel)

	configGoGC()

	logger.Info().Msg("JWT validator initializing..")
	shutdownTimeout := flag.Duration("shutdown-timeout", getShutdownTimeout(getEnv("SHUTDOWN_TIMEOUT", "2"))*time.Second, "shutdown timeout (5s,5m,5h) before connections are cancelled")
	port := getPort(getEnv("PORT", "8080"))

	jwksUrl = getEnv("JWKS_URL")

	if jwksUrl == "" {
		logger.Fatal().Msg("JWKS_URL is not set")
		panic("JWKS_URL is not set")
	}

	authResolverUrl := getEnv("AUTH_RESOLVER_URL")
	if authResolverUrl == "" {
		logger.Fatal().Msg("AUTH_RESOLVER_URL is not set")
		panic("AUTH_RESOLVER_URL is not set")
	}

	expectedIssuer := getEnv("ISSUER")

	if expectedIssuer == "" {
		logger.Fatal().Msg("ISSUER is not set")
		panic("ISSUER is not set")
	}

	forcedRefreshThreshold = time.Duration(safeStringToInt(getEnv("FORCED_REFRESH_THRESHOLD_MINUTES", "5"), 5)) * time.Minute

	if forcedRefreshThreshold < 5*time.Minute {
		logger.Warn().Msg("FORCED_REFRESH_THRESHOLD_MINUTES cannot be lower than 5 minutes. Defaulting to 5 minutes")
		forcedRefreshThreshold = 5 * time.Minute
	}

	expectedClaims := map[string]string{}

	logger.Info().
		Msg(fmt.Sprintf("expected token Issuer is %s", expectedIssuer))

	logger.Info().Msg("JWT validator starting..")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	setupKeysListener(jwksUrl)

	r := router(expectedClaims, expectedIssuer)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				logger.Fatal().Msgf("Failed to start server: %v", err)
			}
		}
	}()

	killSignal := <-interrupt
	switch killSignal {
	case os.Interrupt:
		logger.Info().Msg("Got SIGINT...")
	case syscall.SIGTERM:
		logger.Info().Msg("Got SIGTERM...")
	}

	cancelFn()

	logger.Info().Msg(fmt.Sprintf("%s shutting down ...\n", service))

	ctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal().Msgf("Failed to gracefully shutdown: %v", err)
	}

	logger.Info().Msg(fmt.Sprintf("The %s is shutting down...", service))
	srv.Shutdown(context.Background())
	logger.Info().Msg(fmt.Sprintf("%s is down", service))
}
