package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.elastic.co/ecszerolog"
)

const (
	service = "Jwk-provider"
)

var (
	ctxName                 string = fmt.Sprintf("%s.%s-%s", os.Getenv("NAMESPACE"), service, xid.New().String())
	logger                         = ecszerolog.New(os.Stdout).With().Str("ctx", ctxName).Logger()
	keysLock                sync.Mutex
	publicSet               jwk.Set = jwk.NewSet()
	privateSet              jwk.Set = jwk.NewSet()
	allowedAzureGroups      map[string]bool
	allowedObjectIds        map[string]bool
	allowedAzureUsers       map[string]bool
	allowedAzureAudiences   map[string]bool
	allowedTenantId         string
	externalKeysLoaded      atomic.Bool
	audienceValidationRegex *regexp.Regexp
	issuer                  = ""
	cancellableContext      context.Context
	keySetAutoRefresh       *jwk.AutoRefresh
	forceRefreshLock        sync.Mutex
	lastForcedRefresh       time.Time
	forcedRefreshThreshold  time.Duration = 5 * time.Minute
	jwksUrl                 string
)

func generateKey() (jwk.Key, error) {
	logger.Info().
		Msg("Generating RSA key")

	raw, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		logger.Fatal().Msg("Failed to generate RSA key")
		return nil, fmt.Errorf("failed to generate RSA key %w", err)
	}

	key, err := jwk.New(raw)

	if err != nil {
		logger.Fatal().Msg("Failed to create JWK key")
		return nil, fmt.Errorf("failed to create JWK key %w", err)
	}

	return key, nil
}

func setupKeyWatcher(path string, ctx context.Context) error {

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return waitForFileCreation(ctx, path)
	}

	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		logger.Fatal().
			Str("path", path).
			Msg("Failed to create watcher")
		return fmt.Errorf("failed to create watcher %w", err)
	}

	go func() {
		<-ctx.Done()
		watcher.Close()
	}()

	err = watcher.Add(path)

	if err != nil {
		logger.Fatal().
			Str("path", path).
			Msg("Failed to watch file")
		return fmt.Errorf("failed to watch file %w", err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
					logger.Info().
						Str("path", path).
						Msg("File modified")

					err := readKey(path)

					if err != nil {
						logger.Error().
							Err(err).
							Str("path", path).
							Msg("Failed to read key")
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error().
					Err(err).
					Str("path", path).
					Msg("Watcher error")
			}
		}
	}()

	return readKey(path)
}

func waitForFileCreation(ctx context.Context, path string) error {
	timeoutStr := os.Getenv("KEY_CREATION_TIMEOUT_SECONDS")
	if timeoutStr == "" {
		timeoutStr = "5m"
	}

	var timeout time.Duration

	timeout, err := time.ParseDuration(timeoutStr)

	if err != nil {
		return fmt.Errorf("failed to parse KEY_CREATION_TIMEOUT_SECONDS %w", err)
	}

	done := make(chan struct{})
	var waitErr error = nil

	go func() {
		start := time.Now()
		for {
			if _, err := os.Stat(path); err == nil {
				waitErr = setupKeyWatcher(path, ctx)
				break
			}

			if time.Since(start) > timeout {
				waitErr = fmt.Errorf("timed out waiting for key file creation")
				break
			}

			time.Sleep(500 * time.Millisecond)

			if ctx.Err() != nil {
				break
			}
		}

		done <- struct{}{}
	}()

	<-done

	return waitErr
}

func readKey(path string) error {

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("pem file not found %w", err)
	}

	set, err := jwk.ReadFile(path, jwk.WithPEM(true))

	if err != nil {
		return fmt.Errorf("failed to parse key in PEM format %w", err)
	}

	logger.Info().
		Str("path", path).
		Msg("RSA key loaded")

	key, _ := set.Get(0)

	return updateKeySets(key)
}

func updateKeySets(key jwk.Key) error {

	keysLock.Lock()
	defer keysLock.Unlock()

	var use = jwk.ForSignature

	key.Set(jwk.KeyIDKey, use.String())
	key.Set(jwk.KeyUsageKey, use)

	privateSet = jwk.NewSet()
	privateSet.Add(key)

	pub, err := key.PublicKey()

	pub.Set(jwk.KeyIDKey, use.String())

	if err != nil {
		logger.Fatal().Msg("Failed to get public key")
		return fmt.Errorf("failed to get public key %w", err)
	}

	publicSet = jwk.NewSet()
	publicSet.Add(pub)

	return nil
}

func setupKeys(ctx context.Context) error {

	path := os.Getenv("PRIVATE_KEY_PATH")

	if path != "" {
		err := setupKeyWatcher(path, ctx)

		if err != nil {
			return fmt.Errorf("failed to setup key watcher %w", err)
		}
	} else {
		key, err := generateKey()

		if err != nil {
			return fmt.Errorf("failed to generate key %w", err)
		}

		err = updateKeySets(key)

		if err != nil {
			return fmt.Errorf("failed to update key sets %w", err)
		}
	}

	return nil
}

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

func createHandler() *mux.Router {

	r := mux.NewRouter()
	r.HandleFunc("/keys", handleGetKeys()).Methods("GET")
	r.HandleFunc("/token", handleToken()).Methods("POST")
	r.HandleFunc("/validate", validateToken()).Methods("POST")
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

func validateToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		err := authorizeAzureToken(r)
		if err != nil {
			logger.Error().Err(err).Msg("Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// get the token to validate from the body
		if r.Header.Get("Content-Type") != "text/plain" {
			logger.Error().
				Str("content-type", r.Header.Get("Content-Type")).
				Msg("Invalid content type")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		logger.Info().
			Int("content-length", int(r.ContentLength)).
			Msg("Validating token")

		// read content length bytes from the body
		buf, err := io.ReadAll(r.Body)

		if err != nil {
			logger.Error().
				Err(err).
				Msg("Failed to read body")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		t, err := jwt.ParseString(string(buf), jwt.WithKeySet(publicSet), jwt.InferAlgorithmFromKey(true))

		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
			http.Error(w, "failed to parse payload", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/plain")

		serialized, err := json.Marshal(t)

		if err != nil {
			logger.Error().Msg("Failed to serialize token")
			http.Error(w, "failed to serialize token", http.StatusInternalServerError)
			return
		}

		w.Write(serialized)
	}
}

func handleToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// if there are external keys, then expect a bearer token. Verify it's signature using the external keys
		// set and verify the groups claim is present and any of the groups is on the ALLOWED_GROUPS list
		// remove the Bearer prefix
		// check if the groups claim is present
		err := authorizeAzureToken(r)
		if err != nil {
			logger.Error().Err(err).Msg("Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			logger.Error().
				Str("content-type", r.Header.Get("Content-Type")).
				Msg("Invalid content type")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		var payload map[string]interface{}

		err = json.NewDecoder(r.Body).Decode(&payload)

		if err != nil {
			logger.Error().Msg("Failed to decode json payload")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		_, ok := payload["sub"]
		if !ok {
			logger.Error().Msg("Payload does not have 'sub' key")
			http.Error(w, "payload must contain subject", http.StatusBadRequest)
			return
		}

		audience, ok := payload["aud"]
		if !ok || audience == "" {
			logger.Error().Msg("Payload does not have 'aud' key or it is empty")
			http.Error(w, "payload must contain audience", http.StatusBadRequest)
			return
		}

		if keySetAutoRefresh != nil && audienceValidationRegex != nil {
			audienceStr, ok := audience.(string)

			if !ok {
				logger.Error().Msg("Invalid audience")
				http.Error(w, "invalid audience", http.StatusBadRequest)
				return
			}

			if !audienceValidationRegex.MatchString(audienceStr) {
				logger.Error().Msg("Invalid audience")
				http.Error(w, "invalid audience", http.StatusBadRequest)
				return
			}
		}

		t := jwt.New()
		t.Set(jwt.IssuedAtKey, time.Now().Unix())
		t.Set(jwt.IssuerKey, issuer)

		shouldReturn := setExpiration(payload, t, w)
		if shouldReturn {
			return
		}

		for k, v := range payload {
			t.Set(k, v)
		}

		signingKey, _ := privateSet.LookupKeyID("sig")

		signed, err := jwt.Sign(t, jwa.RS512, signingKey)

		if err != nil {
			logger.Error().Msg("Failed to sign token")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")

		_, err = w.Write([]byte(signed))

		if err != nil {
			logger.Error().Msg("Failed to write token")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}

func loadAzureValidationInfo() error {

	allowedGroups := os.Getenv("ALLOWED_AZURE_GROUPS")
	allowedUsers := os.Getenv("ALLOWED_AZURE_USERS")
	allowedObjects := os.Getenv("ALLOWED_OBJECT_IDS")

	if allowedGroups == "" && allowedUsers == "" && allowedObjects == "" {
		return fmt.Errorf("no allowed groups, object ids or users set in environment variables ALLOWED_AZURE_GROUPS, ALLOWED_OBJECT_IDS and ALLOWED_AZURE_USERS")
	}

	if allowedUsers != "" {
		list := strings.Split(allowedUsers, ",")

		allowedAzureUsers = make(map[string]bool)

		for _, user := range list {
			allowedAzureUsers[user] = true
		}
	}

	if allowedGroups != "" {
		list := strings.Split(allowedGroups, ",")

		allowedAzureGroups = make(map[string]bool)

		for _, group := range list {
			allowedAzureGroups[group] = true
		}
	}

	if allowedObjects != "" {

		list := strings.Split(allowedObjects, ",")

		allowedObjectIds = make(map[string]bool)

		for _, objectId := range list {
			allowedObjectIds[objectId] = true
		}
	}

	allowedTenantId = os.Getenv("ALLOWED_TENANT_ID")

	if allowedTenantId == "" {
		return fmt.Errorf("no allowed tenant id set in environment variable ALLOWED_TENANT_ID")
	}

	allowedAudiences := os.Getenv("ALLOWED_AZURE_AUDIENCES")

	if allowedAudiences != "" {
		list := strings.Split(allowedAudiences, ",")

		allowedAzureAudiences = make(map[string]bool)

		for _, audience := range list {
			allowedAzureAudiences[audience] = true
		}
	} else {
		allowedAzureAudiences = make(map[string]bool)
		allowedAzureAudiences["https://management.core.windows.net/"] = true
	}

	return nil
}

func authorizeAzureToken(r *http.Request) error {
	if keySetAutoRefresh == nil {
		return nil
	}

	header := r.Header.Get("Authorization")

	if header == "" {
		return fmt.Errorf("no token provided")
	}

	header = header[7:]

	externalKeySet, err := keySetAutoRefresh.Fetch(cancellableContext, jwksUrl)

	if err != nil {
		logger.Fatal().Msgf("Unable to fetch jwk. Error is %v", err)
	}

	azToken, err := jwt.ParseString(header, jwt.WithKeySet(externalKeySet), jwt.InferAlgorithmFromKey(true))

	if err != nil {
		if strings.Contains(err.Error(), "failed to find key with key ID") || strings.Contains(err.Error(), "failed to match any of the keys") {
			succeeded := false

			func() {
				forceRefreshLock.Lock()
				defer forceRefreshLock.Unlock()
				if time.Since(lastForcedRefresh) < forcedRefreshThreshold {
					logger.Info().Msg("keys updated recently, skipping forced refresh")
					succeeded = false
					return
				}
				logger.Warn().Msg("Forcing key refresh..")
				lastForcedRefresh = time.Now()
				externalKeySet, err = keySetAutoRefresh.Refresh(cancellableContext, jwksUrl)
				if err != nil {
					logger.Fatal().Msgf("Unable to fetch keys. Error is %v", err)
				}
				succeeded = true
			}()

			if !succeeded {
				return fmt.Errorf("failed to find key with key ID")
			}

			azToken, err = jwt.ParseString(header, jwt.WithKeySet(externalKeySet), jwt.InferAlgorithmFromKey(true))

			if err != nil {
				logger.Info().
					Err(err).
					Msg("failed to parse token")
				return err
			}
		} else {
			logger.Info().
				Err(err).
				Msg("failed to parse token")
			return err
		}
	}

	if err := jwt.Validate(azToken, jwt.WithIssuer("https://sts.windows.net/"+allowedTenantId+"/"), jwt.WithAcceptableSkew(1*time.Minute)); err != nil {
		logger.Info().
			Err(err).
			Msg("failed to validate token")
		return fmt.Errorf("failed to validate token: %w", err)
	}

	logger.Debug().
		Msg("Signature is valid, checking claims..")

	tenantId, ok := azToken.Get("tid")

	if !ok {
		return fmt.Errorf("no tenant id in token")
	}

	if tenantId != allowedTenantId {
		return fmt.Errorf("invalid tenant id '%s' in token", tenantId)
	}

	// check it's a user or an app
	idtyp, ok := azToken.Get("idtyp")

	if !ok {
		return fmt.Errorf("no idtyp in token")
	}

	if idtyp != "user" && idtyp != "app" {
		return fmt.Errorf("invalid idtyp '%s' in token", idtyp)
	}

	tokenGroups, ok := azToken.Get("groups")

	if ok {
		logger.Info().Msg("Checking groups claim")

		groupsList, ok := tokenGroups.([]interface{})

		if !ok {
			return fmt.Errorf("groups claim is not a list")
		}

		for _, group := range groupsList {
			if _, ok := allowedAzureGroups[group.(string)]; ok {
				logger.Info().
					Str("group", group.(string)).
					Msg("User in allowed group")
				return nil
			}
		}
	}

	user, ok := azToken.Get("upn")

	if ok {
		if _, ok := allowedAzureUsers[user.(string)]; ok {
			logger.Info().
				Str("upn", user.(string)).
				Msg("User in allowed users")
			return nil
		}
	} else {
		logger.Info().Msg("No upn claim in token")
	}

	objectId, ok := azToken.Get("oid")

	if ok {
		if _, ok := allowedObjectIds[objectId.(string)]; ok {
			logger.Info().
				Str("oid", objectId.(string)).
				Msg("User in allowed object ids")
			return nil
		}
	} else {
		logger.Info().Msg("No oid claim in token")
	}

	return fmt.Errorf("user not in allowed groups or users")
}

func setExpiration(payload map[string]interface{}, t jwt.Token, w http.ResponseWriter) bool {
	if exp, ok := payload["exp"]; ok {
		switch v := exp.(type) {
		case int:
			t.Set(jwt.ExpirationKey, v)
		case string:
			expTime, err := time.Parse(time.RFC3339, v)
			if err != nil {
				d, err := time.ParseDuration(v)
				if err != nil {
					logger.Error().Msg("Invalid expiration time")
					http.Error(w, "invalid expiration time", http.StatusBadRequest)
					return true
				}
				t.Set(jwt.ExpirationKey, time.Now().Add(d).Unix())
			} else {
				t.Set(jwt.ExpirationKey, expTime)
			}
		default:
			logger.Error().Msg("Invalid expiration time")
			http.Error(w, "invalid expiration time", http.StatusBadRequest)
			return true
		}
		delete(payload, "exp")
	} else {
		t.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())
	}
	return false
}

func handleGetKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// wait for keys to be loaded, but timeout after 60 seconds
		startupTime := time.Now()
		timeout := time.Duration(safeStringToInt(getEnv("KEY_FETCH_TIMEOUT_SECONDS", "60"), 60)) * time.Second

		for !externalKeysLoaded.Load() {
			if time.Since(startupTime) > timeout {
				logger.Error().Msg("Timed out waiting for keys to be loaded")
				http.Error(w, "Timed out waiting for keys to be loaded", http.StatusServiceUnavailable)
				return
			}
			time.Sleep(1 * time.Second)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var jsonbuf []byte
		var err error

		if keySetAutoRefresh == nil {
			jsonbuf, err = json.Marshal(publicSet)
			if err != nil {
				log.Printf("failed to marshal key set into JSON: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {

			var externalKeySet jwk.Set

			if time.Since(lastForcedRefresh) > forcedRefreshThreshold {
				func() {
					forceRefreshLock.Lock()
					defer forceRefreshLock.Unlock()
					externalKeySet, err = keySetAutoRefresh.Refresh(cancellableContext, jwksUrl)
					lastForcedRefresh = time.Now()
				}()

				if err != nil {
					logger.Error().Msgf("Failed to refresh keys: %v", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			} else {
				externalKeySet, err = keySetAutoRefresh.Fetch(cancellableContext, jwksUrl)

				if err != nil {
					logger.Error().Msgf("Failed to fetch external keys: %v", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}

			if err != nil {
				logger.Error().Msgf("Failed to fetch external keys: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			keys := make([]jwk.Key, externalKeySet.Len()+publicSet.Len())

			ctx := r.Context()
			it := externalKeySet.Iterate(ctx)

			max := 0

			for it.Next(ctx) {
				pair := it.Pair()
				keys[pair.Index] = pair.Value.(jwk.Key)
				if pair.Index > max {
					max = pair.Index
				}
			}

			it = publicSet.Iterate(ctx)

			for it.Next(ctx) {
				pair := it.Pair()
				keys[max+1+pair.Index] = pair.Value.(jwk.Key)
			}

			keysMap := make(map[string][]jwk.Key)

			keysMap["keys"] = keys

			// marshal the key set into JSON
			jsonbuf, err = json.Marshal(keysMap)

			if err != nil {
				log.Printf("failed to marshal key set into JSON: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		_, err = w.Write(jsonbuf)

		if err != nil {
			logger.Error().Msg("Failed to write key set")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}

func setupExternalKeysListener(jwksUrl string) {

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
				// TODO: shoud we cancel the context here and die?
			}
		}
	}()

	// retry fetching jwks until successful for KEY_FETCH_TIMEOUT_SECONDS seconds
	// if fetching jwks fails, the service will not start

	startupTime := time.Now()
	timeout := time.Duration(safeStringToInt(getEnv("KEY_FETCH_TIMEOUT_SECONDS", "60"), 60)) * time.Second

	lastForcedRefresh = time.Now().Add(-forcedRefreshThreshold * 2)

	for time.Since(startupTime) < timeout {
		_, err = keySetAutoRefresh.Fetch(cancellableContext, jwksUrl)

		if err != nil {
			logger.Fatal().Msgf("Unable to fetch jwk. Error is %v", err)
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}

	externalKeysLoaded.Store(true)

	logger.Info().
		Str("service", service).
		Msg("Service ready")
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readyz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func getShutdownTimeout(timeout string) time.Duration {
	iTimeout := safeStringToInt(timeout, 2)
	return time.Duration(iTimeout)
}

func getPort(port string) int {
	return safeStringToInt(port, 8080)
}

func safeStringToInt(value string, defaultValue int) int {
	intValue, err := strconv.Atoi(value)
	if err != nil {
		logger.Warn().Msg(fmt.Sprintf("Invalid value '%s', defaulting to %d", value, defaultValue))
		return defaultValue
	}
	return intValue
}

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

func main() {
	logLevel, err := zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel // default to INFO
	}
	zerolog.SetGlobalLevel(logLevel)

	logger.Info().Msg("JWK provider initializing..")
	shutdownTimeout := flag.Duration("shutdown-timeout", getShutdownTimeout(getEnv("SHUTDOWN_TIMEOUT", "2"))*time.Second, "shutdown timeout (5s,5m,5h) before connections are cancelled")
	port := getPort(getEnv("PORT", "8080"))

	issuer = os.Getenv("ISSUER")

	if issuer == "" {
		logger.Fatal().
			Msg("ISSUER environment variable is not set")
	}

	logger.Info().
		Str("issuer", issuer).
		Msg("issuer set")

	jwksUrl = os.Getenv("JWKS_URL")

	if jwksUrl != "" {
		logger.Info().
			Str("jwksUrl", jwksUrl).
			Msg("JWKS_URL provided, setting up external keys listener and enabling Azure token validation")

		audienceValidationRegexStr := os.Getenv("AUDIENCE_VALIDATION_REGEX")

		if audienceValidationRegexStr == "" {
			logger.Fatal().
				Msg("AUDIENCE_VALIDATION_REGEX environment variable is not set")
		}

		audienceValidationRegex, err = regexp.Compile(audienceValidationRegexStr)

		if err != nil {
			logger.Fatal().
				Msg("Invalid AUDIENCE_REGEX")
		}

		err := loadAzureValidationInfo()

		if err != nil {
			logger.Fatal().
				Msg("Failed to load allowed groups from environment variable ALLOWED_AZURE_GROUPS")
		}

		logger.Info().
			Msg("Setting up external keys listener")

		var cancelFn context.CancelFunc

		cancellableContext, cancelFn = context.WithCancel(context.Background())
		defer cancelFn()

		setupExternalKeysListener(jwksUrl)

	} else {
		logger.Info().Msg("No JWKS_URL provided, using only internal keys")
		externalKeysLoaded.Store(true)
	}

	configGoGC()

	logger.Info().Msg("JWK provider starting..")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	keysCtx, cancelKeysCtx := context.WithCancel(context.Background())

	err = setupKeys(keysCtx)

	if err != nil {
		logger.Fatal().Msg("Failed to create keys")
		os.Exit(1)
	}

	r := createHandler()

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

	logger.Info().Msg(fmt.Sprintf("%s shutting down ...\n", service))

	ctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal().Msgf("Failed to gracefully shutdown: %v", err)
		os.Exit(1)
	}

	cancelKeysCtx()

	logger.Info().Msg(fmt.Sprintf("The %s is shutting down...", service))
	srv.Shutdown(context.Background())
	logger.Info().Msg(fmt.Sprintf("%s is down", service))
}
