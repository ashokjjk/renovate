package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

var ts *httptest.Server
var issuer string = "https://sts.windows.net/68767578-3e26-446e-b414-a7f0248c887f/"
var curityIssuer string = "https://curity.example.com/oauth/v2/oauth-anonymous"
var privateSet jwk.Set
var mockAuthResolver *httptest.Server

func TestMain(m *testing.M) {
	// Setup mock JWKS server for Azure AD
	auto := NewMockJwkAutoRefresh()
	keySetAutoRefresh = auto
	privateSet = auto.PrivateSet()

	// Setup mock auth resolver for Curity
	mockAuthResolver = setupMockAuthResolver()
	defer mockAuthResolver.Close()

	// Set environment variables
	os.Setenv("AUTH_RESOLVER_URL", mockAuthResolver.URL)
	os.Setenv("JWKS_URL", "https://login.microsoftonline.com/common/discovery/v2.0/keys")

	ts = httptest.NewServer(
		router(
			map[string]string{},
			issuer))
	defer ts.Close()
	os.Exit(m.Run())
}

func setupMockAuthResolver() *httptest.Server {
	// Get the public key from the private set
	key, _ := privateSet.LookupKeyID(jwk.ForSignature.String())
	publicKey, _ := key.PublicKey()
	n, _ := publicKey.Get("n")
	e, _ := publicKey.Get("e")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jwks" {
			// Get tenant ID from query parameter
			tenantID := r.URL.Query().Get("tenant_id")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Return different JWKS based on tenant ID
			if tenantID == "invalid-tenant" {
				// Return invalid key for invalid tenant
				json.NewEncoder(w).Encode(map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "sig",
							"use": "sig",
							"n":   "invalid-key",
							"e":   "test",
							"alg": "RS512",
						},
					},
				})
				return
			}

			// Return valid key for valid tenant
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "sig",
						"use": "sig",
						"n":   n,
						"e":   e,
						"alg": "RS512",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestVerifyCurityJwt(t *testing.T) {
	// Create a Curity token with kid 'sig'
	claims := map[string]interface{}{
		"tenant_id": "test-tenant",
		"iss":       curityIssuer,
	}
	token, err := createToken(curityIssuer, claims, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)

	// Test without auth header
	res, _ := http.Get(ts.URL)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// Test with expired token
	expiredToken, err := createToken(curityIssuer, claims, time.Now().Add(-1*time.Hour))
	assert.Nil(t, err)
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// Test with valid token
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestVerifyCurityJwtMissingTenant(t *testing.T) {
	// Create a Curity token without tenant_id, with kid 'test-key'
	claims := map[string]interface{}{
		"iss": curityIssuer,
	}
	token, err := createToken(curityIssuer, claims, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ := client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestVerifyCurityJwtInvalidJWKS(t *testing.T) {
	// Create a Curity token with invalid tenant_id
	claims := map[string]interface{}{
		"tenant_id": "invalid-tenant",
		"iss":       curityIssuer,
	}
	token, err := createToken(curityIssuer, claims, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ := client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "Authentication failed")
}

func TestGetBearerToken(t *testing.T) {
	// Test empty header
	req, _ := http.NewRequest("GET", ts.URL, nil)
	token := getBearerToken(req, logger)
	assert.Empty(t, token)

	// Test invalid Bearer format
	req.Header.Set("Authorization", "InvalidFormat token123")
	token = getBearerToken(req, logger)
	assert.Empty(t, token)

	// Test valid Bearer token
	req.Header.Set("Authorization", "Bearer valid-token")
	token = getBearerToken(req, logger)
	assert.Equal(t, "valid-token", token)
}

func TestKeyNotFoundErrorCounter(t *testing.T) {
	// Create a token with a non-existent key ID
	claims := map[string]interface{}{
		"tenant_id": "test-tenant",
		"iss":       curityIssuer,
	}
	token, err := createToken(curityIssuer, claims, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)

	// Modify the token to have an invalid key ID
	parts := strings.Split(token, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var headerMap map[string]interface{}
	json.Unmarshal(header, &headerMap)
	headerMap["kid"] = "non-existent-key"
	headerBytes, _ := json.Marshal(headerMap)
	parts[0] = base64.RawURLEncoding.EncodeToString(headerBytes)
	invalidToken := strings.Join(parts, ".")

	// Make request with invalid token
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ := client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

}

func TestReadyProbe(t *testing.T) {
	time.Sleep(2 * time.Second)
	res, _ := http.Get(ts.URL + "/readyz")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestHealthProbe(t *testing.T) {
	res, _ := http.Get(ts.URL + "/healthz")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestGetPort(t *testing.T) {
	assert.Equal(t, 1234, getPort("1234"))
	assert.Equal(t, 8080, getPort("invalid"))
}

func TestGetShutdownTimeout(t *testing.T) {
	assert.Equal(t, time.Duration(10), getShutdownTimeout("10"))
	assert.Equal(t, time.Duration(2), getShutdownTimeout("ten"))
}

func TestVerifyJwt(t *testing.T) {
	// without auth header
	res, _ := http.Get(ts.URL)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// with (expired) token
	token, err := createToken(issuer, nil, time.Now().Add(-1*time.Hour))
	assert.Nil(t, err)
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// a valid token
	token, err = createToken(issuer, nil, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestVerifyJwtSubPath(t *testing.T) {
	// without auth header
	res, _ := http.Get(ts.URL + "/_external-auth-L2JhbmFuLw-Prefix")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// with (expired) token
	token, err := createToken(issuer, nil, time.Now().Add(-1*time.Hour))
	assert.Nil(t, err)
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	// a valid token
	token, err = createToken(issuer, nil, time.Now().Add(1*time.Hour))
	assert.Nil(t, err)
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	res, _ = client.Do(req)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func createToken(issuer string, claims map[string]interface{}, expiration time.Time) (string, error) {
	t := jwt.New()
	t.Set(jwt.IssuedAtKey, time.Now().Unix())
	t.Set(jwt.ExpirationKey, expiration)
	t.Set(jwt.IssuerKey, issuer)

	for k, v := range claims {
		t.Set(k, v)
	}

	signingKey, _ := privateSet.LookupKeyID(jwk.ForSignature.String())

	signed, err := jwt.Sign(t, jwa.RS512, signingKey)

	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func TestMetricTotalRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, _ := client.Do(req)
	bodyBytes, _ := io.ReadAll(res.Body)
	bodyString := string(bodyBytes)

	// the metric should exist
	assert.True(t, strings.Contains(bodyString, "total_jwt_token_requests"))

	// it should be greater than zero
	assert.False(t, strings.Contains(bodyString, "total_jwt_token_requests 0"))
}

func TestHeadersReturned(t *testing.T) {
	// Define the headers you will send in the request
	headers := map[string]string{
		"X-Request-Id": "Value1",
		"Header2":      "Value2",
		// Add more headers as needed
	}

	// Create a new request
	req, _ := http.NewRequest("GET", ts.URL, nil)

	// Add headers to the request
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send the request
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	res, _ := client.Do(req)

	// Check that each header sent is also present in the response
	for key, sentValue := range headers {
		returnedValue := res.Header.Get(key)
		assert.Equal(t, sentValue, returnedValue, "Header "+key+" was not returned correctly")
	}
}
