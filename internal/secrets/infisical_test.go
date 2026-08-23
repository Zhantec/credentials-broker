package secrets

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeInfisical(t *testing.T) (*httptest.Server, *int, *int) {
	t.Helper()
	var loginCalls, secretCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "test-token",
			"expiresIn":   300,
		})
	})
	mux.HandleFunc("/api/v3/secrets/raw/dsn", func(w http.ResponseWriter, r *http.Request) {
		secretCalls++
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"secretValue": "postgres://real-dsn"},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &loginCalls, &secretCalls
}

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient("", "id", "secret")
	if c.baseURL != defaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultBaseURL)
	}
}

func TestGetSecret_AuthEndpointNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when auth endpoint rejects credentials")
	}
}

func TestGetSecret_MalformedAuthResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when auth response is malformed")
	}
}

func TestGetSecret_SecretEndpointNon200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "test-token", "expiresIn": 300})
	})
	mux.HandleFunc("/api/v3/secrets/raw/dsn", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when secret endpoint returns non-200")
	}
}

func TestGetSecret_MalformedSecretResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "test-token", "expiresIn": 300})
	})
	mux.HandleFunc("/api/v3/secrets/raw/dsn", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when secret response is malformed")
	}
}

func TestGetSecret_AuthEndpointUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := server.URL
	server.Close() // closed before use -> connection refused

	client := NewClient(deadURL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when auth endpoint is unreachable")
	}
}

type erroringSecretTransport struct {
	base http.RoundTripper
}

func (t erroringSecretTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/api/v3/secrets/") {
		return nil, errors.New("simulated network failure")
	}
	return t.base.RoundTrip(req)
}

func TestGetSecret_SecretFetchUnreachable(t *testing.T) {
	server, _, _ := fakeInfisical(t)
	c := &Client{
		baseURL:      server.URL,
		clientID:     "id",
		clientSecret: "secret",
		httpClient:   &http.Client{Transport: erroringSecretTransport{base: http.DefaultTransport}},
		secretCache:  make(map[string]cacheEntry),
	}
	if _, err := c.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err == nil {
		t.Error("expected error when secret fetch is unreachable")
	}
}

func TestGetSecret_TokenCacheReusedAcrossDifferentSecrets(t *testing.T) {
	var loginCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "test-token", "expiresIn": 300})
	})
	mux.HandleFunc("/api/v3/secrets/raw/dsn", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]string{"secretValue": "v1"}})
	})
	mux.HandleFunc("/api/v3/secrets/raw/other", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]string{"secretValue": "v2"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, "client-id", "client-secret")
	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err != nil {
		t.Fatalf("first GetSecret: %v", err)
	}
	if _, err := client.GetSecret("ws-1", "prod", "/prod/other", "other"); err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}
	if loginCalls != 1 {
		t.Errorf("expected 1 login call (token cached across different secrets), got %d", loginCalls)
	}
}

func TestGetSecret_CachesValue(t *testing.T) {
	server, loginCalls, secretCalls := fakeInfisical(t)
	client := NewClient(server.URL, "client-id", "client-secret")

	value, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if value != "postgres://real-dsn" {
		t.Fatalf("unexpected value: %q", value)
	}

	if _, err := client.GetSecret("ws-1", "prod", "/prod/postgres", "dsn"); err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}

	if *loginCalls != 1 {
		t.Errorf("expected 1 login call, got %d", *loginCalls)
	}
	if *secretCalls != 1 {
		t.Errorf("expected 1 secret call (second should hit cache), got %d", *secretCalls)
	}
}
