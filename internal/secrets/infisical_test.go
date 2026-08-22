package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeInfisical(t *testing.T) (*httptest.Server, *int, *int) {
	t.Helper()
	var loginCalls, secretCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		json.NewEncoder(w).Encode(map[string]any{
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
		json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"secretValue": "postgres://real-dsn"},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &loginCalls, &secretCalls
}

func TestGetSecret_CachesValue(t *testing.T) {
	server, loginCalls, secretCalls := fakeInfisical(t)
	client := NewClient(server.URL, "client-id", "client-secret", "ws-1", "prod")

	value, err := client.GetSecret("/prod/postgres", "dsn")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if value != "postgres://real-dsn" {
		t.Fatalf("unexpected value: %q", value)
	}

	if _, err := client.GetSecret("/prod/postgres", "dsn"); err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}

	if *loginCalls != 1 {
		t.Errorf("expected 1 login call, got %d", *loginCalls)
	}
	if *secretCalls != 1 {
		t.Errorf("expected 1 secret call (second should hit cache), got %d", *secretCalls)
	}
}
