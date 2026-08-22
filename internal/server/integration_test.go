package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Zhantec/credentials-broker/internal/config"
	"github.com/Zhantec/credentials-broker/internal/execute"
	"github.com/Zhantec/credentials-broker/internal/proxy"
)

// mapResolver resolves each target's secret by its configured path.
type mapResolver map[string]string

func (m mapResolver) GetSecret(secretPath, secretName string) (string, error) {
	return m[secretPath+"/"+secretName], nil
}

func sqliteOpener(driverName, dsn string) (*sql.DB, error) {
	return sql.Open("sqlite", dsn)
}

// TestEndToEnd_ThroughRealMux exercises the full seam: a real HTTP round trip
// into server.New's ServeMux, its {rest...} wildcard, proxy.Serve's
// PathValue lookup, and a real upstream server.
func TestEndToEnd_ThroughRealMux(t *testing.T) {
	var gotPath, gotQuery, gotAPIKey, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotAPIKey, gotAuth = r.Header.Get("X-Api-Key"), r.Header.Get("Authorization")
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	dsn := "file:" + t.TempDir() + "/test.db"
	cfg := &config.Config{
		Callers: []config.Caller{{Key: "sk_ok", Targets: []string{"stripe", "postgres"}}},
		Targets: []config.Target{
			{
				Name:            "stripe",
				Mode:            "proxy",
				BaseURL:         upstream.URL,
				InjectHeader:    "X-Api-Key",
				InjectPrefix:    "Bearer ",
				InfisicalSecret: "/prod/stripe/api_key",
			},
			{Name: "postgres", Mode: "execute", Driver: "postgres", InfisicalSecret: "/prod/postgres/dsn"},
		},
	}
	resolver := mapResolver{
		"/prod/stripe/api_key": "real-secret",
		"/prod/postgres/dsn":   dsn,
	}

	broker := httptest.NewServer(New(cfg,
		proxy.Serve(resolver, upstream.Client()),
		execute.Serve(resolver, sqliteOpener),
	))
	defer broker.Close()

	req, _ := http.NewRequest(http.MethodGet, broker.URL+"/proxy/stripe/v1/charges?limit=10", nil)
	req.Header.Set("Authorization", "Bearer sk_ok")
	resp, err := broker.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotPath != "/v1/charges" {
		t.Errorf("upstream path = %q, want %q", gotPath, "/v1/charges")
	}
	if gotQuery != "limit=10" {
		t.Errorf("upstream query = %q, want %q", gotQuery, "limit=10")
	}
	if gotAPIKey != "Bearer real-secret" {
		t.Errorf("upstream X-Api-Key = %q, want %q", gotAPIKey, "Bearer real-secret")
	}
	if gotAuth != "" {
		t.Errorf("caller Authorization leaked to upstream: %q", gotAuth)
	}

	// Same wiring, execute route.
	eReq, _ := http.NewRequest(http.MethodPost, broker.URL+"/execute/postgres", strings.NewReader(`{"query": "SELECT 1 AS n"}`))
	eReq.Header.Set("Authorization", "Bearer sk_ok")
	eResp, err := broker.Client().Do(eReq)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer eResp.Body.Close()

	if eResp.StatusCode != http.StatusOK {
		t.Fatalf("execute status = %d, want 200", eResp.StatusCode)
	}
	var got struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.NewDecoder(eResp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding execute response: %v", err)
	}
	if len(got.Rows) != 1 || len(got.Columns) != 1 || got.Columns[0] != "n" {
		t.Errorf("execute result = %+v, want one row, column \"n\"", got)
	}
}
