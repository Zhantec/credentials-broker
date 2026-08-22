package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/config"
	"github.com/Zhantec/credentials-broker/internal/oauth"
	"github.com/Zhantec/credentials-broker/internal/proxy"
)

// mapResolver resolves each target's secret by its configured path.
type mapResolver map[string]string

func (m mapResolver) GetSecret(secretPath, secretName string) (string, error) {
	return m[secretPath+"/"+secretName], nil
}

// TestEndToEnd_ThroughRealMux exercises the full seam: a real HTTP round trip
// into server.New's ServeMux, its {rest...} wildcard, proxy.Serve's
// PathValue lookup, and a real upstream server — for both a static-secret
// proxy target and an oauth target (real token endpoint + real upstream).
func TestEndToEnd_ThroughRealMux(t *testing.T) {
	var gotPath, gotQuery, gotAPIKey, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotAPIKey, gotAuth = r.Header.Get("X-Api-Key"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	var tokenRequests int
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "real-token", "expires_in": 3600}`))
	}))
	defer tokenServer.Close()

	cfg := &config.Config{
		Callers: []config.Caller{{Key: "sk_ok", Targets: []string{"stripe", "github"}}},
		Targets: []config.Target{
			{
				Name:            "stripe",
				Mode:            "proxy",
				BaseURL:         upstream.URL,
				InjectHeader:    "X-Api-Key",
				InjectPrefix:    "Bearer ",
				InfisicalSecret: "/prod/stripe/api_key",
			},
			{
				Name:            "github",
				Mode:            "oauth",
				BaseURL:         upstream.URL,
				InjectHeader:    "Authorization",
				InjectPrefix:    "Bearer ",
				InfisicalSecret: "/prod/github/oauth_client",
			},
		},
	}
	resolver := mapResolver{
		"/prod/stripe/api_key":      "real-secret",
		"/prod/github/oauth_client": `{"client_id": "id", "client_secret": "secret", "token_url": "` + tokenServer.URL + `"}`,
	}

	broker := httptest.NewServer(New(cfg, map[string]DispatchFunc{
		"proxy": proxy.Serve(resolver, upstream.Client()),
		"oauth": proxy.Serve(oauth.NewClient(resolver, tokenServer.Client()), upstream.Client()),
	}))
	defer broker.Close()

	req, _ := http.NewRequest(http.MethodGet, broker.URL+"/proxy/stripe/v1/charges?limit=10", nil)
	req.Header.Set("Authorization", "Bearer sk_ok")
	resp, err := broker.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	// Same wiring, oauth route: broker exchanges client creds for a token
	// against a real token endpoint, then injects it as a Bearer header.
	oReq, _ := http.NewRequest(http.MethodGet, broker.URL+"/proxy/github/user/repos", nil)
	oReq.Header.Set("Authorization", "Bearer sk_ok")
	oResp, err := broker.Client().Do(oReq)
	if err != nil {
		t.Fatalf("oauth request: %v", err)
	}
	defer func() { _ = oResp.Body.Close() }()

	if oResp.StatusCode != http.StatusOK {
		t.Fatalf("oauth status = %d, want 200", oResp.StatusCode)
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, "Bearer real-token")
	}
	if tokenRequests != 1 {
		t.Errorf("token endpoint requests = %d, want 1 (first fetch)", tokenRequests)
	}

	// Second oauth request within TTL must not hit the token endpoint again.
	oReq2, _ := http.NewRequest(http.MethodGet, broker.URL+"/proxy/github/user/repos", nil)
	oReq2.Header.Set("Authorization", "Bearer sk_ok")
	oResp2, err := broker.Client().Do(oReq2)
	if err != nil {
		t.Fatalf("second oauth request: %v", err)
	}
	_ = oResp2.Body.Close()

	if tokenRequests != 1 {
		t.Errorf("token endpoint requests = %d, want 1 (cached)", tokenRequests)
	}
}
