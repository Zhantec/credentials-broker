package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Callers: []config.Caller{
			{Key: "sk_ok", Targets: []string{"stripe"}},
			{Key: "sk_both", Targets: []string{"stripe", "github"}},
		},
		Targets: []config.Target{
			{Name: "stripe", Mode: "proxy"},
			{Name: "github", Mode: "oauth"},
		},
	}
}

func recordingHandler(calls *int) DispatchFunc {
	return func(w http.ResponseWriter, r *http.Request, target *config.Target) {
		*calls++
		w.WriteHeader(http.StatusOK)
	}
}

func TestNew_Routing(t *testing.T) {
	var proxyCalls, oauthCalls int
	cfg := testConfig()
	handler := New(cfg, map[string]DispatchFunc{
		"proxy": recordingHandler(&proxyCalls),
		"oauth": recordingHandler(&oauthCalls),
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	cases := []struct {
		name       string
		method     string
		path       string
		authHeader string
		wantStatus int
	}{
		{"missing key", http.MethodGet, "/proxy/stripe/v1/x", "", http.StatusUnauthorized},
		{"unknown target", http.MethodGet, "/proxy/nope/v1/x", "Bearer sk_ok", http.StatusNotFound},
		{"not permitted", http.MethodGet, "/proxy/github/v1/x", "Bearer sk_ok", http.StatusForbidden},
		{"allowed proxy", http.MethodGet, "/proxy/stripe/v1/x", "Bearer sk_ok", http.StatusOK},
		{"allowed oauth", http.MethodGet, "/proxy/github/v1/x", "Bearer sk_both", http.StatusOK},
		{"unknown mode", http.MethodGet, "/proxy/unmapped/v1/x", "Bearer sk_unmapped", http.StatusNotFound},
	}

	cfg.Callers = append(cfg.Callers, config.Caller{Key: "sk_unmapped", Targets: []string{"unmapped"}})
	cfg.Targets = append(cfg.Targets, config.Target{Name: "unmapped", Mode: "no-such-mode"})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
			if c.authHeader != "" {
				req.Header.Set("Authorization", c.authHeader)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, c.wantStatus)
			}
		})
	}

	if proxyCalls != 1 {
		t.Errorf("proxy handler calls = %d, want 1", proxyCalls)
	}
	if oauthCalls != 1 {
		t.Errorf("oauth handler calls = %d, want 1", oauthCalls)
	}
}
