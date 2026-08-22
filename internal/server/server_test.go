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
			{Key: "sk_both", Targets: []string{"stripe", "postgres"}},
		},
		Targets: []config.Target{
			{Name: "stripe", Mode: "proxy"},
			{Name: "postgres", Mode: "execute"},
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
	var proxyCalls, executeCalls int
	cfg := testConfig()
	handler := New(cfg, recordingHandler(&proxyCalls), recordingHandler(&executeCalls))
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
		{"not permitted", http.MethodPost, "/execute/postgres", "Bearer sk_ok", http.StatusForbidden},
		{"allowed proxy", http.MethodGet, "/proxy/stripe/v1/x", "Bearer sk_ok", http.StatusOK},
		{"execute target via proxy route", http.MethodGet, "/proxy/postgres/v1/x", "Bearer sk_both", http.StatusNotFound},
		{"proxy target via execute route", http.MethodPost, "/execute/stripe", "Bearer sk_both", http.StatusNotFound},
	}

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
}
