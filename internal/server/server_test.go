package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/store"
)

// recordingHandler is a DispatchFunc that records how many times it was
// invoked and replies 200, standing in for the real proxy/oauth handlers
// to isolate withAuthz's routing decisions from what they dispatch to.
func recordingHandler(calls *int) DispatchFunc {
	return func(w http.ResponseWriter, r *http.Request, target *store.Target) {
		*calls++
		w.WriteHeader(http.StatusOK)
	}
}

// TestNew_EmptyAdminAPIKeyFailsClosed confirms the broker refuses to
// start with an admin API nobody can lock rather than serving admin
// routes unauthenticated.
func TestNew_EmptyAdminAPIKeyFailsClosed(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := New(s, "", map[string]DispatchFunc{}); err == nil {
		t.Fatal("New with empty adminAPIKey: got nil error, want non-nil")
	}
}

// TestWithAuthz_DispatchTable exercises New's full caller-facing dispatch
// table over real HTTP round trips: missing key, unknown target, forbidden
// scope, and successful dispatch to both proxy and oauth modes, plus a
// target whose mode has no registered handler.
func TestWithAuthz_DispatchTable(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.CreateTarget(testTarget("stripe")); err != nil {
		t.Fatalf("CreateTarget(stripe): %v", err)
	}
	github := testTarget("github")
	github.Mode = "oauth"
	if err := s.CreateTarget(github); err != nil {
		t.Fatalf("CreateTarget(github): %v", err)
	}
	unmapped := testTarget("unmapped")
	unmapped.Mode = "no-such-mode"
	if err := s.CreateTarget(unmapped); err != nil {
		t.Fatalf("CreateTarget(unmapped): %v", err)
	}

	var proxyCalls, oauthCalls int
	handler, err := New(s, testAdminKey, map[string]DispatchFunc{
		"proxy": recordingHandler(&proxyCalls),
		"oauth": recordingHandler(&oauthCalls),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, stripeOnlyKey, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller(stripe): %v", err)
	}
	_, allKey, err := s.CreateCaller([]string{"stripe", "github", "unmapped"})
	if err != nil {
		t.Fatalf("CreateCaller(all): %v", err)
	}

	tests := []struct {
		name       string
		key        string
		path       string
		wantStatus int
	}{
		{"missing key -> unauthorized", "", "/proxy/stripe/foo", http.StatusUnauthorized},
		{"unknown target -> not found", stripeOnlyKey, "/proxy/does-not-exist/foo", http.StatusNotFound},
		{"forbidden -> forbidden", stripeOnlyKey, "/proxy/github/foo", http.StatusForbidden},
		{"allowed proxy -> ok", stripeOnlyKey, "/proxy/stripe/foo", http.StatusOK},
		{"allowed oauth -> ok", allKey, "/proxy/github/foo", http.StatusOK},
		{"unmapped mode -> not found", allKey, "/proxy/unmapped/foo", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.key != "" {
				req.Header.Set("Authorization", "Bearer "+tt.key)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status: got %d, want %d, body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}

	if proxyCalls != 1 {
		t.Fatalf("proxy handler calls: got %d, want 1", proxyCalls)
	}
	if oauthCalls != 1 {
		t.Fatalf("oauth handler calls: got %d, want 1", oauthCalls)
	}
}
