package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/proxy"
	"github.com/Zhantec/credentials-broker/internal/store"
)

// fakeSecretResolver returns a fixed secret regardless of which
// workspace/environment/path/name is requested, letting this test focus
// on the admin-create -> caller-key -> /proxy flow rather than Infisical
// wiring (covered separately in internal/secrets).
type fakeSecretResolver struct{ secret string }

func (f fakeSecretResolver) GetSecret(workspaceID, environment, secretPath, secretName string) (string, error) {
	return f.secret, nil
}

// TestEndToEnd_AdminCreateThenProxy exercises the full flow this
// migration exists for: an admin registers a target, creates a caller
// scoped to it, and that caller's key immediately works on /proxy —
// with no config file or restart in between.
func TestEndToEnd_AdminCreateThenProxy(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sekret" {
			t.Errorf("upstream saw Authorization=%q, want %q", got, "Bearer sekret")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	handlers := map[string]DispatchFunc{
		"proxy": proxy.Serve(fakeSecretResolver{secret: "sekret"}, &http.Client{}),
	}
	handler, err := New(s, testAdminKey, handlers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 1. Admin registers a target pointing at the fake upstream.
	createTargetRec := doAdminRequest(t, handler, "POST", "/admin/targets", map[string]any{
		"name":                   "stripe",
		"mode":                   "proxy",
		"base_url":               upstream.URL,
		"infisical_workspace_id": "ws-1",
		"infisical_environment":  "prod",
		"infisical_secret":       "/prod/stripe/api_key",
	})
	if createTargetRec.Code != http.StatusCreated {
		t.Fatalf("create target status: got %d, body=%s", createTargetRec.Code, createTargetRec.Body.String())
	}

	// 2. Admin creates a caller scoped to that target.
	createCallerRec := doAdminRequest(t, handler, "POST", "/admin/callers", map[string]any{"targets": []string{"stripe"}})
	if createCallerRec.Code != http.StatusCreated {
		t.Fatalf("create caller status: got %d, body=%s", createCallerRec.Code, createCallerRec.Body.String())
	}
	var caller createCallerResponse
	if err := json.Unmarshal(createCallerRec.Body.Bytes(), &caller); err != nil {
		t.Fatalf("unmarshal caller: %v", err)
	}

	// 3. That caller's key works on /proxy immediately.
	req := httptest.NewRequest("GET", "/proxy/stripe/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+caller.Key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status: got %d, body=%s", rec.Code, rec.Body.String())
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("proxy body: got %q, want %q", body, "ok")
	}
}

// TestEndToEnd_DeletedCallerLosesAccess confirms that deleting a caller
// via the admin API immediately revokes its key on /proxy.
func TestEndToEnd_DeletedCallerLosesAccess(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	handlers := map[string]DispatchFunc{
		"proxy": proxy.Serve(fakeSecretResolver{secret: "sekret"}, &http.Client{}),
	}
	handler, err := New(s, testAdminKey, handlers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.CreateTarget(testTarget("stripe")); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	createCallerRec := doAdminRequest(t, handler, "POST", "/admin/callers", map[string]any{"targets": []string{"stripe"}})
	var caller createCallerResponse
	if err := json.Unmarshal(createCallerRec.Body.Bytes(), &caller); err != nil {
		t.Fatalf("unmarshal caller: %v", err)
	}

	deleteRec := doAdminRequest(t, handler, "DELETE", "/admin/callers/"+itoa(caller.ID), nil)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("delete caller status: got %d", deleteRec.Code)
	}

	req := httptest.NewRequest("GET", "/proxy/stripe/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+caller.Key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
