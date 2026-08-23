package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/store"
)

const testAdminKey = "test-admin-key"

func newTestServer(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	handler, err := New(s, testAdminKey, map[string]DispatchFunc{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, handler
}

func doAdminRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+testAdminKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestCreateTarget(t *testing.T) {
	_, handler := newTestServer(t)

	rec := doAdminRequest(t, handler, "POST", "/admin/targets", map[string]any{
		"name":                   "stripe",
		"mode":                   "proxy",
		"base_url":               "https://api.stripe.com",
		"infisical_workspace_id": "ws-1",
		"infisical_environment":  "prod",
		"infisical_secret":       "/prod/stripe/api_key",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp targetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.InjectHeader != "Authorization" || resp.InjectPrefix != "Bearer " {
		t.Fatalf("defaults not applied: got %+v", resp)
	}
}

func TestCreateTarget_RejectsEmptyInjectHeader(t *testing.T) {
	_, handler := newTestServer(t)

	empty := ""
	rec := doAdminRequest(t, handler, "POST", "/admin/targets", map[string]any{
		"name": "stripe", "mode": "proxy", "base_url": "https://api.stripe.com",
		"infisical_workspace_id": "ws-1", "infisical_environment": "prod", "infisical_secret": "/x",
		"inject_header": &empty,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateTarget_Duplicate(t *testing.T) {
	s, handler := newTestServer(t)
	if err := s.CreateTarget(store.Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	rec := doAdminRequest(t, handler, "POST", "/admin/targets", map[string]any{
		"name": "stripe", "mode": "proxy", "base_url": "https://example.com",
		"infisical_workspace_id": "ws-1", "infisical_environment": "prod", "infisical_secret": "/x",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestListTargets(t *testing.T) {
	s, handler := newTestServer(t)
	if err := s.CreateTarget(store.Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	rec := doAdminRequest(t, handler, "GET", "/admin/targets", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Targets []targetResponse `json:"targets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Targets) != 1 || resp.Targets[0].Name != "stripe" {
		t.Fatalf("got %+v", resp.Targets)
	}
}

func TestDeleteTarget(t *testing.T) {
	s, handler := newTestServer(t)
	if err := s.CreateTarget(store.Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	rec := doAdminRequest(t, handler, "DELETE", "/admin/targets/stripe", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestDeleteTarget_NotFound(t *testing.T) {
	_, handler := newTestServer(t)
	rec := doAdminRequest(t, handler, "DELETE", "/admin/targets/missing", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAdminRoutes_RejectMissingAdminKey(t *testing.T) {
	_, handler := newTestServer(t)
	req := httptest.NewRequest("GET", "/admin/targets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func testTarget(name string) store.Target {
	return store.Target{
		Name: name, Mode: "proxy", BaseURL: "https://example.com",
		InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod",
		InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer ",
	}
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
