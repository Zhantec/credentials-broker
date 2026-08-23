package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCreateCaller_AllAccess(t *testing.T) {
	_, handler := newTestServer(t)

	rec := doAdminRequest(t, handler, "POST", "/admin/callers", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp createCallerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Key == "" {
		t.Fatal("expected non-empty key")
	}
	if len(resp.Targets) != 0 {
		t.Fatalf("got targets %+v, want empty (all-access)", resp.Targets)
	}
}

func TestCreateCaller_Scoped(t *testing.T) {
	s, handler := newTestServer(t)
	if err := s.CreateTarget(testTarget("stripe")); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	rec := doAdminRequest(t, handler, "POST", "/admin/callers", map[string]any{"targets": []string{"stripe"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp createCallerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Targets) != 1 || resp.Targets[0] != "stripe" {
		t.Fatalf("got targets %+v", resp.Targets)
	}
}

func TestListCallers(t *testing.T) {
	s, handler := newTestServer(t)
	if _, _, err := s.CreateCaller(nil); err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	rec := doAdminRequest(t, handler, "GET", "/admin/callers", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Callers []callerResponse `json:"callers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Callers) != 1 {
		t.Fatalf("got %+v", resp.Callers)
	}
	if raw := rec.Body.String(); strings.Contains(raw, `"key"`) {
		t.Fatalf("list response must never contain a raw key: %s", raw)
	}
}

func TestDeleteCaller(t *testing.T) {
	s, handler := newTestServer(t)
	id, _, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	rec := doAdminRequest(t, handler, "DELETE", "/admin/callers/"+itoa(id), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestDeleteCaller_NotFound(t *testing.T) {
	_, handler := newTestServer(t)
	rec := doAdminRequest(t, handler, "DELETE", "/admin/callers/999", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDeleteCaller_InvalidID(t *testing.T) {
	_, handler := newTestServer(t)
	rec := doAdminRequest(t, handler, "DELETE", "/admin/callers/not-a-number", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
