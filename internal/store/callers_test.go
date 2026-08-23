package store

import "testing"

func TestCreateAndFindCallerByKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreateTarget(Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	id, rawKey, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}
	if rawKey == "" {
		t.Fatal("CreateCaller: expected non-empty raw key")
	}

	caller, ok, err := s.FindCallerByKey(rawKey)
	if err != nil {
		t.Fatalf("FindCallerByKey: %v", err)
	}
	if !ok {
		t.Fatal("FindCallerByKey: expected found")
	}
	if caller.ID != id {
		t.Fatalf("FindCallerByKey: got id %d, want %d", caller.ID, id)
	}
	if len(caller.Targets) != 1 || caller.Targets[0] != "stripe" {
		t.Fatalf("FindCallerByKey: got targets %+v", caller.Targets)
	}
}

func TestDeleteTarget_CascadesCallerScope(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreateTarget(Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	_, rawKey, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	if err := s.DeleteTarget("stripe"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	// Deleting the target must cascade-delete its caller_targets row (this
	// only happens if PRAGMA foreign_keys=ON actually took effect on this
	// connection) — the caller's Targets should go empty, not error out
	// with a dangling reference, and AllAccess must stay false regardless.
	caller, ok, err := s.FindCallerByKey(rawKey)
	if err != nil {
		t.Fatalf("FindCallerByKey: %v", err)
	}
	if !ok {
		t.Fatal("FindCallerByKey: expected found")
	}
	if len(caller.Targets) != 0 {
		t.Fatalf("FindCallerByKey: got targets %+v, want empty after cascade delete", caller.Targets)
	}
	if caller.AllAccess {
		t.Fatal("FindCallerByKey: scoped caller must not become all-access when its scope is cascade-deleted")
	}
}

func TestCreateCaller_EmptyTargetsIsAllAccess(t *testing.T) {
	s := newTestStore(t)
	_, rawKey, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}
	caller, ok, err := s.FindCallerByKey(rawKey)
	if err != nil {
		t.Fatalf("FindCallerByKey: %v", err)
	}
	if !ok {
		t.Fatal("FindCallerByKey: expected found")
	}
	if len(caller.Targets) != 0 {
		t.Fatalf("FindCallerByKey: got targets %+v, want empty (all-access)", caller.Targets)
	}
}

func TestFindCallerByKey_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, ok, err := s.FindCallerByKey("sk_live_nonexistent")
	if err != nil {
		t.Fatalf("FindCallerByKey: %v", err)
	}
	if ok {
		t.Fatal("FindCallerByKey: expected not found")
	}
}

func TestListCallers(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreateTarget(Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	id1, _, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}
	id2, _, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	callers, err := s.ListCallers()
	if err != nil {
		t.Fatalf("ListCallers: %v", err)
	}
	if len(callers) != 2 {
		t.Fatalf("ListCallers: got %d callers, want 2", len(callers))
	}
	if callers[0].ID != id1 || len(callers[0].Targets) != 0 {
		t.Fatalf("ListCallers[0]: got %+v", callers[0])
	}
	if callers[1].ID != id2 || len(callers[1].Targets) != 1 || callers[1].Targets[0] != "stripe" {
		t.Fatalf("ListCallers[1]: got %+v", callers[1])
	}
}

func TestDeleteCaller(t *testing.T) {
	s := newTestStore(t)
	id, rawKey, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}
	if err := s.DeleteCaller(id); err != nil {
		t.Fatalf("DeleteCaller: %v", err)
	}
	_, ok, err := s.FindCallerByKey(rawKey)
	if err != nil {
		t.Fatalf("FindCallerByKey: %v", err)
	}
	if ok {
		t.Fatal("FindCallerByKey: expected not found after delete")
	}
}

func TestDeleteCaller_NotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteCaller(999); err != ErrNotFound {
		t.Fatalf("DeleteCaller: got %v, want ErrNotFound", err)
	}
}
