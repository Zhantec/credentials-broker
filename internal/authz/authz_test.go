package authz

import (
	"testing"

	"github.com/Zhantec/credentials-broker/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustCreateTarget(t *testing.T, s *store.Store, name string) {
	t.Helper()
	if err := s.CreateTarget(store.Target{
		Name: name, Mode: "proxy", BaseURL: "https://example.com",
		InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod",
		InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer ",
	}); err != nil {
		t.Fatalf("CreateTarget(%s): %v", name, err)
	}
}

func TestCheck_Allowed_ScopedCaller(t *testing.T) {
	s := newTestStore(t)
	mustCreateTarget(t, s, "stripe")
	_, key, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	result, err := Check(s, key, "stripe")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Allowed {
		t.Fatalf("Check: got %v, want Allowed", result)
	}
}

func TestCheck_Allowed_AllAccessCaller(t *testing.T) {
	s := newTestStore(t)
	mustCreateTarget(t, s, "stripe")
	mustCreateTarget(t, s, "github")
	_, key, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	for _, target := range []string{"stripe", "github"} {
		result, err := Check(s, key, target)
		if err != nil {
			t.Fatalf("Check(%s): %v", target, err)
		}
		if result != Allowed {
			t.Fatalf("Check(%s): got %v, want Allowed", target, result)
		}
	}
}

func TestCheck_Unauthenticated(t *testing.T) {
	s := newTestStore(t)
	mustCreateTarget(t, s, "stripe")

	result, err := Check(s, "sk_live_bogus", "stripe")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Unauthenticated {
		t.Fatalf("Check: got %v, want Unauthenticated", result)
	}
}

func TestCheck_TargetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, key, err := s.CreateCaller(nil)
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	result, err := Check(s, key, "missing")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != TargetNotFound {
		t.Fatalf("Check: got %v, want TargetNotFound", result)
	}
}

func TestCheck_Forbidden(t *testing.T) {
	s := newTestStore(t)
	mustCreateTarget(t, s, "stripe")
	mustCreateTarget(t, s, "github")
	_, key, err := s.CreateCaller([]string{"stripe"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	result, err := Check(s, key, "github")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Forbidden {
		t.Fatalf("Check: got %v, want Forbidden", result)
	}
}

// TestCheck_ScopedCallerStaysForbiddenAfterItsOnlyTargetIsDeleted is a
// regression test for a privilege-escalation bug: caller_targets rows
// cascade-delete when their target is deleted, so a caller scoped to
// exactly one target used to end up with an empty Targets slice after
// that target was removed — and authz.Check read "empty Targets" as
// unrestricted all-access. AllAccess is now fixed at caller-creation
// time, so a scoped caller must stay Forbidden for other targets even
// after its only scoped target is deleted out from under it.
func TestCheck_ScopedCallerStaysForbiddenAfterItsOnlyTargetIsDeleted(t *testing.T) {
	s := newTestStore(t)
	mustCreateTarget(t, s, "alpha")
	mustCreateTarget(t, s, "beta")
	_, key, err := s.CreateCaller([]string{"alpha"})
	if err != nil {
		t.Fatalf("CreateCaller: %v", err)
	}

	result, err := Check(s, key, "beta")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Forbidden {
		t.Fatalf("Check(beta) before delete: got %v, want Forbidden", result)
	}

	if err := s.DeleteTarget("alpha"); err != nil {
		t.Fatalf("DeleteTarget(alpha): %v", err)
	}

	result, err = Check(s, key, "beta")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Forbidden {
		t.Fatalf("Check(beta) after alpha deleted: got %v, want Forbidden (cascade-delete of the caller's only scope row must not widen it to all-access)", result)
	}
}

func TestCheck_UnauthenticatedTakesPriorityOverTargetNotFound(t *testing.T) {
	s := newTestStore(t)
	result, err := Check(s, "sk_live_bogus", "missing")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result != Unauthenticated {
		t.Fatalf("Check: got %v, want Unauthenticated (auth must be checked before target existence)", result)
	}
}
