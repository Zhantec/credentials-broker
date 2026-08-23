package store

import "testing"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAndFindTarget(t *testing.T) {
	s := newTestStore(t)
	target := Target{
		Name:                 "stripe",
		Mode:                 "proxy",
		BaseURL:              "https://api.stripe.com",
		InfisicalWorkspaceID: "ws-1",
		InfisicalEnvironment: "prod",
		InfisicalSecret:      "/prod/stripe/api_key",
		InjectHeader:         "Authorization",
		InjectPrefix:         "Bearer ",
	}
	if err := s.CreateTarget(target); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	got, ok, err := s.FindTarget("stripe")
	if err != nil {
		t.Fatalf("FindTarget: %v", err)
	}
	if !ok {
		t.Fatal("FindTarget: expected found")
	}
	if *got != target {
		t.Fatalf("FindTarget: got %+v, want %+v", *got, target)
	}
}

func TestFindTarget_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, ok, err := s.FindTarget("missing")
	if err != nil {
		t.Fatalf("FindTarget: %v", err)
	}
	if ok {
		t.Fatal("FindTarget: expected not found")
	}
}

func TestCreateTarget_Duplicate(t *testing.T) {
	s := newTestStore(t)
	target := Target{Name: "stripe", Mode: "proxy", BaseURL: "https://api.stripe.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/prod/stripe/api_key", InjectHeader: "Authorization", InjectPrefix: "Bearer "}
	if err := s.CreateTarget(target); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if err := s.CreateTarget(target); err != ErrAlreadyExists {
		t.Fatalf("CreateTarget duplicate: got %v, want ErrAlreadyExists", err)
	}
}

func TestListTargets(t *testing.T) {
	s := newTestStore(t)
	for _, name := range []string{"github", "stripe"} {
		if err := s.CreateTarget(Target{Name: name, Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
			t.Fatalf("CreateTarget(%s): %v", name, err)
		}
	}

	targets, err := s.ListTargets()
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 2 || targets[0].Name != "github" || targets[1].Name != "stripe" {
		t.Fatalf("ListTargets: got %+v", targets)
	}
}

func TestListTargets_Empty(t *testing.T) {
	s := newTestStore(t)
	targets, err := s.ListTargets()
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("ListTargets: got %d targets, want 0", len(targets))
	}
}

func TestDeleteTarget(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreateTarget(Target{Name: "stripe", Mode: "proxy", BaseURL: "https://example.com", InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod", InfisicalSecret: "/x", InjectHeader: "Authorization", InjectPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if err := s.DeleteTarget("stripe"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	_, ok, err := s.FindTarget("stripe")
	if err != nil {
		t.Fatalf("FindTarget: %v", err)
	}
	if ok {
		t.Fatal("FindTarget: expected not found after delete")
	}
}

func TestDeleteTarget_NotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteTarget("missing"); err != ErrNotFound {
		t.Fatalf("DeleteTarget: got %v, want ErrNotFound", err)
	}
}

func TestSecretPathAndName(t *testing.T) {
	tests := []struct {
		secret   string
		wantPath string
		wantName string
	}{
		{"/prod/stripe/api_key", "/prod/stripe", "api_key"},
		{"api_key", "/", "api_key"},
		{"/api_key", "/", "api_key"},
	}
	for _, tt := range tests {
		target := Target{InfisicalSecret: tt.secret}
		path, name := target.SecretPathAndName()
		if path != tt.wantPath || name != tt.wantName {
			t.Errorf("SecretPathAndName(%q) = (%q, %q), want (%q, %q)", tt.secret, path, name, tt.wantPath, tt.wantName)
		}
	}
}
