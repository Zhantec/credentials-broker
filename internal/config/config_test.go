package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleYAML = `
infisical:
  workspace_id: ws-123
  environment: prod

callers:
  - key: sk_agent_one
    targets: ["postgres", "stripe"]
  - key: sk_agent_two
    targets: ["stripe"]

targets:
  - name: postgres
    mode: execute
    driver: postgres
    infisical_secret: "/prod/postgres/dsn"

  - name: stripe
    mode: proxy
    base_url: "https://api.stripe.com"
    infisical_secret: "/prod/stripe/api_key"
    inject_header: "Authorization"
    inject_prefix: "Bearer "
`

func writeSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatalf("writing sample config: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	cfg, err := Load(writeSample(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Infisical.WorkspaceID != "ws-123" || cfg.Infisical.Environment != "prod" {
		t.Fatalf("unexpected infisical block: %+v", cfg.Infisical)
	}
	if len(cfg.Callers) != 2 || len(cfg.Targets) != 2 {
		t.Fatalf("unexpected counts: callers=%d targets=%d", len(cfg.Callers), len(cfg.Targets))
	}
}

func TestFindTarget(t *testing.T) {
	cfg, err := Load(writeSample(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := cfg.FindTarget("missing"); ok {
		t.Fatal("expected missing target to be not-found")
	}
	target, ok := cfg.FindTarget("stripe")
	if !ok || target.BaseURL != "https://api.stripe.com" {
		t.Fatalf("unexpected target: %+v ok=%v", target, ok)
	}
}

func TestFindCaller(t *testing.T) {
	cfg, err := Load(writeSample(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := cfg.FindCaller("sk_unknown"); ok {
		t.Fatal("expected unknown caller to be not-found")
	}
	caller, ok := cfg.FindCaller("sk_agent_two")
	if !ok || len(caller.Targets) != 1 || caller.Targets[0] != "stripe" {
		t.Fatalf("unexpected caller: %+v ok=%v", caller, ok)
	}
}

func TestSecretPathAndName(t *testing.T) {
	cases := []struct {
		secret, wantPath, wantName string
	}{
		{"/prod/postgres/dsn", "/prod/postgres", "dsn"},
		{"dsn", "/", "dsn"},
	}
	for _, c := range cases {
		target := &Target{InfisicalSecret: c.secret}
		path, name := target.SecretPathAndName()
		if path != c.wantPath || name != c.wantName {
			t.Errorf("SecretPathAndName(%q) = (%q, %q), want (%q, %q)", c.secret, path, name, c.wantPath, c.wantName)
		}
	}
}
