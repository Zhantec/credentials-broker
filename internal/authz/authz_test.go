package authz

import (
	"testing"

	"github.com/Zhantec/credentials-broker/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Callers: []config.Caller{
			{Key: "sk_ok", Targets: []string{"stripe"}},
		},
		Targets: []config.Target{
			{Name: "stripe"},
			{Name: "postgres"},
		},
	}
}

func TestCheck(t *testing.T) {
	cfg := testConfig()

	cases := []struct {
		name   string
		key    string
		target string
		want   Result
	}{
		{"unknown key", "sk_bad", "stripe", Unauthenticated},
		{"unknown key, unknown target", "sk_bad", "nope", Unauthenticated},
		{"known key, unknown target", "sk_ok", "nope", TargetNotFound},
		{"known key, not permitted", "sk_ok", "postgres", Forbidden},
		{"known key, permitted", "sk_ok", "stripe", Allowed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Check(cfg, c.key, c.target)
			if got != c.want {
				t.Errorf("Check(%q, %q) = %v, want %v", c.key, c.target, got, c.want)
			}
		})
	}
}
