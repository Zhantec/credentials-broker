# credentials-broker v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go HTTP service that lets callers hit `postgres`/`stripe`/etc. by name, resolves the real credential from Infisical, and either proxies the request (injecting auth) or executes a Postgres query on the caller's behalf — without the caller ever seeing the secret.

**Architecture:** Six small internal packages, each with one job: `config` (load/query YAML), `authz` (401/403/404 decision), `secrets` (Infisical client + TTL cache), `proxy` (HTTP proxy mode), `execute` (Postgres query mode), `server` (routing + the authz/logging wrapper shared by both modes). `cmd/broker/main.go` wires them together. No framework — stdlib `net/http` (Go 1.22+ `ServeMux` path wildcards) and `database/sql`.

**Tech Stack:** Go 1.24, `gopkg.in/yaml.v3` (config), `github.com/jackc/pgx/v5/stdlib` (Postgres driver, prod), `modernc.org/sqlite` (pure-Go driver, tests only — swaps in for the DB-opening step so tests don't need a real Postgres). No Infisical SDK — Universal Auth + secret fetch are two plain `net/http` calls.

**Spec:** `docs/spec.md`

## Global Constraints

- Module path: `github.com/Zhantec/credentials-broker`
- Go version: 1.24 (matches installed toolchain)
- Config file path: `CONFIG_PATH` env var, default `/etc/credentials-broker/config.yaml`
- Infisical auth: Universal Auth via `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` env vars; base URL via `INFISICAL_BASE_URL` (default `https://app.infisical.com`)
- Secret cache TTL: 5 minutes (in-memory, per-process)
- Execute mode v1 supports Postgres only; no query-level authorization or SQL parsing (spec non-goal — blast-radius control is the Infisical credential's DB grants, not broker code)
- Secret material must never appear in response bodies, error bodies, or log lines. Logs record a hash of the caller key, target name, mode, and outcome — never the resolved secret or raw driver errors.
- No testcontainers, no test fixture frameworks — plain `net/http/httptest` and `testing`.

---

### Task 1: Project scaffold + config loader

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `type config.Infisical struct { WorkspaceID, Environment string }`
  - `type config.Caller struct { Key string; Targets []string }`
  - `type config.Target struct { Name, Mode, Driver, BaseURL, InjectHeader, InjectPrefix, InfisicalSecret string }`
  - `type config.Config struct { Infisical Infisical; Callers []Caller; Targets []Target }`
  - `func config.Load(path string) (*Config, error)`
  - `func (c *Config) FindTarget(name string) (*Target, bool)`
  - `func (c *Config) FindCaller(key string) (*Caller, bool)`
  - `func (t *Target) SecretPathAndName() (path, name string)` — splits `"/prod/postgres/dsn"` into `"/prod/postgres"` and `"dsn"`, matching Infisical's `secretPath` + secret-name split.

- [ ] **Step 1: Initialize the module**

```bash
go mod init github.com/Zhantec/credentials-broker
go get gopkg.in/yaml.v3@latest
```

- [ ] **Step 2: Write the failing test**

Create `internal/config/config_test.go`:

```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/config/...`
Expected: FAIL — package `config` and its symbols don't exist yet.

- [ ] **Step 4: Write the implementation**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Infisical struct {
	WorkspaceID string `yaml:"workspace_id"`
	Environment string `yaml:"environment"`
}

type Caller struct {
	Key     string   `yaml:"key"`
	Targets []string `yaml:"targets"`
}

type Target struct {
	Name            string `yaml:"name"`
	Mode            string `yaml:"mode"`
	Driver          string `yaml:"driver,omitempty"`
	BaseURL         string `yaml:"base_url,omitempty"`
	InjectHeader    string `yaml:"inject_header,omitempty"`
	InjectPrefix    string `yaml:"inject_prefix,omitempty"`
	InfisicalSecret string `yaml:"infisical_secret"`
}

type Config struct {
	Infisical Infisical `yaml:"infisical"`
	Callers   []Caller  `yaml:"callers"`
	Targets   []Target  `yaml:"targets"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) FindTarget(name string) (*Target, bool) {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i], true
		}
	}
	return nil, false
}

func (c *Config) FindCaller(key string) (*Caller, bool) {
	for i := range c.Callers {
		if c.Callers[i].Key == key {
			return &c.Callers[i], true
		}
	}
	return nil, false
}

// SecretPathAndName splits the config's dot-path-style secret reference into
// the secretPath and secret name Infisical's API expects as separate fields.
func (t *Target) SecretPathAndName() (path, name string) {
	idx := strings.LastIndex(t.InfisicalSecret, "/")
	if idx < 0 {
		return "/", t.InfisicalSecret
	}
	path = t.InfisicalSecret[:idx]
	if path == "" {
		path = "/"
	}
	return path, t.InfisicalSecret[idx+1:]
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/config/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/config
git commit -m "feat: add config loader for callers/targets/infisical settings"
```

---

### Task 2: Authorization decision logic

**Files:**
- Create: `internal/authz/authz.go`
- Test: `internal/authz/authz_test.go`

**Interfaces:**
- Consumes: `config.Config`, `config.FindCaller`, `config.FindTarget` (Task 1)
- Produces:
  - `type authz.Result int` with values `Allowed`, `Unauthenticated`, `Forbidden`, `TargetNotFound`
  - `func authz.Check(cfg *config.Config, key, targetName string) Result`

Precedence: unknown caller key → `Unauthenticated` (checked first, so an unauthenticated caller can't use target-existence responses to enumerate valid target names). Known key + unknown target → `TargetNotFound`. Known key + known target not in the caller's allow-list → `Forbidden`. Otherwise → `Allowed`.

- [ ] **Step 1: Write the failing test**

Create `internal/authz/authz_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authz/...`
Expected: FAIL — package `authz` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/authz/authz.go`:

```go
package authz

import "github.com/Zhantec/credentials-broker/internal/config"

type Result int

const (
	Allowed Result = iota
	Unauthenticated
	Forbidden
	TargetNotFound
)

// Check authenticates the caller before revealing anything about the
// target, so an invalid key can't be used to probe which target names
// exist.
func Check(cfg *config.Config, key, targetName string) Result {
	caller, ok := cfg.FindCaller(key)
	if !ok {
		return Unauthenticated
	}
	if _, ok := cfg.FindTarget(targetName); !ok {
		return TargetNotFound
	}
	for _, t := range caller.Targets {
		if t == targetName {
			return Allowed
		}
	}
	return Forbidden
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/authz/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/authz
git commit -m "feat: add authz decision logic for caller/target permission checks"
```

---

### Task 3: Infisical secrets client with TTL cache

**Files:**
- Create: `internal/secrets/infisical.go`
- Test: `internal/secrets/infisical_test.go`

**Interfaces:**
- Produces:
  - `func secrets.NewClient(baseURL, clientID, clientSecret, workspaceID, environment string) *Client`
  - `func (c *Client) GetSecret(secretPath, secretName string) (string, error)`
  - `Client` satisfies the `SecretResolver` interface (`GetSecret(secretPath, secretName string) (string, error)`) that Tasks 4 and 5 depend on.

- [ ] **Step 1: Write the failing test**

Create `internal/secrets/infisical_test.go`:

```go
package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeInfisical(t *testing.T) (*httptest.Server, *int, *int) {
	t.Helper()
	var loginCalls, secretCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "test-token",
			"expiresIn":   300,
		})
	})
	mux.HandleFunc("/api/v3/secrets/raw/dsn", func(w http.ResponseWriter, r *http.Request) {
		secretCalls++
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"secretValue": "postgres://real-dsn"},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &loginCalls, &secretCalls
}

func TestGetSecret_CachesValue(t *testing.T) {
	server, loginCalls, secretCalls := fakeInfisical(t)
	client := NewClient(server.URL, "client-id", "client-secret", "ws-1", "prod")

	value, err := client.GetSecret("/prod/postgres", "dsn")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if value != "postgres://real-dsn" {
		t.Fatalf("unexpected value: %q", value)
	}

	if _, err := client.GetSecret("/prod/postgres", "dsn"); err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}

	if *loginCalls != 1 {
		t.Errorf("expected 1 login call, got %d", *loginCalls)
	}
	if *secretCalls != 1 {
		t.Errorf("expected 1 secret call (second should hit cache), got %d", *secretCalls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/secrets/...`
Expected: FAIL — package `secrets` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/secrets/infisical.go`:

```go
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://app.infisical.com"
	cacheTTL       = 5 * time.Minute
)

type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	workspaceID  string
	environment  string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
	cache       map[string]cacheEntry
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

func NewClient(baseURL, clientID, clientSecret, workspaceID, environment string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		workspaceID:  workspaceID,
		environment:  environment,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		cache:        make(map[string]cacheEntry),
	}
}

// GetSecret fetches secretName at secretPath, serving a cached value while
// it's within the TTL.
func (c *Client) GetSecret(secretPath, secretName string) (string, error) {
	cacheKey := secretPath + "/" + secretName

	c.mu.Lock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.value, nil
	}
	c.mu.Unlock()

	token, err := c.accessTokenValue()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s",
		c.baseURL, secretName, c.workspaceID, c.environment, secretPath)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("building secret request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching secret: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching secret: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decoding secret response: %w", err)
	}

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{value: out.Secret.SecretValue, expiresAt: time.Now().Add(cacheTTL)}
	c.mu.Unlock()

	return out.Secret.SecretValue, nil
}

func (c *Client) accessTokenValue() (string, error) {
	c.mu.Lock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		token := c.accessToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	body, err := json.Marshal(map[string]string{
		"clientId":     c.clientID,
		"clientSecret": c.clientSecret,
	})
	if err != nil {
		return "", fmt.Errorf("encoding login request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/auth/universal-auth/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authenticating to infisical: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authenticating to infisical: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int64  `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decoding login response: %w", err)
	}

	c.mu.Lock()
	c.accessToken = out.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	c.mu.Unlock()

	return out.AccessToken, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/secrets/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/secrets
git commit -m "feat: add Infisical secrets client with universal auth and TTL cache"
```

---

### Task 4: Proxy mode handler

**Files:**
- Create: `internal/proxy/proxy.go`
- Test: `internal/proxy/proxy_test.go`

**Interfaces:**
- Consumes: `config.Target` (Task 1), a `SecretResolver` satisfied by `secrets.Client` (Task 3)
- Produces:
  - `type proxy.SecretResolver interface { GetSecret(secretPath, secretName string) (string, error) }`
  - `func proxy.Serve(secrets SecretResolver, httpClient *http.Client) func(w http.ResponseWriter, r *http.Request, target *config.Target)` — the returned function is what Task 6's router dispatches to once authz has passed and the target is resolved.

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/proxy_test.go`:

```go
package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type fakeResolver struct {
	value string
	err   error
}

func (f fakeResolver) GetSecret(secretPath, secretName string) (string, error) {
	return f.value, f.err
}

func TestServe_InjectsHeaderAndForwards(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	target := &config.Target{
		BaseURL:         upstream.URL,
		InjectHeader:    "Authorization",
		InjectPrefix:    "Bearer ",
		InfisicalSecret: "/prod/stripe/api_key",
	}
	handler := Serve(fakeResolver{value: "real-secret"}, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy/stripe/v1/charges", nil)
	req.SetPathValue("rest", "v1/charges")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if gotAuth != "Bearer real-secret" {
		t.Errorf("upstream got Authorization=%q, want %q", gotAuth, "Bearer real-secret")
	}
	if gotPath != "/v1/charges" {
		t.Errorf("upstream got path=%q, want %q", gotPath, "/v1/charges")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("response status = %d, want %d", rec.Code, http.StatusCreated)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "ok" {
		t.Errorf("response body = %q, want %q", body, "ok")
	}
}

func TestServe_SecretResolverError(t *testing.T) {
	target := &config.Target{BaseURL: "http://unused", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{err: errors.New("boom")}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestServe_UpstreamUnreachable(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := upstream.URL
	upstream.Close() // closed before use -> connection refused

	target := &config.Target{BaseURL: deadURL, InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/...`
Expected: FAIL — package `proxy` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/proxy/proxy.go`:

```go
package proxy

import (
	"io"
	"net/http"
	"strings"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type SecretResolver interface {
	GetSecret(secretPath, secretName string) (string, error)
}

// Serve returns a dispatch function for proxy-mode targets: it resolves the
// target's secret, forwards the request to target.BaseURL with the secret
// injected as a header, and streams the upstream response back verbatim.
func Serve(secrets SecretResolver, httpClient *http.Client) func(http.ResponseWriter, *http.Request, *config.Target) {
	return func(w http.ResponseWriter, r *http.Request, target *config.Target) {
		rest := r.PathValue("rest")

		path, name := target.SecretPathAndName()
		secret, err := secrets.GetSecret(path, name)
		if err != nil {
			http.Error(w, "secret unavailable", http.StatusBadGateway)
			return
		}

		upstreamURL := strings.TrimRight(target.BaseURL, "/") + "/" + rest
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
		if err != nil {
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}
		req.Header = r.Header.Clone()
		req.Header.Set(target.InjectHeader, target.InjectPrefix+secret)

		resp, err := httpClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy
git commit -m "feat: add proxy-mode handler that injects resolved secret as a header"
```

---

### Task 5: Execute mode handler (Postgres)

**Files:**
- Create: `internal/execute/postgres.go`
- Test: `internal/execute/postgres_test.go`

**Interfaces:**
- Consumes: `config.Target` (Task 1), a `SecretResolver` satisfied by `secrets.Client` (Task 3)
- Produces:
  - `type execute.SecretResolver interface { GetSecret(secretPath, secretName string) (string, error) }`
  - `type execute.DBOpener func(driverName, dsn string) (*sql.DB, error)`
  - `func execute.Serve(secrets SecretResolver, open DBOpener) func(w http.ResponseWriter, r *http.Request, target *config.Target)`

- [ ] **Step 1: Add the test-only sqlite driver dependency**

```bash
go get modernc.org/sqlite@latest
```

- [ ] **Step 2: Write the failing test**

Create `internal/execute/postgres_test.go`:

```go
package execute

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type fakeResolver struct{ value string }

func (f fakeResolver) GetSecret(secretPath, secretName string) (string, error) {
	return f.value, nil
}

func sqliteOpener(driverName, dsn string) (*sql.DB, error) {
	return sql.Open("sqlite", dsn)
}

func seedDB(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening seed db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER, name TEXT)`); err != nil {
		t.Fatalf("creating table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name) VALUES (1, 'ada')`); err != nil {
		t.Fatalf("seeding row: %v", err)
	}
}

func TestServe_RunsQueryAndReturnsRows(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/test.db"
	seedDB(t, dsn)

	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: dsn}, sqliteOpener)

	body := strings.NewReader(`{"query": "SELECT id, name FROM users"}`)
	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", body)
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got.Columns) != 2 || len(got.Rows) != 1 {
		t.Fatalf("unexpected shape: %+v", got)
	}
	if got.Rows[0][1] != "ada" {
		t.Errorf("row[0][1] = %v, want %q (want string, not base64 bytes)", got.Rows[0][1], "ada")
	}
}

func TestServe_InvalidBody(t *testing.T) {
	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: "unused"}, sqliteOpener)

	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestServe_QueryErrorDoesNotLeakDriverDetails(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/test.db"
	seedDB(t, dsn)

	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: dsn}, sqliteOpener)

	body := strings.NewReader(`{"query": "SELECT * FROM does_not_exist"}`)
	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", body)
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "does_not_exist") {
		t.Errorf("response leaked raw driver error: %s", rec.Body.String())
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/execute/...`
Expected: FAIL — package `execute` doesn't exist yet.

- [ ] **Step 4: Write the implementation**

Create `internal/execute/postgres.go`:

```go
package execute

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type SecretResolver interface {
	GetSecret(secretPath, secretName string) (string, error)
}

type DBOpener func(driverName, dsn string) (*sql.DB, error)

type queryRequest struct {
	Query string `json:"query"`
}

type queryResponse struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// Serve returns a dispatch function for execute-mode targets: it runs the
// caller's query against the target using the resolved credential and
// returns the result as JSON. There is no query-level authorization here by
// design — see docs/spec.md's non-goals.
func Serve(secrets SecretResolver, open DBOpener) func(http.ResponseWriter, *http.Request, *config.Target) {
	return func(w http.ResponseWriter, r *http.Request, target *config.Target) {
		var req queryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Query == "" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		path, name := target.SecretPathAndName()
		dsn, err := secrets.GetSecret(path, name)
		if err != nil {
			http.Error(w, "secret unavailable", http.StatusBadGateway)
			return
		}

		db, err := open(target.Driver, dsn)
		if err != nil {
			log.Printf("execute: opening db for target %s: %v", target.Name, err)
			http.Error(w, "target unavailable", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rows, err := db.QueryContext(r.Context(), req.Query)
		if err != nil {
			log.Printf("execute: query failed for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		cols, err := rows.Columns()
		if err != nil {
			log.Printf("execute: reading columns for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		resp := queryResponse{Columns: cols, Rows: [][]any{}}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				log.Printf("execute: scanning row for target %s: %v", target.Name, err)
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
			// database/sql drivers commonly return TEXT columns as []byte;
			// convert to string so JSON encodes readable text, not base64.
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			resp.Rows = append(resp.Rows, vals)
		}
		if err := rows.Err(); err != nil {
			log.Printf("execute: iterating rows for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/execute/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/execute
git commit -m "feat: add execute-mode handler for running queries against Postgres targets"
```

---

### Task 6: HTTP server wiring (routing, authz, logging)

**Files:**
- Create: `internal/server/server.go`
- Test: `internal/server/server_test.go`

**Interfaces:**
- Consumes: `config.Config`, `authz.Check` (Task 2), the `dispatchFunc` signature produced by `proxy.Serve` (Task 4) and `execute.Serve` (Task 5)
- Produces:
  - `type server.DispatchFunc func(w http.ResponseWriter, r *http.Request, target *config.Target)`
  - `func server.New(cfg *config.Config, proxyHandler, executeHandler DispatchFunc) http.Handler`

- [ ] **Step 1: Write the failing test**

Create `internal/server/server_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/...`
Expected: FAIL — package `server` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/server/server.go`:

```go
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"github.com/Zhantec/credentials-broker/internal/authz"
	"github.com/Zhantec/credentials-broker/internal/config"
)

type DispatchFunc func(w http.ResponseWriter, r *http.Request, target *config.Target)

func New(cfg *config.Config, proxyHandler, executeHandler DispatchFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/{target}/{rest...}", withAuthz(cfg, "proxy", proxyHandler))
	mux.HandleFunc("POST /execute/{target}", withAuthz(cfg, "execute", executeHandler))
	return mux
}

func withAuthz(cfg *config.Config, mode string, next DispatchFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetName := r.PathValue("target")
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		result := authz.Check(cfg, key, targetName)
		log.Printf("caller=%s target=%s mode=%s outcome=%s", hashKey(key), targetName, mode, outcomeLabel(result))

		switch result {
		case authz.Unauthenticated:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		case authz.TargetNotFound:
			http.Error(w, "target not found", http.StatusNotFound)
			return
		case authz.Forbidden:
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		target, _ := cfg.FindTarget(targetName)
		next(w, r, target)
	}
}

// hashKey avoids ever logging a caller's raw API key.
func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:8]
}

func outcomeLabel(r authz.Result) string {
	switch r {
	case authz.Allowed:
		return "allowed"
	case authz.Unauthenticated:
		return "unauthenticated"
	case authz.Forbidden:
		return "forbidden"
	case authz.TargetNotFound:
		return "target_not_found"
	default:
		return "unknown"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/server
git commit -m "feat: add server routing with authz wrapper and non-secret-leaking logs"
```

---

### Task 7: Entrypoint + Dockerfile

**Files:**
- Create: `cmd/broker/main.go`
- Create: `Dockerfile`, `.dockerignore`
- Create: `config.example.yaml`

**Interfaces:**
- Consumes: `config.Load` (Task 1), `secrets.NewClient` (Task 3), `proxy.Serve` (Task 4), `execute.Serve` (Task 5), `server.New` (Task 6)
- Produces: the `broker` binary (no further consumers — this is the top of the dependency graph)

- [ ] **Step 1: Add the production Postgres driver dependency**

```bash
go get github.com/jackc/pgx/v5@latest
```

- [ ] **Step 2: Write main.go**

Create `cmd/broker/main.go`:

```go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Zhantec/credentials-broker/internal/config"
	"github.com/Zhantec/credentials-broker/internal/execute"
	"github.com/Zhantec/credentials-broker/internal/proxy"
	"github.com/Zhantec/credentials-broker/internal/secrets"
	"github.com/Zhantec/credentials-broker/internal/server"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/credentials-broker/config.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	secretsClient := secrets.NewClient(
		os.Getenv("INFISICAL_BASE_URL"),
		os.Getenv("INFISICAL_CLIENT_ID"),
		os.Getenv("INFISICAL_CLIENT_SECRET"),
		cfg.Infisical.WorkspaceID,
		cfg.Infisical.Environment,
	)

	handler := server.New(
		cfg,
		proxy.Serve(secretsClient, http.DefaultClient),
		execute.Serve(secretsClient, openDB),
	)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf(":%s", port)
	log.Printf("credentials-broker listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func openDB(driverName, dsn string) (*sql.DB, error) {
	if driverName != "postgres" {
		return nil, fmt.Errorf("unsupported driver %q", driverName)
	}
	return sql.Open("pgx", dsn)
}
```

- [ ] **Step 3: Verify it builds**

Run: `go build ./...`
Expected: succeeds with no output.

- [ ] **Step 4: Write the example config**

Create `config.example.yaml`:

```yaml
infisical:
  workspace_id: "your-workspace-id"
  environment: "prod"

callers:
  - key: "sk_agent_replace_me"
    targets: ["postgres", "stripe"]

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
```

- [ ] **Step 5: Write the Dockerfile**

Create `Dockerfile`:

```dockerfile
FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/broker ./cmd/broker

FROM gcr.io/distroless/static-debian12
COPY --from=builder /out/broker /broker
EXPOSE 8080
ENTRYPOINT ["/broker"]
```

Create `.dockerignore`:

```
.git
.worktrees
docs
*.md
```

- [ ] **Step 6: Verify the image builds**

Run: `docker build -t credentials-broker:dev .`
Expected: build succeeds.

- [ ] **Step 7: Commit**

```bash
git add cmd/broker Dockerfile .dockerignore config.example.yaml
git commit -m "feat: add entrypoint, Dockerfile, and example config"
```

---

## Self-Review Notes

- Spec coverage: caller auth (Task 2/6), target config (Task 1), Infisical Universal Auth + caching (Task 3), proxy mode (Task 4), execute mode/Postgres (Task 5), error codes 401/403/404/502/500 (Tasks 2, 4, 5, 6), no query-level authorization (Task 5, by omission per spec non-goal), secrets never logged/echoed (Tasks 3, 5, 6 all use generic messages + hashed key in logs), Docker (Task 7). All spec sections have a task.
- Type consistency: `SecretResolver` interface shape (`GetSecret(secretPath, secretName string) (string, error)`) matches across `secrets.Client`, `proxy.SecretResolver`, and `execute.SecretResolver`. `DispatchFunc`/dispatch signature (`func(http.ResponseWriter, *http.Request, *config.Target)`) matches across `proxy.Serve`, `execute.Serve`, and `server.New`'s parameters.
- No placeholders: every step has runnable code.
