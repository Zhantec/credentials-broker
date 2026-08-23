# DB-Backed Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the static `config.yaml` file with an embedded SQLite store (`internal/store`) managed through a new `/admin/*` HTTP API, so targets and callers can be created/listed/deleted at runtime instead of requiring a file SCP to every sidecar.

**Architecture:** A new `internal/store` package owns a SQLite database (three tables: `targets`, `callers`, `caller_targets`) and all CRUD. `internal/secrets`, `internal/oauth`, and `internal/proxy` change `SecretResolver`/`GetSecret` to take `workspaceID, environment` as call-time parameters instead of client-level config, enabling one broker to span multiple Infisical projects. `internal/authz` and `internal/server` swap from `*config.Config` to `*store.Store`, and `internal/server` gains admin routes gated by a constant-time `ADMIN_API_KEY` check. `internal/config` and `config.example.yaml` are deleted once nothing references them.

**Tech Stack:** Go 1.25, `net/http` `ServeMux` (Go 1.22+ path-value wildcards), `database/sql` + `modernc.org/sqlite` (pure-Go, CGO-free — required by the `CGO_ENABLED=0` Dockerfile build).

## Global Constraints

- No CGO: the SQLite driver must be `modernc.org/sqlite` (pure Go), not `mattn/go-sqlite3`. `Dockerfile` builds with `CGO_ENABLED=0`.
- Fail closed: the broker must refuse to start if `ADMIN_API_KEY` is empty.
- Constant-time comparison (`crypto/subtle.ConstantTimeCompare`) for both `ADMIN_API_KEY` and caller-key hash matching.
- Raw caller keys are never stored — only their SHA-256 hash.
- Table-driven tests throughout; no mocking frameworks, no testcontainers (matches existing `docs/spec.md` testing philosophy). `internal/store`-backed tests use a real SQLite database opened at `:memory:`.
- Admin endpoints are create/list/delete only — no update, no get-by-id.
- A caller with zero scoped targets has dynamic all-access to every currently-registered target.
- `inject_header`/`inject_prefix` default to `"Authorization"`/`"Bearer "` when omitted from a target-creation request, then are validated as required (`inject_header` must be non-empty after defaulting; `inject_prefix` may be empty).
- Between Task 3 and Task 9, `go build ./...` / `go test ./...` at the repo root will fail (the `SecretResolver`/`store` signature changes ripple through packages that aren't rewired until later tasks). Each task's testing step scopes `go test` to the packages that task actually touches — this is expected, not a regression to fix early.

---

### Task 1: `internal/store` — schema + Target CRUD

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/targets.go`
- Create: `internal/store/targets_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`)

**Interfaces:**
- Produces: `store.Store` (opaque, holds `*sql.DB`), `store.Open(path string) (*Store, error)`, `(*Store).Close() error`, `store.ErrNotFound`, `store.ErrAlreadyExists`, `store.Target{Name, Mode, BaseURL, InfisicalWorkspaceID, InfisicalEnvironment, InfisicalSecret, InjectHeader, InjectPrefix string}`, `(*Target).SecretPathAndName() (path, name string)`, `(*Store).CreateTarget(t Target) error`, `(*Store).ListTargets() ([]Target, error)`, `(*Store).DeleteTarget(name string) error`, `(*Store).FindTarget(name string) (*Target, bool, error)`.

- [ ] **Step 1: Add the SQLite driver dependency**

Run: `go get modernc.org/sqlite`

This updates `go.mod`/`go.sum` with the latest pure-Go SQLite driver and its transitive dependencies.

- [ ] **Step 2: Write `internal/store/store.go`**

```go
// Package store persists targets and callers in an embedded SQLite
// database, replacing the static YAML config file every prior version
// used. See docs/superpowers/specs/2026-08-22-db-backed-config-design.md.
package store

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup or delete finds no matching row.
var ErrNotFound = errors.New("not found")

// ErrAlreadyExists is returned when a create would violate a uniqueness
// constraint (e.g. a target name that's already registered).
var ErrAlreadyExists = errors.New("already exists")

const schema = `
CREATE TABLE IF NOT EXISTS targets (
	name                   TEXT PRIMARY KEY,
	mode                   TEXT NOT NULL,
	base_url               TEXT NOT NULL,
	infisical_workspace_id TEXT NOT NULL,
	infisical_environment  TEXT NOT NULL,
	infisical_secret       TEXT NOT NULL,
	inject_header          TEXT NOT NULL,
	inject_prefix          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS callers (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS caller_targets (
	caller_id   INTEGER NOT NULL REFERENCES callers(id) ON DELETE CASCADE,
	target_name TEXT NOT NULL REFERENCES targets(name) ON DELETE CASCADE,
	PRIMARY KEY (caller_id, target_name)
);
`

// Store wraps the broker's SQLite database.
type Store struct {
	db *sql.DB
}

// Open creates (if needed) and opens the SQLite database at path,
// applying the schema. path may be ":memory:" for tests.
//
// ponytail: single connection avoids SQLite's multi-writer locking and
// the ":memory:"-per-connection gotcha; move to Postgres if write
// throughput ever matters.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
```

- [ ] **Step 3: Write `internal/store/targets.go`**

```go
package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// Target is a proxyable upstream, addressed by name in
// /proxy/{name}/... and backed by a credential resolved from Infisical.
type Target struct {
	Name                 string
	Mode                 string
	BaseURL              string
	InfisicalWorkspaceID string
	InfisicalEnvironment string
	InfisicalSecret      string
	InjectHeader         string
	InjectPrefix         string
}

// SecretPathAndName splits the slash-path-style secret reference into
// the secretPath and secret name Infisical's API expects as separate
// fields.
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

// CreateTarget inserts a new target. It returns ErrAlreadyExists if a
// target with this name already exists.
func (s *Store) CreateTarget(t Target) error {
	_, err := s.db.Exec(
		`INSERT INTO targets (name, mode, base_url, infisical_workspace_id, infisical_environment, infisical_secret, inject_header, inject_prefix)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Name, t.Mode, t.BaseURL, t.InfisicalWorkspaceID, t.InfisicalEnvironment, t.InfisicalSecret, t.InjectHeader, t.InjectPrefix,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrAlreadyExists
		}
		return fmt.Errorf("inserting target: %w", err)
	}
	return nil
}

// ListTargets returns every registered target, ordered by name.
func (s *Store) ListTargets() ([]Target, error) {
	rows, err := s.db.Query(
		`SELECT name, mode, base_url, infisical_workspace_id, infisical_environment, infisical_secret, inject_header, inject_prefix
		 FROM targets ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var targets []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.Name, &t.Mode, &t.BaseURL, &t.InfisicalWorkspaceID, &t.InfisicalEnvironment, &t.InfisicalSecret, &t.InjectHeader, &t.InjectPrefix); err != nil {
			return nil, fmt.Errorf("scanning target: %w", err)
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// DeleteTarget removes a target by name. It returns ErrNotFound if no
// target has that name.
func (s *Store) DeleteTarget(name string) error {
	res, err := s.db.Exec(`DELETE FROM targets WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("deleting target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking delete result: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// FindTarget looks up a target by name.
func (s *Store) FindTarget(name string) (*Target, bool, error) {
	var t Target
	err := s.db.QueryRow(
		`SELECT name, mode, base_url, infisical_workspace_id, infisical_environment, infisical_secret, inject_header, inject_prefix
		 FROM targets WHERE name = ?`,
		name,
	).Scan(&t.Name, &t.Mode, &t.BaseURL, &t.InfisicalWorkspaceID, &t.InfisicalEnvironment, &t.InfisicalSecret, &t.InjectHeader, &t.InjectPrefix)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("querying target: %w", err)
	}
	return &t, true, nil
}
```

- [ ] **Step 4: Write `internal/store/targets_test.go`**

```go
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
		{"/api_key", "", "api_key"},
	}
	for _, tt := range tests {
		target := Target{InfisicalSecret: tt.secret}
		path, name := target.SecretPathAndName()
		if path != tt.wantPath || name != tt.wantName {
			t.Errorf("SecretPathAndName(%q) = (%q, %q), want (%q, %q)", tt.secret, path, name, tt.wantPath, tt.wantName)
		}
	}
}
```

Note: the third case (`/api_key`) intentionally documents that a leading-slash-only secret with no further path segment yields an **empty** `path`, not `"/"` — the `path == ""` fallback to `"/"` only applies when `InfisicalSecret` has no `/` at all (case 2). This matches `config.go`'s original `SecretPathAndName` behavior being ported here unchanged.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/store/... -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/store/store.go internal/store/targets.go internal/store/targets_test.go
git commit -m "feat: add internal/store with target CRUD backed by SQLite"
```

---

### Task 2: `internal/store` — Caller CRUD

**Files:**
- Create: `internal/store/callers.go`
- Create: `internal/store/callers_test.go`

**Interfaces:**
- Consumes: `store.Store` (Task 1), `store.ErrNotFound`.
- Produces: `store.Caller{ID int64, Targets []string}`, `(*Store).CreateCaller(targets []string) (id int64, rawKey string, err error)`, `(*Store).ListCallers() ([]Caller, error)`, `(*Store).DeleteCaller(id int64) error`, `(*Store).FindCallerByKey(rawKey string) (*Caller, bool, error)`.

- [ ] **Step 1: Write `internal/store/callers.go`**

```go
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Caller is a broker-access identity. Targets lists the target names
// this caller may use; an empty list means the caller may use every
// target currently registered on this broker instance.
type Caller struct {
	ID      int64
	Targets []string
}

func hashRawKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

func generateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating key: %w", err)
	}
	return "sk_live_" + hex.EncodeToString(buf), nil
}

// CreateCaller generates a new random caller key, persists its hash
// with the given target scope, and returns the caller's id alongside
// the raw key. The raw key is never stored and this is the only time
// it's returned — callers must save it now.
func (s *Store) CreateCaller(targets []string) (id int64, rawKey string, err error) {
	rawKey, err = generateKey()
	if err != nil {
		return 0, "", err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, "", fmt.Errorf("starting transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`INSERT INTO callers (key_hash) VALUES (?)`, hashRawKey(rawKey))
	if err != nil {
		return 0, "", fmt.Errorf("inserting caller: %w", err)
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, "", fmt.Errorf("reading new caller id: %w", err)
	}

	for _, target := range targets {
		if _, err := tx.Exec(`INSERT INTO caller_targets (caller_id, target_name) VALUES (?, ?)`, id, target); err != nil {
			return 0, "", fmt.Errorf("scoping caller to target %q: %w", target, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("committing caller: %w", err)
	}
	return id, rawKey, nil
}

// ListCallers returns every registered caller (never their keys),
// ordered by id.
func (s *Store) ListCallers() ([]Caller, error) {
	rows, err := s.db.Query(`SELECT id FROM callers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("querying callers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var callers []Caller
	for rows.Next() {
		var c Caller
		if err := rows.Scan(&c.ID); err != nil {
			return nil, fmt.Errorf("scanning caller: %w", err)
		}
		callers = append(callers, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range callers {
		targets, err := s.targetsForCaller(callers[i].ID)
		if err != nil {
			return nil, err
		}
		callers[i].Targets = targets
	}
	return callers, nil
}

func (s *Store) targetsForCaller(callerID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT target_name FROM caller_targets WHERE caller_id = ? ORDER BY target_name`, callerID)
	if err != nil {
		return nil, fmt.Errorf("querying caller targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var targets []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scanning caller target: %w", err)
		}
		targets = append(targets, name)
	}
	return targets, rows.Err()
}

// DeleteCaller removes a caller by id. It returns ErrNotFound if no
// caller has that id.
func (s *Store) DeleteCaller(id int64) error {
	res, err := s.db.Exec(`DELETE FROM callers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting caller: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking delete result: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// FindCallerByKey looks up the caller whose key hashes to rawKey.
func (s *Store) FindCallerByKey(rawKey string) (*Caller, bool, error) {
	want := hashRawKey(rawKey)

	rows, err := s.db.Query(`SELECT id, key_hash FROM callers`)
	if err != nil {
		return nil, false, fmt.Errorf("querying callers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var id int64
	found := false
	for rows.Next() {
		var candidateID int64
		var candidateHash string
		if err := rows.Scan(&candidateID, &candidateHash); err != nil {
			return nil, false, fmt.Errorf("scanning caller: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(candidateHash), []byte(want)) == 1 {
			id, found = candidateID, true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}

	targets, err := s.targetsForCaller(id)
	if err != nil {
		return nil, false, err
	}
	return &Caller{ID: id, Targets: targets}, true, nil
}
```

- [ ] **Step 2: Write `internal/store/callers_test.go`**

```go
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
```

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/store/... -v`
Expected: all tests PASS (Task 1's tests still pass alongside these).

- [ ] **Step 4: Commit**

```bash
git add internal/store/callers.go internal/store/callers_test.go
git commit -m "feat: add caller CRUD with hashed keys and all-access scoping"
```

---

### Task 3: Multi-project Infisical support (`internal/secrets`, `internal/oauth`, `internal/proxy`)

**Files:**
- Modify: `internal/secrets/infisical.go`
- Modify: `internal/secrets/infisical_test.go`
- Modify: `internal/oauth/oauth.go`
- Modify: `internal/oauth/oauth_test.go`
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/proxy_test.go`

**Interfaces:**
- Consumes: `store.Target` (Task 1).
- Produces: `secrets.Client.GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)`, `secrets.NewClient(baseURL, clientID, clientSecret string) *Client`, `oauth.SecretResolver.GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)`, `oauth.Client.GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)`, `proxy.SecretResolver.GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)`, `proxy.Serve(secrets SecretResolver, httpClient *http.Client) func(http.ResponseWriter, *http.Request, *store.Target)`.

- [ ] **Step 1: Update `internal/secrets/infisical.go`**

Replace the `Client` struct, `NewClient`, and `GetSecret` (lines 18–111) with:

```go
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	mu           sync.RWMutex
	secretCache  map[string]cacheEntry
	tokenCache   *cacheEntry
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

func NewClient(baseURL, clientID, clientSecret string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		secretCache:  make(map[string]cacheEntry),
	}
}

// GetSecret fetches secretName at secretPath within workspaceID's
// environment, serving a cached value while it's within the TTL.
func (c *Client) GetSecret(workspaceID, environment, secretPath, secretName string) (string, error) {
	cacheKey := workspaceID + ":" + environment + ":" + secretPath + ":" + secretName

	// Check cache
	c.mu.RLock()
	if entry, ok := c.secretCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.value, nil
	}
	c.mu.RUnlock()

	// Get access token
	token, err := c.accessTokenValue()
	if err != nil {
		return "", fmt.Errorf("get access token: %w", err)
	}

	// Fetch secret from API
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?secretPath=%s&environment=%s&workspaceId=%s",
		c.baseURL, secretName, secretPath, environment, workspaceID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch secret: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetch secret: %d %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	value := result.Secret.SecretValue

	// Cache result
	c.mu.Lock()
	c.secretCache[cacheKey] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(cacheTTL),
	}
	c.mu.Unlock()

	return value, nil
}
```

`accessTokenValue` (the rest of the file) is unchanged — it only uses `clientID`/`clientSecret`, not workspace/environment.

- [ ] **Step 2: Update `internal/secrets/infisical_test.go`**

Run these two mechanical replacements first:

```bash
sed -i 's/NewClient(\(.*\), "ws-1", "prod")/NewClient(\1)/' internal/secrets/infisical_test.go
sed -i 's/\.GetSecret("\/prod\/postgres", "dsn")/.GetSecret("ws-1", "prod", "\/prod\/postgres", "dsn")/g' internal/secrets/infisical_test.go
```

Then find the `TestGetSecret_SecretFetchUnreachable` test, which builds a `Client` via struct literal instead of `NewClient`. It currently looks like:

```go
c := &Client{
	baseURL:      "http://127.0.0.1:0",
	clientID:     "client-id",
	clientSecret: "client-secret",
	workspaceID:  "ws-1",
	environment:  "prod",
	httpClient:   &http.Client{Timeout: time.Second},
	secretCache:  make(map[string]cacheEntry),
}
```

Remove the `workspaceID:` and `environment:` lines (those fields no longer exist on `Client`):

```go
c := &Client{
	baseURL:      "http://127.0.0.1:0",
	clientID:     "client-id",
	clientSecret: "client-secret",
	httpClient:   &http.Client{Timeout: time.Second},
	secretCache:  make(map[string]cacheEntry),
}
```

(Its `GetSecret` call site was already updated by the second `sed` above.)

- [ ] **Step 3: Run the secrets tests**

Run: `go test ./internal/secrets/... -v`
Expected: all tests PASS.

- [ ] **Step 4: Update `internal/oauth/oauth.go`**

Replace the `SecretResolver` interface and `GetSecret` method with:

```go
type SecretResolver interface {
	GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)
}
```

```go
// GetSecret exchanges the OAuth2 client_credentials stored at
// workspaceID/environment/secretPath/secretName for an access token,
// caching it until shortly before it expires.
func (c *Client) GetSecret(workspaceID, environment, secretPath, secretName string) (string, error) {
	cacheKey := workspaceID + ":" + environment + ":" + secretPath + ":" + secretName

	c.mu.Lock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.value, nil
	}
	c.mu.Unlock()

	raw, err := c.secrets.GetSecret(workspaceID, environment, secretPath, secretName)
	if err != nil {
		return "", fmt.Errorf("resolving client credentials: %w", err)
	}

	var creds clientCredentials
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return "", fmt.Errorf("parsing client credentials: %w", err)
	}
	if creds.TokenURL == "" {
		return "", fmt.Errorf("client credentials missing token_url")
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.ClientID},
		"client_secret": {creds.ClientSecret},
	}
	if creds.Scope != "" {
		form.Set("scope", creds.Scope)
	}

	req, err := http.NewRequest("POST", creds.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token grant: %d %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		// ponytail: some providers omit expires_in; 60s is a
		// conservative floor that forces a near-term refresh instead
		// of caching an unknown-lifetime token indefinitely.
		expiresIn = 60
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn)*time.Second - 5*time.Second)

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{value: tr.AccessToken, expiresAt: expiresAt}
	c.mu.Unlock()

	return tr.AccessToken, nil
}
```

Check the file's import block includes `"net/url"` and `"strings"` (both used above); add them if missing.

- [ ] **Step 5: Update `internal/oauth/oauth_test.go`**

Every call site of the form `c.GetSecret("/prod/gh", "oauth_client")` (or similar 2-arg calls) needs `"ws-1", "prod"` prepended. Run:

```bash
sed -i -E 's/\.GetSecret\("([^"]*)", "([^"]*)"\)/.GetSecret("ws-1", "prod", "\1", "\2")/g' internal/oauth/oauth_test.go
```

Also check `fakeResolver`'s `GetSecret` method signature in this file — update it from `GetSecret(secretPath, secretName string) (string, error)` to `GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)` so it still satisfies `oauth.SecretResolver`. If `fakeResolver`'s body keys its stub responses off `secretPath`/`secretName` (ignoring workspace/environment), keep that behavior — just add the two new unused parameters to the method signature.

- [ ] **Step 6: Run the oauth tests**

Run: `go test ./internal/oauth/... -v`
Expected: all tests PASS. If `fakeResolver`'s updated signature causes a compile error because the sed also rewrote an unrelated call inside its own body, fix that call site manually to match its intent (the sed pattern only matches two-string-literal-argument calls, which should not appear inside `fakeResolver`'s implementation itself).

- [ ] **Step 7: Update `internal/proxy/proxy.go`**

Replace the import of `internal/config` with `internal/store`, and update `SecretResolver` and `Serve`:

```go
package proxy

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/Zhantec/credentials-broker/internal/reqctx"
	"github.com/Zhantec/credentials-broker/internal/store"
)

type SecretResolver interface {
	GetSecret(workspaceID, environment, secretPath, secretName string) (string, error)
}

// Serve returns a dispatch function for proxy-mode targets: it resolves the
// target's secret, forwards the request to target.BaseURL with the secret
// injected as a header, and streams the upstream response back verbatim.
func Serve(secrets SecretResolver, httpClient *http.Client) func(http.ResponseWriter, *http.Request, *store.Target) {
	return func(w http.ResponseWriter, r *http.Request, target *store.Target) {
		secretPath, secretName := target.SecretPathAndName()
		secret, err := secrets.GetSecret(target.InfisicalWorkspaceID, target.InfisicalEnvironment, secretPath, secretName)
		if err != nil {
			log.Printf("caller=%s target=%s outcome=error stage=resolve_secret err=%v", reqctx.Caller(r.Context()), target.Name, err)
			http.Error(w, "secret unavailable", http.StatusBadGateway)
			return
		}

		base, err := url.Parse(target.BaseURL)
		if err != nil {
			log.Printf("caller=%s target=%s outcome=error stage=parse_base_url err=%v", reqctx.Caller(r.Context()), target.Name, err)
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}

		// ServeMux hands the wildcard to us percent-decoded, so "%3F"/"%23"
		// would otherwise re-parse as query/fragment metacharacters and
		// "%2e%2e" as a "..' segment escaping base_url's path prefix.
		// path.Clean resolves the traversal; leaving RawPath empty makes the
		// join re-escape everything else.
		rest := path.Clean("/" + r.PathValue("rest"))
		if strings.HasSuffix(r.PathValue("rest"), "/") && !strings.HasSuffix(rest, "/") {
			rest += "/"
		}

		if httpClient.Timeout > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), httpClient.Timeout)
			defer cancel()
			r = r.WithContext(ctx)
		}

		rp := &httputil.ReverseProxy{
			Transport: httpClient.Transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Path = rest
				pr.Out.URL.RawPath = ""
				pr.SetURL(base)
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Set(target.InjectHeader, target.InjectPrefix+secret)
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				log.Printf("caller=%s target=%s outcome=error stage=upstream_request err=%v", reqctx.Caller(r.Context()), target.Name, err)
				http.Error(w, "upstream unreachable", http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
	}
}
```

- [ ] **Step 8: Update `internal/proxy/proxy_test.go`**

Replace every `&config.Target{...}` construction with `&store.Target{...}` (same field names — `store.Target` was ported field-for-field from `config.Target` in Task 1) and update the import:

```bash
sed -i 's#"github.com/Zhantec/credentials-broker/internal/config"#"github.com/Zhantec/credentials-broker/internal/store"#' internal/proxy/proxy_test.go
sed -i 's/config\.Target/store.Target/g' internal/proxy/proxy_test.go
```

Update `fakeResolver`'s `GetSecret` method signature the same way as Task 3 Step 5 — add `workspaceID, environment` as its first two parameters:

```bash
sed -i -E 's/GetSecret\(secretPath, secretName string\)/GetSecret(workspaceID, environment, secretPath, secretName string)/' internal/proxy/proxy_test.go
```

Any direct call sites in this file of the form `secrets.GetSecret("/some/path", "name")` (e.g. a test that calls the resolver directly rather than through `Serve`) need `"ws-1", "prod"` prepended — apply the same pattern as Task 3 Step 5 if such call sites exist:

```bash
sed -i -E 's/\.GetSecret\("([^"]*)", "([^"]*)"\)/.GetSecret("ws-1", "prod", "\1", "\2")/g' internal/proxy/proxy_test.go
```

Since `store.Target`'s zero-value fields for `InfisicalWorkspaceID`/`InfisicalEnvironment` are now meaningful (Task 1), any test target literal that doesn't set them will pass empty strings through to `GetSecret` — that's fine for tests using a `fakeResolver` that ignores those parameters, but if a test asserts on the exact `GetSecret` call arguments, add `InfisicalWorkspaceID: "ws-1", InfisicalEnvironment: "prod"` to that target literal to match.

- [ ] **Step 9: Run the proxy tests**

Run: `go test ./internal/proxy/... -v`
Expected: all tests PASS.

- [ ] **Step 10: Commit**

```bash
git add internal/secrets internal/oauth internal/proxy
git commit -m "feat: resolve secrets by per-call workspace/environment instead of client-level config"
```

---

### Task 4: `internal/authz` — migrate to the store

**Files:**
- Modify: `internal/authz/authz.go`
- Modify: `internal/authz/authz_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Target`, `store.Caller` (Tasks 1–2).
- Produces: `authz.Check(s *store.Store, key, targetName string) (Result, error)`, `authz.Result` (`Allowed`, `Unauthenticated`, `Forbidden`, `TargetNotFound` — unchanged values/names).

- [ ] **Step 1: Rewrite `internal/authz/authz.go`**

```go
// Package authz decides whether a presented caller key may reach a
// given target.
package authz

import (
	"fmt"

	"github.com/Zhantec/credentials-broker/internal/store"
)

// Result is the outcome of an authorization check.
type Result int

const (
	Allowed Result = iota
	Unauthenticated
	Forbidden
	TargetNotFound
)

// Check authenticates caller before revealing anything about target, so
// an invalid key can't be used to probe target names exist.
func Check(s *store.Store, key, targetName string) (Result, error) {
	caller, ok, err := s.FindCallerByKey(key)
	if err != nil {
		return 0, fmt.Errorf("looking up caller: %w", err)
	}
	if !ok {
		return Unauthenticated, nil
	}

	_, ok, err = s.FindTarget(targetName)
	if err != nil {
		return 0, fmt.Errorf("looking up target: %w", err)
	}
	if !ok {
		return TargetNotFound, nil
	}

	if len(caller.Targets) == 0 {
		return Allowed, nil
	}
	for _, t := range caller.Targets {
		if t == targetName {
			return Allowed, nil
		}
	}
	return Forbidden, nil
}
```

- [ ] **Step 2: Rewrite `internal/authz/authz_test.go`**

```go
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
```

- [ ] **Step 3: Run the authz tests**

Run: `go test ./internal/authz/... -v`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/authz
git commit -m "feat: migrate authz.Check to the SQLite-backed store"
```

---

### Task 5: `internal/server` — store wiring + admin auth middleware

**Files:**
- Modify: `internal/server/server.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Target` (Tasks 1–2), `authz.Check` (Task 4), `proxy.Serve`'s `DispatchFunc`-compatible signature (Task 3).
- Produces: `server.DispatchFunc = func(w http.ResponseWriter, r *http.Request, target *store.Target)`, `server.New(s *store.Store, adminAPIKey string, handlers map[string]DispatchFunc) (http.Handler, error)` (returns an error if `adminAPIKey == ""` — the fail-closed check lives here, not just in `main.go`), unexported `withAuthz`, `withAdminAuth`, `hashKey` (unchanged).

- [ ] **Step 1: Rewrite `internal/server/server.go`**

```go
// Package server wires the broker's HTTP routes: the caller-facing
// /proxy/{target}/... dispatch and the admin-facing /admin/* CRUD API.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/Zhantec/credentials-broker/internal/authz"
	"github.com/Zhantec/credentials-broker/internal/reqctx"
	"github.com/Zhantec/credentials-broker/internal/store"
)

// DispatchFunc handles a single proxy-mode or oauth-mode request once
// authz has approved it.
type DispatchFunc func(w http.ResponseWriter, r *http.Request, target *store.Target)

// New builds the broker's HTTP handler: the caller-facing proxy route
// plus the admin CRUD routes, both backed by s. It returns an error if
// adminAPIKey is empty — the broker must fail closed rather than start
// with an admin API nobody can lock.
func New(s *store.Store, adminAPIKey string, handlers map[string]DispatchFunc) (http.Handler, error) {
	if adminAPIKey == "" {
		return nil, errors.New("admin API key must not be empty")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/{target}/{rest...}", withAuthz(s, handlers))

	mux.HandleFunc("POST /admin/targets", withAdminAuth(adminAPIKey, createTargetHandler(s)))
	mux.HandleFunc("GET /admin/targets", withAdminAuth(adminAPIKey, listTargetsHandler(s)))
	mux.HandleFunc("DELETE /admin/targets/{name}", withAdminAuth(adminAPIKey, deleteTargetHandler(s)))

	mux.HandleFunc("POST /admin/callers", withAdminAuth(adminAPIKey, createCallerHandler(s)))
	mux.HandleFunc("GET /admin/callers", withAdminAuth(adminAPIKey, listCallersHandler(s)))
	mux.HandleFunc("DELETE /admin/callers/{id}", withAdminAuth(adminAPIKey, deleteCallerHandler(s)))

	return mux, nil
}

func withAuthz(s *store.Store, handlers map[string]DispatchFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetName := r.PathValue("target")
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		callerHash := hashKey(key)

		result, err := authz.Check(s, key, targetName)
		if err != nil {
			log.Printf("caller=%s target=%s outcome=error stage=authz err=%v", callerHash, targetName, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		switch result {
		case authz.Unauthenticated:
			log.Printf("caller=%s target=%s outcome=unauthenticated", callerHash, targetName)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		case authz.TargetNotFound:
			log.Printf("caller=%s target=%s outcome=target_not_found", callerHash, targetName)
			http.Error(w, "target not found", http.StatusNotFound)
			return
		case authz.Forbidden:
			log.Printf("caller=%s target=%s outcome=forbidden", callerHash, targetName)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		target, ok, err := s.FindTarget(targetName)
		if err != nil {
			log.Printf("caller=%s target=%s outcome=error stage=find_target err=%v", callerHash, targetName, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			// authz.Check just confirmed the target exists; this would
			// mean it was deleted between that check and this lookup.
			http.Error(w, "target not found", http.StatusNotFound)
			return
		}

		handler, ok := handlers[target.Mode]
		if !ok {
			// An unmapped mode looks like an unknown target to the
			// caller, rather than leaking that the target exists but
			// this broker build doesn't support its mode.
			log.Printf("caller=%s target=%s outcome=unmapped_mode mode=%s", callerHash, targetName, target.Mode)
			http.Error(w, "target not found", http.StatusNotFound)
			return
		}

		log.Printf("caller=%s target=%s outcome=allowed", callerHash, targetName)
		r = r.WithContext(reqctx.WithCaller(r.Context(), callerHash))
		handler(w, r, target)
	}
}

func withAdminAuth(adminAPIKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(presented), []byte(adminAPIKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:8]
}
```

This task references `createTargetHandler`, `listTargetsHandler`, `deleteTargetHandler`, `createCallerHandler`, `listCallersHandler`, `deleteCallerHandler` — these are defined in Tasks 6 and 7. `go build ./internal/server/...` will fail until those land; that's expected per the Global Constraints note. Do not run `go test` for this task in isolation — proceed directly to Task 6.

- [ ] **Step 2: Commit**

```bash
git add internal/server/server.go
git commit -m "feat: wire server against the store, add admin auth middleware"
```

---

### Task 6: `internal/server` — admin target endpoints

**Files:**
- Create: `internal/server/admin_targets.go`
- Create: `internal/server/admin_targets_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Target`, `store.ErrAlreadyExists`, `store.ErrNotFound` (Task 1), `server.New` (Task 5, for test setup).
- Produces: `createTargetHandler(s *store.Store) http.HandlerFunc`, `listTargetsHandler(s *store.Store) http.HandlerFunc`, `deleteTargetHandler(s *store.Store) http.HandlerFunc`.

- [ ] **Step 1: Write `internal/server/admin_targets.go`**

```go
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/Zhantec/credentials-broker/internal/store"
)

type targetRequest struct {
	Name                 string  `json:"name"`
	Mode                 string  `json:"mode"`
	BaseURL              string  `json:"base_url"`
	InfisicalWorkspaceID string  `json:"infisical_workspace_id"`
	InfisicalEnvironment string  `json:"infisical_environment"`
	InfisicalSecret      string  `json:"infisical_secret"`
	InjectHeader         *string `json:"inject_header"`
	InjectPrefix         *string `json:"inject_prefix"`
}

type targetResponse struct {
	Name                 string `json:"name"`
	Mode                 string `json:"mode"`
	BaseURL              string `json:"base_url"`
	InfisicalWorkspaceID string `json:"infisical_workspace_id"`
	InfisicalEnvironment string `json:"infisical_environment"`
	InfisicalSecret      string `json:"infisical_secret"`
	InjectHeader         string `json:"inject_header"`
	InjectPrefix         string `json:"inject_prefix"`
}

func toTargetResponse(t store.Target) targetResponse {
	return targetResponse{
		Name: t.Name, Mode: t.Mode, BaseURL: t.BaseURL,
		InfisicalWorkspaceID: t.InfisicalWorkspaceID, InfisicalEnvironment: t.InfisicalEnvironment,
		InfisicalSecret: t.InfisicalSecret, InjectHeader: t.InjectHeader, InjectPrefix: t.InjectPrefix,
	}
}

func createTargetHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req targetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if req.Mode != "proxy" && req.Mode != "oauth" {
			http.Error(w, `mode must be "proxy" or "oauth"`, http.StatusBadRequest)
			return
		}
		if req.BaseURL == "" {
			http.Error(w, "base_url is required", http.StatusBadRequest)
			return
		}
		if _, err := url.Parse(req.BaseURL); err != nil {
			http.Error(w, "base_url must be a valid URL", http.StatusBadRequest)
			return
		}
		if req.InfisicalWorkspaceID == "" {
			http.Error(w, "infisical_workspace_id is required", http.StatusBadRequest)
			return
		}
		if req.InfisicalEnvironment == "" {
			http.Error(w, "infisical_environment is required", http.StatusBadRequest)
			return
		}
		if req.InfisicalSecret == "" {
			http.Error(w, "infisical_secret is required", http.StatusBadRequest)
			return
		}

		header := "Authorization"
		if req.InjectHeader != nil {
			header = *req.InjectHeader
		}
		if header == "" {
			http.Error(w, "inject_header must not be empty", http.StatusBadRequest)
			return
		}

		prefix := "Bearer "
		if req.InjectPrefix != nil {
			prefix = *req.InjectPrefix
		}

		target := store.Target{
			Name: req.Name, Mode: req.Mode, BaseURL: req.BaseURL,
			InfisicalWorkspaceID: req.InfisicalWorkspaceID, InfisicalEnvironment: req.InfisicalEnvironment,
			InfisicalSecret: req.InfisicalSecret, InjectHeader: header, InjectPrefix: prefix,
		}

		if err := s.CreateTarget(target); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				http.Error(w, "target already exists", http.StatusConflict)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(toTargetResponse(target))
	}
}

func listTargetsHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targets, err := s.ListTargets()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := struct {
			Targets []targetResponse `json:"targets"`
		}{Targets: make([]targetResponse, len(targets))}
		for i, t := range targets {
			resp.Targets[i] = toTargetResponse(t)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func deleteTargetHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := s.DeleteTarget(name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "target not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 2: Write `internal/server/admin_targets_test.go`**

```go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		"name":                    "stripe",
		"mode":                    "proxy",
		"base_url":                "https://api.stripe.com",
		"infisical_workspace_id":  "ws-1",
		"infisical_environment":   "prod",
		"infisical_secret":        "/prod/stripe/api_key",
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
```

- [ ] **Step 3: Run the server tests**

Run: `go test ./internal/server/... -v -run 'Target'`
Expected: all tests PASS. (Full-package `go test ./internal/server/...` still fails until Task 7 adds the caller handlers `New` now references.)

- [ ] **Step 4: Commit**

```bash
git add internal/server/admin_targets.go internal/server/admin_targets_test.go
git commit -m "feat: add admin target create/list/delete endpoints"
```

---

### Task 7: `internal/server` — admin caller endpoints

**Files:**
- Create: `internal/server/admin_callers.go`
- Create: `internal/server/admin_callers_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Caller`, `store.ErrNotFound` (Task 1–2), test helpers from Task 6 (`newTestServer`, `doAdminRequest`).
- Produces: `createCallerHandler(s *store.Store) http.HandlerFunc`, `listCallersHandler(s *store.Store) http.HandlerFunc`, `deleteCallerHandler(s *store.Store) http.HandlerFunc`.

- [ ] **Step 1: Write `internal/server/admin_callers.go`**

```go
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Zhantec/credentials-broker/internal/store"
)

type callerRequest struct {
	Targets []string `json:"targets"`
}

type callerResponse struct {
	ID      int64    `json:"id"`
	Targets []string `json:"targets"`
}

type createCallerResponse struct {
	ID      int64    `json:"id"`
	Key     string   `json:"key"`
	Targets []string `json:"targets"`
}

func createCallerHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req callerRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
		}

		id, key, err := s.CreateCaller(req.Targets)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		targets := req.Targets
		if targets == nil {
			targets = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createCallerResponse{ID: id, Key: key, Targets: targets})
	}
}

func listCallersHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callers, err := s.ListCallers()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := struct {
			Callers []callerResponse `json:"callers"`
		}{Callers: make([]callerResponse, len(callers))}
		for i, c := range callers {
			targets := c.Targets
			if targets == nil {
				targets = []string{}
			}
			resp.Callers[i] = callerResponse{ID: c.ID, Targets: targets}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func deleteCallerHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "id must be an integer", http.StatusBadRequest)
			return
		}

		if err := s.DeleteCaller(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "caller not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 2: Write `internal/server/admin_callers_test.go`**

```go
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
```

Add these two small shared test helpers to `internal/server/admin_targets_test.go` (used above and reused by Task 8's integration test):

```go
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
```

Add `"strconv"` to `internal/server/admin_targets_test.go`'s imports.

- [ ] **Step 3: Run the full server package tests**

Run: `go test ./internal/server/... -v`
Expected: all tests PASS. This is the first point since Task 3 where `internal/server` compiles and tests run standalone — `internal/config`/`cmd/broker` may still be broken until Task 9.

- [ ] **Step 4: Commit**

```bash
git add internal/server/admin_callers.go internal/server/admin_callers_test.go internal/server/admin_targets_test.go
git commit -m "feat: add admin caller create/list/delete endpoints"
```

---

### Task 8: End-to-end integration test

**Files:**
- Modify: `internal/server/integration_test.go` (rewrite in place — the old `config.Config`-based version is fully replaced)

**Interfaces:**
- Consumes: everything from Tasks 1–7 (`store.Store`, `server.New`, `proxy.Serve`, admin handlers).

- [ ] **Step 1: Rewrite `internal/server/integration_test.go`**

```go
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
```

- [ ] **Step 2: Run the full server package tests**

Run: `go test ./internal/server/... -v`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/server/integration_test.go
git commit -m "test: cover end-to-end admin-create-then-proxy and caller revocation flows"
```

---

### Task 9: `cmd/broker/main.go` rewiring

**Files:**
- Modify: `cmd/broker/main.go`

**Interfaces:**
- Consumes: `store.Open` (Task 1), `secrets.NewClient` (Task 3), `server.New` (Task 5), `proxy.Serve` (Task 3), `oauth.NewClient`/`oauth.Client.GetSecret` (Task 3).

- [ ] **Step 1: Read the current `cmd/broker/main.go` to confirm exact existing wiring before editing**

Run: `cat cmd/broker/main.go`

Use this to locate the exact current env-var reads, `config.Load` call, `secrets.NewClient` call, `oauth.NewClient` call, `proxy.Serve` call, `server.New` call, and `http.ListenAndServe` call so the replacement below preserves everything not explicitly changed (e.g. graceful shutdown handling, timeout configuration, log format) that isn't reproduced verbatim in Step 2.

- [ ] **Step 2: Rewrite `cmd/broker/main.go`**

Replace the `config.Load`-based wiring with store-based wiring. The shape below preserves the existing `PORT`/`INFISICAL_BASE_URL`/`INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET` env vars and HTTP server setup; it removes `CONFIG_PATH` and adds `DB_PATH` (default `credentials-broker.db`) and `ADMIN_API_KEY` (required, fail-fast):

```go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Zhantec/credentials-broker/internal/oauth"
	"github.com/Zhantec/credentials-broker/internal/proxy"
	"github.com/Zhantec/credentials-broker/internal/secrets"
	"github.com/Zhantec/credentials-broker/internal/server"
	"github.com/Zhantec/credentials-broker/internal/store"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "credentials-broker.db"
	}

	adminAPIKey := os.Getenv("ADMIN_API_KEY")
	if adminAPIKey == "" {
		log.Fatal("ADMIN_API_KEY must be set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	s, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer func() { _ = s.Close() }()

	infisicalClient := secrets.NewClient(
		os.Getenv("INFISICAL_BASE_URL"),
		os.Getenv("INFISICAL_CLIENT_ID"),
		os.Getenv("INFISICAL_CLIENT_SECRET"),
	)

	httpClient := &http.Client{Timeout: 15 * time.Second}
	oauthClient := oauth.NewClient(infisicalClient, httpClient)

	handlers := map[string]server.DispatchFunc{
		"proxy": proxy.Serve(infisicalClient, httpClient),
		"oauth": proxy.Serve(oauthClient, httpClient),
	}

	handler, err := server.New(s, adminAPIKey, handlers)
	if err != nil {
		log.Fatalf("building server: %v", err)
	}

	log.Printf("credentials-broker listening on :%s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
```

Reconcile this against what Step 1 actually showed: if the existing file has additional behavior (graceful shutdown via `http.Server` + signal handling, custom timeouts, structured logging setup), preserve that structure and apply only the deltas described above (drop `CONFIG_PATH`/`config.Load`, add `DB_PATH`/`store.Open`, add `ADMIN_API_KEY` fail-fast, change `secrets.NewClient` to 3-arg, change `server.New` to take `(s, adminAPIKey, handlers)` and handle its new error return).

- [ ] **Step 3: Verify the full repo builds**

Run: `go build ./...`
Expected: succeeds with no errors. This is the first point since Task 3 where the whole repo compiles.

- [ ] **Step 4: Verify the full test suite passes**

Run: `go test ./...`
Expected: all tests PASS across every package (this will still show `internal/config`'s tests running too, since it isn't deleted until Task 10).

- [ ] **Step 5: Commit**

```bash
git add cmd/broker/main.go
git commit -m "feat: wire main.go to the SQLite store and ADMIN_API_KEY"
```

---

### Task 10: Delete `internal/config`

**Files:**
- Delete: `internal/config/config.go`
- Delete: `internal/config/config_test.go`
- Delete: `config.example.yaml`

**Interfaces:**
- Consumes: nothing (this task only removes code once unreferenced).

- [ ] **Step 1: Confirm nothing still imports `internal/config`**

Run: `grep -rn "credentials-broker/internal/config" --include=*.go .`
Expected: no output. If any output appears, that file wasn't fully migrated in an earlier task — stop and fix it there instead of deleting `internal/config` out from under it.

- [ ] **Step 2: Delete the package and the example config**

```bash
git rm internal/config/config.go internal/config/config_test.go config.example.yaml
```

- [ ] **Step 3: Verify the repo still builds and tests pass**

Run: `go build ./... && go test ./...`
Expected: succeeds, no errors.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: remove YAML config loader, superseded by internal/store"
```

---

### Task 11: Docs — spec.md, README, Makefile

**Files:**
- Modify: `docs/spec.md`
- Modify: `README.md`
- Modify: `Makefile`

**Interfaces:**
- Consumes: nothing (docs only).

- [ ] **Step 1: Read the current README and Makefile**

Run: `cat README.md Makefile`

- [ ] **Step 2: Update `docs/spec.md`**

This is the repo's existing authoritative v1 design doc (`CLAUDE.md` links to it as "Full spec"). It still describes the YAML config file this migration removes. Apply these edits:

Replace the **Components** section's config-file bullet:

```markdown
- **Config file**: static YAML, mounted into the container (path via
  `CONFIG_PATH` env var, default `/etc/credentials-broker/config.yaml`).
```

with:

```markdown
- **Store**: embedded SQLite database (path via `DB_PATH` env var,
  default `credentials-broker.db`), holding targets and callers.
  Managed at runtime through the admin HTTP API below — no file to
  mount or SCP.
- **Admin API**: `/admin/targets` and `/admin/callers`
  (create/list/delete), gated by a single bootstrap `ADMIN_API_KEY` env
  var. The broker fails to start if it's unset.
```

Replace the entire **Config format** section (the YAML code block and
its heading) with:

````markdown
## Admin API

All `/admin/*` routes require `Authorization: Bearer <ADMIN_API_KEY>`.

```bash
curl -X POST http://localhost:8080/admin/targets \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "stripe",
    "mode": "proxy",
    "base_url": "https://api.stripe.com",
    "infisical_workspace_id": "ws-123",
    "infisical_environment": "prod",
    "infisical_secret": "/prod/stripe/api_key"
  }'
# inject_header/inject_prefix are optional, defaulting to
# "Authorization"/"Bearer ".

curl -X POST http://localhost:8080/admin/callers \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["stripe"]}'
# targets is optional; omitted/empty means the caller may use every
# target currently registered on this broker (dynamic all-access).
# The response's "key" field is the caller's bearer token for
# /proxy/* — it is generated here and never shown again.
```

`GET /admin/targets`, `GET /admin/callers`, `DELETE /admin/targets/{name}`,
and `DELETE /admin/callers/{id}` round out create/list/delete for both
resources. There is no update or get-by-id endpoint.
````

Update **Request flow** step 2 from "Broker looks up the key in config."
to "Broker looks up the key in the store." (same three outcomes:
missing/unknown key → `401`; key doesn't cover the requested target →
`403`; target name not registered → `404`).

- [ ] **Step 3: Update `README.md`**

Remove any mention of `CONFIG_PATH` and the YAML config format. Add:
- `DB_PATH` env var (optional, default `credentials-broker.db`) — path to the SQLite database file.
- `ADMIN_API_KEY` env var (required) — bootstrap secret for the admin API; the broker fails to start without it.
- A section documenting the admin API — create/list/delete for targets and callers, matching the request/response shapes implemented in Tasks 6–7 (`internal/server/admin_targets.go`, `internal/server/admin_callers.go`). Reproduce those `curl` examples in the README's existing style, e.g.:

```bash
curl -X POST http://localhost:8080/admin/targets \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "stripe",
    "mode": "proxy",
    "base_url": "https://api.stripe.com",
    "infisical_workspace_id": "ws-123",
    "infisical_environment": "prod",
    "infisical_secret": "/prod/stripe/api_key"
  }'

curl -X POST http://localhost:8080/admin/callers \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["stripe"]}'
```

- [ ] **Step 4: Update the `Makefile`'s `docker-run` target**

Replace the `config.example.yaml` volume mount with a SQLite data volume and the new required env var. The existing target likely resembles:

```makefile
docker-run:
	docker run --rm -p 8080:8080 \
		-v $(PWD)/config.example.yaml:/etc/credentials-broker/config.yaml:ro \
		-e CONFIG_PATH=/etc/credentials-broker/config.yaml \
		-e INFISICAL_CLIENT_ID=$(INFISICAL_CLIENT_ID) \
		-e INFISICAL_CLIENT_SECRET=$(INFISICAL_CLIENT_SECRET) \
		credentials-broker:latest
```

Replace it with:

```makefile
docker-run:
	docker run --rm -p 8080:8080 \
		-v $(PWD)/data:/data \
		-e DB_PATH=/data/credentials-broker.db \
		-e ADMIN_API_KEY=$(ADMIN_API_KEY) \
		-e INFISICAL_CLIENT_ID=$(INFISICAL_CLIENT_ID) \
		-e INFISICAL_CLIENT_SECRET=$(INFISICAL_CLIENT_SECRET) \
		credentials-broker:latest
```

Adjust indentation/variable names to match whatever the actual current target uses (confirmed in Step 1) — the delta is: drop the config-file volume mount and `CONFIG_PATH`, add a `/data` volume mount, `DB_PATH`, and `ADMIN_API_KEY`.

- [ ] **Step 5: Commit**

```bash
git add docs/spec.md README.md Makefile
git commit -m "docs: document DB_PATH, ADMIN_API_KEY, and the admin API"
```

---

## Self-Review

- **Design coverage:** Data model (Tasks 1–2), Admin API create/list/delete for both targets and callers (Tasks 6–7), auth model incl. fail-closed + constant-time compare (Task 5), multi-project Infisical support (Task 3), migration/removal of YAML config (Task 10), testing approach — `:memory:` SQLite, table-driven (Tasks 1–2, 4, 6–8), docs updates incl. the repo's `docs/spec.md` (Task 11). Every design decision reached during brainstorming has a task.
- **Placeholder scan:** No TBD/TODO markers; every code step contains complete, compilable Go source. Task 9's Step 2 explicitly tells the implementer to reconcile against the real file content read in Step 1 rather than blindly overwrite, since `main.go`'s exact current shutdown/timeout handling wasn't fully captured verbatim in this plan.
- **Type consistency:** `store.Target`/`store.Caller` field names are defined once in Task 1/2 and reused verbatim in Tasks 3–8 (`proxy.go`, `authz.go`, `admin_targets.go`, `admin_callers.go`, tests). `server.DispatchFunc`'s signature (`*store.Target`) matches `proxy.Serve`'s return type from Task 3. `authz.Check`'s `(Result, error)` return and `Result` enum values (`Allowed, Unauthenticated, Forbidden, TargetNotFound`) are defined once in Task 4 and consumed identically in Task 5's `withAuthz`. `server.New`'s `(http.Handler, error)` signature (Task 5) is used consistently in every test helper from Task 6 onward.
