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
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash   TEXT NOT NULL UNIQUE,
	all_access INTEGER NOT NULL DEFAULT 0
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
