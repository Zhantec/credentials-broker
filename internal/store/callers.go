package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// Caller is a broker-access identity. Targets lists the target names
// this caller may use. AllAccess is fixed at creation time based on
// whether Targets was empty then — it is NOT re-derived from the
// current Targets length, so it stays false forever for a caller that
// was scoped to specific targets even if every one of those targets is
// later deleted (which cascade-deletes its caller_targets rows). This
// keeps the "empty because unscoped" and "empty because its scope got
// deleted out from under it" cases from being conflated as all-access.
type Caller struct {
	ID        int64
	Targets   []string
	AllAccess bool
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

	res, err := tx.Exec(`INSERT INTO callers (key_hash, all_access) VALUES (?, ?)`, hashRawKey(rawKey), len(targets) == 0)
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
	rows, err := s.db.Query(`SELECT id, all_access FROM callers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("querying callers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type idAndAllAccess struct {
		id        int64
		allAccess bool
	}
	var rowsOut []idAndAllAccess
	for rows.Next() {
		var r idAndAllAccess
		if err := rows.Scan(&r.id, &r.allAccess); err != nil {
			return nil, fmt.Errorf("scanning caller: %w", err)
		}
		rowsOut = append(rowsOut, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()

	var callers []Caller
	for _, r := range rowsOut {
		targets, err := s.targetsForCaller(r.id)
		if err != nil {
			return nil, err
		}
		callers = append(callers, Caller{ID: r.id, Targets: targets, AllAccess: r.allAccess})
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
//
// ponytail: key_hash is a SHA-256 digest looked up via its UNIQUE index
// (WHERE key_hash = ?) rather than a constant-time scan of every row —
// the hash itself is already the thing defeating timing/enumeration
// attacks on the raw key, so an indexed equality lookup buys attackers
// nothing a full scan would have denied them.
func (s *Store) FindCallerByKey(rawKey string) (*Caller, bool, error) {
	want := hashRawKey(rawKey)

	var id int64
	var allAccess bool
	err := s.db.QueryRow(`SELECT id, all_access FROM callers WHERE key_hash = ?`, want).Scan(&id, &allAccess)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("querying caller: %w", err)
	}

	targets, err := s.targetsForCaller(id)
	if err != nil {
		return nil, false, err
	}
	return &Caller{ID: id, Targets: targets, AllAccess: allAccess}, true, nil
}
