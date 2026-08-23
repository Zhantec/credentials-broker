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

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning caller: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	var callers []Caller
	for _, id := range ids {
		targets, err := s.targetsForCaller(id)
		if err != nil {
			return nil, err
		}
		callers = append(callers, Caller{ID: id, Targets: targets})
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
	rows.Close()
	if !found {
		return nil, false, nil
	}

	targets, err := s.targetsForCaller(id)
	if err != nil {
		return nil, false, err
	}
	return &Caller{ID: id, Targets: targets}, true, nil
}
