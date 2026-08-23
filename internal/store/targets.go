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
