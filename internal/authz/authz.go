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

	if caller.AllAccess {
		return Allowed, nil
	}
	for _, t := range caller.Targets {
		if t == targetName {
			return Allowed, nil
		}
	}
	return Forbidden, nil
}
