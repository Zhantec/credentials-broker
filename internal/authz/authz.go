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

	_, ok = cfg.FindTarget(targetName)
	if !ok {
		return TargetNotFound
	}

	for _, t := range caller.Targets {
		if t == targetName {
			return Allowed
		}
	}

	return Forbidden
}
