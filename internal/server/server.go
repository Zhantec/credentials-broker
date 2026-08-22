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

// New builds the broker's HTTP handler. handlers maps a target's configured
// mode (e.g. "proxy", "oauth") to the DispatchFunc that serves it; every
// mode shares the same /proxy/{target}/{rest...} forwarding contract, so
// there's one route dispatching by target.Mode rather than one route per
// mode.
func New(cfg *config.Config, handlers map[string]DispatchFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/{target}/{rest...}", withAuthz(cfg, handlers))
	return mux
}

func withAuthz(cfg *config.Config, handlers map[string]DispatchFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetName := r.PathValue("target")
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		result := authz.Check(cfg, key, targetName)
		log.Printf("caller=%s target=%s outcome=%s", hashKey(key), targetName, outcomeLabel(result))

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
		handler, ok := handlers[target.Mode]
		if !ok {
			// A target whose mode has no registered handler is
			// indistinguishable, to the caller, from one that doesn't exist.
			http.Error(w, "target not found", http.StatusNotFound)
			return
		}
		handler(w, r, target)
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
