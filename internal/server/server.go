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
		// A target that exists but isn't reachable via this route is
		// indistinguishable, to the caller, from one that doesn't exist.
		if target.Mode != mode {
			http.Error(w, "target not found", http.StatusNotFound)
			return
		}
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
