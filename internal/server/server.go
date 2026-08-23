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
