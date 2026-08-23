package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/Zhantec/credentials-broker/internal/store"
)

// maxAdminBodyBytes caps admin JSON request bodies well above any
// legitimate payload, so a malicious/misbehaving caller can't force
// the broker to buffer an unbounded body into memory.
const maxAdminBodyBytes = 1 << 20 // 1 MiB

type callerRequest struct {
	Targets []string `json:"targets"`
}

type callerResponse struct {
	ID        int64    `json:"id"`
	Targets   []string `json:"targets"`
	AllAccess bool     `json:"all_access"`
}

type createCallerResponse struct {
	ID        int64    `json:"id"`
	Key       string   `json:"key"`
	Targets   []string `json:"targets"`
	AllAccess bool     `json:"all_access"`
}

func createCallerHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req callerRequest
		if r.ContentLength != 0 {
			r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
		}

		for _, name := range req.Targets {
			if _, ok, err := s.FindTarget(name); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			} else if !ok {
				http.Error(w, "unknown target: "+name, http.StatusBadRequest)
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
		allAccess := len(targets) == 0
		log.Printf("admin action=create_caller id=%d targets=%v all_access=%v", id, targets, allAccess)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createCallerResponse{ID: id, Key: key, Targets: targets, AllAccess: allAccess})
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
			resp.Callers[i] = callerResponse{ID: c.ID, Targets: targets, AllAccess: c.AllAccess}
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
		log.Printf("admin action=delete_caller id=%d", id)
		w.WriteHeader(http.StatusNoContent)
	}
}
