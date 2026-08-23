package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/Zhantec/credentials-broker/internal/store"
)

type targetRequest struct {
	Name                 string  `json:"name"`
	Mode                 string  `json:"mode"`
	BaseURL              string  `json:"base_url"`
	InfisicalWorkspaceID string  `json:"infisical_workspace_id"`
	InfisicalEnvironment string  `json:"infisical_environment"`
	InfisicalSecret      string  `json:"infisical_secret"`
	InjectHeader         *string `json:"inject_header"`
	InjectPrefix         *string `json:"inject_prefix"`
}

type targetResponse struct {
	Name                 string `json:"name"`
	Mode                 string `json:"mode"`
	BaseURL              string `json:"base_url"`
	InfisicalWorkspaceID string `json:"infisical_workspace_id"`
	InfisicalEnvironment string `json:"infisical_environment"`
	InfisicalSecret      string `json:"infisical_secret"`
	InjectHeader         string `json:"inject_header"`
	InjectPrefix         string `json:"inject_prefix"`
}

func toTargetResponse(t store.Target) targetResponse {
	return targetResponse{
		Name: t.Name, Mode: t.Mode, BaseURL: t.BaseURL,
		InfisicalWorkspaceID: t.InfisicalWorkspaceID, InfisicalEnvironment: t.InfisicalEnvironment,
		InfisicalSecret: t.InfisicalSecret, InjectHeader: t.InjectHeader, InjectPrefix: t.InjectPrefix,
	}
}

func createTargetHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req targetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if req.Mode != "proxy" && req.Mode != "oauth" {
			http.Error(w, `mode must be "proxy" or "oauth"`, http.StatusBadRequest)
			return
		}
		if req.BaseURL == "" {
			http.Error(w, "base_url is required", http.StatusBadRequest)
			return
		}
		if _, err := url.Parse(req.BaseURL); err != nil {
			http.Error(w, "base_url must be a valid URL", http.StatusBadRequest)
			return
		}
		if req.InfisicalWorkspaceID == "" {
			http.Error(w, "infisical_workspace_id is required", http.StatusBadRequest)
			return
		}
		if req.InfisicalEnvironment == "" {
			http.Error(w, "infisical_environment is required", http.StatusBadRequest)
			return
		}
		if req.InfisicalSecret == "" {
			http.Error(w, "infisical_secret is required", http.StatusBadRequest)
			return
		}

		header := "Authorization"
		if req.InjectHeader != nil {
			header = *req.InjectHeader
		}
		if header == "" {
			http.Error(w, "inject_header must not be empty", http.StatusBadRequest)
			return
		}

		prefix := "Bearer "
		if req.InjectPrefix != nil {
			prefix = *req.InjectPrefix
		}

		target := store.Target{
			Name: req.Name, Mode: req.Mode, BaseURL: req.BaseURL,
			InfisicalWorkspaceID: req.InfisicalWorkspaceID, InfisicalEnvironment: req.InfisicalEnvironment,
			InfisicalSecret: req.InfisicalSecret, InjectHeader: header, InjectPrefix: prefix,
		}

		if err := s.CreateTarget(target); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				http.Error(w, "target already exists", http.StatusConflict)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(toTargetResponse(target))
	}
}

func listTargetsHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targets, err := s.ListTargets()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := struct {
			Targets []targetResponse `json:"targets"`
		}{Targets: make([]targetResponse, len(targets))}
		for i, t := range targets {
			resp.Targets[i] = toTargetResponse(t)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func deleteTargetHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := s.DeleteTarget(name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "target not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
