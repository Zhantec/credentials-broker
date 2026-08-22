package execute

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type SecretResolver interface {
	GetSecret(secretPath, secretName string) (string, error)
}

type DBOpener func(driverName, dsn string) (*sql.DB, error)

type queryRequest struct {
	Query string `json:"query"`
}

type queryResponse struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
}

const (
	maxRequestBytes = 1 << 20 // 1MiB
	queryTimeout    = 30 * time.Second
)

// maxRows caps how many rows are buffered in memory before the response is
// marked truncated. Package-level var so tests can lower it.
var maxRows = 10000

// Serve returns a dispatch function for execute-mode targets: it runs the
// caller's query against the target using the resolved credential and
// returns the result as JSON. There is no query-level authorization here by
// design — see docs/spec.md's non-goals.
func Serve(secrets SecretResolver, open DBOpener) func(http.ResponseWriter, *http.Request, *config.Target) {
	return func(w http.ResponseWriter, r *http.Request, target *config.Target) {
		var req queryRequest
		body := http.MaxBytesReader(w, r.Body, maxRequestBytes)
		if err := json.NewDecoder(body).Decode(&req); err != nil || req.Query == "" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		path, name := target.SecretPathAndName()
		dsn, err := secrets.GetSecret(path, name)
		if err != nil {
			log.Printf("execute: resolving secret for target %s: %v", target.Name, err)
			http.Error(w, "secret unavailable", http.StatusBadGateway)
			return
		}

		db, err := open(target.Driver, dsn)
		if err != nil {
			log.Printf("execute: opening db for target %s: %v", target.Name, err)
			http.Error(w, "target unavailable", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
		defer cancel()

		rows, err := db.QueryContext(ctx, req.Query)
		if err != nil {
			log.Printf("execute: query failed for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		cols, err := rows.Columns()
		if err != nil {
			log.Printf("execute: reading columns for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		resp := queryResponse{Columns: cols, Rows: [][]any{}}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				log.Printf("execute: scanning row for target %s: %v", target.Name, err)
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
			// database/sql drivers commonly return TEXT columns as []byte;
			// convert to string so JSON encodes readable text, not base64.
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			resp.Rows = append(resp.Rows, vals)
			if len(resp.Rows) >= maxRows {
				resp.Truncated = true
				break
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("execute: iterating rows for target %s: %v", target.Name, err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
