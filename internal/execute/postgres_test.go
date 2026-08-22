package execute

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type fakeResolver struct{ value string }

func (f fakeResolver) GetSecret(secretPath, secretName string) (string, error) {
	return f.value, nil
}

func sqliteOpener(driverName, dsn string) (*sql.DB, error) {
	return sql.Open("sqlite", dsn)
}

func seedDB(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening seed db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER, name TEXT)`); err != nil {
		t.Fatalf("creating table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name) VALUES (1, 'ada')`); err != nil {
		t.Fatalf("seeding row: %v", err)
	}
}

func TestServe_RunsQueryAndReturnsRows(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/test.db"
	seedDB(t, dsn)

	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: dsn}, sqliteOpener)

	body := strings.NewReader(`{"query": "SELECT id, name FROM users"}`)
	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", body)
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got.Columns) != 2 || len(got.Rows) != 1 {
		t.Fatalf("unexpected shape: %+v", got)
	}
	if got.Rows[0][1] != "ada" {
		t.Errorf("row[0][1] = %v, want %q (want string, not base64 bytes)", got.Rows[0][1], "ada")
	}
}

func TestServe_InvalidBody(t *testing.T) {
	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: "unused"}, sqliteOpener)

	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestServe_QueryErrorDoesNotLeakDriverDetails(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/test.db"
	seedDB(t, dsn)

	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: dsn}, sqliteOpener)

	body := strings.NewReader(`{"query": "SELECT * FROM does_not_exist"}`)
	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", body)
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "does_not_exist") {
		t.Errorf("response leaked raw driver error: %s", rec.Body.String())
	}
}

func TestServe_TruncatesAtRowCap(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/test.db"
	seedDB(t, dsn)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name) VALUES (2, 'bob'), (3, 'cyd')`); err != nil {
		t.Fatalf("seeding rows: %v", err)
	}
	db.Close()

	orig := maxRows
	maxRows = 2
	t.Cleanup(func() { maxRows = orig })

	target := &config.Target{Driver: "postgres", InfisicalSecret: "/prod/db/dsn"}
	handler := Serve(fakeResolver{value: dsn}, sqliteOpener)

	body := strings.NewReader(`{"query": "SELECT id, name FROM users ORDER BY id"}`)
	req := httptest.NewRequest(http.MethodPost, "/execute/postgres", body)
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Rows      [][]any `json:"rows"`
		Truncated bool    `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("got %d rows, want 2 (capped)", len(got.Rows))
	}
	if !got.Truncated {
		t.Error("truncated = false, want true when the row cap is hit")
	}
}
