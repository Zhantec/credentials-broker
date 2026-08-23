package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zhantec/credentials-broker/internal/store"
)

type fakeResolver struct {
	value string
	err   error
}

func (f fakeResolver) GetSecret(workspaceID, environment, secretPath, secretName string) (string, error) {
	return f.value, f.err
}

func TestServe_InjectsHeaderAndForwards(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	target := &store.Target{
		BaseURL:         upstream.URL,
		InjectHeader:    "Authorization",
		InjectPrefix:    "Bearer ",
		InfisicalSecret: "/prod/stripe/api_key",
	}
	handler := Serve(fakeResolver{value: "real-secret"}, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy/stripe/v1/charges", nil)
	req.SetPathValue("rest", "v1/charges")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if gotAuth != "Bearer real-secret" {
		t.Errorf("upstream got Authorization=%q, want %q", gotAuth, "Bearer real-secret")
	}
	if gotPath != "/v1/charges" {
		t.Errorf("upstream got path=%q, want %q", gotPath, "/v1/charges")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("response status = %d, want %d", rec.Code, http.StatusCreated)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "ok" {
		t.Errorf("response body = %q, want %q", body, "ok")
	}
}

func TestServe_SecretResolverError(t *testing.T) {
	target := &store.Target{BaseURL: "http://unused", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{err: errors.New("boom")}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestServe_InvalidBaseURL(t *testing.T) {
	target := &store.Target{BaseURL: "http://foo.com/%zz", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestServe_PreservesTrailingSlash(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer upstream.Close()

	target := &store.Target{BaseURL: upstream.URL, InjectHeader: "Authorization", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/team-a/", nil)
	req.SetPathValue("rest", "team-a/")
	handler(httptest.NewRecorder(), req, target)

	if gotPath != "/team-a/" {
		t.Errorf("upstream got path=%q, want %q", gotPath, "/team-a/")
	}
}

func TestServe_RespectsClientTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := upstream.Client()
	client.Timeout = time.Second
	target := &store.Target{BaseURL: upstream.URL, InjectHeader: "Authorization", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, client)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestServe_UpstreamUnreachable(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := upstream.URL
	upstream.Close() // closed before use -> connection refused

	target := &store.Target{BaseURL: deadURL, InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy/x/anything", nil)
	req.SetPathValue("rest", "anything")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestServe_CallerAuthHeaderNotLeakedToUpstream(t *testing.T) {
	var gotAuth, gotXApiKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotXApiKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := &store.Target{
		BaseURL:         upstream.URL,
		InjectHeader:    "X-Api-Key",
		InjectPrefix:    "Bearer ",
		InfisicalSecret: "/prod/stripe/api_key",
	}
	handler := Serve(fakeResolver{value: "real-secret"}, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy/stripe/v1/charges", nil)
	req.SetPathValue("rest", "v1/charges")
	// Simulate caller authenticating to the broker with their own Authorization header
	req.Header.Set("Authorization", "Bearer caller-key")
	rec := httptest.NewRecorder()

	handler(rec, req, target)

	// Verify the target's secret was injected correctly
	if gotXApiKey != "Bearer real-secret" {
		t.Errorf("upstream got X-Api-Key=%q, want %q", gotXApiKey, "Bearer real-secret")
	}
	// Verify the caller's Authorization header did NOT leak to upstream
	if gotAuth != "" {
		t.Errorf("upstream got Authorization=%q, want empty (caller credential must not leak)", gotAuth)
	}
}

func TestServe_ForwardsQueryString(t *testing.T) {
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
	}))
	defer upstream.Close()

	target := &store.Target{BaseURL: upstream.URL, InjectHeader: "Authorization", InfisicalSecret: "/prod/stripe/api_key"}
	handler := Serve(fakeResolver{value: "real-secret"}, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy/stripe/v1/charges?limit=10", nil)
	req.SetPathValue("rest", "v1/charges")
	handler(httptest.NewRecorder(), req, target)

	if gotQuery != "limit=10" {
		t.Errorf("upstream got query=%q, want %q", gotQuery, "limit=10")
	}
}

func TestServe_PathTraversalCannotEscapeBasePath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer upstream.Close()

	target := &store.Target{BaseURL: upstream.URL + "/team-a", InjectHeader: "Authorization", InfisicalSecret: "/prod/x/y"}
	handler := Serve(fakeResolver{value: "s"}, upstream.Client())

	// ServeMux hands "%2e%2e" to the handler already decoded as "..".
	req := httptest.NewRequest(http.MethodGet, "/proxy/x/%2e%2e/team-b/secrets", nil)
	req.SetPathValue("rest", "../team-b/secrets")
	handler(httptest.NewRecorder(), req, target)

	if !strings.HasPrefix(gotPath, "/team-a/") {
		t.Errorf("upstream got path=%q, want it confined under /team-a/", gotPath)
	}
}
