package oauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeResolver struct {
	value string
	err   error
}

func (f fakeResolver) GetSecret(secretPath, secretName string) (string, error) {
	return f.value, f.err
}

func TestGetSecret_FetchesCachesAndInjectsToken(t *testing.T) {
	var requests int
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.FormValue("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", got)
		}
		if got := r.FormValue("client_id"); got != "id" {
			t.Errorf("client_id = %q, want id", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "tok-1", "expires_in": 3600}`))
	}))
	defer tokenServer.Close()

	creds := `{"client_id": "id", "client_secret": "secret", "token_url": "` + tokenServer.URL + `"}`
	c := NewClient(fakeResolver{value: creds}, tokenServer.Client())

	got, err := c.GetSecret("/prod/gh", "oauth_client")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "tok-1" {
		t.Errorf("token = %q, want %q", got, "tok-1")
	}

	// Second call within TTL should be served from cache.
	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err != nil {
		t.Fatalf("GetSecret (cached): %v", err)
	}
	if requests != 1 {
		t.Errorf("token endpoint requests = %d, want 1 (cached)", requests)
	}
}

func TestGetSecret_RefetchesAfterExpiry(t *testing.T) {
	var requests int
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		// expires_in <= 5 collapses to an already-past expiry (5s early-refresh
		// margin), forcing a refetch on the very next call.
		w.Write([]byte(`{"access_token": "tok", "expires_in": 1}`))
	}))
	defer tokenServer.Close()

	creds := `{"client_id": "id", "client_secret": "secret", "token_url": "` + tokenServer.URL + `"}`
	c := NewClient(fakeResolver{value: creds}, tokenServer.Client())

	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err != nil {
		t.Fatalf("GetSecret (refetch): %v", err)
	}
	if requests != 2 {
		t.Errorf("token endpoint requests = %d, want 2 (expired)", requests)
	}
}

func TestGetSecret_ResolverError(t *testing.T) {
	c := NewClient(fakeResolver{err: errors.New("infisical down")}, http.DefaultClient)
	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err == nil {
		t.Error("expected error when secret resolution fails")
	}
}

func TestGetSecret_MalformedCredentials(t *testing.T) {
	c := NewClient(fakeResolver{value: "not json"}, http.DefaultClient)
	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err == nil {
		t.Error("expected error for malformed client credentials")
	}
}

func TestGetSecret_TokenEndpointError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	creds := `{"client_id": "id", "client_secret": "bad", "token_url": "` + tokenServer.URL + `"}`
	c := NewClient(fakeResolver{value: creds}, tokenServer.Client())

	if _, err := c.GetSecret("/prod/gh", "oauth_client"); err == nil {
		t.Error("expected error when token endpoint rejects credentials")
	}
}
