// Package oauth exchanges Infisical-stored OAuth2 client credentials for a
// short-lived access token, caching it until close to expiry. It implements
// the same SecretResolver interface proxy.Serve already uses for static
// secrets, so oauth-mode targets reuse proxy.Serve's forwarding unchanged —
// the only difference is how the injected credential value is obtained.
package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SecretResolver resolves the raw Infisical secret backing a target. It's
// the same shape internal/secrets.Client already implements.
type SecretResolver interface {
	GetSecret(secretPath, secretName string) (string, error)
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// Client turns a target's Infisical-stored client credentials into a
// cached OAuth2 access token via the client_credentials grant (RFC 6749
// §4.4). The Infisical secret is expected to hold a JSON blob:
//
//	{"client_id": "...", "client_secret": "...", "token_url": "...", "scope": "..."}
//
// ("scope" optional.) token_url lives in the secret rather than static
// config because it's per-target and the secret blob is already the
// single place each target's opaque credential material lives.
type Client struct {
	secrets    SecretResolver
	httpClient *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

func NewClient(secrets SecretResolver, httpClient *http.Client) *Client {
	return &Client{secrets: secrets, httpClient: httpClient, cache: make(map[string]cacheEntry)}
}

type clientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURL     string `json:"token_url"`
	Scope        string `json:"scope"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// GetSecret resolves secretPath/secretName to a client_credentials blob,
// exchanges it for an access token (serving a cached one while it's within
// its TTL), and returns the token as the value proxy.Serve should inject.
func (c *Client) GetSecret(secretPath, secretName string) (string, error) {
	cacheKey := secretPath + ":" + secretName

	c.mu.Lock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.value, nil
	}
	c.mu.Unlock()

	raw, err := c.secrets.GetSecret(secretPath, secretName)
	if err != nil {
		return "", fmt.Errorf("resolving client credentials: %w", err)
	}

	var creds clientCredentials
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return "", fmt.Errorf("parsing client credentials: %w", err)
	}
	if creds.TokenURL == "" {
		return "", fmt.Errorf("client credentials missing token_url")
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.ClientID},
		"client_secret": {creds.ClientSecret},
	}
	if creds.Scope != "" {
		form.Set("scope", creds.Scope)
	}

	req, err := http.NewRequest(http.MethodPost, creds.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		// ponytail: provider didn't advertise a lifetime; assume short-lived
		// and refetch soon rather than cache indefinitely.
		expiresIn = 60
	}
	// Refresh a little early so an in-flight request never carries a token
	// that expires mid-request.
	expiresAt := time.Now().Add(time.Duration(expiresIn)*time.Second - 5*time.Second)

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{value: tr.AccessToken, expiresAt: expiresAt}
	c.mu.Unlock()

	return tr.AccessToken, nil
}
