package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://app.infisical.com"
	cacheTTL       = 5 * time.Minute
)

type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	workspaceID  string
	environment  string
	httpClient   *http.Client
	mu           sync.RWMutex
	secretCache  map[string]cacheEntry
	tokenCache   *cacheEntry
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

func NewClient(baseURL, clientID, clientSecret, workspaceID, environment string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		workspaceID:  workspaceID,
		environment:  environment,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		secretCache:  make(map[string]cacheEntry),
	}
}

// GetSecret fetches secretName at secretPath, serving a cached value while
// it's within the TTL.
func (c *Client) GetSecret(secretPath, secretName string) (string, error) {
	cacheKey := secretPath + ":" + secretName

	// Check cache
	c.mu.RLock()
	if entry, ok := c.secretCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.value, nil
	}
	c.mu.RUnlock()

	// Get access token
	token, err := c.accessTokenValue()
	if err != nil {
		return "", fmt.Errorf("get access token: %w", err)
	}

	// Fetch secret from API
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?secretPath=%s&environment=%s&workspaceId=%s",
		c.baseURL, secretName, secretPath, c.environment, c.workspaceID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch secret: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetch secret: %d %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	value := result.Secret.SecretValue

	// Cache result
	c.mu.Lock()
	c.secretCache[cacheKey] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(cacheTTL),
	}
	c.mu.Unlock()

	return value, nil
}

func (c *Client) accessTokenValue() (string, error) {
	c.mu.RLock()
	if c.tokenCache != nil && time.Now().Before(c.tokenCache.expiresAt) {
		defer c.mu.RUnlock()
		return c.tokenCache.value, nil
	}
	c.mu.RUnlock()

	// Request new token
	payload := map[string]string{
		"clientId":     c.clientID,
		"clientSecret": c.clientSecret,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal auth request: %w", err)
	}

	url := c.baseURL + "/api/v1/auth/universal-auth/login"
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth: %d %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode auth response: %w", err)
	}

	// Cache token with its TTL
	c.mu.Lock()
	c.tokenCache = &cacheEntry{
		value:     result.AccessToken,
		expiresAt: time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}
	c.mu.Unlock()

	return result.AccessToken, nil
}
