package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ContextKey is the type of the context keys this package sets.
type ContextKey string

// UserIDContextKey is the context key under which Middleware stores the
// authenticated user ID.
const UserIDContextKey ContextKey = "mcpoauth.user_id"

// Provider is the authorization server. Create one with New and mount its
// handlers on your router.
type Provider struct {
	cfg   Config
	store Store
	http  *http.Client

	jwks *jwksCache

	// now is overridable in tests.
	now func() time.Time
}

// New validates cfg and returns a Provider.
func New(cfg Config, store Store) (*Provider, error) {
	if store == nil {
		return nil, errors.New("mcpoauth: store is required")
	}

	required := []struct {
		name  string
		value string
	}{
		{"Issuer", cfg.Issuer},
		{"ResourceURL", cfg.ResourceURL},
		{"GoogleClientID", cfg.GoogleClientID},
		{"GoogleClientSecret", cfg.GoogleClientSecret},
		{"GoogleRedirectURL", cfg.GoogleRedirectURL},
		{"AuthorizeURL", cfg.AuthorizeURL},
		{"TokenURL", cfg.TokenURL},
		{"RegisterURL", cfg.RegisterURL},
	}
	var missing []string
	for _, f := range required {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(cfg.JWTSecret) == 0 {
		missing = append(missing, "JWTSecret")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("mcpoauth: missing required config: %s", strings.Join(missing, ", "))
	}

	for _, f := range required {
		if f.name != "Issuer" && !strings.HasSuffix(f.name, "URL") {
			continue
		}
		if err := requireAbsoluteURL(f.name, f.value); err != nil {
			return nil, err
		}
	}

	if cfg.MetadataBaseURL == "" {
		cfg.MetadataBaseURL = cfg.Issuer
	} else if err := requireAbsoluteURL("MetadataBaseURL", cfg.MetadataBaseURL); err != nil {
		return nil, err
	}

	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.AuthCodeTTL <= 0 {
		cfg.AuthCodeTTL = 5 * time.Minute
	}
	if cfg.PendingAuthTTL <= 0 {
		cfg.PendingAuthTTL = 10 * time.Minute
	}
	if cfg.GoogleAuthURL == "" {
		cfg.GoogleAuthURL = DefaultGoogleAuthURL
	}
	if cfg.GoogleTokenURL == "" {
		cfg.GoogleTokenURL = DefaultGoogleTokenURL
	}
	if cfg.GoogleJWKSURL == "" {
		cfg.GoogleJWKSURL = DefaultGoogleJWKSURL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	p := &Provider{
		cfg:   cfg,
		store: store,
		http:  httpClient,
		now:   time.Now,
	}
	p.jwks = newJWKSCache(cfg.GoogleJWKSURL, httpClient, p.nowFn)
	return p, nil
}

func (p *Provider) nowFn() time.Time { return p.now() }

func requireAbsoluteURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("mcpoauth: %s is not a valid URL: %w", name, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("mcpoauth: %s must be an absolute URL, got %q", name, raw)
	}
	return nil
}

// ProtectedResourceMetadataURL is the absolute URL of the RFC 9728 document,
// as advertised in the WWW-Authenticate challenge.
func (p *Provider) ProtectedResourceMetadataURL() string {
	return strings.TrimRight(p.cfg.MetadataBaseURL, "/") + ProtectedResourceMetadataPath
}

// UserIDFromContext returns the user ID injected by Middleware.
func UserIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(UserIDContextKey).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// --- shared HTTP helpers -------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// oauthError is the RFC 6749 §5.2 error body.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// writeOAuthError writes an OAuth error response. Descriptions are static
// strings written by this package — never user input, tokens or secrets.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, oauthError{Error: code, Description: desc})
}

// allowCORS sets permissive CORS headers required by browser-based and CLI MCP
// clients that fetch the discovery documents cross-origin. It reports whether
// the request was a preflight and has already been answered.
func allowCORS(w http.ResponseWriter, r *http.Request, methods string) bool {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", methods+", OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
	h.Set("Access-Control-Max-Age", "3600")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}
