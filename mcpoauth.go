package mcpoauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	// signKey is the HKDF-derived HS256 key; cfg.JWTSecret is never used to
	// sign or verify directly.
	signKey []byte

	jwks *jwksCache

	// now is overridable in tests.
	now func() time.Time

	mu sync.Mutex
	// consumed remembers recently rotated refresh-token hashes so a replay
	// can be attributed to its family. Best effort and per process: a store
	// may implement stronger, cluster-wide detection on top.
	consumed map[string]consumedRefresh
	// lastPurge throttles the opportunistic PurgeExpired call.
	lastPurge time.Time
}

type consumedRefresh struct {
	familyID  string
	expiresAt time.Time
}

// maxConsumedLedger bounds the reuse-detection ledger so it can never be grown
// without limit by an attacker who keeps rotating tokens.
const maxConsumedLedger = 4096

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
	if len(cfg.JWTSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("mcpoauth: JWTSecret must be at least %d bytes, got %d",
			minJWTSecretLen, len(cfg.JWTSecret))
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
	if cfg.RefreshTokenAbsoluteTTL <= 0 {
		cfg.RefreshTokenAbsoluteTTL = 90 * 24 * time.Hour
	}
	if cfg.RefreshReuseWindow <= 0 {
		cfg.RefreshReuseWindow = 24 * time.Hour
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = 5 * time.Minute
	}
	if len(cfg.AllowedRedirectHosts) > 0 {
		hosts := make([]string, 0, len(cfg.AllowedRedirectHosts))
		for _, h := range cfg.AllowedRedirectHosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			hosts = append(hosts, h)
		}
		if len(hosts) == 0 {
			return nil, errors.New("mcpoauth: AllowedRedirectHosts contains only empty entries")
		}
		cfg.AllowedRedirectHosts = hosts
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
		cfg:      cfg,
		store:    store,
		http:     httpClient,
		signKey:  deriveSigningKey(cfg.JWTSecret),
		now:      time.Now,
		consumed: map[string]consumedRefresh{},
	}
	p.jwks = newJWKSCache(cfg.GoogleJWKSURL, httpClient, p.nowFn)
	return p, nil
}

func (p *Provider) nowFn() time.Time { return p.now() }

// PurgeExpired deletes every expired authorization code, pending authorization
// request and refresh token, and prunes the in-process refresh-reuse ledger.
//
// The provider also calls it opportunistically (at most once per
// Config.PurgeInterval) while serving requests, but that is only a backstop:
// run it from a ticker so an idle deployment still cleans up.
//
//	go func() {
//		for range time.Tick(10 * time.Minute) {
//			_ = provider.PurgeExpired(ctx)
//		}
//	}()
func (p *Provider) PurgeExpired(ctx context.Context) error {
	now := p.now()

	p.mu.Lock()
	p.lastPurge = now
	for h, c := range p.consumed {
		if !now.Before(c.expiresAt) {
			delete(p.consumed, h)
		}
	}
	p.mu.Unlock()

	if err := p.store.PurgeExpired(ctx, now); err != nil {
		return fmt.Errorf("purging expired records: %w", err)
	}
	return nil
}

// maybePurge runs PurgeExpired at most once per Config.PurgeInterval. Failures
// are ignored: housekeeping must never fail a login.
func (p *Provider) maybePurge(ctx context.Context) {
	now := p.now()
	p.mu.Lock()
	due := now.Sub(p.lastPurge) >= p.cfg.PurgeInterval
	if due {
		p.lastPurge = now // claim the slot before releasing the lock
	}
	p.mu.Unlock()
	if !due {
		return
	}
	_ = p.PurgeExpired(ctx)
}

// rememberConsumedRefresh records a rotated-away refresh token so a later
// replay can be attributed to its family.
func (p *Provider) rememberConsumedRefresh(tokenHash, familyID string, now time.Time) {
	if familyID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.consumed) >= maxConsumedLedger {
		for h, c := range p.consumed {
			if !now.Before(c.expiresAt) {
				delete(p.consumed, h)
			}
		}
		// Still full: drop arbitrary entries rather than grow without bound.
		for h := range p.consumed {
			if len(p.consumed) < maxConsumedLedger {
				break
			}
			delete(p.consumed, h)
		}
	}
	p.consumed[tokenHash] = consumedRefresh{
		familyID:  familyID,
		expiresAt: now.Add(p.cfg.RefreshReuseWindow),
	}
}

// familyOfConsumedRefresh reports the family of a refresh token that was
// already rotated away, if it is still inside the reuse window.
func (p *Provider) familyOfConsumedRefresh(tokenHash string, now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.consumed[tokenHash]
	if !ok {
		return "", false
	}
	if !now.Before(c.expiresAt) {
		delete(p.consumed, tokenHash)
		return "", false
	}
	return c.familyID, true
}

// --- browser binding -----------------------------------------------------

// binderCookieName is __Host-prefixed unless the provider is in dev mode.
func (p *Provider) binderCookieName() string {
	if p.cfg.InsecureDevMode {
		return BinderCookieNameInsecure
	}
	return BinderCookieName
}

// setBinderCookie issues the browser-binding cookie. SameSite=Lax is required
// (not Strict): the cookie has to survive the top-level GET redirect back from
// Google.
func (p *Provider) setBinderCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     p.binderCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !p.cfg.InsecureDevMode,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(p.cfg.PendingAuthTTL.Seconds()),
	})
}

// clearBinderCookie expires the binding cookie once the flow is over.
func (p *Provider) clearBinderCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     p.binderCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !p.cfg.InsecureDevMode,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// binderMatches reports whether the request carries the binding cookie that
// created the pending record. Fails closed on a missing cookie or a record with
// no binding at all.
func (p *Provider) binderMatches(r *http.Request, wantHash string) bool {
	if wantHash == "" {
		return false
	}
	c, err := r.Cookie(p.binderCookieName())
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashSecret(c.Value)), []byte(wantHash)) == 1
}

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
