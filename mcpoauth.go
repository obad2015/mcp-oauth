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
	// lastPurge throttles the opportunistic PurgeExpired call.
	lastPurge time.Time
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
	if len(cfg.JWTSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("mcpoauth: JWTSecret must be at least %d bytes, got %d",
			minJWTSecretLen, len(cfg.JWTSecret))
	}
	if n := distinctBytes(cfg.JWTSecret); n < minJWTSecretDistinct {
		return nil, fmt.Errorf(
			"mcpoauth: JWTSecret uses only %d distinct byte values (need at least %d); "+
				"it must be random, not a repeated or hand-typed string",
			n, minJWTSecretDistinct)
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

	// InsecureDevMode weakens the browser-binding cookie. It is only ever
	// coherent for plain-http local development, so refuse it for anything
	// that looks remotely like a deployment. Gating Issuer alone was not
	// enough: a loopback Issuer with every OTHER URL pointing at a public
	// https deployment was accepted, and the real origin then lost __Host- and
	// Secure on its binder cookie.
	if cfg.InsecureDevMode {
		devURLs := []struct{ name, value string }{
			{"Issuer", cfg.Issuer},
			{"ResourceURL", cfg.ResourceURL},
			{"MetadataBaseURL", cfg.MetadataBaseURL},
			{"AuthorizeURL", cfg.AuthorizeURL},
			{"TokenURL", cfg.TokenURL},
			{"RegisterURL", cfg.RegisterURL},
			{"GoogleRedirectURL", cfg.GoogleRedirectURL},
		}
		for _, u := range devURLs {
			if err := requireLoopbackHTTP(u.name, u.value); err != nil {
				return nil, err
			}
		}
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
	if cfg.RefreshGracePeriod == 0 {
		cfg.RefreshGracePeriod = 30 * time.Second
	}
	if cfg.RefreshGracePeriod < 0 {
		cfg.RefreshGracePeriod = 0
	}
	if cfg.UnusedClientTTL <= 0 {
		cfg.UnusedClientTTL = 24 * time.Hour
	}
	if cfg.ClientTTL <= 0 {
		cfg.ClientTTL = 90 * 24 * time.Hour
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = 5 * time.Minute
	}
	if strings.TrimSpace(cfg.VerifyStoreUserID) == "" {
		cfg.VerifyStoreUserID = defaultVerifyStoreUserID
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
		cfg:     cfg,
		store:   store,
		http:    httpClient,
		signKey: deriveSigningKey(cfg.JWTSecret),
		now:     time.Now,
	}
	p.jwks = newJWKSCache(cfg.GoogleJWKSURL, httpClient, p.nowFn)
	return p, nil
}

func (p *Provider) nowFn() time.Time { return p.now() }

// PurgeExpired deletes every record whose retention has lapsed: expired
// authorization codes and pending authorization requests, refresh tokens whose
// family has died (consumed rows included — they are the reuse-detection
// ledger), and client registrations that expired unused.
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

// --- browser binding -----------------------------------------------------

// maxBinders is how many concurrent authorization flows one browser can hold
// binders for. Older values fall off the end of the cookie.
const maxBinders = 5

// maxBinderLen caps a single binder value. Real ones are 43 characters (32
// random bytes, base64url). The cap plus the alphabet check below is what stops
// an attacker-supplied 200 KB cookie value from being echoed back verbatim in
// the Set-Cookie header that dropBinder writes.
const maxBinderLen = 64

// validBinder reports whether v has the shape this package issues: a non-empty
// base64url token no longer than maxBinderLen. Anything else is junk a browser
// never received from us, and is dropped on read.
func validBinder(v string) bool {
	if v == "" || len(v) > maxBinderLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// binderCookieName is __Host-prefixed unless the provider is in dev mode.
func (p *Provider) binderCookieName() string {
	if p.cfg.InsecureDevMode {
		return BinderCookieNameInsecure
	}
	return BinderCookieName
}

// readBinders returns the binder values the request carries, newest first.
func (p *Provider) readBinders(r *http.Request) []string {
	c, err := r.Cookie(p.binderCookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	// SplitN, not Split: an oversized cookie must not be exploded into a huge
	// slice. Anything past the cap lands in the final element, which still
	// carries a separator and so is rejected by validBinder.
	out := make([]string, 0, maxBinders)
	for _, v := range strings.SplitN(c.Value, BinderCookieSep, maxBinders+1) {
		if !validBinder(v) {
			continue
		}
		out = append(out, v)
		if len(out) == maxBinders {
			break
		}
	}
	return out
}

// writeBinderCookie stores values (newest first) in the binding cookie.
// SameSite=Lax is required (not Strict): the cookie has to survive the
// top-level GET redirect back from Google.
func (p *Provider) writeBinderCookie(w http.ResponseWriter, values []string) {
	c := &http.Cookie{
		Name:     p.binderCookieName(),
		Value:    strings.Join(values, BinderCookieSep),
		Path:     "/",
		HttpOnly: true,
		Secure:   !p.cfg.InsecureDevMode,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(p.cfg.PendingAuthTTL.Seconds()),
	}
	if len(values) == 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// addBinder prepends a new binder to whatever the browser already holds, so a
// second authorization flow in the same browser does not invalidate the first.
func (p *Provider) addBinder(w http.ResponseWriter, r *http.Request, value string) {
	values := append([]string{value}, p.readBinders(r)...)
	if len(values) > maxBinders {
		values = values[:maxBinders]
	}
	p.writeBinderCookie(w, values)
}

// dropBinder removes the binder a finished flow was pinned to (identified by
// its hash, which is all the pending record holds) and leaves any other tab's
// binder in place.
func (p *Provider) dropBinder(w http.ResponseWriter, r *http.Request, usedHash string) {
	kept := make([]string, 0, maxBinders)
	for _, v := range p.readBinders(r) {
		if usedHash != "" && subtle.ConstantTimeCompare([]byte(HashSecret(v)), []byte(usedHash)) == 1 {
			continue
		}
		kept = append(kept, v)
	}
	p.writeBinderCookie(w, kept)
}

// binderMatches reports whether the request carries the binding cookie that
// created the pending record. Fails closed on a missing cookie or a record with
// no binding at all.
func (p *Provider) binderMatches(r *http.Request, wantHash string) bool {
	if wantHash == "" {
		return false
	}
	match := false
	for _, v := range p.readBinders(r) {
		// No early exit: every candidate is compared in constant time.
		if subtle.ConstantTimeCompare([]byte(HashSecret(v)), []byte(wantHash)) == 1 {
			match = true
		}
	}
	return match
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

// requireLoopbackHTTP rejects anything that is not plain http on a loopback
// host. It gates Config.InsecureDevMode.
func requireLoopbackHTTP(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("mcpoauth: InsecureDevMode requires a loopback http:// %s, got %q", name, raw)
	}
	if !strings.EqualFold(u.Scheme, "http") || !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf(
			"mcpoauth: InsecureDevMode is for plain-http local development only, "+
				"but %s is %q; it must be http:// on 127.0.0.1, [::1] or localhost",
			name, raw)
	}
	return nil
}

// distinctBytes counts how many different byte values appear in b.
func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
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
