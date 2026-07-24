package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProtectedResourceMetadata serves the RFC 9728 protected-resource metadata
// document. Mount it at /.well-known/oauth-protected-resource (and, for MCP
// clients that probe the path-qualified variant, at
// /.well-known/oauth-protected-resource/<mcp path> as well).
func (p *Provider) ProtectedResourceMetadata() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowCORS(w, r, http.MethodGet) {
			return
		}
		if !isReadMethod(r.Method) {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":                 p.cfg.ResourceURL,
			"authorization_servers":    []string{p.cfg.Issuer},
			"scopes_supported":         []string{"openid", "email", "profile"},
			"bearer_methods_supported": []string{"header"},
		})
	}
}

// AuthorizationServerMetadata serves the RFC 8414 authorization-server
// metadata document. Mount it at /.well-known/oauth-authorization-server
// (and, harmlessly, at /.well-known/openid-configuration).
func (p *Provider) AuthorizationServerMetadata() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowCORS(w, r, http.MethodGet) {
			return
		}
		if !isReadMethod(r.Method) {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                p.cfg.Issuer,
			"authorization_endpoint":                p.cfg.AuthorizeURL,
			"token_endpoint":                        p.cfg.TokenURL,
			"registration_endpoint":                 p.cfg.RegisterURL,
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
		})
	}
}

// isReadMethod reports whether the method is one a metadata document may be
// served for.
func isReadMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// --- dynamic client registration (RFC 7591) ------------------------------

type registrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

const (
	maxRedirectURIs      = 10
	maxRedirectURILen    = 2048
	maxClientNameLen     = 200
	maxRegistrationBytes = 16 << 10
)

// Register implements dynamic client registration. Clients are public: no
// client_secret is ever issued, and the token endpoint uses auth method "none"
// (PKCE is what protects the exchange).
func (p *Provider) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowCORS(w, r, http.MethodPost) {
			return
		}
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}

		var req registrationRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, maxRegistrationBytes))
		if err := dec.Decode(&req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be JSON")
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
			return
		}
		if len(req.RedirectURIs) > maxRedirectURIs {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "too many redirect_uris")
			return
		}
		for _, u := range req.RedirectURIs {
			if len(u) > maxRedirectURILen {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is too long")
				return
			}
			if err := ValidateRedirectURI(u); err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
				return
			}
			if err := p.checkRedirectHostPolicy(u); err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
				return
			}
		}
		if len(req.ClientName) > maxClientNameLen {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name is too long")
			return
		}

		clientID, err := randomToken(24)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate client id")
			return
		}

		// Registration is unauthenticated, so a fresh client is short-lived
		// until it actually completes a login (see extendClient).
		now := p.now()
		client := Client{
			ClientID:     clientID,
			RedirectURIs: req.RedirectURIs,
			ClientName:   req.ClientName,
			CreatedAt:    now,
			ExpiresAt:    now.Add(p.cfg.UnusedClientTTL),
		}
		if err := p.store.SaveClient(r.Context(), client); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist client")
			return
		}

		writeJSON(w, http.StatusCreated, registrationResponse{
			ClientID:                client.ClientID,
			RedirectURIs:            client.RedirectURIs,
			ClientName:              client.ClientName,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
		})
	}
}

// ValidateRedirectURI enforces the redirect URI policy: absolute URL, no
// fragment, and either https:// or an http:// loopback address (which is what
// CLI clients such as Claude Code use, on a random port).
func ValidateRedirectURI(raw string) error {
	if raw == "" {
		return errors.New("redirect_uri must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("redirect_uri is not a valid URL")
	}
	if !u.IsAbs() || u.Host == "" {
		return errors.New("redirect_uri must be an absolute URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("redirect_uri must not contain a fragment")
	}
	if u.User != nil {
		return errors.New("redirect_uri must not contain userinfo")
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return errors.New("http redirect_uri is only allowed for loopback addresses")
		}
		return nil
	default:
		return fmt.Errorf("unsupported redirect_uri scheme %q", u.Scheme)
	}
}

// checkRedirectHostPolicy applies Config.AllowedRedirectHosts on top of
// ValidateRedirectURI. Loopback http URIs are always allowed — MCP CLI clients
// listen on a random loopback port and cannot be enumerated in advance. When
// the allowlist is empty the policy is a no-op.
//
// It assumes ValidateRedirectURI already accepted raw.
func (p *Provider) checkRedirectHostPolicy(raw string) error {
	if len(p.cfg.AllowedRedirectHosts) == 0 {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("redirect_uri is not a valid URL")
	}
	host := strings.ToLower(u.Hostname())
	if strings.EqualFold(u.Scheme, "http") && isLoopbackHost(host) {
		return nil
	}
	for _, allowed := range p.cfg.AllowedRedirectHosts {
		if host == allowed {
			return nil
		}
	}
	return errors.New("redirect_uri host is not allowed by this deployment")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- authorize -----------------------------------------------------------

// maxClientStateLen bounds the client's own `state` parameter, which is stored
// verbatim and echoed back on the redirect.
const maxClientStateLen = 512

// maxConsentFormBytes bounds the approval POST body.
const maxConsentFormBytes = 8 << 10

// Authorize is the authorization endpoint. It handles two methods and mounts as
// ONE route:
//
//   - GET renders an interstitial consent page naming the client and the exact
//     redirect URI the authorization code would be delivered to. It does NOT
//     redirect to Google, and the pending record it creates cannot complete a
//     login on its own.
//   - POST carries the single-use consent nonce from that page back, and only
//     then is the browser bounced to Google.
//
// Both steps are pinned to the browser with a binding cookie whose hash is
// stored on the pending record; the Google callback refuses to hand out an
// authorization code to a different browser. Together these stop the
// attacker-initiated flow where a victim is phished with a legitimate-looking
// accounts.google.com link belonging to an attacker-registered client (PKCE
// cannot help there: the attacker owns both halves of the verifier).
//
// Any failure that involves an unknown client or a redirect URI that is not
// exactly registered is answered with a direct 400 — never a redirect — so this
// endpoint can never be abused as an open redirector. For consistency and to
// keep failures visible in the CLI, all other validation failures are also
// answered directly.
func (p *Provider) Authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			p.authorizeConsent(w, r)
		case http.MethodPost:
			p.authorizeApprove(w, r)
		default:
			// HEAD included on purpose: it must not mint or persist anything.
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET or POST required")
		}
	}
}

// authorizeConsent validates the authorization request and renders the approval
// page. The pending record it writes is keyed by the consent nonce and is not
// approved, so it is worthless to anyone who does not complete the POST from
// the same browser.
func (p *Provider) authorizeConsent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id and redirect_uri are required")
		return
	}

	client, ok, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load client")
		return
	}
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if !client.HasRedirectURI(redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return
	}
	// Re-checked here and not only at registration, so that tightening
	// AllowedRedirectHosts takes effect for clients registered earlier.
	if err := p.checkRedirectHostPolicy(redirectURI); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// From here the redirect_uri is trusted, but we still answer directly.
	if rt := q.Get("response_type"); rt != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required (PKCE)")
		return
	}
	if err := validateCodeChallenge(challenge); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}
	clientState := q.Get("state")
	if len(clientState) > maxClientStateLen {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "state is too long")
		return
	}

	p.maybePurge(r.Context())

	// The nonce identifies the pending record until it is approved; the binder
	// pins the whole flow to this browser.
	nonce, err := randomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate consent nonce")
		return
	}
	binder, err := randomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate browser binding")
		return
	}

	now := p.now()
	if err := p.store.SavePendingAuth(r.Context(), PendingAuth{
		StateHash:     HashSecret(nonce),
		ClientID:      client.ClientID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		ClientState:   clientState,
		BinderHash:    HashSecret(binder),
		Approved:      false,
		ExpiresAt:     now.Add(p.cfg.PendingAuthTTL),
		CreatedAt:     now,
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist authorization request")
		return
	}

	p.addBinder(w, r, binder)
	p.renderConsent(w, r, client, ConsentRequest{
		RedirectURI: redirectURI,
		Scopes:      strings.Fields(GrantedScope),
		FormAction:  p.cfg.AuthorizeURL,
		NonceField:  ConsentNonceField,
		Nonce:       nonce,
	})
}

// authorizeApprove completes the consent step and starts the Google hop.
func (p *Provider) authorizeApprove(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxConsentFormBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	nonce := r.PostFormValue(ConsentNonceField)
	if nonce == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing consent nonce")
		return
	}

	// Single-use: the nonce is burned whether or not the rest succeeds.
	pending, ok, err := p.store.ConsumePendingAuth(r.Context(), HashSecret(nonce))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load authorization request")
		return
	}
	if !ok || pending.Approved {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"consent nonce is unknown, expired or already used")
		return
	}
	if !p.now().Before(pending.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization request expired")
		return
	}
	if !p.binderMatches(r, pending.BinderHash) {
		p.dropBinder(w, r, pending.BinderHash)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"this approval did not come from the browser that started the authorization request")
		return
	}

	state, err := randomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate state")
		return
	}
	now := p.now()
	approved := pending
	approved.StateHash = HashSecret(state)
	approved.Approved = true
	approved.ExpiresAt = now.Add(p.cfg.PendingAuthTTL)
	if err := p.store.SavePendingAuth(r.Context(), approved); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist authorization request")
		return
	}

	google := p.cfg.GoogleAuthURL + "?" + url.Values{
		"client_id":     {p.cfg.GoogleClientID},
		"redirect_uri":  {p.cfg.GoogleRedirectURL},
		"response_type": {"code"},
		"scope":         {GrantedScope},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"select_account"},
	}.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, google, http.StatusFound)
}

// --- google callback -----------------------------------------------------

const unlinkedAccountHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Account not linked</title></head>
<body style="font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.6">
<h1 style="font-size:1.4rem">This Google account is not linked to an account in this app</h1>
<p>Sign in to the app with this Google account first, then retry the connection.</p>
<p>No account was created.</p>
</body></html>`

// GoogleCallback completes the upstream login and hands an authorization code
// back to the MCP client.
func (p *Provider) GoogleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET required")
			return
		}
		q := r.URL.Query()

		state := q.Get("state")
		if state == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing state")
			return
		}
		pending, ok, err := p.store.ConsumePendingAuth(r.Context(), HashSecret(state))
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load authorization request")
			return
		}
		// From here the pending record is consumed whatever happens: every
		// failure below burns it, so nothing can be retried by an attacker.
		if !ok {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown, expired or already used state")
			return
		}
		p.dropBinder(w, r, pending.BinderHash)
		if !pending.Approved {
			// A record that never passed the consent step (its handle is the
			// consent nonce, not a Google state).
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"this authorization request was never approved")
			return
		}
		if !p.binderMatches(r, pending.BinderHash) {
			// The browser completing the Google login is not the one that
			// started the flow. This is the cross-browser authorization
			// hijack; fail closed and never emit a code.
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"this login was completed in a different browser than the one that "+
					"started the authorization request; start the connection again")
			return
		}
		if !p.now().Before(pending.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization request expired")
			return
		}

		// The user denied consent (or Google failed): bounce the error back to
		// the client on its already-validated redirect URI.
		if gerr := q.Get("error"); gerr != "" {
			p.redirectClientError(w, r, pending, "access_denied", "the upstream login was not completed")
			return
		}

		code := q.Get("code")
		if code == "" {
			p.redirectClientError(w, r, pending, "invalid_request", "google returned no authorization code")
			return
		}

		identity, err := p.exchangeGoogleCode(r.Context(), code)
		if err != nil {
			// err may reference upstream detail; do not surface it.
			p.redirectClientError(w, r, pending, "access_denied", "could not verify the google login")
			return
		}

		userID, ok, err := p.store.FindUserIDByEmail(r.Context(), identity.Email)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not look up user")
			return
		}
		if !ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, unlinkedAccountHTML)
			return
		}

		rawCode, err := randomToken(32)
		if err != nil {
			p.redirectClientError(w, r, pending, "server_error", "could not generate authorization code")
			return
		}
		now := p.now()
		if err := p.store.SaveAuthCode(r.Context(), AuthCode{
			CodeHash:      HashSecret(rawCode),
			ClientID:      pending.ClientID,
			UserID:        userID,
			RedirectURI:   pending.RedirectURI,
			CodeChallenge: pending.CodeChallenge,
			ExpiresAt:     now.Add(p.cfg.AuthCodeTTL),
			CreatedAt:     now,
		}); err != nil {
			p.redirectClientError(w, r, pending, "server_error", "could not persist authorization code")
			return
		}

		// The registration has now been used to complete a login, so it stops
		// being a throwaway row.
		p.extendClient(r.Context(), pending.ClientID, now)

		params := url.Values{"code": {rawCode}}
		if pending.ClientState != "" {
			params.Set("state", pending.ClientState)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, appendQuery(pending.RedirectURI, params), http.StatusFound)
	}
}

// extendClient pushes a client's expiry out to Config.ClientTTL once it has
// completed a login. Failures are ignored: this is housekeeping, and losing it
// only means the registration expires earlier than it should.
func (p *Provider) extendClient(ctx context.Context, clientID string, now time.Time) {
	c, ok, err := p.store.GetClient(ctx, clientID)
	if err != nil || !ok {
		return
	}
	want := now.Add(p.cfg.ClientTTL)
	if !c.ExpiresAt.Before(want) {
		return
	}
	c.ExpiresAt = want
	_ = p.store.SaveClient(ctx, c)
}

// redirectClientError sends an OAuth error back to the client's registered
// redirect URI. Only ever called with a redirect URI that was validated at
// authorize time.
func (p *Provider) redirectClientError(w http.ResponseWriter, r *http.Request, pending PendingAuth, code, desc string) {
	params := url.Values{"error": {code}, "error_description": {desc}}
	if pending.ClientState != "" {
		params.Set("state", pending.ClientState)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, appendQuery(pending.RedirectURI, params), http.StatusFound)
}

// appendQuery merges params into the query string of a (already validated) URL.
func appendQuery(raw string, params url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// --- token ---------------------------------------------------------------

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// Token implements the token endpoint for the authorization_code and
// refresh_token grants.
func (p *Provider) Token() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowCORS(w, r, http.MethodPost) {
			return
		}
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return
		}

		switch r.PostFormValue("grant_type") {
		case "authorization_code":
			p.authorizationCodeGrant(w, r)
		case "refresh_token":
			p.refreshTokenGrant(w, r)
		case "":
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		}
	}
}

func (p *Provider) authorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	redirectURI := r.PostFormValue("redirect_uri")
	verifier := r.PostFormValue("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"code, client_id, redirect_uri and code_verifier are required")
		return
	}

	// Single-use: a replay finds nothing.
	ac, ok, err := p.store.ConsumeAuthCode(r.Context(), HashSecret(code))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load authorization code")
		return
	}
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or already used")
		return
	}
	if !p.now().Before(ac.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if ac.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued to another client")
		return
	}
	if ac.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if !verifyPKCE(verifier, ac.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// A fresh login starts a new refresh-token family.
	familyID, err := randomToken(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not start a token family")
		return
	}
	p.issueTokenPair(r.Context(), w, rotation{}, ac.ClientID, ac.UserID, familyID, p.now())
}

// rotation identifies the refresh token a new pair is descended from, so the
// predecessor's row can be linked to its successor. The zero value means "this
// is a fresh login, there is no predecessor".
type rotation struct {
	raw  string
	hash string
}

// refreshTokenGrant rotates a refresh token.
//
// Store.ConsumeRefreshToken does not delete: it stamps ConsumedAt and returns
// the row as it was, which is what makes the three cases distinguishable
// durably — across restarts, and however many times an attacker rotates.
//
//	unknown hash              -> invalid_grant, nothing is revoked.
//	row with zero  ConsumedAt -> legitimate rotation.
//	row with a set ConsumedAt -> replay: either a duplicate submission inside
//	                             Config.RefreshGracePeriod (answered with the
//	                             same successor) or REUSE (family revoked).
func (p *Provider) refreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	raw := r.PostFormValue("refresh_token")
	clientID := r.PostFormValue("client_id")
	if raw == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}
	now := p.now()
	tokenHash := HashSecret(raw)

	// Bind the token to the presenting client BEFORE consuming it. Consuming
	// first would let anyone who merely learns a refresh token burn it by
	// presenting it with an arbitrary client_id: the owner's next legitimate
	// use would then be classified as reuse and kill the whole family — an
	// unauthenticated logout of the victim, and a self-inflicted one on a
	// client_id typo. A client mismatch is therefore non-consuming and never
	// revokes anything.
	bound, known, err := p.store.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load refresh token")
		return
	}
	if known && bound.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to another client")
		return
	}

	rt, ok, err := p.store.ConsumeRefreshToken(r.Context(), tokenHash, now)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not load refresh token")
		return
	}
	if !ok {
		// Never issued, or the family is already gone (revoked or purged).
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or already used")
		return
	}
	if !rt.ConsumedAt.IsZero() {
		p.replayedRefreshToken(w, r, rt, raw, clientID, now)
		return
	}

	if !now.Before(rt.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	// Absolute lifetime: rotation must not be able to extend a session
	// forever. Measured from the login that created the family.
	familyStart := rt.FamilyCreatedAt
	if familyStart.IsZero() {
		familyStart = rt.CreatedAt
	}
	if familyStart.IsZero() || !now.Before(familyStart.Add(p.cfg.RefreshTokenAbsoluteTTL)) {
		if rt.FamilyID != "" {
			if err := p.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID); err != nil {
				writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not revoke the token family")
				return
			}
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token family has reached its absolute lifetime; sign in again")
		return
	}
	if rt.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to another client")
		return
	}

	// Fail closed on a token with no family: rather than propagate the
	// emptiness (which would opt the whole chain out of reuse detection and the
	// absolute cap), start a family here. LinkRefreshSuccessor stamps it back
	// onto this row so a later replay of it still revokes the new family.
	familyID := rt.FamilyID
	if familyID == "" {
		if familyID, err = randomToken(16); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not start a token family")
			return
		}
	}

	p.issueTokenPair(r.Context(), w, rotation{raw: raw, hash: tokenHash},
		rt.ClientID, rt.UserID, familyID, familyStart)
}

// replayedRefreshToken handles a token that was already rotated away.
//
// Inside Config.RefreshGracePeriod, and only for the token that was consumed
// most recently in its family whose successor is still unused, this is treated
// as a duplicate submission and answered with the same refresh token the
// original rotation issued. That keeps a client that lost the response (or
// fired two requests at once) from destroying its own session.
//
// Everything else is refresh-token REUSE: either the legitimate client or a
// thief is replaying a spent token and we cannot tell which, so the whole
// family dies and both holders have to sign in again.
func (p *Provider) replayedRefreshToken(w http.ResponseWriter, r *http.Request, rt RefreshToken, raw, clientID string, now time.Time) {
	if p.graceApplies(r.Context(), rt, raw, clientID, now) {
		successor, ok := p.openSuccessor(raw, rt.SuccessorSealed)
		if ok {
			p.writeTokenPair(w, rt.UserID, successor, now)
			return
		}
		// The winning rotation has not attached its successor yet (a genuinely
		// concurrent duplicate). Fail this attempt, but never revoke: the
		// caller retries and the family stays alive.
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"this refresh token is being rotated by another request; retry")
		return
	}

	if rt.FamilyID != "" {
		if err := p.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not revoke the token family")
			return
		}
	}
	writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
		"refresh token was already used; the whole token family has been revoked, sign in again")
}

// graceApplies reports whether a replayed token qualifies for the idempotent
// grace window. Every condition is deliberately narrow.
func (p *Provider) graceApplies(ctx context.Context, rt RefreshToken, raw, clientID string, now time.Time) bool {
	if p.cfg.RefreshGracePeriod <= 0 || rt.ConsumedAt.IsZero() {
		return false
	}
	// Only lateness disqualifies a replay. There is deliberately NO lower bound:
	// a `now` that precedes the stored stamp is the signature of a genuinely
	// concurrent duplicate — this request sampled its clock before the winning
	// rotation stamped the row — and on a multi-node deployment it is also
	// ordinary clock skew. Rejecting it revoked the family for the exact case
	// this window exists to absorb.
	if now.After(rt.ConsumedAt.Add(p.cfg.RefreshGracePeriod)) {
		return false
	}
	if rt.ClientID != clientID {
		return false
	}
	if len(rt.SuccessorSealed) == 0 {
		// Mid-rotation: no successor yet, but this is still not reuse.
		return true
	}
	successor, ok := p.openSuccessor(raw, rt.SuccessorSealed)
	if !ok {
		return false
	}
	// The family must not have moved on: if the successor was itself already
	// rotated away, this replay is a token that is two steps stale, which is
	// reuse however recent it is.
	next, found, err := p.store.GetRefreshToken(ctx, HashSecret(successor))
	if err != nil || !found {
		return false
	}
	return next.ConsumedAt.IsZero() && now.Before(next.ExpiresAt)
}

// issueTokenPair mints a new access/refresh pair, persists the refresh token
// and, when this is a rotation, seals the new refresh token onto the row of the
// token it replaces.
func (p *Provider) issueTokenPair(ctx context.Context, w http.ResponseWriter, prev rotation, clientID, userID, familyID string, familyCreatedAt time.Time) {
	now := p.now()

	refresh, err := randomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
		return
	}
	// The sliding window never outlives the absolute cap.
	familyExpiresAt := familyCreatedAt.Add(p.cfg.RefreshTokenAbsoluteTTL)
	expiresAt := now.Add(p.cfg.RefreshTokenTTL)
	if familyExpiresAt.Before(expiresAt) {
		expiresAt = familyExpiresAt
	}

	// Persist the successor BEFORE linking it onto the predecessor. The reverse
	// order left a sealed blob pointing at a row that did not exist yet, so a
	// failed or slow SaveRefreshToken turned the client's next legitimate retry
	// into a family revocation.
	if err := p.store.SaveRefreshToken(ctx, RefreshToken{
		TokenHash:       HashSecret(refresh),
		ClientID:        clientID,
		UserID:          userID,
		FamilyID:        familyID,
		FamilyCreatedAt: familyCreatedAt,
		FamilyExpiresAt: familyExpiresAt,
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist refresh token")
		return
	}

	if prev.hash != "" {
		sealed, err := p.sealSuccessor(prev.raw, refresh)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not seal the rotated token")
			return
		}
		if err := p.store.LinkRefreshSuccessor(ctx, prev.hash, familyID, sealed); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not record the token rotation")
			return
		}
		// Re-check the family AFTER the write. A reuse detection that fired
		// while this rotation was in flight would have deleted the family
		// between our read and our SaveRefreshToken, and the row we just
		// inserted would silently resurrect it — the victim stays evicted while
		// the attacker keeps rotating. The predecessor row disappearing is that
		// signal: undo our own insert by revoking the family we issued into.
		_, still, err := p.store.GetRefreshToken(ctx, prev.hash)
		if err != nil {
			// A transient read error is not proof of revocation. The
			// predecessor is already consumed either way, so nothing usable is
			// left behind by failing closed here WITHOUT revoking the family —
			// revoking on a DB blip would log the legitimate client out.
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not verify token rotation")
			return
		}
		if !still {
			_ = p.store.RevokeRefreshTokenFamily(ctx, familyID)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
				"refresh token was already used; the whole token family has been revoked, sign in again")
			return
		}
	}

	p.writeTokenPair(w, userID, refresh, now)
}

// writeTokenPair mints a fresh access token for userID and writes the token
// response. The refresh token is passed in because a grace-window replay
// returns the one that already exists rather than minting another.
func (p *Provider) writeTokenPair(w http.ResponseWriter, userID, refresh string, now time.Time) {
	access, err := p.issueAccessToken(userID, now)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refresh,
		Scope:        GrantedScope,
	})
}

// --- middleware ----------------------------------------------------------

// Middleware protects the MCP endpoint. It requires a valid access token
// issued by this Provider and injects the user ID into the request context
// (read it back with UserIDFromContext).
//
// Every failure is a 401 carrying the RFC 9728 WWW-Authenticate challenge, which
// is what makes an MCP client discover the authorization server and start the
// flow.
func (p *Provider) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r)
		if !ok {
			p.Unauthorized(w)
			return
		}
		userID, err := p.ValidateAccessToken(token)
		if err != nil {
			p.Unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserIDContextKey, userID)))
	})
}

// BearerToken extracts the token from an Authorization: Bearer header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// Unauthorized writes the 401 challenge. Exported so applications that chain
// their own legacy token check can emit the identical response.
func (p *Provider) Unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer resource_metadata=%q", p.ProtectedResourceMetadataURL()))
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}
