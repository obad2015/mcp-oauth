package mcpoauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// authorizeParams is a complete, valid authorization request.
func authorizeParams(clientID, redirectURI string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {pkceChallenge("a-verifier")},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
}

func TestConsentStep(t *testing.T) {
	t.Run("GET renders the approval page instead of bouncing to google", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)

		rec := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("GET /authorize redirected to %q; it must not touch google", loc)
		}
		body := rec.Body.String()
		if strings.Contains(body, "accounts.google.com") {
			t.Fatal("the consent page links to google")
		}
		if !strings.Contains(body, testRedirectURI) {
			t.Fatalf("the consent page does not show the redirect_uri:\n%s", body)
		}
		if !strings.Contains(body, "Test MCP Client") {
			t.Fatalf("the consent page does not name the client:\n%s", body)
		}
	})

	t.Run("GET alone creates no state usable at the callback", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		get := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		nonce := consentNonce(t, get.Body.String())
		h.google.grant("gc", testEmail)

		// The nonce is the pending record's handle before approval. Feeding it
		// to the callback as if it were a google state must fail closed.
		rec := h.callbackWithCookie(nonce, "gc", h.binder)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("an unapproved request produced a redirect to %q", loc)
		}
	})

	t.Run("the binder cookie is set with the hardened attributes", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		rec := h.authorizeGET(authorizeParams(clientID, testRedirectURI))

		c := binderCookie(rec)
		if c == nil {
			t.Fatal("no binder cookie was set")
		}
		checks := []struct {
			name string
			ok   bool
		}{
			{"__Host- prefixed name", c.Name == mcpoauth.BinderCookieName},
			{"HttpOnly", c.HttpOnly},
			{"Secure", c.Secure},
			{"SameSite=Lax", c.SameSite == http.SameSiteLaxMode},
			{"Path=/", c.Path == "/"},
			{"no Domain (required by __Host-)", c.Domain == ""},
			{"random-looking value", len(c.Value) >= 40},
		}
		for _, chk := range checks {
			if !chk.ok {
				t.Errorf("binder cookie: %s failed (%+v)", chk.name, c)
			}
		}
	})

	t.Run("dev mode falls back to the unprefixed cookie name", func(t *testing.T) {
		h := newHarness(t, devLoopback)
		clientID := h.register(testRedirectURI)
		c := binderCookie(h.authorizeGET(authorizeParams(clientID, testRedirectURI)))
		if c == nil {
			t.Fatal("no binder cookie was set")
		}
		if c.Name != mcpoauth.BinderCookieNameInsecure || c.Secure {
			t.Fatalf("dev-mode cookie = %+v, want %q without Secure", c, mcpoauth.BinderCookieNameInsecure)
		}
	})

	t.Run("approval is rejected", func(t *testing.T) {
		tests := []struct {
			name string
			// nonce and cookie are derived from a real consent page.
			nonce  func(h *harness, real string) string
			cookie func(h *harness, real *http.Cookie) *http.Cookie
		}{
			{
				name:   "without a nonce",
				nonce:  func(*harness, string) string { return "" },
				cookie: func(_ *harness, c *http.Cookie) *http.Cookie { return c },
			},
			{
				name:   "with a made-up nonce",
				nonce:  func(*harness, string) string { return "not-a-real-nonce" },
				cookie: func(_ *harness, c *http.Cookie) *http.Cookie { return c },
			},
			{
				name:   "with another flow's nonce",
				nonce:  func(h *harness, _ string) string { return h.otherFlowNonce(t) },
				cookie: func(_ *harness, c *http.Cookie) *http.Cookie { return c },
			},
			{
				name:   "without the binder cookie",
				nonce:  func(_ *harness, real string) string { return real },
				cookie: func(*harness, *http.Cookie) *http.Cookie { return nil },
			},
			{
				name:  "with a binder cookie from another browser",
				nonce: func(_ *harness, real string) string { return real },
				cookie: func(*harness, *http.Cookie) *http.Cookie {
					return &http.Cookie{Name: mcpoauth.BinderCookieName, Value: "someone-elses-binder"}
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				clientID := h.register(testRedirectURI)
				get := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
				real := consentNonce(t, get.Body.String())

				rec := h.approve(tc.nonce(h, real), tc.cookie(h, h.binder))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
				}
				if loc := rec.Header().Get("Location"); loc != "" {
					t.Fatalf("a rejected approval redirected to %q", loc)
				}
			})
		}
	})

	t.Run("the consent nonce is single use", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		get := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		nonce := consentNonce(t, get.Body.String())

		if rec := h.approve(nonce, h.binder); rec.Code != http.StatusFound {
			t.Fatalf("first approval: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if rec := h.approve(nonce, h.binder); rec.Code != http.StatusBadRequest {
			t.Fatalf("replayed approval: status = %d, want 400", rec.Code)
		}
	})

	t.Run("approval hands the browser to google and the flow still completes", func(t *testing.T) {
		h := newHarness(t)
		clientID, code, verifier := h.login(testEmail)
		if code == "" {
			t.Fatal("no authorization code came out of the consented flow")
		}
		rec := h.token(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("token: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if _, err := h.p.ValidateAccessToken(decodeJSON[tokenSuccess](t, rec).AccessToken); err != nil {
			t.Fatalf("access token invalid: %v", err)
		}
	})

	t.Run("attacker controlled strings are escaped on the default page", func(t *testing.T) {
		h := newHarness(t)
		const xss = `<img src=x onerror="alert(1)">`
		clientID := h.registerNamed(xss, "https://client.example.com/cb?a=<b>")

		rec := h.authorizeGET(authorizeParams(clientID, "https://client.example.com/cb?a=<b>"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, xss) || strings.Contains(body, "<img") {
			t.Fatalf("client_name was not escaped:\n%s", body)
		}
		if !strings.Contains(body, "&lt;img") {
			t.Fatalf("client_name is missing from the page entirely:\n%s", body)
		}
	})

	t.Run("a custom ConsentHandler replaces the default page", func(t *testing.T) {
		var seen mcpoauth.ConsentRequest
		var seenClient mcpoauth.Client
		h := newHarness(t, func(c *mcpoauth.Config) {
			c.ConsentHandler = func(w http.ResponseWriter, _ *http.Request, cl mcpoauth.Client, req mcpoauth.ConsentRequest) {
				seen, seenClient = req, cl
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("custom page"))
			}
		})
		clientID := h.register(testRedirectURI)
		rec := h.authorizeGET(authorizeParams(clientID, testRedirectURI))

		if rec.Body.String() != "custom page" {
			t.Fatalf("body = %q, want the custom page", rec.Body.String())
		}
		if seen.RedirectURI != testRedirectURI {
			t.Fatalf("ConsentRequest.RedirectURI = %q, want %q", seen.RedirectURI, testRedirectURI)
		}
		if seen.NonceField != mcpoauth.ConsentNonceField || seen.Nonce == "" {
			t.Fatalf("ConsentRequest nonce = %+v, want a nonce in the standard field", seen)
		}
		if seen.FormAction != testIssuer+"/api/mcp/oauth/authorize" {
			t.Fatalf("ConsentRequest.FormAction = %q", seen.FormAction)
		}
		if seenClient.ClientID != clientID {
			t.Fatalf("ConsentHandler got client %q, want %q", seenClient.ClientID, clientID)
		}
		// The nonce the integrator was handed must actually work.
		if rec := h.approve(seen.Nonce, h.binder); rec.Code != http.StatusFound {
			t.Fatalf("approving with the handler's nonce: status = %d", rec.Code)
		}
	})
}

// TestAuthorizationHijack is the adversarial scenario that motivated the
// consent + browser-binding work: an attacker registers a client pointing at
// their own server, generates an authorize URL, and phishes a victim with it.
// The victim only ever sees an accounts.google.com link, and PKCE is useless
// because the attacker owns both halves of the verifier.
func TestAuthorizationHijack(t *testing.T) {
	const evilRedirect = "https://evil.example.com/collect"

	// attackerFlow drives the attacker's own browser as far as the google hop
	// and returns the state they would phish the victim with.
	attackerFlow := func(t *testing.T, h *harness) (clientID, state string, attackerBinder *http.Cookie) {
		t.Helper()
		clientID = h.register(evilRedirect)
		get := h.authorizeGET(authorizeParams(clientID, evilRedirect))
		if get.Code != http.StatusOK {
			t.Fatalf("attacker authorize GET: status = %d", get.Code)
		}
		attackerBinder = h.binder
		rec := h.approve(consentNonce(t, get.Body.String()), attackerBinder)
		if rec.Code != http.StatusFound {
			t.Fatalf("attacker approval: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("bad Location: %v", err)
		}
		return clientID, loc.Query().Get("state"), attackerBinder
	}

	// The victim's browser never carries the attacker's binder cookie.
	victimCookies := []struct {
		name   string
		cookie func(attacker *http.Cookie) *http.Cookie
	}{
		{"victim has no binder cookie", func(*http.Cookie) *http.Cookie { return nil }},
		{
			"victim has a binder cookie from their own unrelated flow",
			func(*http.Cookie) *http.Cookie {
				return &http.Cookie{Name: mcpoauth.BinderCookieName, Value: "victims-own-unrelated-binder-value"}
			},
		},
		{
			"victim has an empty binder cookie",
			func(*http.Cookie) *http.Cookie {
				return &http.Cookie{Name: mcpoauth.BinderCookieName, Value: ""}
			},
		},
	}

	for _, tc := range victimCookies {
		t.Run("phished victim completes google login: "+tc.name, func(t *testing.T) {
			h := newHarness(t)
			_, state, attackerBinder := attackerFlow(t, h)
			h.google.grant("victims-google-code", testEmail)

			rec := h.callbackWithCookie(state, "victims-google-code", tc.cookie(attackerBinder))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("callback status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("the victim's browser was redirected to %q; no code may leave here", loc)
			}
			if _, codes, _, _ := h.store.Len(); codes != 0 {
				t.Fatalf("%d authorization codes were minted for a hijacked flow", codes)
			}
		})
	}

	t.Run("the pending record is burned, so the attacker cannot retry", func(t *testing.T) {
		h := newHarness(t)
		_, state, attackerBinder := attackerFlow(t, h)
		h.google.grant("victims-google-code", testEmail)

		if rec := h.callbackWithCookie(state, "victims-google-code", nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("victim callback: status = %d, want 400", rec.Code)
		}
		// Even the attacker's own browser cannot pick the flow back up.
		rec := h.callbackWithCookie(state, "victims-google-code", attackerBinder)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attacker retry: status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "evil.example.com") {
			t.Fatalf("a code was delivered to the attacker at %q", loc)
		}
	})

	t.Run("no token is ever mintable for the victim", func(t *testing.T) {
		h := newHarness(t)
		clientID, state, _ := attackerFlow(t, h)
		h.google.grant("victims-google-code", testEmail)
		_ = h.callbackWithCookie(state, "victims-google-code", nil)

		// The attacker has no code; try the exchange anyway with everything
		// they do control.
		rec := h.token(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {state},
			"client_id":     {clientID},
			"redirect_uri":  {evilRedirect},
			"code_verifier": {"a-verifier"},
		})
		if rec.Code == http.StatusOK {
			t.Fatalf("a token was issued to the attacker: %s", rec.Body.String())
		}
		if _, _, _, refresh := h.store.Len(); refresh != 0 {
			t.Fatalf("%d refresh tokens exist after a failed hijack", refresh)
		}
	})

	t.Run("the phishing link shows the victim the attacker's address", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(evilRedirect)

		// This is what the victim's browser renders when they click the link.
		rec := h.authorizeGET(authorizeParams(clientID, evilRedirect))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("the victim was bounced straight to %q with nothing to see", loc)
		}
		if !strings.Contains(rec.Body.String(), evilRedirect) {
			t.Fatalf("the consent page hides the attacker's redirect_uri:\n%s", rec.Body.String())
		}
	})

	t.Run("a registered client cannot be swapped for another redirect_uri", func(t *testing.T) {
		h := newHarness(t)
		honest := h.register(testRedirectURI)
		h.register(evilRedirect) // exists, but belongs to the attacker

		rec := h.authorizeGET(authorizeParams(honest, evilRedirect))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if _, _, pending, _ := h.store.Len(); pending != 0 {
			t.Fatalf("%d pending records written for a rejected request", pending)
		}
	})
}
