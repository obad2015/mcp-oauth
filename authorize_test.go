package mcpoauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorize(t *testing.T) {
	// baseParams is a valid authorize request for the registered client.
	baseParams := func(clientID string) url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRedirectURI},
			"code_challenge":        {pkceChallenge("verifier")},
			"code_challenge_method": {"S256"},
			"state":                 {"client-state"},
			"scope":                 {"openid email profile"},
		}
	}

	t.Run("valid request redirects to google", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)

		rec, state := h.authorize(baseParams(clientID))
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 (body %s)", rec.Code, rec.Body.String())
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("bad Location: %v", err)
		}
		if loc.Host != "accounts.google.com" {
			t.Fatalf("redirected to %q, want accounts.google.com", loc.Host)
		}

		q := loc.Query()
		want := map[string]string{
			"client_id":     testGoogleCID,
			"redirect_uri":  testIssuer + "/api/mcp/oauth/google/callback",
			"response_type": "code",
			"scope":         "openid email profile",
			"access_type":   "offline",
			"prompt":        "select_account",
		}
		for k, v := range want {
			if q.Get(k) != v {
				t.Fatalf("google param %s = %q, want %q", k, q.Get(k), v)
			}
		}
		if state == "" {
			t.Fatal("no state handed to google")
		}
		if strings.Contains(loc.String(), "client-state") {
			t.Fatal("the client's own state value was forwarded to google")
		}
	})

	t.Run("rejections are answered directly, never redirected", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(h *harness, params url.Values)
			wantError string
		}{
			{
				name:      "unregistered client",
				mutate:    func(_ *harness, p url.Values) { p.Set("client_id", "never-registered") },
				wantError: "invalid_client",
			},
			{
				name:      "missing client_id",
				mutate:    func(_ *harness, p url.Values) { p.Del("client_id") },
				wantError: "invalid_request",
			},
			{
				name:      "redirect_uri not registered for this client",
				mutate:    func(_ *harness, p url.Values) { p.Set("redirect_uri", "http://127.0.0.1:9999/callback") },
				wantError: "invalid_request",
			},
			{
				name:      "redirect_uri only prefix-matches",
				mutate:    func(_ *harness, p url.Values) { p.Set("redirect_uri", testRedirectURI+"/extra") },
				wantError: "invalid_request",
			},
			{
				name: "redirect_uri of another client",
				mutate: func(h *harness, p url.Values) {
					h.register("https://other.example.com/cb")
					p.Set("redirect_uri", "https://other.example.com/cb")
				},
				wantError: "invalid_request",
			},
			{
				name:      "missing redirect_uri",
				mutate:    func(_ *harness, p url.Values) { p.Del("redirect_uri") },
				wantError: "invalid_request",
			},
			{
				name:      "plain pkce method",
				mutate:    func(_ *harness, p url.Values) { p.Set("code_challenge_method", "plain") },
				wantError: "invalid_request",
			},
			{
				name:      "missing pkce method",
				mutate:    func(_ *harness, p url.Values) { p.Del("code_challenge_method") },
				wantError: "invalid_request",
			},
			{
				name:      "lowercase pkce method",
				mutate:    func(_ *harness, p url.Values) { p.Set("code_challenge_method", "s256") },
				wantError: "invalid_request",
			},
			{
				name:      "missing code_challenge",
				mutate:    func(_ *harness, p url.Values) { p.Del("code_challenge") },
				wantError: "invalid_request",
			},
			{
				name:      "token response type",
				mutate:    func(_ *harness, p url.Values) { p.Set("response_type", "token") },
				wantError: "unsupported_response_type",
			},
			{
				name:      "missing response type",
				mutate:    func(_ *harness, p url.Values) { p.Del("response_type") },
				wantError: "unsupported_response_type",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				params := baseParams(h.register(testRedirectURI))
				tc.mutate(h, params)

				rec, _ := h.authorize(params)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
				}
				if loc := rec.Header().Get("Location"); loc != "" {
					t.Fatalf("a rejected authorize request redirected to %q", loc)
				}
				if got := decodeJSON[errorBody](t, rec).Error; got != tc.wantError {
					t.Fatalf("error = %q, want %q", got, tc.wantError)
				}
			})
		}
	})

	// POST is the consent-approval leg, so it is no longer a 405 — but the
	// authorization parameters alone must not get anyone past it.
	t.Run("POST without a consent nonce is rejected", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		req := postForm("/authorize", baseParams(clientID))
		rec := newRec()
		h.p.Authorize()(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("an unapproved POST redirected to %q", loc)
		}
	})
}
