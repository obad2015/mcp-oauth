package mcpoauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

func TestAuthorizationCodeGrant(t *testing.T) {
	t.Run("happy path issues a usable token pair", func(t *testing.T) {
		h := newHarness(t)
		clientID, code, verifier := h.login(testEmail)

		rec := h.token(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}

		out := decodeJSON[tokenSuccess](t, rec)
		if out.TokenType != "Bearer" {
			t.Fatalf("token_type = %q, want Bearer", out.TokenType)
		}
		if out.ExpiresIn != int64((time.Hour).Seconds()) {
			t.Fatalf("expires_in = %d, want 3600", out.ExpiresIn)
		}
		if out.Scope != mcpoauth.GrantedScope {
			t.Fatalf("scope = %q, want %q", out.Scope, mcpoauth.GrantedScope)
		}
		if out.RefreshToken == "" {
			t.Fatal("refresh_token is empty")
		}
		userID, err := h.p.ValidateAccessToken(out.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error: %v", err)
		}
		if userID != testUserID {
			t.Fatalf("subject = %q, want %q", userID, testUserID)
		}
	})

	t.Run("client state is echoed back on the redirect", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		_, state := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRedirectURI},
			"code_challenge":        {pkceChallenge("v")},
			"code_challenge_method": {"S256"},
			"state":                 {"client-state-xyz"},
		})
		h.google.grant("gc", testEmail)
		rec := h.callback(state, "gc")

		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("bad Location: %v", err)
		}
		if !strings.HasPrefix(loc.String(), testRedirectURI) {
			t.Fatalf("redirected to %q, want prefix %q", loc.String(), testRedirectURI)
		}
		if got := loc.Query().Get("state"); got != "client-state-xyz" {
			t.Fatalf("state = %q, want client-state-xyz", got)
		}
		if loc.Query().Get("code") == "" {
			t.Fatal("no code in redirect")
		}
	})

	// Table over the ways the code exchange must fail.
	t.Run("rejections", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(h *harness, form url.Values)
			wantCode  int
			wantError string
		}{
			{
				name: "wrong pkce verifier",
				mutate: func(_ *harness, form url.Values) {
					form.Set("code_verifier", "some-other-verifier")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "missing pkce verifier",
				mutate: func(_ *harness, form url.Values) {
					form.Del("code_verifier")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_request",
			},
			{
				name: "redirect_uri does not match the authorization request",
				mutate: func(_ *harness, form url.Values) {
					form.Set("redirect_uri", "http://127.0.0.1:9999/callback")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "code presented by a different client",
				mutate: func(h *harness, form url.Values) {
					form.Set("client_id", h.register(testRedirectURI))
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "unknown code",
				mutate: func(_ *harness, form url.Values) {
					form.Set("code", "not-a-real-code")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "missing grant_type",
				mutate: func(_ *harness, form url.Values) {
					form.Del("grant_type")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_request",
			},
			{
				name: "unsupported grant_type",
				mutate: func(_ *harness, form url.Values) {
					form.Set("grant_type", "client_credentials")
				},
				wantCode:  http.StatusBadRequest,
				wantError: "unsupported_grant_type",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				clientID, code, verifier := h.login(testEmail)
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"client_id":     {clientID},
					"redirect_uri":  {testRedirectURI},
					"code_verifier": {verifier},
				}
				tc.mutate(h, form)

				rec := h.token(form)
				if rec.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
				}
				if got := decodeJSON[errorBody](t, rec).Error; got != tc.wantError {
					t.Fatalf("error = %q, want %q", got, tc.wantError)
				}
			})
		}
	})

	t.Run("authorization code is single use", func(t *testing.T) {
		h := newHarness(t)
		clientID, code, verifier := h.login(testEmail)
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {verifier},
		}

		if rec := h.token(form); rec.Code != http.StatusOK {
			t.Fatalf("first exchange: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		rec := h.token(form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("replay: status = %d, want 400", rec.Code)
		}
		if got := decodeJSON[errorBody](t, rec).Error; got != "invalid_grant" {
			t.Fatalf("replay error = %q, want invalid_grant", got)
		}
	})

	t.Run("a failed exchange still burns the code", func(t *testing.T) {
		h := newHarness(t)
		clientID, code, verifier := h.login(testEmail)
		bad := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {"wrong"},
		}
		if rec := h.token(bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad exchange: status = %d, want 400", rec.Code)
		}

		bad.Set("code_verifier", verifier)
		if rec := h.token(bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("retry with the right verifier: status = %d, want 400 (code must be burned)", rec.Code)
		}
	})

	t.Run("expired authorization code is rejected", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		verifier := "expired-flow-verifier"
		raw := "expired-raw-code"

		if err := h.store.SaveAuthCode(context.Background(), mcpoauth.AuthCode{
			CodeHash:      mcpoauth.HashSecret(raw),
			ClientID:      clientID,
			UserID:        testUserID,
			RedirectURI:   testRedirectURI,
			CodeChallenge: pkceChallenge(verifier),
			ExpiresAt:     time.Now().Add(-time.Second),
			CreatedAt:     time.Now().Add(-10 * time.Minute),
		}); err != nil {
			t.Fatalf("seeding auth code: %v", err)
		}

		rec := h.token(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {raw},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		body := decodeJSON[errorBody](t, rec)
		if body.Error != "invalid_grant" || !strings.Contains(body.Description, "expired") {
			t.Fatalf("body = %+v, want invalid_grant/expired", body)
		}
	})
}

func TestRefreshTokenGrant(t *testing.T) {
	// exchange runs the full login and returns the first token pair.
	exchange := func(t *testing.T, h *harness) (clientID string, pair tokenSuccess) {
		t.Helper()
		clientID, code, verifier := h.login(testEmail)
		rec := h.token(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {testRedirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("initial exchange: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		return clientID, decodeJSON[tokenSuccess](t, rec)
	}

	t.Run("refresh rotates the token", func(t *testing.T) {
		h := newHarness(t)
		clientID, first := exchange(t, h)

		rec := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {first.RefreshToken},
			"client_id":     {clientID},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("refresh: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		second := decodeJSON[tokenSuccess](t, rec)
		if second.RefreshToken == first.RefreshToken {
			t.Fatal("refresh token was not rotated")
		}
		userID, err := h.p.ValidateAccessToken(second.AccessToken)
		if err != nil || userID != testUserID {
			t.Fatalf("new access token invalid: userID = %q, err = %v", userID, err)
		}

		// The freshly issued one still works. (Checked before the replay:
		// replaying a rotated token now revokes the whole family — see
		// TestRefreshTokenFamily.)
		if rec := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {second.RefreshToken},
			"client_id":     {clientID},
		}); rec.Code != http.StatusOK {
			t.Fatalf("second refresh: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		// The rotated-away token must be dead.
		replay := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {first.RefreshToken},
			"client_id":     {clientID},
		})
		if replay.Code != http.StatusBadRequest {
			t.Fatalf("replay of rotated token: status = %d, want 400", replay.Code)
		}
		if got := decodeJSON[errorBody](t, replay).Error; got != "invalid_grant" {
			t.Fatalf("replay error = %q, want invalid_grant", got)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		tests := []struct {
			name      string
			form      func(h *harness, clientID string, pair tokenSuccess) url.Values
			wantCode  int
			wantError string
		}{
			{
				name: "unknown refresh token",
				form: func(_ *harness, clientID string, _ tokenSuccess) url.Values {
					return url.Values{
						"grant_type":    {"refresh_token"},
						"refresh_token": {"not-a-real-token"},
						"client_id":     {clientID},
					}
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "missing refresh token",
				form: func(_ *harness, clientID string, _ tokenSuccess) url.Values {
					return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}}
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_request",
			},
			{
				name: "missing client_id",
				form: func(_ *harness, _ string, pair tokenSuccess) url.Values {
					return url.Values{
						"grant_type":    {"refresh_token"},
						"refresh_token": {pair.RefreshToken},
					}
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_request",
			},
			{
				name: "token belongs to another client",
				form: func(h *harness, _ string, pair tokenSuccess) url.Values {
					return url.Values{
						"grant_type":    {"refresh_token"},
						"refresh_token": {pair.RefreshToken},
						"client_id":     {h.register(testRedirectURI)},
					}
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
			{
				name: "expired refresh token",
				form: func(h *harness, clientID string, _ tokenSuccess) url.Values {
					raw := "expired-refresh-token"
					if err := h.store.SaveRefreshToken(context.Background(), mcpoauth.RefreshToken{
						TokenHash: mcpoauth.HashSecret(raw),
						ClientID:  clientID,
						UserID:    testUserID,
						ExpiresAt: time.Now().Add(-time.Hour),
						CreatedAt: time.Now().Add(-2 * time.Hour),
					}); err != nil {
						h.t.Fatalf("seeding refresh token: %v", err)
					}
					return url.Values{
						"grant_type":    {"refresh_token"},
						"refresh_token": {raw},
						"client_id":     {clientID},
					}
				},
				wantCode:  http.StatusBadRequest,
				wantError: "invalid_grant",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				clientID, pair := exchange(t, h)

				rec := h.token(tc.form(h, clientID, pair))
				if rec.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
				}
				if got := decodeJSON[errorBody](t, rec).Error; got != tc.wantError {
					t.Fatalf("error = %q, want %q", got, tc.wantError)
				}
			})
		}
	})

	t.Run("revoking a user kills their refresh tokens", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := exchange(t, h)
		if err := h.store.RevokeRefreshTokensForUser(context.Background(), testUserID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		rec := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {pair.RefreshToken},
			"client_id":     {clientID},
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGoogleCallback(t *testing.T) {
	t.Run("unknown email is refused with 403 and creates nothing", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		_, state := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRedirectURI},
			"code_challenge":        {pkceChallenge("v")},
			"code_challenge_method": {"S256"},
		})
		h.google.grant("gc", "stranger@example.com")

		rec := h.callback(state, "gc")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not linked") {
			t.Fatalf("body does not explain the failure: %s", rec.Body.String())
		}
		if _, ok, _ := h.store.FindUserIDByEmail(context.Background(), "stranger@example.com"); ok {
			t.Fatal("a user was created for an unknown email")
		}
	})

	t.Run("state is single use", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		_, state := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRedirectURI},
			"code_challenge":        {pkceChallenge("v")},
			"code_challenge_method": {"S256"},
		})
		h.google.grant("gc", testEmail)

		if rec := h.callback(state, "gc"); rec.Code != http.StatusFound {
			t.Fatalf("first callback: status = %d", rec.Code)
		}
		if rec := h.callback(state, "gc"); rec.Code != http.StatusBadRequest {
			t.Fatalf("replayed callback: status = %d, want 400", rec.Code)
		}
	})

	t.Run("failure modes", func(t *testing.T) {
		tests := []struct {
			name     string
			setup    func(h *harness)
			state    func(valid string) string
			wantCode int
			// wantRedirect means the error is bounced to the client instead.
			wantRedirect bool
		}{
			{
				name:     "unknown state",
				state:    func(string) string { return "totally-made-up-state" },
				wantCode: http.StatusBadRequest,
			},
			{
				name:     "empty state",
				state:    func(string) string { return "" },
				wantCode: http.StatusBadRequest,
			},
			{
				name:         "google token exchange fails",
				setup:        func(h *harness) { h.google.tokenStatus = http.StatusBadRequest },
				wantCode:     http.StatusFound,
				wantRedirect: true,
			},
			{
				name:         "id token audience is another client",
				setup:        func(h *harness) { h.google.audience = "someone-else.apps.googleusercontent.com" },
				wantCode:     http.StatusFound,
				wantRedirect: true,
			},
			{
				name:         "id token issuer is wrong",
				setup:        func(h *harness) { h.google.issuer = "https://evil.example.com" },
				wantCode:     http.StatusFound,
				wantRedirect: true,
			},
			{
				name:         "id token is expired",
				setup:        func(h *harness) { h.google.expiresIn = -time.Hour },
				wantCode:     http.StatusFound,
				wantRedirect: true,
			},
			{
				name:         "email is not verified",
				setup:        func(h *harness) { h.google.emailVerified = false },
				wantCode:     http.StatusFound,
				wantRedirect: true,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				clientID := h.register(testRedirectURI)
				_, state := h.authorize(url.Values{
					"response_type":         {"code"},
					"client_id":             {clientID},
					"redirect_uri":          {testRedirectURI},
					"code_challenge":        {pkceChallenge("v")},
					"code_challenge_method": {"S256"},
					"state":                 {"cs"},
				})
				h.google.grant("gc", testEmail)
				if tc.setup != nil {
					tc.setup(h)
				}
				if tc.state != nil {
					state = tc.state(state)
				}

				rec := h.callback(state, "gc")
				if rec.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
				}
				if !tc.wantRedirect {
					return
				}
				loc, err := url.Parse(rec.Header().Get("Location"))
				if err != nil {
					t.Fatalf("bad Location: %v", err)
				}
				if !strings.HasPrefix(loc.String(), testRedirectURI) {
					t.Fatalf("redirected to %q, want the registered redirect URI", loc.String())
				}
				if loc.Query().Get("error") == "" {
					t.Fatalf("no error param in %q", loc.String())
				}
				if loc.Query().Get("code") != "" {
					t.Fatalf("an authorization code leaked on a failed login: %q", loc.String())
				}
			})
		}
	})

	t.Run("google signing keys are fetched once and cached", func(t *testing.T) {
		h := newHarness(t)
		for i := 0; i < 3; i++ {
			h.login(testEmail)
		}
		if h.google.jwksCalls != 1 {
			t.Fatalf("jwks fetched %d times, want 1 (keys must be cached)", h.google.jwksCalls)
		}
	})

	t.Run("user denial is bounced back to the client", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		_, state := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRedirectURI},
			"code_challenge":        {pkceChallenge("v")},
			"code_challenge_method": {"S256"},
			"state":                 {"cs"},
		})

		q := url.Values{"state": {state}, "error": {"access_denied"}}
		req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
		req.AddCookie(h.binder) // the same browser comes back
		rec := httptest.NewRecorder()
		h.p.GoogleCallback()(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Query().Get("error") != "access_denied" {
			t.Fatalf("error = %q, want access_denied", loc.Query().Get("error"))
		}
		if loc.Query().Get("state") != "cs" {
			t.Fatalf("state = %q, want cs", loc.Query().Get("state"))
		}
	})
}
