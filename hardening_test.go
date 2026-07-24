package mcpoauth_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpoauth "github.com/obad2015/mcp-oauth"
)

func TestJWTSecretStrength(t *testing.T) {
	base := func() mcpoauth.Config {
		return mcpoauth.Config{
			Issuer: testIssuer, ResourceURL: testResourceURL,
			GoogleClientID: testGoogleCID, GoogleClientSecret: "secret",
			GoogleRedirectURL: testIssuer + "/cb",
			AuthorizeURL:      testIssuer + "/authorize",
			TokenURL:          testIssuer + "/token",
			RegisterURL:       testIssuer + "/register",
			JWTSecret:         testSecret,
		}
	}

	t.Run("New rejects a weak secret", func(t *testing.T) {
		tests := []struct {
			name    string
			secret  []byte
			wantErr bool
		}{
			{"nil", nil, true},
			{"empty", []byte{}, true},
			{"one byte", []byte("a"), true},
			{"31 bytes", bytes.Repeat([]byte("x"), 31), true},
			{"exactly 32 bytes", bytes.Repeat([]byte("x"), 32), false},
			{"64 bytes", bytes.Repeat([]byte("x"), 64), false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				cfg := base()
				cfg.JWTSecret = tc.secret
				_, err := mcpoauth.New(cfg, newStore())
				if (err != nil) != tc.wantErr {
					t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("the signing key is derived, never the configured secret", func(t *testing.T) {
		derived := mcpoauth.DeriveSigningKeyForTest(testSecret)
		if bytes.Equal(derived, testSecret) {
			t.Fatal("the raw secret is used as the signing key")
		}
		if len(derived) != 32 {
			t.Fatalf("derived key is %d bytes, want 32", len(derived))
		}
		if !bytes.Equal(derived, mcpoauth.DeriveSigningKeyForTest(testSecret)) {
			t.Fatal("derivation is not deterministic")
		}
		other := mcpoauth.DeriveSigningKeyForTest(append([]byte("x"), testSecret...))
		if bytes.Equal(derived, other) {
			t.Fatal("two different secrets derive the same key")
		}
	})

	t.Run("a token signed with the raw secret is refused in both directions", func(t *testing.T) {
		h := newHarness(t)

		// The app's own session JWT, signed with the very same configured
		// secret and otherwise perfectly shaped, must not open the MCP endpoint.
		session := mintToken(t, testSecret, jwt.SigningMethodHS256, validClaims())
		if _, err := h.p.ValidateAccessToken(session); err == nil {
			t.Fatal("a token signed with the raw configured secret was accepted")
		}

		// And an MCP access token is not verifiable with the raw secret, so an
		// app whose middleware uses cfg.JWTSecret cannot accept it either.
		clientID, code, verifier := h.login(testEmail)
		rec := h.token(url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {clientID}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
		})
		access := decodeJSON[tokenSuccess](t, rec).AccessToken
		_, err := jwt.Parse(access, func(*jwt.Token) (any, error) { return testSecret, nil },
			jwt.WithValidMethods([]string{"HS256"}))
		if err == nil {
			t.Fatal("an MCP access token verified against the raw configured secret")
		}
	})
}

func TestInputValidation(t *testing.T) {
	t.Run("code_challenge must satisfy RFC 7636", func(t *testing.T) {
		tests := []struct {
			name      string
			challenge string
			wantErr   bool
		}{
			{"S256 challenge", pkceChallenge("v"), false},
			{"minimum length", strings.Repeat("a", 43), false},
			{"maximum length", strings.Repeat("a", 128), false},
			{"full unreserved charset", strings.Repeat("aA0-._~", 7), false},
			{"too short", strings.Repeat("a", 42), true},
			{"too long", strings.Repeat("a", 129), true},
			{"empty", "", true},
			{"illegal plus", strings.Repeat("a", 42) + "+", true},
			{"illegal slash", strings.Repeat("a", 42) + "/", true},
			{"base64 padding", strings.Repeat("a", 42) + "=", true},
			{"space", strings.Repeat("a", 42) + " ", true},
			{"nul byte", strings.Repeat("a", 42) + "\x00", true},
			{"non-ascii", strings.Repeat("a", 42) + "é", true},
			{"megabyte of junk", strings.Repeat("B", 100_000), true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if err := mcpoauth.ValidateCodeChallengeForTest(tc.challenge); (err != nil) != tc.wantErr {
					t.Fatalf("validateCodeChallenge() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("authorize rejects oversized and malformed input", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(p url.Values)
		}{
			{"unbounded state", func(p url.Values) { p.Set("state", strings.Repeat("A", 200_000)) }},
			{"state just over the cap", func(p url.Values) { p.Set("state", strings.Repeat("A", 513)) }},
			{"unbounded code_challenge", func(p url.Values) { p.Set("code_challenge", strings.Repeat("B", 100_000)) }},
			{"short code_challenge", func(p url.Values) { p.Set("code_challenge", "too-short") }},
			{"code_challenge with illegal characters", func(p url.Values) {
				p.Set("code_challenge", strings.Repeat("a", 42)+"/")
			}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				params := authorizeParams(h.register(testRedirectURI), testRedirectURI)
				tc.mutate(params)

				rec := h.authorizeGET(params)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
				}
				if _, _, pending, _ := h.store.Len(); pending != 0 {
					t.Fatalf("%d pending records written for a rejected request", pending)
				}
			})
		}

		t.Run("a state at exactly the cap is accepted", func(t *testing.T) {
			h := newHarness(t)
			params := authorizeParams(h.register(testRedirectURI), testRedirectURI)
			params.Set("state", strings.Repeat("A", 512))
			if rec := h.authorizeGET(params); rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
		})
	})

	t.Run("registration rejects oversized payloads", func(t *testing.T) {
		tests := []struct {
			name string
			body string
		}{
			{"client_name over the cap", `{"redirect_uris":["https://a.example.com/cb"],"client_name":"` +
				strings.Repeat("n", 201) + `"}`},
			{"a redirect_uri over the cap", `{"redirect_uris":["https://a.example.com/` +
				strings.Repeat("p", 2100) + `"]}`},
			{"body over the read limit", `{"client_name":"` + strings.Repeat("n", 20_000) +
				`","redirect_uris":["https://a.example.com/cb"]}`},
			{"too many redirect_uris", `{"redirect_uris":["https://a/1","https://a/2","https://a/3",` +
				`"https://a/4","https://a/5","https://a/6","https://a/7","https://a/8","https://a/9",` +
				`"https://a/10","https://a/11"]}`},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				h := newHarness(t)
				rec := newRec()
				h.p.Register()(rec, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(tc.body)))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
				}
				if clients, _, _, _ := h.store.Len(); clients != 0 {
					t.Fatalf("%d clients persisted from a rejected registration", clients)
				}
			})
		}
	})
}

func TestAllowedRedirectHosts(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		uri     string
		wantOK  bool
	}{
		{"empty allowlist keeps the old behaviour", nil, "https://anything.example.com/cb", true},
		{"listed host", []string{"app.example.com"}, "https://app.example.com/cb", true},
		{"listed host, different path", []string{"app.example.com"}, "https://app.example.com/other?x=1", true},
		{"case-insensitive host match", []string{"App.Example.COM"}, "https://app.example.com/cb", true},
		{"unlisted host", []string{"app.example.com"}, "https://evil.example.com/cb", false},
		{"subdomain of a listed host is not implied", []string{"example.com"}, "https://evil.example.com/cb", false},
		{"loopback stays allowed", []string{"app.example.com"}, "http://127.0.0.1:51234/callback", true},
		{"localhost stays allowed", []string{"app.example.com"}, "http://localhost:8765/cb", true},
		{"ipv6 loopback stays allowed", []string{"app.example.com"}, "http://[::1]:9/cb", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *mcpoauth.Config) { c.AllowedRedirectHosts = tc.allowed })
			body, _ := json.Marshal(map[string]any{
				"redirect_uris": []string{tc.uri},
				"client_name":   "Test MCP Client",
			})
			rec := newRec()
			h.p.Register()(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))

			gotOK := rec.Code == http.StatusCreated
			if gotOK != tc.wantOK {
				t.Fatalf("register(%q) status = %d, wantOK %v (body %s)",
					tc.uri, rec.Code, tc.wantOK, rec.Body.String())
			}
		})
	}

	t.Run("tightening the allowlist locks out an already registered client", func(t *testing.T) {
		// Registration happened while anything was allowed...
		h := newHarness(t)
		clientID := h.register("https://legacy.example.com/cb")
		if rec := h.authorizeGET(authorizeParams(clientID, "https://legacy.example.com/cb")); rec.Code != http.StatusOK {
			t.Fatalf("baseline authorize: status = %d", rec.Code)
		}

		// ...and the same stored client must be refused once it is not.
		tight := newHarness(t, func(c *mcpoauth.Config) {
			c.AllowedRedirectHosts = []string{"app.example.com"}
		})
		if err := tight.store.SaveClient(context.Background(), mcpoauth.Client{
			ClientID:     "legacy-client",
			RedirectURIs: []string{"https://legacy.example.com/cb"},
			ClientName:   "Legacy",
			CreatedAt:    time.Now(),
		}); err != nil {
			t.Fatalf("seeding client: %v", err)
		}
		rec := tight.authorizeGET(authorizeParams("legacy-client", "https://legacy.example.com/cb"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
	})
}

func TestMethodHandling(t *testing.T) {
	handlers := func(h *harness) map[string]http.HandlerFunc {
		return map[string]http.HandlerFunc{
			"authorization server metadata": h.p.AuthorizationServerMetadata(),
			"protected resource metadata":   h.p.ProtectedResourceMetadata(),
		}
	}

	t.Run("metadata documents reject write methods", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			for name, hf := range handlers(newHarness(t)) {
				t.Run(method+" "+name, func(t *testing.T) {
					rec := newRec()
					hf(rec, httptest.NewRequest(method, "/.well-known/x", nil))
					if rec.Code != http.StatusMethodNotAllowed {
						t.Fatalf("status = %d, want 405", rec.Code)
					}
				})
			}
		}
	})

	t.Run("metadata documents still answer GET and HEAD", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for name, hf := range handlers(newHarness(t)) {
				t.Run(method+" "+name, func(t *testing.T) {
					rec := newRec()
					hf(rec, httptest.NewRequest(method, "/.well-known/x", nil))
					if rec.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200", rec.Code)
					}
				})
			}
		}
	})

	t.Run("authorize rejects everything but GET and POST", func(t *testing.T) {
		for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(method, func(t *testing.T) {
				h := newHarness(t)
				params := authorizeParams(h.register(testRedirectURI), testRedirectURI)
				rec := newRec()
				h.p.Authorize()(rec, httptest.NewRequest(method, "/authorize?"+params.Encode(), nil))

				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status = %d, want 405", rec.Code)
				}
				// The point of rejecting HEAD: it must not mint state.
				if _, _, pending, _ := h.store.Len(); pending != 0 {
					t.Fatalf("%s /authorize persisted %d pending records", method, pending)
				}
				if binderCookie(rec) != nil {
					t.Fatalf("%s /authorize handed out a binder cookie", method)
				}
			})
		}
	})

	t.Run("the google callback is GET only", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodHead, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				h := newHarness(t)
				rec := newRec()
				h.p.GoogleCallback()(rec, httptest.NewRequest(method, "/callback?state=x&code=y", nil))
				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status = %d, want 405", rec.Code)
				}
			})
		}
	})
}

// TestConcurrentCodeDoubleSpend proves the single-use guarantee holds under
// real concurrency, not just sequentially.
func TestConcurrentDoubleSpend(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the form that 32 goroutines will race with.
		setup func(t *testing.T, h *harness) url.Values
	}{
		{
			name: "authorization code",
			setup: func(t *testing.T, h *harness) url.Values {
				clientID, code, verifier := h.login(testEmail)
				return url.Values{
					"grant_type": {"authorization_code"}, "code": {code},
					"client_id": {clientID}, "redirect_uri": {testRedirectURI},
					"code_verifier": {verifier},
				}
			},
		},
		{
			name: "refresh token",
			setup: func(t *testing.T, h *harness) url.Values {
				clientID, pair := firstPair(t, h)
				return url.Values{
					"grant_type": {"refresh_token"}, "refresh_token": {pair.RefreshToken},
					"client_id": {clientID},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			form := tc.setup(t, h)

			const n = 32
			var wg sync.WaitGroup
			results := make([]int, n)
			start := make(chan struct{})
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					results[i] = h.token(form).Code
				}(i)
			}
			close(start)
			wg.Wait()

			ok := 0
			for _, c := range results {
				if c == http.StatusOK {
					ok++
				}
			}
			if ok != 1 {
				t.Fatalf("%d of %d concurrent exchanges succeeded, want exactly 1", ok, n)
			}
		})
	}
}

func TestPurgeExpired(t *testing.T) {
	t.Run("expired records are dropped, live ones survive", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		now := time.Now()

		// One expired and one live record of each kind.
		for _, tc := range []struct {
			name      string
			expiresAt time.Time
		}{{"expired", now.Add(-time.Hour)}, {"live", now.Add(time.Hour)}} {
			ctx := context.Background()
			if err := h.store.SaveAuthCode(ctx, mcpoauth.AuthCode{
				CodeHash: "code-" + tc.name, ClientID: clientID, UserID: testUserID,
				RedirectURI: testRedirectURI, ExpiresAt: tc.expiresAt, CreatedAt: now,
			}); err != nil {
				t.Fatalf("seeding code: %v", err)
			}
			if err := h.store.SavePendingAuth(ctx, mcpoauth.PendingAuth{
				StateHash: "pending-" + tc.name, ClientID: clientID,
				RedirectURI: testRedirectURI, ExpiresAt: tc.expiresAt, CreatedAt: now,
			}); err != nil {
				t.Fatalf("seeding pending: %v", err)
			}
			if err := h.store.SaveRefreshToken(ctx, mcpoauth.RefreshToken{
				TokenHash: "refresh-" + tc.name, ClientID: clientID, UserID: testUserID,
				FamilyID: "f", FamilyCreatedAt: now, ExpiresAt: tc.expiresAt, CreatedAt: now,
			}); err != nil {
				t.Fatalf("seeding refresh: %v", err)
			}
		}

		if err := h.p.PurgeExpired(context.Background()); err != nil {
			t.Fatalf("PurgeExpired() error: %v", err)
		}
		clients, codes, pending, refresh := h.store.Len()
		if clients != 1 || codes != 1 || pending != 1 || refresh != 1 {
			t.Fatalf("after purge: clients=%d codes=%d pending=%d refresh=%d, want 1 of each",
				clients, codes, pending, refresh)
		}
	})

	t.Run("the provider purges opportunistically while serving authorize", func(t *testing.T) {
		h := newHarness(t, func(c *mcpoauth.Config) { c.PurgeInterval = time.Nanosecond })
		clientID := h.register(testRedirectURI)
		if err := h.store.SavePendingAuth(context.Background(), mcpoauth.PendingAuth{
			StateHash: "stale", ClientID: clientID, RedirectURI: testRedirectURI,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour),
		}); err != nil {
			t.Fatalf("seeding pending: %v", err)
		}

		h.authorizeGET(authorizeParams(clientID, testRedirectURI))

		// The stale row is gone; only the one this request just wrote remains.
		if _, _, pending, _ := h.store.Len(); pending != 1 {
			t.Fatalf("pending records = %d, want 1 (the stale one should have been purged)", pending)
		}
	})

	t.Run("purging is throttled between requests", func(t *testing.T) {
		h := newHarness(t) // default 5m interval
		clientID := h.register(testRedirectURI)
		h.authorizeGET(authorizeParams(clientID, testRedirectURI)) // claims the purge slot

		if err := h.store.SavePendingAuth(context.Background(), mcpoauth.PendingAuth{
			StateHash: "stale", ClientID: clientID, RedirectURI: testRedirectURI,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour),
		}); err != nil {
			t.Fatalf("seeding pending: %v", err)
		}
		h.authorizeGET(authorizeParams(clientID, testRedirectURI))

		if _, _, pending, _ := h.store.Len(); pending != 3 {
			t.Fatalf("pending records = %d, want 3 (no second purge within the interval)", pending)
		}
	})
}

// TestSigningKeyDerivation pins the derivation to the HKDF-Expand construction
// (RFC 5869 §2.3). A refactor that silently changed it would invalidate every
// access token in the field, so the expected value is recomputed here from the
// spec rather than trusting the implementation.
func TestSigningKeyDerivation(t *testing.T) {
	const info = "mcpoauth/v1/access-token"

	tests := []struct {
		name   string
		secret []byte
	}{
		{"repeated bytes", bytes.Repeat([]byte{0x0b}, 32)},
		{"the test secret", testSecret},
		{"64 bytes", bytes.Repeat([]byte("secret"), 11)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// T(1) = HMAC-SHA256(PRK, info || 0x01); 32 bytes need no T(2).
			mac := hmac.New(sha256.New, tc.secret)
			mac.Write([]byte(info))
			mac.Write([]byte{0x01})
			want := mac.Sum(nil)

			got := mcpoauth.DeriveSigningKeyForTest(tc.secret)
			if !bytes.Equal(got, want) {
				t.Fatalf("derived key = %s, want %s",
					base64.RawURLEncoding.EncodeToString(got),
					base64.RawURLEncoding.EncodeToString(want))
			}
		})
	}
}
