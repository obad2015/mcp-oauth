package mcpoauth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// TestInsecureDevModeGating: InsecureDevMode strips __Host- and Secure from the
// browser-binding cookie, so a config that pairs it with anything that looks
// like a deployment is a misconfiguration, not a preference.
func TestInsecureDevModeGating(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		dev     bool
		wantErr bool
	}{
		{"https issuer without dev mode", "https://finance.example.com", false, false},
		{"https issuer WITH dev mode", "https://finance.example.com", true, true},
		{"http non-loopback issuer with dev mode", "http://finance.example.com", true, true},
		{"http loopback-lookalike host with dev mode", "http://127.0.0.1.evil.com", true, true},
		{"https loopback with dev mode", "https://127.0.0.1:8080", true, true},
		{"http 127.0.0.1 with dev mode", "http://127.0.0.1:8080", true, false},
		{"http localhost with dev mode", "http://localhost:8080", true, false},
		{"http ipv6 loopback with dev mode", "http://[::1]:8080", true, false},
		{"uppercase scheme and host with dev mode", "HTTP://LocalHost:8080", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mcpoauth.New(mcpoauth.Config{
				Issuer: tc.issuer, ResourceURL: tc.issuer + "/api/mcp",
				GoogleClientID: testGoogleCID, GoogleClientSecret: "secret",
				GoogleRedirectURL: tc.issuer + "/cb",
				AuthorizeURL:      tc.issuer + "/authorize",
				TokenURL:          tc.issuer + "/token",
				RegisterURL:       tc.issuer + "/register",
				JWTSecret:         testSecret,
				InsecureDevMode:   tc.dev,
			}, newStore())
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestClientRegistrationLifetime: /register is unauthenticated, so a
// registration is a lease, not a permanent row.
func TestClientRegistrationLifetime(t *testing.T) {
	t.Run("a client that never logs in is purged", func(t *testing.T) {
		h := newHarness(t)
		for i := 0; i < 200; i++ {
			h.register(testRedirectURI)
		}
		if clients, _, _, _ := h.store.Len(); clients != 200 {
			t.Fatalf("clients = %d, want 200", clients)
		}

		// Nothing is purged while the lease is alive...
		h.advance(23 * time.Hour)
		if err := h.p.PurgeExpired(context.Background()); err != nil {
			t.Fatalf("PurgeExpired(): %v", err)
		}
		if clients, _, _, _ := h.store.Len(); clients != 200 {
			t.Fatalf("clients purged too early: %d, want 200", clients)
		}

		// ...and all of it goes once UnusedClientTTL has passed.
		h.advance(2 * time.Hour)
		if err := h.p.PurgeExpired(context.Background()); err != nil {
			t.Fatalf("PurgeExpired(): %v", err)
		}
		if clients, _, _, _ := h.store.Len(); clients != 0 {
			t.Fatalf("clients = %d after UnusedClientTTL, want 0", clients)
		}
	})

	t.Run("completing a login extends the registration", func(t *testing.T) {
		h := newHarness(t)
		clientID, _, _ := h.login(testEmail)

		c, ok, err := h.store.GetClient(context.Background(), clientID)
		if err != nil || !ok {
			t.Fatalf("GetClient: ok=%v err=%v", ok, err)
		}
		if want := h.clock.Add(89 * 24 * time.Hour); c.ExpiresAt.Before(want) {
			t.Fatalf("a used client expires at %v, want at least %v", c.ExpiresAt, want)
		}

		// A used client outlives the unused lease.
		h.advance(48 * time.Hour)
		if err := h.p.PurgeExpired(context.Background()); err != nil {
			t.Fatalf("PurgeExpired(): %v", err)
		}
		if _, ok, _ := h.store.GetClient(context.Background(), clientID); !ok {
			t.Fatal("a client that completed a login was purged after 48h")
		}
	})

	t.Run("an expired registration cannot authorize", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		h.advance(25 * time.Hour)
		if err := h.p.PurgeExpired(context.Background()); err != nil {
			t.Fatalf("PurgeExpired(): %v", err)
		}
		rec := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("authorize with a purged client: status = %d, want 400", rec.Code)
		}
	})
}

// TestConcurrentFlowsInOneBrowser: a browser only keeps one cookie per name, so
// starting a second authorization used to overwrite the first tab's binder and
// silently break it. The cookie now carries a short list of binders.
func TestConcurrentFlowsInOneBrowser(t *testing.T) {
	t.Run("both tabs can still be approved", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)

		tab1 := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		nonce1 := consentNonce(t, tab1.Body.String())

		tab2 := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		nonce2 := consentNonce(t, tab2.Body.String())

		// The browser now sends whatever the last Set-Cookie left it holding.
		current := h.binder
		if rec := h.approve(nonce1, current); rec.Code != http.StatusFound {
			t.Fatalf("approving the FIRST tab: status = %d, body = %s (the second tab broke it)",
				rec.Code, rec.Body.String())
		}
		if rec := h.approve(nonce2, current); rec.Code != http.StatusFound {
			t.Fatalf("approving the second tab: status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("both tabs complete the whole flow", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)

		g1 := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		n1 := consentNonce(t, g1.Body.String())
		g2 := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		n2 := consentNonce(t, g2.Body.String())

		state := func(nonce string) string {
			t.Helper()
			rec := h.approve(nonce, h.binder)
			if rec.Code != http.StatusFound {
				t.Fatalf("approve: status = %d, body = %s", rec.Code, rec.Body.String())
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("bad Location: %v", err)
			}
			return loc.Query().Get("state")
		}
		s1, s2 := state(n1), state(n2)

		h.google.grant("code-1", testEmail)
		h.google.grant("code-2", testEmail)
		for i, tc := range []struct{ state, code string }{{s1, "code-1"}, {s2, "code-2"}} {
			rec := h.callbackWithCookie(tc.state, tc.code, h.binder)
			if rec.Code != http.StatusFound {
				t.Fatalf("callback %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
			}
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if loc.Query().Get("code") == "" {
				t.Fatalf("callback %d delivered no authorization code", i)
			}
		}
	})

	// The deliberate consequence of accepting a set: within ONE browser, the
	// cookie that a later flow left behind still satisfies an earlier flow.
	// That is the same-browser proof the binder exists to give — the nonce
	// still decides which pending record proceeds, and no other browser can
	// ever hold any of these values.
	t.Run("a later flow's cookie satisfies an earlier flow in the same browser", func(t *testing.T) {
		h := newHarness(t)
		mine := h.authorizeGET(authorizeParams(h.register(testRedirectURI), testRedirectURI))
		mineNonce := consentNonce(t, mine.Body.String())

		// A second flow, different client, same browser.
		const evil = "https://evil.example.com/collect"
		h.authorizeGET(authorizeParams(h.register(evil), evil))

		rec := h.approve(mineNonce, h.binder)
		if rec.Code != http.StatusFound {
			t.Fatalf("the first flow was broken by the second: status = %d", rec.Code)
		}
		// The nonce, not the cookie, is what picked the flow: this went to
		// Google for the first request, and the second is untouched.
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://accounts.google.com/") {
			t.Fatalf("approval went to %q", loc)
		}
	})

	t.Run("the binder list is bounded and still rejects a foreign browser", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)

		// The FIRST flow's nonce, kept while nine more flows push binders in.
		first := h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		oldest := consentNonce(t, first.Body.String())
		for i := 0; i < 9; i++ {
			h.authorizeGET(authorizeParams(clientID, testRedirectURI))
		}
		if rec := h.approve(oldest, h.binder); rec.Code != http.StatusBadRequest {
			t.Fatalf("a binder evicted from the list was still accepted: status = %d", rec.Code)
		}

		// And an unrelated browser is refused however long the list is.
		h2 := newHarness(t)
		c2 := h2.register(testRedirectURI)
		get := h2.authorizeGET(authorizeParams(c2, testRedirectURI))
		rec := h2.approve(consentNonce(t, get.Body.String()),
			&http.Cookie{Name: mcpoauth.BinderCookieName, Value: h.binder.Value})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("another browser's binder list was accepted: status = %d", rec.Code)
		}
	})
}
