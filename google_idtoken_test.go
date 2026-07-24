package mcpoauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpoauth "github.com/obad2015/mcp-oauth"
)

// rogueGoogle is a hostile upstream: its JWKS advertises the honest key, but
// its token endpoint signs the ID token however the test tells it to. It exists
// to prove the ID-token signature is really verified — the single highest-stakes
// check in the package, since a forged ID token is a login as any user.
type rogueGoogle struct {
	srv    *httptest.Server
	honest *rsa.PrivateKey
	rogue  *rsa.PrivateKey

	mu      sync.Mutex
	signKey any               // *rsa.PrivateKey, []byte (HMAC) or the none sentinel
	method  jwt.SigningMethod // how to sign
	kid     any               // string, or nil to omit the header entirely
}

func newRogueGoogle(t *testing.T) *rogueGoogle {
	t.Helper()
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rogue key: %v", err)
	}
	g := &rogueGoogle{honest: googleSigningKey(t), rogue: rogue}
	g.set(googleSigningKey(t), jwt.SigningMethodRS256, "test-kid-1")

	mux := http.NewServeMux()
	mux.HandleFunc("/certs", g.handleCerts)
	mux.HandleFunc("/token", g.handleToken)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *rogueGoogle) set(key any, method jwt.SigningMethod, kid any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.signKey, g.method, g.kid = key, method, kid
}

// handleCerts always publishes the honest public key under the honest kid.
func (g *rogueGoogle) handleCerts(w http.ResponseWriter, _ *http.Request) {
	pub := g.honest.Public().(*rsa.PublicKey)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kid": "test-kid-1", "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (g *rogueGoogle) handleToken(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	key, method, kid := g.signKey, g.method, g.kid
	g.mu.Unlock()

	now := time.Now()
	tok := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": testGoogleCID,
		"sub": "attacker", "email": testEmail, "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if kid != nil {
		tok.Header["kid"] = kid
	} else {
		delete(tok.Header, "kid")
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed})
}

func TestGoogleIDTokenSignature(t *testing.T) {
	// Built once: RSA keygen is expensive and the rogue key is reused.
	shared := newRogueGoogle(t)

	tests := []struct {
		name string
		// arrange configures how the rogue upstream signs the ID token.
		arrange func(g *rogueGoogle)
		// wantCode reports whether a login must come out of the callback.
		wantAccepted bool
	}{
		{
			name:    "id_token signed with a rogue RSA key",
			arrange: func(g *rogueGoogle) { g.set(g.rogue, jwt.SigningMethodRS256, "test-kid-1") },
		},
		{
			name: "alg none",
			arrange: func(g *rogueGoogle) {
				g.set(jwt.UnsafeAllowNoneSignatureType, jwt.SigningMethodNone, "test-kid-1")
			},
		},
		{
			name: "HS256 signed with the JWKS RSA modulus (alg confusion)",
			arrange: func(g *rogueGoogle) {
				g.set(g.honest.Public().(*rsa.PublicKey).N.Bytes(), jwt.SigningMethodHS256, "test-kid-1")
			},
		},
		{
			name:    "unknown kid",
			arrange: func(g *rogueGoogle) { g.set(g.honest, jwt.SigningMethodRS256, "some-other-kid") },
		},
		{
			name:    "no kid header",
			arrange: func(g *rogueGoogle) { g.set(g.honest, jwt.SigningMethodRS256, nil) },
		},
		{
			name:    "empty kid header",
			arrange: func(g *rogueGoogle) { g.set(g.honest, jwt.SigningMethodRS256, "") },
		},
		{
			name:         "honestly signed id_token is accepted (control)",
			arrange:      func(g *rogueGoogle) { g.set(g.honest, jwt.SigningMethodRS256, "test-kid-1") },
			wantAccepted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.arrange(shared)

			h := newHarness(t, func(c *mcpoauth.Config) {
				c.GoogleTokenURL = shared.srv.URL + "/token"
				c.GoogleJWKSURL = shared.srv.URL + "/certs"
			})
			clientID := h.register(testRedirectURI)
			_, state := h.authorize(authorizeParams(clientID, testRedirectURI))
			if state == "" {
				t.Fatal("authorize did not reach the google hop")
			}

			rec := h.callback(state, "any-upstream-code")
			loc, _ := url.Parse(rec.Header().Get("Location"))
			gotCode := loc != nil && loc.Query().Get("code") != ""

			if gotCode != tc.wantAccepted {
				t.Fatalf("authorization code issued = %v, want %v (status %d, location %q, body %s)",
					gotCode, tc.wantAccepted, rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			if tc.wantAccepted {
				return
			}
			// A rejected upstream login must also leave nothing behind.
			if _, codes, _, _ := h.store.Len(); codes != 0 {
				t.Fatalf("%d authorization codes minted for a forged id_token", codes)
			}
		})
	}
}

func TestGoogleJWKSStaleFallback(t *testing.T) {
	tests := []struct {
		name string
		// advance is how far past the cached document's expiry the second
		// login happens, with the JWKS endpoint now failing.
		advance time.Duration
		wantOK  bool
	}{
		{"inside the cache lifetime", 30 * time.Minute, true},
		{"expired but inside the stale grace period", 2 * time.Hour, true},
		{"just inside the grace bound", time.Hour + mcpoauth.MaxStaleJWKSForTest - time.Minute, true},
		{"past the stale bound: fail closed", time.Hour + mcpoauth.MaxStaleJWKSForTest + time.Minute, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			// Warm the cache with a real login (the fake advertises max-age=3600).
			h.login(testEmail)

			// The JWKS endpoint now fails, and time moves on. The upstream
			// still issues ID tokens that are valid at that later instant, so
			// the only thing under test is the key cache.
			h.google.certsStatus = http.StatusInternalServerError
			h.google.expiresIn = tc.advance + time.Hour
			base := time.Now()
			h.p.SetNowForTest(func() time.Time { return base.Add(tc.advance) })

			clientID := h.register(testRedirectURI)
			_, state := h.authorize(authorizeParams(clientID, testRedirectURI))
			h.google.grant("gc-stale", testEmail)
			rec := h.callback(state, "gc-stale")

			loc, _ := url.Parse(rec.Header().Get("Location"))
			gotCode := loc != nil && loc.Query().Get("code") != ""
			if gotCode != tc.wantOK {
				t.Fatalf("login succeeded = %v, want %v (status %d, body %s)",
					gotCode, tc.wantOK, rec.Code, rec.Body.String())
			}
		})
	}
}
