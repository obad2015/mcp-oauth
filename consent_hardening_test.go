package mcpoauth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// TestConsentPageIsNotReadableCrossOrigin: the consent page carries the
// single-use nonce, so an attacker page must not be able to fetch and scrape it.
func TestConsentPageIsNotReadableCrossOrigin(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(testRedirectURI)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+authorizeParams(clientID, testRedirectURI).Encode(), nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := newRec()
	h.p.Authorize()(rec, req)

	checks := []struct {
		name string
		ok   bool
	}{
		{"no Access-Control-Allow-Origin", rec.Header().Get("Access-Control-Allow-Origin") == ""},
		{"frame-ancestors 'none' in the CSP", strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")},
		{"X-Frame-Options: DENY", rec.Header().Get("X-Frame-Options") == "DENY"},
		{"Cache-Control: no-store", rec.Header().Get("Cache-Control") == "no-store"},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("consent page: %s failed", c.name)
		}
	}
}

// TestConsentNonceEntropy: the nonce is the only thing standing between a
// pending record and the Google hop.
func TestConsentNonceEntropy(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(testRedirectURI)

	seen := make(map[string]bool, 200)
	shortest := 1 << 30
	for i := 0; i < 200; i++ {
		n := consentNonce(t, h.authorizeGET(authorizeParams(clientID, testRedirectURI)).Body.String())
		if seen[n] {
			t.Fatalf("nonce %q repeated after %d flows", n, i)
		}
		seen[n] = true
		if len(n) < shortest {
			shortest = len(n)
		}
	}
	if shortest < 40 {
		t.Fatalf("shortest nonce is %d characters, want at least 40", shortest)
	}
}

// TestConsentPageEscapesHostileInput: ClientName and RedirectURI are chosen by
// whoever called /register, which is anyone.
func TestConsentPageEscapesHostileInput(t *testing.T) {
	tests := []struct{ name, clientName, redirect string }{
		{"script tag", `"><script>alert(1)</script>`, "https://evil.example.com/cb"},
		{"attribute break", `x" autofocus onfocus="alert(1)`, "https://evil.example.com/cb"},
		{"javascript uri in the redirect", "ok", "https://evil.example.com/cb?next=javascript:alert(1)"},
		{"pre-escaped entities", `&lt;script&gt;alert(1)&lt;/script&gt;`, "https://evil.example.com/cb"},
		{"style close", `</style><script>alert(1)</script>`, "https://evil.example.com/cb"},
		{"form hijack", `</form><form method=post action=https://evil.example.com>`, "https://evil.example.com/cb"},
		{"nul and newline", "a\x00b\ncd", "https://evil.example.com/cb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			clientID := h.registerNamed(tc.clientName, tc.redirect)
			rec := h.authorizeGET(authorizeParams(clientID, tc.redirect))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()

			for _, raw := range []string{tc.clientName, tc.redirect} {
				if strings.ContainsAny(raw, `<>"`) && strings.Contains(body, raw) {
					t.Fatalf("%q survived verbatim in the page:\n%s", raw, body)
				}
			}
			// Nothing may introduce a tag below the fixed <style> block.
			tail := strings.ToLower(body[strings.Index(body, "</style>"):])
			for _, bad := range []string{"<script", "<img", "<svg", "<iframe"} {
				if strings.Contains(tail, bad) {
					t.Fatalf("%q was injected into the page:\n%s", bad, body)
				}
			}
			if n := strings.Count(body, "<form"); n != 1 {
				t.Fatalf("%d <form> elements on the page, want 1", n)
			}
		})
	}
}

// TestDevCookieNameIsNotAcceptedInProd: the two cookie names must not be
// interchangeable, or a victim could be talked into presenting the weaker one.
func TestDevCookieNameIsNotAcceptedInProd(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(testRedirectURI)
	_, state := h.authorize(authorizeParams(clientID, testRedirectURI))
	h.google.grant("gc", testEmail)

	rec := h.callbackWithCookie(state, "gc", &http.Cookie{
		Name:  mcpoauth.BinderCookieNameInsecure,
		Value: h.binder.Value,
	})
	if rec.Code == http.StatusFound {
		t.Fatal("a production provider accepted the dev-mode cookie name")
	}
}
