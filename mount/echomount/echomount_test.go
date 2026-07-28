package echomount_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
	"github.com/obad2015/mcp-oauth/mount/echomount"
)

func newProvider(t *testing.T) *mcpoauth.Provider {
	t.Helper()
	const base = "https://app.example.com"
	cfg := mcpoauth.Config{
		Issuer:             base,
		ResourceURL:        base + "/mcp",
		GoogleClientID:     "google-client-id",
		GoogleClientSecret: "google-client-secret",
		GoogleRedirectURL:  base + "/mcp/oauth/google/callback",
		AuthorizeURL:       base + "/mcp/oauth/authorize",
		TokenURL:           base + "/mcp/oauth/token",
		RegisterURL:        base + "/mcp/oauth/register",
		JWTSecret:          []byte("test-signing-secret-please-rotate"),
	}
	p, err := mcpoauth.New(cfg, memstore.NewMemoryStore())
	if err != nil {
		t.Fatalf("mcpoauth.New() error: %v", err)
	}
	return p
}

// TestMount spins up a real Echo instance, mounts every route, and asserts
// each one resolves — the regression guard for the exact production 404 the
// hand-rolled mountMCPOAuthRoutes could produce, now covered by an adapter
// instead of app code.
func TestMount(t *testing.T) {
	p := newProvider(t)
	e := echo.New()

	echomount.Mount(e, p)

	for _, route := range p.Routes() {
		method := route.Methods[0]
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, route.Path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s: echo returned 404, route was not mounted", method, route.Path)
		}
	}
}

// TestMountNeverPanics guards against Echo's own behaviour: it panics on a
// duplicate route registration, so Mount must never call e.Any twice for
// the same path even when the provider's own dedup were ever to regress.
func TestMountNeverPanics(t *testing.T) {
	p := newProvider(t)
	e := echo.New()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Mount panicked: %v", r)
		}
	}()

	echomount.Mount(e, p)
}
