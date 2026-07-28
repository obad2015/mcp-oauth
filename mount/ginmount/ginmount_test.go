package ginmount_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
	"github.com/obad2015/mcp-oauth/mount/ginmount"
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

// TestMount spins up a real Gin engine, mounts every route, and asserts
// each one resolves for at least one of its documented methods.
func TestMount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p := newProvider(t)
	r := gin.New()

	ginmount.Mount(r, p)

	for _, route := range p.Routes() {
		method := route.Methods[0]
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, route.Path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s: gin returned 404, route was not mounted", method, route.Path)
		}
	}
}

// TestMountNeverPanics guards against Gin's own behaviour: it panics on a
// conflicting route registration, so Mount must never register the same
// path twice even if the provider's own dedup were ever to regress.
func TestMountNeverPanics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p := newProvider(t)
	r := gin.New()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Mount panicked: %v", rec)
		}
	}()

	ginmount.Mount(r, p)
}
