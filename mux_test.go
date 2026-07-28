package mcpoauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// TestMount spins up a real http.ServeMux, mounts every route Routes()
// reports, and asserts each one actually resolves (never a bare 404 from
// the mux itself) for at least one of its documented Methods.
func TestMount(t *testing.T) {
	cfg := routesConfig("https://app.example.com", "/mcp")
	p, err := mcpoauth.New(cfg, newStore())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	mux := http.NewServeMux()
	mcpoauth.Mount(mux, p)

	for _, route := range p.Routes() {
		method := route.Methods[0]
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, route.Path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s: mux returned 404, route was not mounted", method, route.Path)
		}
	}
}

// TestMountNeverPanicsOnCollidingConfig is the mount-level counterpart of
// TestRoutesDedupesCollidingPaths: even a misconfiguration that would make
// two of the provider's URLs collide on one path must not panic when
// mounted (http.ServeMux.Handle panics on a duplicate pattern).
func TestMountNeverPanicsOnCollidingConfig(t *testing.T) {
	cfg := routesConfig("https://app.example.com", "/mcp")
	cfg.TokenURL = cfg.AuthorizeURL // deliberately colliding

	p, err := mcpoauth.New(cfg, newStore())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Mount panicked on a colliding config: %v", r)
		}
	}()

	mux := http.NewServeMux()
	mcpoauth.Mount(mux, p)
}
