package mcpoauth_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// routesConfig builds a minimal valid Config for exercising Routes(). base
// is the issuer/resource origin; resourcePath becomes ResourceURL's path
// component (the thing Routes derives the RFC 9728 path-inserted route
// from). The authorize/token/register/google-callback URLs are fixed under
// "/oauth/..." regardless of resourcePath, since Routes derives those
// independently.
func routesConfig(base, resourcePath string) mcpoauth.Config {
	return mcpoauth.Config{
		Issuer:             base,
		ResourceURL:        base + resourcePath,
		GoogleClientID:     testGoogleCID,
		GoogleClientSecret: "secret",
		GoogleRedirectURL:  base + "/oauth/google/callback",
		AuthorizeURL:       base + "/oauth/authorize",
		TokenURL:           base + "/oauth/token",
		RegisterURL:        base + "/oauth/register",
		JWTSecret:          testSecret,
	}
}

// sortedPaths extracts and sorts the Path of every route, for order-
// independent comparison.
func sortedPaths(routes []mcpoauth.Route) []string {
	out := make([]string, len(routes))
	for i, r := range routes {
		out[i] = r.Path
	}
	sort.Strings(out)
	return out
}

func TestRoutesDerivedPaths(t *testing.T) {
	wellKnown := []string{
		mcpoauth.AuthorizationServerMetadataPath,
		mcpoauth.OpenIDConfigurationPath,
		mcpoauth.ProtectedResourceMetadataPath,
	}
	oauthEndpoints := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/register",
		"/oauth/google/callback",
	}

	tests := []struct {
		name string
		cfg  mcpoauth.Config
		want []string
	}{
		{
			name: "resource path /mcp",
			cfg:  routesConfig("https://app.example.com", "/mcp"),
			want: append(append([]string{}, oauthEndpoints...), append(wellKnown,
				mcpoauth.ProtectedResourceMetadataPath+"/mcp")...),
		},
		{
			name: "resource path /api/mcp",
			cfg:  routesConfig("https://app.example.com", "/api/mcp"),
			want: append(append([]string{}, oauthEndpoints...), append(wellKnown,
				mcpoauth.ProtectedResourceMetadataPath+"/api/mcp")...),
		},
		{
			name: "bare host, no resource path",
			cfg:  routesConfig("https://app.example.com", ""),
			want: append(append([]string{}, oauthEndpoints...), wellKnown...),
		},
		{
			name: "resource path is exactly root",
			cfg:  routesConfig("https://app.example.com", "/"),
			want: append(append([]string{}, oauthEndpoints...), wellKnown...),
		},
		{
			name: "resource path with trailing slash",
			cfg:  routesConfig("https://app.example.com", "/mcp/"),
			want: append(append([]string{}, oauthEndpoints...), append(wellKnown,
				mcpoauth.ProtectedResourceMetadataPath+"/mcp/")...),
		},
		{
			// The real personal-finance production config, current shape:
			// /mcp is the canonical public path, nginx preserves it
			// unchanged, so the Go server sees the same paths the public
			// URLs use.
			name: "personal-finance production (current, /mcp canonical)",
			cfg: mcpoauth.Config{
				Issuer:             "https://finance.example.com",
				ResourceURL:        "https://finance.example.com/mcp",
				MetadataBaseURL:    "https://finance.example.com",
				GoogleClientID:     testGoogleCID,
				GoogleClientSecret: "secret",
				GoogleRedirectURL:  "https://finance.example.com/mcp/oauth/google/callback",
				AuthorizeURL:       "https://finance.example.com/mcp/oauth/authorize",
				TokenURL:           "https://finance.example.com/mcp/oauth/token",
				RegisterURL:        "https://finance.example.com/mcp/oauth/register",
				JWTSecret:          testSecret,
			},
			want: []string{
				"/mcp/oauth/authorize",
				"/mcp/oauth/token",
				"/mcp/oauth/register",
				"/mcp/oauth/google/callback",
				mcpoauth.AuthorizationServerMetadataPath,
				mcpoauth.OpenIDConfigurationPath,
				mcpoauth.ProtectedResourceMetadataPath,
				mcpoauth.ProtectedResourceMetadataPath + "/mcp",
			},
		},
		{
			// The historical, buggy shape: ResourceURL was under /api/mcp,
			// and personal-finance hand-derived the path-inserted metadata
			// route as ".../mcp" instead of ".../api/mcp" — a 404 for every
			// spec-compliant client. This is the regression guard: Routes()
			// must derive ".../api/mcp", never ".../mcp", from this config.
			name: "personal-finance historical bug config (/api/mcp)",
			cfg: mcpoauth.Config{
				Issuer:             "https://finance.example.com",
				ResourceURL:        "https://finance.example.com/api/mcp",
				MetadataBaseURL:    "https://finance.example.com",
				GoogleClientID:     testGoogleCID,
				GoogleClientSecret: "secret",
				GoogleRedirectURL:  "https://finance.example.com/api/mcp/oauth/google/callback",
				AuthorizeURL:       "https://finance.example.com/api/mcp/oauth/authorize",
				TokenURL:           "https://finance.example.com/api/mcp/oauth/token",
				RegisterURL:        "https://finance.example.com/api/mcp/oauth/register",
				JWTSecret:          testSecret,
			},
			want: []string{
				"/api/mcp/oauth/authorize",
				"/api/mcp/oauth/token",
				"/api/mcp/oauth/register",
				"/api/mcp/oauth/google/callback",
				mcpoauth.AuthorizationServerMetadataPath,
				mcpoauth.OpenIDConfigurationPath,
				mcpoauth.ProtectedResourceMetadataPath,
				mcpoauth.ProtectedResourceMetadataPath + "/api/mcp",
			},
		},
		{
			// todo's real production config: no /api prefix anywhere, MCP
			// served at the host root under /mcp.
			name: "todo production (/mcp, no prefix)",
			cfg: mcpoauth.Config{
				Issuer:             "https://todo.example.com",
				ResourceURL:        "https://todo.example.com/mcp",
				MetadataBaseURL:    "https://todo.example.com",
				GoogleClientID:     testGoogleCID,
				GoogleClientSecret: "secret",
				GoogleRedirectURL:  "https://todo.example.com/mcp/oauth/google/callback",
				AuthorizeURL:       "https://todo.example.com/mcp/oauth/authorize",
				TokenURL:           "https://todo.example.com/mcp/oauth/token",
				RegisterURL:        "https://todo.example.com/mcp/oauth/register",
				JWTSecret:          testSecret,
			},
			want: []string{
				"/mcp/oauth/authorize",
				"/mcp/oauth/token",
				"/mcp/oauth/register",
				"/mcp/oauth/google/callback",
				mcpoauth.AuthorizationServerMetadataPath,
				mcpoauth.OpenIDConfigurationPath,
				mcpoauth.ProtectedResourceMetadataPath,
				mcpoauth.ProtectedResourceMetadataPath + "/mcp",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := mcpoauth.New(tc.cfg, newStore())
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			routes := p.Routes()

			for _, r := range routes {
				if r.Path == "" {
					t.Errorf("route with empty Path: %+v", r)
				}
				if r.Handler == nil {
					t.Errorf("route %q has a nil Handler", r.Path)
				}
				if len(r.Methods) == 0 {
					t.Errorf("route %q has no Methods", r.Path)
				}
			}

			got := sortedPaths(routes)
			want := append([]string{}, tc.want...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("Routes() paths = %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("Routes() paths = %v, want %v", got, want)
				}
			}

			// No duplicate paths, ever — the property Mount and every
			// framework adapter relies on to never double-register.
			seen := make(map[string]bool, len(got))
			for _, path := range got {
				if seen[path] {
					t.Fatalf("Routes() returned duplicate path %q", path)
				}
				seen[path] = true
			}
		})
	}
}

// TestRoutesDedupesCollidingPaths guards the defensive dedup in Routes()
// itself: if two of the configured URLs are (mis)configured to the same
// path, Routes() must still return that path exactly once rather than
// handing a registrar two Routes for it (Echo panics on that).
func TestRoutesDedupesCollidingPaths(t *testing.T) {
	cfg := routesConfig("https://app.example.com", "/mcp")
	cfg.TokenURL = cfg.AuthorizeURL // deliberately colliding

	p, err := mcpoauth.New(cfg, newStore())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	routes := p.Routes()
	count := 0
	for _, r := range routes {
		if r.Path == "/oauth/authorize" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("colliding path registered %d times, want 1", count)
	}
}

// findRoute returns the single route whose Path equals path, failing the
// test if there isn't exactly one.
func findRoute(t *testing.T, routes []mcpoauth.Route, path string) mcpoauth.Route {
	t.Helper()
	for _, r := range routes {
		if r.Path == path {
			return r
		}
	}
	t.Fatalf("no route for path %q", path)
	return mcpoauth.Route{}
}

// TestRoutesMethodDiscipline checks that the Handler reachable through
// Routes() still enforces the same method discipline documented on the
// underlying Provider methods (Routes is a thin derivation over them, but
// this is the regression guard for that staying true).
func TestRoutesMethodDiscipline(t *testing.T) {
	cfg := routesConfig("https://app.example.com", "/mcp")
	p, err := mcpoauth.New(cfg, newStore())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	routes := p.Routes()

	t.Run("metadata routes 405 on POST", func(t *testing.T) {
		for _, path := range []string{
			mcpoauth.AuthorizationServerMetadataPath,
			mcpoauth.OpenIDConfigurationPath,
			mcpoauth.ProtectedResourceMetadataPath,
		} {
			route := findRoute(t, routes, path)
			rec := httptest.NewRecorder()
			route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("POST %s = %d, want 405", path, rec.Code)
			}
		}
	})

	t.Run("authorize refuses HEAD", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/authorize")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/oauth/authorize", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("HEAD /oauth/authorize = %d, want 405", rec.Code)
		}
	})

	t.Run("authorize GET never redirects to google", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/authorize")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil))
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("GET /oauth/authorize set Location: %q, must never redirect", loc)
		}
	})

	t.Run("token is POST-only", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/token")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/token", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /oauth/token = %d, want 405", rec.Code)
		}
	})

	t.Run("token answers CORS preflight", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/token")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/oauth/token", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS /oauth/token = %d, want 204", rec.Code)
		}
	})

	t.Run("register is POST-only", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/register")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/register", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /oauth/register = %d, want 405", rec.Code)
		}
	})

	t.Run("register answers CORS preflight", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/register")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/oauth/register", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS /oauth/register = %d, want 204", rec.Code)
		}
	})

	t.Run("google callback is GET-only", func(t *testing.T) {
		route := findRoute(t, routes, "/oauth/google/callback")
		rec := httptest.NewRecorder()
		route.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/google/callback", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST /oauth/google/callback = %d, want 405", rec.Code)
		}
	})
}
