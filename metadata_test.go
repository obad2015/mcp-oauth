package mcpoauth_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

func TestMetadataDocuments(t *testing.T) {
	tests := []struct {
		name    string
		handler func(h *harness) http.HandlerFunc
		want    map[string]any
	}{
		{
			name:    "protected resource metadata",
			handler: func(h *harness) http.HandlerFunc { return h.p.ProtectedResourceMetadata() },
			want: map[string]any{
				"resource":                 testResourceURL,
				"authorization_servers":    []any{testIssuer},
				"scopes_supported":         []any{"openid", "email", "profile"},
				"bearer_methods_supported": []any{"header"},
			},
		},
		{
			name:    "authorization server metadata",
			handler: func(h *harness) http.HandlerFunc { return h.p.AuthorizationServerMetadata() },
			want: map[string]any{
				"issuer":                                testIssuer,
				"authorization_endpoint":                testIssuer + "/api/mcp/oauth/authorize",
				"token_endpoint":                        testIssuer + "/api/mcp/oauth/token",
				"registration_endpoint":                 testIssuer + "/api/mcp/oauth/register",
				"response_types_supported":              []any{"code"},
				"grant_types_supported":                 []any{"authorization_code", "refresh_token"},
				"code_challenge_methods_supported":      []any{"S256"},
				"token_endpoint_auth_methods_supported": []any{"none"},
				"scopes_supported":                      []any{"openid", "email", "profile"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			rec := httptest.NewRecorder()
			tc.handler(h)(rec, httptest.NewRequest(http.MethodGet, "/.well-known/x", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
			}
			got := decodeJSON[map[string]any](t, rec)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("document =\n%#v\nwant\n%#v", got, tc.want)
			}
		})

		t.Run(tc.name+" preflight", func(t *testing.T) {
			h := newHarness(t)
			rec := httptest.NewRecorder()
			tc.handler(h)(rec, httptest.NewRequest(http.MethodOptions, "/.well-known/x", nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
			}
		})
	}
}

func TestNewConfigValidation(t *testing.T) {
	valid := func() mcpoauth.Config {
		return mcpoauth.Config{
			Issuer:             testIssuer,
			ResourceURL:        testResourceURL,
			GoogleClientID:     testGoogleCID,
			GoogleClientSecret: "secret",
			GoogleRedirectURL:  testIssuer + "/cb",
			AuthorizeURL:       testIssuer + "/authorize",
			TokenURL:           testIssuer + "/token",
			RegisterURL:        testIssuer + "/register",
			JWTSecret:          testSecret,
		}
	}

	tests := []struct {
		name    string
		mutate  func(c *mcpoauth.Config)
		wantErr bool
	}{
		{"complete config", func(*mcpoauth.Config) {}, false},
		{"missing issuer", func(c *mcpoauth.Config) { c.Issuer = "" }, true},
		{"missing resource url", func(c *mcpoauth.Config) { c.ResourceURL = "" }, true},
		{"missing google client id", func(c *mcpoauth.Config) { c.GoogleClientID = "" }, true},
		{"missing google client secret", func(c *mcpoauth.Config) { c.GoogleClientSecret = "" }, true},
		{"missing google redirect url", func(c *mcpoauth.Config) { c.GoogleRedirectURL = "" }, true},
		{"missing authorize url", func(c *mcpoauth.Config) { c.AuthorizeURL = "" }, true},
		{"missing token url", func(c *mcpoauth.Config) { c.TokenURL = "" }, true},
		{"missing register url", func(c *mcpoauth.Config) { c.RegisterURL = "" }, true},
		{"missing jwt secret", func(c *mcpoauth.Config) { c.JWTSecret = nil }, true},
		{"empty jwt secret", func(c *mcpoauth.Config) { c.JWTSecret = []byte{} }, true},
		{"relative issuer", func(c *mcpoauth.Config) { c.Issuer = "/app" }, true},
		{"issuer without host", func(c *mcpoauth.Config) { c.Issuer = "https://" }, true},
		{"relative metadata base url", func(c *mcpoauth.Config) { c.MetadataBaseURL = "/api" }, true},
		{"whitespace only issuer", func(c *mcpoauth.Config) { c.Issuer = "   " }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(&cfg)
			_, err := mcpoauth.New(cfg, newStore())
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	t.Run("nil store is rejected", func(t *testing.T) {
		if _, err := mcpoauth.New(valid(), nil); err == nil {
			t.Fatal("New() with a nil store must fail")
		}
	})

	t.Run("metadata url defaults to the issuer", func(t *testing.T) {
		p, err := mcpoauth.New(valid(), newStore())
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		want := testIssuer + mcpoauth.ProtectedResourceMetadataPath
		if got := p.ProtectedResourceMetadataURL(); got != want {
			t.Fatalf("ProtectedResourceMetadataURL() = %q, want %q", got, want)
		}
	})

	t.Run("ttl defaults are applied", func(t *testing.T) {
		h := newHarness(t)
		clientID, code, verifier := h.login(testEmail)
		rec := h.token(formValues(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"client_id":     clientID,
			"redirect_uri":  testRedirectURI,
			"code_verifier": verifier,
		}))
		if got := decodeJSON[tokenSuccess](t, rec).ExpiresIn; got != 3600 {
			t.Fatalf("expires_in = %d, want the 1h default", got)
		}
	})
}
