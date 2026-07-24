package mcpoauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https url", "https://app.example.com/callback", false},
		{"https url with query", "https://app.example.com/cb?x=1", false},
		{"loopback ipv4 with random port", "http://127.0.0.1:51234/callback", false},
		{"loopback ipv4 without port", "http://127.0.0.1/callback", false},
		{"localhost with port", "http://localhost:8765/oauth/callback", false},
		{"localhost uppercase", "http://LOCALHOST:8765/cb", false},
		{"loopback ipv6", "http://[::1]:51234/callback", false},
		{"other 127.x loopback", "http://127.0.0.53:9999/cb", false},
		{"plain http to a public host", "http://app.example.com/callback", true},
		{"http to a LAN address", "http://192.168.1.10:8080/cb", true},
		{"http to a lookalike host", "http://localhost.evil.com/cb", true},
		{"https with fragment", "https://app.example.com/cb#frag", true},
		{"loopback with fragment", "http://127.0.0.1:1234/cb#frag", true},
		{"empty fragment marker", "https://app.example.com/cb#", true},
		{"relative url", "/callback", true},
		{"scheme only", "https://", true},
		{"custom scheme", "myapp://callback", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"data scheme", "data:text/html,hi", true},
		{"userinfo in url", "https://user:pass@app.example.com/cb", true},
		{"empty string", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := mcpoauth.ValidateRedirectURI(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateRedirectURI(%q) error = %v, wantErr %v", tc.uri, err, tc.wantErr)
			}
		})
	}
}

func TestRegisterHandler(t *testing.T) {
	post := func(h *harness, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		h.p.Register()(rec, req)
		return rec
	}

	tests := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"loopback client", `{"redirect_uris":["http://127.0.0.1:51234/callback"],"client_name":"Claude Code"}`, http.StatusCreated},
		{"https client", `{"redirect_uris":["https://app.example.com/cb"]}`, http.StatusCreated},
		{"several uris", `{"redirect_uris":["https://a.example.com/cb","http://localhost:1/cb"]}`, http.StatusCreated},
		{"one bad uri poisons the batch", `{"redirect_uris":["https://a.example.com/cb","http://evil.com/cb"]}`, http.StatusBadRequest},
		{"no redirect uris", `{"client_name":"x"}`, http.StatusBadRequest},
		{"empty redirect uris", `{"redirect_uris":[]}`, http.StatusBadRequest},
		{"not json", `not json at all`, http.StatusBadRequest},
		{"empty body", ``, http.StatusBadRequest},
		{
			"too many redirect uris",
			`{"redirect_uris":["https://a/1","https://a/2","https://a/3","https://a/4","https://a/5","https://a/6","https://a/7","https://a/8","https://a/9","https://a/10","https://a/11"]}`,
			http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			rec := post(h, tc.body)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode != http.StatusCreated {
				return
			}

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			if _, ok := resp["client_secret"]; ok {
				t.Fatal("a client_secret was issued to a public client")
			}
			if resp["token_endpoint_auth_method"] != "none" {
				t.Fatalf("token_endpoint_auth_method = %v, want none", resp["token_endpoint_auth_method"])
			}
			id, _ := resp["client_id"].(string)
			if len(id) < 16 {
				t.Fatalf("client_id %q looks too short to be random", id)
			}
		})
	}

	t.Run("client ids are unique", func(t *testing.T) {
		h := newHarness(t)
		seen := map[string]bool{}
		for i := 0; i < 20; i++ {
			id := h.register(testRedirectURI)
			if seen[id] {
				t.Fatal("duplicate client_id issued")
			}
			seen[id] = true
		}
	})

	t.Run("GET is rejected", func(t *testing.T) {
		h := newHarness(t)
		rec := httptest.NewRecorder()
		h.p.Register()(rec, httptest.NewRequest(http.MethodGet, "/register", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("preflight is answered with CORS headers", func(t *testing.T) {
		h := newHarness(t)
		rec := httptest.NewRecorder()
		h.p.Register()(rec, httptest.NewRequest(http.MethodOptions, "/register", nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
		}
	})
}
