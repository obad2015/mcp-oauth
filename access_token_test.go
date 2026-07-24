package mcpoauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpoauth "github.com/obad2015/mcp-oauth"
)

// mintToken builds an access-token-shaped JWT with arbitrary claims, so the
// validator can be tested against tokens it must refuse.
func mintToken(t *testing.T, secret []byte, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	var key any = secret
	if _, ok := method.(*jwt.SigningMethodHMAC); !ok {
		key = jwt.UnsafeAllowNoneSignatureType
	}
	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}
	return signed
}

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       testUserID,
		"aud":       testResourceURL,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"scope":     mcpoauth.GrantedScope,
		"token_use": mcpoauth.TokenUseMCPAccess,
	}
}

func TestValidateAccessToken(t *testing.T) {
	tests := []struct {
		name    string
		token   func(t *testing.T) string
		wantErr bool
	}{
		{
			name:    "valid token",
			token:   func(t *testing.T) string { return mintToken(t, signingKey(), jwt.SigningMethodHS256, validClaims()) },
			wantErr: false,
		},
		{
			name: "wrong audience",
			token: func(t *testing.T) string {
				c := validClaims()
				c["aud"] = "https://app.example.com/api/other"
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			token: func(t *testing.T) string {
				c := validClaims()
				delete(c, "aud")
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T) string {
				c := validClaims()
				c["iss"] = "https://evil.example.com"
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "expired",
			token: func(t *testing.T) string {
				c := validClaims()
				c["exp"] = time.Now().Add(-time.Minute).Unix()
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "no expiry at all",
			token: func(t *testing.T) string {
				c := validClaims()
				delete(c, "exp")
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			// The whole point of token_use: an app web-session JWT signed with
			// the same secret must not open the MCP endpoint.
			name: "app session token with the same secret",
			token: func(t *testing.T) string {
				c := validClaims()
				c["token_use"] = "web_session"
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "no token_use claim",
			token: func(t *testing.T) string {
				c := validClaims()
				delete(c, "token_use")
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name: "signed with another secret",
			token: func(t *testing.T) string {
				return mintToken(t, []byte("a-completely-different-secret"), jwt.SigningMethodHS256, validClaims())
			},
			wantErr: true,
		},
		{
			name: "alg none",
			token: func(t *testing.T) string {
				return mintToken(t, signingKey(), jwt.SigningMethodNone, validClaims())
			},
			wantErr: true,
		},
		{
			name: "empty subject",
			token: func(t *testing.T) string {
				c := validClaims()
				c["sub"] = ""
				return mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantErr: true,
		},
		{
			name:    "garbage",
			token:   func(*testing.T) string { return "not.a.jwt" },
			wantErr: true,
		},
		{
			name:    "empty string",
			token:   func(*testing.T) string { return "" },
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			userID, err := h.p.ValidateAccessToken(tc.token(t))
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateAccessToken() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if userID != "" {
					t.Fatalf("a user id (%q) was returned for an invalid token", userID)
				}
				return
			}
			if userID != testUserID {
				t.Fatalf("userID = %q, want %q", userID, testUserID)
			}
		})
	}

	t.Run("wrong token_use reports ErrWrongTokenUse", func(t *testing.T) {
		h := newHarness(t)
		c := validClaims()
		c["token_use"] = "web_session"
		_, err := h.p.ValidateAccessToken(mintToken(t, signingKey(), jwt.SigningMethodHS256, c))
		if !errors.Is(err, mcpoauth.ErrWrongTokenUse) {
			t.Fatalf("error = %v, want ErrWrongTokenUse", err)
		}
	})
}

func TestMiddleware(t *testing.T) {
	protected := func(h *harness) http.Handler {
		return h.p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := mcpoauth.UserIDFromContext(r.Context())
			if !ok {
				t.Error("middleware let a request through without a user id")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(userID))
		}))
	}

	tests := []struct {
		name     string
		header   func(t *testing.T) string
		wantCode int
	}{
		{
			name: "valid bearer token",
			header: func(t *testing.T) string {
				return "Bearer " + mintToken(t, signingKey(), jwt.SigningMethodHS256, validClaims())
			},
			wantCode: http.StatusOK,
		},
		{
			name: "lowercase scheme",
			header: func(t *testing.T) string {
				return "bearer " + mintToken(t, signingKey(), jwt.SigningMethodHS256, validClaims())
			},
			wantCode: http.StatusOK,
		},
		{
			name:     "no header",
			header:   func(*testing.T) string { return "" },
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "empty bearer",
			header:   func(*testing.T) string { return "Bearer " },
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "wrong scheme",
			header:   func(*testing.T) string { return "Basic dXNlcjpwYXNz" },
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "token is not a jwt",
			header:   func(*testing.T) string { return "Bearer legacy-api-token" },
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "app session token",
			header: func(t *testing.T) string {
				c := validClaims()
				c["token_use"] = "web_session"
				return "Bearer " + mintToken(t, signingKey(), jwt.SigningMethodHS256, c)
			},
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			req := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
			if v := tc.header(t); v != "" {
				req.Header.Set("Authorization", v)
			}
			rec := httptest.NewRecorder()
			protected(h).ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantCode == http.StatusOK {
				if rec.Body.String() != testUserID {
					t.Fatalf("body = %q, want the user id", rec.Body.String())
				}
				return
			}

			challenge := rec.Header().Get("WWW-Authenticate")
			want := `Bearer resource_metadata="https://app.example.com/api/.well-known/oauth-protected-resource"`
			if challenge != want {
				t.Fatalf("WWW-Authenticate = %q, want %q", challenge, want)
			}
			if got := decodeJSON[errorBody](t, rec).Error; got != "unauthorized" {
				t.Fatalf("error = %q, want unauthorized", got)
			}
		})
	}
}
