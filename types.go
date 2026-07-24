// Package mcpoauth turns any Go HTTP application into an OAuth 2.1
// authorization server for its MCP endpoint, using Google as the upstream
// identity provider.
//
// The application mints its OWN access tokens; Google is only used to prove
// who the user is. This is required because MCP clients such as the Claude
// Code CLI use a random loopback redirect port that cannot be pre-registered
// with Google — so this package implements dynamic client registration
// (RFC 7591) and accepts the client's redirect URI itself.
//
// Security model highlights:
//
//   - Authorization codes, refresh tokens and the pending-authorize state are
//     persisted only as SHA-256 hashes; the raw values never touch the store.
//   - Authorization codes, pending state and refresh tokens are single-use.
//   - PKCE S256 is mandatory; "plain" is rejected.
//   - Redirect URIs are matched exactly against the registered set; a request
//     with an unknown client or a mismatching redirect URI is answered with a
//     direct 400 and never redirected (no open redirect).
//   - Access tokens carry token_use="mcp_access". Validation requires it, so an
//     application's ordinary web-session JWT signed with the same secret cannot
//     be replayed against the MCP endpoint (and vice versa).
//   - Only pre-existing application users are admitted: if the Google email is
//     not known to the app, the flow ends in a 403 and no user is created.
package mcpoauth

import (
	"net/http"
	"time"
)

// Default endpoints of the upstream Google identity provider. They can be
// overridden through Config for testing.
const (
	DefaultGoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	DefaultGoogleTokenURL = "https://oauth2.googleapis.com/token"
	DefaultGoogleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
)

// TokenUseMCPAccess is the value of the token_use claim carried by every
// access token this package issues. Validation requires it.
const TokenUseMCPAccess = "mcp_access"

// GrantedScope is the scope granted to every issued token.
const GrantedScope = "openid email profile"

// ProtectedResourceMetadataPath is the path (relative to Config.MetadataBaseURL)
// where the RFC 9728 protected-resource metadata document is expected to be
// served. It is used to build the absolute URL advertised in the
// WWW-Authenticate challenge.
const ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// Config configures a Provider. Every URL must be the absolute, publicly
// reachable URL as the MCP client sees it.
type Config struct {
	// Issuer is the public base URL of the application, e.g.
	// https://finance.example.com. It becomes the "iss" claim of issued
	// access tokens and the issuer in the authorization-server metadata.
	Issuer string

	// ResourceURL is the MCP endpoint URL, e.g.
	// https://finance.example.com/api/mcp. It becomes the "aud" claim.
	ResourceURL string

	// MetadataBaseURL is the base URL the well-known documents are actually
	// served from. It may differ from Issuer when the app is proxied under a
	// prefix such as /api. Defaults to Issuer when empty.
	MetadataBaseURL string

	GoogleClientID     string
	GoogleClientSecret string
	// GoogleRedirectURL is OUR callback URL, e.g.
	// https://finance.example.com/api/mcp/oauth/google/callback. It is the
	// single redirect URI that has to be registered in Google Cloud Console.
	GoogleRedirectURL string

	// Endpoint URLs as the public client sees them.
	AuthorizeURL string
	TokenURL     string
	RegisterURL  string

	// JWTSecret signs the access tokens this package issues (HS256).
	JWTSecret []byte

	AccessTokenTTL  time.Duration // default 1h
	RefreshTokenTTL time.Duration // default 30d
	AuthCodeTTL     time.Duration // default 5m
	PendingAuthTTL  time.Duration // default 10m

	// HTTPClient is used for the Google token exchange and JWKS fetches.
	// Defaults to a client with a 10s timeout.
	HTTPClient *http.Client

	// Advanced / testing: override the upstream Google endpoints.
	GoogleAuthURL  string
	GoogleTokenURL string
	GoogleJWKSURL  string
}

// Client is a dynamically registered public OAuth client.
type Client struct {
	ClientID     string
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
}

// HasRedirectURI reports whether uri exactly matches one of the client's
// registered redirect URIs. Matching is exact; no prefix or wildcard logic.
func (c Client) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AuthCode is a single-use authorization code. Only the SHA-256 hash of the
// code is stored.
type AuthCode struct {
	CodeHash      string
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// PendingAuth is the state carried across the Google round-trip. Only the
// SHA-256 hash of the state value handed to Google is stored.
type PendingAuth struct {
	StateHash     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// RefreshToken is a single-use (rotating) refresh token. Only the SHA-256 hash
// of the token is stored.
type RefreshToken struct {
	TokenHash string
	ClientID  string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}
