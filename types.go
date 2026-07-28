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
//   - The authorization endpoint renders an interstitial consent page naming
//     the client and the exact redirect URI, and only continues on a POST
//     carrying a single-use nonce. It never redirects to Google on a GET.
//   - The whole flow is pinned to one browser with a __Host- prefixed binding
//     cookie whose hash lives on the pending record; the Google callback
//     refuses to mint a code for any other browser. Together with consent this
//     defeats the attacker-initiated flow that PKCE cannot help with.
//   - Authorization codes, refresh tokens, the pending-authorize state and the
//     browser binder are persisted only as SHA-256 hashes; the raw values never
//     touch the store.
//   - Authorization codes, the consent nonce, pending state and refresh tokens
//     are single-use. Replaying a rotated refresh token revokes its whole
//     family, and a family cannot outlive Config.RefreshTokenAbsoluteTTL.
//     Reuse detection lives in the Store — a consumed refresh-token row is
//     retained until its family expires — so it survives a process restart and
//     cannot be evicted by rotating a stolen token in a loop.
//   - PKCE S256 is mandatory; "plain" is rejected and the challenge must
//     satisfy RFC 7636.
//   - Redirect URIs are matched exactly against the registered set; a request
//     with an unknown client or a mismatching redirect URI is answered with a
//     direct 400 and never redirected (no open redirect).
//   - The access-token signing key is HKDF-derived from Config.JWTSecret, and
//     tokens carry token_use="mcp_access". An application's web-session JWT
//     therefore cannot be replayed against the MCP endpoint, or vice versa,
//     even when the same secret is configured for both.
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

// ConsentNonceField is the form field the interstitial consent page must POST
// back to the authorization endpoint. It is also carried on ConsentRequest so a
// custom ConsentHandler never has to hard-code it.
const ConsentNonceField = "mcpoauth_consent"

// Binder cookie names. The __Host- prefix pins the cookie to the exact origin
// and requires Secure + Path=/ + no Domain; the bare name is only used when
// Config.InsecureDevMode is set (plain-http local development).
//
// One cookie carries up to maxBinders values separated by BinderCookieSep, so
// several authorization flows can be in progress in the same browser (two tabs,
// or a retry) without the newest one invalidating the others.
const (
	BinderCookieName         = "__Host-mcpoauth_binder"
	BinderCookieNameInsecure = "mcpoauth_binder"
	// BinderCookieSep separates the individual binder values inside the
	// cookie. It is not part of the base64url alphabet the values use.
	BinderCookieSep = "."
)

// ConsentRequest is everything a custom consent page needs in order to render
// an approval form. The zero value is never handed out.
//
// A ConsentHandler MUST render a form that POSTs to FormAction with
// NonceField=Nonce. Nothing else is required: the rest of the authorization
// request is held server-side and looked up from the nonce.
type ConsentRequest struct {
	// RedirectURI is the EXACT URI the authorization code will be delivered
	// to. Display it verbatim — it is attacker-controlled and is the single
	// most important thing the user has to look at.
	RedirectURI string
	// Scopes are the scopes that will be granted.
	Scopes []string
	// FormAction is the URL the approval form must POST to (the authorization
	// endpoint itself).
	FormAction string
	// NonceField is the name of the form field carrying Nonce
	// (always ConsentNonceField).
	NonceField string
	// Nonce is a single-use, unguessable value bound to this pending
	// authorization request and to the browser's binder cookie.
	Nonce string
}

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

	// JWTSecret is the input keying material for the access-token signing key.
	//
	// It must be at least 32 bytes AND contain at least 8 distinct byte
	// values; New rejects anything else. Those are crude sanity checks, not a
	// real entropy measurement: 32 bytes of `openssl rand -base64 32` output
	// pass, "aaaa..." does not, but a low-entropy passphrase that happens to
	// use enough different characters still would. Generate it randomly.
	//
	// It is NOT used to sign directly: the HS256 key is derived from it with
	// HKDF-Expand(SHA-256, JWTSecret, "mcpoauth/v1/access-token"). An
	// application that passes the same secret it uses for its own session
	// JWTs therefore still cannot have the two token families share a key in
	// either direction.
	JWTSecret []byte

	AccessTokenTTL  time.Duration // default 1h
	RefreshTokenTTL time.Duration // default 30d (sliding, per rotation)
	AuthCodeTTL     time.Duration // default 5m
	PendingAuthTTL  time.Duration // default 10m

	// RefreshTokenAbsoluteTTL caps the lifetime of a whole refresh-token
	// family measured from the login that created it, regardless of how often
	// it is rotated. Default 90d.
	RefreshTokenAbsoluteTTL time.Duration

	// RefreshGracePeriod makes a rotation idempotent for a short moment: if
	// the token that was JUST rotated away is presented again within this
	// window, the Provider replies with the very same refresh token the
	// rotation issued (plus a freshly minted access token) instead of treating
	// it as reuse. Default 30s; set a negative value to disable it.
	//
	// It exists because a client that never received the rotation response
	// (dropped connection, a retry, two parallel requests) would otherwise
	// destroy its own session: its retry looks exactly like a replay and
	// revokes the family.
	//
	// The predecessor -> successor mapping the answer needs is held IN PROCESS
	// (see grace.go), so a duplicate that arrives after a restart, or on
	// another instance, cannot be answered: it costs one re-login and nothing
	// else. The reuse ledger it is judged against — RefreshToken.ConsumedAt —
	// is durable in the Store and is what bounds this window; losing a grace
	// entry can never widen it.
	//
	// The trade-off is explicit: for this window a leaked refresh token that is
	// replayed does NOT trigger family revocation, it simply hands the replayer
	// the same successor. The window only ever applies to the single
	// most-recently-consumed token of a family, only while its successor is
	// still unused, and only to the same client. Anything older, anything after
	// the window, or a family whose successor has already moved on is reuse and
	// revokes the family.
	RefreshGracePeriod time.Duration

	// UnusedClientTTL is how long a dynamically registered client that never
	// completed a login is kept before PurgeExpired may delete it. Default 24h.
	// Registration is unauthenticated, so this is what stops the client table
	// from growing forever — put a rate limit in front of the endpoint too.
	UnusedClientTTL time.Duration

	// ClientTTL is how long a client that DID complete a login is kept, from
	// the most recent completed login. Default 90d. An expired registration is
	// not a lockout: MCP clients re-register automatically.
	ClientTTL time.Duration

	// PurgeInterval throttles the opportunistic call to PurgeExpired the
	// provider makes while serving requests. Default 5m. It is a backstop
	// only — run Provider.PurgeExpired from your own ticker.
	PurgeInterval time.Duration

	// ConsentHandler renders the interstitial approval page. When nil a
	// safe, self-contained default page is used.
	//
	// The handler MUST NOT redirect to Google itself: it renders a form that
	// POSTs req.Nonce back to req.FormAction. c.ClientName and
	// req.RedirectURI are attacker-controlled — escape them.
	ConsentHandler func(w http.ResponseWriter, r *http.Request, c Client, req ConsentRequest)

	// AllowedRedirectHosts, when non-empty, restricts which hosts an https
	// redirect_uri may point at. Loopback http redirect URIs (which MCP CLI
	// clients need) are always allowed. Empty means "any https host", which
	// is what dynamic client registration implies — see the README.
	AllowedRedirectHosts []string

	// InsecureDevMode drops the __Host- prefix and the Secure attribute from
	// the browser-binding cookie so the flow works over plain http on
	// localhost. NEVER set it in production — New enforces that by rejecting
	// it unless EVERY configured URL (Issuer, ResourceURL, MetadataBaseURL,
	// AuthorizeURL, TokenURL, RegisterURL and GoogleRedirectURL) is http:// on
	// a loopback host.
	InsecureDevMode bool

	// VerifyStoreUserID is the user ID Provider.VerifyStore writes on its
	// canary auth-code and refresh-token records. Default
	// "mcpoauth-verify-user".
	//
	// Set it when your schema constrains the user_id column — a `user_id UUID`
	// column, or a CHECK constraint — otherwise VerifyStore fails at startup
	// with a driver type error instead of a contract error. Any syntactically
	// valid value of the right type works; it must NOT be a real user, and
	// there must be no foreign key from these tables to your users table (see
	// the README).
	VerifyStoreUserID string

	// HTTPClient is used for the Google token exchange and JWKS fetches.
	// Defaults to a client with a 10s timeout.
	HTTPClient *http.Client

	// Advanced / testing: override the upstream Google endpoints.
	GoogleAuthURL  string
	GoogleTokenURL string
	GoogleJWKSURL  string
}

// Client is a dynamically registered public OAuth client.
//
// Registration is unauthenticated (that is what RFC 7591 dynamic registration
// means for MCP CLI clients), so registrations are not permanent: ExpiresAt
// starts at Config.UnusedClientTTL and is pushed out to Config.ClientTTL each
// time a login completes with this client.
type Client struct {
	ClientID     string
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
	// ExpiresAt is when PurgeExpired may delete this registration. Never
	// zero for a record written by this package.
	ExpiresAt time.Time
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

// PendingAuth is an in-flight authorization request. It exists in two phases
// and the store never needs to tell them apart:
//
//  1. before consent: StateHash is the SHA-256 of the single-use consent nonce
//     embedded in the approval form, and Approved is false. A record in this
//     phase is useless at the Google callback.
//  2. after consent: StateHash is the SHA-256 of the opaque state handed to
//     Google, and Approved is true.
//
// BinderHash pins the record to the browser that started the flow.
type PendingAuth struct {
	StateHash     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	// BinderHash is HashSecret of the value of the browser-binding cookie set
	// when the flow started. The Google callback refuses to proceed unless the
	// requesting browser presents the matching cookie.
	BinderHash string
	// Approved reports whether the user passed the interstitial consent step.
	Approved  bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RefreshToken is a single-use (rotating) refresh token. Only the SHA-256 hash
// of the token is stored.
//
// Every token issued by rotating an earlier one keeps the same FamilyID and
// FamilyCreatedAt: the family is the unit of revocation (on reuse detection)
// and of the absolute lifetime cap.
// A row is ALSO the durable reuse-detection ledger: it is not deleted when the
// token is rotated away, only stamped with ConsumedAt, and it survives until
// both ExpiresAt and FamilyExpiresAt have passed.
type RefreshToken struct {
	TokenHash string
	ClientID  string
	UserID    string
	// FamilyID identifies the rotation chain this token belongs to. All
	// tokens descended from one login share it.
	FamilyID string
	// FamilyCreatedAt is when the chain started (the original login), not
	// when this particular token was minted.
	FamilyCreatedAt time.Time
	// FamilyExpiresAt is FamilyCreatedAt + Config.RefreshTokenAbsoluteTTL: the
	// instant the whole chain dies no matter how often it was rotated. The row
	// must be retained until then even after it was consumed.
	FamilyExpiresAt time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
	// ConsumedAt is when this token was rotated away. Zero means it has never
	// been used. Set only by Store.ConsumeRefreshToken, and never overwritten
	// once set.
	ConsumedAt time.Time
}
