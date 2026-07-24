# mcp-oauth

Turn any Go HTTP application into an **OAuth 2.1 authorization server for its MCP endpoint**, with **Google as the upstream login**.

Your app mints its **own** MCP access tokens. Google is only the identity step — it answers "who is this person", nothing more.

```
go get github.com/obad2015/mcp-oauth
```

Standard library + `github.com/golang-jwt/jwt/v5`. No web framework: every entry point is a plain `http.Handler` / `http.HandlerFunc`, so it drops into `net/http`, Echo, Gin, chi, whatever.

## Why this exists

The MCP spec requires the server to behave as an OAuth 2.1 authorization server (with dynamic client registration, RFC 7591) so that clients can connect without a human pre-registering them.

The Claude Code CLI (and most MCP clients) complete the login on a **random loopback port** — `http://127.0.0.1:51234/callback`. Google refuses to register a redirect URI it has never seen, and the port changes on every run. So Google cannot be the authorization server for MCP clients.

The fix is to put your app in the middle:

- your app implements dynamic client registration and accepts the client's loopback redirect URI,
- your app redirects the user to Google using **one fixed** redirect URI that *is* registered with Google,
- your app maps the verified Google email to an existing user of your app and issues its own tokens.

## Flow

```
 MCP client (Claude Code)          your app (this package)                 Google
 ------------------------          -----------------------                 ------
  1. GET /.well-known/oauth-protected-resource
     (triggered by a 401 + WWW-Authenticate from /mcp)
                        ------->   metadata: authorization_servers

  2. GET /.well-known/oauth-authorization-server
                        ------->   metadata: authorize/token/register URLs

  3. POST /oauth/register {redirect_uris:["http://127.0.0.1:51234/cb"]}
                        ------->   validate + store, return client_id

  4. GET /oauth/authorize?client_id&redirect_uri&code_challenge(S256)&state
                        ------->   exact-match redirect_uri,
                                   store PendingAuth (state hash),
                                   302  --------------------------------->  consent
                                                                            screen
  5.                               GET /oauth/google/callback?code&state
                                   <---------------------------------------  302
                                   consume state, exchange code,
                                   verify id_token (JWKS, iss, aud, exp,
                                   email_verified),
                                   FindUserIDByEmail -> 403 if unknown,
                                   mint auth code (hash stored)
     <-------  302 redirect_uri?code=...&state=...

  6. POST /oauth/token grant_type=authorization_code + code_verifier
                        ------->   consume code (single use), verify PKCE,
     <-------  {access_token (JWT), refresh_token, expires_in}

  7. POST /mcp  Authorization: Bearer <access_token>
                        ------->   Middleware validates and injects user id
```

Refresh works the same way and **rotates**: the presented refresh token is invalidated and a new pair is issued.

## Mounting it

### net/http

```go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

func main() {
	base := "https://finance.example.com"

	provider, err := mcpoauth.New(mcpoauth.Config{
		Issuer:          base,
		ResourceURL:     base + "/api/mcp",
		MetadataBaseURL: base, // where the .well-known docs are actually served

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  base + "/api/mcp/oauth/google/callback",

		AuthorizeURL: base + "/api/mcp/oauth/authorize",
		TokenURL:     base + "/api/mcp/oauth/token",
		RegisterURL:  base + "/api/mcp/oauth/register",

		JWTSecret:       []byte(os.Getenv("MCP_OAUTH_JWT_SECRET")),
		AccessTokenTTL:  time.Hour,          // default
		RefreshTokenTTL: 30 * 24 * time.Hour, // default
		AuthCodeTTL:     5 * time.Minute,     // default
	}, myStore{db}) // your mcpoauth.Store implementation

	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Discovery. These must be reachable at the URLs above (see "Reverse
	// proxies" below if your API is mounted under a prefix).
	mux.HandleFunc("/.well-known/oauth-protected-resource", provider.ProtectedResourceMetadata())
	mux.HandleFunc("/.well-known/oauth-protected-resource/", provider.ProtectedResourceMetadata())
	mux.HandleFunc("/.well-known/oauth-authorization-server", provider.AuthorizationServerMetadata())
	mux.HandleFunc("/.well-known/openid-configuration", provider.AuthorizationServerMetadata())

	// The OAuth endpoints.
	mux.HandleFunc("/mcp/oauth/register", provider.Register())
	mux.HandleFunc("/mcp/oauth/authorize", provider.Authorize())
	mux.HandleFunc("/mcp/oauth/token", provider.Token())
	mux.HandleFunc("/mcp/oauth/google/callback", provider.GoogleCallback())

	// The protected MCP endpoint.
	mux.Handle("/mcp", provider.Middleware(myMCPHandler()))

	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}
```

Inside the MCP handler:

```go
userID, ok := mcpoauth.UserIDFromContext(r.Context())
```

### Echo

Wrap the `http.HandlerFunc`s with `echo.WrapHandler`:

```go
e.Any("/.well-known/oauth-protected-resource", echo.WrapHandler(provider.ProtectedResourceMetadata()))
e.Any("/.well-known/oauth-authorization-server", echo.WrapHandler(provider.AuthorizationServerMetadata()))
e.Any("/mcp/oauth/register", echo.WrapHandler(provider.Register()))
e.Any("/mcp/oauth/authorize", echo.WrapHandler(provider.Authorize()))
e.Any("/mcp/oauth/token", echo.WrapHandler(provider.Token()))
e.Any("/mcp/oauth/google/callback", echo.WrapHandler(provider.GoogleCallback()))
```

Use `echo.WrapMiddleware(provider.Middleware)` to protect the MCP route, or — more commonly — keep your existing auth middleware and chain the validators:

```go
func mcpAuth(p *mcpoauth.Provider, tokens TokenStore) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw, ok := mcpoauth.BearerToken(c.Request())
			if !ok {
				p.Unauthorized(c.Response())
				return nil
			}
			// 1) legacy app-issued API token
			if userID, err := tokens.Lookup(c.Request().Context(), raw); err == nil {
				c.Set("user_id", userID)
				return next(c)
			}
			// 2) OAuth access token from this package
			userID, err := p.ValidateAccessToken(raw)
			if err != nil {
				p.Unauthorized(c.Response())
				return nil
			}
			c.Set("user_id", userID)
			return next(c)
		}
	}
}
```

`Unauthorized` emits exactly the 401 + `WWW-Authenticate: Bearer resource_metadata="…"` that makes an MCP client start the OAuth flow, so both paths stay consistent.

### Reverse proxies

The discovery documents are fetched by the client at the **issuer host root**: `https://host/.well-known/oauth-protected-resource` and `https://host/.well-known/oauth-authorization-server`. If your Go API only receives traffic under `/api/`, add the two well-known paths to the proxy:

```nginx
location ^~ /.well-known/oauth- {
    proxy_pass http://api:8080;
    proxy_set_header Host $host;
}
```

`MetadataBaseURL` only affects the URL advertised in the `WWW-Authenticate` challenge — set it to whatever base actually serves the documents (it defaults to `Issuer`).

## The Store interface

You implement persistence; the package never touches a database.

```go
type Store interface {
	SaveClient(ctx context.Context, c Client) error
	GetClient(ctx context.Context, clientID string) (Client, bool, error)

	SaveAuthCode(ctx context.Context, code AuthCode) error
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCode, bool, error)

	SavePendingAuth(ctx context.Context, p PendingAuth) error
	ConsumePendingAuth(ctx context.Context, stateHash string) (PendingAuth, bool, error)

	SaveRefreshToken(ctx context.Context, rt RefreshToken) error
	ConsumeRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, bool, error)
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error

	FindUserIDByEmail(ctx context.Context, email string) (userID string, ok bool, err error)
}
```

Two rules:

1. **`Consume*` must be atomic and single-use.** A concurrent second call for the same hash must return `ok=false`. In PostgreSQL that is one statement:

   ```sql
   DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
   RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at;
   ```

2. **`FindUserIDByEmail` must not create users.** Returning `ok=false` is how you refuse a stranger.

Expiry is checked by the provider, so `Consume*` may return expired rows; a periodic `DELETE ... WHERE expires_at < now()` sweep is enough housekeeping.

`github.com/obad2015/mcp-oauth/memstore` ships a ready-made in-memory implementation (`memstore.NewMemoryStore()`) for tests and local development.

## Google Cloud Console setup

1. **APIs & Services → Credentials → Create credentials → OAuth client ID.**
2. Application type: **Web application** (not "Desktop" — we need a client secret and a fixed redirect).
3. **Authorized redirect URIs**: add exactly **one** entry, your `GoogleRedirectURL`:
   `https://finance.example.com/api/mcp/oauth/google/callback`
   The MCP client's loopback URI is never sent to Google — that is the whole point of this package.
4. Copy the **Client ID** and **Client secret**.
5. On the OAuth consent screen, the scopes needed are just `openid`, `email`, `profile`.

## Environment variables

There is no magic env reading — you pass a `Config`. A conventional set:

| Variable | Meaning |
|---|---|
| `GOOGLE_CLIENT_ID` | Web-application OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | its client secret |
| `MCP_OAUTH_JWT_SECRET` | HS256 signing key for the access tokens (32+ random bytes) |
| `PUBLIC_BASE_URL` | the issuer, e.g. `https://finance.example.com` |

`MCP_OAUTH_JWT_SECRET` may be the same secret your app already uses for session JWTs — the `token_use` claim keeps the two apart (see below). Using a separate secret is still preferable.

## Security model

- **Only pre-existing users are admitted.** After a successful Google login the email is looked up with `FindUserIDByEmail`. If there is no match, the flow ends in a 403 page explaining that the account is not linked. No user is ever created, and no account is ever silently merged.
- **Google email must be verified** (`email_verified == true`) and the ID token is fully validated: RS256 signature against Google's JWKS (cached for the lifetime the response advertises), `iss ∈ {accounts.google.com, https://accounts.google.com}`, `aud == GoogleClientID`, `exp`.
- **`token_use="mcp_access"` — read this one twice.** Access tokens are HS256 JWTs with `iss`, `sub` (user id), `aud` (the MCP resource URL), `exp`, `iat`, `scope` and `token_use`. Validation requires **all** of signature, issuer, audience, expiry **and** `token_use == "mcp_access"`.
  This is what stops cross-protocol replay: applications commonly sign their web-session JWTs with the same secret, and without a distinguishing claim a stolen session token would open the MCP endpoint (and an MCP token would authenticate a web session). If your app's session tokens do not already carry a different `token_use`/`typ` claim, give them one.
- **Nothing secret is stored in the clear.** Authorization codes, refresh tokens and the pending Google state are persisted only as hex SHA-256 hashes. Raw values exist only in flight.
- **Single use, everywhere.** Authorization codes, pending state and refresh tokens are consumed atomically. A replayed code fails; a rotated refresh token fails. A code is burned even by a *failed* exchange.
- **PKCE S256 is mandatory.** `plain` and a missing `code_challenge_method` are rejected. The verifier is compared in constant time (`crypto/subtle`).
- **No open redirect.** `redirect_uri` must exactly match one of the client's registered URIs — no prefix, no wildcard, no substring. An unknown `client_id` or a mismatching `redirect_uri` is answered with a direct 400 and never a redirect. Errors are only bounced to a redirect URI after it has been validated.
- **Redirect URI policy at registration:** absolute URL, no fragment, no userinfo, and either `https://` or `http://` on a loopback host (`127.0.0.0/8`, `::1`, `localhost`). Every other `http://` and every custom scheme is refused.
- **Public clients only.** No `client_secret` is issued; `token_endpoint_auth_method` is `none`. PKCE plus exact redirect matching is the protection, per OAuth 2.1 for native apps.
- **All randomness comes from `crypto/rand`** (32 bytes for codes, refresh tokens and state; 24 for client ids).
- **No secrets in logs or errors.** The package logs nothing, and error strings never contain a token, code, upstream response body or email.
- Token responses always carry `Cache-Control: no-store`.

Things this package deliberately does **not** do: consent screens (Google's is the only one), scope negotiation (one fixed scope), client secrets, token introspection/revocation endpoints, or user provisioning.

## API surface

| Symbol | Purpose |
|---|---|
| `New(cfg, store) (*Provider, error)` | validate config, build the provider |
| `Provider.ProtectedResourceMetadata()` | RFC 9728 document |
| `Provider.AuthorizationServerMetadata()` | RFC 8414 document |
| `Provider.Register()` | RFC 7591 dynamic client registration |
| `Provider.Authorize()` | authorization endpoint (redirects to Google) |
| `Provider.GoogleCallback()` | upstream callback, mints the authorization code |
| `Provider.Token()` | `authorization_code` + `refresh_token` grants |
| `Provider.Middleware(next)` | protects the MCP endpoint |
| `Provider.ValidateAccessToken(s)` | validate a token yourself (for chaining) |
| `Provider.Unauthorized(w)` | emit the standard 401 challenge |
| `Provider.ProtectedResourceMetadataURL()` | the URL used in that challenge |
| `UserIDFromContext(ctx)` | read the authenticated user id |
| `BearerToken(r)` | extract an `Authorization: Bearer` value |
| `ValidateRedirectURI(s)` | the redirect-URI policy, exported for reuse |
| `HashSecret(s)` | the SHA-256 hashing used by the store contract |

The metadata and registration endpoints answer `OPTIONS` preflights and send `Access-Control-Allow-Origin: *`; MCP clients fetch them cross-origin.

## Tests

```
go test ./...
```

Covers PKCE success/failure, authorization-code single use and expiry, redirect-URI mismatch, unregistered clients, `plain` challenge rejection, refresh rotation and reuse rejection, access-token claim validation (wrong `aud`/`iss`, expired, wrong `token_use`, `alg: none`, wrong secret), the registration redirect-URI policy, and the unknown-email 403. Google is mocked with `httptest`, including a JWKS document and RS256-signed ID tokens.

## License

MIT
