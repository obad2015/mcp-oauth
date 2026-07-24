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
                                   store PendingAuth (nonce hash, NOT approved),
                                   set __Host-mcpoauth_binder cookie
     <-------  200 consent page: "<client> wants access, the code goes to <uri>"

  5. POST /oauth/authorize  mcpoauth_consent=<nonce>   (the user clicks Approve)
                        ------->   consume nonce (single use),
                                   require the binder cookie,
                                   store PendingAuth (state hash, approved),
                                   302  --------------------------------->  Google
                                                                            login
  6.                               GET /oauth/google/callback?code&state
                                   <---------------------------------------  302
                                   consume state, REQUIRE the binder cookie,
                                   exchange code,
                                   verify id_token (JWKS, iss, aud, exp,
                                   email_verified),
                                   FindUserIDByEmail -> 403 if unknown,
                                   mint auth code (hash stored)
     <-------  302 redirect_uri?code=...&state=...

  7. POST /oauth/token grant_type=authorization_code + code_verifier
                        ------->   consume code (single use), verify PKCE,
     <-------  {access_token (JWT), refresh_token, expires_in}

  8. POST /mcp  Authorization: Bearer <access_token>
                        ------->   Middleware validates and injects user id
```

Steps 4 and 5 are the **same route**: `provider.Authorize()` handles GET and POST. Nothing extra to mount.

Refresh works the same way and **rotates**: the presented refresh token is invalidated and a new pair is issued. Replaying a rotated token revokes the **whole family**, and a family can never outlive `RefreshTokenAbsoluteTTL` however often it is rotated.

## Consent and browser binding

`GET /oauth/authorize` does **not** redirect to Google. It renders an interstitial approval page naming the client and the **exact** `redirect_uri` the authorization code would be delivered to; the flow only continues on a `POST` carrying a single-use nonce from that page.

This exists because client registration is unauthenticated by design (RFC 7591). Without it, an attacker registers a client pointing at their own server, generates an `/authorize` URL and sends the victim a link that — as far as the victim can see — goes to `accounts.google.com`. The victim's authorization code is then delivered to the attacker, and PKCE cannot help: the attacker chose both halves of the verifier.

Two independent defences:

1. **Consent.** The victim is shown the attacker's address, on a page served by your own origin, before anything happens.
2. **Browser binding.** The first request sets a cookie:

   | | |
   |---|---|
   | name | `__Host-mcpoauth_binder` (`mcpoauth_binder` when `InsecureDevMode` is set) |
   | value | 32 random bytes, base64url — only its SHA-256 is persisted, on the `PendingAuth` row |
   | flags | `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain` |

   `GoogleCallback` refuses to mint an authorization code unless the browser presents the cookie matching the pending record (constant-time compare), and burns the record either way. This kills the cross-browser variant even if consent were bypassed. The cookie is cleared once the flow ends.

What this requires of your deployment:

- **HTTPS.** `__Host-` and `Secure` mean the cookie only travels over TLS. For plain-http local development set `Config.InsecureDevMode = true` — never in production.
- **The cookie must survive the Google round trip.** `SameSite=Lax` is correct and deliberate: the return from Google is a top-level `GET` navigation, which `Lax` allows and `Strict` would block. Do not tighten it.
- **Same origin throughout.** `AuthorizeURL` and `GoogleRedirectURL` must be on the host that set the cookie — already true for any normal deployment.
- One browser runs one flow at a time: starting a second `/authorize` overwrites the cookie and abandons the first.

### Restyling the consent page

The built-in page is self-contained (no external stylesheet, script, font or image; strict `Content-Security-Policy`; everything HTML-escaped). To match your own product, set `Config.ConsentHandler`:

```go
ConsentHandler: func(w http.ResponseWriter, r *http.Request, c mcpoauth.Client, req mcpoauth.ConsentRequest) {
	// c.ClientName and req.RedirectURI are attacker-controlled — ESCAPE THEM.
	_ = myTemplate.Execute(w, map[string]any{
		"ClientName":  c.ClientName,
		"RedirectURI": req.RedirectURI, // show it verbatim: it is the thing that matters
		"Scopes":      req.Scopes,
		"Action":      req.FormAction,  // your form must POST here
		"NonceField":  req.NonceField,  // ...with this hidden field...
		"Nonce":       req.Nonce,       // ...carrying this value
	})
}
```

Your handler must not redirect to Google itself — posting the nonce back is what does that.

## Mounting it

### net/http

```go
package main

import (
	"context"
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

		// >= 32 bytes. The HS256 key is DERIVED from this, never used directly.
		JWTSecret:               []byte(os.Getenv("MCP_OAUTH_JWT_SECRET")),
		AccessTokenTTL:          time.Hour,           // default
		RefreshTokenTTL:         30 * 24 * time.Hour, // default (sliding)
		RefreshTokenAbsoluteTTL: 90 * 24 * time.Hour, // default (hard cap)
		AuthCodeTTL:             5 * time.Minute,     // default

		// Optional: bound where a redirect_uri may point (loopback always OK).
		AllowedRedirectHosts: []string{"finance.example.com"},
	}, myStore{db}) // your mcpoauth.Store implementation

	if err != nil {
		log.Fatal(err)
	}

	// Housekeeping: nothing else deletes expired codes, pending requests or
	// refresh tokens. The provider purges opportunistically at most once every
	// Config.PurgeInterval, which is only a backstop for an idle deployment.
	go func() {
		for range time.Tick(10 * time.Minute) {
			if err := provider.PurgeExpired(context.Background()); err != nil {
				log.Printf("mcp oauth purge: %v", err)
			}
		}
	}()

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
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error

	PurgeExpired(ctx context.Context, before time.Time) error

	FindUserIDByEmail(ctx context.Context, email string) (userID string, ok bool, err error)
}
```

`PendingAuth` carries `BinderHash string` and `Approved bool`; `RefreshToken` carries `FamilyID string` and `FamilyCreatedAt time.Time`. Persist and return them like every other field — the provider's binding and family-revocation logic is worthless if they are dropped on the floor.

Four rules:

1. **`Consume*` must be atomic and single-use.** A concurrent second call for the same hash must return `ok=false`. In PostgreSQL that is one statement:

   ```sql
   DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
   RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at;
   ```

2. **`FindUserIDByEmail` must not create users.** Returning `ok=false` is how you refuse a stranger.

3. **`RevokeRefreshTokenFamily` must delete every token sharing the `family_id`** — one `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`. It is called when a rotated-away token is replayed, which is the canonical signal that a refresh token leaked; a no-op implementation silently disables the defence.

4. **`PurgeExpired` must be safe to call concurrently with everything else.** One statement per table:

   ```sql
   DELETE FROM mcp_oauth_auth_codes     WHERE expires_at < $1;
   DELETE FROM mcp_oauth_pending_auth   WHERE expires_at < $1;
   DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < $1;
   ```

   Expiry is still checked by the provider, so `Consume*` may return expired rows — but nothing else deletes them. `/authorize` is unauthenticated, so without a purge the pending table grows forever. **Run `Provider.PurgeExpired` from a ticker** (see the mounting example); the provider's own opportunistic call, throttled to once per `Config.PurgeInterval`, is only a backstop.

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
| `MCP_OAUTH_JWT_SECRET` | input keying material for the access-token signature — **32+ random bytes, required** |
| `PUBLIC_BASE_URL` | the issuer, e.g. `https://finance.example.com` |

`New` rejects a `JWTSecret` shorter than 32 bytes. It may be the same secret your app already uses for session JWTs: the actual signing key is derived from it, so the two can never collide (see below). A separate secret is still preferable.

## Configuration reference (beyond the required URLs)

| Field | Default | What it does |
|---|---|---|
| `JWTSecret` | — | ≥32 bytes; the HS256 key is HKDF-derived from it |
| `AccessTokenTTL` | 1h | access-token lifetime |
| `RefreshTokenTTL` | 30d | sliding refresh lifetime, recomputed on each rotation |
| `RefreshTokenAbsoluteTTL` | 90d | hard cap on a refresh **family**, measured from the login |
| `RefreshReuseWindow` | 24h | how long a rotated-away token hash is remembered for reuse detection |
| `AuthCodeTTL` | 5m | authorization-code lifetime |
| `PendingAuthTTL` | 10m | lifetime of the consent + Google round trip |
| `PurgeInterval` | 5m | throttle on the provider's opportunistic `PurgeExpired` |
| `ConsentHandler` | built-in page | render your own approval page |
| `AllowedRedirectHosts` | empty (any https host) | allowlist of hosts an https `redirect_uri` may point at |
| `InsecureDevMode` | false | plain-http local development: drops `__Host-`/`Secure` from the binder cookie |

## Security model

- **Consent is mandatory and the browser is pinned.** See [Consent and browser binding](#consent-and-browser-binding). `GET /authorize` never reaches Google, and an authorization code is only ever handed to the browser that started — and approved — the request.
- **Only pre-existing users are admitted.** After a successful Google login the email is looked up with `FindUserIDByEmail`. If there is no match, the flow ends in a 403 page explaining that the account is not linked. No user is ever created, and no account is ever silently merged.
- **Google email must be verified** (`email_verified == true`) and the ID token is fully validated: RS256 signature against Google's JWKS (cached for the lifetime the response advertises), `iss ∈ {accounts.google.com, https://accounts.google.com}`, `aud == GoogleClientID`, `exp`. `alg: none`, HS256/RS256 confusion, an unknown `kid` and a missing `kid` are all rejected. If the JWKS endpoint is unreachable a cached key is served for at most **24h past its expiry**, then logins fail closed.
- **Key separation, not just a claim.** The HS256 key is `HKDF-Expand(SHA-256, JWTSecret, "mcpoauth/v1/access-token")` — `JWTSecret` itself never signs or verifies anything. An application that passes the secret it already uses for session JWTs therefore ends up with two unrelated keys: a session token cannot be replayed against the MCP endpoint, **and** an MCP token cannot authenticate a web session, in either direction, even before any claim is inspected.
- **`token_use="mcp_access"`.** Access tokens are HS256 JWTs with `iss`, `sub` (user id), `aud` (the MCP resource URL), `exp`, `iat`, `scope` and `token_use`. Validation requires **all** of signature, issuer, audience, expiry **and** `token_use == "mcp_access"`. As the mirror image, **your own session middleware should reject any token that carries a `token_use` claim** (or require its own distinct value) — belt and braces on top of the derived key.
- **Refresh-token reuse revokes the family.** Rotation is single-use; every token descended from one login shares a `FamilyID`. Replaying a token that was already rotated away — the canonical leak signal — revokes the entire family through `RevokeRefreshTokenFamily`, so a thief's chain dies the moment the legitimate client (or the thief) tries the spent token. Detection uses an in-process ledger of recently consumed hashes (`RefreshReuseWindow`, bounded in size), so it is best-effort across a multi-instance deployment: a store can implement stronger cluster-wide detection underneath.
- **Refresh sessions have an absolute lifetime.** Rotation carries `FamilyCreatedAt` forward, so a stolen token cannot be kept alive indefinitely by rotating it just before expiry. Past `RefreshTokenAbsoluteTTL` the grant is refused and the family revoked; the user signs in again.
- **Nothing secret is stored in the clear.** Authorization codes, refresh tokens, the pending Google state and the browser binder are persisted only as hex SHA-256 hashes. Raw values exist only in flight.
- **Single use, everywhere.** Authorization codes, the consent nonce, pending state and refresh tokens are consumed atomically. A replayed code fails; a rotated refresh token fails. A code is burned even by a *failed* exchange.
- **PKCE S256 is mandatory.** `plain` and a missing `code_challenge_method` are rejected. The `code_challenge` must satisfy RFC 7636 (43–128 characters of `[A-Za-z0-9-._~]`). The verifier is compared in constant time (`crypto/subtle`).
- **Bounded inputs.** `state` is capped at 512 bytes; registration bodies at 16 KiB, with at most 10 redirect URIs of 2048 bytes each and a 200-byte `client_name`. Oversized input is rejected, not truncated.
- **No open redirect.** `redirect_uri` must exactly match one of the client's registered URIs — no prefix, no wildcard, no substring. An unknown `client_id` or a mismatching `redirect_uri` is answered with a direct 400 and never a redirect. Errors are only bounced to a redirect URI after it has been validated.
- **Redirect URI policy at registration:** absolute URL, no fragment, no userinfo, and either `https://` or `http://` on a loopback host (`127.0.0.0/8`, `::1`, `localhost`). Every other `http://` and every custom scheme is refused. `AllowedRedirectHosts` narrows the https case further — **strongly recommended for single-tenant deployments**, because with an empty allowlist anyone may register a client pointing anywhere, which is exactly what the consent page has to warn the user about.
- **Method discipline.** The metadata documents answer `GET`/`HEAD` (and `OPTIONS` preflights) and 405 everything else. `Authorize` accepts only `GET`/`POST` — `HEAD` is refused so it can never mint state — and the Google callback is `GET`-only.
- **Public clients only.** No `client_secret` is issued; `token_endpoint_auth_method` is `none`. PKCE plus exact redirect matching is the protection, per OAuth 2.1 for native apps.
- **All randomness comes from `crypto/rand`** (32 bytes for codes, refresh tokens, state, the consent nonce and the binder; 24 for client ids; 16 for family ids).
- **No secrets in logs or errors.** The package logs nothing, and error strings never contain a token, code, upstream response body or email.
- Token responses always carry `Cache-Control: no-store`.

Things this package deliberately does **not** do: scope negotiation (one fixed scope), client secrets, token introspection/revocation endpoints, rate limiting, or user provisioning.

## API surface

| Symbol | Purpose |
|---|---|
| `New(cfg, store) (*Provider, error)` | validate config, build the provider |
| `Provider.ProtectedResourceMetadata()` | RFC 9728 document |
| `Provider.AuthorizationServerMetadata()` | RFC 8414 document |
| `Provider.Register()` | RFC 7591 dynamic client registration |
| `Provider.Authorize()` | authorization endpoint: GET renders consent, POST approves and goes to Google |
| `Provider.GoogleCallback()` | upstream callback, mints the authorization code |
| `Provider.Token()` | `authorization_code` + `refresh_token` grants |
| `Provider.PurgeExpired(ctx)` | delete expired records — call it from a ticker |
| `Provider.Middleware(next)` | protects the MCP endpoint |
| `Provider.ValidateAccessToken(s)` | validate a token yourself (for chaining) |
| `Provider.Unauthorized(w)` | emit the standard 401 challenge |
| `Provider.ProtectedResourceMetadataURL()` | the URL used in that challenge |
| `UserIDFromContext(ctx)` | read the authenticated user id |
| `BearerToken(r)` | extract an `Authorization: Bearer` value |
| `ValidateRedirectURI(s)` | the redirect-URI policy, exported for reuse |
| `HashSecret(s)` | the SHA-256 hashing used by the store contract |
| `ConsentRequest`, `ConsentNonceField` | what a custom `ConsentHandler` renders and posts back |
| `BinderCookieName`, `BinderCookieNameInsecure` | the browser-binding cookie names |

The metadata and registration endpoints answer `OPTIONS` preflights and send `Access-Control-Allow-Origin: *`; MCP clients fetch them cross-origin.

## Tests

```
go test ./...
```

Table-driven throughout. Google is mocked with `httptest`, including a JWKS document and RS256-signed ID tokens.

Functional coverage: PKCE success/failure, authorization-code single use and expiry, redirect-URI mismatch, unregistered clients, `plain` challenge rejection, refresh rotation, access-token claim validation (wrong `aud`/`iss`, expired, wrong `token_use`, `alg: none`, wrong secret), the registration redirect-URI policy, and the unknown-email 403.

Adversarial coverage, one suite per finding:

- **Google ID-token forgery** — rogue RSA key, `alg: none`, HS256 signed with the JWKS modulus, unknown `kid`, absent/empty `kid`, plus a passing control; and the bounded stale-JWKS fallback.
- **Authorization hijack** — an attacker-registered client phishing a victim: the flow dies at the callback for every variant of "wrong browser", the pending record is burned so it cannot be retried, no code is ever delivered to the attacker's redirect URI and no token is mintable.
- **Consent** — GET does not redirect to Google and its record is unusable on its own; approval is rejected without a nonce, with a forged nonce, with another flow's nonce, without the binder cookie and with someone else's; the nonce is single-use; hostile `client_name`/`redirect_uri` are escaped; a custom `ConsentHandler` is exercised end to end.
- **Refresh families** — reuse revokes the family and stops the attacker's chain, revocation does not leak across families, honest rotation is unaffected; the absolute lifetime cap is enforced and does not slide.
- **Config and input validation** — short `JWTSecret` rejected, the derived key differs from the input and neither verifies the other's tokens, `code_challenge` charset/length, oversized `state` and registration payloads, the redirect-host allowlist.
- **Concurrency and methods** — 32 goroutines double-spending an authorization code and a refresh token (exactly one wins), and the 405 behaviour of every endpoint.

`go test -race ./...` is green.

## License

MIT
