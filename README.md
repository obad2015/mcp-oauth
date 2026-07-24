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
   | value | up to 5 binders, `.`-separated, newest first — each 32 random bytes, base64url. Only the SHA-256 of one binder is persisted, on the `PendingAuth` row |
   | flags | `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain` |

   `GoogleCallback` refuses to mint an authorization code unless the browser presents a cookie containing the binder that matches the pending record (constant-time compare against each value), and burns the record either way. This kills the cross-browser variant even if consent were bypassed. Only the binder a finished flow used is removed from the cookie; the others stay.

   The cookie holds a *list* so that several flows can be in progress in one browser. A browser keeps only one cookie per name, so a single-valued cookie meant that opening a second `/authorize` (a second tab, or a retry) silently broke the first one.

What this requires of your deployment:

- **HTTPS.** `__Host-` and `Secure` mean the cookie only travels over TLS. For plain-http local development set `Config.InsecureDevMode = true` — `New` only accepts it when `Issuer` is `http://` on a loopback host, so it cannot be left on by accident.
- **The cookie must survive the Google round trip.** `SameSite=Lax` is correct and deliberate: the return from Google is a top-level `GET` navigation, which `Lax` allows and `Strict` would block. Do not tighten it.
- **Same origin throughout.** `AuthorizeURL` and `GoogleRedirectURL` must be on the host that set the cookie — already true for any normal deployment.
- Up to 5 authorization flows can be in progress in one browser at once. Starting a sixth pushes the oldest binder out of the cookie, abandoning that flow.

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

	// REQUIRED at startup. Round-trips canary records through your Store and
	// fails loudly if a field or a guarantee did not survive. A Store that
	// drops BinderHash, FamilyID, FamilyCreatedAt or ConsumedAt keeps working
	// perfectly while silently disabling a security control — this is the only
	// thing that catches that.
	if err := provider.VerifyStore(context.Background()); err != nil {
		log.Fatal(err)
	}

	// Housekeeping: nothing else deletes expired codes, pending requests,
	// refresh tokens or stale client registrations. The provider purges
	// opportunistically at most once every Config.PurgeInterval, which is only
	// a backstop for an idle deployment.
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
	SaveClient(ctx context.Context, c Client) error   // upsert on ClientID
	GetClient(ctx context.Context, clientID string) (Client, bool, error)

	SaveAuthCode(ctx context.Context, code AuthCode) error
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCode, bool, error)

	SavePendingAuth(ctx context.Context, p PendingAuth) error
	ConsumePendingAuth(ctx context.Context, stateHash string) (PendingAuth, bool, error)

	SaveRefreshToken(ctx context.Context, rt RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, bool, error)
	ConsumeRefreshToken(ctx context.Context, tokenHash string, consumedAt time.Time) (RefreshToken, bool, error)
	LinkRefreshSuccessor(ctx context.Context, tokenHash, familyID string, sealed []byte) error
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error

	PurgeExpired(ctx context.Context, before time.Time) error

	FindUserIDByEmail(ctx context.Context, email string) (userID string, ok bool, err error)
}
```

**Every field of every struct must round-trip.** Dropping one does not break the flow, it disables a defence:

| Field | Dropping it means |
|---|---|
| `PendingAuth.BinderHash` | the browser binding is gone — the authorization hijack works again |
| `PendingAuth.Approved` | the consent step can be skipped |
| `RefreshToken.FamilyID` | reuse detection has nothing to revoke |
| `RefreshToken.FamilyCreatedAt` | the absolute session cap turns back into a session that slides forever |
| `RefreshToken.FamilyExpiresAt` | consumed rows are purged early, so reuse stops being detectable |
| `RefreshToken.ConsumedAt` | a replayed refresh token looks like a first use — no detection at all |
| `RefreshToken.SuccessorSealed` | a duplicate refresh submission logs the client out |
| `Client.ExpiresAt` | client registrations become permanent and unbounded |

`Provider.VerifyStore(ctx)` checks all of this at startup. **Call it. Treat a failure as fatal.**

### Suggested PostgreSQL schema

```sql
CREATE TABLE mcp_oauth_clients (
    client_id      TEXT PRIMARY KEY,
    redirect_uris  JSONB       NOT NULL,
    client_name    TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE mcp_oauth_refresh_tokens (
    token_hash        TEXT PRIMARY KEY,
    client_id         TEXT        NOT NULL,
    user_id           TEXT        NOT NULL,
    family_id         TEXT        NOT NULL,
    family_created_at TIMESTAMPTZ NOT NULL,
    family_expires_at TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,          -- NULL = never used
    successor_sealed  BYTEA                 -- opaque; store verbatim
);
CREATE INDEX ON mcp_oauth_refresh_tokens (family_id);
```

(`mcp_oauth_auth_codes` and `mcp_oauth_pending_auth` are the obvious column-per-field tables, keyed by `code_hash` / `state_hash`.)

Six rules:

1. **`ConsumeAuthCode` and `ConsumePendingAuth` must be atomic and single-use.** A concurrent second call for the same hash must return `ok=false`. In PostgreSQL that is one statement:

   ```sql
   DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
   RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at;
   ```

2. **`ConsumeRefreshToken` must NOT delete.** This is the one that changed, and the one that matters most. The row *is* the reuse-detection ledger: it is stamped, kept, and only removed by `PurgeExpired`. It must return the row **as it was before the call**, so the provider can tell the three cases apart:

   | return | meaning |
   |---|---|
   | `ok=false` | never issued, or the family is already revoked/purged → `invalid_grant` |
   | `ok=true`, `ConsumedAt` zero | first use → a legitimate rotation |
   | `ok=true`, `ConsumedAt` set | replay → duplicate submission (inside `RefreshGracePeriod`) or **reuse**, which revokes the family |

   `consumed_at` must be stamped exactly once (never overwritten) and exactly one of N concurrent callers may see it unset:

   ```sql
   WITH before AS (
       SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE
   ), stamped AS (
       UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
       WHERE token_hash = $1 AND consumed_at IS NULL
   )
   SELECT * FROM before;
   ```

   This is what makes detection **durable**: it survives a restart, and it cannot be evicted by an attacker who rotates a stolen token in a loop.

3. **`LinkRefreshSuccessor` attaches the sealed successor and re-stamps the family**, on the row that was just consumed. `sealed` is an opaque encrypted blob — persist the bytes, return them unchanged, never interpret them. Only a caller presenting the raw predecessor token can decrypt it, so a dump of this table reveals no tokens.

   ```sql
   UPDATE mcp_oauth_refresh_tokens
   SET family_id = $2, successor_sealed = $3
   WHERE token_hash = $1;   -- unknown hash: no-op, return nil
   ```

4. **`RevokeRefreshTokenFamily` must delete every token sharing the `family_id`**, consumed rows included — one `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`. It is called when a rotated-away token is replayed, which is the canonical signal that a refresh token leaked; a no-op implementation silently disables the defence.

5. **`FindUserIDByEmail` must not create users.** Returning `ok=false` is how you refuse a stranger.

6. **`PurgeExpired` must be safe to call concurrently with everything else**, and it now covers four tables. Note the refresh-token condition: a consumed row is retained until its **family** dies, which is much later than its own `expires_at`.

   ```sql
   DELETE FROM mcp_oauth_auth_codes     WHERE expires_at < $1;
   DELETE FROM mcp_oauth_pending_auth   WHERE expires_at < $1;
   DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < $1 AND family_expires_at < $1;
   DELETE FROM mcp_oauth_clients        WHERE expires_at < $1;
   ```

   Expiry is still checked by the provider, so `Consume*` may return expired rows — but nothing else deletes them. `/authorize` and `/register` are unauthenticated, so without a purge those tables grow forever. **Run `Provider.PurgeExpired` from a ticker** (see the mounting example); the provider's own opportunistic call, throttled to once per `Config.PurgeInterval`, is only a backstop.

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

`New` rejects a `JWTSecret` shorter than 32 bytes, and also one that uses fewer than 8 distinct byte values — `"aaaa…"` padded to length is a placeholder, not a secret. Neither check measures entropy; nothing can. Generate it properly: `openssl rand -base64 32`.

It may be the same secret your app already uses for session JWTs: the actual signing key is derived from it, so the two can never collide (see below). A separate secret is still preferable.

## Configuration reference (beyond the required URLs)

| Field | Default | What it does |
|---|---|---|
| `JWTSecret` | — | ≥32 bytes and ≥8 distinct byte values; the HS256 key is HKDF-derived from it |
| `AccessTokenTTL` | 1h | access-token lifetime |
| `RefreshTokenTTL` | 30d | sliding refresh lifetime, recomputed on each rotation |
| `RefreshTokenAbsoluteTTL` | 90d | hard cap on a refresh **family**, measured from the login. Also how long consumed rows are retained for reuse detection |
| `RefreshGracePeriod` | 30s | window in which re-presenting the token that was *just* rotated away returns the same successor instead of revoking the family. Negative disables it |
| `AuthCodeTTL` | 5m | authorization-code lifetime |
| `PendingAuthTTL` | 10m | lifetime of the consent + Google round trip |
| `UnusedClientTTL` | 24h | how long a registered client that never completed a login is kept |
| `ClientTTL` | 90d | how long a client is kept after its most recent completed login |
| `PurgeInterval` | 5m | throttle on the provider's opportunistic `PurgeExpired` |
| `ConsentHandler` | built-in page | render your own approval page |
| `AllowedRedirectHosts` | empty (any https host) | allowlist of hosts an https `redirect_uri` may point at |
| `InsecureDevMode` | false | plain-http local development: drops `__Host-`/`Secure` from the binder cookie. `New` rejects it unless `Issuer` is `http://` on a loopback host |

`RefreshReuseWindow` no longer exists. Reuse detection is not time-bounded any more: it lasts as long as the family does (`RefreshTokenAbsoluteTTL`) and lives in the Store rather than in process memory.

### Rate-limit `/register`

Dynamic client registration is unauthenticated by design — an MCP CLI client on a random loopback port cannot pre-register. `UnusedClientTTL` bounds how long the junk lives, but it does not bound how fast it arrives. Put a rate limit in front of the endpoint at the proxy:

```nginx
limit_req_zone $binary_remote_addr zone=mcp_register:10m rate=10r/m;

location = /api/mcp/oauth/register {
    limit_req zone=mcp_register burst=5 nodelay;
    proxy_pass http://api:8080;
}
```

The authorization endpoint is worth the same treatment (a looser rate), since `GET /authorize` also writes a pending row.

## Security model

- **Consent is mandatory and the browser is pinned.** See [Consent and browser binding](#consent-and-browser-binding). `GET /authorize` never reaches Google, and an authorization code is only ever handed to the browser that started — and approved — the request.
- **Only pre-existing users are admitted.** After a successful Google login the email is looked up with `FindUserIDByEmail`. If there is no match, the flow ends in a 403 page explaining that the account is not linked. No user is ever created, and no account is ever silently merged.
- **Google email must be verified** (`email_verified == true`) and the ID token is fully validated: RS256 signature against Google's JWKS (cached for the lifetime the response advertises), `iss ∈ {accounts.google.com, https://accounts.google.com}`, `aud == GoogleClientID`, `exp`. `alg: none`, HS256/RS256 confusion, an unknown `kid` and a missing `kid` are all rejected. If the JWKS endpoint is unreachable a cached key is served for at most **24h past its expiry**, then logins fail closed.
- **Key separation, not just a claim.** The HS256 key is `HKDF-Expand(SHA-256, JWTSecret, "mcpoauth/v1/access-token")` — `JWTSecret` itself never signs or verifies anything. An application that passes the secret it already uses for session JWTs therefore ends up with two unrelated keys: a session token cannot be replayed against the MCP endpoint, **and** an MCP token cannot authenticate a web session, in either direction, even before any claim is inspected.
- **`token_use="mcp_access"`.** Access tokens are HS256 JWTs with `iss`, `sub` (user id), `aud` (the MCP resource URL), `exp`, `iat`, `scope` and `token_use`. Validation requires **all** of signature, issuer, audience, expiry **and** `token_use == "mcp_access"`. As the mirror image, **your own session middleware should reject any token that carries a `token_use` claim** (or require its own distinct value) — belt and braces on top of the derived key.
- **Refresh-token reuse revokes the family, durably.** Rotation is single-use; every token descended from one login shares a `FamilyID`. Replaying a token that was already rotated away — the canonical leak signal — revokes the entire family through `RevokeRefreshTokenFamily`, so a thief's chain dies the moment the legitimate client (or the thief) tries the spent token. Detection state is the refresh-token row itself: consuming a token **stamps** `ConsumedAt` rather than deleting the row, and the row is retained until the family expires. It therefore survives a process restart or a redeploy, works across instances, and cannot be evicted — the old in-process ledger was capped at 4096 entries, so a thief could rotate a stolen token in a loop to flush out the evidence of their own theft.
- **A refresh token with no family fails closed.** Rotating a row whose `FamilyID` is empty (written by older code, or by a Store that drops the column) mints a *fresh* family rather than propagating the emptiness, and stamps it back onto the consumed predecessor — so a later replay still revokes the chain it spawned. A row with no family timestamps at all is refused outright.
- **Duplicate refresh submissions do not log you out.** A client that loses the rotation response, retries, or fires two requests at once used to destroy its own session: the retry looked exactly like a replay and revoked the family. Inside `RefreshGracePeriod` (30s) the token that was *just* rotated away is answered with the very same successor instead. The window is deliberately narrow: it applies only to the single most-recently-consumed token of a family, only while its successor is still unused, and only to the same `client_id`; anything older, anything later, or a family that has already moved on is treated as reuse. The successor is recovered by decrypting a blob sealed with a key derived from the presented token, so this costs no plaintext at rest — the database still holds nothing but hashes. Set `RefreshGracePeriod` negative for strict, zero-tolerance detection.
- **Client registrations are leases.** `/register` is unauthenticated, so a registration that never completes a login is purged after `UnusedClientTTL` (24h) and one that has is kept for `ClientTTL` (90d) from its last login. Expiry is not a lockout — MCP clients re-register automatically. Rate-limit the endpoint at your proxy as well; see above.
- **`InsecureDevMode` cannot be switched on in production.** It weakens the binder cookie, so `New` refuses it unless `Issuer` is an `http://` URL on `127.0.0.1`, `::1` or `localhost`.
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
| `Provider.VerifyStore(ctx) error` | **call at startup**: round-trips canaries through the Store and reports every dropped field or broken guarantee |
| `Provider.ProtectedResourceMetadata()` | RFC 9728 document |
| `Provider.AuthorizationServerMetadata()` | RFC 8414 document |
| `Provider.Register()` | RFC 7591 dynamic client registration |
| `Provider.Authorize()` | authorization endpoint: GET renders consent, POST approves and goes to Google |
| `Provider.GoogleCallback()` | upstream callback, mints the authorization code |
| `Provider.Token()` | `authorization_code` + `refresh_token` grants |
| `Provider.PurgeExpired(ctx)` | delete expired records (codes, pending, dead token families, stale clients) — call it from a ticker |
| `Provider.Middleware(next)` | protects the MCP endpoint |
| `Provider.ValidateAccessToken(s)` | validate a token yourself (for chaining) |
| `Provider.Unauthorized(w)` | emit the standard 401 challenge |
| `Provider.ProtectedResourceMetadataURL()` | the URL used in that challenge |
| `UserIDFromContext(ctx)` | read the authenticated user id |
| `BearerToken(r)` | extract an `Authorization: Bearer` value |
| `ValidateRedirectURI(s)` | the redirect-URI policy, exported for reuse |
| `HashSecret(s)` | the SHA-256 hashing used by the store contract |
| `ConsentRequest`, `ConsentNonceField` | what a custom `ConsentHandler` renders and posts back |
| `BinderCookieName`, `BinderCookieNameInsecure`, `BinderCookieSep` | the browser-binding cookie names, and the separator between the binders of concurrent flows |

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
- **Durable reuse detection** — the replay is still caught after 6000 rotations of the stolen chain (the old bounded ledger was flushed by exactly this), after a process restart onto the same Store, after 45 days, and after all three at once; a familyless token is re-familied rather than opted out; consumed rows survive a purge until their family dies.
- **Refresh grace window** — a duplicate submission gets the same refresh token back and keeps its session; 32 concurrent grants leave exactly one usable token and it still works; a two-step-stale token, another client, or a replay past the window all revoke the family; the sealed successor is not recoverable from the stored row.
- **`VerifyStore`** — ten deliberately broken Stores (dropping `BinderHash`, `FamilyID`, `FamilyCreatedAt`, `FamilyExpiresAt`, `SuccessorSealed`; deleting on consume; never stamping `ConsumedAt`; returning the post-update row; a replayable auth code; a purge that forgets clients) are each caught with a message naming the fault — and a compliant Store passes, twice, leaving nothing behind.
- **Lifecycle** — `InsecureDevMode` is rejected against https and non-loopback issuers and accepted for loopback http; unused client registrations are purged and used ones are not; two authorization flows in one browser both complete, while an evicted or foreign binder is still refused.
- **Config and input validation** — short *and* low-entropy `JWTSecret` rejected, the derived key differs from the input and neither verifies the other's tokens, `code_challenge` charset/length, oversized `state` and registration payloads, the redirect-host allowlist.
- **Concurrency and methods** — 32 goroutines double-spending an authorization code and a refresh token (exactly one wins), and the 405 behaviour of every endpoint.

`go test -race ./...` is green.

## License

MIT
