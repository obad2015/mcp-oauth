# mcp-oauth

Turn any Go HTTP application into an **OAuth 2.1 authorization server for its MCP endpoint**, with **Google as the upstream login**.

Your app mints its **own** MCP access tokens. Google is only the identity step — it answers "who is this person", nothing more.

```
go get github.com/obad2015/mcp-oauth
```

Standard library + `github.com/golang-jwt/jwt/v5`. No web framework: every entry point is a plain `http.Handler` / `http.HandlerFunc`, so it drops into `net/http`, Echo, Gin, chi, whatever. Persistence is `github.com/obad2015/mcp-oauth/pgstore` (PostgreSQL over `database/sql`, no driver dependency); the only method your application writes is the one that looks up a user by email.

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

- **HTTPS.** `__Host-` and `Secure` mean the cookie only travels over TLS. For plain-http local development set `Config.InsecureDevMode = true` — `New` only accepts it when **every** configured URL is `http://` on a loopback host, so it cannot be left on by accident.
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
	}, store) // pgstore.New(db, pgstore.WithUserLookup(...)) — see "Persistence"

	if err != nil {
		log.Fatal(err)
	}

	// Creates/upgrades the four mcp_oauth_* tables. Idempotent.
	if err := store.EnsureSchema(context.Background()); err != nil {
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

## Persistence

The package ships its own PostgreSQL store, so you implement **one** method:

```go
import "github.com/obad2015/mcp-oauth/pgstore"

store, err := pgstore.New(db, pgstore.WithUserLookup(
	// The ONLY method that is yours, because only you know your users table.
	// It must never create a user: ok=false is how a stranger is refused.
	// Compare case-insensitively — see below.
	func(ctx context.Context, email string) (string, bool, error) {
		var id string
		err := db.QueryRowContext(ctx,
			`SELECT id::text FROM users WHERE LOWER(email) = LOWER($1)`, email).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return id, err == nil, err
	}))
if err != nil {
	log.Fatal(err)
}

// Creates and upgrades the four mcp_oauth_* tables. Idempotent, safe at every
// startup, safe from several instances at once, and it adopts a database whose
// tables an earlier migration of yours created.
if err := store.EnsureSchema(ctx); err != nil {
	log.Fatal(err)
}
```

`db` is a plain `*sql.DB`, so `pgstore` has no driver dependency of its own:

- **lib/pq** — pass your `*sql.DB` directly.
- **pgx/v5** — `stdlib.OpenDBFromPool(pool)`, one line.

Two things about that lookup are load-bearing:

- **It must not create users.** Anything else is silent account provisioning: whoever controls a Google address controls a new account in your app.
- **`LOWER()` on both sides.** The provider lowercases the verified Google email before calling you, while most signup paths store whatever casing Google returned. A plain `=` therefore locks out every user whose stored address has an uppercase character. This is a fixed production bug, not a micro-optimisation to undo.

Applications that own their DDL through a migration tool can use `pgstore.SchemaSQL` instead of `EnsureSchema` — but then the versioned upgrade steps are yours to carry too, and `EnsureSchema` is the supported path.

`github.com/obad2015/mcp-oauth/memstore` is an in-memory `Store` for tests and local development.

### Writing your own Store

`mcpoauth.Store` stays public for backends `pgstore` cannot serve. It is a small interface with a very unforgiving contract: four of its clauses are individually load-bearing, and getting one wrong disables a security control **while the OAuth flow keeps working perfectly**. That is the whole reason this library ships a store at all.

If you need to write one, everything you have to know is in **[STORE-CONTRACT.md](STORE-CONTRACT.md)** — the eight rules, the schema constraints, and `Provider.VerifyStore`, which round-trips canary records through your implementation and names every field or guarantee that did not survive. Run it from your test suite, against the real backend.

## Upgrading to v2

Two breaking changes, both in the same release, both absorbed by one small PR per application. **No user is logged out**: refresh-token rows, hashes and families are untouched, and a token issued by v1 keeps rotating in its own family straight through the upgrade.

1. **Swap your `Store` for `pgstore`.** Delete your `oauth.go` (~300 lines of transcribed SQL) and replace the `VerifyStore` call at startup with `EnsureSchema`, as shown under [Persistence](#persistence). Keep your existing `mcp_oauth_*` migrations as history — `EnsureSchema` adopts the tables they created.
2. **`Store` lost `LinkRefreshSuccessor`, and `RefreshToken` lost `SuccessorSealed`.** v1 sealed a rotation's successor onto the consumed predecessor row with AES-GCM so a duplicate submission could be answered even after a restart. v2 keeps that link in process instead, because losing it fails *safe* — the duplicate simply cannot be answered and the client signs in once — while the thing that must be durable, the `consumed_at` reuse ledger, has not moved. `EnsureSchema` drops the now-unused `successor_sealed` column as its first versioned step; nothing reads it, so there is nothing to restore on a rollback.

Also worth knowing: `VerifyStore` is no longer a startup ritual. It is a contract check for custom-`Store` authors, run from a test suite; `pgstore` is verified by this repository's CI against a real PostgreSQL server on every push.

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
| `RefreshGracePeriod` | 30s | window in which re-presenting the token that was *just* rotated away returns the same successor instead of revoking the family. The link is in-process, so a duplicate arriving after a restart or on another instance costs one re-login and nothing more. Negative disables it |
| `AuthCodeTTL` | 5m | authorization-code lifetime |
| `PendingAuthTTL` | 10m | lifetime of the consent + Google round trip |
| `UnusedClientTTL` | 24h | how long a registered client that never completed a login is kept |
| `ClientTTL` | 90d | how long a client is kept after its most recent completed login |
| `PurgeInterval` | 5m | throttle on the provider's opportunistic `PurgeExpired` |
| `ConsentHandler` | built-in page | render your own approval page |
| `AllowedRedirectHosts` | empty (any https host) | allowlist of hosts an https `redirect_uri` may point at |
| `InsecureDevMode` | false | plain-http local development: drops `__Host-`/`Secure` from the binder cookie. `New` rejects it unless **every** configured URL (`Issuer`, `ResourceURL`, `MetadataBaseURL`, `AuthorizeURL`, `TokenURL`, `RegisterURL`, `GoogleRedirectURL`) is `http://` on a loopback host |
| `VerifyStoreUserID` | `"mcpoauth-verify-user"` | the user ID `VerifyStore` writes on its canary rows. Only relevant if you run `VerifyStore` against a **custom** Store whose `user_id` column is `UUID`. Must not be a real user |

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
- **A refresh token is bound to its client before it is consumed.** A refresh grant presented with a `client_id` other than the one the token was issued to is refused *without* stamping `consumed_at`. Consuming first meant anyone who merely learned a refresh token could burn it with an arbitrary `client_id`, so the owner's next legitimate use was classified as reuse and killed the family — an unauthenticated logout of the victim, and a self-inflicted one on a typo. A client mismatch never revokes anything; a replay by the rightful client still does.
- **A refresh token with no family fails closed.** Rotating a row whose `FamilyID` is empty (written by older code, or by a Store that drops the column) starts a family rather than propagating the emptiness. That family is *derived* from the row's own token hash, not random, so a later replay of that same familyless token recomputes it and still revokes the chain it spawned — with no extra write and no extra Store method. A row with no family timestamps at all is refused outright.
- **Duplicate refresh submissions do not log you out.** A client that loses the rotation response, retries, or fires two requests at once used to destroy its own session: the retry looked exactly like a replay and revoked the family. Inside `RefreshGracePeriod` (30s) the token that was *just* rotated away is answered with the very same successor instead. The window is deliberately narrow: it applies only to the single most-recently-consumed token of a family, only while its successor is still unused, and only to the same `client_id`; anything older, anything later, or a family that has already moved on is treated as reuse. It is bounded only on the *late* side — a duplicate whose clock runs behind the request that won the race is exactly what the window exists for, and on a multi-node deployment that is ordinary clock skew. The predecessor → successor link is held **in process**, capped and swept, so the database still holds nothing but hashes and there is no plaintext at rest anywhere. Losing that link (a restart, another instance) is not a security event: the duplicate simply cannot be answered, and it costs one re-login. The ledger it is judged against — the durable `consumed_at` stamp — is unaffected, so the window can never widen. Set `RefreshGracePeriod` negative for strict, zero-tolerance detection.
- **Client registrations are leases.** `/register` is unauthenticated, so a registration that never completes a login is purged after `UnusedClientTTL` (24h) and one that has is kept for `ClientTTL` (90d) from its last login. Expiry is not a lockout — MCP clients re-register automatically. Rate-limit the endpoint at your proxy as well; see above.
- **`InsecureDevMode` cannot be switched on in production.** It weakens the binder cookie, so `New` refuses it unless **every** configured URL — `Issuer`, `ResourceURL`, `MetadataBaseURL`, `AuthorizeURL`, `TokenURL`, `RegisterURL` and `GoogleRedirectURL` — is an `http://` URL on `127.0.0.1`, `::1` or `localhost`. Checking `Issuer` alone was not enough: a loopback issuer alongside a public https deployment stripped `__Host-`/`Secure` from the cookie on the real origin.
- **Refresh sessions have an absolute lifetime.** Rotation carries `FamilyCreatedAt` forward, so a stolen token cannot be kept alive indefinitely by rotating it just before expiry. Past `RefreshTokenAbsoluteTTL` the grant is refused and the family revoked; the user signs in again.
- **Reuse detection cannot be undone by a rotation already in flight.** A rotation persists its successor *before* it becomes answerable to a duplicate, and then re-reads the predecessor. If a concurrent reuse detection revoked the family in between, the predecessor is gone — so the rotation revokes the family it just issued into and fails, instead of silently resurrecting a dead family with a fresh live row while the victim stays evicted.
- **Nothing secret is stored in the clear.** Authorization codes, refresh tokens, the pending Google state and the browser binder are persisted only as hex SHA-256 hashes. Raw values exist only in flight.
- **Single use, everywhere.** Authorization codes, the consent nonce, pending state and refresh tokens are consumed atomically. A replayed code fails; a rotated refresh token fails. A code is burned even by a *failed* exchange.
- **PKCE S256 is mandatory.** `plain` and a missing `code_challenge_method` are rejected. The `code_challenge` must satisfy RFC 7636 (43–128 characters of `[A-Za-z0-9-._~]`). The verifier is compared in constant time (`crypto/subtle`).
- **Bounded inputs.** `state` is capped at 512 bytes; registration bodies at 16 KiB, with at most 10 redirect URIs of 2048 bytes each and a 200-byte `client_name`. Oversized input is rejected, not truncated.
- **No open redirect.** `redirect_uri` must exactly match one of the client's registered URIs — no prefix, no wildcard, no substring. An unknown `client_id` or a mismatching `redirect_uri` is answered with a direct 400 and never a redirect. Errors are only bounced to a redirect URI after it has been validated.
- **Redirect URI policy at registration:** absolute URL, no fragment, no userinfo, and either `https://` or `http://` on a loopback host (`127.0.0.0/8`, `::1`, `localhost`). Every other `http://` and every custom scheme is refused. `AllowedRedirectHosts` narrows the https case further — **strongly recommended for single-tenant deployments**, because with an empty allowlist anyone may register a client pointing anywhere, which is exactly what the consent page has to warn the user about.
- **Method discipline.** The metadata documents answer `GET`/`HEAD` (and `OPTIONS` preflights) and 405 everything else. `Authorize` accepts only `GET`/`POST` — `HEAD` is refused so it can never mint state — and the Google callback is `GET`-only.
- **Public clients only.** No `client_secret` is issued; `token_endpoint_auth_method` is `none`. PKCE plus exact redirect matching is the protection, per OAuth 2.1 for native apps.
- **All randomness comes from `crypto/rand`** (32 bytes for codes, refresh tokens, state, the consent nonce and the binder; 24 for client ids; 16 for family ids). Family ids are internal revocation keys only — never accepted from a caller.
- **No secrets in logs or errors.** The package logs nothing, and error strings never contain a token, code, upstream response body or email.
- Token responses always carry `Cache-Control: no-store`.

Things this package deliberately does **not** do: scope negotiation (one fixed scope), client secrets, token introspection/revocation endpoints, rate limiting, or user provisioning.

## API surface

| Symbol | Purpose |
|---|---|
| `New(cfg, store) (*Provider, error)` | validate config, build the provider |
| `Provider.VerifyStore(ctx) error` | contract check for **custom** `Store` implementations: round-trips canaries and reports every dropped field or broken guarantee. Run it from your tests; `pgstore` users do not need it |
| `pgstore.New(db, opts...) (*Store, error)` | the PostgreSQL `Store`; `pgstore.WithUserLookup(fn)` supplies the one application-owned method |
| `pgstore.EnsureSchema(ctx, db)` / `(*Store).EnsureSchema(ctx)` | create and upgrade the four tables, idempotently |
| `pgstore.SchemaSQL` | the DDL, for applications that own their own migrations |
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
go test ./...                                                   # no database needed
MCPOAUTH_TEST_POSTGRES='postgres://...' go test -race ./...     # + the PostgreSQL contract suite
```

Table-driven throughout. Google is mocked with `httptest`, including a JWKS document and RS256-signed ID tokens. The PostgreSQL suites skip themselves when `MCPOAUTH_TEST_POSTGRES` is unset; CI runs them against a `postgres:17` service container on every push.

Functional coverage: PKCE success/failure, authorization-code single use and expiry, redirect-URI mismatch, unregistered clients, `plain` challenge rejection, refresh rotation, access-token claim validation (wrong `aud`/`iss`, expired, wrong `token_use`, `alg: none`, wrong secret), the registration redirect-URI policy, and the unknown-email 403.

Adversarial coverage, one suite per finding:

- **Google ID-token forgery** — rogue RSA key, `alg: none`, HS256 signed with the JWKS modulus, unknown `kid`, absent/empty `kid`, plus a passing control; and the bounded stale-JWKS fallback.
- **Authorization hijack** — an attacker-registered client phishing a victim: the flow dies at the callback for every variant of "wrong browser", the pending record is burned so it cannot be retried, no code is ever delivered to the attacker's redirect URI and no token is mintable.
- **Consent** — GET does not redirect to Google and its record is unusable on its own; approval is rejected without a nonce, with a forged nonce, with another flow's nonce, without the binder cookie and with someone else's; the nonce is single-use; hostile `client_name`/`redirect_uri` are escaped; a custom `ConsentHandler` is exercised end to end.
- **Refresh families** — reuse revokes the family and stops the attacker's chain, revocation does not leak across families, honest rotation is unaffected; the absolute lifetime cap is enforced and does not slide.
- **Durable reuse detection** — the replay is still caught after 6000 rotations of the stolen chain (the old bounded ledger was flushed by exactly this), after a process restart onto the same Store, after 45 days, and after all three at once; a familyless token is re-familied rather than opted out; consumed rows survive a purge until their family dies.
- **Refresh grace window** — a duplicate submission gets the same refresh token back and keeps its session; 32 concurrent grants leave exactly one usable token and it still works; a two-step-stale token or a replay past the window revokes the family; the window is anchored to the first `consumed_at` and does not roll; neither raw token is recoverable from anything the Store holds; a duplicate the process cannot answer (a restart mid-window) is retried rather than treated as reuse, and detection resumes unchanged the moment the window closes; the grace cache expires, stays under its cap, and holds nothing at all when the window is disabled.
- **Store fault injection** — the highest-value suite, because it is how an insecure deployment actually happens. A compliant Store is wrapped and exactly ONE rule is broken per case: dropping `BinderHash`, `Approved`, `FamilyID`, `FamilyCreatedAt` or `FamilyExpiresAt`; deleting on consume; never stamping `ConsumedAt`; returning the post-update row; **overwriting** `ConsumedAt` (the missing `AND consumed_at IS NULL`); filtering expired rows out of the consume; a `GetRefreshToken` that hides consumed rows; `SavePendingAuth` upserting on `client_id` and losing a record; a replayable auth code; a no-op `RevokeRefreshTokenFamily`; a purge that forgets clients. Every one is caught with a message naming the fault — and a compliant Store passes, twice, leaving nothing behind and disturbing no real rows.
- **The PostgreSQL contract suite** (`MCPOAUTH_TEST_POSTGRES`) — the same rules, on the medium that ships. `pgstore` is put through `VerifyStore` and through direct assertions of each load-bearing invariant: the `ConsumeRefreshToken` CTE under 16 concurrent callers (exactly one sees a zero `ConsumedAt`) and under replay (the ORIGINAL stamp comes back, and is never re-written); the unfiltered `GetRefreshToken`; single-use authorization codes and pending state, including 8 goroutines racing one code; `PurgeExpired` retaining a row until BOTH its own and its family's expiry; and the token endpoint driven end to end over real SQL. Then ten pieces of plausible-but-wrong **real SQL** — the missing `AND consumed_at IS NULL`, `UPDATE ... RETURNING`, `DELETE ... RETURNING`, an expiry filter, a `SELECT`-then-`UPDATE` with no `FOR UPDATE`, a filtered `GetRefreshToken`, a purge missing half its condition or a whole table, a `client_id`-keyed pending upsert, a read-only auth-code consume — each of which `VerifyStore` has to name.
- **Schema adoption** — `pgstore.EnsureSchema` builds the schema from nothing, is idempotent, survives 8 instances booting at once, and adopts a database created by the consumers' own hand-written migrations: it drops the retired `successor_sealed` column, and a refresh token issued by v1 keeps rotating in the same family across the upgrade, with reuse detection intact. Nobody is logged out by the deploy.
- **`VerifyStore` canaries** — 40 verifications run against a hot `PurgeExpired` ticker with no false positive, four concurrent verifications (a rolling deploy) all pass, `Config.VerifyStoreUserID` reaches every canary row, and the canary `client_id` stays within the 48 characters the README promises.
- **Refresh rotation races** — a duplicate whose clock runs *behind* the winner's is absorbed rather than revoking the family (the bug behind this suite's own historic flake); 10 × 32 concurrent refreshes of one token always leave exactly one usable chain and never revoke; a reuse detection that fires mid-rotation is not undone by the in-flight `SaveRefreshToken`; a rotation whose persist failed lets the client retry instead of killing its session; a wrong `client_id` neither consumes the token nor revokes the family, while the owner's own replay still does.
- **Lifecycle** — `InsecureDevMode` is rejected unless *every* configured URL is loopback http (each URL poisoned in turn); unused client registrations are purged and used ones are not; two authorization flows in one browser both complete, while an evicted, foreign, oversized or malformed binder is refused and never echoed back in `Set-Cookie`.
- **Config and input validation** — short *and* low-entropy `JWTSecret` rejected, the derived key differs from the input and neither verifies the other's tokens, `code_challenge` charset/length, oversized `state` and registration payloads, the redirect-host allowlist.
- **Concurrency and methods** — 32 goroutines double-spending an authorization code and a refresh token (exactly one wins), and the 405 behaviour of every endpoint.

`go test -race -count=20 ./...` is green — the concurrency suites are repeated, not sampled once.

## License

MIT
