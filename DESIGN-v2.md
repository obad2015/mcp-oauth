# mcp-oauth v2 — design plan

Reviewed: every source file at `f890079`, the README, `git log`, and both production
integrations (`personal-finance/api/{internal/store/oauth.go, cmd/server/mcp_oauth.go}`,
`todo/api/{internal/store/oauth.go, cmd/server/mcp_oauth.go}`).

## Verdict

Most of this library's complexity is **earned, not accumulated**. The consent
interstitial, browser binder, PKCE, hash-only persistence, exact redirect matching,
and Google ID-token verification each map to a concrete, demonstrated attack — the
consent+binder pair killed a working code-hijack — and none of them is a candidate for
removal. The refresh subsystem is where the complexity concentrates, and the owner's
"extremely complex" impression is correct about *where the cost lands*: not in the
provider code (which is now finished, adversarially tested, and stable), but in the
**Store contract** — 14 methods, nine load-bearing SQL rules, a 330-line README section,
and a 584-line `VerifyStore` that exists only because integrators can silently disable
security by mistranscribing a WHERE clause. That is the design smell, and the fix is not
to delete the security — it is to **stop asking integrators to implement it**.

The v2 shape:

1. **Library-owned PostgreSQL store** (`pgstore`) — apps implement one method
   (`FindUserIDByEmail`), not fourteen. `VerifyStore` becomes a CI tool for the
   library, not a startup ritual for every app.
2. **One deliberate deletion in the refresh subsystem**: the AES-GCM `SuccessorSealed`
   blob and `LinkRefreshSuccessor` are replaced by an in-process grace cache. Everything
   else in the refresh subsystem stays.
3. **Unified sessions via a direct grant** (`IssueSession`): the app keeps its existing
   Google/Apple/Capacitor login UX and swaps only the *token* it mints — the 30-day
   unrevocable HS256 JWT becomes the same rotating, revocable refresh family MCP clients
   already use. No new redirect flow, no consent-skip decision surface, Apple and
   Capacitor need zero changes to their login step.
4. **Route mounting derived from `Config`** (`Routes()` + tiny `mount/echo`,
   `mount/gin` modules) so the RFC 9728 path-inserted metadata route — the thing
   personal-finance 404'd in production — is computed by the library and cannot be
   forgotten or mis-derived.

Net effect: the two consumers each delete ~350–400 lines of transcribed SQL and route
wiring; the library grows ~600 lines it can actually test itself; the security model is
unchanged except one narrow, explicitly-argued trade (grace-window durability).

---

## 1. Essential vs incidental complexity

### Keep — load-bearing, with the attack each defends against

| Control | Defends against |
|---|---|
| Consent interstitial (GET renders, POST+nonce continues) | the CRITICAL: attacker-registered client phishing a victim with a genuine `accounts.google.com` link; PKCE is useless because the attacker owns both halves |
| `__Host-` binder cookie, hash on the pending record, checked at approve **and** callback | the cross-browser variant of the same hijack, even if consent were bypassed |
| Exact redirect-URI match; unknown client / mismatched URI → direct 400, never a redirect | open redirector |
| PKCE S256 mandatory, RFC 7636 validation, constant-time compare | code interception on the loopback redirect |
| Hash-only persistence (codes, refresh tokens, state, binder) | DB dump ≠ credential dump |
| Rotation + `FamilyID` + durable `ConsumedAt` ledger in the Store | stolen refresh token used alongside the legitimate one — detection survives restarts and cannot be flushed by rotating in a loop (the round-2 HIGH) |
| Client-binding pre-check **before** consume (`GetRefreshToken` first) | unauthenticated victim-logout: anyone who learns a token burning it with an arbitrary `client_id` |
| Post-rotation predecessor re-read in `issueTokenPair` | in-flight rotation silently resurrecting a family that reuse detection just revoked (round-3 HIGH) |
| Absolute family TTL (`FamilyCreatedAt` carried forward) | a thief keeping a stolen chain alive forever by rotating before expiry |
| Grace window with **no lower clock bound** | the round-3 clock-skew finding: a concurrent duplicate whose clock ran behind the winner revoked the family |
| Full Google ID-token verification (JWKS, iss, aud, exp, `email_verified`, bounded 24h stale-key fallback) | token forgery / unverified-email account takeover |
| HKDF-derived signing key + `token_use` claim | session-JWT ↔ MCP-token cross-replay when the app reuses one secret |
| `InsecureDevMode` gated on *every* URL being loopback http | the "loopback Issuer, public everything else" foot-gun that stripped `__Host-` in a real config |
| `FindUserIDByEmail` never creates users | silent account provisioning/merging |
| Client leases (`UnusedClientTTL`/`ClientTTL`) + purge | unauthenticated `/register` growing the table forever |

### The refresh subsystem: keep it — and here is the honest accounting

Deleting refresh tokens entirely would remove roughly 600 lines of provider code, the
three hardest Store methods, and about half of `VerifyStore` and the README. What it
costs:

- **With short access tokens (1h) and no refresh**, Claude Code re-runs the full
  browser flow every hour. The earlier reviewer's habituation argument is correct and
  I'll sharpen it: the consent screen is the control that killed the CRITICAL, and its
  entire value is that the operator *reads* it. An operator who sees it hourly — or even
  daily — clicks Approve by reflex within a week. At that point the interstitial is
  security theater and the hijack is alive again in practice. **Agree with the earlier
  reviewer; do not drop refresh tokens.**
- **With long access tokens (30d) and no refresh**, you have recreated, byte for byte,
  the defect the owner wants out of the web app: a long-lived bearer token with no
  revocation path, now also granted to third-party MCP clients.
- The refresh subsystem is the only mechanism that provides *both* continuity (no
  habituation) and revocability. It is also **already built, adversarially reviewed
  four times, and green under `-race -count=20`**. The marginal cost of keeping it is
  near zero; the cost it still imposes is integration cost, which section 2 removes.

Conclusion: rotation, families, the durable reuse ledger, and the absolute TTL are
**essential** complexity. Four of five post-CRITICAL findings came from here because
this is where the hard state-machine lives, not because the state-machine is
unnecessary.

### Delete — the one incidental piece: `SuccessorSealed` + `LinkRefreshSuccessor`

The sealed-successor blob exists so a duplicate refresh submission inside the 30s grace
window can be answered with the same successor **durably** — across process restarts
and multiple instances — without plaintext at rest. That durability is the incidental
part. Distinguish the two ledgers:

- The **reuse ledger** (`ConsumedAt`) must be durable: losing it is a security bypass
  (round-2 HIGH). It stays in the Store.
- The **grace cache** (predecessor → successor) does not: losing an entry fails
  *safe* — the duplicate is classified as reuse, the family is revoked, and the
  operator logs in again once. No attacker gains anything from evicting it; flooding it
  only degrades honest retries.

**v2 replaces the sealed blob with a small in-process cache** keyed by predecessor
hash, holding the raw successor and family ID, TTL = `RefreshGracePeriod`, capped
(say 1024 entries):

```go
type graceEntry struct {
    successorRaw string
    familyID     string
    expiresAt    time.Time
}
// Provider gains: mu-guarded map[string]graceEntry, swept opportunistically.
```

What this deletes:
- `successorKey` / `sealSuccessor` / `openSuccessor` / `newGCM` (~90 lines of AES-GCM),
- `Store.LinkRefreshSuccessor` and its "never an UPSERT" trap (README rule 6),
- the `successor_sealed` column and its round-trip + upsert canary checks in
  `VerifyStore` (~50 lines),
- the "two-step-stale" check in `graceApplies` simplifies (the cache entry *is* the
  most-recent link; the successor-still-unused check via `GetRefreshToken` stays).

What stays even without the blob: the **post-rotation predecessor re-read** in
`issueTokenPair` (it defends the revocation-undo race, which is independent of
sealing) and every grace-window qualification rule (same client, no lower clock bound,
late side only, successor unused).

**Residual risk, stated plainly:** on a process restart or in a multi-instance
deployment, a duplicate refresh submission inside a 30-second window is treated as
reuse and logs the client out (one re-login; no data exposure). The bearer of that
risk is a single operator running single-process deployments on one VPS — for whom a
restart coinciding with a 30s refresh race is a once-a-year annoyance, purchased by
deleting the most baroque code in the library and the single most error-prone Store
method. If either app ever scales out, the options are sticky-routing `/oauth/token`
or accepting the occasional re-login. This trade is right for these consumers.

### Keep but demote: `VerifyStore`

`VerifyStore` encodes four rounds of hard-won failure knowledge and is the test rig for
the library's own store (below). It stays, verbatim minus the successor checks. What
changes is its *audience*: apps using `pgstore` no longer call it at startup (the
library's CI has already verified `pgstore` against real PostgreSQL); only authors of
custom Stores do. Startup for a `pgstore` app is `EnsureSchema` + a connectivity ping.

---

## 2. The integration burden

Today each consumer transcribes ~300 lines of SQL where four clauses are individually
load-bearing, and both files carry "do not simplify this" comments begging future
maintainers not to break security. `VerifyStore` exists because the library knows the
transcription will sometimes be wrong. The fix is obvious once stated: **the library
ships the store, so the tricky invariants live next to the code that depends on
them and are tested by the library's own CI.**

### What I would actually do

**`github.com/obad2015/mcp-oauth/pgstore` — in the main module, `database/sql` only.**

```go
package pgstore

// New returns a Store backed by the given database/sql handle (PostgreSQL).
// Works with lib/pq and with pgx via stdlib: stdlib.OpenDBFromPool(pool).
func New(db *sql.DB, opts ...Option) *Store

// EnsureSchema creates/upgrades the mcp_oauth_* tables idempotently
// (its own schema_version row; safe to run at every startup).
func (s *Store) EnsureSchema(ctx context.Context) error

// Option: WithUserLookup lets the app keep FindUserIDByEmail in its own code —
// the ONE method that genuinely belongs to the application.
func WithUserLookup(fn func(ctx context.Context, email string) (string, bool, error)) Option
```

Decisions and why:

- **One implementation, `database/sql`, no new dependencies in the main module.**
  personal-finance uses it natively; todo passes `stdlib.OpenDBFromPool(pool)` — one
  line. A native-pgx twin doubles the surface for zero security value; skip it. (If a
  future consumer really needs native pgx, it becomes a nested module then.)
- **`FindUserIDByEmail` stays app-provided** via `WithUserLookup`. It is the only Store
  method that touches app tables, and both consumers already learned a real lesson
  there (PF's `LOWER()` casing fix) that the library cannot know. Everything else —
  all 12 remaining methods after the `LinkRefreshSuccessor` deletion — is generic and
  moves into `pgstore` verbatim from the (already battle-tested) consumer code.
- **Schema is owned by `pgstore`** (`EnsureSchema`). Both apps run golang-migrate; they
  simply *stop* owning these four tables — their existing migrations 000021/000023 stay
  historical, `EnsureSchema` no-ops over them by adopting the current shape and applying
  the `successor_sealed` drop as its first versioned step. Apps that insist on owning
  DDL can use the exported `pgstore.SchemaSQL` instead.
- **CI proof, not startup proof**: the library repo gets a `pgstore` test job against
  real PostgreSQL (docker) that runs `Provider.VerifyStore` plus the existing
  fault-injection suites. The README's nine-rule section moves to `STORE-CONTRACT.md`
  for custom-Store authors; the main README quickstart shrinks to ~15 lines.
- The `Store` interface itself shrinks by one method (`LinkRefreshSuccessor` gone) and,
  more importantly, by all of its documentation weight — the interface stays public for
  exotic backends, but nobody in this workspace implements it anymore.

Integration cost after this: `pgstore.New(db, pgstore.WithUserLookup(...))` +
`EnsureSchema` + `Mount` (section 4). Roughly 15 lines where there were ~400.

---

## 3. Unifying MCP and normal (web) user login

### The key design call: unify the token layer, not the login layer

Both apps already have working, native-feeling first-party login: Google GIS and Apple
Sign-In verified **server-side** at `POST /login`, including inside the Capacitor
wrapper (native plugins hand back an ID token; no redirect, no deep links). Forcing
that through `/oauth/authorize` would mean: building a consent-skip mechanism for
first-party clients (a new decision surface on the exact control that killed the
CRITICAL), rewriting two frontends to redirect flows, and adding deep-link handling to
the Capacitor app — all to end up authenticating the same Google account.

The actual defect the owner wants fixed is narrower: the web session is a **30-day
HS256 JWT with no revocation path**. So v2 unifies at the point where the defect lives:

> The app authenticates the human however it already does; the library becomes the
> single mint for *all* tokens — MCP and web — so every session is short-lived,
> refresh-rotated, reuse-detected, and revocable through one mechanism.

This also means **the consent interstitial stays universal**: every `/oauth/authorize`
flow renders it, there is no "is this client first-party?" branch to get wrong, and
`/register` can never mint a consent-skipping client because no such thing exists.

### Proposed API

```go
// SessionTokenUse is the token_use claim of first-party session access tokens.
// Distinct from TokenUseMCPAccess; ValidateAccessToken still rejects it and
// vice versa, so the two families remain non-interchangeable.
const SessionTokenUse = "app_session"

// sessionClientID is a reserved client id ("app:session"). randomToken output
// never contains ':', and Register refuses names with the "app:" prefix, so no
// dynamic registration can collide with it.

// TokenPair is what login and refresh hand to the frontend.
type TokenPair struct {
    AccessToken  string // HS256 JWT, token_use=app_session, aud=Issuer, TTL SessionAccessTokenTTL (default 1h)
    RefreshToken string // opaque, rotating, same family machinery as MCP
    ExpiresIn    int64
}

// IssueSession mints a session token pair for a user the APPLICATION has
// already authenticated (Google GIS, Apple, dev login). Starts a new refresh
// family with clientID "app:session".
func (p *Provider) IssueSession(ctx context.Context, userID string) (TokenPair, error)

// RefreshSession rotates a session refresh token. Same rotation, grace,
// reuse-revocation and absolute-TTL semantics as the MCP grant.
func (p *Provider) RefreshSession(ctx context.Context, refreshToken string) (TokenPair, error)

// ValidateSessionToken verifies an app_session access token → userID.
func (p *Provider) ValidateSessionToken(token string) (string, error)

// RevokeSession revokes the family of one refresh token (this-device logout).
func (p *Provider) RevokeSession(ctx context.Context, refreshToken string) error

// RevokeAllSessions revokes every refresh token of the user — MCP families
// included (that is "log out everywhere", and it is the right semantic).
func (p *Provider) RevokeAllSessions(ctx context.Context, userID string) error
```

Config additions: `SessionAccessTokenTTL` (default 1h), `SessionRefreshTokenTTL` /
`SessionAbsoluteTTL` (defaults: reuse the MCP values — 30d sliding / 90d absolute,
which matches the current 30-day habit while finally capping it). Session access
tokens are signed with a **second HKDF derivation** (`"mcpoauth/v1/session-token"`),
so MCP and session tokens differ in key *and* `aud` *and* `token_use` — three
independent walls against cross-replay.

Implementation cost is small because it is almost all reuse: `IssueSession` is
`issueTokenPair` with the reserved client ID and a session-key signer;
`RefreshSession` is `refreshTokenGrant` minus the HTTP form parsing. The rows live in
the same `mcp_oauth_refresh_tokens` table (the `client_id` column distinguishes them).
Handlers stay app-owned — they are ~10 lines each in Echo and keeping them out of the
library preserves its framework-free core:

```go
// app side (personal-finance): POST /login body handling unchanged, then
pair, err := provider.IssueSession(ctx, userID.String())
// POST /auth/refresh, POST /auth/logout → RefreshSession / RevokeSession.
```

### Migration without a flag day (per app)

1. `POST /login` starts returning `{access_token, refresh_token, expires_in}`
   (new shape) **while the old 30-day JWT keeps validating**: the session middleware
   tries `ValidateSessionToken` first, then falls back to the legacy HS256 parse.
   Legacy tokens carry no `token_use` claim and new ones always do, so the two are
   cleanly distinguishable; the legacy path additionally *rejects* any token carrying
   `token_use` (the mirror-image check the library README already recommends).
2. Frontend: store the pair (localStorage, as today — moving to cookies is a separate
   decision and out of scope), add refresh-on-401 to the `openapi-fetch` middleware,
   wire logout to `POST /auth/logout` (finally a real server-side logout).
3. 30 days after deploy every legacy token has expired naturally; delete the fallback
   branch and `createJWT`. Nobody was ever force-logged-out.

### Apple Sign-In and Capacitor: explicitly in scope, at zero cost

Both ride `IssueSession`: the app keeps verifying Apple/Google ID tokens exactly as it
does today (`verifyAppleToken` / `verifyGoogleToken` in PF's `auth.go`) and calls
`IssueSession` with the resolved user. No redirect flow → no deep links, no
`ASWebAuthenticationSession`, no changes to the Capacitor shell. The library never
learns Apple exists. A first-party *redirect* login through `/oauth/authorize` is
**scoped out** — it buys nothing for these consumers and would reopen the consent-skip
question; revisit only if a consumer ever appears that has no login UI of its own.

---

## 4. Router helpers

Both consumers hand-rolled ~85 lines of route registration, duplicating the
RFC 9728 suffix-derivation function, and PF shipped a production 404 by deriving the
path-inserted metadata route wrong. The class of mistake to make impossible: **routes
are currently written twice** — once as URLs in `Config`, once as router paths — and
nothing checks they agree.

### Design: the Provider computes its own route table from Config

```go
// Route is one endpoint the provider must be reachable at.
type Route struct {
    Path    string       // as the Go server sees it, e.g. "/mcp/oauth/authorize"
    Handler http.Handler // method discipline handled inside, mount with Any/Handle
}

// Routes derives every required route from the Config URLs:
//   - authorize, token, register, google callback (paths of the configured URLs)
//   - /.well-known/oauth-protected-resource            (bare, from MetadataBaseURL)
//   - /.well-known/oauth-protected-resource/<resource-path>  (RFC 9728 path-inserted,
//     derived from ResourceURL — the route PF got wrong by hand)
//   - /.well-known/oauth-authorization-server, /.well-known/openid-configuration
// Paths are deduplicated (the PF "suffix could collapse to bare path" guard lives
// here, once, tested in the library).
func (p *Provider) Routes() []Route

// Mount registers every route through the given registrar. This is the whole
// framework-independent core; MountMux/echo/gin are one-liners over it.
func (p *Provider) Mount(register func(path string, h http.Handler))

// MountMux — stdlib.
func (p *Provider) MountMux(mux *http.ServeMux)
```

Framework adapters as **nested modules** so the core keeps its two-line go.sum:

```go
// github.com/obad2015/mcp-oauth/mount/echomount (own go.mod, imports echo)
func Mount(e *echo.Echo, p *mcpoauth.Provider)      // e.Any(path, echo.WrapHandler(h)) per route

// github.com/obad2015/mcp-oauth/mount/ginmount (own go.mod, imports gin)
func Mount(r gin.IRouter, p *mcpoauth.Provider)     // r.Any(path, gin.WrapH(h)) per route
```

Each adapter is ~20 lines; Gin is included because the Impala CMS MCP is a plausible
third consumer.

Hardening that goes with it, all in `New` so misconfiguration fails at startup:

- **Same-origin validation**: `AuthorizeURL`, `TokenURL`, `RegisterURL`,
  `GoogleRedirectURL` must share one origin with `Issuer` (the binder cookie already
  silently requires this; today a mismatch just breaks logins mysteriously).
- **Path-prefix reality check**: `Routes()` registers the paths exactly as they appear
  in the configured public URLs. That is correct for both consumers today (nginx
  preserves `/mcp/...`). For proxies that strip a prefix, `Routes()` is the escape
  hatch — the app rewrites `Path` before registering; document this in one paragraph
  instead of supporting a rewrite option nobody currently needs.
- Consumers then delete `mountMCPOAuthRoutes` + `protectedResourceMetadataSuffix`
  (both copies), and the derived-metadata-path logic finally has unit tests in exactly
  one place.

Config remains explicit URLs (they are the public contract, and `MetadataBaseURL` vs
`Issuer` genuinely differ under proxies), but v2 adds the convenience most callers
want:

```go
// ConfigForBase fills Issuer/ResourceURL/MetadataBaseURL/Authorize/Token/
// Register/GoogleRedirect from one base URL + one mcp path, matching the layout
// both consumers already converged on ("/mcp", "/mcp/oauth/*").
func ConfigForBase(publicBaseURL, mcpPath string) Config
```

That replaces PF's `mcpOAuthPublicURLs` and todo's inline equivalents.

---

## Staged migration plan

Each stage is independently deployable; the single breaking release is v2.0.0 and both
consumers absorb it in one small PR each.

**Stage 0 — freeze the contract tests.** Port the existing store fault-injection and
`VerifyStore` suites to run against real PostgreSQL in the library's CI (docker
service). This is the safety net for everything below. No consumer impact.

**Stage 1 — `pgstore` + grace-cache change together, tagged v2.0.0.**
These are one release because both touch the Store surface and doing them separately
means two breaking bumps:
- Add `pgstore` (code lifted from the consumers' proven implementations, minus
  `LinkRefreshSuccessor`), `EnsureSchema`, `WithUserLookup`.
- Replace `SuccessorSealed`/`LinkRefreshSuccessor` with the in-process grace cache;
  delete the sealing code; `EnsureSchema`'s first version step drops
  `successor_sealed`.
- *Breaking for consumers:* the `Store` interface loses a method — irrelevant, because
  the same PR that bumps the dependency swaps each app to `pgstore` and **deletes its
  `oauth.go` entirely** (~300 lines each). `VerifyStore` call in each app's startup is
  replaced by `EnsureSchema`. Refresh tokens in flight are unaffected (rows,
  hashes and families are unchanged; only the grace path's storage moved) — no user
  re-login on deploy.

**Stage 2 — `Routes()`/`Mount` + `mount/echomount` (+ `ginmount`), v2.1.0.**
Additive. Each consumer deletes `mountMCPOAuthRoutes` + suffix helper (~85 lines) for
`echomount.Mount(e, provider)` + `ConfigForBase`. Verify with a curl sweep of all
well-known paths post-deploy (the exact check that would have caught PF's 404).

**Stage 3 — sessions, v2.2.0.** Additive library API (`IssueSession` etc.). Per app:
`/login` returns a pair, middleware chains new→legacy validation, frontend gains
refresh-on-401 and real logout. No mass logout (see §3 migration). 30 days later a
cleanup PR removes `createJWT` and the legacy fallback.

**Stage 4 — docs.** README rewritten around `pgstore` + `Mount` (~150 lines);
`STORE-CONTRACT.md` keeps the nine-rules material for custom-Store authors.

Rollback story: every stage is a normal dependency bump; stage 1 is the only schema
change (a column drop — restore requires nothing, since v2 never reads it).

---

## Do NOT simplify these

- **Consent interstitial (POST + single-use nonce; GET never redirects to Google)** —
  the control that killed the CRITICAL code-hijack; the only thing standing between a
  phished `accounts.google.com` link and an attacker's redirect URI.
- **`__Host-` binder cookie + binder check at approve and callback** — kills the
  cross-browser hijack even if consent is clicked through; `SameSite=Lax` is required
  for the Google round-trip, do not "tighten" it to Strict.
- **Exact redirect-URI matching; unknown client/URI → direct 400, never a redirect** —
  open-redirect prevention.
- **Mandatory PKCE S256** with RFC 7636 validation — loopback code interception.
- **Hash-only persistence of every secret** — a DB dump must stay worthless.
- **Durable `ConsumedAt` reuse ledger + family revocation + retention until
  `FamilyExpiresAt`** — the flushable in-process ledger was a HIGH; this must stay in
  the Store even though the grace cache moves out.
- **Client-binding pre-check before `ConsumeRefreshToken`** — prevents unauthenticated
  victim logout via a learned token + arbitrary client_id.
- **Post-rotation predecessor re-read** — prevents an in-flight rotation from
  resurrecting a family that reuse detection just revoked.
- **Absolute family TTL carried from `FamilyCreatedAt`** — a stolen chain must die on
  schedule regardless of rotation.
- **Grace window's late-side-only clock bound** — the lower bound was a real bug
  (clock skew revoking honest concurrent duplicates); do not "fix" its absence.
- **Full Google ID-token verification incl. `email_verified` and the 24h-bounded stale
  JWKS fallback** — forgery and unverified-email takeover; unbounded staleness would
  keep rotated-away keys authenticating forever.
- **HKDF key derivation + distinct `token_use`/`aud` per token family** — cross-replay
  walls between web sessions and MCP tokens (three walls after v2: key, aud, claim).
- **`InsecureDevMode` gated on every URL being loopback http** — the partial gate
  already failed once in a realistic config.
- **`FindUserIDByEmail` never creates users** — and keep PF's `LOWER()` comparison;
  it is a documented production fix, not an inefficiency.
- **Bounded inputs, method discipline, CORS on discovery/token only** — cheap, tested,
  and each bound answers a concrete abuse (binder-cookie echo, oversized state, HEAD
  minting state).
