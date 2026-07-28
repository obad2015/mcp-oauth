# Writing a custom `mcpoauth.Store`

**You almost certainly do not need this document.**

The library ships [`pgstore`](pgstore/), a PostgreSQL implementation of the whole
contract that this repository's CI verifies against a real PostgreSQL 17 server
on every push. Applications supply one method — `FindUserIDByEmail`, through
`pgstore.WithUserLookup` — and get everything below for free. See the README.

This document is for the case `pgstore` cannot serve: a different database, or a
backend that is not SQL at all. It is the accumulated output of four adversarial
review rounds, and every rule in it was written because breaking it disables a
security control **without breaking anything visible**. That asymmetry is the
whole problem: the OAuth flow keeps working perfectly, it just stops being safe.

If you write one of these, run `Provider.VerifyStore` against it from your test
suite. It catches most — not all — of what follows.

## The interface

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
| `Client.ExpiresAt` | client registrations become permanent and unbounded |

Round-tripping the fields is necessary and **not sufficient** — the rules below cover the behaviours that no column can express. `Provider.VerifyStore(ctx)` checks both; see [What `VerifyStore` actually catches](#what-verifystore-actually-catches).

### Schema requirements before you write any DDL

Three constraints apply to **all four** tables. They are not stylistic:

- **No foreign keys.** Not between these tables, and not from them to your `users` table. The rows have independent lifetimes — a client registration expires long before the refresh tokens it issued, and `RevokeRefreshTokenFamily` deletes rows a pending record may still reference. `VerifyStore` also writes canary rows for a user that does not exist; an FK to `users` turns startup verification into a startup crash.
- **`user_id` is `TEXT`.** If your application's user IDs are UUIDs and you want a `user_id UUID` column, that is fine — but then set `Config.VerifyStoreUserID` to a syntactically valid UUID, or `VerifyStore` will fail at startup trying to insert its default string canary. It must not be a real user's ID.
- **`client_id` must hold at least 48 characters.** Issued client IDs are 32, so a `VARCHAR(32)` column works in production and fails only in `VerifyStore`, whose canary is 48. Use `TEXT`.

### PostgreSQL schema — all four tables

(`pgstore.SchemaSQL` is this, idempotent, if you only want the DDL.)

```sql
CREATE TABLE mcp_oauth_clients (
    client_id      TEXT PRIMARY KEY,       -- must hold >= 48 chars (VerifyStore canary)
    redirect_uris  JSONB       NOT NULL,
    client_name    TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE mcp_oauth_auth_codes (
    code_hash      TEXT PRIMARY KEY,       -- sha256 hex of the authorization code
    client_id      TEXT        NOT NULL,   -- NO foreign key
    user_id        TEXT        NOT NULL,   -- NO foreign key
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,   -- PKCE S256; without it PKCE is unenforceable
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE mcp_oauth_pending_auth (
    state_hash     TEXT PRIMARY KEY,       -- sha256 hex of the consent nonce OR the Google state
    client_id      TEXT        NOT NULL,   -- NOT unique: two rows per flow share it
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,
    client_state   TEXT        NOT NULL DEFAULT '',
    binder_hash    TEXT        NOT NULL,   -- browser binding; dropping it re-opens the hijack
    approved       BOOLEAN     NOT NULL DEFAULT FALSE,  -- easy to forget; consent becomes skippable
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
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
    consumed_at       TIMESTAMPTZ           -- NULL = never used. Stamped ONCE, never overwritten
);
CREATE INDEX ON mcp_oauth_refresh_tokens (family_id);
CREATE INDEX ON mcp_oauth_refresh_tokens (expires_at, family_expires_at);
```

### Eight rules

1. **`ConsumeAuthCode` and `ConsumePendingAuth` must be atomic and single-use.** A concurrent second call for the same hash must return `ok=false`. In PostgreSQL that is one statement:

   ```sql
   DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
   RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at;
   ```

2. **`SavePendingAuth` is called TWICE per authorization flow, with two different primary keys.** Once for the consent nonce, once for the Google `state` — same `client_id`, different `state_hash`. It is a plain `INSERT`:

   ```sql
   INSERT INTO mcp_oauth_pending_auth
       (state_hash, client_id, redirect_uri, code_challenge, client_state, binder_hash, approved, expires_at, created_at)
   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);
   ```

   An `UPDATE`, or an `ON CONFLICT (client_id) DO UPDATE`, silently loses the first record and every login then dies at the consent step with "unknown nonce". Do not put a unique constraint on `client_id`.

3. **`ConsumeRefreshToken` must NOT delete, must NOT filter, and must stamp exactly once.** This is the one that matters most. The row *is* the reuse-detection ledger: it is stamped, kept, and only removed by `PurgeExpired`. It must return the row **as it was before the call**, so the provider can tell the three cases apart:

   | return | meaning |
   |---|---|
   | `ok=false` | never issued, or the family is already revoked/purged → `invalid_grant` |
   | `ok=true`, `ConsumedAt` zero | first use → a legitimate rotation |
   | `ok=true`, `ConsumedAt` set | replay → duplicate submission (inside `RefreshGracePeriod`) or **reuse**, which revokes the family |

   The correct idiom, one statement, at **`READ COMMITTED`** (PostgreSQL's default — see rule 5):

   ```sql
   WITH before AS (
       SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE
   ), stamped AS (
       UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
       WHERE token_hash = $1 AND consumed_at IS NULL
   )
   SELECT * FROM before;
   ```

   Verified on PostgreSQL 17: 32 concurrent callers, exactly one winner, 12 runs out of 12.

   **`AND consumed_at IS NULL` is load-bearing.** Drop it and the row is re-stamped on every call — while still returning the value from *before* that call, so first-use detection, replay detection and every round-trip check still look correct. What breaks is invisible: `RefreshGracePeriod` is anchored to `consumed_at`, so a rolling stamp converts the fixed 30-second window into an unbounded one. A stolen refresh token can then be replayed indefinitely, each replay handing back a fresh access token, and reuse detection **never fires**. Measured against a real PostgreSQL 17 store with the clause removed: 200 out of 200 replays of an already-consumed token accepted, spanning over an hour. `Provider.VerifyStore` consumes its canary **three** times specifically to catch this.

   **Do not write the tempting shorter version:**

   ```sql
   -- WRONG. Do not use.
   UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
   WHERE token_hash = $1 AND consumed_at IS NULL
   RETURNING *;
   ```

   It looks equivalent and is not. On a replay the `WHERE` matches nothing, so it returns **zero rows**, which the provider reads as `ok=false` — "unknown token". The replay of a leaked token becomes a plain `invalid_grant` and the family is never revoked. The failure is completely silent: the client sees the same 400 either way.

   **Do not filter on `expires_at` either.** An *expired* `consumed_at`-stamped row is precisely the ledger entry that catches a token stolen weeks ago; `AND expires_at > now()` turns that replay into an ordinary `invalid_grant` with no revocation. The provider checks expiry itself. (The same licence *is* safe for `ConsumeAuthCode` and `ConsumePendingAuth` — those records are deleted on use and carry no history.)

4. **`GetRefreshToken` must never be filtered, on anything — not `consumed_at`, not `expires_at`, not `family_expires_at`:**

   ```sql
   SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1;  -- never filtered, on anything (not consumed_at, not expiry)
   ```

   The provider calls this on an already-consumed row in two places: the `client_id` pre-check before a rotation, and the post-rotation re-read that confirms the predecessor still exists (the check that stops an in-flight rotation from resurrecting a family reuse detection just revoked). It is tempting to add `AND consumed_at IS NULL` by symmetry with `ConsumeRefreshToken` — do not. That breaks both callers: the pre-check treats every refresh as an unknown token, and the re-read never finds the just-consumed predecessor, so every single rotation revokes its own family.

5. **Isolation level: `READ COMMITTED`.** That is PostgreSQL's default and what the idiom above is written for. Under `REPEATABLE READ` or `SERIALIZABLE` the statement still yields exactly one winner, but concurrent callers get `SQLSTATE 40001` (`could not serialize access due to concurrent update`) and **you must catch it and retry** — an unhandled 40001 surfaces as a 500 on a perfectly ordinary parallel refresh. If your application runs everything inside a `REPEATABLE READ` transaction, either run these statements on their own connection or add the retry.

6. **`RevokeRefreshTokenFamily` must delete every token sharing the `family_id`**, consumed rows included — one `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`. It is called when a rotated-away token is replayed, which is the canonical signal that a refresh token leaked; a no-op implementation silently disables the defence. Guard the empty string: an unguarded `WHERE family_id = ''` matches every legacy row that never had a family and takes unrelated sessions down with it.

7. **`FindUserIDByEmail` must not create users, and must compare case-insensitively.** Returning `ok=false` is how you refuse a stranger — creating an account here is silent provisioning, and matching loosely is account takeover. The provider lowercases the verified Google email before calling you, but application signup paths usually store whatever casing the identity provider returned, so a plain equality check locks out every user whose stored address has an uppercase character. That was a production bug; the fix is `LOWER()` on both sides.

   ```sql
   SELECT id::text FROM users WHERE LOWER(email) = LOWER($1);
   ```

8. **`PurgeExpired` must be safe to call concurrently with everything else**, and it covers all four tables. Note the refresh-token condition: a consumed row is retained until its **family** dies, which is much later than its own `expires_at`.

   ```sql
   DELETE FROM mcp_oauth_auth_codes     WHERE expires_at < $1;
   DELETE FROM mcp_oauth_pending_auth   WHERE expires_at < $1;
   DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < $1 AND family_expires_at < $1;
   DELETE FROM mcp_oauth_clients        WHERE expires_at < $1;
   ```

   `/authorize` and `/register` are unauthenticated, so without a purge those tables grow forever. **Run `Provider.PurgeExpired` from a ticker** (see the mounting example); the provider's own opportunistic call, throttled to once per `Config.PurgeInterval`, is only a backstop. `VerifyStore` is safe to run alongside that ticker: its canaries are written with a lifetime in the future and expired explicitly at the end.

### What `VerifyStore` actually catches

It round-trips a canary through every method and reports, in one error, each rule that was broken. It detects all of: a dropped `BinderHash`, `Approved`, `FamilyID`, `FamilyCreatedAt`, `FamilyExpiresAt` or `ConsumedAt`; a `ConsumeRefreshToken` that deletes, that never stamps, that returns the row *after* stamping, that **overwrites** the stamp (rule 3), that filters expired rows, or that is not atomic under concurrent callers (it fires 8 concurrent calls at one canary and requires exactly one zero `ConsumedAt`); a `GetRefreshToken` that stops returning a row once it has been consumed (rule 4); a `SavePendingAuth` that loses one of the two records (rule 2); a replayable authorization code; a no-op `RevokeRefreshTokenFamily`; and a `PurgeExpired` that deletes a refresh-token row before its `family_expires_at` has passed, or that skips the **refresh-token or client** table entirely.

It does *not* exercise `PurgeExpired` against the auth-code or pending-auth tables — those canaries are already consumed by the time cleanup runs, so a purge that forgets either of those two tables still passes.

```go
func TestMyStoreIsCompliant(t *testing.T) {
	p, err := mcpoauth.New(cfg, myStore)
	if err != nil { t.Fatal(err) }
	if err := p.VerifyStore(context.Background()); err != nil { t.Fatal(err) }
}
```

Run it from your **test suite**, against a real instance of whatever backend you are targeting — an in-memory double proves nothing here, because every rule above is a property of the real storage engine. It is also safe to call at startup (it writes only its own canaries, with lifetimes in the future so a concurrent purge ticker cannot delete them mid-check, and expires them at the end), but a Store whose compliance cannot change between deploys is better checked where a failure costs a red build instead of an outage.

Two schema requirements it imposes: `user_id` must accept `Config.VerifyStoreUserID` (default a plain string — set it to a valid UUID if your column is one), and `client_id` must hold at least 48 characters.

`github.com/obad2015/mcp-oauth/memstore` ships a ready-made in-memory implementation (`memstore.NewMemoryStore()`) for tests and local development, and is the reference for what compliant behaviour looks like in Go. `pgstore` is the reference for what it looks like in SQL — read it before writing your own.
