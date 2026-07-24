package mcpoauth

import (
	"context"
	"time"
)

// Store is the persistence contract an application implements to back the
// authorization server. It is deliberately driver-agnostic: any SQL, KV or
// in-memory backend works.
//
// Implementation requirements:
//
//   - ConsumeAuthCode and ConsumePendingAuth MUST be single-use and atomic: a
//     concurrent second call for the same value must return ok=false. In SQL
//     this is typically a "DELETE ... RETURNING *" in one statement.
//   - ConsumeRefreshToken is different: it MUST NOT delete. See its own doc.
//   - ConsumeAuthCode and ConsumePendingAuth may return expired records (the
//     Provider checks expiry itself) or filter them out — either is fine.
//     ConsumeRefreshToken MUST NOT filter: an expired CONSUMED refresh-token
//     row is the reuse-detection ledger, so `AND expires_at > now()` there
//     turns a replayed stolen token into a plain invalid_grant and the family
//     is never revoked. Return the row and let the Provider judge it.
//   - No foreign keys between these tables, and none from them to your users
//     table. Rows are removed independently (a client registration expires
//     long before the refresh tokens it issued), and Provider.VerifyStore
//     writes canary rows for a user that does not exist.
//   - Nothing here ever receives a raw secret: codes, refresh tokens, the
//     pending state and the browser binder are always identified by their
//     SHA-256 hash (hex).
//   - Every field of every struct MUST round-trip. Dropping FamilyID,
//     FamilyCreatedAt, FamilyExpiresAt, ConsumedAt, SuccessorSealed or
//     BinderHash silently disables a security control. Call
//     Provider.VerifyStore once at startup — it round-trips canary records and
//     fails loudly if anything is lost.
//
// Retention rule (important): a refresh-token row is the durable
// reuse-detection ledger. It must be kept until BOTH its own ExpiresAt and its
// FamilyExpiresAt have passed, long after it was consumed. PurgeExpired is the
// only thing that may remove it.
type Store interface {
	// SaveClient persists a dynamically registered client. It is also called
	// to extend an existing client's ExpiresAt after a completed login, so it
	// MUST upsert on ClientID.
	SaveClient(ctx context.Context, c Client) error
	// GetClient looks up a client by its ID. ok=false when unknown.
	GetClient(ctx context.Context, clientID string) (Client, bool, error)

	// SaveAuthCode persists an authorization code record (hash only).
	SaveAuthCode(ctx context.Context, code AuthCode) error
	// ConsumeAuthCode atomically fetches and invalidates an authorization
	// code. A second call with the same hash MUST return ok=false.
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCode, bool, error)

	// SavePendingAuth persists the state of an in-flight authorize request.
	//
	// It is called TWICE per flow, with the same ClientID and two DIFFERENT
	// StateHash values (the consent nonce, then the Google state). It is
	// therefore a plain INSERT keyed on state_hash. An UPDATE, or an upsert
	// keyed on client_id, silently drops the first record and every login then
	// dies at the consent step.
	SavePendingAuth(ctx context.Context, p PendingAuth) error
	// ConsumePendingAuth atomically fetches and invalidates pending state.
	ConsumePendingAuth(ctx context.Context, stateHash string) (PendingAuth, bool, error)

	// SaveRefreshToken persists a refresh token record (hash only). The row
	// is written with a zero ConsumedAt and no SuccessorSealed.
	SaveRefreshToken(ctx context.Context, rt RefreshToken) error

	// GetRefreshToken reads a refresh-token row without modifying it.
	// ok=false when the hash is unknown.
	//
	// It MUST NOT be filtered on anything — not ConsumedAt, not ExpiresAt, not
	// FamilyExpiresAt:
	//
	//	SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1;
	//
	// The Provider calls this on an already-consumed row in two places: the
	// client_id pre-check before a rotation, and the post-Link re-read that
	// confirms the row it just wrote onto still exists. Add `AND consumed_at IS
	// NULL` by symmetry with ConsumeRefreshToken and both break: the pre-check
	// treats every refresh as an unknown token, and the post-Link re-read never
	// finds the just-consumed predecessor, so every rotation revokes its own
	// family.
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, bool, error)

	// ConsumeRefreshToken atomically stamps ConsumedAt on a refresh-token row
	// and returns the row AS IT WAS BEFORE the call.
	//
	// It MUST NOT delete the row — the consumed marker is what makes reuse
	// detection durable across process restarts and unbounded rotation counts.
	// Only PurgeExpired removes refresh-token rows.
	//
	// The Provider classifies the presented token from the return values:
	//
	//	ok == false                    -> unknown token: plain invalid_grant.
	//	ok, rt.ConsumedAt.IsZero()     -> first use: a legitimate rotation.
	//	ok, !rt.ConsumedAt.IsZero()    -> REUSE (or a duplicate submission
	//	                                  inside Config.RefreshGracePeriod);
	//	                                  the whole family is revoked.
	//
	// Requirements:
	//
	//   - Atomic: of N concurrent calls for the same hash, exactly one may see
	//     a zero ConsumedAt.
	//   - Idempotent stamp: an already-consumed row keeps its ORIGINAL
	//     ConsumedAt forever (never overwrite it), and the returned ConsumedAt
	//     is the value that was stored before this call.
	//   - No filtering: return the row whatever its ExpiresAt says.
	//   - consumedAt is the Provider's clock; store exactly that value.
	//
	// PostgreSQL, one statement, at READ COMMITTED (the default):
	//
	//	WITH before AS (
	//	    SELECT * FROM mcp_oauth_refresh_tokens
	//	    WHERE token_hash = $1 FOR UPDATE
	//	), stamped AS (
	//	    UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
	//	    WHERE token_hash = $1 AND consumed_at IS NULL
	//	)
	//	SELECT * FROM before;
	//
	// `AND consumed_at IS NULL` is LOAD-BEARING — see the README. Without it
	// the row is re-stamped on every replay while still returning its previous
	// value, which passes any casual test and turns Config.RefreshGracePeriod
	// into a rolling, unbounded window: a stolen token is replayable forever
	// and reuse detection never fires. Provider.VerifyStore consumes its canary
	// three times specifically to catch this.
	//
	// Do NOT write it as `UPDATE ... WHERE consumed_at IS NULL RETURNING *`:
	// that returns ZERO rows on a replay, which the Provider reads as "unknown
	// token" — plain invalid_grant, no family revocation, silently.
	ConsumeRefreshToken(ctx context.Context, tokenHash string, consumedAt time.Time) (RefreshToken, bool, error)

	// LinkRefreshSuccessor records, on an already-consumed row, the sealed
	// successor token that rotation produced, and (re)stamps the row's
	// FamilyID.
	//
	// sealed is an opaque encrypted blob: store and return it verbatim, never
	// interpret it. It lets a duplicate submission inside
	// Config.RefreshGracePeriod be answered with the very same refresh token
	// instead of destroying the client's session — see the README.
	//
	// familyID is the family the successor belongs to. It is normally the row's
	// own family; for a legacy row whose FamilyID was empty this adopts the row
	// into the new family, so a later replay can still revoke it.
	//
	// It MUST be a no-op returning nil when the hash is unknown, and it must
	// NEVER be an UPSERT: an INSERT path here materialises a refresh-token row
	// that was never issued, with a caller-influenced family_id.
	LinkRefreshSuccessor(ctx context.Context, tokenHash, familyID string, sealed []byte) error

	// RevokeRefreshTokensForUser invalidates every refresh token of a user.
	// Deleting the rows is fine here.
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
	// RevokeRefreshTokenFamily invalidates every refresh token in one
	// rotation chain, consumed rows included. The Provider calls it when it
	// sees a refresh token replayed after it was already rotated away, which
	// is the canonical signal that a token leaked. Deleting the rows is fine:
	// once the family is dead there is nothing left to detect.
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error

	// PurgeExpired deletes records whose retention has lapsed, as of the given
	// instant:
	//
	//   - authorization codes and pending authorize requests: ExpiresAt passed.
	//   - refresh tokens: BOTH ExpiresAt and FamilyExpiresAt passed. A consumed
	//     row MUST survive until then — that is the reuse-detection window.
	//   - clients: ExpiresAt passed. Registration is unauthenticated, so
	//     clients that never completed a login expire quickly
	//     (Config.UnusedClientTTL) and used ones live for Config.ClientTTL.
	//
	// It must be safe to call concurrently with everything else. The Provider
	// calls it opportunistically; applications should also run it from a
	// ticker.
	PurgeExpired(ctx context.Context, before time.Time) error

	// FindUserIDByEmail maps a verified Google email to an EXISTING
	// application user. Return ok=false when there is no such user — the
	// Provider then refuses the login instead of creating an account.
	FindUserIDByEmail(ctx context.Context, email string) (userID string, ok bool, err error)
}
