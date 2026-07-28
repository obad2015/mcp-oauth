// Package pgstore is a PostgreSQL implementation of mcpoauth.Store.
//
// It exists because the Store contract is small but unforgiving: four of its
// clauses are individually load-bearing, and transcribing them wrongly disables
// a security control without breaking anything visible. Two production
// applications each carried ~300 lines of that SQL, with "do not simplify this"
// comments begging future maintainers not to break it. Now the library ships
// it, the tricky invariants live next to the code that depends on them, and the
// library's own CI verifies them against a real PostgreSQL server.
//
// Applications supply exactly one method — FindUserIDByEmail, through
// WithUserLookup — because only the application knows its users table:
//
//	store, err := pgstore.New(db, pgstore.WithUserLookup(
//		func(ctx context.Context, email string) (string, bool, error) {
//			var id string
//			err := db.QueryRowContext(ctx,
//				`SELECT id::text FROM users WHERE LOWER(email) = LOWER($1)`, email).Scan(&id)
//			if errors.Is(err, sql.ErrNoRows) {
//				return "", false, nil
//			}
//			return id, err == nil, err
//		}))
//	if err != nil { log.Fatal(err) }
//	if err := store.EnsureSchema(ctx); err != nil { log.Fatal(err) }
//
// The handle is a plain *sql.DB, so there is no driver dependency here and both
// of the drivers in use work: lib/pq natively, and pgx through
// stdlib.OpenDBFromPool(pool).
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// Store implements mcpoauth.Store against PostgreSQL.
type Store struct {
	db         *sql.DB
	userLookup UserLookupFunc
}

// UserLookupFunc maps a verified, lowercased Google email to an EXISTING
// application user. It MUST NOT create one: ok=false is how an unknown email is
// refused, and the Provider then ends the flow in a 403.
//
// Compare case-insensitively. The Provider lowercases the email claim before
// calling this, but application signup paths typically store whatever casing
// the identity provider returned, so a plain equality check locks out every
// user whose stored address contains an uppercase character. That is not a
// hypothetical — it was a production bug, fixed with LOWER() on both sides.
type UserLookupFunc func(ctx context.Context, email string) (userID string, ok bool, err error)

// Option configures a Store.
type Option func(*Store)

// WithUserLookup supplies FindUserIDByEmail, the one Store method that touches
// application tables. It is required.
func WithUserLookup(fn UserLookupFunc) Option {
	return func(s *Store) { s.userLookup = fn }
}

// New returns a Store backed by db.
//
// It does not touch the database; call EnsureSchema (or run the DDL in
// SchemaSQL through your own migration tool) before serving traffic.
func New(db *sql.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("pgstore: db is required")
	}
	s := &Store{db: db}
	for _, o := range opts {
		if o != nil {
			o(s)
		}
	}
	if s.userLookup == nil {
		return nil, errors.New("pgstore: WithUserLookup is required — only the application " +
			"can map a verified email to one of its own users, and it must never create one")
	}
	return s, nil
}

var _ mcpoauth.Store = (*Store)(nil)

// --- clients -------------------------------------------------------------

// SaveClient upserts on client_id: it is called both at registration and to
// push out ExpiresAt after a completed login. created_at is deliberately absent
// from the SET clause so the original registration time survives.
func (s *Store) SaveClient(ctx context.Context, c mcpoauth.Client) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("pgstore: encoding redirect_uris: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_clients (client_id, redirect_uris, client_name, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (client_id) DO UPDATE SET
			redirect_uris = EXCLUDED.redirect_uris,
			client_name = EXCLUDED.client_name,
			expires_at = EXCLUDED.expires_at
	`, c.ClientID, uris, c.ClientName, c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("pgstore: saving client: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (mcpoauth.Client, bool, error) {
	var c mcpoauth.Client
	var uris []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, redirect_uris, client_name, created_at, expires_at
		FROM mcp_oauth_clients WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &uris, &c.ClientName, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.Client{}, false, nil
	}
	if err != nil {
		return mcpoauth.Client{}, false, fmt.Errorf("pgstore: loading client: %w", err)
	}
	if err := json.Unmarshal(uris, &c.RedirectURIs); err != nil {
		return mcpoauth.Client{}, false, fmt.Errorf("pgstore: decoding redirect_uris: %w", err)
	}
	return c, true, nil
}

// --- authorization codes -------------------------------------------------

func (s *Store) SaveAuthCode(ctx context.Context, code mcpoauth.AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_auth_codes
			(code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.CodeChallenge,
		code.ExpiresAt, code.CreatedAt)
	if err != nil {
		return fmt.Errorf("pgstore: saving authorization code: %w", err)
	}
	return nil
}

// ConsumeAuthCode fetches and invalidates a code in ONE statement, so a
// concurrent second exchange of the same code gets ok=false. A SELECT followed
// by a DELETE would let two callers both win the race and redeem one code
// twice.
func (s *Store) ConsumeAuthCode(ctx context.Context, codeHash string) (mcpoauth.AuthCode, bool, error) {
	var c mcpoauth.AuthCode
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
		RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at
	`, codeHash).Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.CodeChallenge,
		&c.ExpiresAt, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.AuthCode{}, false, nil
	}
	if err != nil {
		return mcpoauth.AuthCode{}, false, fmt.Errorf("pgstore: consuming authorization code: %w", err)
	}
	return c, true, nil
}

// --- pending authorize state ---------------------------------------------

// savePendingAuthSQL is a plain INSERT keyed on state_hash.
//
// Every authorization flow calls it TWICE with the same client_id and two
// DIFFERENT state hashes — first the consent nonce, then the state handed to
// Google. An UPDATE, or an upsert keyed on client_id, silently drops the first
// record and every login then dies at the consent step with "unknown nonce".
const savePendingAuthSQL = `
	INSERT INTO mcp_oauth_pending_auth
		(state_hash, client_id, redirect_uri, code_challenge, client_state,
		 binder_hash, approved, expires_at, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

func (s *Store) SavePendingAuth(ctx context.Context, p mcpoauth.PendingAuth) error {
	_, err := s.db.ExecContext(ctx, savePendingAuthSQL,
		p.StateHash, p.ClientID, p.RedirectURI, p.CodeChallenge, p.ClientState,
		p.BinderHash, p.Approved, p.ExpiresAt, p.CreatedAt)
	if err != nil {
		return fmt.Errorf("pgstore: saving pending authorization: %w", err)
	}
	return nil
}

func (s *Store) ConsumePendingAuth(ctx context.Context, stateHash string) (mcpoauth.PendingAuth, bool, error) {
	var p mcpoauth.PendingAuth
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM mcp_oauth_pending_auth WHERE state_hash = $1
		RETURNING state_hash, client_id, redirect_uri, code_challenge, client_state,
		          binder_hash, approved, expires_at, created_at
	`, stateHash).Scan(&p.StateHash, &p.ClientID, &p.RedirectURI, &p.CodeChallenge,
		&p.ClientState, &p.BinderHash, &p.Approved, &p.ExpiresAt, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.PendingAuth{}, false, nil
	}
	if err != nil {
		return mcpoauth.PendingAuth{}, false, fmt.Errorf("pgstore: consuming pending authorization: %w", err)
	}
	return p, true, nil
}

// --- refresh tokens ------------------------------------------------------

// refreshCols is the projection every refresh-token read uses. It is spelled
// out rather than `SELECT *` so that a column added to (or dropped from) the
// table cannot silently shift the Scan targets — which is also what lets
// ConsumeRefreshToken run unchanged before and after EnsureSchema drops the
// legacy successor_sealed column.
const refreshCols = `token_hash, client_id, user_id, family_id, family_created_at,
	family_expires_at, expires_at, created_at, consumed_at`

// SaveRefreshToken inserts a freshly issued token with a NULL consumed_at.
//
// It is a plain INSERT on purpose. The Provider only ever calls it with the
// hash of a token it has just generated from a CSPRNG, so a conflict is not
// something to paper over with an upsert — an upsert here could reset the
// consumed_at stamp of an existing row, which is the reuse ledger.
func (s *Store) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_refresh_tokens
			(token_hash, client_id, user_id, family_id, family_created_at,
			 family_expires_at, expires_at, created_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)
	`, rt.TokenHash, rt.ClientID, rt.UserID, rt.FamilyID, rt.FamilyCreatedAt,
		rt.FamilyExpiresAt, rt.ExpiresAt, rt.CreatedAt)
	if err != nil {
		return fmt.Errorf("pgstore: saving refresh token: %w", err)
	}
	return nil
}

// getRefreshTokenSQL is UNFILTERED, and must stay that way — not on
// consumed_at, not on expires_at, not on family_expires_at.
//
// The Provider reads an already-consumed row here twice per rotation: the
// client-binding pre-check before consuming (which stops anyone who merely
// learns a refresh token from burning it with an arbitrary client_id) and the
// post-rotation predecessor re-read (which stops an in-flight rotation from
// resurrecting a family that reuse detection just revoked). Adding
// `AND consumed_at IS NULL` "by symmetry" with ConsumeRefreshToken breaks both:
// the pre-check treats every refresh as unknown, and every rotation revokes its
// own family.
const getRefreshTokenSQL = `SELECT ` + refreshCols + `
	FROM mcp_oauth_refresh_tokens WHERE token_hash = $1`

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (mcpoauth.RefreshToken, bool, error) {
	rt, err := scanRefreshToken(s.db.QueryRowContext(ctx, getRefreshTokenSQL, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.RefreshToken{}, false, nil
	}
	if err != nil {
		return mcpoauth.RefreshToken{}, false, fmt.Errorf("pgstore: loading refresh token: %w", err)
	}
	return rt, true, nil
}

// consumeRefreshTokenSQL stamps consumed_at exactly once and returns the row AS
// IT WAS BEFORE the call. Three things about it are load-bearing; none is a
// style choice.
//
//  1. It does NOT delete. The consumed row IS the reuse-detection ledger: it is
//     retained until its family expires, which is what makes detection survive a
//     restart and an unbounded number of rotations. Only PurgeExpired removes it.
//
//  2. `AND consumed_at IS NULL` on the UPDATE. Without it the row is re-stamped
//     on every replay while still returning its previous value — which passes
//     any two-call test, and turns Config.RefreshGracePeriod into a rolling,
//     unbounded window in which a stolen token is replayable forever and reuse
//     detection never fires. (Provider.VerifyStore consumes its canary three
//     times specifically to catch this.)
//
//  3. `SELECT ... FOR UPDATE` inside the SAME statement as the UPDATE. This is
//     what serialises concurrent callers so exactly one of them observes a zero
//     consumed_at. A SELECT then a separate UPDATE lets every concurrent caller
//     read the pre-write state, so one stolen token forks into N independently
//     usable rotation chains and there is no longer a canonical "next" token
//     whose replay would be caught.
//
// Do NOT rewrite it as `UPDATE ... WHERE consumed_at IS NULL RETURNING *`: that
// returns zero rows on a replay, which the Provider reads as "unknown token" —
// a plain invalid_grant with no family revocation, silently.
//
// It runs at READ COMMITTED, PostgreSQL's default, which is what the idiom is
// written for.
const consumeRefreshTokenSQL = `
	WITH before AS (
		SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE
	), stamped AS (
		UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL
	)
	SELECT ` + refreshCols + ` FROM before`

func (s *Store) ConsumeRefreshToken(ctx context.Context, tokenHash string, consumedAt time.Time) (mcpoauth.RefreshToken, bool, error) {
	rt, err := scanRefreshToken(s.db.QueryRowContext(ctx, consumeRefreshTokenSQL, tokenHash, consumedAt))
	if errors.Is(err, sql.ErrNoRows) {
		return mcpoauth.RefreshToken{}, false, nil
	}
	if err != nil {
		return mcpoauth.RefreshToken{}, false, fmt.Errorf("pgstore: consuming refresh token: %w", err)
	}
	return rt, true, nil
}

func (s *Store) RevokeRefreshTokensForUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("pgstore: revoking a user's refresh tokens: %w", err)
	}
	return nil
}

// RevokeRefreshTokenFamily deletes every token of one rotation chain, consumed
// rows included. It is called when a rotated-away token is replayed — the
// canonical signal that a token leaked — so once the family is dead there is
// nothing left to detect and deleting is correct.
//
// The empty-family guard matters: an unguarded `WHERE family_id = ”` would
// match every legacy row that never had a family and take unrelated sessions
// down with it.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`, familyID)
	if err != nil {
		return fmt.Errorf("pgstore: revoking refresh-token family: %w", err)
	}
	return nil
}

// --- purge ---------------------------------------------------------------

// purgeRefreshSQL requires BOTH conditions.
//
// A consumed row is the reuse ledger and must outlive its own expiry until the
// whole family dies. Dropping `AND family_expires_at < $1` deletes the evidence
// the moment the token's own TTL lapses, so a token stolen earlier and replayed
// later comes back as a plain invalid_grant instead of revoking the thief's
// family.
const purgeRefreshSQL = `DELETE FROM mcp_oauth_refresh_tokens
	WHERE expires_at < $1 AND family_expires_at < $1`

// PurgeExpired deletes records whose retention has lapsed. It is safe to run
// concurrently with everything else; the Provider calls it opportunistically,
// and applications should also run it from a ticker.
func (s *Store) PurgeExpired(ctx context.Context, before time.Time) error {
	stmts := []struct{ what, sql string }{
		{"authorization codes", `DELETE FROM mcp_oauth_auth_codes WHERE expires_at < $1`},
		{"pending authorizations", `DELETE FROM mcp_oauth_pending_auth WHERE expires_at < $1`},
		{"refresh tokens", purgeRefreshSQL},
		// /register is unauthenticated, so this is what stops the client table
		// from growing forever.
		{"clients", `DELETE FROM mcp_oauth_clients WHERE expires_at < $1`},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.sql, before); err != nil {
			return fmt.Errorf("pgstore: purging expired %s: %w", st.what, err)
		}
	}
	return nil
}

// --- user lookup ---------------------------------------------------------

// FindUserIDByEmail delegates to the application's WithUserLookup. It never
// creates a user: ok=false is how an unknown email is refused.
func (s *Store) FindUserIDByEmail(ctx context.Context, email string) (string, bool, error) {
	return s.userLookup(ctx, email)
}

// --- scanning ------------------------------------------------------------

type scanRow interface{ Scan(dest ...any) error }

func scanRefreshToken(row scanRow) (mcpoauth.RefreshToken, error) {
	var rt mcpoauth.RefreshToken
	var consumedAt sql.NullTime
	err := row.Scan(
		&rt.TokenHash, &rt.ClientID, &rt.UserID, &rt.FamilyID,
		&rt.FamilyCreatedAt, &rt.FamilyExpiresAt, &rt.ExpiresAt, &rt.CreatedAt,
		&consumedAt,
	)
	if err != nil {
		return mcpoauth.RefreshToken{}, err
	}
	if consumedAt.Valid {
		rt.ConsumedAt = normalizeZeroTime(consumedAt.Time)
	}
	rt.FamilyCreatedAt = normalizeZeroTime(rt.FamilyCreatedAt)
	rt.FamilyExpiresAt = normalizeZeroTime(rt.FamilyExpiresAt)
	rt.ExpiresAt = normalizeZeroTime(rt.ExpiresAt)
	rt.CreatedAt = normalizeZeroTime(rt.CreatedAt)
	return rt, nil
}

// normalizeZeroTime maps a timestamp that went in as Go's zero time back onto
// time.Time{}.
//
// PostgreSQL returns a TIMESTAMPTZ already converted to the session timezone,
// so `0001-01-01 00:00:00` read back under a non-UTC session is a *different
// instant* and IsZero() flips to false. That matters exactly where the Provider
// tests IsZero to decide something: a row with no family metadata would stop
// looking like one, and — far worse — a never-consumed row whose consumed_at
// was somehow written as the zero time would read as already consumed. Cheap
// insurance against a session-level setting the library does not control.
func normalizeZeroTime(t time.Time) time.Time {
	if t.Year() <= 1 {
		return time.Time{}
	}
	return t
}
