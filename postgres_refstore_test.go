package mcpoauth_test

// The PostgreSQL Store the contract suite runs against.
//
// STAGE 0 NOTE: at this commit the library does not ship a Store of its own, so
// this file carries a reference implementation transcribed from the two live
// consumers (personal-finance/api/internal/store/oauth.go, database/sql +
// lib/pq, and todo/api/internal/store/oauth.go, pgx/v5). That is deliberate:
// the contract suite in postgres_contract_test.go is the safety net for the v2
// Store-surface change, so it has to exist and pass BEFORE anything moves. When
// pgstore lands, this file is what gets replaced — the suite does not move.

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// ensureTestSchema creates the four tables the way the consumers' migrations do
// (personal-finance 000023, todo 000021), verbatim, so the suite is testing the
// shape that is actually in production.
func ensureTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	const ddl = `
CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    client_id      TEXT PRIMARY KEY,
    redirect_uris  JSONB       NOT NULL,
    client_name    TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS mcp_oauth_auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT        NOT NULL,
    user_id        TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS mcp_oauth_pending_auth (
    state_hash     TEXT PRIMARY KEY,
    client_id      TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,
    client_state   TEXT        NOT NULL DEFAULT '',
    binder_hash    TEXT        NOT NULL,
    approved       BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
    token_hash        TEXT PRIMARY KEY,
    client_id         TEXT        NOT NULL,
    user_id           TEXT        NOT NULL,
    family_id         TEXT        NOT NULL,
    family_created_at TIMESTAMPTZ NOT NULL,
    family_expires_at TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    successor_sealed  BYTEA
);
CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_family_id_idx
    ON mcp_oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_expires_at_family_expires_at_idx
    ON mcp_oauth_refresh_tokens (expires_at, family_expires_at);
`
	if _, err := db.ExecContext(context.Background(), ddl); err != nil {
		t.Fatalf("creating the oauth schema: %v", err)
	}
}

// newPostgresStore returns the Store under contract test. users maps a
// lowercased email to a user ID, standing in for the application's users table.
func newPostgresStore(t *testing.T, db *sql.DB, users map[string]string) mcpoauth.Store {
	t.Helper()
	return &pgRefStore{db: db, users: users}
}

// pgRefStore is the consumers' proven SQL, one implementation, database/sql.
type pgRefStore struct {
	db    *sql.DB
	users map[string]string
}

var _ mcpoauth.Store = (*pgRefStore)(nil)

func (s *pgRefStore) SaveClient(ctx context.Context, c mcpoauth.Client) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_clients (client_id, redirect_uris, client_name, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (client_id) DO UPDATE SET
			redirect_uris = EXCLUDED.redirect_uris,
			client_name = EXCLUDED.client_name,
			expires_at = EXCLUDED.expires_at
	`, c.ClientID, uris, c.ClientName, c.CreatedAt, c.ExpiresAt)
	return err
}

func (s *pgRefStore) GetClient(ctx context.Context, clientID string) (mcpoauth.Client, bool, error) {
	var c mcpoauth.Client
	var uris []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, redirect_uris, client_name, created_at, expires_at
		FROM mcp_oauth_clients WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &uris, &c.ClientName, &c.CreatedAt, &c.ExpiresAt)
	if err == sql.ErrNoRows {
		return mcpoauth.Client{}, false, nil
	}
	if err != nil {
		return mcpoauth.Client{}, false, err
	}
	if err := json.Unmarshal(uris, &c.RedirectURIs); err != nil {
		return mcpoauth.Client{}, false, err
	}
	return c, true, nil
}

func (s *pgRefStore) SaveAuthCode(ctx context.Context, code mcpoauth.AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_auth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.CodeChallenge, code.ExpiresAt, code.CreatedAt)
	return err
}

func (s *pgRefStore) ConsumeAuthCode(ctx context.Context, codeHash string) (mcpoauth.AuthCode, bool, error) {
	var c mcpoauth.AuthCode
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM mcp_oauth_auth_codes WHERE code_hash = $1
		RETURNING code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at
	`, codeHash).Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.CodeChallenge, &c.ExpiresAt, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return mcpoauth.AuthCode{}, false, nil
	}
	if err != nil {
		return mcpoauth.AuthCode{}, false, err
	}
	return c, true, nil
}

func (s *pgRefStore) SavePendingAuth(ctx context.Context, p mcpoauth.PendingAuth) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_pending_auth
			(state_hash, client_id, redirect_uri, code_challenge, client_state, binder_hash, approved, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, p.StateHash, p.ClientID, p.RedirectURI, p.CodeChallenge, p.ClientState, p.BinderHash, p.Approved, p.ExpiresAt, p.CreatedAt)
	return err
}

func (s *pgRefStore) ConsumePendingAuth(ctx context.Context, stateHash string) (mcpoauth.PendingAuth, bool, error) {
	var p mcpoauth.PendingAuth
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM mcp_oauth_pending_auth WHERE state_hash = $1
		RETURNING state_hash, client_id, redirect_uri, code_challenge, client_state, binder_hash, approved, expires_at, created_at
	`, stateHash).Scan(&p.StateHash, &p.ClientID, &p.RedirectURI, &p.CodeChallenge, &p.ClientState, &p.BinderHash, &p.Approved, &p.ExpiresAt, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return mcpoauth.PendingAuth{}, false, nil
	}
	if err != nil {
		return mcpoauth.PendingAuth{}, false, err
	}
	return p, true, nil
}

func (s *pgRefStore) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_refresh_tokens
			(token_hash, client_id, user_id, family_id, family_created_at, family_expires_at, expires_at, created_at, consumed_at, successor_sealed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL)
	`, rt.TokenHash, rt.ClientID, rt.UserID, rt.FamilyID, rt.FamilyCreatedAt, rt.FamilyExpiresAt, rt.ExpiresAt, rt.CreatedAt)
	return err
}

func (s *pgRefStore) GetRefreshToken(ctx context.Context, tokenHash string) (mcpoauth.RefreshToken, bool, error) {
	rt, err := scanPGRefreshToken(s.db.QueryRowContext(ctx, `
		SELECT token_hash, client_id, user_id, family_id, family_created_at, family_expires_at, expires_at, created_at, consumed_at, successor_sealed
		FROM mcp_oauth_refresh_tokens WHERE token_hash = $1
	`, tokenHash))
	if err == sql.ErrNoRows {
		return mcpoauth.RefreshToken{}, false, nil
	}
	if err != nil {
		return mcpoauth.RefreshToken{}, false, err
	}
	return rt, true, nil
}

func (s *pgRefStore) ConsumeRefreshToken(ctx context.Context, tokenHash string, consumedAt time.Time) (mcpoauth.RefreshToken, bool, error) {
	rt, err := scanPGRefreshToken(s.db.QueryRowContext(ctx, `
		WITH before AS (
			SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE
		), stamped AS (
			UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
			WHERE token_hash = $1 AND consumed_at IS NULL
		)
		SELECT token_hash, client_id, user_id, family_id, family_created_at,
		       family_expires_at, expires_at, created_at, consumed_at, successor_sealed
		FROM before
	`, tokenHash, consumedAt))
	if err == sql.ErrNoRows {
		return mcpoauth.RefreshToken{}, false, nil
	}
	if err != nil {
		return mcpoauth.RefreshToken{}, false, err
	}
	return rt, true, nil
}

func (s *pgRefStore) LinkRefreshSuccessor(ctx context.Context, tokenHash, familyID string, sealed []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE mcp_oauth_refresh_tokens
		SET family_id = $2, successor_sealed = $3
		WHERE token_hash = $1
	`, tokenHash, familyID, sealed)
	return err
}

func (s *pgRefStore) RevokeRefreshTokensForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE user_id = $1`, userID)
	return err
}

func (s *pgRefStore) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`, familyID)
	return err
}

func (s *pgRefStore) PurgeExpired(ctx context.Context, before time.Time) error {
	stmts := []string{
		`DELETE FROM mcp_oauth_auth_codes WHERE expires_at < $1`,
		`DELETE FROM mcp_oauth_pending_auth WHERE expires_at < $1`,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < $1 AND family_expires_at < $1`,
		`DELETE FROM mcp_oauth_clients WHERE expires_at < $1`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q, before); err != nil {
			return err
		}
	}
	return nil
}

func (s *pgRefStore) FindUserIDByEmail(_ context.Context, email string) (string, bool, error) {
	id, ok := s.users[email]
	return id, ok, nil
}

type pgScanRow interface{ Scan(dest ...any) error }

func scanPGRefreshToken(row pgScanRow) (mcpoauth.RefreshToken, error) {
	var rt mcpoauth.RefreshToken
	var consumedAt sql.NullTime
	var sealed []byte
	err := row.Scan(
		&rt.TokenHash, &rt.ClientID, &rt.UserID, &rt.FamilyID,
		&rt.FamilyCreatedAt, &rt.FamilyExpiresAt, &rt.ExpiresAt, &rt.CreatedAt,
		&consumedAt, &sealed,
	)
	if err != nil {
		return mcpoauth.RefreshToken{}, err
	}
	if consumedAt.Valid {
		rt.ConsumedAt = normalizePGTime(consumedAt.Time)
	}
	rt.FamilyCreatedAt = normalizePGTime(rt.FamilyCreatedAt)
	rt.FamilyExpiresAt = normalizePGTime(rt.FamilyExpiresAt)
	rt.ExpiresAt = normalizePGTime(rt.ExpiresAt)
	rt.CreatedAt = normalizePGTime(rt.CreatedAt)
	rt.SuccessorSealed = sealed
	return rt, nil
}

// normalizePGTime maps a timestamp that went into the database as Go's zero
// time back onto time.Time{}. PostgreSQL hands a TIMESTAMPTZ back already
// converted to the session timezone, and `0001-01-01 00:00:00` under a non-UTC
// session is a different instant — so IsZero() flips to false and a token with
// no family metadata stops looking like one.
func normalizePGTime(t time.Time) time.Time {
	if t.Year() <= 1 {
		return time.Time{}
	}
	return t
}
