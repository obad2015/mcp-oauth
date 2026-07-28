package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SchemaSQL is the DDL for the four tables and their indexes, idempotent and
// safe to run repeatedly.
//
// Applications that insist on owning their own DDL can paste this into a
// migration instead of calling EnsureSchema — but then they also own the
// versioned steps in schemaSteps, and there is no upgrade path handed to them.
// EnsureSchema is the supported route.
//
// Three constraints here are not stylistic:
//
//   - No foreign keys. Not between these tables, and not to the application's
//     users table. The rows have independent lifetimes (a client registration
//     expires long before the refresh tokens it issued, and revoking a family
//     deletes rows other records may still name), and Provider.VerifyStore
//     writes canary rows for a user that does not exist.
//   - user_id is TEXT, not UUID. The Store contract is a plain string, and the
//     canary VerifyStore writes is not a UUID unless you set
//     Config.VerifyStoreUserID.
//   - client_id must hold at least 48 characters. Issued IDs are 32, so a
//     VARCHAR(32) column works in production and fails only under VerifyStore.
const SchemaSQL = `
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
    consumed_at       TIMESTAMPTZ
);

-- These two index names are PostgreSQL's own defaults for
--   CREATE INDEX ON mcp_oauth_refresh_tokens (family_id);
--   CREATE INDEX ON mcp_oauth_refresh_tokens (expires_at, family_expires_at);
-- which is how the pre-pgstore migrations created them. Naming them explicitly
-- is what makes IF NOT EXISTS a no-op on a database that already has them.
CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_family_id_idx
    ON mcp_oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_tokens_expires_at_family_expires_at_idx
    ON mcp_oauth_refresh_tokens (expires_at, family_expires_at);

CREATE TABLE IF NOT EXISTS mcp_oauth_schema_version (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version    INTEGER     NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

// schemaSteps are the versioned migrations applied after the baseline DDL, in
// order. A step is applied when the recorded version is below its own, and the
// version is bumped in the same transaction.
//
// Every step must be safe to run against a database created by an older
// version of this library AND against one the pre-pgstore migrations built by
// hand — which is why they use IF EXISTS / IF NOT EXISTS throughout.
var schemaSteps = []struct {
	version int
	sql     string
	why     string
}{
	{
		version: 1,
		sql:     `ALTER TABLE mcp_oauth_refresh_tokens DROP COLUMN IF EXISTS successor_sealed`,
		why: "v1 sealed a rotation's successor onto the consumed predecessor row so a " +
			"duplicate submission could be answered after a restart. v2 keeps that link in " +
			"process instead (losing it costs one re-login, never a security control), so the " +
			"column, its AES-GCM machinery and the Store method that wrote it are gone.",
	},
}

// schemaLockKey serialises concurrent EnsureSchema calls — two instances of a
// rolling deploy booting at once, or an app and a migration job. It is an
// arbitrary constant; it only has to be stable and unlikely to collide with
// another application's advisory locks.
const schemaLockKey int64 = 7043620148315471

// EnsureSchema creates and upgrades the mcp_oauth_* tables. It is idempotent
// and safe to call at every startup, and safe to call concurrently from several
// instances (it holds a transaction-scoped advisory lock).
//
// It adopts a database whose tables were created by an application's own
// migrations: the baseline DDL is all IF NOT EXISTS, so an existing schema is
// left alone and only the versioned steps run.
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("pgstore: db is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore: beginning schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, schemaLockKey); err != nil {
		return fmt.Errorf("pgstore: taking the schema lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, SchemaSQL); err != nil {
		return fmt.Errorf("pgstore: creating the schema: %w", err)
	}

	var version int
	err = tx.QueryRowContext(ctx, `SELECT version FROM mcp_oauth_schema_version`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		// A database that predates the version table. The baseline DDL above has
		// already brought its shape up to date, so it starts at 0 and the
		// versioned steps below run once.
		version = 0
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mcp_oauth_schema_version (singleton, version) VALUES (TRUE, 0)`); err != nil {
			return fmt.Errorf("pgstore: initialising the schema version: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("pgstore: reading the schema version: %w", err)
	}

	for _, step := range schemaSteps {
		if version >= step.version {
			continue
		}
		if _, err := tx.ExecContext(ctx, step.sql); err != nil {
			return fmt.Errorf("pgstore: applying schema step %d (%s): %w", step.version, step.why, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE mcp_oauth_schema_version SET version = $1, updated_at = now()`,
			step.version); err != nil {
			return fmt.Errorf("pgstore: recording schema version %d: %w", step.version, err)
		}
		version = step.version
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: committing the schema transaction: %w", err)
	}
	return nil
}

// EnsureSchema is EnsureSchema(ctx, s.db) — the form most callers want, since
// they already hold the Store.
func (s *Store) EnsureSchema(ctx context.Context) error {
	return EnsureSchema(ctx, s.db)
}
