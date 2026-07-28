package mcpoauth_test

// pgstore.EnsureSchema against a database that already exists.
//
// Both consumers created these tables by hand, through golang-migrate, before
// pgstore existed. Adopting those databases without a flag day — and without
// logging anyone out — is a hard requirement of the v2 release, so it is tested
// against the exact DDL those migrations shipped.

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/pgstore"
)

// legacySchemaSQL is personal-finance migration 000023 / todo migration 000021,
// verbatim: the four tables as they exist in production today, successor_sealed
// and all, with no version table.
const legacySchemaSQL = `
CREATE TABLE mcp_oauth_clients (
    client_id      TEXT PRIMARY KEY,
    redirect_uris  JSONB       NOT NULL,
    client_name    TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE mcp_oauth_auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT        NOT NULL,
    user_id        TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE mcp_oauth_pending_auth (
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
CREATE TABLE mcp_oauth_refresh_tokens (
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
CREATE INDEX ON mcp_oauth_refresh_tokens (family_id);
CREATE INDEX ON mcp_oauth_refresh_tokens (expires_at, family_expires_at);
`

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_name = $1 AND column_name = $2`, table, column).Scan(&n)
	if err != nil {
		t.Fatalf("inspecting %s.%s: %v", table, column, err)
	}
	return n > 0
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRowContext(context.Background(),
		`SELECT version FROM mcp_oauth_schema_version`).Scan(&v); err != nil {
		t.Fatalf("reading the schema version: %v", err)
	}
	return v
}

func TestPostgresEnsureSchema(t *testing.T) {
	ctx := context.Background()

	t.Run("creates everything from nothing, and is idempotent", func(t *testing.T) {
		db := openPostgresRaw(t)
		dropAll(t, db)

		for i := 0; i < 3; i++ {
			if err := pgstore.EnsureSchema(ctx, db); err != nil {
				t.Fatalf("EnsureSchema run %d: %v", i, err)
			}
		}
		if columnExists(t, db, "mcp_oauth_refresh_tokens", "successor_sealed") {
			t.Fatal("a fresh database was created with the removed successor_sealed column")
		}
		if got := schemaVersion(t, db); got != 1 {
			t.Fatalf("schema version = %d, want 1", got)
		}
	})

	t.Run("adopts a database the consumers' migrations built", func(t *testing.T) {
		db := openPostgresRaw(t)
		dropAll(t, db)
		mustExec(t, db, legacySchemaSQL)

		if !columnExists(t, db, "mcp_oauth_refresh_tokens", "successor_sealed") {
			t.Fatal("the legacy fixture is wrong: successor_sealed should be present")
		}
		if err := pgstore.EnsureSchema(ctx, db); err != nil {
			t.Fatalf("EnsureSchema over the legacy schema: %v", err)
		}
		if columnExists(t, db, "mcp_oauth_refresh_tokens", "successor_sealed") {
			t.Fatal("EnsureSchema did not drop successor_sealed")
		}
		if got := schemaVersion(t, db); got != 1 {
			t.Fatalf("schema version = %d, want 1", got)
		}
	})

	t.Run("in-flight refresh tokens keep working across the upgrade", func(t *testing.T) {
		// The release requirement: rows, hashes and families are unchanged, so
		// nobody is logged out by the deploy. Seed a live token into the LEGACY
		// schema exactly as v1 would have written it — sealed successor and all
		// — then upgrade and rotate it.
		db := openPostgresRaw(t)
		dropAll(t, db)
		mustExec(t, db, legacySchemaSQL)

		now := time.Now()
		const clientID = "in-flight-client"
		const liveToken = "an-in-flight-refresh-token-from-v1"
		mustExec(t, db, `
			INSERT INTO mcp_oauth_clients (client_id, redirect_uris, client_name, created_at, expires_at)
			VALUES ($1, $2, '', $3, $4)`,
			clientID, `["`+testRedirectURI+`"]`, now.Add(-time.Hour), now.Add(90*24*time.Hour))
		mustExec(t, db, `
			INSERT INTO mcp_oauth_refresh_tokens
				(token_hash, client_id, user_id, family_id, family_created_at,
				 family_expires_at, expires_at, created_at, consumed_at, successor_sealed)
			VALUES ($1, $2, $3, 'in-flight-family', $4, $5, $6, $4, NULL, $7)`,
			mcpoauth.HashSecret(liveToken), clientID, testUserID,
			now.Add(-time.Hour), now.Add(89*24*time.Hour), now.Add(29*24*time.Hour),
			[]byte("a v1 sealed successor blob nobody will ever open"))

		if err := pgstore.EnsureSchema(ctx, db); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}

		store := newPostgresStore(t, db, pgUsers())
		p := verifyProvider(t, store)

		rec := newRec()
		p.Token()(rec, postForm("/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {liveToken}, "client_id": {clientID},
		}))
		if rec.Code != 200 {
			t.Fatalf("a refresh token issued by v1 stopped working after the upgrade: %d %s",
				rec.Code, rec.Body.String())
		}
		next := decodeJSON[tokenSuccess](t, rec)

		// Same family, and reuse detection is intact across the boundary.
		row, ok, err := store.GetRefreshToken(ctx, mcpoauth.HashSecret(next.RefreshToken))
		if err != nil || !ok {
			t.Fatalf("the successor row is missing: ok=%v err=%v", ok, err)
		}
		if row.FamilyID != "in-flight-family" {
			t.Fatalf("the rotation started a new family (%q): every v1 session would be "+
				"orphaned from its own reuse ledger", row.FamilyID)
		}
		p.SetNowForTest(func() time.Time { return time.Now().Add(5 * time.Minute) })
		rec = newRec()
		p.Token()(rec, postForm("/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {liveToken}, "client_id": {clientID},
		}))
		if desc := decodeJSON[errorBody](t, rec).Description; !strings.Contains(desc, "revoked") {
			t.Fatalf("replaying the upgraded token did not revoke its family: %d %q", rec.Code, desc)
		}
	})

	t.Run("concurrent instances booting at once", func(t *testing.T) {
		// A rolling deploy runs EnsureSchema from several processes
		// simultaneously; CREATE TABLE IF NOT EXISTS is not, on its own, immune
		// to that. The advisory lock is.
		db := openPostgresRaw(t)
		dropAll(t, db)

		const racers = 8
		errs := make([]error, racers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = pgstore.EnsureSchema(ctx, db)
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent EnsureSchema %d: %v", i, err)
			}
		}
		if got := schemaVersion(t, db); got != 1 {
			t.Fatalf("schema version = %d, want 1", got)
		}
	})

	t.Run("the schema it creates is contract-compliant", func(t *testing.T) {
		db := openPostgresRaw(t)
		dropAll(t, db)
		if err := pgstore.EnsureSchema(ctx, db); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}
		if err := verifyProvider(t, newPostgresStore(t, db, pgUsers())).VerifyStore(ctx); err != nil {
			t.Fatalf("VerifyStore against a schema EnsureSchema built: %v", err)
		}
	})
}

// TestPgstoreNewRequiresAUserLookup pins the one method applications must
// supply. Defaulting it to something would mean guessing at a users table, and
// the wrong guess is either a lockout or — far worse — silent account creation.
func TestPgstoreNewRequiresAUserLookup(t *testing.T) {
	db := openPostgresRaw(t)
	if _, err := pgstore.New(db); err == nil {
		t.Fatal("pgstore.New accepted a Store with no user lookup")
	}
	if _, err := pgstore.New(nil, pgstore.WithUserLookup(
		func(context.Context, string) (string, bool, error) { return "", false, nil })); err == nil {
		t.Fatal("pgstore.New accepted a nil *sql.DB")
	}
}
