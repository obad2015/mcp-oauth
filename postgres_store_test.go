package mcpoauth_test

// The Store the PostgreSQL contract suite runs against.
//
// This is the seam. Stage 0 put a reference implementation here, transcribed
// from the two live consumers, so the suite in postgres_contract_test.go could
// be written and made green BEFORE the Store surface changed. Stage 1 replaced
// it with the library's own pgstore, and the suite itself did not move a line —
// which is the whole point of having written it first.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/pgstore"
)

// ensureTestSchema is what an application calls at startup.
func ensureTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := pgstore.EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("pgstore.EnsureSchema: %v", err)
	}
}

// newPostgresStore returns the Store under contract test. users stands in for
// the application's own users table — the one thing pgstore does not own.
func newPostgresStore(t *testing.T, db *sql.DB, users map[string]string) mcpoauth.Store {
	t.Helper()
	s, err := pgstore.New(db, pgstore.WithUserLookup(
		func(_ context.Context, email string) (string, bool, error) {
			id, ok := users[email]
			return id, ok, nil
		}))
	if err != nil {
		t.Fatalf("pgstore.New: %v", err)
	}
	return s
}

// pgScanRow and normalizePGTime are used by the deliberately-broken SQL in
// postgres_contract_test.go, which scans rows itself.
type pgScanRow interface{ Scan(dest ...any) error }

func normalizePGTime(t time.Time) time.Time {
	if t.Year() <= 1 {
		return time.Time{}
	}
	return t
}
