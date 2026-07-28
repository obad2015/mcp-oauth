package mcpoauth_test

// PostgreSQL-backed contract tests.
//
// The package's own suites run against memstore, which is a perfect Store by
// construction: it cannot lose a column, it cannot forget a WHERE clause, and
// its "atomicity" is a mutex. Everything this library actually ships to
// production runs on SQL, where every one of those failure modes is one typo
// away — and four hardening rounds found their bugs exactly there. These tests
// pin the contract against a real PostgreSQL server.
//
// They are skipped unless MCPOAUTH_TEST_POSTGRES holds a DSN, so `go test ./...`
// stays green with no database:
//
//	MCPOAUTH_TEST_POSTGRES='postgres://user:pass@127.0.0.1:5432/db?sslmode=disable' go test -race ./...
//
// github.com/lib/pq is a TEST-ONLY dependency of this module: no non-test file
// imports it, so it is never linked into an application that depends on
// mcp-oauth (pgstore takes a *sql.DB and speaks no driver of its own).

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// postgresDSNEnv holds the connection string for the contract tests.
const postgresDSNEnv = "MCPOAUTH_TEST_POSTGRES"

// postgresDSN returns the configured DSN with the session timezone forced to
// UTC, or "" when the suite should be skipped.
//
// The timezone matters for exactly one value: Go's zero time. PostgreSQL
// returns a TIMESTAMPTZ already converted to the session timezone, and
// `0001-01-01 00:00:00` read back under, say, Europe/London comes back offset by
// the local mean time of 1901 — no longer time.Time{}, so RefreshToken.
// ConsumedAt.IsZero() silently flips to false and every first rotation looks
// like reuse. pgstore normalises that on the way out; forcing UTC here means
// the tests exercise the normal case as well as the pathological one.
func postgresDSN(t *testing.T) string {
	t.Helper()
	raw := os.Getenv(postgresDSNEnv)
	if raw == "" {
		t.Skipf("%s is not set; skipping the PostgreSQL contract tests", postgresDSNEnv)
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%s is not a valid URL: %v", postgresDSNEnv, err)
	}
	q := u.Query()
	if q.Get("TimeZone") == "" && q.Get("timezone") == "" {
		q.Set("TimeZone", "UTC")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// openPostgres returns a connected *sql.DB with the four tables present and
// empty. Every top-level test starts from a clean slate; the suite is
// deliberately not parallel, because PurgeExpired and the fault stores operate
// on whole tables.
func openPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := postgresDSN(t)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("connecting to postgres (%s): %v", postgresDSNEnv, err)
	}
	// A generous but bounded pool: the atomicity checks fire 8-32 concurrent
	// statements at the same row and each one holds a FOR UPDATE lock.
	db.SetMaxOpenConns(maxTestConns)
	warmPool(t, db)

	ensureTestSchema(t, db)
	truncateAll(t, db)
	return db
}

// maxTestConns bounds the pool. The atomicity checks fire 8-16 statements at
// one row simultaneously, and every one of them must already hold a connection
// when it starts.
const maxTestConns = 16

// warmPool establishes every connection up front.
//
// Without this the concurrency checks are worthless and quietly so: opening a
// TCP connection and authenticating costs milliseconds, far more than the race
// window they are trying to observe, so the first caller finishes its whole
// read-modify-write before the second has a connection to speak on. A
// non-atomic Store then looks perfectly atomic.
func warmPool(t *testing.T, db *sql.DB) {
	t.Helper()
	conns := make([]*sql.Conn, 0, maxTestConns)
	for i := 0; i < maxTestConns; i++ {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("warming connection %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		_ = c.Close() // returns it to the pool, still open
	}
}

func truncateAll(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		TRUNCATE mcp_oauth_clients, mcp_oauth_auth_codes,
		         mcp_oauth_pending_auth, mcp_oauth_refresh_tokens`)
	if err != nil {
		t.Fatalf("truncating the oauth tables: %v", err)
	}
}
