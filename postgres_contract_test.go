package mcpoauth_test

// The Store contract, pinned against a real PostgreSQL server.
//
// Two kinds of test live here:
//
//  1. The shipped SQL must be compliant: VerifyStore passes, and each invariant
//     the security model leans on is asserted directly.
//  2. Plausible WRONG SQL must be caught. Every fault below is real SQL that a
//     competent engineer could write — the `AND consumed_at IS NULL` guard left
//     off, `UPDATE ... RETURNING` instead of the CTE, a purge missing half its
//     condition — run against the same server. Over memstore these faults have
//     to be simulated in a wrapper; here they are the actual statements, so the
//     suite proves the detection works on the medium that ships.
//
// This file is the safety net for the v2 Store-surface change: it is written
// against the mcpoauth.Store interface and the *sql.DB only, so swapping the
// implementation underneath it (memstore reference SQL -> pgstore) does not
// touch a line of it.

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// pgUsers is the stand-in application users table for the contract suite.
func pgUsers() map[string]string { return map[string]string{testEmail: testUserID} }

// seedRefresh writes a refresh-token row and returns it.
func seedRefresh(t *testing.T, s mcpoauth.Store, rt mcpoauth.RefreshToken) mcpoauth.RefreshToken {
	t.Helper()
	if err := s.SaveRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	return rt
}

// liveRefresh reports how many usable (unconsumed) refresh rows exist. The
// memstore suites get this from memstore.LiveRefresh; over SQL it is a query.
func liveRefresh(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM mcp_oauth_refresh_tokens WHERE consumed_at IS NULL`).Scan(&n)
	if err != nil {
		t.Fatalf("counting live refresh rows: %v", err)
	}
	return n
}

// --- 1. the shipped SQL is compliant -------------------------------------

// TestPostgresVerifyStore runs the startup self-check against real PostgreSQL.
// Everything below it is a more specific restatement of one of its checks; this
// is the one that has to stay green for the library to be shippable at all.
func TestPostgresVerifyStore(t *testing.T) {
	db := openPostgres(t)
	store := newPostgresStore(t, db, pgUsers())
	p := verifyProvider(t, store)

	// Twice: startup verification runs on every boot, including the second
	// instance of a rolling deploy.
	for i := 0; i < 2; i++ {
		if err := p.VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore() run %d against PostgreSQL: %v", i, err)
		}
	}
}

// TestPostgresConsumeRefreshTokenCTE pins the single most load-bearing
// statement in the package. Its exact shape is the difference between working
// reuse detection and a stolen refresh token that is replayable forever.
func TestPostgresConsumeRefreshTokenCTE(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)

	newRow := func(hash string) mcpoauth.RefreshToken {
		return mcpoauth.RefreshToken{
			TokenHash: hash, ClientID: "client-a", UserID: testUserID,
			FamilyID:        "family-" + hash[:8],
			FamilyCreatedAt: now.Add(-time.Hour),
			FamilyExpiresAt: now.Add(24 * time.Hour),
			ExpiresAt:       now.Add(time.Hour),
			CreatedAt:       now.Add(-time.Hour),
		}
	}

	t.Run("of N concurrent callers exactly one sees a zero ConsumedAt", func(t *testing.T) {
		// The blind spot no single-threaded check can see: a SELECT-then-UPDATE
		// lets every caller read the row before any of them writes, so one
		// stolen token forks into N usable rotation chains and reuse detection
		// can never fire again.
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		const racers = 16
		hash := mcpoauth.HashSecret("cte-atomicity")
		seedRefresh(t, store, newRow(hash))

		type result struct {
			rt  mcpoauth.RefreshToken
			ok  bool
			err error
		}
		results := make([]result, racers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				rt, ok, err := store.ConsumeRefreshToken(ctx, hash, now)
				results[i] = result{rt, ok, err}
			}(i)
		}
		close(start)
		wg.Wait()

		zero := 0
		for i, r := range results {
			if r.err != nil {
				t.Fatalf("concurrent consume %d: %v", i, r.err)
			}
			if !r.ok {
				t.Fatalf("concurrent consume %d returned ok=false for a row that exists", i)
			}
			if r.rt.ConsumedAt.IsZero() {
				zero++
			}
		}
		if zero != 1 {
			t.Fatalf("%d of %d concurrent callers saw a zero ConsumedAt, want exactly 1: "+
				"the CTE's `SELECT ... FOR UPDATE` is not serialising the callers", zero, racers)
		}
	})

	t.Run("a replay returns the ORIGINAL stamp and never re-stamps", func(t *testing.T) {
		// The `AND consumed_at IS NULL` guard. Without it the row is re-stamped
		// on every call while still returning its previous value, which passes
		// any two-call test and turns RefreshGracePeriod into a rolling,
		// unbounded window.
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		hash := mcpoauth.HashSecret("cte-anchored")
		seedRefresh(t, store, newRow(hash))

		first, ok, err := store.ConsumeRefreshToken(ctx, hash, now)
		if err != nil || !ok {
			t.Fatalf("first consume: ok=%v err=%v", ok, err)
		}
		if !first.ConsumedAt.IsZero() {
			t.Fatalf("the first consume returned the row AFTER stamping it (ConsumedAt=%v); "+
				"every first rotation would look like reuse", first.ConsumedAt)
		}

		for i, at := range []time.Time{now.Add(time.Hour), now.Add(9 * time.Hour)} {
			again, ok, err := store.ConsumeRefreshToken(ctx, hash, at)
			if err != nil {
				t.Fatalf("replay %d: %v", i, err)
			}
			if !ok {
				t.Fatalf("replay %d: the row is gone — ConsumeRefreshToken must never delete, "+
					"it is the durable reuse-detection ledger", i)
			}
			if d := again.ConsumedAt.Sub(now); d > time.Second || d < -time.Second {
				t.Fatalf("replay %d reports ConsumedAt=%v, want the ORIGINAL %v: the UPDATE is "+
					"missing its `AND consumed_at IS NULL` guard, so the grace window rolls "+
					"forever and a stolen token stays replayable", i, again.ConsumedAt.UTC(), now.UTC())
			}
		}

		// ...and the stamp that is actually persisted is the first one too.
		stored, ok, err := store.GetRefreshToken(ctx, hash)
		if err != nil || !ok {
			t.Fatalf("reading the consumed row back: ok=%v err=%v", ok, err)
		}
		if d := stored.ConsumedAt.Sub(now); d > time.Second || d < -time.Second {
			t.Fatalf("the persisted ConsumedAt is %v, want %v", stored.ConsumedAt.UTC(), now.UTC())
		}
	})

	t.Run("an expired row is still returned", func(t *testing.T) {
		// `AND expires_at > now()` here turns a replayed stolen token into a
		// plain invalid_grant and the family is never revoked.
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		hash := mcpoauth.HashSecret("cte-expired")
		row := newRow(hash)
		row.ExpiresAt = now.Add(-time.Hour) // lapsed; its family has not
		seedRefresh(t, store, row)

		got, ok, err := store.ConsumeRefreshToken(ctx, hash, now)
		if err != nil {
			t.Fatalf("consuming an expired row: %v", err)
		}
		if !ok {
			t.Fatal("ConsumeRefreshToken filtered out a row whose own ExpiresAt has passed; " +
				"an expired CONSUMED row is the reuse-detection ledger")
		}
		if got.TokenHash != hash {
			t.Fatalf("returned the wrong row: %q", got.TokenHash)
		}
	})

	t.Run("an unknown hash is ok=false, not an error", func(t *testing.T) {
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		rt, ok, err := store.ConsumeRefreshToken(ctx, mcpoauth.HashSecret("never-issued"), now)
		if err != nil {
			t.Fatalf("consuming an unknown hash errored instead of reporting ok=false: %v", err)
		}
		if ok {
			t.Fatalf("an unknown hash was reported as a real row: %+v", rt)
		}
	})
}

// TestPostgresGetRefreshTokenIsUnfiltered covers the rule the Provider calls on
// an ALREADY-CONSUMED row twice: the client-binding pre-check before a rotation,
// and the post-rotation predecessor re-read. Adding `AND consumed_at IS NULL`
// by symmetry with ConsumeRefreshToken breaks both — the pre-check treats every
// refresh as an unknown token, and the re-read never finds the predecessor, so
// every rotation revokes its own family.
func TestPostgresGetRefreshTokenIsUnfiltered(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	store := newPostgresStore(t, db, pgUsers())
	now := time.Now()

	hash := mcpoauth.HashSecret("unfiltered-get")
	seedRefresh(t, store, mcpoauth.RefreshToken{
		TokenHash: hash, ClientID: "client-a", UserID: testUserID,
		FamilyID:        "family-unfiltered",
		FamilyCreatedAt: now.Add(-time.Hour),
		FamilyExpiresAt: now.Add(24 * time.Hour),
		ExpiresAt:       now.Add(-time.Minute), // already expired
		CreatedAt:       now.Add(-time.Hour),
	})
	if _, _, err := store.ConsumeRefreshToken(ctx, hash, now); err != nil {
		t.Fatalf("consuming: %v", err)
	}

	got, ok, err := store.GetRefreshToken(ctx, hash)
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if !ok {
		t.Fatal("GetRefreshToken dropped a consumed, expired row. It must not be filtered on " +
			"consumed_at, expires_at or family_expires_at: the Provider reads exactly this " +
			"row for the client-binding pre-check and the post-rotation re-read")
	}
	if got.ConsumedAt.IsZero() {
		t.Fatal("GetRefreshToken returned the row without its ConsumedAt stamp")
	}
	if got.FamilyID != "family-unfiltered" {
		t.Fatalf("FamilyID = %q, want family-unfiltered", got.FamilyID)
	}
}

// TestPostgresSingleUse covers the two records that MUST be destroyed by
// reading them: authorization codes and pending-authorize state.
func TestPostgresSingleUse(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("an authorization code cannot be consumed twice", func(t *testing.T) {
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		hash := mcpoauth.HashSecret("single-use-code")
		if err := store.SaveAuthCode(ctx, mcpoauth.AuthCode{
			CodeHash: hash, ClientID: "client-a", UserID: testUserID,
			RedirectURI: testRedirectURI, CodeChallenge: strings.Repeat("a", 43),
			ExpiresAt: now.Add(5 * time.Minute), CreatedAt: now,
		}); err != nil {
			t.Fatalf("SaveAuthCode: %v", err)
		}
		if _, ok, err := store.ConsumeAuthCode(ctx, hash); err != nil || !ok {
			t.Fatalf("first consume: ok=%v err=%v", ok, err)
		}
		if _, ok, err := store.ConsumeAuthCode(ctx, hash); err != nil || ok {
			t.Fatalf("an authorization code was exchangeable twice (ok=%v err=%v): "+
				"ConsumeAuthCode must be a DELETE ... RETURNING", ok, err)
		}
	})

	t.Run("concurrent callers: exactly one wins the code", func(t *testing.T) {
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		hash := mcpoauth.HashSecret("racing-code")
		if err := store.SaveAuthCode(ctx, mcpoauth.AuthCode{
			CodeHash: hash, ClientID: "client-a", UserID: testUserID,
			RedirectURI: testRedirectURI, CodeChallenge: strings.Repeat("a", 43),
			ExpiresAt: now.Add(5 * time.Minute), CreatedAt: now,
		}); err != nil {
			t.Fatalf("SaveAuthCode: %v", err)
		}

		const racers = 8
		wins := make([]bool, racers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range wins {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, ok, err := store.ConsumeAuthCode(ctx, hash)
				if err != nil {
					t.Errorf("concurrent ConsumeAuthCode %d: %v", i, err)
				}
				wins[i] = ok
			}(i)
		}
		close(start)
		wg.Wait()

		n := 0
		for _, w := range wins {
			if w {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d of %d concurrent callers exchanged the same authorization code, want 1", n, racers)
		}
	})

	t.Run("pending auth is single-use and keyed on state_hash, not client_id", func(t *testing.T) {
		// Every flow saves TWO pending records with the same ClientID and
		// different StateHashes (the consent nonce, then the Google state). An
		// upsert keyed on client_id silently drops the first and every login
		// dies at the consent step.
		db := openPostgres(t)
		store := newPostgresStore(t, db, pgUsers())
		first := mcpoauth.HashSecret("pending-consent-nonce")
		second := mcpoauth.HashSecret("pending-google-state")
		for _, h := range []string{first, second} {
			if err := store.SavePendingAuth(ctx, mcpoauth.PendingAuth{
				StateHash: h, ClientID: "client-a", RedirectURI: testRedirectURI,
				CodeChallenge: strings.Repeat("b", 43), BinderHash: mcpoauth.HashSecret("binder"),
				Approved: true, ExpiresAt: now.Add(10 * time.Minute), CreatedAt: now,
			}); err != nil {
				t.Fatalf("SavePendingAuth(%s): %v", h[:8], err)
			}
		}
		for _, h := range []string{first, second} {
			got, ok, err := store.ConsumePendingAuth(ctx, h)
			if err != nil || !ok {
				t.Fatalf("ConsumePendingAuth(%s): ok=%v err=%v — SavePendingAuth must be a "+
					"plain INSERT keyed on state_hash", h[:8], ok, err)
			}
			if got.BinderHash == "" {
				t.Fatal("PendingAuth.BinderHash did not round-trip: the browser binding that " +
					"stops the authorization hijack is gone")
			}
			if !got.Approved {
				t.Fatal("PendingAuth.Approved did not round-trip: the consent step is bypassable")
			}
			if _, again, err := store.ConsumePendingAuth(ctx, h); err != nil || again {
				t.Fatalf("pending state %s was consumable twice (ok=%v err=%v)", h[:8], again, err)
			}
		}
	})
}

// TestPostgresPurgeRetention pins the retention rule: a consumed refresh-token
// row is the reuse ledger, so it must survive its OWN expiry and only go when
// its family has expired too.
func TestPostgresPurgeRetention(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	store := newPostgresStore(t, db, pgUsers())
	now := time.Now()

	hash := mcpoauth.HashSecret("retention")
	seedRefresh(t, store, mcpoauth.RefreshToken{
		TokenHash: hash, ClientID: "client-a", UserID: testUserID,
		FamilyID:        "family-retention",
		FamilyCreatedAt: now.Add(-2 * time.Hour),
		FamilyExpiresAt: now.Add(time.Hour),    // family alive
		ExpiresAt:       now.Add(-time.Minute), // token itself expired
		CreatedAt:       now.Add(-2 * time.Hour),
	})
	if _, _, err := store.ConsumeRefreshToken(ctx, hash, now.Add(-time.Minute)); err != nil {
		t.Fatalf("consuming: %v", err)
	}

	if err := store.PurgeExpired(ctx, now); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if _, ok, err := store.GetRefreshToken(ctx, hash); err != nil || !ok {
		t.Fatal("PurgeExpired deleted a consumed row whose own ExpiresAt had passed while its " +
			"FamilyExpiresAt had not. The DELETE is missing `AND family_expires_at < $1`: a " +
			"token stolen earlier and replayed later becomes a plain invalid_grant instead of " +
			"the reuse signal that revokes the thief's family")
	}

	// Once the family is over too, the row goes.
	if err := store.PurgeExpired(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if _, ok, _ := store.GetRefreshToken(ctx, hash); ok {
		t.Fatal("PurgeExpired kept a refresh row whose own ExpiresAt AND FamilyExpiresAt have " +
			"both passed: the ledger grows without bound")
	}

	t.Run("expired clients, codes and pending records are purged", func(t *testing.T) {
		clientID := "purge-client-" + strings.Repeat("x", 34)
		if err := store.SaveClient(ctx, mcpoauth.Client{
			ClientID: clientID, RedirectURIs: []string{testRedirectURI},
			ClientName: "canary", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("SaveClient: %v", err)
		}
		if err := store.SaveAuthCode(ctx, mcpoauth.AuthCode{
			CodeHash: mcpoauth.HashSecret("purge-code"), ClientID: clientID, UserID: testUserID,
			RedirectURI: testRedirectURI, CodeChallenge: strings.Repeat("a", 43),
			ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SaveAuthCode: %v", err)
		}
		if err := store.SavePendingAuth(ctx, mcpoauth.PendingAuth{
			StateHash: mcpoauth.HashSecret("purge-pending"), ClientID: clientID,
			RedirectURI: testRedirectURI, CodeChallenge: strings.Repeat("b", 43),
			BinderHash: "x", ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SavePendingAuth: %v", err)
		}
		if err := store.PurgeExpired(ctx, now); err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if _, ok, _ := store.GetClient(ctx, clientID); ok {
			t.Fatal("PurgeExpired does not delete expired clients: /register is unauthenticated, " +
				"so the client table grows without bound")
		}
		if _, ok, _ := store.ConsumeAuthCode(ctx, mcpoauth.HashSecret("purge-code")); ok {
			t.Fatal("PurgeExpired does not delete expired authorization codes")
		}
		if _, ok, _ := store.ConsumePendingAuth(ctx, mcpoauth.HashSecret("purge-pending")); ok {
			t.Fatal("PurgeExpired does not delete expired pending-authorize records")
		}
	})
}

// TestPostgresRefreshRotationEndToEnd drives the actual token endpoint over
// real SQL: rotate, duplicate inside the grace window, replay outside it. This
// is the shape of the four HIGH findings the refresh subsystem produced, run on
// the medium they were found on.
func TestPostgresRefreshRotationEndToEnd(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	store := newPostgresStore(t, db, pgUsers())
	p := verifyProvider(t, store)

	clock := time.Now()
	at := func(d time.Duration) { clock = clock.Add(d); p.SetNowForTest(func() time.Time { return clock }) }
	at(0)

	const clientID = "pg-e2e-client"
	if err := store.SaveClient(ctx, mcpoauth.Client{
		ClientID: clientID, RedirectURIs: []string{testRedirectURI},
		CreatedAt: clock, ExpiresAt: clock.Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	const seedToken = "pg-e2e-seed-refresh-token"
	seedRefresh(t, store, mcpoauth.RefreshToken{
		TokenHash: mcpoauth.HashSecret(seedToken), ClientID: clientID, UserID: testUserID,
		FamilyID:        "pg-e2e-family",
		FamilyCreatedAt: clock,
		FamilyExpiresAt: clock.Add(90 * 24 * time.Hour),
		ExpiresAt:       clock.Add(30 * 24 * time.Hour),
		CreatedAt:       clock,
	})

	refresh := func(token string) (int, tokenSuccess, errorBody) {
		t.Helper()
		rec := newRec()
		p.Token()(rec, postForm("/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {clientID},
		}))
		if rec.Code == 200 {
			return rec.Code, decodeJSON[tokenSuccess](t, rec), errorBody{}
		}
		return rec.Code, tokenSuccess{}, decodeJSON[errorBody](t, rec)
	}

	at(time.Minute)
	code, first, errBody := refresh(seedToken)
	if code != 200 {
		t.Fatalf("rotation: %d %+v", code, errBody)
	}
	if first.RefreshToken == "" || first.AccessToken == "" {
		t.Fatal("rotation returned an empty pair")
	}
	if n := liveRefresh(t, db); n != 1 {
		t.Fatalf("%d live refresh rows after one rotation, want 1", n)
	}

	// A duplicate submission inside the grace window gets the SAME successor.
	at(5 * time.Second)
	code, dup, errBody := refresh(seedToken)
	if code != 200 {
		t.Fatalf("duplicate submission inside the grace window was rejected: %d %+v — "+
			"the client's own retry just logged it out", code, errBody)
	}
	if dup.RefreshToken != first.RefreshToken {
		t.Fatal("the duplicate was answered with a DIFFERENT refresh token: the family now has two heads")
	}

	// Outside the window the same replay is reuse and the family dies.
	at(5 * time.Minute)
	code, _, errBody = refresh(seedToken)
	if code != 400 || !strings.Contains(errBody.Description, "revoked") {
		t.Fatalf("a replay outside the grace window must revoke the family, got %d %q",
			code, errBody.Description)
	}
	if code, _, _ := refresh(first.RefreshToken); code == 200 {
		t.Fatal("the successor survived reuse detection: the family was not revoked")
	}
	if n := liveRefresh(t, db); n != 0 {
		t.Fatalf("%d usable refresh tokens survived the family revocation", n)
	}
}

// --- 2. plausible wrong SQL must be caught -------------------------------

// pgBrokenStore is the shipped Store with exactly one statement replaced by a
// plausible-but-wrong version of itself. Unlike the memstore fault wrapper,
// these are the real statements, executed by the real server.
type pgBrokenStore struct {
	mcpoauth.Store
	db  *sql.DB
	sql string
	// mode selects which method the broken statement replaces.
	mode string
}

const pgRefreshCols = `token_hash, client_id, user_id, family_id, family_created_at,
	family_expires_at, expires_at, created_at, consumed_at`

func (b *pgBrokenStore) ConsumeRefreshToken(ctx context.Context, hash string, at time.Time) (mcpoauth.RefreshToken, bool, error) {
	switch b.mode {
	case "consume":
		rt, err := scanBrokenRefresh(b.db.QueryRowContext(ctx, b.sql, hash, at))
		if err == sql.ErrNoRows {
			return mcpoauth.RefreshToken{}, false, nil
		}
		return rt, err == nil, err
	case "consume-select-then-update":
		// SELECT, then UPDATE, in two statements with no FOR UPDATE — the shape
		// an ORM read/modify/save produces.
		before, ok, err := b.Store.GetRefreshToken(ctx, hash)
		if err != nil || !ok {
			return before, ok, err
		}
		if before.ConsumedAt.IsZero() {
			time.Sleep(2 * time.Millisecond) // widen the window this fault opens
			if _, err := b.db.ExecContext(ctx,
				`UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2 WHERE token_hash = $1`,
				hash, at); err != nil {
				return mcpoauth.RefreshToken{}, false, err
			}
		}
		return before, true, nil
	}
	return b.Store.ConsumeRefreshToken(ctx, hash, at)
}

func (b *pgBrokenStore) GetRefreshToken(ctx context.Context, hash string) (mcpoauth.RefreshToken, bool, error) {
	if b.mode != "get" {
		return b.Store.GetRefreshToken(ctx, hash)
	}
	rt, err := scanBrokenRefresh(b.db.QueryRowContext(ctx, b.sql, hash))
	if err == sql.ErrNoRows {
		return mcpoauth.RefreshToken{}, false, nil
	}
	return rt, err == nil, err
}

func (b *pgBrokenStore) PurgeExpired(ctx context.Context, before time.Time) error {
	if b.mode != "purge" {
		return b.Store.PurgeExpired(ctx, before)
	}
	for _, q := range strings.Split(b.sql, ";") {
		if strings.TrimSpace(q) == "" {
			continue
		}
		if _, err := b.db.ExecContext(ctx, q, before); err != nil {
			return err
		}
	}
	return nil
}

func (b *pgBrokenStore) SavePendingAuth(ctx context.Context, p mcpoauth.PendingAuth) error {
	if b.mode != "pending" {
		return b.Store.SavePendingAuth(ctx, p)
	}
	_, err := b.db.ExecContext(ctx, b.sql,
		p.StateHash, p.ClientID, p.RedirectURI, p.CodeChallenge, p.ClientState,
		p.BinderHash, p.Approved, p.ExpiresAt, p.CreatedAt)
	return err
}

func (b *pgBrokenStore) ConsumeAuthCode(ctx context.Context, hash string) (mcpoauth.AuthCode, bool, error) {
	if b.mode != "authcode" {
		return b.Store.ConsumeAuthCode(ctx, hash)
	}
	var c mcpoauth.AuthCode
	err := b.db.QueryRowContext(ctx, b.sql, hash).Scan(&c.CodeHash, &c.ClientID, &c.UserID,
		&c.RedirectURI, &c.CodeChallenge, &c.ExpiresAt, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return mcpoauth.AuthCode{}, false, nil
	}
	return c, err == nil, err
}

func scanBrokenRefresh(row pgScanRow) (mcpoauth.RefreshToken, error) {
	var rt mcpoauth.RefreshToken
	var consumedAt sql.NullTime
	err := row.Scan(&rt.TokenHash, &rt.ClientID, &rt.UserID, &rt.FamilyID,
		&rt.FamilyCreatedAt, &rt.FamilyExpiresAt, &rt.ExpiresAt, &rt.CreatedAt, &consumedAt)
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
	return rt, nil
}

// TestPostgresVerifyStoreCatchesWrongSQL is the fault-injection suite. Each case
// is SQL somebody could reasonably write; VerifyStore has to name the mistake.
func TestPostgresVerifyStoreCatchesWrongSQL(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		sql     string
		wantMsg string
	}{
		{
			// The one a two-call check cannot see: the row is re-stamped on
			// every replay while still returning its previous value, so the
			// grace window rolls forever.
			name: "consume without the `AND consumed_at IS NULL` guard",
			mode: "consume",
			sql: `WITH before AS (
				SELECT * FROM mcp_oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE
			), stamped AS (
				UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2 WHERE token_hash = $1
			)
			SELECT ` + pgRefreshCols + ` FROM before`,
			wantMsg: "`AND consumed_at IS NULL`",
		},
		{
			// Returns ZERO rows on a replay, which the Provider reads as
			// "unknown token": invalid_grant, no family revocation, silently.
			name: "consume as UPDATE ... RETURNING",
			mode: "consume",
			sql: `UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
			      WHERE token_hash = $1 AND consumed_at IS NULL
			      RETURNING ` + pgRefreshCols,
			wantMsg: "must return the row as it was BEFORE",
		},
		{
			name: "consume as DELETE ... RETURNING",
			mode: "consume",
			sql: `DELETE FROM mcp_oauth_refresh_tokens WHERE token_hash = $1
			      AND $2::timestamptz IS NOT NULL RETURNING ` + pgRefreshCols,
			wantMsg: "reuse can never be detected",
		},
		{
			name: "consume filters on expires_at",
			mode: "consume",
			sql: `WITH before AS (
				SELECT * FROM mcp_oauth_refresh_tokens
				WHERE token_hash = $1 AND expires_at > $2 FOR UPDATE
			), stamped AS (
				UPDATE mcp_oauth_refresh_tokens SET consumed_at = $2
				WHERE token_hash = $1 AND consumed_at IS NULL
			)
			SELECT ` + pgRefreshCols + ` FROM before`,
			wantMsg: "Do NOT filter on expires_at",
		},
		{
			name:    "consume as SELECT-then-UPDATE with no FOR UPDATE",
			mode:    "consume-select-then-update",
			wantMsg: "is not atomic",
		},
		{
			// Added "by symmetry" with ConsumeRefreshToken. It breaks the
			// client-binding pre-check and the post-rotation re-read.
			name: "get filters on consumed_at",
			mode: "get",
			sql: `SELECT ` + pgRefreshCols + ` FROM mcp_oauth_refresh_tokens
			      WHERE token_hash = $1 AND consumed_at IS NULL`,
			wantMsg: "GetRefreshToken stopped returning the row",
		},
		{
			name: "purge drops the family_expires_at condition",
			mode: "purge",
			sql: `DELETE FROM mcp_oauth_auth_codes WHERE expires_at < $1;
			      DELETE FROM mcp_oauth_pending_auth WHERE expires_at < $1;
			      DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < $1;
			      DELETE FROM mcp_oauth_clients WHERE expires_at < $1`,
			wantMsg: "`AND family_expires_at < $1`",
		},
		{
			name: "purge forgets the clients table",
			mode: "purge",
			sql: `DELETE FROM mcp_oauth_auth_codes WHERE expires_at < $1;
			      DELETE FROM mcp_oauth_pending_auth WHERE expires_at < $1;
			      DELETE FROM mcp_oauth_refresh_tokens
			          WHERE expires_at < $1 AND family_expires_at < $1`,
			wantMsg: "does not delete expired clients",
		},
		{
			name: "pending auth upserts on client_id",
			mode: "pending",
			sql: `INSERT INTO mcp_oauth_pending_auth
				(state_hash, client_id, redirect_uri, code_challenge, client_state, binder_hash, approved, expires_at, created_at)
			      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			      ON CONFLICT (client_id) DO UPDATE SET
			          state_hash = EXCLUDED.state_hash, binder_hash = EXCLUDED.binder_hash`,
			wantMsg: "SavePendingAuth lost record",
		},
		{
			name: "authorization codes are read, not consumed",
			mode: "authcode",
			sql: `SELECT code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, created_at
			      FROM mcp_oauth_auth_codes WHERE code_hash = $1`,
			wantMsg: "not single-use",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := openPostgres(t)
			if tc.mode == "pending" {
				// A client_id-keyed upsert needs a unique index to conflict on;
				// that is exactly the schema an integrator who wrote this SQL
				// would have created.
				mustExec(t, db, `CREATE UNIQUE INDEX IF NOT EXISTS
					mcp_oauth_pending_auth_client_id_key ON mcp_oauth_pending_auth (client_id)`)
				t.Cleanup(func() {
					mustExec(t, db, `DROP INDEX IF EXISTS mcp_oauth_pending_auth_client_id_key`)
				})
			}
			broken := &pgBrokenStore{
				Store: newPostgresStore(t, db, pgUsers()),
				db:    db, sql: tc.sql, mode: tc.mode,
			}
			err := verifyProvider(t, broken).VerifyStore(context.Background())
			if err == nil {
				t.Fatal("VerifyStore accepted SQL that silently disables a security control")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("VerifyStore error does not mention %q:\n%v", tc.wantMsg, err)
			}
		})
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %s: %v", firstLine(q), err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " ..."
	}
	return s
}
