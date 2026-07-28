package mcpoauth

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// verifyTolerance is how much clock/precision drift a round-tripped timestamp
// may show. Postgres truncates to microseconds; some drivers to seconds.
const verifyTolerance = 2 * time.Second

// defaultVerifyStoreUserID is the canary user ID used when
// Config.VerifyStoreUserID is unset. Applications whose user_id column is a
// UUID (or otherwise constrained) must override it.
const defaultVerifyStoreUserID = "mcpoauth-verify-user"

// VerifyStore round-trips canary records through the Store and reports, in one
// error, every field or behaviour that did not survive.
//
// Call it once at startup, before serving traffic, and treat a failure as
// fatal:
//
//	provider, err := mcpoauth.New(cfg, store)
//	if err != nil { log.Fatal(err) }
//	if err := provider.VerifyStore(ctx); err != nil { log.Fatal(err) }
//
// A Store that silently drops a column is the most likely way to deploy this
// package insecurely: losing BinderHash disables the browser binding that stops
// the authorization hijack, losing FamilyID or ConsumedAt disables refresh
// reuse detection, and losing FamilyCreatedAt turns the absolute session cap
// back into a session that slides forever. None of those fail visibly at
// runtime — the flow keeps working, it just stops being safe.
//
// VerifyStore writes only records it generates itself (random hashes, a canary
// client and a canary user ID that no real login can collide with) and removes
// them again. It calls Store.PurgeExpired at the end, which also drops any
// genuinely expired records — that is the intended behaviour, not a side
// effect to worry about.
//
// Every canary is written with a lifetime that is still in the FUTURE while it
// is being checked, and is expired (or revoked) explicitly at the end. That
// matters because the README tells applications to run PurgeExpired from a
// ticker: an already-expired canary could be deleted mid-verification by that
// ticker, or by a second instance booting during a rolling deploy, and
// VerifyStore would report a contract violation against a perfectly compliant
// Store — a startup outage caused by this package's own advice.
//
// Two schema requirements this writes into your tables (see the README):
// user_id must accept Config.VerifyStoreUserID (default a plain string — set
// the field when the column is a UUID), and client_id must hold at least 48
// characters. There must be no foreign keys from these tables to anything else.
func (p *Provider) VerifyStore(ctx context.Context) error {
	v := &storeVerifier{p: p, ctx: ctx, now: p.now(), userID: p.cfg.VerifyStoreUserID}
	if v.userID == "" {
		v.userID = defaultVerifyStoreUserID
	}
	v.checkClient()
	v.checkAuthCode()
	v.checkPendingAuth()
	v.checkRefreshToken()
	v.cleanup()

	if len(v.problems) == 0 {
		return nil
	}
	return fmt.Errorf("mcpoauth: Store implementation is not spec-compliant:\n  - %s",
		strings.Join(v.problems, "\n  - "))
}

type storeVerifier struct {
	p        *Provider
	ctx      context.Context
	now      time.Time
	userID   string
	problems []string

	canaryClientID    string
	canaryRefreshHash string
	canaryAtomicHash  string
}

func (v *storeVerifier) failf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

// eq records a problem unless got == want.
func (v *storeVerifier) eq(what string, got, want any) {
	if got != want {
		v.failf("%s: got %v, want %v", what, got, want)
	}
}

// eqTime records a problem unless got is within verifyTolerance of want.
func (v *storeVerifier) eqTime(what string, got, want time.Time) {
	if want.IsZero() {
		if !got.IsZero() {
			v.failf("%s: got %v, want the zero time", what, got)
		}
		return
	}
	if got.IsZero() {
		v.failf("%s: came back as the zero time (the column is not being persisted)", what)
		return
	}
	if d := got.Sub(want); d > verifyTolerance || d < -verifyTolerance {
		v.failf("%s: got %v, want %v (drift %v)", what, got.UTC(), want.UTC(), d)
	}
}

// canary returns an unguessable, collision-free hash-shaped value.
func (v *storeVerifier) canary(label string) string {
	tok, err := randomToken(24)
	if err != nil {
		v.failf("could not generate a canary value: %v", err)
		return HashSecret("mcpoauth-verify-fallback-" + label)
	}
	return HashSecret("mcpoauth-verify-" + label + "-" + tok)
}

func (v *storeVerifier) checkClient() {
	// 48 characters. Real client IDs are 32, so a VARCHAR(32) client_id column
	// passes in production and fails here — which is the point: the column has
	// to be wide enough for the canary too.
	id := "mcpoauth-verify-" + v.canary("client")[:32]
	v.canaryClientID = id
	want := Client{
		ClientID:     id,
		RedirectURIs: []string{"http://127.0.0.1:1/mcpoauth-verify"},
		ClientName:   "mcpoauth VerifyStore canary",
		CreatedAt:    v.now,
		// Deliberately NOT already expired: a concurrent PurgeExpired would
		// otherwise delete it mid-check. cleanup expires it explicitly.
		ExpiresAt: v.now.Add(time.Hour),
	}
	if err := v.p.store.SaveClient(v.ctx, want); err != nil {
		v.failf("SaveClient failed: %v", err)
		return
	}
	got, ok, err := v.p.store.GetClient(v.ctx, id)
	if err != nil {
		v.failf("GetClient failed: %v", err)
		return
	}
	if !ok {
		v.failf("GetClient did not find a client that SaveClient had just written")
		return
	}
	v.eq("Client.ClientID", got.ClientID, want.ClientID)
	v.eq("Client.ClientName", got.ClientName, want.ClientName)
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != want.RedirectURIs[0] {
		v.failf("Client.RedirectURIs: got %v, want %v", got.RedirectURIs, want.RedirectURIs)
	}
	v.eqTime("Client.ExpiresAt", got.ExpiresAt, want.ExpiresAt)
}

func (v *storeVerifier) checkAuthCode() {
	hash := v.canary("code")
	want := AuthCode{
		CodeHash:      hash,
		ClientID:      v.canaryClientID,
		UserID:        v.userID,
		RedirectURI:   "http://127.0.0.1:1/mcpoauth-verify",
		CodeChallenge: strings.Repeat("a", 43),
		ExpiresAt:     v.now.Add(time.Minute),
		CreatedAt:     v.now,
	}
	if err := v.p.store.SaveAuthCode(v.ctx, want); err != nil {
		v.failf("SaveAuthCode failed: %v", err)
		return
	}
	got, ok, err := v.p.store.ConsumeAuthCode(v.ctx, hash)
	if err != nil {
		v.failf("ConsumeAuthCode failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumeAuthCode did not find a code that SaveAuthCode had just written")
		return
	}
	v.eq("AuthCode.ClientID", got.ClientID, want.ClientID)
	v.eq("AuthCode.UserID", got.UserID, want.UserID)
	v.eq("AuthCode.RedirectURI", got.RedirectURI, want.RedirectURI)
	v.eq("AuthCode.CodeChallenge (PKCE is unenforceable without it)", got.CodeChallenge, want.CodeChallenge)
	v.eqTime("AuthCode.ExpiresAt", got.ExpiresAt, want.ExpiresAt)

	if _, again, err := v.p.store.ConsumeAuthCode(v.ctx, hash); err == nil && again {
		v.failf("ConsumeAuthCode is not single-use: the same code was returned twice " +
			"(authorization codes would be replayable)")
	}
}

func (v *storeVerifier) checkPendingAuth() {
	hash := v.canary("pending")
	want := PendingAuth{
		StateHash:     hash,
		ClientID:      v.canaryClientID,
		RedirectURI:   "http://127.0.0.1:1/mcpoauth-verify",
		CodeChallenge: strings.Repeat("b", 43),
		ClientState:   "mcpoauth-verify-client-state",
		BinderHash:    v.canary("binder"),
		Approved:      true,
		ExpiresAt:     v.now.Add(time.Minute),
		CreatedAt:     v.now,
	}
	if err := v.p.store.SavePendingAuth(v.ctx, want); err != nil {
		v.failf("SavePendingAuth failed: %v", err)
		return
	}
	got, ok, err := v.p.store.ConsumePendingAuth(v.ctx, hash)
	if err != nil {
		v.failf("ConsumePendingAuth failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumePendingAuth did not find a record that SavePendingAuth had just written")
		return
	}
	v.eq("PendingAuth.ClientID", got.ClientID, want.ClientID)
	v.eq("PendingAuth.RedirectURI", got.RedirectURI, want.RedirectURI)
	v.eq("PendingAuth.CodeChallenge", got.CodeChallenge, want.CodeChallenge)
	v.eq("PendingAuth.ClientState", got.ClientState, want.ClientState)
	v.eq("PendingAuth.BinderHash (the browser binding that stops the authorization hijack)",
		got.BinderHash, want.BinderHash)
	v.eq("PendingAuth.Approved (consent would be bypassable)", got.Approved, want.Approved)
	v.eqTime("PendingAuth.ExpiresAt", got.ExpiresAt, want.ExpiresAt)

	if _, again, err := v.p.store.ConsumePendingAuth(v.ctx, hash); err == nil && again {
		v.failf("ConsumePendingAuth is not single-use: the same record was returned twice")
	}

	v.checkPendingAuthIsInsertNotUpsert()
}

// checkPendingAuthIsInsertNotUpsert catches a SavePendingAuth written as an
// UPDATE, or as an upsert keyed on client_id. Every authorization flow calls it
// twice with the SAME ClientID and two DIFFERENT StateHash values (the consent
// nonce, then the Google state); a client_id-keyed upsert silently overwrites
// the first record, and the consent leg then fails with "unknown nonce".
func (v *storeVerifier) checkPendingAuthIsInsertNotUpsert() {
	first, second := v.canary("pending-a"), v.canary("pending-b")
	base := PendingAuth{
		ClientID:      v.canaryClientID,
		RedirectURI:   "http://127.0.0.1:1/mcpoauth-verify",
		CodeChallenge: strings.Repeat("c", 43),
		BinderHash:    v.canary("binder2"),
		Approved:      true,
		ExpiresAt:     v.now.Add(time.Minute),
		CreatedAt:     v.now,
	}
	for _, hash := range []string{first, second} {
		p := base
		p.StateHash = hash
		if err := v.p.store.SavePendingAuth(v.ctx, p); err != nil {
			v.failf("SavePendingAuth failed: %v", err)
			return
		}
	}
	for i, hash := range []string{first, second} {
		got, ok, err := v.p.store.ConsumePendingAuth(v.ctx, hash)
		if err != nil {
			v.failf("ConsumePendingAuth failed: %v", err)
			return
		}
		if !ok || got.StateHash != hash {
			v.failf("SavePendingAuth lost record %d of 2: it is called TWICE per flow with the "+
				"same ClientID and two different StateHash values, so it must be an INSERT "+
				"keyed on state_hash — an UPDATE, or an upsert keyed on client_id, drops the "+
				"first record and every login then fails at the consent step", i+1)
			return
		}
	}
}

func (v *storeVerifier) checkRefreshToken() {
	hash := v.canary("refresh")
	v.canaryRefreshHash = hash
	familyID := "mcpoauth-verify-family-" + v.canary("family")[:16]
	adopted := "mcpoauth-verify-family2-" + v.canary("family2")[:16]
	want := RefreshToken{
		TokenHash:       hash,
		ClientID:        v.canaryClientID,
		UserID:          v.userID,
		FamilyID:        familyID,
		FamilyCreatedAt: v.now.Add(-time.Hour),
		// The row's own lifetime has lapsed but its FAMILY is still alive.
		// That is exactly the state a consumed row spends most of its life in,
		// and it is retained (PurgeExpired needs BOTH to have passed), so a
		// concurrent purge cannot delete the canary mid-check — while a
		// ConsumeRefreshToken that filters on expires_at is still caught below.
		FamilyExpiresAt: v.now.Add(time.Hour),
		ExpiresAt:       v.now.Add(-time.Minute),
		CreatedAt:       v.now,
	}
	if err := v.p.store.SaveRefreshToken(v.ctx, want); err != nil {
		v.failf("SaveRefreshToken failed: %v", err)
		return
	}

	got, ok, err := v.p.store.GetRefreshToken(v.ctx, hash)
	if err != nil {
		v.failf("GetRefreshToken failed: %v", err)
		return
	}
	if !ok {
		v.failf("GetRefreshToken did not find a token that SaveRefreshToken had just written")
		return
	}
	v.eq("RefreshToken.ClientID", got.ClientID, want.ClientID)
	v.eq("RefreshToken.UserID", got.UserID, want.UserID)
	v.eq("RefreshToken.FamilyID (reuse detection cannot revoke a family without it)",
		got.FamilyID, want.FamilyID)
	v.eqTime("RefreshToken.FamilyCreatedAt (the absolute session cap depends on it)",
		got.FamilyCreatedAt, want.FamilyCreatedAt)
	v.eqTime("RefreshToken.FamilyExpiresAt (consumed rows would be purged too early)",
		got.FamilyExpiresAt, want.FamilyExpiresAt)
	v.eqTime("RefreshToken.ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	if !got.ConsumedAt.IsZero() {
		v.failf("RefreshToken.ConsumedAt: a freshly saved token came back consumed (%v)", got.ConsumedAt)
	}

	// LinkRefreshSuccessor on a hash nobody issued must be a plain no-op. An
	// integrator who writes it as an UPSERT materialises a refresh-token row
	// that was never issued — and, with an attacker-chosen family_id, one that
	// is immediately usable as a rotation anchor.
	unknown := v.canary("never-issued")
	if err := v.p.store.LinkRefreshSuccessor(v.ctx, unknown, familyID, []byte("x")); err != nil {
		v.failf("LinkRefreshSuccessor returned an error for an unknown hash (it must be a "+
			"no-op returning nil): %v", err)
	}
	if _, created, err := v.p.store.GetRefreshToken(v.ctx, unknown); err == nil && created {
		v.failf("LinkRefreshSuccessor created a refresh-token row from an unknown hash: it " +
			"must be a plain UPDATE ... WHERE token_hash = $1, never an UPSERT — an INSERT " +
			"path here mints a token row that was never issued")
	}

	// The canary is right now in exactly the state PurgeExpired must retain: its
	// own ExpiresAt has passed but its FamilyExpiresAt has not — the state a
	// consumed row spends most of its life in. A purge written
	// `WHERE expires_at < $1` (dropping `AND family_expires_at < $1`) deletes
	// the reuse-detection ledger the moment the token's own TTL lapses, so a
	// token stolen earlier and replayed later comes back as a plain
	// invalid_grant instead of revoking the thief's family.
	if err := v.p.store.PurgeExpired(v.ctx, v.now); err != nil {
		v.failf("PurgeExpired failed: %v", err)
		return
	}
	if _, still, err := v.p.store.GetRefreshToken(v.ctx, hash); err != nil || !still {
		v.failf("PurgeExpired deleted a refresh token whose own ExpiresAt has passed but " +
			"whose FamilyExpiresAt has not: it must delete a row only when BOTH have passed. " +
			"The DELETE is missing its `AND family_expires_at < $1` condition — without it, a " +
			"token stolen earlier and replayed after its own expiry is a plain invalid_grant " +
			"with no family revocation, instead of the reuse signal it must be")
		return
	}

	// First consume: the row must come back UNconsumed and must survive. Note
	// the canary's own ExpiresAt has passed: an expired CONSUMED row is the
	// reuse-detection ledger, so ConsumeRefreshToken must still return it.
	consumedAt := v.now
	first, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, consumedAt)
	if err != nil {
		v.failf("ConsumeRefreshToken failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumeRefreshToken did not return a row whose own ExpiresAt has passed but " +
			"whose family is still alive. Do NOT filter on expires_at: the Provider checks " +
			"expiry itself, and an expired consumed row IS the reuse-detection ledger — " +
			"filtering it turns a replayed stolen token into a plain invalid_grant with no " +
			"family revocation")
		return
	}
	if !first.ConsumedAt.IsZero() {
		v.failf("ConsumeRefreshToken returned the row AFTER stamping it (ConsumedAt=%v); "+
			"it must return the row as it was BEFORE the call, or every first rotation "+
			"looks like reuse", first.ConsumedAt)
	}
	v.eq("ConsumeRefreshToken FamilyID", first.FamilyID, want.FamilyID)

	sealed := []byte("mcpoauth-verify-sealed-successor-blob")
	if err := v.p.store.LinkRefreshSuccessor(v.ctx, hash, adopted, sealed); err != nil {
		v.failf("LinkRefreshSuccessor failed: %v", err)
	}

	// Second consume: this is the reuse signal. The row MUST still exist.
	second, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, v.now.Add(time.Hour))
	if err != nil {
		v.failf("ConsumeRefreshToken (second call) failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumeRefreshToken deleted the row instead of stamping ConsumedAt: " +
			"refresh-token reuse can never be detected, so a stolen token's family is " +
			"never revoked")
		return
	}
	if second.ConsumedAt.IsZero() {
		v.failf("ConsumeRefreshToken did not persist ConsumedAt: a replayed refresh token " +
			"is indistinguishable from a first use, so reuse detection is disabled")
	} else {
		v.eqTime("RefreshToken.ConsumedAt", second.ConsumedAt, consumedAt)
	}
	if !bytes.Equal(second.SuccessorSealed, sealed) {
		v.failf("LinkRefreshSuccessor did not persist SuccessorSealed (got %d bytes, want %d): "+
			"a duplicate refresh submission will log the client out instead of replaying",
			len(second.SuccessorSealed), len(sealed))
	}
	v.eq("LinkRefreshSuccessor did not re-stamp FamilyID", second.FamilyID, adopted)

	// Third consume, two hours after the stamp the row should still be carrying.
	// A Store that omits `AND consumed_at IS NULL` from the UPDATE re-stamps on
	// every call while still returning the row as it was before that call — so
	// it satisfies every check above, and only a THIRD call reveals that the
	// original stamp was replaced. The damage is silent and total: the grace
	// window is anchored to ConsumedAt, so a rolling stamp turns the fixed
	// 30-second window into an unbounded one and a stolen token can be replayed
	// forever without reuse detection ever firing.
	third, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, v.now.Add(2*time.Hour))
	if err != nil {
		v.failf("ConsumeRefreshToken (third call) failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumeRefreshToken stopped returning the row on the third call: the row is " +
			"the durable reuse-detection ledger and only PurgeExpired may remove it")
		return
	}
	if !third.ConsumedAt.Equal(second.ConsumedAt) || !withinTolerance(third.ConsumedAt, consumedAt) {
		v.failf("ConsumeRefreshToken OVERWRITES ConsumedAt: after three calls the row reports "+
			"%v, but it must still report the very first stamp %v. The UPDATE is missing its "+
			"`AND consumed_at IS NULL` guard — that clause is load-bearing. Without it every "+
			"replay re-anchors Config.RefreshGracePeriod, so a stolen refresh token can be "+
			"replayed indefinitely and reuse detection never fires",
			third.ConsumedAt.UTC(), consumedAt.UTC())
	}

	// GetRefreshToken must be UNFILTERED. Adding `AND consumed_at IS NULL` to it
	// "by symmetry" with ConsumeRefreshToken is a natural mistake and a silent
	// disaster: the Provider reads exactly this row twice on every rotation —
	// the client-binding pre-check before consuming, and the post-rotation
	// predecessor re-read that confirms the family was not revoked mid-flight.
	// Filtered, the pre-check treats every refresh as an unknown token and the
	// re-read never finds the predecessor, so every rotation revokes its own
	// family. Nothing above catches it, because every earlier Get is of a row
	// that has not been consumed yet.
	if _, still, err := v.p.store.GetRefreshToken(v.ctx, hash); err != nil || !still {
		v.failf("GetRefreshToken stopped returning the row once ConsumeRefreshToken had stamped " +
			"it: it must not be filtered on consumed_at, expires_at or family_expires_at. The " +
			"Provider reads consumed rows deliberately (the client-binding pre-check and the " +
			"post-rotation predecessor re-read); filtering breaks both, and every rotation then " +
			"revokes its own family")
	}

	if err := v.p.store.RevokeRefreshTokenFamily(v.ctx, adopted); err != nil {
		v.failf("RevokeRefreshTokenFamily failed: %v", err)
		return
	}
	if _, still, err := v.p.store.GetRefreshToken(v.ctx, hash); err == nil && still {
		v.failf("RevokeRefreshTokenFamily left a token of the revoked family alive: " +
			"reuse detection would revoke a family that keeps working")
	}

	v.checkRefreshTokenAtomicity()
}

// atomicityConcurrency is how many goroutines race ConsumeRefreshToken for the
// same hash. Every check above is single-threaded, so a Store implemented as
// SELECT-then-UPDATE (no `FOR UPDATE`, or a read/modify/save ORM call) passes
// all of them: under concurrency, every caller reads ConsumedAt as zero before
// any of them writes, so all N return ok=true with a zero ConsumedAt. The
// Provider treats each as a legitimate first rotation, so one stolen token
// forks into N independently usable successor chains and reuse detection can
// never fire again — there is no longer a single canonical "next" token whose
// replay would be caught.
const atomicityConcurrency = 8

func (v *storeVerifier) checkRefreshTokenAtomicity() {
	hash := v.canary("atomic")
	v.canaryAtomicHash = hash
	familyID := "mcpoauth-verify-atomic-family-" + v.canary("atomic-family")[:16]
	want := RefreshToken{
		TokenHash:       hash,
		ClientID:        v.canaryClientID,
		UserID:          v.userID,
		FamilyID:        familyID,
		FamilyCreatedAt: v.now.Add(-time.Hour),
		FamilyExpiresAt: v.now.Add(time.Hour),
		ExpiresAt:       v.now.Add(time.Hour),
		CreatedAt:       v.now,
	}
	if err := v.p.store.SaveRefreshToken(v.ctx, want); err != nil {
		v.failf("SaveRefreshToken (atomicity canary) failed: %v", err)
		return
	}

	type result struct {
		rt  RefreshToken
		ok  bool
		err error
	}
	results := make([]result, atomicityConcurrency)
	ready := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			rt, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, v.now)
			results[i] = result{rt, ok, err}
		}(i)
	}
	close(ready)
	wg.Wait()

	zeroCount := 0
	for i, r := range results {
		if r.err != nil {
			v.failf("ConsumeRefreshToken (concurrent call %d of %d) failed: %v",
				i+1, atomicityConcurrency, r.err)
			return
		}
		if !r.ok {
			v.failf("ConsumeRefreshToken (concurrent call %d of %d) returned ok=false for a "+
				"token that was saved moments earlier", i+1, atomicityConcurrency)
			return
		}
		if r.rt.ConsumedAt.IsZero() {
			zeroCount++
		}
	}
	if zeroCount != 1 {
		v.failf("ConsumeRefreshToken is not atomic: of %d concurrent calls for the SAME "+
			"refresh token, %d observed a zero ConsumedAt (want exactly 1). A "+
			"SELECT-then-UPDATE (or a read/modify/save ORM call) lets every concurrent caller "+
			"read the row before any of them writes, so a single stolen token forks into %d "+
			"independently usable rotation chains and reuse detection can never fire again. Use "+
			"the documented CTE idiom: `SELECT ... FOR UPDATE` inside the same statement as the "+
			"`consumed_at IS NULL`-guarded UPDATE",
			atomicityConcurrency, zeroCount, atomicityConcurrency)
	}
}

// withinTolerance reports whether got is close enough to want to be the same
// stored instant.
func withinTolerance(got, want time.Time) bool {
	d := got.Sub(want)
	return d <= verifyTolerance && d >= -verifyTolerance
}

// cleanup expires whatever canaries are still around and purges them. They were
// written with a lifetime in the future precisely so a concurrent PurgeExpired
// could not remove them while they were being checked; this is where they are
// handed over to it.
func (v *storeVerifier) cleanup() {
	if v.canaryClientID != "" {
		if c, ok, err := v.p.store.GetClient(v.ctx, v.canaryClientID); err == nil && ok {
			c.ExpiresAt = v.now.Add(-time.Hour)
			if err := v.p.store.SaveClient(v.ctx, c); err != nil {
				v.failf("SaveClient failed while expiring the canary (it must upsert on "+
					"ClientID): %v", err)
			}
		}
	}
	// A compliant Store already dropped the refresh canary in
	// RevokeRefreshTokenFamily; one that did not gets it purged here instead of
	// leaving it behind forever. The atomicity canary (checkRefreshTokenAtomicity)
	// is never revoked at all, so it always needs this sweep.
	for _, hash := range []string{v.canaryRefreshHash, v.canaryAtomicHash} {
		if hash == "" {
			continue
		}
		if rt, ok, err := v.p.store.GetRefreshToken(v.ctx, hash); err == nil && ok {
			rt.ExpiresAt = v.now.Add(-time.Hour)
			rt.FamilyExpiresAt = v.now.Add(-time.Hour)
			_ = v.p.store.SaveRefreshToken(v.ctx, rt)
		}
	}

	if err := v.p.store.PurgeExpired(v.ctx, v.now); err != nil {
		v.failf("PurgeExpired failed: %v", err)
		return
	}
	if v.canaryClientID == "" {
		return
	}
	if _, still, err := v.p.store.GetClient(v.ctx, v.canaryClientID); err == nil && still {
		v.failf("PurgeExpired does not delete expired clients: /register is " +
			"unauthenticated, so the client table would grow without bound")
	}
	if v.canaryRefreshHash != "" {
		if _, still, err := v.p.store.GetRefreshToken(v.ctx, v.canaryRefreshHash); err == nil && still {
			v.failf("PurgeExpired does not delete refresh tokens whose own ExpiresAt AND " +
				"FamilyExpiresAt have both passed: the ledger would grow without bound")
		}
	}
}
