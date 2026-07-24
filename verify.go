package mcpoauth

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
)

// verifyTolerance is how much clock/precision drift a round-tripped timestamp
// may show. Postgres truncates to microseconds; some drivers to seconds.
const verifyTolerance = 2 * time.Second

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
func (p *Provider) VerifyStore(ctx context.Context) error {
	v := &storeVerifier{p: p, ctx: ctx, now: p.now()}
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
	problems []string

	canaryClientID string
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
	id := "mcpoauth-verify-" + v.canary("client")[:32]
	v.canaryClientID = id
	want := Client{
		ClientID:     id,
		RedirectURIs: []string{"http://127.0.0.1:1/mcpoauth-verify"},
		ClientName:   "mcpoauth VerifyStore canary",
		CreatedAt:    v.now,
		// Already expired, so the final PurgeExpired removes it.
		ExpiresAt: v.now.Add(-time.Hour),
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
		UserID:        "mcpoauth-verify-user",
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
}

func (v *storeVerifier) checkRefreshToken() {
	hash := v.canary("refresh")
	familyID := "mcpoauth-verify-family-" + v.canary("family")[:16]
	adopted := "mcpoauth-verify-family2-" + v.canary("family2")[:16]
	want := RefreshToken{
		TokenHash:       hash,
		ClientID:        v.canaryClientID,
		UserID:          "mcpoauth-verify-user",
		FamilyID:        familyID,
		FamilyCreatedAt: v.now.Add(-time.Hour),
		FamilyExpiresAt: v.now.Add(-time.Minute), // already lapsed: purged at the end
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

	// First consume: the row must come back UNconsumed and must survive.
	consumedAt := v.now
	first, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, consumedAt)
	if err != nil {
		v.failf("ConsumeRefreshToken failed: %v", err)
		return
	}
	if !ok {
		v.failf("ConsumeRefreshToken did not find a live token")
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
	second, ok, err := v.p.store.ConsumeRefreshToken(v.ctx, hash, v.now.Add(time.Second))
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

	if err := v.p.store.RevokeRefreshTokenFamily(v.ctx, adopted); err != nil {
		v.failf("RevokeRefreshTokenFamily failed: %v", err)
		return
	}
	if _, still, err := v.p.store.GetRefreshToken(v.ctx, hash); err == nil && still {
		v.failf("RevokeRefreshTokenFamily left a token of the revoked family alive: " +
			"reuse detection would revoke a family that keeps working")
	}
}

func (v *storeVerifier) cleanup() {
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
}
