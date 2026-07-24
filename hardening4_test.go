package mcpoauth_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
)

// This file holds the regression for the fourth hardening round's LOW finding:
// a transient GetRefreshToken error during the post-rotation re-read
// (handlers.go, issueTokenPair) used to be treated identically to the row
// genuinely being gone, so a DB blip mid-rotation revoked the family and logged
// the user out. Only the real signal — the row is gone because reuse detection
// fired concurrently (covered by TestRevocationIsNotUndoneByAnInFlightRotation
// in hardening3_test.go, the H2 fix) may revoke.

// transientGetRefreshStore wraps a Store and returns an error on the Nth call
// to GetRefreshToken for one specific, caller-supplied hash — standing in for
// a DB blip that lands exactly on the post-Link re-read (the second
// GetRefreshToken call for a submitted token: the first is the client_id
// pre-check, the second is the post-Link confirmation in issueTokenPair).
type transientGetRefreshStore struct {
	mcpoauth.Store

	mu         sync.Mutex
	hash       string
	failOnCall int
	calls      int
}

func (s *transientGetRefreshStore) setTarget(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hash = hash
	s.calls = 0
}

func (s *transientGetRefreshStore) GetRefreshToken(ctx context.Context, hash string) (mcpoauth.RefreshToken, bool, error) {
	s.mu.Lock()
	match := hash == s.hash
	n := 0
	if match {
		s.calls++
		n = s.calls
	}
	s.mu.Unlock()
	if match && n == s.failOnCall {
		return mcpoauth.RefreshToken{}, false, errors.New("transient read error")
	}
	return s.Store.GetRefreshToken(ctx, hash)
}

func TestTransientReadErrorDuringPostLinkDoesNotRevokeFamily(t *testing.T) {
	base := memstore.NewMemoryStore()
	hooked := &transientGetRefreshStore{Store: base, failOnCall: 2}
	h := harnessOver(t, hooked, base)
	clientID, pair := firstPair(t, h)

	// The pre-check GetRefreshToken (call 1) must succeed; only the post-Link
	// re-read (call 2) fails.
	hooked.setTarget(mcpoauth.HashSecret(pair.RefreshToken))

	h.advance(time.Minute)
	rec := rotate(h, clientID, pair.RefreshToken)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a transient read error during the post-Link re-read must surface as a 500, "+
			"not be treated as proof of revocation; got %d %s", rec.Code, rec.Body.String())
	}

	// The rotation itself had already completed — the predecessor was consumed
	// and the successor saved and linked — before the confirmation read failed.
	// Nothing here may have been revoked because of that failed read: the
	// predecessor row (the reuse-detection ledger entry) must survive, and the
	// successor it points to must still be the one live row in the family.
	if _, ok, err := base.GetRefreshToken(context.Background(), mcpoauth.HashSecret(pair.RefreshToken)); err != nil || !ok {
		t.Fatal("the predecessor row is gone: a transient read error revoked the family")
	}
	if live := base.LiveRefresh(); live != 1 {
		t.Fatalf("%d live refresh rows after a transient read error, want 1 (the successor, "+
			"untouched by the failed confirmation read)", live)
	}
}

// TestGetRefreshTokenGoneStillRevokesFamily is the companion case: when the
// post-Link re-read succeeds but genuinely finds the row gone (ok=false, no
// error — the real H2 signal), the family must still be revoked exactly as
// before. This pins the boundary the fix must not blur: only err==nil && !ok
// revokes; err!=nil must not.
func TestGetRefreshTokenGoneStillRevokesFamily(t *testing.T) {
	base := memstore.NewMemoryStore()
	hooked := &goneGetRefreshStore{Store: base}
	h := harnessOver(t, hooked, base)
	clientID, pair := firstPair(t, h)

	hooked.mu.Lock()
	hooked.hash = mcpoauth.HashSecret(pair.RefreshToken)
	hooked.fireOnCall = 2
	hooked.mu.Unlock()

	h.advance(time.Minute)
	rec := rotate(h, clientID, pair.RefreshToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid_grant once the post-Link re-read genuinely finds the row "+
			"gone, got %d %s", rec.Code, rec.Body.String())
	}
	if live := base.LiveRefresh(); live != 0 {
		t.Fatalf("%d live refresh rows survive a genuine post-Link gone signal, want 0 "+
			"(the family must still be revoked)", live)
	}
}

// goneGetRefreshStore makes ONE specific hash's GetRefreshToken report
// ok=false, err=nil (never found) the first time it is armed — simulating the
// row being genuinely gone by the time issueTokenPair re-reads it, independent
// of the real RevokeRefreshTokenFamily plumbing exercised in hardening3_test.go.
type goneGetRefreshStore struct {
	mcpoauth.Store
	mu         sync.Mutex
	hash       string
	fireOnCall int
	calls      int
}

func (s *goneGetRefreshStore) GetRefreshToken(ctx context.Context, hash string) (mcpoauth.RefreshToken, bool, error) {
	s.mu.Lock()
	match := hash == s.hash
	n := 0
	if match {
		s.calls++
		n = s.calls
	}
	s.mu.Unlock()
	if match && n == s.fireOnCall {
		return mcpoauth.RefreshToken{}, false, nil
	}
	return s.Store.GetRefreshToken(ctx, hash)
}
