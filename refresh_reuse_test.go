package mcpoauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// rotate is one refresh_token grant.
func rotate(h *harness, clientID, token string) *httptest.ResponseRecorder {
	return h.token(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {clientID},
	})
}

// pastGrace steps far enough forward that a replay can no longer be mistaken
// for a duplicate submission.
func pastGrace(h *harness) { h.advance(5 * time.Minute) }

// TestRefreshReuseDetectionIsDurable is the regression suite for the
// reuse-detection ledger. It used to be a 4096-entry in-process map with
// arbitrary eviction, which meant a thief could rotate a stolen token in a loop
// to evict the entry that identified their theft, and a process restart wiped
// detection entirely. Detection now lives in the Store, on the refresh-token
// row itself, and lasts as long as the family does.
func TestRefreshReuseDetectionIsDurable(t *testing.T) {
	// Each case establishes a family, rotates the stolen token away, does
	// something that used to defeat detection, and then replays. In every case
	// the replay must revoke the family and kill the successor chain.
	tests := []struct {
		name string
		// evade runs between the thief's rotation and the victim's replay.
		evade func(t *testing.T, h *harness, clientID, chainToken string) string
	}{
		{
			name:  "immediately after the grace window",
			evade: func(_ *testing.T, h *harness, _, chain string) string { pastGrace(h); return chain },
		},
		{
			name: "after 6000 rotations of the stolen chain (ledger flood)",
			evade: func(t *testing.T, h *harness, clientID, chain string) string {
				// The thief needs no credential other than the stolen token:
				// rotating it in a loop used to evict their own tracking entry.
				for i := 0; i < 6000; i++ {
					rec := rotate(h, clientID, chain)
					if rec.Code != http.StatusOK {
						t.Fatalf("flood rotation %d: %d %s", i, rec.Code, rec.Body.String())
					}
					chain = decodeJSON[tokenSuccess](t, rec).RefreshToken
				}
				pastGrace(h)
				return chain
			},
		},
		{
			name: "after a process restart",
			evade: func(_ *testing.T, h *harness, _, chain string) string {
				pastGrace(h)
				h.restart() // same Store, brand new Provider
				return chain
			},
		},
		{
			name: "long after the old 24h reuse window would have lapsed",
			evade: func(_ *testing.T, h *harness, _, chain string) string {
				h.advance(45 * 24 * time.Hour) // inside the 90d family cap
				return chain
			},
		},
		{
			name: "after a flood AND a restart AND 30 days",
			evade: func(t *testing.T, h *harness, clientID, chain string) string {
				for i := 0; i < 2000; i++ {
					rec := rotate(h, clientID, chain)
					if rec.Code != http.StatusOK {
						t.Fatalf("flood rotation %d: %d", i, rec.Code)
					}
					chain = decodeJSON[tokenSuccess](t, rec).RefreshToken
				}
				h.advance(30 * 24 * time.Hour)
				h.restart()
				return chain
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			clientID, pair := firstPair(t, h)

			stolen := pair.RefreshToken
			thief := decodeJSON[tokenSuccess](t, rotate(h, clientID, stolen))
			chain := tc.evade(t, h, clientID, thief.RefreshToken)

			// The victim's client comes back with the token it still holds.
			replay := rotate(h, clientID, stolen)
			if replay.Code != http.StatusBadRequest {
				t.Fatalf("replay of a rotated token: status = %d, want 400 (body %s)",
					replay.Code, replay.Body.String())
			}
			if got := decodeJSON[errorBody](t, replay).Error; got != "invalid_grant" {
				t.Fatalf("replay error = %q, want invalid_grant", got)
			}

			// ...and it must have taken the thief's whole chain with it.
			if rec := rotate(h, clientID, chain); rec.Code == http.StatusOK {
				t.Fatal("the stolen chain survived reuse detection")
			}
			if live := h.store.LiveRefresh(); live != 0 {
				t.Fatalf("%d usable refresh tokens survived the family revocation", live)
			}
		})
	}
}

// TestRefreshTokenWithoutFamilyFailsClosed covers a refresh token whose
// FamilyID is empty — a row written by older code, or by a Store that drops the
// column. Propagating the emptiness would opt the whole chain out of reuse
// detection and out of the absolute lifetime cap.
func TestRefreshTokenWithoutFamilyFailsClosed(t *testing.T) {
	seed := func(h *harness, clientID, raw string, rt mcpoauth.RefreshToken) {
		h.t.Helper()
		rt.TokenHash = mcpoauth.HashSecret(raw)
		rt.ClientID = clientID
		rt.UserID = testUserID
		if err := h.store.SaveRefreshToken(context.Background(), rt); err != nil {
			h.t.Fatalf("seeding refresh token: %v", err)
		}
	}

	t.Run("rotation mints a fresh family instead of propagating the empty one", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		now := time.Now()
		seed(h, clientID, "legacy-token-with-no-family", mcpoauth.RefreshToken{
			FamilyCreatedAt: now, FamilyExpiresAt: now.Add(90 * 24 * time.Hour),
			ExpiresAt: now.Add(30 * 24 * time.Hour), CreatedAt: now,
		})

		rec := rotate(h, clientID, "legacy-token-with-no-family")
		if rec.Code != http.StatusOK {
			t.Fatalf("rotation: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		next := decodeJSON[tokenSuccess](t, rec)

		stored, ok, err := h.store.GetRefreshToken(context.Background(), mcpoauth.HashSecret(next.RefreshToken))
		if err != nil || !ok {
			t.Fatalf("looking up the issued token: ok=%v err=%v", ok, err)
		}
		if stored.FamilyID == "" {
			t.Fatal("the successor of a familyless token is itself familyless: " +
				"reuse detection and the absolute cap can never apply to this chain")
		}
	})

	t.Run("replaying the familyless token still revokes the family it spawned", func(t *testing.T) {
		h := newHarness(t)
		clientID := h.register(testRedirectURI)
		now := time.Now()
		const raw = "legacy-token-with-no-family"
		seed(h, clientID, raw, mcpoauth.RefreshToken{
			FamilyCreatedAt: now, FamilyExpiresAt: now.Add(90 * 24 * time.Hour),
			ExpiresAt: now.Add(30 * 24 * time.Hour), CreatedAt: now,
		})

		thief := decodeJSON[tokenSuccess](t, rotate(h, clientID, raw))
		pastGrace(h)

		if rec := rotate(h, clientID, raw); rec.Code != http.StatusBadRequest {
			t.Fatalf("replay: status = %d, want 400", rec.Code)
		}
		if rec := rotate(h, clientID, thief.RefreshToken); rec.Code == http.StatusOK {
			t.Fatal("the chain descended from a familyless token survived reuse detection")
		}
	})

	t.Run("a token with no family metadata at all is refused, not slid forever", func(t *testing.T) {
		// A Store that drops FamilyCreatedAt would otherwise restore the
		// sliding-forever session that RefreshTokenAbsoluteTTL exists to kill.
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshTokenAbsoluteTTL = 24 * time.Hour })
		clientID := h.register(testRedirectURI)
		seed(h, clientID, "token-without-any-timestamps", mcpoauth.RefreshToken{
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		})

		rec := rotate(h, clientID, "token-without-any-timestamps")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
	})
}

// TestRefreshGracePeriod covers the duplicate-submission window: a client that
// retries a refresh (or fires two at once) must get its session back, not be
// logged out — while a genuine replay outside the window still revokes.
func TestRefreshGracePeriod(t *testing.T) {
	t.Run("a duplicate submission is answered with the same refresh token", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)

		first := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))
		h.advance(5 * time.Second) // still inside the 30s default

		rec := rotate(h, clientID, pair.RefreshToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("duplicate submission: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		replay := decodeJSON[tokenSuccess](t, rec)
		if replay.RefreshToken != first.RefreshToken {
			t.Fatal("the replay handed out a different refresh token; the family now has two heads")
		}
		if replay.AccessToken == "" {
			t.Fatal("the replay did not mint an access token")
		}
		if live := h.store.LiveRefresh(); live != 1 {
			t.Fatalf("%d usable refresh tokens after a duplicate submission, want 1", live)
		}
		if rec := rotate(h, clientID, first.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("the client's session was destroyed by its own retry: %d %s", rec.Code, rec.Body.String())
		}
	})

	// The cost of the window, pinned so it can never widen by accident: for
	// those 30 seconds a replay is NOT reuse, because a thief's replay and a
	// client's retry are the same bytes on the wire and nothing can tell them
	// apart. Detection is deferred, not lost — the two holders now share one
	// token, and the next time either presents a spent one outside the window
	// the family dies (the case below). Set RefreshGracePeriod <= 0 to trade
	// the retry back for zero tolerance.
	t.Run("inside the window an immediate replay does not revoke (documented cost)", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		thief := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("replay inside the window: status = %d, want 200", rec.Code)
		}
		if rec := rotate(h, clientID, thief.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("the chain died inside the window: status = %d", rec.Code)
		}
		// ...and detection resumes the moment the window closes.
		pastGrace(h)
		if rec := rotate(h, clientID, thief.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("replay after the window: status = %d, want 400", rec.Code)
		}
		if live := h.store.LiveRefresh(); live != 0 {
			t.Fatalf("%d usable tokens survived the deferred detection", live)
		}
	})

	t.Run("outside the window it is reuse and the family dies", func(t *testing.T) {
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshGracePeriod = time.Second })
		clientID, pair := firstPair(t, h)

		next := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))
		h.advance(2 * time.Second)

		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("late replay: status = %d, want 400", rec.Code)
		}
		if rec := rotate(h, clientID, next.RefreshToken); rec.Code == http.StatusOK {
			t.Fatal("a late replay did not revoke the family")
		}
	})

	t.Run("an older token in the chain is reuse even inside the window", func(t *testing.T) {
		// The grace only ever covers the single most-recently-consumed token
		// whose successor is still unused. T0 is two steps stale.
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		t0 := pair.RefreshToken

		t1 := decodeJSON[tokenSuccess](t, rotate(h, clientID, t0)).RefreshToken
		t2 := decodeJSON[tokenSuccess](t, rotate(h, clientID, t1)).RefreshToken

		if rec := rotate(h, clientID, t0); rec.Code != http.StatusBadRequest {
			t.Fatalf("replay of a two-step-stale token: status = %d, want 400", rec.Code)
		}
		if rec := rotate(h, clientID, t2); rec.Code == http.StatusOK {
			t.Fatal("replaying an older token of the family did not revoke it")
		}
	})

	t.Run("the grace never crosses clients", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		other := h.register(testRedirectURI)
		_ = decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

		if rec := rotate(h, other, pair.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("replay from another client: status = %d, want 400", rec.Code)
		}
	})

	t.Run("disabling it restores strict reuse detection", func(t *testing.T) {
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshGracePeriod = -1 })
		clientID, pair := firstPair(t, h)
		next := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("immediate replay: status = %d, want 400", rec.Code)
		}
		if rec := rotate(h, clientID, next.RefreshToken); rec.Code == http.StatusOK {
			t.Fatal("strict mode did not revoke the family on an immediate replay")
		}
	})

	t.Run("the successor never reaches the Store in any form", func(t *testing.T) {
		// v1 sealed the successor onto the consumed predecessor row with
		// AES-GCM so that a database dump stayed worthless. v2 keeps the
		// predecessor -> successor link in process instead, which makes the
		// same guarantee unconditional: there is nothing to decrypt because
		// there is nothing stored. What the Store still holds — and must —
		// is the ConsumedAt stamp that reuse detection is judged against.
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		issued := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

		row, ok, err := h.store.GetRefreshToken(context.Background(), mcpoauth.HashSecret(pair.RefreshToken))
		if err != nil || !ok {
			t.Fatalf("the consumed row is gone: ok=%v err=%v", ok, err)
		}
		if row.ConsumedAt.IsZero() {
			t.Fatal("the predecessor row lost its ConsumedAt stamp: reuse detection is disabled")
		}
		// Everything the database holds about either row, and neither raw
		// token is in any of it.
		successorRow, ok, err := h.store.GetRefreshToken(context.Background(), mcpoauth.HashSecret(issued.RefreshToken))
		if err != nil || !ok {
			t.Fatalf("the successor row is missing: ok=%v err=%v", ok, err)
		}
		for _, field := range []string{
			row.TokenHash, row.FamilyID, row.ClientID, row.UserID,
			successorRow.TokenHash, successorRow.FamilyID,
		} {
			if field == issued.RefreshToken || field == pair.RefreshToken {
				t.Fatalf("a raw refresh token is recoverable from the stored rows: %q", field)
			}
		}
	})

	t.Run("a duplicate that this process cannot answer never revokes", func(t *testing.T) {
		// The grace link is in process, so a restart (or another instance)
		// loses it. That must fail SAFE in the liveness direction too: the
		// duplicate is reported as an in-flight rotation and retried, never
		// treated as reuse — reading an absence as evidence is exactly the
		// round-3 HIGH where pure concurrency collapsed a family.
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		first := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

		h.advance(5 * time.Second) // still inside the 30s window
		h.restart()                // same Store, brand new Provider: grace cache gone

		rec := rotate(h, clientID, pair.RefreshToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if desc := decodeJSON[errorBody](t, rec).Description; strings.Contains(desc, "revoked") {
			t.Fatalf("a duplicate the restarted process could not answer revoked the family: %q", desc)
		}
		if rec := rotate(h, clientID, first.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("the client's live token died with a duplicate it never sent: %d %s",
				rec.Code, rec.Body.String())
		}

		// ...and once the window closes, detection is exactly as strict as ever.
		pastGrace(h)
		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("late replay: status = %d, want 400", rec.Code)
		}
		if desc := decodeJSON[errorBody](t, rotate(h, clientID, first.RefreshToken)).Description; desc == "" {
			t.Fatal("the family survived reuse detection after the grace window closed")
		}
		if live := h.store.LiveRefresh(); live != 0 {
			t.Fatalf("%d usable refresh tokens survived the family revocation", live)
		}
	})
}

// TestConcurrentRefreshKeepsTheSession is the survivor-count form of the
// duplicate-submission race: 32 identical grants must leave the client with a
// working session, not log it out.
func TestConcurrentRefreshKeepsTheSession(t *testing.T) {
	for attempt := 0; attempt < 5; attempt++ {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		form := url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {pair.RefreshToken},
			"client_id": {clientID},
		}

		const n = 32
		var wg sync.WaitGroup
		recs := make([]*httptest.ResponseRecorder, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); <-start; recs[i] = h.token(form) }(i)
		}
		close(start)
		wg.Wait()

		issued := map[string]bool{}
		for _, rec := range recs {
			if rec.Code == http.StatusOK {
				issued[decodeJSON[tokenSuccess](t, rec).RefreshToken] = true
			}
		}
		if len(issued) != 1 {
			t.Fatalf("attempt %d: %d distinct refresh tokens issued, want exactly 1", attempt, len(issued))
		}
		if live := h.store.LiveRefresh(); live != 1 {
			t.Fatalf("attempt %d: %d usable refresh tokens survive, want 1 "+
				"(the client must not be logged out by its own duplicate request)", attempt, live)
		}
		for tok := range issued {
			if rec := rotate(h, clientID, tok); rec.Code != http.StatusOK {
				t.Fatalf("attempt %d: the surviving token is dead: %d %s", attempt, rec.Code, rec.Body.String())
			}
		}
	}
}

// TestPurgeRetainsTheReuseLedger pins the retention rule: a consumed row is
// what makes reuse detectable, so it must outlive the token's own expiry and
// only go when the family does.
func TestPurgeRetainsTheReuseLedger(t *testing.T) {
	h := newHarness(t, func(c *mcpoauth.Config) {
		c.RefreshTokenTTL = time.Hour
		c.RefreshTokenAbsoluteTTL = 48 * time.Hour
	})
	clientID, pair := firstPair(t, h)
	next := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken))

	// Past the token's own 1h expiry but well inside the family's 48h.
	h.advance(2 * time.Hour)
	if err := h.p.PurgeExpired(context.Background()); err != nil {
		t.Fatalf("PurgeExpired() error: %v", err)
	}
	if _, ok, _ := h.store.GetRefreshToken(context.Background(), mcpoauth.HashSecret(pair.RefreshToken)); !ok {
		t.Fatal("the consumed row was purged while its family was still alive: reuse is now undetectable")
	}
	if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay after purge: status = %d, want 400", rec.Code)
	}
	if rec := rotate(h, clientID, next.RefreshToken); rec.Code == http.StatusOK {
		t.Fatal("reuse detection did not survive a purge")
	}

	// Once the family is over, the rows go.
	h.advance(60 * time.Hour)
	if err := h.p.PurgeExpired(context.Background()); err != nil {
		t.Fatalf("PurgeExpired() error: %v", err)
	}
	if _, _, _, refresh := h.store.Len(); refresh != 0 {
		t.Fatalf("%d refresh rows outlived their family", refresh)
	}
}
