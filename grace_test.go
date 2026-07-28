package mcpoauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// TestGraceCacheIsBounded pins the two memory properties of the in-process
// grace cache. Neither is a correctness control — losing an entry only ever
// costs a re-login — but an unbounded map keyed by a value an attacker can
// generate at will is a denial of service, and the v1 reuse ledger's 4096-entry
// map with arbitrary eviction is exactly the mistake not to repeat.
func TestGraceCacheIsBounded(t *testing.T) {
	t.Run("entries expire with the window", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		token := pair.RefreshToken

		for i := 0; i < 5; i++ {
			h.advance(time.Second)
			rec := rotate(h, clientID, token)
			if rec.Code != http.StatusOK {
				t.Fatalf("rotation %d: %d %s", i, rec.Code, rec.Body.String())
			}
			token = decodeJSON[tokenSuccess](t, rec).RefreshToken
		}
		if n := h.p.GraceLenForTest(); n == 0 {
			t.Fatal("nothing was remembered: a duplicate submission would log the client out")
		}

		// Past the window, the next rotation sweeps what it can and the stale
		// entries stop being answerable.
		pastGrace(h)
		h.advance(time.Second)
		if rec := rotate(h, clientID, token); rec.Code != http.StatusOK {
			t.Fatalf("rotation after the window: %d %s", rec.Code, rec.Body.String())
		}
		if _, ok := h.p.RecallForTest(mcpoauth.HashSecret(pair.RefreshToken)); ok {
			t.Fatal("an entry outlived its grace window")
		}
	})

	t.Run("the map never exceeds its cap", func(t *testing.T) {
		// One family per iteration, none of them ever expiring, so eviction —
		// not the sweep — is what has to hold the line.
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshGracePeriod = time.Hour })
		clientID := h.register(testRedirectURI)
		now := time.Now()

		n := mcpoauth.MaxGraceEntriesForTest + 50
		for i := 0; i < n; i++ {
			raw := "bounded-token-" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + itoa(i)
			if err := h.store.SaveRefreshToken(context.Background(), mcpoauth.RefreshToken{
				TokenHash: mcpoauth.HashSecret(raw), ClientID: clientID, UserID: testUserID,
				FamilyID:        "bounded-family-" + itoa(i),
				FamilyCreatedAt: now,
				FamilyExpiresAt: now.Add(90 * 24 * time.Hour),
				ExpiresAt:       now.Add(30 * 24 * time.Hour),
				CreatedAt:       now,
			}); err != nil {
				t.Fatalf("seeding %d: %v", i, err)
			}
			if rec := rotate(h, clientID, raw); rec.Code != http.StatusOK {
				t.Fatalf("rotation %d: %d %s", i, rec.Code, rec.Body.String())
			}
		}
		if got := h.p.GraceLenForTest(); got > mcpoauth.MaxGraceEntriesForTest {
			t.Fatalf("the grace cache holds %d entries, cap is %d: an attacker holding many "+
				"refresh tokens can grow it without bound", got, mcpoauth.MaxGraceEntriesForTest)
		}
	})

	t.Run("disabling the window remembers nothing", func(t *testing.T) {
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshGracePeriod = -1 })
		clientID, pair := firstPair(t, h)
		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("rotation: %d", rec.Code)
		}
		if n := h.p.GraceLenForTest(); n != 0 {
			t.Fatalf("%d entries cached with the grace window disabled", n)
		}
	})
}

// TestLegacyFamilyIDIsDerivedNotRandom covers why the family a familyless row
// is adopted into must be deterministic.
//
// Nothing writes it back onto the predecessor row — v1's LinkRefreshSuccessor
// did, and it is gone. A random family would therefore be forgotten the instant
// the rotation's request ended, so a later replay of that same familyless token
// would find nothing to revoke and the chain it spawned would live on. Deriving
// it from the row's own hash means any process, at any later time, recomputes
// the same value.
func TestLegacyFamilyIDIsDerivedNotRandom(t *testing.T) {
	const raw = "legacy-token-with-no-family"

	h := newHarness(t)
	clientID := h.register(testRedirectURI)
	now := time.Now()
	if err := h.store.SaveRefreshToken(context.Background(), mcpoauth.RefreshToken{
		TokenHash: mcpoauth.HashSecret(raw), ClientID: clientID, UserID: testUserID,
		FamilyCreatedAt: now, FamilyExpiresAt: now.Add(90 * 24 * time.Hour),
		ExpiresAt: now.Add(30 * 24 * time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	thief := decodeJSON[tokenSuccess](t, rotate(h, clientID, raw))

	// A different process entirely judges the replay.
	pastGrace(h)
	h.restart()

	rec := rotate(h, clientID, raw)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want 400", rec.Code)
	}
	if desc := decodeJSON[errorBody](t, rec).Description; !strings.Contains(desc, "revoked") {
		t.Fatalf("a replay of a familyless token did not revoke the family it spawned: %q", desc)
	}
	if rec := rotate(h, clientID, thief.RefreshToken); rec.Code == http.StatusOK {
		t.Fatal("the chain descended from a familyless token survived a restart plus reuse detection")
	}
	if live := h.store.LiveRefresh(); live != 0 {
		t.Fatalf("%d usable refresh tokens survived", live)
	}
}

// itoa avoids pulling strconv into the test file for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
