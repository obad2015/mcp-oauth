package mcpoauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// firstPair runs a full login and returns the client id plus the token pair the
// authorization-code grant issued.
func firstPair(t *testing.T, h *harness) (string, tokenSuccess) {
	t.Helper()
	clientID, code, verifier := h.login(testEmail)
	rec := h.token(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {verifier},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("initial exchange: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return clientID, decodeJSON[tokenSuccess](t, rec)
}

func TestRefreshTokenFamily(t *testing.T) {
	// rotate is one refresh_token grant.
	rotate := func(h *harness, clientID, token string) *httptest.ResponseRecorder {
		return h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {clientID},
		})
	}

	t.Run("reuse of a rotated token kills the whole family", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)

		// The attacker exfiltrated the refresh token and rotates first.
		stolen := pair.RefreshToken
		attacker := decodeJSON[tokenSuccess](t, rotate(h, clientID, stolen))
		if attacker.RefreshToken == "" {
			t.Fatal("the attacker's rotation did not produce a token")
		}

		// The legitimate client now presents the same token: canonical reuse.
		replay := rotate(h, clientID, stolen)
		if replay.Code != http.StatusBadRequest {
			t.Fatalf("reuse: status = %d, want 400", replay.Code)
		}
		if got := decodeJSON[errorBody](t, replay).Error; got != "invalid_grant" {
			t.Fatalf("reuse error = %q, want invalid_grant", got)
		}

		// ...and that must have taken the attacker's chain down with it.
		if rec := rotate(h, clientID, attacker.RefreshToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("the attacker's chain still works: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if _, _, _, refresh := h.store.Len(); refresh != 0 {
			t.Fatalf("%d refresh tokens survived the family revocation", refresh)
		}
	})

	t.Run("revocation is scoped to the family", func(t *testing.T) {
		h := newHarness(t)
		// Two independent logins by the same user => two families.
		clientA, pairA := firstPair(t, h)
		clientB, pairB := firstPair(t, h)

		stolen := pairA.RefreshToken
		_ = decodeJSON[tokenSuccess](t, rotate(h, clientA, stolen))
		if rec := rotate(h, clientA, stolen); rec.Code != http.StatusBadRequest {
			t.Fatalf("reuse: status = %d, want 400", rec.Code)
		}

		// The other login must be untouched.
		if rec := rotate(h, clientB, pairB.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("an unrelated family was revoked: status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("a family survives many honest rotations", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		for i := 0; i < 5; i++ {
			rec := rotate(h, clientID, pair.RefreshToken)
			if rec.Code != http.StatusOK {
				t.Fatalf("rotation %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
			}
			pair = decodeJSON[tokenSuccess](t, rec)
		}
	})

	t.Run("an unknown token that was never issued does not revoke anything", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		if rec := rotate(h, clientID, "never-issued-token"); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusOK {
			t.Fatalf("a live family was revoked by an unrelated bogus token: status = %d", rec.Code)
		}
	})
}

func TestRefreshTokenAbsoluteLifetime(t *testing.T) {
	// seed writes a refresh token directly so its family age can be chosen.
	seed := func(h *harness, clientID string, familyAge, expiresIn time.Duration) string {
		h.t.Helper()
		raw := "seeded-refresh-token-" + familyAge.String()
		now := time.Now()
		if err := h.store.SaveRefreshToken(context.Background(), mcpoauth.RefreshToken{
			TokenHash:       mcpoauth.HashSecret(raw),
			ClientID:        clientID,
			UserID:          testUserID,
			FamilyID:        "family-" + familyAge.String(),
			FamilyCreatedAt: now.Add(-familyAge),
			ExpiresAt:       now.Add(expiresIn),
			CreatedAt:       now,
		}); err != nil {
			h.t.Fatalf("seeding refresh token: %v", err)
		}
		return raw
	}

	tests := []struct {
		name        string
		absoluteTTL time.Duration
		familyAge   time.Duration
		wantOK      bool
	}{
		{"young family rotates fine", 90 * 24 * time.Hour, time.Hour, true},
		{"family just inside the cap", 90 * 24 * time.Hour, 89 * 24 * time.Hour, true},
		{"family past the cap is refused", 90 * 24 * time.Hour, 91 * 24 * time.Hour, false},
		{"a short configured cap is enforced", time.Hour, 2 * time.Hour, false},
		{"exactly at the cap is refused", time.Hour, time.Hour, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshTokenAbsoluteTTL = tc.absoluteTTL })
			clientID := h.register(testRedirectURI)
			// The sliding expiry is always in the future: only the absolute
			// cap is under test.
			raw := seed(h, clientID, tc.familyAge, 30*24*time.Hour)

			rec := h.token(url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {raw},
				"client_id":     {clientID},
			})
			if (rec.Code == http.StatusOK) != tc.wantOK {
				t.Fatalf("status = %d, wantOK = %v (body %s)", rec.Code, tc.wantOK, rec.Body.String())
			}
			if tc.wantOK {
				return
			}
			if got := decodeJSON[errorBody](t, rec).Error; got != "invalid_grant" {
				t.Fatalf("error = %q, want invalid_grant", got)
			}
			// The expired family is gone, not merely refused this once.
			if _, _, _, refresh := h.store.Len(); refresh != 0 {
				t.Fatalf("%d tokens of an over-age family survived", refresh)
			}
		})
	}

	t.Run("rotation carries the original family start, it does not slide", func(t *testing.T) {
		// A one-hour absolute cap with a family that started 59 minutes ago:
		// one rotation is allowed, and the token it issues must still expire at
		// the family's cap rather than a fresh 30 days out.
		h := newHarness(t, func(c *mcpoauth.Config) { c.RefreshTokenAbsoluteTTL = time.Hour })
		clientID := h.register(testRedirectURI)
		raw := seed(h, clientID, 59*time.Minute, 30*24*time.Hour)

		rec := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {raw},
			"client_id":     {clientID},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("rotation: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		next := decodeJSON[tokenSuccess](t, rec)

		// Move a couple of minutes past the family's absolute cap.
		base := time.Now().Add(3 * time.Minute)
		h.p.SetNowForTest(func() time.Time { return base })
		again := h.token(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {next.RefreshToken},
			"client_id":     {clientID},
		})
		if again.Code != http.StatusBadRequest {
			t.Fatalf("rotation past the cap: status = %d, want 400 (body %s)", again.Code, again.Body.String())
		}
	})
}
