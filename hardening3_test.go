package mcpoauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
)

// This file holds the regressions for the third hardening round. Each test
// corresponds to a finding that was reproduced against the previous commit.

// hookStore wraps a Store so a single method can be intercepted per test.
type hookStore struct {
	mcpoauth.Store
	beforeSaveRefresh func(mcpoauth.RefreshToken) error
}

func (h *hookStore) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	if h.beforeSaveRefresh != nil {
		if err := h.beforeSaveRefresh(rt); err != nil {
			return err
		}
	}
	return h.Store.SaveRefreshToken(ctx, rt)
}

// harnessOver builds a harness whose Provider talks to an arbitrary Store while
// still using the fake Google endpoints.
func harnessOver(t *testing.T, store mcpoauth.Store, base *memstore.MemoryStore) *harness {
	t.Helper()
	g := newFakeGoogle(t)
	cfg := mcpoauth.Config{
		Issuer:             testIssuer,
		ResourceURL:        testResourceURL,
		MetadataBaseURL:    testIssuer + "/api",
		GoogleClientID:     testGoogleCID,
		GoogleClientSecret: "google-client-secret",
		GoogleRedirectURL:  testIssuer + "/api/mcp/oauth/google/callback",
		AuthorizeURL:       testIssuer + "/api/mcp/oauth/authorize",
		TokenURL:           testIssuer + "/api/mcp/oauth/token",
		RegisterURL:        testIssuer + "/api/mcp/oauth/register",
		JWTSecret:          testSecret,
		GoogleAuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		GoogleTokenURL:     g.tokenURL(),
		GoogleJWKSURL:      g.jwksURL(),
	}
	p, err := mcpoauth.New(cfg, store)
	if err != nil {
		t.Fatalf("mcpoauth.New(): %v", err)
	}
	base.AddUser(testEmail, testUserID)
	h := &harness{t: t, p: p, cfg: cfg, store: base, google: g, clock: time.Now()}
	h.advance(0)
	return h
}

// TestGraceWindowHasNoLowerClockBound covers the HIGH that made the package's
// own concurrency test flake.
//
// graceApplies used to disqualify any replay whose `now` preceded the stored
// ConsumedAt. That is precisely the signature of a genuinely concurrent
// duplicate — the second request sampled its clock before the winner stamped
// the row — and, on a multi-node deployment, of ordinary clock skew. So the one
// case the window exists to absorb was the one it rejected: two parallel
// refreshes from ONE legitimate client revoked the family and logged the user
// out.
func TestGraceWindowHasNoLowerClockBound(t *testing.T) {
	tests := []struct {
		name string
		// skew is applied to the provider clock before the duplicate is
		// submitted. Negative means the duplicate's clock runs BEHIND the node
		// that won the race.
		skew time.Duration
	}{
		{"duplicate sampled its clock 500ms before the winner stamped", -500 * time.Millisecond},
		{"duplicate is 5s behind (multi-node clock skew)", -5 * time.Second},
		{"duplicate arrives at the same instant", 0},
		{"duplicate arrives 5s later", 5 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			clientID, pair := firstPair(t, h)

			h.advance(time.Minute)
			rot := rotate(h, clientID, pair.RefreshToken)
			if rot.Code != http.StatusOK {
				t.Fatalf("rotation: %d %s", rot.Code, rot.Body.String())
			}
			successor := decodeJSON[tokenSuccess](t, rot).RefreshToken

			h.advance(tc.skew)
			dup := rotate(h, clientID, pair.RefreshToken)
			if dup.Code != http.StatusOK {
				t.Fatalf("a duplicate submission inside the grace window was rejected "+
					"(%d %s) — the family is now revoked and the user is signed out",
					dup.Code, dup.Body.String())
			}
			if got := decodeJSON[tokenSuccess](t, dup).RefreshToken; got != successor {
				t.Fatal("the duplicate was answered with a DIFFERENT refresh token: two live chains")
			}
			if live := h.store.LiveRefresh(); live != 1 {
				t.Fatalf("%d live refresh rows after the duplicate, want exactly 1", live)
			}
		})
	}
}

// TestConcurrentRefreshNeverRevokesTheFamily is the statistical form of the same
// finding: 32 parallel refreshes of ONE token, repeated. Safety (never two live
// chains) always held; liveness did not — roughly one run in eight collapsed the
// family purely through concurrency.
func TestConcurrentRefreshNeverRevokesTheFamily(t *testing.T) {
	const runs = 10
	const racers = 32

	for run := 0; run < runs; run++ {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {pair.RefreshToken},
			"client_id":     {clientID},
		}

		var wg sync.WaitGroup
		results := make([]*httptest.ResponseRecorder, racers)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				rec := httptest.NewRecorder()
				h.p.Token()(rec, postForm("/token", form))
				results[i] = rec
			}(i)
		}
		close(start)
		wg.Wait()

		issued := map[string]bool{}
		for _, rec := range results {
			switch rec.Code {
			case http.StatusOK:
				issued[decodeJSON[tokenSuccess](t, rec).RefreshToken] = true
			case http.StatusBadRequest:
				desc := decodeJSON[errorBody](t, rec).Description
				if strings.Contains(desc, "revoked") || strings.Contains(desc, "invalid or already used") {
					t.Fatalf("run %d: pure concurrency killed the session: %q", run, desc)
				}
				if !strings.Contains(desc, "being rotated by another request") {
					t.Fatalf("run %d: unexpected 400 %q", run, desc)
				}
			default:
				t.Fatalf("run %d: unexpected status %d: %s", run, rec.Code, rec.Body.String())
			}
		}
		if len(issued) != 1 {
			t.Fatalf("run %d: %d distinct refresh tokens issued from ONE token, want 1", run, len(issued))
		}
		if live := h.store.LiveRefresh(); live != 1 {
			t.Fatalf("run %d: %d live refresh rows survive the race, want 1", run, live)
		}
		for tok := range issued {
			h.advance(time.Minute)
			if rec := rotate(h, clientID, tok); rec.Code != http.StatusOK {
				t.Fatalf("run %d: the token the race handed out is dead: %d %s",
					run, rec.Code, rec.Body.String())
			}
		}
	}
}

// TestRevocationIsNotUndoneByAnInFlightRotation covers the second HIGH.
//
// LinkRefreshSuccessor used to run BEFORE SaveRefreshToken and nothing re-read
// the family afterwards. A thief could replay a stale token to trigger detection
// while its own rotation was in flight: RevokeRefreshTokenFamily deleted the
// family, then the in-flight SaveRefreshToken inserted a fresh LIVE row carrying
// the dead family_id. The victim stayed evicted and the attacker kept rotating.
func TestRevocationIsNotUndoneByAnInFlightRotation(t *testing.T) {
	base := memstore.NewMemoryStore()
	gate := make(chan struct{})
	var mu sync.Mutex
	armed := false

	hooked := &hookStore{Store: base}
	hooked.beforeSaveRefresh = func(mcpoauth.RefreshToken) error {
		mu.Lock()
		wait := armed
		armed = false
		mu.Unlock()
		if wait {
			<-gate
		}
		return nil
	}

	h := harnessOver(t, hooked, base)
	clientID, pair := firstPair(t, h)

	h.advance(time.Second)
	t1 := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken)).RefreshToken
	h.advance(time.Second)
	t2 := decodeJSON[tokenSuccess](t, rotate(h, clientID, t1)).RefreshToken

	// Park the next rotation inside SaveRefreshToken.
	mu.Lock()
	armed = true
	mu.Unlock()

	var wg sync.WaitGroup
	var inFlight *httptest.ResponseRecorder
	wg.Add(1)
	go func() {
		defer wg.Done()
		inFlight = rotate(h, clientID, t2)
	}()

	// Wait until the rotation is actually parked.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		parked := !armed
		mu.Unlock()
		if parked || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)

	// Meanwhile a thief replays the original token: two steps stale, so no
	// grace — this is reuse, and it must kill the family for good.
	replay := rotate(h, clientID, pair.RefreshToken)
	if desc := decodeJSON[errorBody](t, replay).Description; !strings.Contains(desc, "revoked") {
		t.Fatalf("expected a family revocation, got %d %q", replay.Code, desc)
	}
	if live := base.LiveRefresh(); live != 0 {
		t.Fatalf("%d live refresh rows immediately after the revocation, want 0", live)
	}

	close(gate)
	wg.Wait()

	if inFlight.Code == http.StatusOK {
		resurrected := decodeJSON[tokenSuccess](t, inFlight).RefreshToken
		h.advance(time.Second)
		after := rotate(h, clientID, resurrected)
		t.Fatalf("the in-flight rotation resurrected the revoked family: it returned a usable "+
			"token (re-use of it -> %d) and %d live rows survive the revocation",
			after.Code, base.LiveRefresh())
	}
	if desc := decodeJSON[errorBody](t, inFlight).Description; !strings.Contains(desc, "revoked") {
		t.Fatalf("in-flight rotation should report the revocation, got %d %q", inFlight.Code, desc)
	}
	if live := base.LiveRefresh(); live != 0 {
		t.Fatalf("%d live refresh rows survive the revocation, want 0", live)
	}
}

// TestFailedSuccessorPersistDoesNotRevokeOnRetry is the corollary of the same
// reordering. Linking the sealed successor before persisting it left a blob
// pointing at a row that did not exist, so a failed SaveRefreshToken turned the
// client's immediate, entirely legitimate retry into a family revocation.
func TestFailedSuccessorPersistDoesNotRevokeOnRetry(t *testing.T) {
	base := memstore.NewMemoryStore()
	var mu sync.Mutex
	failNext := false

	hooked := &hookStore{Store: base}
	hooked.beforeSaveRefresh = func(mcpoauth.RefreshToken) error {
		mu.Lock()
		defer mu.Unlock()
		if failNext {
			failNext = false
			return fmt.Errorf("transient database error")
		}
		return nil
	}

	h := harnessOver(t, hooked, base)
	clientID, pair := firstPair(t, h)

	mu.Lock()
	failNext = true
	mu.Unlock()

	h.advance(time.Second)
	if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected the injected store failure to surface, got %d %s", rec.Code, rec.Body.String())
	}

	// The client saw a 500, still holds only the old token, and retries at once.
	h.advance(time.Second)
	retry := rotate(h, clientID, pair.RefreshToken)
	desc := decodeJSON[errorBody](t, retry).Description
	if strings.Contains(desc, "revoked") {
		t.Fatalf("a retry after a failed rotation revoked the family: %q", desc)
	}
	if !strings.Contains(desc, "being rotated by another request") {
		t.Fatalf("retry should land in the harmless mid-rotation branch, got %d %q", retry.Code, desc)
	}
}

// TestWrongClientIDDoesNotBurnTheToken covers the MEDIUM where
// ConsumeRefreshToken ran before the client_id check.
//
// Presenting a valid refresh token with any other client_id consumed it anyway,
// so the owner's next legitimate use was classified as reuse and killed the
// family: an unauthenticated logout for anyone who learns a refresh token, and a
// self-inflicted one on a client_id typo.
func TestWrongClientIDDoesNotBurnTheToken(t *testing.T) {
	t.Run("a fresh token survives a wrong client_id", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		other := h.register(testRedirectURI)

		rec := rotate(h, other, pair.RefreshToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("wrong client_id: status = %d, want 400", rec.Code)
		}
		if desc := decodeJSON[errorBody](t, rec).Description; !strings.Contains(desc, "another client") {
			t.Fatalf("wrong client_id -> %q, want a client-mismatch error", desc)
		}
		if live := h.store.LiveRefresh(); live != 1 {
			t.Fatalf("the token was consumed by the mismatching request: %d live rows", live)
		}

		// The rightful owner is unaffected.
		h.advance(time.Hour)
		own := rotate(h, clientID, pair.RefreshToken)
		if own.Code != http.StatusOK {
			t.Fatalf("the owner's own use failed after someone else's typo: %d %s",
				own.Code, own.Body.String())
		}
	})

	t.Run("a wrong client_id never revokes the family", func(t *testing.T) {
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		other := h.register(testRedirectURI)

		h.advance(time.Second)
		next := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken)).RefreshToken

		// A consumed token presented by the wrong client is not evidence of
		// anything: it is rejected without touching the family.
		pastGrace(h)
		rec := rotate(h, other, pair.RefreshToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if desc := decodeJSON[errorBody](t, rec).Description; strings.Contains(desc, "revoked") {
			t.Fatalf("a foreign client_id revoked the family: %q", desc)
		}
		if rec := rotate(h, clientID, next); rec.Code != http.StatusOK {
			t.Fatalf("the live token died with the family: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("the owner replaying it is still reuse", func(t *testing.T) {
		// The defence itself must be intact: nothing above weakens detection
		// for the client the token actually belongs to.
		h := newHarness(t)
		clientID, pair := firstPair(t, h)
		h.advance(time.Second)
		next := decodeJSON[tokenSuccess](t, rotate(h, clientID, pair.RefreshToken)).RefreshToken

		pastGrace(h)
		rec := rotate(h, clientID, pair.RefreshToken)
		if desc := decodeJSON[errorBody](t, rec).Description; !strings.Contains(desc, "revoked") {
			t.Fatalf("a genuine replay was not treated as reuse: %q", desc)
		}
		if rec := rotate(h, clientID, next); rec.Code == http.StatusOK {
			t.Fatal("the family survived reuse detection")
		}
	})
}

// TestGraceWindowIsAnchoredNotRolling is the end-to-end consequence of the
// Store rule VerifyStore now enforces with a third ConsumeRefreshToken call: the
// window is measured from the FIRST stamp. A Store that overwrites ConsumedAt
// makes it roll forever, and a stolen token stays replayable indefinitely.
func TestGraceWindowIsAnchoredNotRolling(t *testing.T) {
	h := newHarness(t)
	clientID, pair := firstPair(t, h)
	h.advance(time.Second)
	if rec := rotate(h, clientID, pair.RefreshToken); rec.Code != http.StatusOK {
		t.Fatalf("rotation: %d %s", rec.Code, rec.Body.String())
	}

	// Re-present every 10s. Anchored, it must die inside the 30s window; if
	// ConsumedAt were re-stamped on each call it would live forever.
	for i := 1; i <= 10; i++ {
		h.advance(10 * time.Second)
		rec := rotate(h, clientID, pair.RefreshToken)
		if rec.Code == http.StatusOK {
			if i*10 > 30 {
				t.Fatalf("the grace window is rolling: still alive at +%ds", i*10)
			}
			continue
		}
		if desc := decodeJSON[errorBody](t, rec).Description; !strings.Contains(desc, "revoked") {
			t.Fatalf("past the window a replay must revoke the family, got %q", desc)
		}
		return
	}
	t.Fatal("the grace window never closed — it is rolling")
}

// TestInsecureDevModeGatesEveryURL covers the LOW where only Issuer was checked:
// a loopback Issuer with every other URL pointing at a public https deployment
// was accepted, and the binder cookie then lost __Host-/Secure on the real
// origin.
func TestInsecureDevModeGatesEveryURL(t *testing.T) {
	const public = "https://finance.example.com"

	tests := []struct {
		name    string
		poison  func(c *mcpoauth.Config)
		wantErr bool
	}{
		{"all loopback", func(*mcpoauth.Config) {}, false},
		{"ResourceURL is public", func(c *mcpoauth.Config) { c.ResourceURL = public + "/api/mcp" }, true},
		{"MetadataBaseURL is public", func(c *mcpoauth.Config) { c.MetadataBaseURL = public + "/api" }, true},
		{"AuthorizeURL is public", func(c *mcpoauth.Config) { c.AuthorizeURL = public + "/authorize" }, true},
		{"TokenURL is public", func(c *mcpoauth.Config) { c.TokenURL = public + "/token" }, true},
		{"RegisterURL is public", func(c *mcpoauth.Config) { c.RegisterURL = public + "/register" }, true},
		{"GoogleRedirectURL is public", func(c *mcpoauth.Config) { c.GoogleRedirectURL = public + "/cb" }, true},
		{"Issuer is public", func(c *mcpoauth.Config) { c.Issuer = public }, true},
		{"loopback but https", func(c *mcpoauth.Config) { c.TokenURL = "https://127.0.0.1:8080/t" }, true},
		{"loopback lookalike host", func(c *mcpoauth.Config) { c.TokenURL = "http://127.0.0.1.evil.com/t" }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mcpoauth.Config{JWTSecret: testSecret, GoogleClientID: testGoogleCID, GoogleClientSecret: "s"}
			devLoopback(&cfg)
			tc.poison(&cfg)

			_, err := mcpoauth.New(cfg, newStore())
			if tc.wantErr && err == nil {
				t.Fatal("InsecureDevMode was accepted with a URL pointing at a real deployment")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a wholly loopback dev config was rejected: %v", err)
			}
		})
	}
}

// TestBinderCookieIsBounded covers the LOW where a binder value had no length
// cap, so a 200 KB attacker-supplied cookie was echoed back verbatim in
// Set-Cookie.
func TestBinderCookieIsBounded(t *testing.T) {
	// startFlow returns a harness parked on the consent page plus its nonce and
	// the real binder value the provider issued.
	startFlow := func(t *testing.T) (*harness, string, string) {
		t.Helper()
		h := newHarness(t)
		cid := h.register(testRedirectURI)
		h.binder = nil
		get := h.authorizeGET(authorizeParams(cid, testRedirectURI))
		if get.Code != http.StatusOK {
			t.Fatalf("authorize: %d", get.Code)
		}
		return h, consentNonce(t, get.Body.String()), h.binder.Value
	}

	huge := strings.Repeat("Z", 200_000)

	tests := []struct {
		name string
		// junk values are submitted alongside (or instead of) the real binder.
		junk []string
		// includeReal decides whether the genuine binder is in the cookie.
		includeReal bool
		wantApprove bool
	}{
		{"the real binder alone still matches", nil, true, true},
		{"short junk values do not displace it", []string{"aaa", "bbb"}, true, true},
		{"an oversized value is dropped but does not displace it", []string{huge}, true, true},
		{"illegal characters are dropped", []string{"not/base64url", "also+bad", "sp ace"}, true, true},
		// The amplification case: no genuine binder, so the approval fails and
		// dropBinder rewrites the cookie — which is where 200 KB of
		// attacker-controlled bytes used to come straight back in Set-Cookie.
		{"a 200 KB junk cookie is not echoed back", []string{huge}, false, false},
		{"forged binders never approve", []string{"forged-a", "forged-b"}, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, nonce, real := startFlow(t)
			values := append([]string{}, tc.junk...)
			if tc.includeReal {
				values = append(values, real)
			}
			submitted := strings.Join(values, mcpoauth.BinderCookieSep)

			rec := h.approve(nonce, &http.Cookie{
				Name:  mcpoauth.BinderCookieName,
				Value: submitted,
			})
			if tc.wantApprove && rec.Code != http.StatusFound {
				t.Fatalf("the real binder should still match: %d %s", rec.Code, rec.Body.String())
			}
			if !tc.wantApprove && rec.Code != http.StatusBadRequest {
				t.Fatalf("a cookie with no genuine binder approved the flow: %d", rec.Code)
			}

			// Whatever happened, the response must not echo the caller's bytes.
			for _, c := range rec.Result().Cookies() {
				if !strings.Contains(c.Name, "binder") {
					continue
				}
				if len(c.Value) > 5*64 {
					t.Fatalf("Set-Cookie echoed %d bytes back from a %d-byte request cookie",
						len(c.Value), len(submitted))
				}
				for _, v := range strings.Split(c.Value, mcpoauth.BinderCookieSep) {
					if len(v) > 64 {
						t.Fatalf("a %d-character binder survived into Set-Cookie", len(v))
					}
				}
			}
		})
	}
}
