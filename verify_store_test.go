package mcpoauth_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
)

// faultStore wraps a fully compliant Store and breaks exactly ONE documented
// rule, standing in for the ways a hand-written SQL Store silently loses a
// column or a guarantee.
//
// Every fault here keeps the OAuth happy path working and only removes a
// defence — which is why VerifyStore exists, and why this is the highest-value
// test in the package: it is the shape an insecure deployment actually takes.
//
// The faults are simulated entirely in the wrapper (an overlay of stamps and
// tombstones) rather than by reaching into memstore, so memstore stays a clean
// reference implementation with no test-only escape hatches.
type faultStore struct {
	mcpoauth.Store

	mu sync.Mutex
	// stamps records what an overwriting ConsumeRefreshToken would have
	// written, so GetRefreshToken can report the newest value.
	stamps map[string]time.Time
	// gone are hashes a deleting ConsumeRefreshToken destroyed.
	gone map[string]bool
	// pendingByClient is what a client_id-keyed upsert would collapse on.
	pendingByClient map[string]string
	// savedClients is what keepExpiredClients has to resurrect.
	savedClients []string

	dropBinderHash      bool
	dropApproved        bool
	dropFamilyID        bool
	dropFamilyCreatedAt bool
	dropFamilyExpiresAt bool
	dropSealed          bool
	deleteOnConsume     bool
	neverStampConsumed  bool
	returnRowAfterStamp bool
	overwriteConsumedAt bool
	filterExpiredRows   bool
	linkIsUpsert        bool
	pendingIsUpsert     bool
	replayableAuthCode  bool
	revokeIsNoOp        bool
	keepExpiredClients  bool
}

func newFaultStore(breakOneRule func(*faultStore)) *faultStore {
	f := &faultStore{
		Store:           memstore.NewMemoryStore(),
		stamps:          map[string]time.Time{},
		gone:            map[string]bool{},
		pendingByClient: map[string]string{},
	}
	breakOneRule(f)
	return f
}

func (f *faultStore) SavePendingAuth(ctx context.Context, p mcpoauth.PendingAuth) error {
	if f.dropBinderHash {
		p.BinderHash = ""
	}
	if f.dropApproved {
		p.Approved = false
	}
	if f.pendingIsUpsert {
		// ON CONFLICT (client_id) DO UPDATE: the previous record for this
		// client is silently replaced.
		f.mu.Lock()
		prev, had := f.pendingByClient[p.ClientID]
		f.pendingByClient[p.ClientID] = p.StateHash
		f.mu.Unlock()
		if had && prev != p.StateHash {
			_, _, _ = f.Store.ConsumePendingAuth(ctx, prev)
		}
	}
	return f.Store.SavePendingAuth(ctx, p)
}

func (f *faultStore) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	if f.dropFamilyID {
		rt.FamilyID = ""
	}
	if f.dropFamilyCreatedAt {
		rt.FamilyCreatedAt = time.Time{}
	}
	if f.dropFamilyExpiresAt {
		rt.FamilyExpiresAt = time.Time{}
	}
	return f.Store.SaveRefreshToken(ctx, rt)
}

func (f *faultStore) GetRefreshToken(ctx context.Context, hash string) (mcpoauth.RefreshToken, bool, error) {
	f.mu.Lock()
	dead := f.gone[hash]
	stamp, restamped := f.stamps[hash]
	f.mu.Unlock()
	if dead {
		return mcpoauth.RefreshToken{}, false, nil
	}
	rt, ok, err := f.Store.GetRefreshToken(ctx, hash)
	if ok && restamped {
		rt.ConsumedAt = stamp
	}
	return rt, ok, err
}

func (f *faultStore) ConsumeRefreshToken(ctx context.Context, hash string, at time.Time) (mcpoauth.RefreshToken, bool, error) {
	switch {
	case f.deleteOnConsume:
		// The classic `DELETE ... RETURNING *`: rotation destroys the evidence.
		f.mu.Lock()
		dead := f.gone[hash]
		f.mu.Unlock()
		if dead {
			return mcpoauth.RefreshToken{}, false, nil
		}
		rt, ok, err := f.Store.ConsumeRefreshToken(ctx, hash, at)
		if ok {
			f.mu.Lock()
			f.gone[hash] = true
			f.mu.Unlock()
		}
		return rt, ok, err

	case f.neverStampConsumed:
		// A SELECT with no UPDATE.
		return f.Store.GetRefreshToken(ctx, hash)

	case f.returnRowAfterStamp:
		if _, _, err := f.Store.ConsumeRefreshToken(ctx, hash, at); err != nil {
			return mcpoauth.RefreshToken{}, false, err
		}
		return f.Store.GetRefreshToken(ctx, hash)

	case f.overwriteConsumedAt:
		// `SET consumed_at = $2 WHERE token_hash = $1` — the `AND consumed_at
		// IS NULL` guard omitted. The row is re-stamped on every call, but the
		// value RETURNED is still the one from before the call, so this
		// satisfies every other documented requirement.
		rt, ok, err := f.Store.ConsumeRefreshToken(ctx, hash, at)
		if !ok || err != nil {
			return rt, ok, err
		}
		f.mu.Lock()
		prev, had := f.stamps[hash]
		f.stamps[hash] = at
		f.mu.Unlock()
		if had {
			rt.ConsumedAt = prev
		}
		return rt, ok, err

	case f.filterExpiredRows:
		// `AND expires_at > now()` added to the consume query.
		rt, ok, err := f.Store.ConsumeRefreshToken(ctx, hash, at)
		if ok && !at.Before(rt.ExpiresAt) {
			return mcpoauth.RefreshToken{}, false, nil
		}
		return rt, ok, err
	}
	return f.Store.ConsumeRefreshToken(ctx, hash, at)
}

func (f *faultStore) LinkRefreshSuccessor(ctx context.Context, hash, familyID string, sealed []byte) error {
	if f.dropSealed {
		sealed = nil
	}
	if f.linkIsUpsert {
		if _, ok, err := f.Store.GetRefreshToken(ctx, hash); err == nil && !ok {
			// INSERT ... ON CONFLICT DO UPDATE: a row is conjured for a token
			// that was never issued.
			return f.Store.SaveRefreshToken(ctx, mcpoauth.RefreshToken{
				TokenHash:       hash,
				FamilyID:        familyID,
				SuccessorSealed: sealed,
			})
		}
	}
	return f.Store.LinkRefreshSuccessor(ctx, hash, familyID, sealed)
}

func (f *faultStore) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	if f.revokeIsNoOp {
		return nil
	}
	return f.Store.RevokeRefreshTokenFamily(ctx, familyID)
}

func (f *faultStore) ConsumeAuthCode(ctx context.Context, hash string) (mcpoauth.AuthCode, bool, error) {
	code, ok, err := f.Store.ConsumeAuthCode(ctx, hash)
	if f.replayableAuthCode && ok {
		// A SELECT with no DELETE: the code stays exchangeable forever.
		_ = f.Store.SaveAuthCode(ctx, code)
	}
	return code, ok, err
}

func (f *faultStore) SaveClient(ctx context.Context, c mcpoauth.Client) error {
	f.savedClients = append(f.savedClients, c.ClientID)
	return f.Store.SaveClient(ctx, c)
}

func (f *faultStore) PurgeExpired(ctx context.Context, before time.Time) error {
	if !f.keepExpiredClients {
		return f.Store.PurgeExpired(ctx, before)
	}
	// A PurgeExpired that forgot the clients table.
	kept := make([]mcpoauth.Client, 0, len(f.savedClients))
	for _, id := range f.savedClients {
		if c, ok, err := f.Store.GetClient(ctx, id); err == nil && ok {
			kept = append(kept, c)
		}
	}
	if err := f.Store.PurgeExpired(ctx, before); err != nil {
		return err
	}
	for _, c := range kept {
		if err := f.Store.SaveClient(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func verifyProvider(t *testing.T, store mcpoauth.Store, tweak ...func(*mcpoauth.Config)) *mcpoauth.Provider {
	t.Helper()
	cfg := mcpoauth.Config{
		Issuer: testIssuer, ResourceURL: testResourceURL,
		GoogleClientID: testGoogleCID, GoogleClientSecret: "secret",
		GoogleRedirectURL: testIssuer + "/cb",
		AuthorizeURL:      testIssuer + "/authorize",
		TokenURL:          testIssuer + "/token",
		RegisterURL:       testIssuer + "/register",
		JWTSecret:         testSecret,
	}
	for _, f := range tweak {
		f(&cfg)
	}
	p, err := mcpoauth.New(cfg, store)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return p
}

// TestVerifyStore is the startup self-check integrators are told to call. It has
// to be loud about every silent-but-insecure Store bug.
func TestVerifyStore(t *testing.T) {
	t.Run("a compliant store passes", func(t *testing.T) {
		p := verifyProvider(t, newStore())
		if err := p.VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore() on a compliant store: %v", err)
		}
	})

	t.Run("verification leaves no canary records behind", func(t *testing.T) {
		store := newStore()
		p := verifyProvider(t, store)
		if err := p.VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore(): %v", err)
		}
		clients, codes, pending, refresh := store.Len()
		if clients+codes+pending+refresh != 0 {
			t.Fatalf("canaries left behind: clients=%d codes=%d pending=%d refresh=%d",
				clients, codes, pending, refresh)
		}
	})

	t.Run("it is safe to run twice", func(t *testing.T) {
		store := newStore()
		p := verifyProvider(t, store)
		for i := 0; i < 2; i++ {
			if err := p.VerifyStore(context.Background()); err != nil {
				t.Fatalf("VerifyStore() run %d: %v", i, err)
			}
		}
	})

	t.Run("it does not disturb real records", func(t *testing.T) {
		store := newStore()
		live := mcpoauth.RefreshToken{
			TokenHash:       mcpoauth.HashSecret("a-real-live-token"),
			ClientID:        "real-client",
			UserID:          testUserID,
			FamilyID:        "real-family",
			FamilyCreatedAt: time.Now(),
			FamilyExpiresAt: time.Now().Add(90 * 24 * time.Hour),
			ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
			CreatedAt:       time.Now(),
		}
		if err := store.SaveRefreshToken(context.Background(), live); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveClient(context.Background(), mcpoauth.Client{
			ClientID: "real-client", RedirectURIs: []string{testRedirectURI},
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		if err := verifyProvider(t, store).VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore(): %v", err)
		}
		if _, ok, _ := store.GetRefreshToken(context.Background(), live.TokenHash); !ok {
			t.Fatal("VerifyStore destroyed a live production refresh token")
		}
		if _, ok, _ := store.GetClient(context.Background(), "real-client"); !ok {
			t.Fatal("VerifyStore destroyed a live production client")
		}
		if clients, _, _, refresh := store.Len(); clients != 1 || refresh != 1 {
			t.Fatalf("residue: %d clients, %d refresh rows (want 1 real one of each)", clients, refresh)
		}
	})

	// One broken rule per case. Each must be caught, and the message must name
	// the field or behaviour so the integrator knows what to fix.
	tests := []struct {
		name    string
		broken  func(f *faultStore)
		wantMsg string
	}{
		{
			name:    "drops PendingAuth.BinderHash",
			broken:  func(f *faultStore) { f.dropBinderHash = true },
			wantMsg: "BinderHash",
		},
		{
			name:    "drops PendingAuth.Approved",
			broken:  func(f *faultStore) { f.dropApproved = true },
			wantMsg: "Approved",
		},
		{
			name:    "drops RefreshToken.FamilyID",
			broken:  func(f *faultStore) { f.dropFamilyID = true },
			wantMsg: "FamilyID",
		},
		{
			name:    "drops RefreshToken.FamilyCreatedAt",
			broken:  func(f *faultStore) { f.dropFamilyCreatedAt = true },
			wantMsg: "FamilyCreatedAt",
		},
		{
			name:    "drops RefreshToken.FamilyExpiresAt",
			broken:  func(f *faultStore) { f.dropFamilyExpiresAt = true },
			wantMsg: "FamilyExpiresAt",
		},
		{
			name:    "drops RefreshToken.SuccessorSealed",
			broken:  func(f *faultStore) { f.dropSealed = true },
			wantMsg: "SuccessorSealed",
		},
		{
			name:    "deletes the row on consume instead of stamping it",
			broken:  func(f *faultStore) { f.deleteOnConsume = true },
			wantMsg: "reuse can never be detected",
		},
		{
			name:    "never persists ConsumedAt",
			broken:  func(f *faultStore) { f.neverStampConsumed = true },
			wantMsg: "did not persist ConsumedAt",
		},
		{
			name:    "returns the row after stamping instead of before",
			broken:  func(f *faultStore) { f.returnRowAfterStamp = true },
			wantMsg: "must return the row as it was BEFORE",
		},
		{
			// The one a two-call check cannot see: the UPDATE is missing its
			// `AND consumed_at IS NULL` guard, so the grace window rolls
			// forever and a stolen token stays replayable indefinitely.
			name:    "overwrites ConsumedAt on every call",
			broken:  func(f *faultStore) { f.overwriteConsumedAt = true },
			wantMsg: "`AND consumed_at IS NULL`",
		},
		{
			name:    "filters out expired rows on consume",
			broken:  func(f *faultStore) { f.filterExpiredRows = true },
			wantMsg: "Do NOT filter on expires_at",
		},
		{
			name:    "LinkRefreshSuccessor is an upsert",
			broken:  func(f *faultStore) { f.linkIsUpsert = true },
			wantMsg: "never an UPSERT",
		},
		{
			name:    "SavePendingAuth upserts on client_id and loses a record",
			broken:  func(f *faultStore) { f.pendingIsUpsert = true },
			wantMsg: "SavePendingAuth lost record",
		},
		{
			name:    "lets an authorization code be consumed twice",
			broken:  func(f *faultStore) { f.replayableAuthCode = true },
			wantMsg: "not single-use",
		},
		{
			name:    "RevokeRefreshTokenFamily is a no-op",
			broken:  func(f *faultStore) { f.revokeIsNoOp = true },
			wantMsg: "RevokeRefreshTokenFamily left a token",
		},
		{
			name:    "never purges expired clients",
			broken:  func(f *faultStore) { f.keepExpiredClients = true },
			wantMsg: "does not delete expired clients",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyProvider(t, newFaultStore(tc.broken)).VerifyStore(context.Background())
			if err == nil {
				t.Fatal("VerifyStore() accepted a store that silently disables a security control")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("VerifyStore() error does not mention %q:\n%v", tc.wantMsg, err)
			}
		})
	}
}

// TestVerifyStoreCanaries covers the two ways the canaries themselves used to be
// wrong: an already-expired canary a concurrent PurgeExpired could delete
// mid-check, and a hard-coded string user ID that a `user_id UUID` column
// rejects.
func TestVerifyStoreCanaries(t *testing.T) {
	t.Run("a concurrent PurgeExpired ticker causes no false positive", func(t *testing.T) {
		// The README tells applications to run PurgeExpired from a ticker, and
		// a rolling deploy boots a second instance while the first verifies.
		// A canary written already-expired was deleted out from under the check
		// and VerifyStore — documented as fatal — refused to start the app.
		const attempts = 40
		for i := 0; i < attempts; i++ {
			store := newStore()
			p := verifyProvider(t, store)

			stop := make(chan struct{})
			var wg sync.WaitGroup
			for k := 0; k < 4; k++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
							_ = store.PurgeExpired(context.Background(), time.Now())
						}
					}
				}()
			}
			err := p.VerifyStore(context.Background())
			close(stop)
			wg.Wait()
			if err != nil {
				t.Fatalf("run %d: VerifyStore reported a contract violation against a "+
					"compliant Store while a purge ticker was running:\n%v", i, err)
			}
		}
	})

	t.Run("concurrent VerifyStore runs do not collide", func(t *testing.T) {
		store := newStore()
		p := verifyProvider(t, store)
		errs := make([]error, 4)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) { defer wg.Done(); errs[i] = p.VerifyStore(context.Background()) }(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent VerifyStore #%d failed: %v", i, err)
			}
		}
	})

	t.Run("the canary user ID is caller-supplied", func(t *testing.T) {
		const uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
		rec := &recordingStore{Store: newStore()}
		p := verifyProvider(t, rec, func(c *mcpoauth.Config) { c.VerifyStoreUserID = uuid })
		if err := p.VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore(): %v", err)
		}
		if len(rec.userIDs) == 0 {
			t.Fatal("no canary user ID was written at all")
		}
		for _, got := range rec.userIDs {
			if got != uuid {
				t.Fatalf("canary user_id = %q, want the configured %q "+
					"(a user_id UUID column, or an FK to users, rejects anything else)", got, uuid)
			}
		}
	})

	t.Run("the canary client_id fits the documented 48-character column", func(t *testing.T) {
		// Issued client IDs are 32 chars, so a VARCHAR(32) column passes in
		// production and fails only here. The README promises >= 48; this pins
		// the number so it cannot drift past what integrators were told.
		rec := &recordingStore{Store: newStore()}
		if err := verifyProvider(t, rec).VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore(): %v", err)
		}
		if n := len(rec.clientID); n > 48 {
			t.Fatalf("canary client_id is %d chars; the README promises integrators 48", n)
		}
	})
}

// recordingStore captures the canary shapes VerifyStore writes.
type recordingStore struct {
	mcpoauth.Store
	mu       sync.Mutex
	clientID string
	userIDs  []string
}

func (r *recordingStore) SaveClient(ctx context.Context, c mcpoauth.Client) error {
	r.mu.Lock()
	r.clientID = c.ClientID
	r.mu.Unlock()
	return r.Store.SaveClient(ctx, c)
}

func (r *recordingStore) SaveAuthCode(ctx context.Context, c mcpoauth.AuthCode) error {
	r.mu.Lock()
	r.userIDs = append(r.userIDs, c.UserID)
	r.mu.Unlock()
	return r.Store.SaveAuthCode(ctx, c)
}

func (r *recordingStore) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	r.mu.Lock()
	r.userIDs = append(r.userIDs, rt.UserID)
	r.mu.Unlock()
	return r.Store.SaveRefreshToken(ctx, rt)
}
