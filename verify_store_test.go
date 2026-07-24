package mcpoauth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
)

// brokenStore is a MemoryStore with one deliberately broken behaviour, standing
// in for the ways a hand-written SQL Store silently loses a column or a
// guarantee. Every one of these keeps the happy path working and only disables
// a security control, which is exactly why VerifyStore exists.
type brokenStore struct {
	*memstore.MemoryStore

	// savedClients tracks what keepExpiredClients has to resurrect.
	savedClients []string

	dropBinderHash      bool
	dropFamilyID        bool
	dropFamilyCreatedAt bool
	dropFamilyExpiresAt bool
	dropSealed          bool
	deleteOnConsume     bool
	neverStampConsumed  bool
	returnRowAfterStamp bool
	replayableAuthCode  bool
	keepExpiredClients  bool
}

func (s *brokenStore) SavePendingAuth(ctx context.Context, p mcpoauth.PendingAuth) error {
	if s.dropBinderHash {
		p.BinderHash = ""
	}
	return s.MemoryStore.SavePendingAuth(ctx, p)
}

func (s *brokenStore) SaveRefreshToken(ctx context.Context, rt mcpoauth.RefreshToken) error {
	if s.dropFamilyID {
		rt.FamilyID = ""
	}
	if s.dropFamilyCreatedAt {
		rt.FamilyCreatedAt = time.Time{}
	}
	if s.dropFamilyExpiresAt {
		rt.FamilyExpiresAt = time.Time{}
	}
	return s.MemoryStore.SaveRefreshToken(ctx, rt)
}

func (s *brokenStore) ConsumeRefreshToken(ctx context.Context, hash string, at time.Time) (mcpoauth.RefreshToken, bool, error) {
	switch {
	case s.deleteOnConsume:
		// The pre-hardening behaviour: rotation destroys the evidence.
		rt, ok, err := s.MemoryStore.GetRefreshToken(ctx, hash)
		if ok {
			// The canary is alone in its family, so this deletes just it.
			_ = s.MemoryStore.RevokeRefreshTokenFamily(ctx, rt.FamilyID)
		}
		return rt, ok, err
	case s.neverStampConsumed:
		return s.MemoryStore.GetRefreshToken(ctx, hash)
	case s.returnRowAfterStamp:
		if _, _, err := s.MemoryStore.ConsumeRefreshToken(ctx, hash, at); err != nil {
			return mcpoauth.RefreshToken{}, false, err
		}
		return s.MemoryStore.GetRefreshToken(ctx, hash)
	}
	return s.MemoryStore.ConsumeRefreshToken(ctx, hash, at)
}

func (s *brokenStore) LinkRefreshSuccessor(ctx context.Context, hash, familyID string, sealed []byte) error {
	if s.dropSealed {
		sealed = nil
	}
	return s.MemoryStore.LinkRefreshSuccessor(ctx, hash, familyID, sealed)
}

func (s *brokenStore) ConsumeAuthCode(ctx context.Context, hash string) (mcpoauth.AuthCode, bool, error) {
	code, ok, err := s.MemoryStore.ConsumeAuthCode(ctx, hash)
	if s.replayableAuthCode && ok {
		// A SELECT with no DELETE: the code stays exchangeable forever.
		_ = s.MemoryStore.SaveAuthCode(ctx, code)
	}
	return code, ok, err
}

func (s *brokenStore) SaveClient(ctx context.Context, c mcpoauth.Client) error {
	s.savedClients = append(s.savedClients, c.ClientID)
	return s.MemoryStore.SaveClient(ctx, c)
}

func (s *brokenStore) PurgeExpired(ctx context.Context, before time.Time) error {
	if !s.keepExpiredClients {
		return s.MemoryStore.PurgeExpired(ctx, before)
	}
	// A PurgeExpired that forgot the clients table.
	kept := make([]mcpoauth.Client, 0, len(s.savedClients))
	for _, id := range s.savedClients {
		if c, ok, err := s.MemoryStore.GetClient(ctx, id); err == nil && ok {
			kept = append(kept, c)
		}
	}
	if err := s.MemoryStore.PurgeExpired(ctx, before); err != nil {
		return err
	}
	for _, c := range kept {
		if err := s.MemoryStore.SaveClient(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// TestVerifyStore is the startup self-check integrators are told to call. It has
// to be loud about every silent-but-insecure Store bug.
func TestVerifyStore(t *testing.T) {
	newProvider := func(t *testing.T, store mcpoauth.Store) *mcpoauth.Provider {
		t.Helper()
		p, err := mcpoauth.New(mcpoauth.Config{
			Issuer: testIssuer, ResourceURL: testResourceURL,
			GoogleClientID: testGoogleCID, GoogleClientSecret: "secret",
			GoogleRedirectURL: testIssuer + "/cb",
			AuthorizeURL:      testIssuer + "/authorize",
			TokenURL:          testIssuer + "/token",
			RegisterURL:       testIssuer + "/register",
			JWTSecret:         testSecret,
		}, store)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		return p
	}

	t.Run("a compliant store passes", func(t *testing.T) {
		p := newProvider(t, newStore())
		if err := p.VerifyStore(context.Background()); err != nil {
			t.Fatalf("VerifyStore() on a compliant store: %v", err)
		}
	})

	t.Run("verification leaves no canary records behind", func(t *testing.T) {
		store := newStore()
		p := newProvider(t, store)
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
		p := newProvider(t, store)
		for i := 0; i < 2; i++ {
			if err := p.VerifyStore(context.Background()); err != nil {
				t.Fatalf("VerifyStore() run %d: %v", i, err)
			}
		}
	})

	// Each broken store must be caught, and the message must name the field or
	// behaviour so the integrator knows what to fix.
	tests := []struct {
		name    string
		broken  func(s *brokenStore)
		wantMsg string
	}{
		{
			name:    "drops PendingAuth.BinderHash",
			broken:  func(s *brokenStore) { s.dropBinderHash = true },
			wantMsg: "BinderHash",
		},
		{
			name:    "drops RefreshToken.FamilyID",
			broken:  func(s *brokenStore) { s.dropFamilyID = true },
			wantMsg: "FamilyID",
		},
		{
			name:    "drops RefreshToken.FamilyCreatedAt",
			broken:  func(s *brokenStore) { s.dropFamilyCreatedAt = true },
			wantMsg: "FamilyCreatedAt",
		},
		{
			name:    "drops RefreshToken.FamilyExpiresAt",
			broken:  func(s *brokenStore) { s.dropFamilyExpiresAt = true },
			wantMsg: "FamilyExpiresAt",
		},
		{
			name:    "deletes the row on consume instead of stamping it",
			broken:  func(s *brokenStore) { s.deleteOnConsume = true },
			wantMsg: "reuse can never be detected",
		},
		{
			name:    "never persists ConsumedAt",
			broken:  func(s *brokenStore) { s.neverStampConsumed = true },
			wantMsg: "did not persist ConsumedAt",
		},
		{
			name:    "returns the row after stamping instead of before",
			broken:  func(s *brokenStore) { s.returnRowAfterStamp = true },
			wantMsg: "must return the row as it was BEFORE",
		},
		{
			name:    "drops SuccessorSealed",
			broken:  func(s *brokenStore) { s.dropSealed = true },
			wantMsg: "SuccessorSealed",
		},
		{
			name:    "lets an authorization code be consumed twice",
			broken:  func(s *brokenStore) { s.replayableAuthCode = true },
			wantMsg: "not single-use",
		},
		{
			name:    "never purges expired clients",
			broken:  func(s *brokenStore) { s.keepExpiredClients = true },
			wantMsg: "does not delete expired clients",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &brokenStore{MemoryStore: newStore()}
			tc.broken(s)

			err := newProvider(t, s).VerifyStore(context.Background())
			if err == nil {
				t.Fatal("VerifyStore() accepted a store that silently disables a security control")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("VerifyStore() error does not mention %q:\n%v", tc.wantMsg, err)
			}
		})
	}
}
