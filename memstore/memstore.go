// Package memstore provides an in-memory mcpoauth.Store.
//
// It is intended for tests and local development. Everything lives in process
// memory and is lost on restart — use a real database in production.
package memstore

import (
	"context"
	"strings"
	"sync"
	"time"

	mcpoauth "github.com/obad2015/mcp-oauth"
)

// MemoryStore is a goroutine-safe, in-memory implementation of
// mcpoauth.Store.
type MemoryStore struct {
	mu       sync.Mutex
	clients  map[string]mcpoauth.Client
	codes    map[string]mcpoauth.AuthCode
	pending  map[string]mcpoauth.PendingAuth
	refresh  map[string]mcpoauth.RefreshToken
	usersByE map[string]string
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:  map[string]mcpoauth.Client{},
		codes:    map[string]mcpoauth.AuthCode{},
		pending:  map[string]mcpoauth.PendingAuth{},
		refresh:  map[string]mcpoauth.RefreshToken{},
		usersByE: map[string]string{},
	}
}

// AddUser registers an application user so FindUserIDByEmail can resolve it.
func (s *MemoryStore) AddUser(email, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersByE[normalizeEmail(email)] = userID
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *MemoryStore) SaveClient(_ context.Context, c mcpoauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
	return nil
}

func (s *MemoryStore) GetClient(_ context.Context, clientID string) (mcpoauth.Client, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	return c, ok, nil
}

func (s *MemoryStore) SaveAuthCode(_ context.Context, code mcpoauth.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.CodeHash] = code
	return nil
}

func (s *MemoryStore) ConsumeAuthCode(_ context.Context, codeHash string) (mcpoauth.AuthCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[codeHash]
	delete(s.codes, codeHash)
	return c, ok, nil
}

func (s *MemoryStore) SavePendingAuth(_ context.Context, p mcpoauth.PendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[p.StateHash] = p
	return nil
}

func (s *MemoryStore) ConsumePendingAuth(_ context.Context, stateHash string) (mcpoauth.PendingAuth, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[stateHash]
	delete(s.pending, stateHash)
	return p, ok, nil
}

func (s *MemoryStore) SaveRefreshToken(_ context.Context, rt mcpoauth.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[rt.TokenHash] = rt
	return nil
}

func (s *MemoryStore) GetRefreshToken(_ context.Context, tokenHash string) (mcpoauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refresh[tokenHash]
	return rt, ok, nil
}

// ConsumeRefreshToken stamps ConsumedAt and returns the row as it was before.
// The row is deliberately kept: it is the durable reuse-detection ledger, and
// only PurgeExpired removes it.
func (s *MemoryStore) ConsumeRefreshToken(_ context.Context, tokenHash string, consumedAt time.Time) (mcpoauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, ok := s.refresh[tokenHash]
	if !ok {
		return mcpoauth.RefreshToken{}, false, nil
	}
	if before.ConsumedAt.IsZero() {
		stamped := before
		stamped.ConsumedAt = consumedAt
		s.refresh[tokenHash] = stamped
	}
	return before, true, nil
}

// LinkRefreshSuccessor attaches the sealed successor to a consumed row and
// re-stamps its family.
func (s *MemoryStore) LinkRefreshSuccessor(_ context.Context, tokenHash, familyID string, sealed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refresh[tokenHash]
	if !ok {
		return nil
	}
	rt.FamilyID = familyID
	rt.SuccessorSealed = sealed
	s.refresh[tokenHash] = rt
	return nil
}

func (s *MemoryStore) RevokeRefreshTokensForUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, rt := range s.refresh {
		if rt.UserID == userID {
			delete(s.refresh, h)
		}
	}
	return nil
}

// RevokeRefreshTokenFamily drops every token in one rotation chain. Called on
// refresh-token reuse detection.
func (s *MemoryStore) RevokeRefreshTokenFamily(_ context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, rt := range s.refresh {
		if rt.FamilyID == familyID {
			delete(s.refresh, h)
		}
	}
	return nil
}

// PurgeExpired drops every record whose retention has lapsed. Records with a
// zero ExpiresAt are treated as already expired: nothing this package writes
// leaves it unset.
//
// A refresh token survives until BOTH its own expiry and its family's have
// passed — a consumed row is the reuse-detection ledger and must outlive the
// token itself.
func (s *MemoryStore) PurgeExpired(_ context.Context, before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, c := range s.codes {
		if c.ExpiresAt.Before(before) {
			delete(s.codes, h)
		}
	}
	for h, p := range s.pending {
		if p.ExpiresAt.Before(before) {
			delete(s.pending, h)
		}
	}
	for h, rt := range s.refresh {
		if rt.ExpiresAt.Before(before) && rt.FamilyExpiresAt.Before(before) {
			delete(s.refresh, h)
		}
	}
	for id, c := range s.clients {
		if c.ExpiresAt.Before(before) {
			delete(s.clients, id)
		}
	}
	return nil
}

// Len reports how many records of each kind the store holds, consumed refresh
// tokens included. Exported for tests and local debugging.
func (s *MemoryStore) Len() (clients, codes, pending, refresh int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients), len(s.codes), len(s.pending), len(s.refresh)
}

// LiveRefresh reports how many refresh tokens are still usable — rows that
// have not been consumed. Exported for tests and local debugging.
func (s *MemoryStore) LiveRefresh() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rt := range s.refresh {
		if rt.ConsumedAt.IsZero() {
			n++
		}
	}
	return n
}

func (s *MemoryStore) FindUserIDByEmail(_ context.Context, email string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.usersByE[normalizeEmail(email)]
	return id, ok, nil
}

// compile-time check
var _ mcpoauth.Store = (*MemoryStore)(nil)
