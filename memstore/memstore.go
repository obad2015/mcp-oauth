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

func (s *MemoryStore) ConsumeRefreshToken(_ context.Context, tokenHash string) (mcpoauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refresh[tokenHash]
	delete(s.refresh, tokenHash)
	return rt, ok, nil
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

// PurgeExpired drops every expired record. Records with a zero ExpiresAt are
// treated as already expired: nothing this package writes leaves it unset.
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
		if rt.ExpiresAt.Before(before) {
			delete(s.refresh, h)
		}
	}
	return nil
}

// Len reports how many live records of each kind the store holds. Exported for
// tests and local debugging.
func (s *MemoryStore) Len() (clients, codes, pending, refresh int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients), len(s.codes), len(s.pending), len(s.refresh)
}

func (s *MemoryStore) FindUserIDByEmail(_ context.Context, email string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.usersByE[normalizeEmail(email)]
	return id, ok, nil
}

// compile-time check
var _ mcpoauth.Store = (*MemoryStore)(nil)
