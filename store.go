package mcpoauth

import "context"

// Store is the persistence contract an application implements to back the
// authorization server. It is deliberately driver-agnostic: any SQL, KV or
// in-memory backend works.
//
// Implementation requirements:
//
//   - The Consume* methods MUST be single-use and atomic: a concurrent second
//     call for the same value must return ok=false. In SQL this is typically a
//     "DELETE ... RETURNING *" (or a conditional UPDATE) in one statement.
//   - Consume* returning an expired record is fine; the Provider checks
//     expiry itself. Returning ok=false for expired records is also fine.
//   - Nothing here ever receives a raw secret: codes, refresh tokens and the
//     pending state are always identified by their SHA-256 hash (hex).
type Store interface {
	// SaveClient persists a dynamically registered client.
	SaveClient(ctx context.Context, c Client) error
	// GetClient looks up a client by its ID. ok=false when unknown.
	GetClient(ctx context.Context, clientID string) (Client, bool, error)

	// SaveAuthCode persists an authorization code record (hash only).
	SaveAuthCode(ctx context.Context, code AuthCode) error
	// ConsumeAuthCode atomically fetches and invalidates an authorization
	// code. A second call with the same hash MUST return ok=false.
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCode, bool, error)

	// SavePendingAuth persists the state of an in-flight authorize request.
	SavePendingAuth(ctx context.Context, p PendingAuth) error
	// ConsumePendingAuth atomically fetches and invalidates pending state.
	ConsumePendingAuth(ctx context.Context, stateHash string) (PendingAuth, bool, error)

	// SaveRefreshToken persists a refresh token record (hash only).
	SaveRefreshToken(ctx context.Context, rt RefreshToken) error
	// ConsumeRefreshToken atomically fetches and invalidates a refresh token.
	// This is what makes refresh-token rotation safe: replaying a rotated
	// token MUST return ok=false.
	ConsumeRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, bool, error)
	// RevokeRefreshTokensForUser invalidates every refresh token of a user.
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error

	// FindUserIDByEmail maps a verified Google email to an EXISTING
	// application user. Return ok=false when there is no such user — the
	// Provider then refuses the login instead of creating an account.
	FindUserIDByEmail(ctx context.Context, email string) (userID string, ok bool, err error)
}
