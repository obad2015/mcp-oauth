package mcpoauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// accessTokenKeyInfo is the HKDF info string that separates the access-token
// signing key from every other use of Config.JWTSecret. Changing it invalidates
// every issued access token.
const accessTokenKeyInfo = "mcpoauth/v1/access-token"

// Sanity floors New enforces on Config.JWTSecret. They are NOT an entropy
// measurement — nothing can measure the entropy of a given string — they only
// reject the two shapes that show up in practice: a secret that is too short to
// key HMAC-SHA256, and a padded or repeated placeholder such as "aaaa...".
// A real secret is 32+ bytes from a CSPRNG.
const (
	minJWTSecretLen      = 32
	minJWTSecretDistinct = 8
)

// refreshSuccessorKeyInfo is the HKDF info prefix for the key that seals a
// rotation's successor token onto its consumed predecessor row.
const refreshSuccessorKeyInfo = "mcpoauth/v1/refresh-successor|"

// hkdfExpand is HKDF-Expand (RFC 5869 §2.3) with SHA-256. The input is already
// a high-entropy secret (New enforces >= 32 bytes), so the extract step is not
// needed and the secret is used directly as the pseudorandom key.
func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// deriveSigningKey turns the configured secret into the actual HS256 key.
//
// This is deliberately one-way: an application that reuses its session-JWT
// secret as Config.JWTSecret still ends up with two unrelated keys, so a
// session token can never be replayed as an MCP access token and vice versa —
// even if the token_use claim check were ever removed.
func deriveSigningKey(secret []byte) []byte {
	return hkdfExpand(secret, []byte(accessTokenKeyInfo), 32)
}

// successorKey derives the AES key that seals the successor of one specific
// refresh token. The raw predecessor token is part of the derivation, so the
// blob can only ever be opened by someone who presents that token — a dump of
// the refresh-token table (which holds hashes only) is useless.
func (p *Provider) successorKey(predecessorRaw string) []byte {
	return hkdfExpand(p.signKey, []byte(refreshSuccessorKeyInfo+predecessorRaw), 32)
}

// sealSuccessor encrypts successorRaw so it can be handed back to a client that
// re-presents predecessorRaw inside Config.RefreshGracePeriod.
func (p *Provider) sealSuccessor(predecessorRaw, successorRaw string) ([]byte, error) {
	gcm, err := newGCM(p.successorKey(predecessorRaw))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating seal nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, []byte(successorRaw), []byte(HashSecret(predecessorRaw))), nil
}

// openSuccessor reverses sealSuccessor. ok=false for anything it cannot
// authenticate, including a blob written for a different token.
func (p *Provider) openSuccessor(predecessorRaw string, sealed []byte) (string, bool) {
	gcm, err := newGCM(p.successorKey(predecessorRaw))
	if err != nil {
		return "", false
	}
	if len(sealed) < gcm.NonceSize() {
		return "", false
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, []byte(HashSecret(predecessorRaw)))
	if err != nil || len(plain) == 0 {
		return "", false
	}
	return string(plain), true
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	return gcm, nil
}

// Errors returned by ValidateAccessToken.
var (
	ErrInvalidToken  = errors.New("mcpoauth: invalid access token")
	ErrWrongTokenUse = errors.New("mcpoauth: token is not an MCP access token")
)

// AccessTokenClaims are the claims carried by the access tokens this package
// issues.
//
// TokenUse is always TokenUseMCPAccess and validation rejects anything else.
// It is the second half of the cross-replay defence: the signing key is already
// derived away from Config.JWTSecret (see deriveSigningKey), and the claim
// keeps the two token families distinguishable even for an application that
// somehow signs both with one key. Applications should reject a token carrying
// token_use in their own session middleware for the mirror-image protection.
type AccessTokenClaims struct {
	Scope    string `json:"scope,omitempty"`
	TokenUse string `json:"token_use"`
	jwt.RegisteredClaims
}

// randomToken returns n cryptographically random bytes, base64url encoded
// without padding.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret returns the hex-encoded SHA-256 of a secret value. This is the
// only form in which authorization codes, refresh tokens and pending state are
// ever persisted.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// verifyPKCE reports whether verifier matches challenge under the S256 method,
// using a constant-time comparison.
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// PKCE code_challenge bounds from RFC 7636 §4.1 (the challenge shares the
// verifier's ABNF and length range).
const (
	minCodeChallengeLen = 43
	maxCodeChallengeLen = 128
)

// validateCodeChallenge enforces RFC 7636: 43..128 characters drawn from the
// unreserved set [A-Za-z0-9-._~]. An S256 challenge is always exactly 43
// characters, but the wider range is what the RFC specifies.
func validateCodeChallenge(challenge string) error {
	if n := len(challenge); n < minCodeChallengeLen || n > maxCodeChallengeLen {
		return fmt.Errorf("code_challenge must be %d-%d characters",
			minCodeChallengeLen, maxCodeChallengeLen)
	}
	for i := 0; i < len(challenge); i++ {
		c := challenge[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return errors.New("code_challenge contains an illegal character")
		}
	}
	return nil
}

// issueAccessToken mints a signed HS256 access token for userID.
func (p *Provider) issueAccessToken(userID string, now time.Time) (string, error) {
	claims := AccessTokenClaims{
		Scope:    GrantedScope,
		TokenUse: TokenUseMCPAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.cfg.Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{p.cfg.ResourceURL},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.cfg.AccessTokenTTL)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.signKey)
	if err != nil {
		return "", fmt.Errorf("signing access token: %w", err)
	}
	return tok, nil
}

// ValidateAccessToken verifies an access token issued by this Provider and
// returns the user ID it is bound to.
//
// It checks the HS256 signature, the issuer, the audience (the MCP resource
// URL), expiry, and that token_use == "mcp_access". Applications that also
// accept a legacy bearer-token scheme can chain this call: try the legacy
// lookup, then ValidateAccessToken (or the other way round).
func (p *Provider) ValidateAccessToken(tokenString string) (string, error) {
	var claims AccessTokenClaims
	_, err := jwt.ParseWithClaims(tokenString, &claims,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
			}
			return p.signKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(p.cfg.Issuer),
		jwt.WithAudience(p.cfg.ResourceURL),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.TokenUse != TokenUseMCPAccess {
		return "", ErrWrongTokenUse
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: empty subject", ErrInvalidToken)
	}
	return claims.Subject, nil
}
