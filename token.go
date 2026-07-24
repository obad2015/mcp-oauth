package mcpoauth

import (
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

// Errors returned by ValidateAccessToken.
var (
	ErrInvalidToken  = errors.New("mcpoauth: invalid access token")
	ErrWrongTokenUse = errors.New("mcpoauth: token is not an MCP access token")
)

// AccessTokenClaims are the claims carried by the access tokens this package
// issues.
//
// TokenUse is the security-critical one: it is always TokenUseMCPAccess and
// validation rejects anything else. Applications typically sign their ordinary
// web-session JWTs with the same secret; without this claim such a session
// token would be replayable against the MCP endpoint, and an MCP token would be
// accepted by the web app.
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
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.cfg.JWTSecret)
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
			return p.cfg.JWTSecret, nil
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
