package mcpoauth

import "time"

// This file exposes a few internals to the package's own tests (including the
// external mcpoauth_test package compiled into the same test binary). Nothing
// here is part of the public API.

// DeriveSigningKeyForTest exposes the HKDF derivation of the access-token
// signing key so tests can mint tokens the validator will accept.
func DeriveSigningKeyForTest(secret []byte) []byte { return deriveSigningKey(secret) }

// ValidateCodeChallengeForTest exposes the RFC 7636 code_challenge check.
func ValidateCodeChallengeForTest(challenge string) error { return validateCodeChallenge(challenge) }

// MaxStaleJWKSForTest is the bound on serving a cached JWKS key after a failed
// refresh.
const MaxStaleJWKSForTest = maxStaleJWKS

// SetNowForTest overrides the provider's clock so expiry behaviour can be
// exercised without sleeping.
func (p *Provider) SetNowForTest(f func() time.Time) { p.now = f }
