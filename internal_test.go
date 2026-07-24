package mcpoauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerifyPKCE(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{"matching verifier", "a-perfectly-fine-verifier", challengeFor("a-perfectly-fine-verifier"), true},
		{"wrong verifier", "not-the-verifier", challengeFor("a-perfectly-fine-verifier"), false},
		{"empty verifier", "", challengeFor("x"), false},
		{"empty challenge", "verifier", "", false},
		{"both empty", "", "", false},
		{"challenge is the raw verifier (plain style)", "verifier", "verifier", false},
		{"padded base64 challenge is rejected", "verifier", challengeFor("verifier") + "=", false},
		{"case flipped challenge", "verifier", flipCase(challengeFor("verifier")), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyPKCE(tc.verifier, tc.challenge); got != tc.want {
				t.Fatalf("verifyPKCE() = %v, want %v", got, tc.want)
			}
		})
	}
}

func flipCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - 32
		case c >= 'A' && c <= 'Z':
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestHashSecret(t *testing.T) {
	tests := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"same input hashes equal", "secret", "secret", true},
		{"different input hashes differ", "secret", "secret2", false},
		{"empty vs non-empty", "", "x", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ha, hb := HashSecret(tc.a), HashSecret(tc.b)
			if len(ha) != 64 {
				t.Fatalf("hash length = %d, want 64 hex chars", len(ha))
			}
			if ha == tc.a {
				t.Fatal("hash must not equal the raw secret")
			}
			if (ha == hb) != tc.equal {
				t.Fatalf("hash equality = %v, want %v", ha == hb, tc.equal)
			}
		})
	}
}

func TestCacheTTL(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"empty header falls back to 1h", "", time.Hour},
		{"plain max-age", "max-age=3600", time.Hour},
		{"max-age among directives", "public, max-age=1800, must-revalidate", 30 * time.Minute},
		{"spaces around value", "public,  max-age= 600 ", 10 * time.Minute},
		{"tiny max-age clamped up", "max-age=1", time.Minute},
		{"huge max-age clamped down", "max-age=999999999", 24 * time.Hour},
		{"zero max-age falls back", "max-age=0", time.Hour},
		{"garbage max-age falls back", "max-age=soon", time.Hour},
		{"no-store falls back", "no-store", time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheTTL(tc.header); got != tc.want {
				t.Fatalf("cacheTTL(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestRandomTokenIsUniqueAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		tok, err := randomToken(32)
		if err != nil {
			t.Fatalf("randomToken() error: %v", err)
		}
		if seen[tok] {
			t.Fatal("randomToken() produced a duplicate")
		}
		seen[tok] = true
		if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
			t.Fatalf("token is not raw base64url: %v", err)
		}
	}
}

func TestRSAPublicKeyFromJWK(t *testing.T) {
	tests := []struct {
		name    string
		n, e    string
		wantErr bool
	}{
		{"valid key", base64.RawURLEncoding.EncodeToString([]byte{0xC5, 0x01, 0x02}), "AQAB", false},
		{"empty modulus", "", "AQAB", true},
		{"empty exponent", base64.RawURLEncoding.EncodeToString([]byte{0x01}), "", true},
		{"bad base64 modulus", "!!!", "AQAB", true},
		{
			"oversized exponent",
			base64.RawURLEncoding.EncodeToString([]byte{0xC5, 0x01, 0x02}),
			base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}),
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rsaPublicKeyFromJWK(tc.n, tc.e)
			if (err != nil) != tc.wantErr {
				t.Fatalf("rsaPublicKeyFromJWK() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
