package mcpoauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// googleIssuers are the accepted "iss" values of a Google ID token.
var googleIssuers = map[string]bool{
	"accounts.google.com":         true,
	"https://accounts.google.com": true,
}

// googleIdentity is what we take away from the upstream login.
type googleIdentity struct {
	Email string
}

type googleIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}

// exchangeGoogleCode swaps an authorization code for an ID token and returns
// the verified identity behind it.
func (p *Provider) exchangeGoogleCode(ctx context.Context, code string) (googleIdentity, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {p.cfg.GoogleClientID},
		"client_secret": {p.cfg.GoogleClientSecret},
		"redirect_uri":  {p.cfg.GoogleRedirectURL},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.GoogleTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return googleIdentity{}, fmt.Errorf("building google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return googleIdentity{}, fmt.Errorf("calling google token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the body: we never want to buffer an unbounded upstream response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return googleIdentity{}, fmt.Errorf("reading google token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Deliberately does not include the body: it can echo the code.
		return googleIdentity{}, fmt.Errorf("google token endpoint returned status %d", resp.StatusCode)
	}

	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return googleIdentity{}, fmt.Errorf("decoding google token response: %w", err)
	}
	if tr.IDToken == "" {
		return googleIdentity{}, errors.New("google token response contained no id_token")
	}
	return p.verifyGoogleIDToken(ctx, tr.IDToken)
}

// verifyGoogleIDToken validates signature (via Google's JWKS), issuer,
// audience, expiry and email_verified.
func (p *Provider) verifyGoogleIDToken(ctx context.Context, idToken string) (googleIdentity, error) {
	var claims googleIDTokenClaims
	_, err := jwt.ParseWithClaims(idToken, &claims,
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return p.jwks.key(ctx, kid)
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithAudience(p.cfg.GoogleClientID),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(p.now),
	)
	if err != nil {
		return googleIdentity{}, fmt.Errorf("verifying google id_token: %w", err)
	}
	if !googleIssuers[claims.Issuer] {
		return googleIdentity{}, fmt.Errorf("unexpected google id_token issuer %q", claims.Issuer)
	}
	if !claims.EmailVerified {
		return googleIdentity{}, errors.New("google account email is not verified")
	}
	email := strings.TrimSpace(strings.ToLower(claims.Email))
	if email == "" {
		return googleIdentity{}, errors.New("google id_token contained no email")
	}
	return googleIdentity{Email: email}, nil
}

// --- JWKS ----------------------------------------------------------------

type jwksCache struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

func newJWKSCache(jwksURL string, client *http.Client, now func() time.Time) *jwksCache {
	return &jwksCache{url: jwksURL, client: client, now: now}
}

// key returns the RSA public key for kid, refreshing the cache when the key is
// unknown or the cached document has expired.
func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("id_token header has no kid")
	}

	c.mu.Lock()
	k, ok := c.keys[kid]
	fresh := c.now().Before(c.expiresAt)
	c.mu.Unlock()
	if ok && fresh {
		return k, nil
	}

	keys, ttl, err := c.fetch(ctx)
	if err != nil {
		// Fall back to a stale-but-known key rather than failing a login on a
		// transient JWKS outage.
		if ok {
			return k, nil
		}
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.expiresAt = c.now().Add(ttl)
	k, ok = c.keys[kid]
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no google signing key for kid %q", kid)
	}
	return k, nil
}

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building jwks request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("reading jwks: %w", err)
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("decoding jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue // skip unusable keys, keep the rest
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, 0, errors.New("jwks contained no usable RSA signing keys")
	}
	return keys, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL extracts max-age from a Cache-Control header, clamped to a sane
// range. Defaults to one hour.
func cacheTTL(cacheControl string) time.Duration {
	const (
		fallback = time.Hour
		minTTL   = time.Minute
		maxTTL   = 24 * time.Hour
	)
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		v, ok := strings.CutPrefix(part, "max-age=")
		if !ok {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || secs <= 0 {
			break
		}
		ttl := time.Duration(secs) * time.Second
		return min(max(ttl, minTTL), maxTTL)
	}
	return fallback
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decoding jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decoding jwk exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("malformed jwk rsa parameters")
	}
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 0 || e > 1<<31-1 {
		return nil, errors.New("jwk rsa exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}
