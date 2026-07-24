package mcpoauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpoauth "github.com/obad2015/mcp-oauth"
	"github.com/obad2015/mcp-oauth/memstore"
)

// devLoopback is the only shape of config InsecureDevMode is allowed with:
// plain http on a loopback host.
func devLoopback(c *mcpoauth.Config) {
	const base = "http://127.0.0.1:8080"
	c.InsecureDevMode = true
	c.Issuer = base
	c.ResourceURL = base + "/api/mcp"
	c.MetadataBaseURL = base + "/api"
	c.GoogleRedirectURL = base + "/api/mcp/oauth/google/callback"
	c.AuthorizeURL = base + "/api/mcp/oauth/authorize"
	c.TokenURL = base + "/api/mcp/oauth/token"
	c.RegisterURL = base + "/api/mcp/oauth/register"
}

const (
	testIssuer      = "https://app.example.com"
	testResourceURL = "https://app.example.com/api/mcp"
	testGoogleCID   = "google-client-id.apps.googleusercontent.com"
	testEmail       = "user@example.com"
	testUserID      = "11111111-2222-3333-4444-555555555555"
	testRedirectURI = "http://127.0.0.1:51234/callback"
)

var testSecret = []byte("test-signing-secret-please-rotate")

// --- fake Google ---------------------------------------------------------

// fakeGoogle stands in for accounts.google.com: it serves a token endpoint and
// a JWKS document, signing ID tokens with a throwaway RSA key.
type fakeGoogle struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	// emails maps an upstream authorization code to the email it resolves to.
	emails map[string]string

	emailVerified bool
	tokenStatus   int
	certsStatus   int
	audience      string
	issuer        string
	expiresIn     time.Duration
	jwksCalls     int
}

// testKeyOnce keeps the (expensive) RSA keygen to once per test binary.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyErr  error
)

func googleSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() { testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if testKeyErr != nil {
		t.Fatalf("generating rsa key: %v", testKeyErr)
	}
	return testKey
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	g := &fakeGoogle{
		key:           googleSigningKey(t),
		kid:           "test-kid-1",
		emails:        map[string]string{},
		emailVerified: true,
		tokenStatus:   http.StatusOK,
		certsStatus:   http.StatusOK,
		audience:      testGoogleCID,
		issuer:        "https://accounts.google.com",
		expiresIn:     time.Hour,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", g.handleToken)
	mux.HandleFunc("/certs", g.handleCerts)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGoogle) tokenURL() string { return g.srv.URL + "/token" }
func (g *fakeGoogle) jwksURL() string  { return g.srv.URL + "/certs" }

// grant registers an upstream code that resolves to email.
func (g *fakeGoogle) grant(code, email string) {
	g.emails[code] = email
}

func (g *fakeGoogle) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if g.tokenStatus != http.StatusOK {
		w.WriteHeader(g.tokenStatus)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	email, ok := g.emails[r.PostFormValue("code")]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            g.issuer,
		"aud":            g.audience,
		"sub":            "google-subject-1",
		"email":          email,
		"email_verified": g.emailVerified,
		"iat":            now.Unix(),
		"exp":            now.Add(g.expiresIn).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = g.kid
	signed, err := tok.SignedString(g.key)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "upstream-access-token",
		"id_token":     signed,
		"token_type":   "Bearer",
	})
}

func (g *fakeGoogle) handleCerts(w http.ResponseWriter, _ *http.Request) {
	g.jwksCalls++
	if g.certsStatus != http.StatusOK {
		w.WriteHeader(g.certsStatus)
		return
	}
	pub := g.key.Public().(*rsa.PublicKey)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]string{{
			"kid": g.kid,
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// --- harness -------------------------------------------------------------

type harness struct {
	t      *testing.T
	p      *mcpoauth.Provider
	cfg    mcpoauth.Config
	store  *memstore.MemoryStore
	google *fakeGoogle

	// binder is the browser-binding cookie handed out by the last authorize
	// GET, replayed by callback() the way a real browser would.
	binder *http.Cookie

	// clock backs advance(); it starts at the real time.
	clock time.Time
}

// advance moves the provider's clock forward and leaves it there.
func (h *harness) advance(d time.Duration) {
	h.clock = h.clock.Add(d)
	at := h.clock
	h.p.SetNowForTest(func() time.Time { return at })
}

// signingKey is the key access tokens are actually signed with: the configured
// secret is never used directly (HKDF key separation).
func signingKey() []byte { return mcpoauth.DeriveSigningKeyForTest(testSecret) }

func newHarness(t *testing.T, tweak ...func(*mcpoauth.Config)) *harness {
	t.Helper()
	g := newFakeGoogle(t)
	store := memstore.NewMemoryStore()
	store.AddUser(testEmail, testUserID)

	cfg := mcpoauth.Config{
		Issuer:             testIssuer,
		ResourceURL:        testResourceURL,
		MetadataBaseURL:    testIssuer + "/api",
		GoogleClientID:     testGoogleCID,
		GoogleClientSecret: "google-client-secret",
		GoogleRedirectURL:  testIssuer + "/api/mcp/oauth/google/callback",
		AuthorizeURL:       testIssuer + "/api/mcp/oauth/authorize",
		TokenURL:           testIssuer + "/api/mcp/oauth/token",
		RegisterURL:        testIssuer + "/api/mcp/oauth/register",
		JWTSecret:          testSecret,
		GoogleAuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		GoogleTokenURL:     g.tokenURL(),
		GoogleJWKSURL:      g.jwksURL(),
	}
	for _, f := range tweak {
		f(&cfg)
	}

	p, err := mcpoauth.New(cfg, store)
	if err != nil {
		t.Fatalf("mcpoauth.New() error: %v", err)
	}
	return &harness{t: t, p: p, cfg: cfg, store: store, google: g, clock: time.Now()}
}

// restart replaces the Provider with a brand new one over the SAME store, the
// way a redeploy or `systemctl restart` would. Anything the old provider was
// holding in process memory is gone.
func (h *harness) restart() {
	h.t.Helper()
	p, err := mcpoauth.New(h.cfg, h.store)
	if err != nil {
		h.t.Fatalf("restarting provider: %v", err)
	}
	at := h.clock
	p.SetNowForTest(func() time.Time { return at })
	h.p = p
}

// register runs dynamic client registration and returns the client_id.
func (h *harness) register(redirectURIs ...string) string {
	h.t.Helper()
	return h.registerNamed("Test MCP Client", redirectURIs...)
}

// registerNamed is register with an explicit (possibly hostile) client_name.
func (h *harness) registerNamed(name string, redirectURIs ...string) string {
	h.t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": redirectURIs,
		"client_name":   name,
	})
	rec := httptest.NewRecorder()
	h.p.Register()(rec, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body))))
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("register: decoding response: %v", err)
	}
	return resp.ClientID
}

// authorizeGET performs only the first leg: the interstitial consent page.
//
// It behaves like a browser cookie jar: whatever binder cookie the harness
// currently holds is sent along, and whatever comes back replaces it. That
// matters because one cookie carries the binders of several concurrent flows.
func (h *harness) authorizeGET(params url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	if h.binder != nil {
		req.AddCookie(h.binder)
	}
	rec := httptest.NewRecorder()
	h.p.Authorize()(rec, req)
	if c := binderCookie(rec); c != nil {
		h.binder = c
	}
	return rec
}

// approve posts the consent form back, optionally with a different cookie than
// the one the consent page set (nil = send none).
func (h *harness) approve(nonce string, cookie *http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	req := postForm("/authorize", url.Values{consentNonceField: {nonce}})
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.p.Authorize()(rec, req)
	return rec
}

// authorize runs the whole authorization leg the way a browser does — GET the
// consent page, POST the approval — and returns the final recorder plus the
// opaque state handed to Google (empty when the request was rejected).
func (h *harness) authorize(params url.Values) (*httptest.ResponseRecorder, string) {
	h.t.Helper()
	get := h.authorizeGET(params)
	if get.Code != http.StatusOK {
		return get, ""
	}
	nonce := consentNonce(h.t, get.Body.String())
	rec := h.approve(nonce, h.binder)
	if rec.Code != http.StatusFound {
		return rec, ""
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		h.t.Fatalf("authorize: bad Location header: %v", err)
	}
	return rec, loc.Query().Get("state")
}

// otherFlowNonce starts a second, unrelated authorization flow and returns its
// consent nonce, leaving the harness's own binder cookie untouched.
func (h *harness) otherFlowNonce(t *testing.T) string {
	t.Helper()
	saved := h.binder
	defer func() { h.binder = saved }()
	get := h.authorizeGET(authorizeParams(h.register(testRedirectURI), testRedirectURI))
	return consentNonce(t, get.Body.String())
}

// callback runs the Google callback for an upstream code + our state, carrying
// the binder cookie the same browser would.
func (h *harness) callback(state, googleCode string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.callbackWithCookie(state, googleCode, h.binder)
}

// callbackWithCookie is callback() with an explicit binding cookie (nil sends
// none), which is how the cross-browser hijack is simulated.
func (h *harness) callbackWithCookie(state, googleCode string, cookie *http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	q := url.Values{"state": {state}, "code": {googleCode}}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.p.GoogleCallback()(rec, req)
	return rec
}

// consentNonceField mirrors mcpoauth.ConsentNonceField for brevity in tests.
const consentNonceField = mcpoauth.ConsentNonceField

// binderCookie extracts the browser-binding cookie from a response, if set.
func binderCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == mcpoauth.BinderCookieName || c.Name == mcpoauth.BinderCookieNameInsecure {
			if c.Value == "" {
				return nil // a clearing cookie
			}
			return c
		}
	}
	return nil
}

var consentNonceRE = regexp.MustCompile(
	`name="` + regexp.QuoteMeta(mcpoauth.ConsentNonceField) + `" value="([^"]+)"`)

// consentNonce scrapes the single-use nonce out of the default consent page.
func consentNonce(t *testing.T, page string) string {
	t.Helper()
	m := consentNonceRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no consent nonce in page:\n%s", page)
	}
	return m[1]
}

// token posts to the token endpoint.
func (h *harness) token(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.p.Token()(rec, req)
	return rec
}

// login runs register -> authorize -> google callback and returns the client
// id, the authorization code and the PKCE verifier.
func (h *harness) login(email string) (clientID, code, verifier string) {
	h.t.Helper()
	clientID = h.register(testRedirectURI)
	verifier = "verifier-" + email

	_, state := h.authorize(url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state-xyz"},
	})
	if state == "" {
		h.t.Fatal("login: authorize did not redirect to google")
	}

	h.google.grant("google-code-1", email)
	rec := h.callback(state, "google-code-1")
	if rec.Code != http.StatusFound {
		h.t.Fatalf("login: callback status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		h.t.Fatalf("login: bad Location header: %v", err)
	}
	return clientID, loc.Query().Get("code"), verifier
}

func newRec() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func newStore() *memstore.MemoryStore { return memstore.NewMemoryStore() }

func formValues(kv map[string]string) url.Values {
	form := url.Values{}
	for k, v := range kv {
		form.Set(k, v)
	}
	return form
}

func postForm(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding response %q: %v", rec.Body.String(), err)
	}
	return out
}

type tokenSuccess struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}
