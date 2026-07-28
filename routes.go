package mcpoauth

import (
	"net/http"
	"net/url"
)

// Route is one endpoint the provider must be reachable at.
type Route struct {
	// Path is the route path as the Go server sees it (i.e. after any
	// reverse-proxy prefix stripping has already happened), derived from
	// the URLs in Config and, for the discovery documents, from the RFC
	// 8615 well-known paths. It never includes a scheme or host.
	//
	// Routes() registers paths exactly as they appear in the configured
	// public URLs — correct as long as your reverse proxy preserves the
	// path (both known consumers of this package do). If yours strips a
	// prefix instead, rewrite Path on the returned Routes before mounting
	// them; that is the intended escape hatch, and it is one line.
	Path string

	// Methods lists the HTTP methods Handler accepts, for documentation and
	// for registrars that want to be method-specific. It is informational
	// only: every Handler in this package already enforces its own method
	// discipline (including CORS preflight OPTIONS handling and HEAD
	// refusal where that matters), so Mount and the framework adapters in
	// mount/echomount and mount/ginmount register Path for ANY method —
	// the same thing Echo's e.Any and Gin's r.Any already did by hand. A
	// registrar that filters by Methods instead must include every entry
	// or part of the Handler (e.g. its own OPTIONS preflight reply)
	// becomes unreachable.
	Methods []string

	// Handler serves Path. Mount it for every method (see Methods above).
	Handler http.Handler
}

// Routes derives every route this provider must be reachable at from
// Config: the authorize, token, register and Google-callback endpoints at
// the paths of their configured URLs, plus the RFC 8414 / RFC 9728
// discovery documents (including the path-inserted protected-resource
// variant RFC 9728 requires a compliant client to also probe).
//
// This is the one place that derivation happens. personal-finance once
// hand-derived the path-inserted route against the wrong URL and shipped a
// 404 for every spec-compliant client; computing it here from the same
// Config the rest of the provider already validated makes that mistake
// structurally impossible to repeat, and it is unit-tested in
// routes_test.go against both production configs that exist today.
//
// The returned slice never contains two Routes with the same Path — see
// the Path field doc for what to do if two of your configured URLs
// legitimately need to collide with a proxy's own routing instead.
func (p *Provider) Routes() []Route {
	metadataMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}

	routes := []Route{
		{
			Path:    urlPath(p.cfg.AuthorizeURL),
			Methods: []string{http.MethodGet, http.MethodPost},
			Handler: p.Authorize(),
		},
		{
			Path:    urlPath(p.cfg.TokenURL),
			Methods: []string{http.MethodPost, http.MethodOptions},
			Handler: p.Token(),
		},
		{
			Path:    urlPath(p.cfg.RegisterURL),
			Methods: []string{http.MethodPost, http.MethodOptions},
			Handler: p.Register(),
		},
		{
			Path:    urlPath(p.cfg.GoogleRedirectURL),
			Methods: []string{http.MethodGet},
			Handler: p.GoogleCallback(),
		},
		{
			Path:    AuthorizationServerMetadataPath,
			Methods: metadataMethods,
			Handler: p.AuthorizationServerMetadata(),
		},
		{
			Path:    OpenIDConfigurationPath,
			Methods: metadataMethods,
			Handler: p.AuthorizationServerMetadata(),
		},
		{
			Path:    ProtectedResourceMetadataPath,
			Methods: metadataMethods,
			Handler: p.ProtectedResourceMetadata(),
		},
	}

	// RFC 9728: a compliant client derives the metadata URL by inserting
	// the well-known segment between the host and the RESOURCE's own path,
	// not just by using the bare well-known root — e.g. for a ResourceURL
	// of ".../mcp" a client requests
	// /.well-known/oauth-protected-resource/mcp. Register that derived
	// route too, alongside (not instead of) the bare one above, whenever
	// it would actually differ from it.
	if suffix := protectedResourceMetadataSuffix(p.cfg.ResourceURL); suffix != "" {
		if derived := ProtectedResourceMetadataPath + suffix; derived != ProtectedResourceMetadataPath {
			routes = append(routes, Route{
				Path:    derived,
				Methods: metadataMethods,
				Handler: p.ProtectedResourceMetadata(),
			})
		}
	}

	return dedupeRoutes(routes)
}

// urlPath returns raw's path component. Config's own validation (see New)
// already requires every URL Routes derives a path from to be an absolute
// URL, so url.Parse cannot fail here in practice; the fallback below only
// matters if that invariant is ever violated.
func urlPath(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Path
	}
	return raw
}

// protectedResourceMetadataSuffix returns the RFC 9728 path-inserted suffix
// derived from resourceURL's own path component (e.g. "/mcp" or
// "/api/mcp"), or "" when resourceURL has no meaningful path (unparsable,
// empty, or root "/") — in which case only the bare well-known route
// applies.
func protectedResourceMetadataSuffix(resourceURL string) string {
	u, err := url.Parse(resourceURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	return u.Path
}

// dedupeRoutes drops every Route whose Path was already seen, keeping the
// first occurrence. Real configs never produce a collision (their URLs and
// the fixed well-known paths are all distinct), but this keeps a
// misconfiguration where two of them coincide from ever reaching a
// registrar as a duplicate registration — Echo, for one, panics on that.
func dedupeRoutes(routes []Route) []Route {
	seen := make(map[string]bool, len(routes))
	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		if seen[r.Path] {
			continue
		}
		seen[r.Path] = true
		out = append(out, r)
	}
	return out
}
