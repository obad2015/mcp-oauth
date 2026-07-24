package mcpoauth

import (
	"html/template"
	"net/http"
)

// defaultConsentTemplate is the built-in approval page.
//
// It is deliberately self-contained: no external stylesheet, font, script or
// image, so it renders identically under any Content-Security-Policy. Every
// interpolated value goes through html/template's contextual escaping —
// .ClientName and .RedirectURI are attacker-controlled (anyone can register a
// client), so they are rendered as inert text, never as a link.
var defaultConsentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.5;
 margin:0;padding:1.5rem 1rem;display:flex;justify-content:center}
main{width:100%;max-width:32rem}
h1{font-size:1.25rem;margin:0 0 1rem}
dl{margin:1.25rem 0;padding:0}
dt{font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;opacity:.7;margin-top:.9rem}
dd{margin:.2rem 0 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
 font-size:.9rem;word-break:break-all}
.warn{border-left:3px solid #d97706;padding:.6rem .8rem;margin:1.25rem 0;font-size:.9rem}
button{width:100%;min-height:44px;font-size:1rem;font-weight:600;border:0;border-radius:.5rem;
 padding:.7rem 1rem;background:#2563eb;color:#fff;cursor:pointer}
button:hover{background:#1d4ed8}
p.deny{font-size:.85rem;opacity:.75;margin-top:1rem;text-align:center}
</style></head>
<body><main>
<h1>Authorize access to your account</h1>
<p><strong>{{.ClientName}}</strong> is asking to connect to your account.</p>
<dl>
  <dt>Application</dt><dd>{{.ClientName}}</dd>
  <dt>Will receive the authorization code at</dt><dd>{{.RedirectURI}}</dd>
  <dt>Scopes</dt><dd>{{range $i, $s := .Scopes}}{{if $i}} {{end}}{{$s}}{{end}}</dd>
</dl>
<p class="warn">Check the address above. If you did not just start this
connection yourself — or you do not recognise it — close this page. Approving
gives whoever controls that address access to your data.</p>
<form method="post" action="{{.FormAction}}">
  <input type="hidden" name="{{.NonceField}}" value="{{.Nonce}}">
  <button type="submit">Approve</button>
</form>
<p class="deny">To deny, just close this page.</p>
</main></body></html>`))

// consentPageData is the template model for the built-in page.
type consentPageData struct {
	ClientName  string
	RedirectURI string
	Scopes      []string
	FormAction  string
	NonceField  string
	Nonce       string
}

// renderConsent writes the approval page, delegating to Config.ConsentHandler
// when the application supplied one.
func (p *Provider) renderConsent(w http.ResponseWriter, r *http.Request, c Client, req ConsentRequest) {
	w.Header().Set("Cache-Control", "no-store")
	if p.cfg.ConsentHandler != nil {
		p.cfg.ConsentHandler(w, r, c, req)
		return
	}

	name := c.ClientName
	if name == "" {
		name = "An unnamed application"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Belt and braces: the page has no external references, so this CSP can be
	// maximally strict.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	_ = defaultConsentTemplate.Execute(w, consentPageData{
		ClientName:  name,
		RedirectURI: req.RedirectURI,
		Scopes:      req.Scopes,
		FormAction:  req.FormAction,
		NonceField:  req.NonceField,
		Nonce:       req.Nonce,
	})
}
