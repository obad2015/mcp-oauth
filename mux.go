package mcpoauth

import "net/http"

// Mount registers every Route from p.Routes() on mux. Each route is
// registered for its bare Path — matching any HTTP method — because every
// Handler already enforces its own method discipline (see Route.Methods);
// this mirrors exactly what Echo's e.Any and Gin's r.Any already did for
// this package's two production consumers.
//
// Routes() never returns two Routes with the same Path, so this can never
// panic on a duplicate registration.
func Mount(mux *http.ServeMux, p *Provider) {
	for _, route := range p.Routes() {
		mux.Handle(route.Path, route.Handler)
	}
}
