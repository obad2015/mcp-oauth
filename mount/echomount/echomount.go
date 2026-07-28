// Package echomount mounts a github.com/obad2015/mcp-oauth Provider's routes
// on an Echo v4 server.
//
// It is a separate module so that the main mcp-oauth module never takes a
// dependency on Echo: `go get github.com/obad2015/mcp-oauth` alone never
// pulls this package or Echo along with it. Only import echomount if you
// are already using Echo.
package echomount

import (
	"github.com/labstack/echo/v4"
	mcpoauth "github.com/obad2015/mcp-oauth"
)

// Mount registers every route p.Routes() reports on e, each for any HTTP
// method — the Handler behind every route already enforces its own method
// discipline (including CORS preflight and HEAD refusal where that
// matters), so this is exactly the e.Any(path, echo.WrapHandler(h)) both of
// this package's production consumers hand-wrote per route.
//
// p.Routes() never returns two routes with the same path, so this can
// never panic on a duplicate registration.
func Mount(e *echo.Echo, p *mcpoauth.Provider) {
	for _, route := range p.Routes() {
		e.Any(route.Path, echo.WrapHandler(route.Handler))
	}
}
