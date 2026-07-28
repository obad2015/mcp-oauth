// Package ginmount mounts a github.com/obad2015/mcp-oauth Provider's routes
// on a Gin server.
//
// It is a separate module so that the main mcp-oauth module never takes a
// dependency on Gin: `go get github.com/obad2015/mcp-oauth` alone never
// pulls this package or Gin along with it. Only import ginmount if you are
// already using Gin.
package ginmount

import (
	"github.com/gin-gonic/gin"
	mcpoauth "github.com/obad2015/mcp-oauth"
)

// Mount registers every route p.Routes() reports on r, each for any HTTP
// method (r.Any registers GET/POST/PUT/PATCH/HEAD/OPTIONS/DELETE/CONNECT/
// TRACE on one handler) — the Handler behind every route already enforces
// its own method discipline (including CORS preflight and HEAD refusal
// where that matters), so this is the Gin equivalent of the Echo e.Any(...,
// echo.WrapHandler(h)) this package's production consumers hand-wrote per
// route.
//
// p.Routes() never returns two routes with the same path, so this can
// never panic on a duplicate registration.
func Mount(r gin.IRouter, p *mcpoauth.Provider) {
	for _, route := range p.Routes() {
		r.Any(route.Path, gin.WrapH(route.Handler))
	}
}
