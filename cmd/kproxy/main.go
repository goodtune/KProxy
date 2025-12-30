package main

// @title KProxy Admin API
// @version 1.0
// @description KProxy is a transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls.
// @description It combines DNS-level routing decisions with proxy-level policy enforcement, dynamic TLS certificate generation, and usage tracking.

// @contact.name KProxy Support
// @contact.url https://github.com/goodtune/kproxy

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8443
// @BasePath /api

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the JWT token

func main() {
	Execute()
}
