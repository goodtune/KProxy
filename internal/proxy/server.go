package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/rs/zerolog"
)

//go:embed assets/kproxy-logo.png
var logoData []byte
var logoETag string

func init() {
	// Calculate ETag from logo data
	hash := sha256.Sum256(logoData)
	logoETag = hex.EncodeToString(hash[:])
}

// Server is the main proxy server
type Server struct {
	httpServer   *http.Server
	httpsServer  *http.Server
	policyEngine *policy.Engine
	ca           *ca.CA
	logger       zerolog.Logger
	adminDomain  string
	serverName   string // Server name for client setup (e.g., "local.kproxy")
	httpsPort    int    // HTTPS port for redirect

	// Let's Encrypt certificate for server.name (optional)
	letsEncryptCert *tls.Certificate

	// Optional pre-created listeners (for systemd socket activation)
	httpListener  net.Listener
	httpsListener net.Listener
}

// Config holds proxy server configuration
type Config struct {
	HTTPAddr    string
	HTTPSAddr   string
	AdminDomain string
	ServerName  string // Server name for client setup
	HTTPSPort   int    // HTTPS port for redirect
}

// NewServer creates a new proxy server
func NewServer(
	config Config,
	policyEngine *policy.Engine,
	ca *ca.CA,
	logger zerolog.Logger,
) *Server {
	s := &Server{
		policyEngine: policyEngine,
		ca:           ca,
		logger:       logger.With().Str("component", "proxy").Logger(),
		adminDomain:  config.AdminDomain,
		serverName:   config.ServerName,
		httpsPort:    config.HTTPSPort,
	}

	// HTTP server
	s.httpServer = &http.Server{
		Addr:         config.HTTPAddr,
		Handler:      http.HandlerFunc(s.handleHTTP),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// HTTPS server with TLS
	s.httpsServer = &http.Server{
		Addr:         config.HTTPSAddr,
		Handler:      http.HandlerFunc(s.handleHTTPS),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: s.getCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	return s
}

// SetLetsEncryptCert sets the Let's Encrypt certificate for server.name
func (s *Server) SetLetsEncryptCert(cert *tls.Certificate) {
	s.letsEncryptCert = cert
	s.logger.Info().
		Str("server_name", s.serverName).
		Msg("Let's Encrypt certificate configured for server name")
}

// getCertificate returns the appropriate certificate based on SNI hostname
func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// If we have a Let's Encrypt cert and the SNI matches server.name, use it
	if s.letsEncryptCert != nil && s.matchesServerName(hello.ServerName) {
		s.logger.Debug().
			Str("sni", hello.ServerName).
			Str("server_name", s.serverName).
			Msg("Serving Let's Encrypt certificate for server name")
		return s.letsEncryptCert, nil
	}

	// Otherwise, generate/retrieve certificate from CA
	return s.ca.GetCertificate(hello)
}

// SetListeners sets pre-created listeners for systemd socket activation
func (s *Server) SetListeners(httpLn, httpsLn net.Listener) {
	s.httpListener = httpLn
	s.httpsListener = httpsLn
}

// Start starts the proxy servers
func (s *Server) Start() error {
	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		s.logger.Info().Str("addr", s.httpServer.Addr).Msg("Starting HTTP proxy server")
		var err error
		if s.httpListener != nil {
			// Use systemd socket-activated listener
			s.logger.Debug().Msg("Using systemd socket-activated HTTP listener")
			err = s.httpServer.Serve(s.httpListener)
		} else {
			// Create and bind listener ourselves
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server
	go func() {
		s.logger.Info().Str("addr", s.httpsServer.Addr).Msg("Starting HTTPS proxy server")
		var err error
		if s.httpsListener != nil {
			// Use systemd socket-activated listener
			s.logger.Debug().Msg("Using systemd socket-activated HTTPS listener")
			// For TLS with pre-created listener, we need to wrap it with TLS
			tlsListener := tls.NewListener(s.httpsListener, s.httpsServer.TLSConfig)
			err = s.httpsServer.Serve(tlsListener)
		} else {
			// Create and bind listener ourselves
			err = s.httpsServer.ListenAndServeTLS("", "")
		}
		if err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	// Wait a bit to ensure servers started
	select {
	case err := <-errChan:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// Stop stops the proxy servers
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping proxy servers")

	// Give servers 5 seconds to shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var errs []error

	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("HTTP server shutdown error: %w", err))
	}

	if err := s.httpsServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("HTTPS server shutdown error: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// serveLogo serves the embedded KProxy logo with caching headers
func (s *Server) serveLogo(w http.ResponseWriter, r *http.Request) {
	// Check ETag
	if match := r.Header.Get("If-None-Match"); match == logoETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set cache headers
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400") // 1 day
	w.Header().Set("ETag", logoETag)
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(logoData); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write logo")
	}
}

// handleHTTP handles HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Serve embedded assets
	if r.URL.Path == "/.kproxy/logo.png" {
		s.serveLogo(w, r)
		return
	}

	// Check if this is a request to server.name - redirect to HTTPS
	host := r.Host
	if strings.HasSuffix(host, fmt.Sprintf(":%d", 80)) {
		host = strings.TrimSuffix(host, fmt.Sprintf(":%d", 80))
	}

	if s.matchesServerName(host) {
		// Redirect to HTTPS
		httpsURL := fmt.Sprintf("https://%s", s.serverName)
		if s.httpsPort != 443 {
			httpsURL = fmt.Sprintf("https://%s:%d", s.serverName, s.httpsPort)
		}
		httpsURL += r.URL.Path
		if r.URL.RawQuery != "" {
			httpsURL += "?" + r.URL.RawQuery
		}

		s.logger.Debug().
			Str("from", r.Host).
			Str("to", httpsURL).
			Msg("Redirecting HTTP to HTTPS for server name")

		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		return
	}

	// Extract client info
	clientIP := s.extractClientIP(r)

	// Build policy request
	policyReq := &policy.ProxyRequest{
		ClientIP:  clientIP,
		Host:      r.Host,
		Path:      r.URL.Path,
		Method:    r.Method,
		UserAgent: r.UserAgent(),
		Encrypted: false,
	}

	// Evaluate policy
	decision := s.policyEngine.Evaluate(policyReq)

	// Log request and record metrics
	defer func() {
		duration := time.Since(startTime).Milliseconds()
		s.logRequest(policyReq, decision, http.StatusOK, 0, duration)

		// Record metrics
		// Device identification now happens in OPA; use client IP for metrics
		deviceName := clientIP.String()

		metrics.RequestsTotal.WithLabelValues(deviceName, policyReq.Host, string(decision.Action), policyReq.Method).Inc()
		metrics.RequestDuration.WithLabelValues(deviceName, string(decision.Action)).Observe(time.Since(startTime).Seconds())

		if decision.Action == policy.ActionBlock {
			metrics.BlockedRequests.WithLabelValues(deviceName, decision.Reason).Inc()
		}
	}()

	// Handle based on decision
	switch decision.Action {
	case policy.ActionBlock:
		s.handleBlock(w, r, decision)
		return

	case policy.ActionAllow:
		s.handleProxy(w, r, false)
		return

	default:
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}

// handleHTTPS handles HTTPS requests (after TLS termination)
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Serve embedded assets
	if r.URL.Path == "/.kproxy/logo.png" {
		s.serveLogo(w, r)
		return
	}

	// Check if this is a request to server.name for client setup
	host := r.Host
	if strings.HasSuffix(host, fmt.Sprintf(":%d", s.httpsPort)) {
		host = strings.TrimSuffix(host, fmt.Sprintf(":%d", s.httpsPort))
	}

	if s.matchesServerName(host) {
		// Serve client setup routes
		s.handleClientSetup(w, r)
		return
	}

	// Extract client info
	clientIP := s.extractClientIP(r)

	// Build policy request
	policyReq := &policy.ProxyRequest{
		ClientIP:  clientIP,
		Host:      r.Host,
		Path:      r.URL.Path,
		Method:    r.Method,
		UserAgent: r.UserAgent(),
		Encrypted: true,
	}

	// Evaluate policy
	decision := s.policyEngine.Evaluate(policyReq)

	// Log request and record metrics
	defer func() {
		duration := time.Since(startTime).Milliseconds()
		s.logRequest(policyReq, decision, http.StatusOK, 0, duration)

		// Record metrics
		// Device identification now happens in OPA; use client IP for metrics
		deviceName := clientIP.String()

		metrics.RequestsTotal.WithLabelValues(deviceName, policyReq.Host, string(decision.Action), policyReq.Method).Inc()
		metrics.RequestDuration.WithLabelValues(deviceName, string(decision.Action)).Observe(time.Since(startTime).Seconds())

		if decision.Action == policy.ActionBlock {
			metrics.BlockedRequests.WithLabelValues(deviceName, decision.Reason).Inc()
		}
	}()

	// Handle based on decision
	switch decision.Action {
	case policy.ActionBlock:
		s.handleBlock(w, r, decision)
		return

	case policy.ActionAllow:
		s.handleProxy(w, r, true)
		return

	default:
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}

// handleProxy proxies the request to the upstream server
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request, isHTTPS bool) {
	// Build upstream URL
	scheme := "http"
	if isHTTPS {
		scheme = "https"
	}

	// Create upstream request
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)
	upstreamReq, err := http.NewRequest(r.Method, upstreamURL, r.Body)
	if err != nil {
		s.logger.Error().Err(err).Str("url", upstreamURL).Msg("Failed to create upstream request")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(upstreamReq.Header)

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Send request
	resp, err := client.Do(upstreamReq)
	if err != nil {
		s.logger.Error().Err(err).Str("url", upstreamURL).Msg("Upstream request failed")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(w.Header())

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logger.Error().Err(err).Msg("Failed to copy response body")
	}
}

// handleBlock handles blocked requests
func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request, decision *policy.PolicyDecision) {
	// Get device info
	clientIP := s.extractClientIP(r)
	// Device identification now happens in OPA; use client IP for display
	deviceName := clientIP.String()

	// Render block page with branding
	blockHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Access Blocked - KProxy</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.container {
			background: white;
			border-radius: 16px;
			padding: 40px;
			max-width: 500px;
			text-align: center;
			box-shadow: 0 20px 60px rgba(0,0,0,0.3);
		}
		.logo {
			max-width: 200px;
			height: auto;
			margin-bottom: 20px;
		}
		.icon { font-size: 64px; margin-bottom: 20px; }
		h1 { color: #333; margin-bottom: 16px; }
		p { color: #666; line-height: 1.6; margin-bottom: 24px; }
		.reason {
			background: #f5f5f5;
			padding: 16px;
			border-radius: 8px;
			font-family: monospace;
			color: #c00;
			word-break: break-all;
		}
		.info { font-size: 14px; color: #999; margin-top: 24px; }
		.powered-by {
			font-size: 12px;
			color: #999;
			margin-top: 20px;
			opacity: 0.7;
		}
	</style>
</head>
<body>
	<div class="container">
		<img src="/.kproxy/logo.png" alt="KProxy" class="logo">
		<div class="icon">🚫</div>
		<h1>Access Blocked</h1>
		<p>This website has been blocked by your network filter.</p>
		<div class="reason">%s</div>
		<p class="info">
			If you believe this is a mistake, please talk to your administrator.<br>
			Blocked at: %s<br>
			Device: %s<br>
			URL: %s
		</p>
		<div class="powered-by">Powered by KProxy</div>
	</div>
</body>
</html>`, decision.Reason, time.Now().Format("2006-01-02 15:04:05"), deviceName, r.Host+r.URL.Path)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write([]byte(blockHTML)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write block page")
	}
}

// extractClientIP extracts the client IP from the request
func (s *Server) extractClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := net.ParseIP(strings.TrimSpace(ips[0]))
			if ip != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		ip := net.ParseIP(xri)
		if ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// logRequest logs a proxied request to structured logger
func (s *Server) logRequest(req *policy.ProxyRequest, decision *policy.PolicyDecision, statusCode int, responseSize int64, durationMS int64) {
	// Log to structured logger
	logEvent := s.logger.Info().
		Str("client_ip", req.ClientIP.String())

	if req.ClientMAC != nil {
		logEvent = logEvent.Str("client_mac", req.ClientMAC.String())
	}

	logEvent.
		Str("method", req.Method).
		Str("host", req.Host).
		Str("path", req.Path).
		Str("user_agent", req.UserAgent).
		Int("status_code", statusCode).
		Int64("response_size", responseSize).
		Int64("duration_ms", durationMS).
		Str("action", string(decision.Action)).
		Str("matched_rule", decision.MatchedRuleID).
		Str("reason", decision.Reason).
		Str("category", decision.Category).
		Bool("encrypted", req.Encrypted).
		Msg("Proxy request processed")
}

// removeHopByHopHeaders removes hop-by-hop headers
func removeHopByHopHeaders(h http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// matchesServerName checks if the host matches the server name
func (s *Server) matchesServerName(host string) bool {
	// Strip port if present
	if colonPos := strings.LastIndex(host, ":"); colonPos != -1 {
		host = host[:colonPos]
	}
	return strings.EqualFold(host, s.serverName)
}

// handleClientSetup handles client setup routes for server.name
func (s *Server) handleClientSetup(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug().
		Str("path", r.URL.Path).
		Msg("Serving client setup route")

	switch r.URL.Path {
	case "/ca.crt", "/setup/ca.crt":
		s.serveRootCertificate(w, r)
	case "/", "/setup", "/setup/":
		s.serveSetupPage(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveRootCertificate serves the root CA certificate for installation
func (s *Server) serveRootCertificate(w http.ResponseWriter, r *http.Request) {
	// Get root certificate from CA
	certPEM, err := s.ca.GetRootCertPEM()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get root certificate")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set headers for certificate download
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=kproxy-root-ca.crt")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(certPEM); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write certificate")
	}

	s.logger.Info().
		Str("client", s.extractClientIP(r).String()).
		Msg("Root certificate downloaded")
}

// serveSetupPage serves the client setup page
func (s *Server) serveSetupPage(w http.ResponseWriter, r *http.Request) {
	setupHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>KProxy Client Setup</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.container {
			background: white;
			border-radius: 16px;
			padding: 40px;
			max-width: 600px;
			box-shadow: 0 20px 60px rgba(0,0,0,0.3);
		}
		.logo { font-size: 48px; text-align: center; margin-bottom: 20px; }
		h1 { color: #333; margin-bottom: 16px; text-align: center; }
		p { color: #666; line-height: 1.6; margin-bottom: 24px; }
		.steps {
			background: #f8f9fa;
			padding: 20px;
			border-radius: 8px;
			margin-bottom: 24px;
		}
		.step {
			margin-bottom: 16px;
			padding-left: 24px;
			position: relative;
		}
		.step:before {
			content: "→";
			position: absolute;
			left: 0;
			color: #667eea;
			font-weight: bold;
		}
		.download-btn {
			display: block;
			width: 100%%;
			padding: 16px;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			color: white;
			text-align: center;
			text-decoration: none;
			border-radius: 8px;
			font-weight: bold;
			font-size: 16px;
			transition: transform 0.2s;
		}
		.download-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 12px rgba(0,0,0,0.2);
		}
		.info { font-size: 14px; color: #999; margin-top: 24px; text-align: center; }
	</style>
</head>
<body>
	<div class="container">
		<div class="logo">🔒</div>
		<h1>KProxy Client Setup</h1>
		<p>Welcome to KProxy! To use this proxy with HTTPS interception, you need to install the root certificate on your device.</p>

		<div class="steps">
			<div class="step">Download the root certificate below</div>
			<div class="step">Install it as a trusted root certificate on your device</div>
			<div class="step">Configure your device to use this proxy for DNS/HTTP/HTTPS</div>
		</div>

		<a href="/ca.crt" class="download-btn" download="kproxy-root-ca.crt">
			Download Root Certificate
		</a>

		<p class="info">
			Server: %s<br>
			Need help? Check the KProxy documentation for installation instructions.
		</p>
	</div>
</body>
</html>`, s.serverName)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(setupHTML)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write setup page")
	}
}
