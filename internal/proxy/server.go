package proxy

import (
	"context"
	"crypto/tls"
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

// Server is the main proxy server
type Server struct {
	httpServer   *http.Server
	httpsServer  *http.Server
	policyEngine *policy.Engine
	ca           *ca.CA
	logger       zerolog.Logger
	adminDomain  string
}

// Config holds proxy server configuration
type Config struct {
	HTTPAddr    string
	HTTPSAddr   string
	AdminDomain string
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
			GetCertificate: ca.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	return s
}

// Start starts the proxy servers
func (s *Server) Start() error {
	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		s.logger.Info().Str("addr", s.httpServer.Addr).Msg("Starting HTTP proxy server")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server
	go func() {
		s.logger.Info().Str("addr", s.httpsServer.Addr).Msg("Starting HTTPS proxy server")
		if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
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

// handleHTTP handles HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

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

	// Render block page
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
	</style>
</head>
<body>
	<div class="container">
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
