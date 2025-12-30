package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// Server handles DNS queries with intercept/bypass logic
type Server struct {
	proxyIP      net.IP
	upstreamDNS  []string
	policyEngine *policy.Engine
	logger       zerolog.Logger

	// TTL settings
	interceptTTL uint32
	bypassTTLCap uint32
	blockTTL     uint32

	// DNS client for upstream queries
	client *dns.Client

	// Servers
	udpServer *dns.Server
	tcpServer *dns.Server

	// Optional pre-created listeners (for systemd socket activation)
	udpConn net.PacketConn
	tcpLn   net.Listener
}

// Config holds DNS server configuration
type Config struct {
	ListenAddr   string
	ProxyIP      string
	UpstreamDNS  []string
	InterceptTTL uint32
	BypassTTLCap uint32
	BlockTTL     uint32
	EnableTCP    bool
	EnableUDP    bool
	Timeout      time.Duration
}

// NewServer creates a new DNS server
func NewServer(config Config, policy *policy.Engine, logger zerolog.Logger) (*Server, error) {
	// ProxyIP is optional - if not set, we'll auto-detect from incoming connections
	var proxyIP net.IP
	if config.ProxyIP != "" {
		proxyIP = net.ParseIP(config.ProxyIP)
		if proxyIP == nil {
			return nil, fmt.Errorf("invalid proxy IP: %s", config.ProxyIP)
		}
	}

	s := &Server{
		proxyIP:      proxyIP,
		upstreamDNS:  config.UpstreamDNS,
		policyEngine: policy,
		logger:       logger.With().Str("component", "dns").Logger(),
		interceptTTL: config.InterceptTTL,
		bypassTTLCap: config.BypassTTLCap,
		blockTTL:     config.BlockTTL,
		client: &dns.Client{
			Timeout: config.Timeout,
		},
	}

	// Set up DNS handler
	dns.HandleFunc(".", s.handleDNSRequest)

	// Create servers
	if config.EnableUDP {
		s.udpServer = &dns.Server{
			Addr: config.ListenAddr,
			Net:  "udp",
		}
	}

	if config.EnableTCP {
		s.tcpServer = &dns.Server{
			Addr: config.ListenAddr,
			Net:  "tcp",
		}
	}

	return s, nil
}

// SetListeners sets pre-created listeners for systemd socket activation
func (s *Server) SetListeners(udpConn net.PacketConn, tcpLn net.Listener) {
	s.udpConn = udpConn
	s.tcpLn = tcpLn
}

// Start starts the DNS server
func (s *Server) Start() error {
	errChan := make(chan error, 2)

	if s.udpServer != nil {
		go func() {
			s.logger.Info().Str("addr", s.udpServer.Addr).Msg("Starting DNS server (UDP)")
			var err error
			if s.udpConn != nil {
				// Use systemd socket-activated connection
				s.logger.Debug().Msg("Using systemd socket-activated UDP connection")
				s.udpServer.PacketConn = s.udpConn
				err = s.udpServer.ActivateAndServe()
			} else {
				// Create and bind connection ourselves
				err = s.udpServer.ListenAndServe()
			}
			if err != nil {
				errChan <- fmt.Errorf("UDP server error: %w", err)
			}
		}()
	}

	if s.tcpServer != nil {
		go func() {
			s.logger.Info().Str("addr", s.tcpServer.Addr).Msg("Starting DNS server (TCP)")
			var err error
			if s.tcpLn != nil {
				// Use systemd socket-activated listener
				s.logger.Debug().Msg("Using systemd socket-activated TCP listener")
				s.tcpServer.Listener = s.tcpLn
				err = s.tcpServer.ActivateAndServe()
			} else {
				// Create and bind listener ourselves
				err = s.tcpServer.ListenAndServe()
			}
			if err != nil {
				errChan <- fmt.Errorf("TCP server error: %w", err)
			}
		}()
	}

	// Wait a bit to ensure servers started
	select {
	case err := <-errChan:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	var errs []error

	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("UDP shutdown error: %w", err))
		}
	}

	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("TCP shutdown error: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// handleDNSRequest handles incoming DNS requests
func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Get client IP for device identification
	clientIP := s.extractClientIP(w.RemoteAddr())

	// Process each question
	for _, question := range r.Question {
		domain := strings.TrimSuffix(question.Name, ".")
		qtype := question.Qtype

		s.logger.Debug().
			Str("client", clientIP.String()).
			Str("domain", domain).
			Str("type", dns.TypeToString[qtype]).
			Msg("DNS query received")

		// Determine action based on policy
		// Note: DNS queries don't include MAC address, but we could look it up from DHCP leases in the future
		action := s.policyEngine.GetDNSAction(clientIP, nil, domain)

		var logAction string
		var responseIP string
		var upstream string

		switch action {
		case policy.DNSActionIntercept:
			// Return proxy IP
			if answer := s.createInterceptResponse(&question, domain); answer != nil {
				msg.Answer = append(msg.Answer, answer)
				responseIP = s.getResponseIP(answer)
			}
			logAction = "INTERCEPT"

		case policy.DNSActionBypass:
			// Forward to upstream and return real response
			upstreamResp, upstreamAddr, err := s.forwardToUpstream(r)
			if err != nil {
				s.logger.Warn().Err(err).Str("domain", domain).Msg("Upstream DNS query failed, falling back to intercept")
				// On error, fall back to intercept
				if answer := s.createInterceptResponse(&question, domain); answer != nil {
					msg.Answer = append(msg.Answer, answer)
					responseIP = s.getResponseIP(answer)
				}
				logAction = "INTERCEPT_FALLBACK"
			} else {
				// Copy answers from upstream, potentially cap TTL
				for _, ans := range upstreamResp.Answer {
					if s.bypassTTLCap > 0 && ans.Header().Ttl > s.bypassTTLCap {
						ans.Header().Ttl = s.bypassTTLCap
					}
					msg.Answer = append(msg.Answer, ans)
				}
				if len(upstreamResp.Answer) > 0 {
					responseIP = s.getResponseIP(upstreamResp.Answer[0])
				}
				upstream = upstreamAddr
				logAction = "BYPASS"
			}

		case policy.DNSActionBlock:
			// Return 0.0.0.0 (sinkhole)
			if answer := s.createBlockResponse(&question, domain); answer != nil {
				msg.Answer = append(msg.Answer, answer)
				responseIP = "0.0.0.0"
			}
			logAction = "BLOCK"
		}

		// Log the DNS query to structured logger
		latency := time.Since(startTime).Milliseconds()
		s.logger.Info().
			Str("client_ip", clientIP.String()).
			Str("domain", domain).
			Str("query_type", dns.TypeToString[qtype]).
			Str("action", logAction).
			Str("response_ip", responseIP).
			Str("upstream", upstream).
			Int64("latency_ms", latency).
			Msg("DNS query processed")

		// Record metrics
		// Device identification now happens in OPA; use client IP for metrics
		deviceName := clientIP.String()

		metrics.DNSQueriesTotal.WithLabelValues(deviceName, logAction, dns.TypeToString[qtype]).Inc()
		metrics.DNSQueryDuration.WithLabelValues(logAction).Observe(time.Since(startTime).Seconds())
	}

	// Send response
	if err := w.WriteMsg(msg); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write DNS response")
	}
}

// createInterceptResponse creates a DNS response that returns the proxy IP
func (s *Server) createInterceptResponse(q *dns.Question, domain string) dns.RR {
	switch q.Qtype {
	case dns.TypeA:
		s.logger.Debug().
			Str("domain", domain).
			Str("proxy_ip", s.proxyIP.String()).
			Msg("Creating DNS intercept response")

		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    s.interceptTTL,
			},
			A: s.proxyIP.To4(),
		}
	case dns.TypeAAAA:
		// Return empty for IPv6 to force IPv4
		return nil
	default:
		return nil
	}
}

// createBlockResponse creates a DNS response that blocks the domain
func (s *Server) createBlockResponse(q *dns.Question, domain string) dns.RR {
	if q.Qtype == dns.TypeA {
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    s.blockTTL,
			},
			A: net.ParseIP("0.0.0.0").To4(),
		}
	}
	return nil
}

// forwardToUpstream forwards a DNS query to upstream DNS servers
func (s *Server) forwardToUpstream(r *dns.Msg) (*dns.Msg, string, error) {
	// Try each upstream DNS server
	for _, upstream := range s.upstreamDNS {
		resp, _, err := s.client.Exchange(r, upstream)
		if err == nil && resp != nil {
			return resp, upstream, nil
		}
		s.logger.Warn().
			Err(err).
			Str("upstream", upstream).
			Msg("Upstream DNS query failed, trying next")

		// Record upstream error
		metrics.DNSUpstreamErrors.WithLabelValues(upstream).Inc()
	}
	return nil, "", fmt.Errorf("all upstream DNS servers failed")
}

// extractClientIP extracts the client IP from the remote address
func (s *Server) extractClientIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}

// getResponseIP extracts the IP address from a DNS answer
func (s *Server) getResponseIP(answer dns.RR) string {
	if a, ok := answer.(*dns.A); ok {
		return a.A.String()
	}
	if aaaa, ok := answer.(*dns.AAAA); ok {
		return aaaa.AAAA.String()
	}
	return ""
}
