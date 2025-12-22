package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/goodtune/kproxy/internal/database"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// Server handles DNS queries with intercept/bypass logic
type Server struct {
	proxyIP        net.IP
	upstreamDNS    []string
	policyEngine   *policy.Engine
	logger         zerolog.Logger
	db             *database.DB

	// TTL settings
	interceptTTL   uint32
	bypassTTLCap   uint32
	blockTTL       uint32

	// DNS client for upstream queries
	client         *dns.Client

	// Servers
	udpServer      *dns.Server
	tcpServer      *dns.Server
}

// Config holds DNS server configuration
type Config struct {
	ListenAddr      string
	ProxyIP         string
	UpstreamDNS     []string
	InterceptTTL    uint32
	BypassTTLCap    uint32
	BlockTTL        uint32
	EnableTCP       bool
	EnableUDP       bool
	Timeout         time.Duration
}

// NewServer creates a new DNS server
func NewServer(config Config, policy *policy.Engine, db *database.DB, logger zerolog.Logger) (*Server, error) {
	proxyIP := net.ParseIP(config.ProxyIP)
	if proxyIP == nil {
		return nil, fmt.Errorf("invalid proxy IP: %s", config.ProxyIP)
	}

	s := &Server{
		proxyIP:      proxyIP,
		upstreamDNS:  config.UpstreamDNS,
		policyEngine: policy,
		db:           db,
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

// Start starts the DNS server
func (s *Server) Start() error {
	errChan := make(chan error, 2)

	if s.udpServer != nil {
		go func() {
			s.logger.Info().Str("addr", s.udpServer.Addr).Msg("Starting DNS server (UDP)")
			if err := s.udpServer.ListenAndServe(); err != nil {
				errChan <- fmt.Errorf("UDP server error: %w", err)
			}
		}()
	}

	if s.tcpServer != nil {
		go func() {
			s.logger.Info().Str("addr", s.tcpServer.Addr).Msg("Starting DNS server (TCP)")
			if err := s.tcpServer.ListenAndServe(); err != nil {
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
		action := s.policyEngine.GetDNSAction(clientIP, domain)

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

		// Log the DNS query
		latency := time.Since(startTime).Milliseconds()
		if err := s.logDNS(clientIP, domain, dns.TypeToString[qtype], logAction, responseIP, upstream, latency); err != nil {
			s.logger.Error().Err(err).Msg("Failed to log DNS query")
		}
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

// logDNS logs a DNS query to the database
func (s *Server) logDNS(clientIP net.IP, domain, queryType, action, responseIP, upstream string, latencyMS int64) error {
	// Identify device
	device := s.policyEngine.IdentifyDevice(clientIP, nil)

	var deviceID, deviceName string
	if device != nil {
		deviceID = device.ID
		deviceName = device.Name
	}

	_, err := s.db.Exec(`
		INSERT INTO dns_logs (
			client_ip, device_id, device_name, domain, query_type,
			action, response_ip, upstream, latency_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, clientIP.String(), deviceID, deviceName, domain, queryType, action, responseIP, upstream, latencyMS)

	return err
}
