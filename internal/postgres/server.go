package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/rs/zerolog"
)

// Server handles PostgreSQL proxy connections
type Server struct {
	listener     net.Listener
	backendName  string
	backendAddr  string
	policyEngine *policy.Engine
	logger       zerolog.Logger
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc

	// Optional pre-created listener (for systemd socket activation)
	preListener net.Listener
}

// Config holds PostgreSQL server configuration
type Config struct {
	BackendName string // Name of the backend (e.g., "dev", "prod")
	ListenAddr  string
	BackendAddr string // Backend PostgreSQL server address
}

// NewServer creates a new PostgreSQL proxy server
func NewServer(
	config Config,
	policyEngine *policy.Engine,
	logger zerolog.Logger,
) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		backendName:  config.BackendName,
		backendAddr:  config.BackendAddr,
		policyEngine: policyEngine,
		logger:       logger.With().Str("component", "postgres").Str("backend", config.BackendName).Logger(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetListener sets pre-created listener for systemd socket activation
func (s *Server) SetListener(ln net.Listener) {
	s.preListener = ln
}

// Start starts the PostgreSQL proxy server
func (s *Server) Start(listenAddr string) error {
	var err error

	if s.preListener != nil {
		// Use systemd socket-activated listener
		s.logger.Debug().Msg("Using systemd socket-activated PostgreSQL listener")
		s.listener = s.preListener
	} else {
		// Create and bind listener ourselves
		s.listener, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
		}
	}

	s.logger.Info().Str("addr", s.listener.Addr().String()).Msg("PostgreSQL proxy server started")

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop stops the PostgreSQL proxy server
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping PostgreSQL proxy server")

	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Close listener to stop accepting new connections
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Error().Err(err).Msg("Failed to close listener")
		}
	}

	// Wait for all connections to finish
	s.wg.Wait()

	s.logger.Info().Msg("PostgreSQL proxy server stopped")
	return nil
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				// Server is shutting down
				return
			default:
				s.logger.Error().Err(err).Msg("Failed to accept connection")
				continue
			}
		}

		// Handle connection in a goroutine
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single PostgreSQL connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer s.wg.Done()
	defer clientConn.Close()

	startTime := time.Now()

	// Extract client IP
	clientIP := s.extractClientIP(clientConn.RemoteAddr())

	s.logger.Debug().
		Str("client", clientIP.String()).
		Msg("PostgreSQL connection received")

	// Read startup message to extract connection metadata
	connInfo, err := s.parseStartupMessage(clientConn)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("client", clientIP.String()).
			Msg("Failed to parse PostgreSQL startup message")

		// Send error response to client
		s.sendErrorResponse(clientConn, "FATAL", "08P01", "Failed to parse startup message")
		return
	}

	// Build policy request
	policyReq := &policy.PostgresRequest{
		ClientIP: clientIP,
		Backend:  s.backendName,
		Database: connInfo.Database,
		Username: connInfo.Username,
	}

	// Evaluate policy
	decision := s.policyEngine.EvaluatePostgres(policyReq)

	// Log connection attempt
	defer func() {
		duration := time.Since(startTime).Milliseconds()
		s.logConnection(policyReq, decision, duration)

		// Record metrics
		deviceName := clientIP.String()

		metrics.PostgresConnectionsTotal.WithLabelValues(
			deviceName,
			connInfo.Database,
			connInfo.Username,
			string(decision.Action),
		).Inc()

		metrics.PostgresConnectionDuration.WithLabelValues(
			deviceName,
			string(decision.Action),
		).Observe(time.Since(startTime).Seconds())

		if decision.Action == policy.ActionBlock {
			metrics.PostgresBlockedConnectionsTotal.WithLabelValues(
				deviceName,
				decision.Reason,
			).Inc()
		}
	}()

	// Handle based on decision
	switch decision.Action {
	case policy.ActionBlock:
		s.logger.Info().
			Str("client", clientIP.String()).
			Str("database", connInfo.Database).
			Str("username", connInfo.Username).
			Str("reason", decision.Reason).
			Msg("PostgreSQL connection blocked by policy")

		// Send error response to client
		s.sendErrorResponse(clientConn, "FATAL", "28000", decision.Reason)
		return

	case policy.ActionAllow:
		s.logger.Info().
			Str("client", clientIP.String()).
			Str("database", connInfo.Database).
			Str("username", connInfo.Username).
			Msg("PostgreSQL connection allowed, proxying to backend")

		// Connect to backend PostgreSQL server
		backendConn, err := net.DialTimeout("tcp", s.backendAddr, 10*time.Second)
		if err != nil {
			s.logger.Error().
				Err(err).
				Str("backend", s.backendAddr).
				Msg("Failed to connect to backend PostgreSQL server")

			s.sendErrorResponse(clientConn, "FATAL", "08001", "Failed to connect to backend database")
			return
		}
		defer backendConn.Close()

		// Send the original startup message to backend
		if err := s.forwardStartupMessage(backendConn, connInfo); err != nil {
			s.logger.Error().
				Err(err).
				Msg("Failed to forward startup message to backend")
			return
		}

		// Proxy traffic between client and backend
		s.proxyConnections(clientConn, backendConn, connInfo)

	default:
		s.sendErrorResponse(clientConn, "FATAL", "28000", "Access denied")
		return
	}
}

// ConnectionInfo holds parsed PostgreSQL connection information
type ConnectionInfo struct {
	Database   string
	Username   string
	RawMessage []byte // Store original message to forward to backend
	IsSSL      bool
}

// parseStartupMessage parses the PostgreSQL startup message
func (s *Server) parseStartupMessage(conn net.Conn) (*ConnectionInfo, error) {
	// Set read timeout
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Read message length (4 bytes)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length < 8 || length > 10000 {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read the rest of the message
	messageBuf := make([]byte, length-4)
	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	// Read protocol version (4 bytes)
	protocol := binary.BigEndian.Uint32(messageBuf[0:4])

	// Check for SSL request (protocol number 80877103)
	if protocol == 80877103 {
		// Respond with 'N' to decline SSL
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return nil, fmt.Errorf("failed to send SSL response: %w", err)
		}

		// Now read the actual startup message
		return s.parseStartupMessage(conn)
	}

	// Parse startup message parameters
	connInfo := &ConnectionInfo{
		RawMessage: append(lengthBuf, messageBuf...),
	}

	// Parameters start at byte 4 (after protocol version)
	offset := 4
	for offset < len(messageBuf)-1 {
		// Read parameter name
		nameEnd := offset
		for nameEnd < len(messageBuf) && messageBuf[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= len(messageBuf) {
			break
		}
		name := string(messageBuf[offset:nameEnd])
		offset = nameEnd + 1

		// Read parameter value
		valueEnd := offset
		for valueEnd < len(messageBuf) && messageBuf[valueEnd] != 0 {
			valueEnd++
		}
		if valueEnd >= len(messageBuf) {
			break
		}
		value := string(messageBuf[offset:valueEnd])
		offset = valueEnd + 1

		// Extract database and user
		switch name {
		case "database":
			connInfo.Database = value
		case "user":
			connInfo.Username = value
		}
	}

	if connInfo.Database == "" {
		// If no database specified, use username as database name (PostgreSQL default)
		connInfo.Database = connInfo.Username
	}

	return connInfo, nil
}

// forwardStartupMessage forwards the startup message to backend
func (s *Server) forwardStartupMessage(conn net.Conn, info *ConnectionInfo) error {
	if _, err := conn.Write(info.RawMessage); err != nil {
		return fmt.Errorf("failed to write startup message: %w", err)
	}
	return nil
}

// proxyConnections proxies data between client and backend
func (s *Server) proxyConnections(clientConn, backendConn net.Conn, info *ConnectionInfo) {
	// Track active connection
	metrics.PostgresActiveConnections.Inc()
	defer metrics.PostgresActiveConnections.Dec()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend
	go func() {
		defer wg.Done()
		written, err := io.Copy(backendConn, clientConn)
		if err != nil {
			s.logger.Debug().
				Err(err).
				Str("database", info.Database).
				Str("username", info.Username).
				Msg("Client->Backend copy finished")
		}
		metrics.PostgresBytesSent.WithLabelValues(info.Database).Add(float64(written))
		backendConn.Close()
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		written, err := io.Copy(clientConn, backendConn)
		if err != nil {
			s.logger.Debug().
				Err(err).
				Str("database", info.Database).
				Str("username", info.Username).
				Msg("Backend->Client copy finished")
		}
		metrics.PostgresBytesReceived.WithLabelValues(info.Database).Add(float64(written))
		clientConn.Close()
	}()

	wg.Wait()

	s.logger.Debug().
		Str("database", info.Database).
		Str("username", info.Username).
		Msg("PostgreSQL connection closed")
}

// sendErrorResponse sends a PostgreSQL error message to the client
func (s *Server) sendErrorResponse(conn net.Conn, severity, code, message string) {
	// ErrorResponse message format:
	// 'E' (1 byte)
	// Length (4 bytes, including itself)
	// Fields (null-terminated strings)
	// Final null byte

	// Build error message
	var buf []byte

	// Severity
	buf = append(buf, 'S')
	buf = append(buf, []byte(severity)...)
	buf = append(buf, 0)

	// SQLSTATE code
	buf = append(buf, 'C')
	buf = append(buf, []byte(code)...)
	buf = append(buf, 0)

	// Message
	buf = append(buf, 'M')
	buf = append(buf, []byte(message)...)
	buf = append(buf, 0)

	// Final null byte
	buf = append(buf, 0)

	// Prepend message type and length
	length := uint32(len(buf) + 4)
	msg := make([]byte, 1+4+len(buf))
	msg[0] = 'E'
	binary.BigEndian.PutUint32(msg[1:5], length)
	copy(msg[5:], buf)

	// Write to connection
	conn.Write(msg)
}

// extractClientIP extracts the client IP from the remote address
func (s *Server) extractClientIP(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	// Fallback: parse from string
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return net.ParseIP(addr.String())
	}
	return net.ParseIP(host)
}

// logConnection logs a PostgreSQL connection to structured logger
func (s *Server) logConnection(req *policy.PostgresRequest, decision *policy.PolicyDecision, durationMS int64) {
	logEvent := s.logger.Info().
		Str("client_ip", req.ClientIP.String())

	if req.ClientMAC != nil {
		logEvent = logEvent.Str("client_mac", req.ClientMAC.String())
	}

	logEvent.
		Str("database", req.Database).
		Str("username", req.Username).
		Int64("duration_ms", durationMS).
		Str("action", string(decision.Action)).
		Str("matched_rule", decision.MatchedRuleID).
		Str("reason", decision.Reason).
		Msg("PostgreSQL connection processed")
}
