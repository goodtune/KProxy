package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/rs/zerolog"
)

// Config holds DHCP server configuration
type Config struct {
	Enabled        bool
	Port           int
	BindAddress    string
	ServerIP       string
	SubnetMask     string
	Gateway        string
	DNSServers     []string
	LeaseTime      time.Duration
	RangeStart     string
	RangeEnd       string
	BootFileName   string
	BootServerName string
	TFTPIP         string
	BootURI        string
}

// Server implements a DHCP server for network boot support
type Server struct {
	config       Config
	policyEngine *policy.Engine
	leaseStore   storage.DHCPLeaseStore
	logger       zerolog.Logger

	// Server instance
	server *server4.Server

	// IP pool management
	poolStart net.IP
	poolEnd   net.IP
	mu        sync.RWMutex

	// Shutdown coordination
	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer creates a new DHCP server instance
func NewServer(
	config Config,
	policyEngine *policy.Engine,
	leaseStore storage.DHCPLeaseStore,
	logger zerolog.Logger,
) (*Server, error) {
	// Parse IP range
	poolStart := net.ParseIP(config.RangeStart)
	if poolStart == nil {
		return nil, fmt.Errorf("invalid range_start IP: %s", config.RangeStart)
	}
	poolEnd := net.ParseIP(config.RangeEnd)
	if poolEnd == nil {
		return nil, fmt.Errorf("invalid range_end IP: %s", config.RangeEnd)
	}

	// Validate server IP
	if net.ParseIP(config.ServerIP) == nil {
		return nil, fmt.Errorf("invalid server_ip: %s", config.ServerIP)
	}

	// Validate subnet mask
	if net.ParseIP(config.SubnetMask) == nil {
		return nil, fmt.Errorf("invalid subnet_mask: %s", config.SubnetMask)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:       config,
		policyEngine: policyEngine,
		leaseStore:   leaseStore,
		logger:       logger.With().Str("component", "dhcp").Logger(),
		poolStart:    poolStart.To4(),
		poolEnd:      poolEnd.To4(),
		ctx:          ctx,
		cancel:       cancel,
	}

	return s, nil
}

// Start starts the DHCP server
func (s *Server) Start() error {
	laddr := &net.UDPAddr{
		IP:   net.ParseIP(s.config.BindAddress),
		Port: s.config.Port,
	}

	s.logger.Info().
		Str("addr", laddr.String()).
		Str("range", fmt.Sprintf("%s-%s", s.config.RangeStart, s.config.RangeEnd)).
		Msg("Starting DHCP server")

	// Create DHCP server with the interface
	server, err := server4.NewServer("", laddr, s.handleDHCP, server4.WithDebugLogger())
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %w", err)
	}

	s.server = server

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.Serve(); err != nil {
			s.logger.Error().Err(err).Msg("DHCP server error")
			errChan <- err
		}
	}()

	// Wait briefly for startup errors
	select {
	case err := <-errChan:
		return fmt.Errorf("DHCP server failed to start: %w", err)
	case <-time.After(100 * time.Millisecond):
		s.logger.Info().Msg("DHCP server started successfully")
		return nil
	}
}

// Stop gracefully stops the DHCP server
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping DHCP server")
	s.cancel()

	if s.server != nil {
		if err := s.server.Close(); err != nil {
			return fmt.Errorf("failed to stop DHCP server: %w", err)
		}
	}

	s.logger.Info().Msg("DHCP server stopped")
	return nil
}

// handleDHCP processes incoming DHCP requests
func (s *Server) handleDHCP(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	s.logger.Debug().
		Str("type", m.MessageType().String()).
		Str("mac", m.ClientHWAddr.String()).
		Str("peer", peer.String()).
		Msg("Received DHCP request")

	var response *dhcpv4.DHCPv4
	var err error

	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		response, err = s.handleDiscover(m)
		metrics.DHCPRequestsTotal.WithLabelValues("discover").Inc()
	case dhcpv4.MessageTypeRequest:
		response, err = s.handleRequest(m)
		metrics.DHCPRequestsTotal.WithLabelValues("request").Inc()
	case dhcpv4.MessageTypeRelease:
		err = s.handleRelease(m)
		metrics.DHCPRequestsTotal.WithLabelValues("release").Inc()
		return // No response needed for release
	case dhcpv4.MessageTypeDecline:
		err = s.handleDecline(m)
		metrics.DHCPRequestsTotal.WithLabelValues("decline").Inc()
		return // No response needed for decline
	default:
		s.logger.Warn().
			Str("type", m.MessageType().String()).
			Msg("Unsupported DHCP message type")
		return
	}

	if err != nil {
		s.logger.Error().Err(err).Msg("Error handling DHCP request")
		return
	}

	if response != nil {
		// Send response
		_, err = conn.WriteTo(response.ToBytes(), peer)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to send DHCP response")
			return
		}

		s.logger.Debug().
			Str("type", response.MessageType().String()).
			Str("mac", response.ClientHWAddr.String()).
			Str("ip", response.YourIPAddr.String()).
			Msg("Sent DHCP response")
	}
}

// handleDiscover processes DHCP DISCOVER messages
func (s *Server) handleDiscover(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	mac := req.ClientHWAddr.String()

	// Check for existing lease
	lease, err := s.leaseStore.GetByMAC(s.ctx, mac)
	var offerIP net.IP

	if err == nil && lease != nil && !lease.IsExpired() {
		// Check if existing lease IP is still in the current pool
		existingIP := net.ParseIP(lease.IP)
		if s.isIPInPool(existingIP) {
			// Reuse existing lease if IP is still in pool
			offerIP = existingIP
			s.logger.Debug().
				Str("mac", mac).
				Str("ip", lease.IP).
				Msg("Reusing existing lease")
		} else {
			// Old lease is outside current pool, delete and allocate new IP
			s.logger.Info().
				Str("mac", mac).
				Str("old_ip", lease.IP).
				Msg("Existing lease outside pool range, allocating new IP")
			if err := s.leaseStore.Delete(s.ctx, mac); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to delete old lease")
			}
			offerIP, err = s.allocateIP(mac)
			if err != nil {
				s.logger.Error().Err(err).Str("mac", mac).Msg("Failed to allocate IP")
				return nil, err
			}
			s.logger.Debug().
				Str("mac", mac).
				Str("ip", offerIP.String()).
				Msg("Allocated new IP")
		}
	} else {
		// Allocate new IP
		offerIP, err = s.allocateIP(mac)
		if err != nil {
			s.logger.Error().Err(err).Str("mac", mac).Msg("Failed to allocate IP")
			return nil, err
		}
		s.logger.Debug().
			Str("mac", mac).
			Str("ip", offerIP.String()).
			Msg("Allocated new IP")
	}

	// Create DHCP OFFER
	offer, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create reply: %w", err)
	}

	offer.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	offer.YourIPAddr = offerIP
	offer.ServerIPAddr = net.ParseIP(s.config.ServerIP)

	// Add standard options
	s.addStandardOptions(offer)

	// Add boot options for PXE/netboot
	s.addBootOptions(offer, req)

	return offer, nil
}

// handleRequest processes DHCP REQUEST messages
func (s *Server) handleRequest(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	mac := req.ClientHWAddr.String()
	requestedIP := req.RequestedIPAddress()

	// Validate requested IP is in our pool
	if requestedIP == nil {
		requestedIP = req.ClientIPAddr
	}

	if !s.isIPInPool(requestedIP) {
		s.logger.Warn().
			Str("mac", mac).
			Str("ip", requestedIP.String()).
			Msg("Requested IP not in pool, sending NAK")
		return s.createNAK(req), nil
	}

	// Create or update lease
	lease := &storage.DHCPLease{
		MAC:       mac,
		IP:        requestedIP.String(),
		Hostname:  req.HostName(),
		ExpiresAt: time.Now().Add(s.config.LeaseTime),
	}

	if err := s.leaseStore.Create(s.ctx, lease); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save lease")
		return nil, err
	}

	metrics.DHCPLeasesActive.Inc()

	s.logger.Info().
		Str("mac", mac).
		Str("ip", requestedIP.String()).
		Str("hostname", lease.Hostname).
		Msg("Assigned IP lease")

	// Create DHCP ACK
	ack, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create reply: %w", err)
	}

	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	ack.YourIPAddr = requestedIP
	ack.ServerIPAddr = net.ParseIP(s.config.ServerIP)

	// Add standard options
	s.addStandardOptions(ack)

	// Add boot options for PXE/netboot
	s.addBootOptions(ack, req)

	return ack, nil
}

// handleRelease processes DHCP RELEASE messages
func (s *Server) handleRelease(req *dhcpv4.DHCPv4) error {
	mac := req.ClientHWAddr.String()
	ip := req.ClientIPAddr.String()

	if err := s.leaseStore.Delete(s.ctx, mac); err != nil {
		s.logger.Error().Err(err).Str("mac", mac).Msg("Failed to delete lease")
		return err
	}

	metrics.DHCPLeasesActive.Dec()

	s.logger.Info().
		Str("mac", mac).
		Str("ip", ip).
		Msg("Released IP lease")

	return nil
}

// handleDecline processes DHCP DECLINE messages
func (s *Server) handleDecline(req *dhcpv4.DHCPv4) error {
	mac := req.ClientHWAddr.String()
	requestedIP := req.RequestedIPAddress()

	s.logger.Warn().
		Str("mac", mac).
		Str("ip", requestedIP.String()).
		Msg("Client declined IP address (possible conflict)")

	// Mark IP as unavailable temporarily or remove lease
	if err := s.leaseStore.Delete(s.ctx, mac); err != nil {
		return err
	}

	return nil
}

// addStandardOptions adds standard DHCP options to response
func (s *Server) addStandardOptions(resp *dhcpv4.DHCPv4) {
	// Subnet mask
	mask := net.IPMask(net.ParseIP(s.config.SubnetMask).To4())
	resp.UpdateOption(dhcpv4.OptSubnetMask(mask))

	// Router (gateway)
	if s.config.Gateway != "" {
		resp.UpdateOption(dhcpv4.OptRouter(net.ParseIP(s.config.Gateway)))
	}

	// DNS servers
	var dnsServers []net.IP
	if len(s.config.DNSServers) > 0 {
		for _, dns := range s.config.DNSServers {
			dnsServers = append(dnsServers, net.ParseIP(dns))
		}
	} else {
		// Use server IP as DNS if none specified
		dnsServers = []net.IP{net.ParseIP(s.config.ServerIP)}
	}
	resp.UpdateOption(dhcpv4.OptDNS(dnsServers...))

	// Lease time
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.config.LeaseTime))

	// Server identifier
	resp.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(s.config.ServerIP)))
}

// addBootOptions adds PXE/netboot options to response
func (s *Server) addBootOptions(resp *dhcpv4.DHCPv4, req *dhcpv4.DHCPv4) {
	// Check if client is requesting PXE boot (option 93 - client architecture)
	if req.Options.Has(dhcpv4.OptionClientSystemArchitectureType) {
		s.logger.Debug().
			Str("mac", req.ClientHWAddr.String()).
			Msg("PXE boot request detected")

		// Get client architecture
		archType := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)

		// Determine boot mode based on architecture
		if len(archType) >= 2 {
			arch := binary.BigEndian.Uint16(archType)

			// 0x0000 = BIOS, 0x0007 = UEFI x64, 0x0009 = UEFI x64 HTTP
			if arch == 0x0000 {
				// BIOS PXE boot
				if s.config.BootFileName != "" {
					resp.UpdateOption(dhcpv4.OptBootFileName(s.config.BootFileName))
				}
				if s.config.BootServerName != "" {
					resp.ServerHostName = s.config.BootServerName
				}
				if s.config.TFTPIP != "" {
					resp.ServerIPAddr = net.ParseIP(s.config.TFTPIP)
				}

				s.logger.Debug().
					Str("mac", req.ClientHWAddr.String()).
					Str("mode", "BIOS").
					Str("file", s.config.BootFileName).
					Msg("Configured BIOS PXE boot")
			} else if arch == 0x0007 || arch == 0x0009 {
				// UEFI boot (potentially HTTP boot)
				if s.config.BootURI != "" {
					// Option 114 - Boot URI (UEFI HTTP boot)
					resp.UpdateOption(dhcpv4.Option{
						Code:  dhcpv4.GenericOptionCode(114),
						Value: dhcpv4.String(s.config.BootURI),
					})

					s.logger.Debug().
						Str("mac", req.ClientHWAddr.String()).
						Str("mode", "UEFI-HTTP").
						Str("uri", s.config.BootURI).
						Msg("Configured UEFI HTTP boot")
				} else if s.config.BootFileName != "" {
					// Fallback to TFTP boot
					resp.UpdateOption(dhcpv4.OptBootFileName(s.config.BootFileName))
					if s.config.TFTPIP != "" {
						resp.ServerIPAddr = net.ParseIP(s.config.TFTPIP)
					}

					s.logger.Debug().
						Str("mac", req.ClientHWAddr.String()).
						Str("mode", "UEFI-TFTP").
						Str("file", s.config.BootFileName).
						Msg("Configured UEFI TFTP boot")
				}
			}
		}
	}
}

// allocateIP finds an available IP address in the pool
func (s *Server) allocateIP(mac string) (net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get all active leases
	leases, err := s.leaseStore.List(s.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list leases: %w", err)
	}

	// Build map of allocated IPs
	allocated := make(map[string]bool)
	for _, lease := range leases {
		if !lease.IsExpired() {
			allocated[lease.IP] = true
		}
	}

	// Find first available IP in pool
	current := make(net.IP, len(s.poolStart))
	copy(current, s.poolStart)

	for {
		if !allocated[current.String()] {
			return current, nil
		}

		// Increment IP
		current = nextIP(current)

		// Check if we've exceeded pool range
		if ipToInt(current) > ipToInt(s.poolEnd) {
			return nil, fmt.Errorf("no available IPs in pool")
		}
	}
}

// isIPInPool checks if an IP is within the configured pool range
func (s *Server) isIPInPool(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ipInt := ipToInt(ip.To4())
	startInt := ipToInt(s.poolStart)
	endInt := ipToInt(s.poolEnd)

	return ipInt >= startInt && ipInt <= endInt
}

// createNAK creates a DHCP NAK response
func (s *Server) createNAK(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	nak, _ := dhcpv4.NewReplyFromRequest(req)
	nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	nak.ServerIPAddr = net.ParseIP(s.config.ServerIP)
	return nak
}

// ipToInt converts IP address to uint32
func ipToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		ip = ip[12:16]
	}
	return binary.BigEndian.Uint32(ip)
}

// nextIP increments an IP address by one
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}

	return next
}
