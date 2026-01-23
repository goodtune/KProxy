package snoopy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/grandcat/zeroconf"
	"github.com/rs/zerolog"
)

const (
	// SnoopyServiceType is the mDNS service type advertised by snoopy servers
	SnoopyServiceType = "_snoopy._tcp"
	// DefaultDomain is the default mDNS domain
	DefaultDomain = "local."
	// DefaultScanInterval is how often to scan for snoopy servers
	DefaultScanInterval = 30 * time.Second
	// DefaultServerTTL is how long to keep a server in the registry without refresh
	DefaultServerTTL = 90 * time.Second
)

// Server represents a discovered snoopy server
type Server struct {
	IP         net.IP
	Port       int
	Hostname   string
	LastSeen   time.Time
	TXTRecords []string
}

// Registry maintains an index of active snoopy servers discovered via mDNS
type Registry struct {
	servers      map[string]*Server // key: IP address string
	mu           sync.RWMutex
	logger       zerolog.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	scanInterval time.Duration
	serverTTL    time.Duration
}

// Config holds configuration for the snoopy registry
type Config struct {
	ScanInterval time.Duration
	ServerTTL    time.Duration
}

// NewRegistry creates a new snoopy server registry
func NewRegistry(config Config, logger zerolog.Logger) *Registry {
	ctx, cancel := context.WithCancel(context.Background())

	if config.ScanInterval == 0 {
		config.ScanInterval = DefaultScanInterval
	}
	if config.ServerTTL == 0 {
		config.ServerTTL = DefaultServerTTL
	}

	r := &Registry{
		servers:      make(map[string]*Server),
		logger:       logger.With().Str("component", "snoopy-registry").Logger(),
		ctx:          ctx,
		cancel:       cancel,
		scanInterval: config.ScanInterval,
		serverTTL:    config.ServerTTL,
	}

	return r
}

// Start begins background mDNS discovery
func (r *Registry) Start() {
	r.logger.Info().
		Dur("scan_interval", r.scanInterval).
		Dur("server_ttl", r.serverTTL).
		Msg("Starting snoopy mDNS discovery")

	// Start discovery worker
	r.wg.Add(1)
	go r.discoveryWorker()

	// Start cleanup worker
	r.wg.Add(1)
	go r.cleanupWorker()
}

// Stop halts the discovery process
func (r *Registry) Stop() {
	r.logger.Info().Msg("Stopping snoopy registry")
	r.cancel()
	r.wg.Wait()
	r.logger.Info().Msg("Snoopy registry stopped")
}

// IsActive checks if snoopy is running on the given IP address
func (r *Registry) IsActive(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ipStr := ip.String()
	server, exists := r.servers[ipStr]
	if !exists {
		return false
	}

	// Check if server is still within TTL
	if time.Since(server.LastSeen) > r.serverTTL {
		return false
	}

	return true
}

// GetServer returns information about a snoopy server if it exists and is active
func (r *Registry) GetServer(ip net.IP) (*Server, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ipStr := ip.String()
	server, exists := r.servers[ipStr]
	if !exists {
		return nil, false
	}

	// Check if server is still within TTL
	if time.Since(server.LastSeen) > r.serverTTL {
		return nil, false
	}

	// Return a copy to avoid race conditions
	return &Server{
		IP:         server.IP,
		Port:       server.Port,
		Hostname:   server.Hostname,
		LastSeen:   server.LastSeen,
		TXTRecords: append([]string{}, server.TXTRecords...),
	}, true
}

// GetActiveServers returns a list of all currently active snoopy servers
func (r *Registry) GetActiveServers() []*Server {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	active := make([]*Server, 0, len(r.servers))

	for _, server := range r.servers {
		if now.Sub(server.LastSeen) <= r.serverTTL {
			// Return a copy
			active = append(active, &Server{
				IP:         server.IP,
				Port:       server.Port,
				Hostname:   server.Hostname,
				LastSeen:   server.LastSeen,
				TXTRecords: append([]string{}, server.TXTRecords...),
			})
		}
	}

	return active
}

// discoveryWorker continuously scans for snoopy servers via mDNS
func (r *Registry) discoveryWorker() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.scanInterval)
	defer ticker.Stop()

	// Do an initial scan immediately
	r.scan()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.scan()
		}
	}
}

// scan performs a single mDNS scan for snoopy servers
func (r *Registry) scan() {
	r.logger.Debug().Msg("Scanning for snoopy servers via mDNS")

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to create mDNS resolver")
		return
	}

	entries := make(chan *zeroconf.ServiceEntry, 10)

	// Start discovery in a separate goroutine
	scanCtx, scanCancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer scanCancel()

	go func() {
		err := resolver.Browse(scanCtx, SnoopyServiceType, DefaultDomain, entries)
		if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
			r.logger.Error().Err(err).Msg("mDNS browse error")
		}
	}()

	// Process discovered entries
	discovered := 0
	for {
		select {
		case <-scanCtx.Done():
			if discovered > 0 {
				r.logger.Debug().
					Int("count", discovered).
					Msg("mDNS scan completed")
			} else {
				r.logger.Debug().Msg("mDNS scan completed, no snoopy servers found")
			}
			return

		case entry := <-entries:
			if entry == nil {
				continue
			}

			// Process each IP address in the entry
			for _, ip := range entry.AddrIPv4 {
				r.updateServer(ip, entry)
				discovered++
			}
			for _, ip := range entry.AddrIPv6 {
				r.updateServer(ip, entry)
				discovered++
			}
		}
	}
}

// updateServer adds or updates a snoopy server in the registry
func (r *Registry) updateServer(ip net.IP, entry *zeroconf.ServiceEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ipStr := ip.String()
	now := time.Now()

	if existing, exists := r.servers[ipStr]; exists {
		// Update existing entry
		existing.LastSeen = now
		existing.Port = entry.Port
		existing.Hostname = entry.HostName
		existing.TXTRecords = entry.Text

		r.logger.Debug().
			Str("ip", ipStr).
			Str("hostname", entry.HostName).
			Int("port", entry.Port).
			Msg("Updated snoopy server")
	} else {
		// Add new entry
		r.servers[ipStr] = &Server{
			IP:         ip,
			Port:       entry.Port,
			Hostname:   entry.HostName,
			LastSeen:   now,
			TXTRecords: entry.Text,
		}

		// Record discovery in metrics
		metrics.SnoopyDiscoveriesTotal.WithLabelValues(ipStr, entry.HostName).Inc()

		r.logger.Info().
			Str("ip", ipStr).
			Str("hostname", entry.HostName).
			Int("port", entry.Port).
			Msg("Discovered new snoopy server")
	}

	// Update active servers gauge
	r.updateActiveServersMetric()
}

// updateActiveServersMetric updates the Prometheus gauge for active servers
// Must be called with lock held
func (r *Registry) updateActiveServersMetric() {
	now := time.Now()
	activeCount := 0

	for _, server := range r.servers {
		if now.Sub(server.LastSeen) <= r.serverTTL {
			activeCount++
		}
	}

	metrics.SnoopyServersActive.Set(float64(activeCount))
}

// cleanupWorker removes stale entries from the registry
func (r *Registry) cleanupWorker() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.serverTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

// cleanup removes entries that haven't been seen within the TTL
func (r *Registry) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	removed := 0

	for ipStr, server := range r.servers {
		if now.Sub(server.LastSeen) > r.serverTTL {
			delete(r.servers, ipStr)
			removed++

			r.logger.Info().
				Str("ip", ipStr).
				Str("hostname", server.Hostname).
				Dur("last_seen", now.Sub(server.LastSeen)).
				Msg("Removed stale snoopy server")
		}
	}

	if removed > 0 {
		// Update active servers gauge
		r.updateActiveServersMetric()

		r.logger.Debug().
			Int("removed", removed).
			Int("remaining", len(r.servers)).
			Msg("Cleanup completed")
	}
}

// Stats returns statistics about the registry
func (r *Registry) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	activeCount := 0

	for _, server := range r.servers {
		if now.Sub(server.LastSeen) <= r.serverTTL {
			activeCount++
		}
	}

	return Stats{
		TotalServers:  len(r.servers),
		ActiveServers: activeCount,
	}
}

// Stats holds registry statistics
type Stats struct {
	TotalServers  int
	ActiveServers int
}

// String returns a formatted string representation of the stats
func (s Stats) String() string {
	return fmt.Sprintf("total=%d active=%d", s.TotalServers, s.ActiveServers)
}
