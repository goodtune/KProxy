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

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goodtune/kproxy/internal/admin"
	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/dhcp"
	"github.com/goodtune/kproxy/internal/dns"
	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/proxy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/storage/bolt"
	"github.com/goodtune/kproxy/internal/usage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	version = "dev"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "/etc/kproxy/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("KProxy version %s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logger
	logger := setupLogger(cfg.Logging)
	log.Logger = logger

	logger.Info().
		Str("version", version).
		Str("config", *configPath).
		Msg("Starting KProxy")

	// Initialize storage
	store, err := openStorage(cfg.Storage)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize storage")
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error().Err(err).Msg("Failed to close storage")
		}
	}()

	logger.Info().Str("path", cfg.Storage.Path).Str("type", cfg.Storage.Type).Msg("Storage initialized")

	// Initialize Certificate Authority
	caConfig := ca.Config{
		RootCertPath:   cfg.TLS.CACert,
		RootKeyPath:    cfg.TLS.CAKey,
		IntermCertPath: cfg.TLS.IntermediateCert,
		IntermKeyPath:  cfg.TLS.IntermediateKey,
		CertCacheSize:  cfg.TLS.CertCacheSize,
		CertCacheTTL:   parseDuration(cfg.TLS.CertCacheTTL, 24*time.Hour),
		CertValidity:   parseDuration(cfg.TLS.CertValidity, 24*time.Hour),
	}

	certificateAuthority, err := ca.NewCA(caConfig, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize Certificate Authority")
	}

	logger.Info().Msg("Certificate Authority initialized")

	// Initialize Policy Engine (fact-based, no config loading)
	// Build OPA configuration
	opaConfig := opa.Config{
		Source:      cfg.Policy.OPAPolicySource,
		PolicyDir:   cfg.Policy.OPAPolicyDir,
		PolicyURLs:  cfg.Policy.OPAPolicyURLs,
		HTTPTimeout: parseDuration(cfg.Policy.OPAHTTPTimeout, 30*time.Second),
		HTTPRetries: cfg.Policy.OPAHTTPRetries,
	}

	policyEngine, err := policy.NewEngine(
		store.Usage(), // Only need usage store for facts
		opaConfig,
		logger,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize Policy Engine")
	}

	logger.Info().
		Str("opa_source", opaConfig.Source).
		Msg("Fact-based Policy Engine initialized (configuration in OPA policies)")

	// Initialize Usage Tracker
	usageTracker := usage.NewTracker(
		store.Usage(),
		usage.Config{
			InactivityTimeout:  parseDuration(cfg.Usage.InactivityTimeout, 2*time.Minute),
			MinSessionDuration: parseDuration(cfg.Usage.MinSessionDuration, 10*time.Second),
		},
		logger,
	)

	logger.Info().Msg("Usage Tracker initialized")

	// Connect usage tracker to policy engine
	policyEngine.SetUsageTracker(usageTracker)

	// Initialize Reset Scheduler
	resetScheduler, err := usage.NewResetScheduler(
		store.Usage(),
		cfg.Usage.DailyResetTime,
		logger,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize Reset Scheduler")
	}

	resetScheduler.Start()
	logger.Info().Msg("Reset Scheduler initialized")

	// Initialize DNS Server
	// ProxyIP - if not configured, auto-detect the server's primary IP
	proxyIP := cfg.Server.ProxyIP
	if proxyIP == "" {
		detectedIP, err := detectServerIP()
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to auto-detect server IP. Please set server.proxy_ip in config")
		}
		proxyIP = detectedIP
		logger.Info().Str("proxy_ip", proxyIP).Msg("Auto-detected server IP for DNS intercept responses")
	} else {
		logger.Info().Str("proxy_ip", proxyIP).Msg("Using configured proxy IP for DNS intercept responses")
	}

	dnsConfig := dns.Config{
		ListenAddr:   fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.DNSPort),
		ProxyIP:      proxyIP,
		UpstreamDNS:  cfg.DNS.UpstreamServers,
		InterceptTTL: cfg.DNS.InterceptTTL,
		BypassTTLCap: cfg.DNS.BypassTTLCap,
		BlockTTL:     cfg.DNS.BlockTTL,
		EnableTCP:    cfg.Server.DNSEnableTCP,
		EnableUDP:    cfg.Server.DNSEnableUDP,
		Timeout:      parseDuration(cfg.DNS.UpstreamTimeout, 5*time.Second),
	}

	dnsServer, err := dns.NewServer(dnsConfig, policyEngine, store.Logs(), logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize DNS Server")
	}

	if err := dnsServer.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start DNS Server")
	}

	logger.Info().
		Str("addr", dnsConfig.ListenAddr).
		Msg("DNS Server started")

	// Initialize DHCP Server (if enabled)
	var dhcpServer *dhcp.Server
	if cfg.DHCP.Enabled {
		// Auto-detect network configuration if not provided
		dhcpServerIP := cfg.DHCP.ServerIP
		dhcpSubnetMask := cfg.DHCP.SubnetMask
		dhcpGateway := cfg.DHCP.Gateway

		if dhcpServerIP == "" || dhcpSubnetMask == "" || dhcpGateway == "" {
			detectedIP, detectedSubnet, detectedGateway, err := detectNetworkConfig()
			if err != nil {
				logger.Warn().Err(err).Msg("Failed to auto-detect network configuration for DHCP")
				if dhcpServerIP == "" || dhcpSubnetMask == "" || dhcpGateway == "" {
					logger.Fatal().Msg("DHCP server requires server_ip, subnet_mask, and gateway. Auto-detection failed. Please configure manually.")
				}
			} else {
				if dhcpServerIP == "" {
					dhcpServerIP = detectedIP
					logger.Info().Str("server_ip", dhcpServerIP).Msg("Auto-detected DHCP server IP")
				}
				if dhcpSubnetMask == "" {
					dhcpSubnetMask = detectedSubnet
					logger.Info().Str("subnet_mask", dhcpSubnetMask).Msg("Auto-detected subnet mask")
				}
				if dhcpGateway == "" {
					dhcpGateway = detectedGateway
					logger.Info().Str("gateway", dhcpGateway).Msg("Auto-detected gateway (using server IP)")
				}
			}
		}

		dhcpConfig := dhcp.Config{
			Enabled:        cfg.DHCP.Enabled,
			Port:           cfg.DHCP.Port,
			BindAddress:    cfg.DHCP.BindAddress,
			ServerIP:       dhcpServerIP,
			SubnetMask:     dhcpSubnetMask,
			Gateway:        dhcpGateway,
			DNSServers:     cfg.DHCP.DNSServers,
			LeaseTime:      parseDuration(cfg.DHCP.LeaseTime, 24*time.Hour),
			RangeStart:     cfg.DHCP.RangeStart,
			RangeEnd:       cfg.DHCP.RangeEnd,
			BootFileName:   cfg.DHCP.BootFileName,
			BootServerName: cfg.DHCP.BootServerName,
			TFTPIP:         cfg.DHCP.TFTPIP,
			BootURI:        cfg.DHCP.BootURI,
		}

		dhcpServer, err = dhcp.NewServer(dhcpConfig, policyEngine, store.DHCPLeases(), logger)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to initialize DHCP Server")
		}

		if err := dhcpServer.Start(); err != nil {
			logger.Fatal().Err(err).Msg("Failed to start DHCP Server")
		}

		logger.Info().
			Str("addr", fmt.Sprintf("%s:%d", cfg.DHCP.BindAddress, cfg.DHCP.Port)).
			Str("server_ip", dhcpServerIP).
			Str("subnet", dhcpSubnetMask).
			Str("gateway", dhcpGateway).
			Str("range", fmt.Sprintf("%s-%s", cfg.DHCP.RangeStart, cfg.DHCP.RangeEnd)).
			Msg("DHCP Server started")
	}

	// Initialize Proxy Server
	proxyConfig := proxy.Config{
		HTTPAddr:    fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.HTTPPort),
		HTTPSAddr:   fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.HTTPSPort),
		AdminDomain: cfg.Server.AdminDomain,
	}

	proxyServer := proxy.NewServer(
		proxyConfig,
		policyEngine,
		certificateAuthority,
		store.Logs(),
		logger,
	)

	if err := proxyServer.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start Proxy Server")
	}

	logger.Info().
		Str("http", proxyConfig.HTTPAddr).
		Str("https", proxyConfig.HTTPSAddr).
		Msg("Proxy Server started")

	// Initialize Metrics Server
	metricsAddr := fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.MetricsPort)
	metricsServer := metrics.NewServer(metricsAddr, logger)

	if err := metricsServer.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start Metrics Server")
	}

	logger.Info().
		Str("addr", metricsAddr).
		Msg("Metrics Server started")

	// Initialize Admin Server (if enabled)
	var adminServer *admin.GorfServer
	if cfg.Admin.Enabled {
		// Ensure initial admin user exists
		if err := admin.EnsureInitialAdminUser(
			context.Background(),
			store.AdminUsers(),
			cfg.Admin.InitialUsername,
			cfg.Admin.InitialPassword,
			logger,
		); err != nil {
			logger.Fatal().Err(err).Msg("Failed to create initial admin user")
		}

		// Create admin server
		adminConfig := admin.Config{
			ListenAddr:      fmt.Sprintf("%s:%d", cfg.Admin.BindAddress, cfg.Admin.Port),
			ServerName:      cfg.Server.AdminDomain,
			JWTSecret:       cfg.Admin.JWTSecret,
			TokenExpiration: parseDuration(cfg.Admin.SessionTimeout, 24*time.Hour),
			RateLimit:       cfg.Admin.RateLimit,
			RateLimitWindow: parseDuration(cfg.Admin.RateLimitWindow, time.Minute),
		}

		adminServer = admin.NewGorfServer(adminConfig, store, policyEngine, usageTracker, certificateAuthority, logger)

		if err := adminServer.Start(); err != nil {
			logger.Fatal().Err(err).Msg("Failed to start Admin Server")
		}

		logger.Info().
			Str("addr", adminConfig.ListenAddr).
			Msg("Admin Server started (gorf/Gin)")
	}

	// Log startup complete
	logger.Info().Msg("KProxy startup complete")
	logger.Info().Msgf("DNS Server: %s:%d", cfg.Server.BindAddress, cfg.Server.DNSPort)
	logger.Info().Msgf("HTTP Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPPort)
	logger.Info().Msgf("HTTPS Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPSPort)
	logger.Info().Msgf("Metrics: http://%s:%d/metrics", cfg.Server.BindAddress, cfg.Server.MetricsPort)
	if cfg.Admin.Enabled {
		logger.Info().Msgf("Admin Interface: https://%s:%d/admin/login", cfg.Admin.BindAddress, cfg.Admin.Port)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	logger.Info().Msg("Shutdown signal received, gracefully stopping...")

	// Stop servers
	resetScheduler.Stop()

	if err := dnsServer.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping DNS Server")
	}

	if dhcpServer != nil {
		if err := dhcpServer.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping DHCP Server")
		}
	}

	if err := proxyServer.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping Proxy Server")
	}

	if err := metricsServer.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping Metrics Server")
	}

	if adminServer != nil {
		if err := adminServer.Stop(); err != nil {
			logger.Error().Err(err).Msg("Error stopping Admin Server")
		}
	}

	logger.Info().Msg("KProxy stopped")
}

func openStorage(cfg config.StorageConfig) (storage.Store, error) {
	storageType := cfg.Type
	if storageType == "" {
		storageType = "bolt"
	}

	switch storageType {
	case "bolt", "bbolt":
		return bolt.Open(cfg.Path)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// setupLogger configures the logger based on configuration
func setupLogger(cfg config.LoggingConfig) zerolog.Logger {
	// Set log level
	level := zerolog.InfoLevel
	switch cfg.Level {
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	}

	zerolog.SetGlobalLevel(level)

	// Set output format
	if cfg.Format == "text" {
		return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	}

	// Default to JSON
	return zerolog.New(os.Stdout).With().Timestamp().Logger()
}

// parseDuration parses a duration string with a fallback
func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// detectServerIP attempts to detect the server's primary non-loopback IP address
func detectServerIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		// Check if it's an IP address (not a network)
		if ipNet, ok := addr.(*net.IPNet); ok {
			// Skip loopback addresses
			if ipNet.IP.IsLoopback() {
				continue
			}
			// Skip IPv6 for now (prefer IPv4)
			if ipNet.IP.To4() == nil {
				continue
			}
			// Return the first valid IPv4 non-loopback address
			return ipNet.IP.String(), nil
		}
	}

	return "", fmt.Errorf("no suitable IP address found")
}

// detectNetworkConfig attempts to detect network configuration (IP, subnet mask, gateway)
func detectNetworkConfig() (ip, subnet, gateway string, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		// Check if it's an IP network address
		if ipNet, ok := addr.(*net.IPNet); ok {
			// Skip loopback addresses
			if ipNet.IP.IsLoopback() {
				continue
			}
			// Skip IPv6 for now (prefer IPv4)
			if ipNet.IP.To4() == nil {
				continue
			}

			// Found valid IPv4 address
			ip = ipNet.IP.String()

			// Get subnet mask
			mask := ipNet.Mask
			subnet = fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

			// Gateway is typically the server IP itself (acting as router) or .1 of the subnet
			// We'll use the server IP as default, which is common for router/gateway setups
			gateway = ip

			return ip, subnet, gateway, nil
		}
	}

	return "", "", "", fmt.Errorf("no suitable network configuration found")
}
