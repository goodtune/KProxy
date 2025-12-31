package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goodtune/kproxy/internal/acme"
	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/dhcp"
	"github.com/goodtune/kproxy/internal/dns"
	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/proxy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/storage/redis"
	"github.com/goodtune/kproxy/internal/systemd"
	"github.com/goodtune/kproxy/internal/usage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start KProxy server",
	Long:  `Start the KProxy server with DNS, DHCP (optional), HTTP/HTTPS proxy, and metrics endpoints.`,
	RunE:  runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logger
	logger := setupLogger(cfg.Logging)
	log.Logger = logger

	logger.Info().
		Str("version", version).
		Str("config", configPath).
		Msg("Starting KProxy")

	// Check for systemd socket activation
	sdListeners, err := systemd.GetListeners()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to get systemd listeners")
	}
	if sdListeners.Activated {
		logger.Info().Msg("Running with systemd socket activation")
	}

	// Initialize storage
	store, err := openStorage(cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error().Err(err).Msg("Failed to close storage")
		}
	}()

	logger.Info().
		Str("type", cfg.Storage.Type).
		Str("redis_host", cfg.Storage.Redis.Host).
		Int("redis_port", cfg.Storage.Redis.Port).
		Msg("Storage initialized")

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
		return fmt.Errorf("failed to initialize Certificate Authority: %w", err)
	}

	logger.Info().Msg("Certificate Authority initialized")

	// Obtain and load Let's Encrypt certificate if configured
	var letsEncryptCert *tls.Certificate
	if cfg.TLS.UseLetsEncrypt {
		logger.Info().
			Str("domain", cfg.Server.Name).
			Str("dns_provider", cfg.TLS.LegoDNSProvider).
			Msg("Let's Encrypt is enabled, obtaining certificate via ACME DNS-01 challenge")

		acmeClient := acme.NewClient(acme.Config{
			Email:       cfg.TLS.LegoEmail,
			DNSProvider: cfg.TLS.LegoDNSProvider,
			Credentials: cfg.TLS.LegoCredentials,
			CertPath:    cfg.TLS.LegoCertPath,
			KeyPath:     cfg.TLS.LegoKeyPath,
			CADirURL:    cfg.TLS.LegoCADirURL,
			Domain:      cfg.Server.Name,
		}, logger)

		if err := acmeClient.ObtainCertificate(); err != nil {
			logger.Error().
				Err(err).
				Str("domain", cfg.Server.Name).
				Msg("Failed to obtain Let's Encrypt certificate - continuing with self-signed CA")
		} else {
			logger.Info().
				Str("domain", cfg.Server.Name).
				Str("cert_path", cfg.TLS.LegoCertPath).
				Str("key_path", cfg.TLS.LegoKeyPath).
				Msg("Let's Encrypt certificate obtained successfully")
		}
	}

	// Load Let's Encrypt certificate if it exists
	if cfg.TLS.UseLetsEncrypt {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.LegoCertPath, cfg.TLS.LegoKeyPath)
		if err != nil {
			logger.Warn().
				Err(err).
				Str("cert_path", cfg.TLS.LegoCertPath).
				Str("key_path", cfg.TLS.LegoKeyPath).
				Msg("Failed to load Let's Encrypt certificate - will use self-signed CA for server name")
		} else {
			letsEncryptCert = &cert
			logger.Info().
				Str("domain", cfg.Server.Name).
				Msg("Let's Encrypt certificate loaded successfully")
		}
	}

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
		cfg.Server.Name,
		opaConfig,
		logger,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize Policy Engine: %w", err)
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
		return fmt.Errorf("failed to initialize Reset Scheduler: %w", err)
	}

	resetScheduler.Start()
	logger.Info().Msg("Reset Scheduler initialized")

	// Initialize DNS Server
	// ProxyIP - if not configured, auto-detect the server's primary IP
	proxyIP := cfg.Server.ProxyIP
	if proxyIP == "" {
		detectedIP, err := detectServerIP()
		if err != nil {
			return fmt.Errorf("failed to auto-detect server IP. Please set server.proxy_ip in config: %w", err)
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

	dnsServer, err := dns.NewServer(dnsConfig, policyEngine, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize DNS Server: %w", err)
	}

	// Use systemd socket-activated listeners if available
	if sdListeners.Activated {
		dnsServer.SetListeners(sdListeners.DNSUdp, sdListeners.DNSTcp)
	}

	if err := dnsServer.Start(); err != nil {
		return fmt.Errorf("failed to start DNS Server: %w", err)
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
					return fmt.Errorf("DHCP server requires server_ip, subnet_mask, and gateway. Auto-detection failed. Please configure manually")
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
			return fmt.Errorf("failed to initialize DHCP Server: %w", err)
		}

		if err := dhcpServer.Start(); err != nil {
			return fmt.Errorf("failed to start DHCP Server: %w", err)
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
		ServerName:  cfg.Server.Name,
		HTTPSPort:   cfg.Server.HTTPSPort,
	}

	proxyServer := proxy.NewServer(
		proxyConfig,
		policyEngine,
		certificateAuthority,
		logger,
	)

	// Configure Let's Encrypt certificate if available
	if letsEncryptCert != nil {
		proxyServer.SetLetsEncryptCert(letsEncryptCert)
	}

	// Use systemd socket-activated listeners if available
	if sdListeners.Activated {
		proxyServer.SetListeners(sdListeners.HTTP, sdListeners.HTTPS)
	}

	if err := proxyServer.Start(); err != nil {
		return fmt.Errorf("failed to start Proxy Server: %w", err)
	}

	logger.Info().
		Str("http", proxyConfig.HTTPAddr).
		Str("https", proxyConfig.HTTPSAddr).
		Msg("Proxy Server started")

	// Initialize Metrics Server
	metricsAddr := fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.MetricsPort)
	metricsServer := metrics.NewServer(metricsAddr, logger)

	// Use systemd socket-activated listener if available
	if sdListeners.Activated && sdListeners.Metrics != nil {
		metricsServer.SetListener(sdListeners.Metrics)
	}

	if err := metricsServer.Start(); err != nil {
		return fmt.Errorf("failed to start Metrics Server: %w", err)
	}

	logger.Info().
		Str("addr", metricsAddr).
		Msg("Metrics Server started")

	// Log startup complete
	logger.Info().Msg("KProxy startup complete")
	logger.Info().Msgf("DNS Server: %s:%d", cfg.Server.BindAddress, cfg.Server.DNSPort)
	logger.Info().Msgf("HTTP Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPPort)
	logger.Info().Msgf("HTTPS Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPSPort)
	logger.Info().Msgf("Metrics: http://%s:%d/metrics", cfg.Server.BindAddress, cfg.Server.MetricsPort)

	// Notify systemd that we're ready to serve requests
	if err := systemd.NotifyReady(); err != nil {
		logger.Warn().Err(err).Msg("Failed to send systemd ready notification")
	} else {
		logger.Debug().Msg("Sent systemd ready notification")
	}

	// Wait for signals (shutdown or reload)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Signal handling loop
	for {
		sig := <-sigChan

		switch sig {
		case syscall.SIGHUP:
			logger.Info().Msg("SIGHUP received, reloading policies...")
			if err := policyEngine.Reload(); err != nil {
				logger.Error().Err(err).Msg("Failed to reload policies")
			} else {
				logger.Info().Msg("Policies reloaded successfully")
			}
			// Continue running
			continue

		case os.Interrupt, syscall.SIGTERM:
			logger.Info().Msg("Shutdown signal received, gracefully stopping...")
			// Break out of loop to shutdown
		}

		// Only reached on shutdown signals
		break
	}

	// Notify systemd that we're stopping
	if err := systemd.NotifyStopping(); err != nil {
		logger.Warn().Err(err).Msg("Failed to send systemd stopping notification")
	}

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

	logger.Info().Msg("KProxy stopped")

	return nil
}

func openStorage(cfg config.StorageConfig) (storage.Store, error) {
	storageType := cfg.Type
	if storageType == "" {
		storageType = "redis"
	}

	switch storageType {
	case "redis":
		return redis.Open(cfg.Redis)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s (only 'redis' is supported)", storageType)
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
