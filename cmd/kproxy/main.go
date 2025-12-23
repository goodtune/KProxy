package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/database"
	"github.com/goodtune/kproxy/internal/dns"
	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/proxy"
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

	// Initialize database
	db, err := database.New(cfg.Database.Path)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error().Err(err).Msg("Failed to close database")
		}
	}()

	logger.Info().Str("path", cfg.Database.Path).Msg("Database initialized")

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

	// Initialize Policy Engine
	defaultAction := cfg.Policy.DefaultAction
	if defaultAction == "" {
		defaultAction = "block"
	}

	policyEngine, err := policy.NewEngine(
		db,
		cfg.DNS.GlobalBypass,
		defaultAction,
		cfg.Policy.UseMACAddress,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize Policy Engine")
	}

	logger.Info().Msg("Policy Engine initialized")

	// Initialize Usage Tracker
	usageTracker := usage.NewTracker(
		db,
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
		db,
		cfg.Usage.DailyResetTime,
		logger,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize Reset Scheduler")
	}

	resetScheduler.Start()
	logger.Info().Msg("Reset Scheduler initialized")

	// Initialize DNS Server
	dnsConfig := dns.Config{
		ListenAddr:   fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.DNSPort),
		ProxyIP:      cfg.Server.BindAddress,
		UpstreamDNS:  cfg.DNS.UpstreamServers,
		InterceptTTL: cfg.DNS.InterceptTTL,
		BypassTTLCap: cfg.DNS.BypassTTLCap,
		BlockTTL:     cfg.DNS.BlockTTL,
		EnableTCP:    cfg.Server.DNSEnableTCP,
		EnableUDP:    cfg.Server.DNSEnableUDP,
		Timeout:      parseDuration(cfg.DNS.UpstreamTimeout, 5*time.Second),
	}

	dnsServer, err := dns.NewServer(dnsConfig, policyEngine, db, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize DNS Server")
	}

	if err := dnsServer.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start DNS Server")
	}

	logger.Info().
		Str("addr", dnsConfig.ListenAddr).
		Msg("DNS Server started")

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
		db,
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

	// Log startup complete
	logger.Info().Msg("KProxy startup complete")
	logger.Info().Msgf("DNS Server: %s:%d", cfg.Server.BindAddress, cfg.Server.DNSPort)
	logger.Info().Msgf("HTTP Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPPort)
	logger.Info().Msgf("HTTPS Proxy: %s:%d", cfg.Server.BindAddress, cfg.Server.HTTPSPort)
	logger.Info().Msgf("Metrics: http://%s:%d/metrics", cfg.Server.BindAddress, cfg.Server.MetricsPort)

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

	if err := proxyServer.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping Proxy Server")
	}

	if err := metricsServer.Stop(); err != nil {
		logger.Error().Err(err).Msg("Error stopping Metrics Server")
	}

	logger.Info().Msg("KProxy stopped")
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
