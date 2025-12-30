package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	validateDump bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long:  `Validate the KProxy configuration file for syntax and semantic errors.`,
	RunE:  runValidate,
}

func init() {
	validateCmd.Flags().BoolVar(&validateDump, "dump", false, "Dump full configuration with defaults highlighted")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Configuration validation failed: %v\n", err)
		return err
	}

	// Check for unknown keys (always, not just with -dump)
	unknownKeys, err := findUnknownKeys(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "⚠️  Warning: Could not check for unknown keys: %v\n", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "✅ Configuration is valid: %s\n", configPath)

	// Warn about unknown keys
	if len(unknownKeys) > 0 {
		red := color.New(color.FgRed, color.Bold)
		fmt.Fprintln(os.Stdout)
		red.Fprintf(os.Stdout, "⚠️  WARNING: Found %d unknown configuration key(s):\n", len(unknownKeys))
		for _, key := range unknownKeys {
			red.Fprintf(os.Stdout, "   - %s\n", key)
		}
		fmt.Fprintln(os.Stdout, "\nThese keys will be ignored and may indicate typos or deprecated settings.")
	}

	// If dump requested, show full configuration with defaults highlighted
	if validateDump {
		_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("=", 80))
		_, _ = fmt.Fprintln(os.Stdout, "FULL CONFIGURATION (values different from defaults are highlighted)")
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("=", 80))

		// Get default configuration
		defaultCfg := getDefaultConfig()

		// Dump configuration
		dumpConfig(cfg, defaultCfg, unknownKeys)
	}

	return nil
}

// getDefaultConfig creates a configuration with default values
func getDefaultConfig() *config.Config {
	v := viper.New()
	setDefaultsForDump(v)

	var cfg config.Config
	_ = v.Unmarshal(&cfg)

	return &cfg
}

// setDefaultsForDump sets default configuration values (copied from config package)
func setDefaultsForDump(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.dns_port", 53)
	v.SetDefault("server.dns_enable_udp", true)
	v.SetDefault("server.dns_enable_tcp", true)
	v.SetDefault("server.http_port", 80)
	v.SetDefault("server.https_port", 443)
	v.SetDefault("server.admin_domain", "kproxy.home.local")
	v.SetDefault("server.metrics_port", 9090)
	v.SetDefault("server.bind_address", "0.0.0.0")
	v.SetDefault("server.proxy_ip", "")

	// DNS defaults
	v.SetDefault("dns.upstream_servers", []string{"8.8.8.8:53", "1.1.1.1:53"})
	v.SetDefault("dns.intercept_ttl", uint32(60))
	v.SetDefault("dns.bypass_ttl_cap", uint32(300))
	v.SetDefault("dns.block_ttl", uint32(60))
	v.SetDefault("dns.upstream_timeout", "5s")
	v.SetDefault("dns.global_bypass", []string{
		"ocsp.*.com",
		"crl.*.com",
		"*.ocsp.*",
		"time.*.com",
		"time.*.gov",
	})

	// DHCP defaults
	v.SetDefault("dhcp.enabled", false)
	v.SetDefault("dhcp.port", 67)
	v.SetDefault("dhcp.bind_address", "0.0.0.0")
	v.SetDefault("dhcp.lease_time", "24h")
	v.SetDefault("dhcp.dns_servers", []string{})

	// TLS defaults
	v.SetDefault("tls.ca_cert", "/etc/kproxy/ca/root-ca.crt")
	v.SetDefault("tls.ca_key", "/etc/kproxy/ca/root-ca.key")
	v.SetDefault("tls.intermediate_cert", "/etc/kproxy/ca/intermediate-ca.crt")
	v.SetDefault("tls.intermediate_key", "/etc/kproxy/ca/intermediate-ca.key")
	v.SetDefault("tls.cert_cache_size", 1000)
	v.SetDefault("tls.cert_cache_ttl", "24h")
	v.SetDefault("tls.cert_validity", "24h")

	// Storage defaults
	v.SetDefault("storage.type", "redis")
	v.SetDefault("storage.redis.host", "localhost")
	v.SetDefault("storage.redis.port", 6379)
	v.SetDefault("storage.redis.password", "")
	v.SetDefault("storage.redis.db", 0)
	v.SetDefault("storage.redis.pool_size", 10)
	v.SetDefault("storage.redis.min_idle_conns", 5)
	v.SetDefault("storage.redis.dial_timeout", "5s")
	v.SetDefault("storage.redis.read_timeout", "3s")
	v.SetDefault("storage.redis.write_timeout", "3s")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")

	// Policy defaults
	v.SetDefault("policy.default_action", "block")
	v.SetDefault("policy.default_allow", false)
	v.SetDefault("policy.use_mac_address", true)
	v.SetDefault("policy.arp_cache_ttl", "5m")
	v.SetDefault("policy.opa_policy_dir", "/etc/kproxy/policies")
	v.SetDefault("policy.opa_policy_source", "filesystem")
	v.SetDefault("policy.opa_policy_urls", []string{})
	v.SetDefault("policy.opa_http_timeout", "30s")
	v.SetDefault("policy.opa_http_retries", 3)

	// Usage tracking defaults
	v.SetDefault("usage_tracking.inactivity_timeout", "2m")
	v.SetDefault("usage_tracking.min_session_duration", "10s")
	v.SetDefault("usage_tracking.daily_reset_time", "00:00")

	// Response modification defaults
	v.SetDefault("response_modification.enabled", true)
	v.SetDefault("response_modification.disabled_hosts", []string{"*.bank.com", "secure.*"})
	v.SetDefault("response_modification.allowed_content_types", []string{"text/html"})
}

// findUnknownKeys loads the config file and checks for unknown keys
func findUnknownKeys(configPath string) ([]string, error) {
	v := viper.New()
	v.SetConfigFile(configPath)

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	// Get all keys from the config file
	allKeys := v.AllKeys()

	// Build set of valid keys
	validKeys := getValidKeys()

	// Find unknown keys
	unknown := []string{}
	for _, key := range allKeys {
		if !validKeys[key] {
			unknown = append(unknown, key)
		}
	}

	return unknown, nil
}

// getValidKeys returns a set of all valid configuration keys
func getValidKeys() map[string]bool {
	keys := map[string]bool{
		// Server
		"server.dns_port":        true,
		"server.dns_enable_udp":  true,
		"server.dns_enable_tcp":  true,
		"server.http_port":       true,
		"server.https_port":      true,
		"server.admin_domain":    true,
		"server.metrics_port":    true,
		"server.bind_address":    true,
		"server.proxy_ip":        true,

		// DNS
		"dns.upstream_servers":  true,
		"dns.intercept_ttl":     true,
		"dns.bypass_ttl_cap":    true,
		"dns.block_ttl":         true,
		"dns.upstream_timeout":  true,
		"dns.global_bypass":     true,

		// DHCP
		"dhcp.enabled":          true,
		"dhcp.port":             true,
		"dhcp.bind_address":     true,
		"dhcp.server_ip":        true,
		"dhcp.subnet_mask":      true,
		"dhcp.gateway":          true,
		"dhcp.dns_servers":      true,
		"dhcp.lease_time":       true,
		"dhcp.range_start":      true,
		"dhcp.range_end":        true,
		"dhcp.boot_filename":    true,
		"dhcp.boot_server_name": true,
		"dhcp.tftp_ip":          true,
		"dhcp.boot_uri":         true,

		// TLS
		"tls.ca_cert":           true,
		"tls.ca_key":            true,
		"tls.intermediate_cert": true,
		"tls.intermediate_key":  true,
		"tls.cert_cache_size":   true,
		"tls.cert_cache_ttl":    true,
		"tls.cert_validity":     true,

		// Storage
		"storage.type":                   true,
		"storage.redis.host":             true,
		"storage.redis.port":             true,
		"storage.redis.password":         true,
		"storage.redis.db":               true,
		"storage.redis.pool_size":        true,
		"storage.redis.min_idle_conns":   true,
		"storage.redis.dial_timeout":     true,
		"storage.redis.read_timeout":     true,
		"storage.redis.write_timeout":    true,

		// Logging
		"logging.level":  true,
		"logging.format": true,

		// Policy
		"policy.default_action":    true,
		"policy.default_allow":     true,
		"policy.use_mac_address":   true,
		"policy.arp_cache_ttl":     true,
		"policy.opa_policy_dir":    true,
		"policy.opa_policy_source": true,
		"policy.opa_policy_urls":   true,
		"policy.opa_http_timeout":  true,
		"policy.opa_http_retries":  true,

		// Usage tracking
		"usage_tracking.inactivity_timeout":   true,
		"usage_tracking.min_session_duration": true,
		"usage_tracking.daily_reset_time":     true,

		// Response modification
		"response_modification.enabled":              true,
		"response_modification.disabled_hosts":       true,
		"response_modification.allowed_content_types": true,
	}

	return keys
}

// dumpConfig dumps configuration with color highlighting for non-default values
func dumpConfig(cfg, defaultCfg *config.Config, unknownKeys []string) {
	// Setup colors (only if terminal supports it)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan, color.Bold)

	// Server
	_, _ = cyan.Println("\n[server]")
	dumpField("  dns_port", cfg.Server.DNSPort, defaultCfg.Server.DNSPort, yellow, green)
	dumpField("  dns_enable_udp", cfg.Server.DNSEnableUDP, defaultCfg.Server.DNSEnableUDP, yellow, green)
	dumpField("  dns_enable_tcp", cfg.Server.DNSEnableTCP, defaultCfg.Server.DNSEnableTCP, yellow, green)
	dumpField("  http_port", cfg.Server.HTTPPort, defaultCfg.Server.HTTPPort, yellow, green)
	dumpField("  https_port", cfg.Server.HTTPSPort, defaultCfg.Server.HTTPSPort, yellow, green)
	dumpField("  admin_domain", cfg.Server.AdminDomain, defaultCfg.Server.AdminDomain, yellow, green)
	dumpField("  metrics_port", cfg.Server.MetricsPort, defaultCfg.Server.MetricsPort, yellow, green)
	dumpField("  bind_address", cfg.Server.BindAddress, defaultCfg.Server.BindAddress, yellow, green)
	dumpField("  proxy_ip", cfg.Server.ProxyIP, defaultCfg.Server.ProxyIP, yellow, green)

	// DNS
	_, _ = cyan.Println("\n[dns]")
	dumpField("  upstream_servers", cfg.DNS.UpstreamServers, defaultCfg.DNS.UpstreamServers, yellow, green)
	dumpField("  intercept_ttl", cfg.DNS.InterceptTTL, defaultCfg.DNS.InterceptTTL, yellow, green)
	dumpField("  bypass_ttl_cap", cfg.DNS.BypassTTLCap, defaultCfg.DNS.BypassTTLCap, yellow, green)
	dumpField("  block_ttl", cfg.DNS.BlockTTL, defaultCfg.DNS.BlockTTL, yellow, green)
	dumpField("  upstream_timeout", cfg.DNS.UpstreamTimeout, defaultCfg.DNS.UpstreamTimeout, yellow, green)
	dumpField("  global_bypass", cfg.DNS.GlobalBypass, defaultCfg.DNS.GlobalBypass, yellow, green)

	// DHCP
	_, _ = cyan.Println("\n[dhcp]")
	dumpField("  enabled", cfg.DHCP.Enabled, defaultCfg.DHCP.Enabled, yellow, green)
	dumpField("  port", cfg.DHCP.Port, defaultCfg.DHCP.Port, yellow, green)
	dumpField("  bind_address", cfg.DHCP.BindAddress, defaultCfg.DHCP.BindAddress, yellow, green)
	dumpField("  server_ip", cfg.DHCP.ServerIP, defaultCfg.DHCP.ServerIP, yellow, green)
	dumpField("  subnet_mask", cfg.DHCP.SubnetMask, defaultCfg.DHCP.SubnetMask, yellow, green)
	dumpField("  gateway", cfg.DHCP.Gateway, defaultCfg.DHCP.Gateway, yellow, green)
	dumpField("  dns_servers", cfg.DHCP.DNSServers, defaultCfg.DHCP.DNSServers, yellow, green)
	dumpField("  lease_time", cfg.DHCP.LeaseTime, defaultCfg.DHCP.LeaseTime, yellow, green)
	dumpField("  range_start", cfg.DHCP.RangeStart, defaultCfg.DHCP.RangeStart, yellow, green)
	dumpField("  range_end", cfg.DHCP.RangeEnd, defaultCfg.DHCP.RangeEnd, yellow, green)
	dumpField("  boot_filename", cfg.DHCP.BootFileName, defaultCfg.DHCP.BootFileName, yellow, green)
	dumpField("  boot_server_name", cfg.DHCP.BootServerName, defaultCfg.DHCP.BootServerName, yellow, green)
	dumpField("  tftp_ip", cfg.DHCP.TFTPIP, defaultCfg.DHCP.TFTPIP, yellow, green)
	dumpField("  boot_uri", cfg.DHCP.BootURI, defaultCfg.DHCP.BootURI, yellow, green)

	// TLS
	_, _ = cyan.Println("\n[tls]")
	dumpField("  ca_cert", cfg.TLS.CACert, defaultCfg.TLS.CACert, yellow, green)
	dumpField("  ca_key", cfg.TLS.CAKey, defaultCfg.TLS.CAKey, yellow, green)
	dumpField("  intermediate_cert", cfg.TLS.IntermediateCert, defaultCfg.TLS.IntermediateCert, yellow, green)
	dumpField("  intermediate_key", cfg.TLS.IntermediateKey, defaultCfg.TLS.IntermediateKey, yellow, green)
	dumpField("  cert_cache_size", cfg.TLS.CertCacheSize, defaultCfg.TLS.CertCacheSize, yellow, green)
	dumpField("  cert_cache_ttl", cfg.TLS.CertCacheTTL, defaultCfg.TLS.CertCacheTTL, yellow, green)
	dumpField("  cert_validity", cfg.TLS.CertValidity, defaultCfg.TLS.CertValidity, yellow, green)

	// Storage
	_, _ = cyan.Println("\n[storage]")
	dumpField("  type", cfg.Storage.Type, defaultCfg.Storage.Type, yellow, green)
	_, _ = cyan.Println("  [storage.redis]")
	dumpField("    host", cfg.Storage.Redis.Host, defaultCfg.Storage.Redis.Host, yellow, green)
	dumpField("    port", cfg.Storage.Redis.Port, defaultCfg.Storage.Redis.Port, yellow, green)
	dumpField("    password", redactPassword(cfg.Storage.Redis.Password), redactPassword(defaultCfg.Storage.Redis.Password), yellow, green)
	dumpField("    db", cfg.Storage.Redis.DB, defaultCfg.Storage.Redis.DB, yellow, green)
	dumpField("    pool_size", cfg.Storage.Redis.PoolSize, defaultCfg.Storage.Redis.PoolSize, yellow, green)
	dumpField("    min_idle_conns", cfg.Storage.Redis.MinIdleConns, defaultCfg.Storage.Redis.MinIdleConns, yellow, green)
	dumpField("    dial_timeout", cfg.Storage.Redis.DialTimeout, defaultCfg.Storage.Redis.DialTimeout, yellow, green)
	dumpField("    read_timeout", cfg.Storage.Redis.ReadTimeout, defaultCfg.Storage.Redis.ReadTimeout, yellow, green)
	dumpField("    write_timeout", cfg.Storage.Redis.WriteTimeout, defaultCfg.Storage.Redis.WriteTimeout, yellow, green)

	// Logging
	_, _ = cyan.Println("\n[logging]")
	dumpField("  level", cfg.Logging.Level, defaultCfg.Logging.Level, yellow, green)
	dumpField("  format", cfg.Logging.Format, defaultCfg.Logging.Format, yellow, green)

	// Policy
	_, _ = cyan.Println("\n[policy]")
	dumpField("  default_action", cfg.Policy.DefaultAction, defaultCfg.Policy.DefaultAction, yellow, green)
	dumpField("  default_allow", cfg.Policy.DefaultAllow, defaultCfg.Policy.DefaultAllow, yellow, green)
	dumpField("  use_mac_address", cfg.Policy.UseMACAddress, defaultCfg.Policy.UseMACAddress, yellow, green)
	dumpField("  arp_cache_ttl", cfg.Policy.ARPCacheTTL, defaultCfg.Policy.ARPCacheTTL, yellow, green)
	dumpField("  opa_policy_dir", cfg.Policy.OPAPolicyDir, defaultCfg.Policy.OPAPolicyDir, yellow, green)
	dumpField("  opa_policy_source", cfg.Policy.OPAPolicySource, defaultCfg.Policy.OPAPolicySource, yellow, green)
	dumpField("  opa_policy_urls", cfg.Policy.OPAPolicyURLs, defaultCfg.Policy.OPAPolicyURLs, yellow, green)
	dumpField("  opa_http_timeout", cfg.Policy.OPAHTTPTimeout, defaultCfg.Policy.OPAHTTPTimeout, yellow, green)
	dumpField("  opa_http_retries", cfg.Policy.OPAHTTPRetries, defaultCfg.Policy.OPAHTTPRetries, yellow, green)

	// Usage
	_, _ = cyan.Println("\n[usage_tracking]")
	dumpField("  inactivity_timeout", cfg.Usage.InactivityTimeout, defaultCfg.Usage.InactivityTimeout, yellow, green)
	dumpField("  min_session_duration", cfg.Usage.MinSessionDuration, defaultCfg.Usage.MinSessionDuration, yellow, green)
	dumpField("  daily_reset_time", cfg.Usage.DailyResetTime, defaultCfg.Usage.DailyResetTime, yellow, green)

	// Response modification
	_, _ = cyan.Println("\n[response_modification]")
	dumpField("  enabled", cfg.Response.Enabled, defaultCfg.Response.Enabled, yellow, green)
	dumpField("  disabled_hosts", cfg.Response.DisabledHosts, defaultCfg.Response.DisabledHosts, yellow, green)
	dumpField("  allowed_content_types", cfg.Response.AllowedContentTypes, defaultCfg.Response.AllowedContentTypes, yellow, green)

<<<<<<< HEAD
	_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("=", 80))
=======
	// Display unknown keys if any
	if len(unknownKeys) > 0 {
		red := color.New(color.FgRed, color.Bold)
		cyan := color.New(color.FgCyan, color.Bold)

		cyan.Println("\n[UNKNOWN KEYS - These will be ignored!]")
		for _, key := range unknownKeys {
			red.Printf("  %s = (unknown key - check for typos)\n", key)
		}
	}

	fmt.Fprintln(os.Stdout, "\n" + strings.Repeat("=", 80))
>>>>>>> 68bd690 (feat: detect and highlight unknown configuration keys)
}

// dumpField prints a field with color if it differs from default
func dumpField(name string, value, defaultValue interface{}, modifiedColor, defaultColor *color.Color) {
	// Deep equal comparison
	isDefault := reflect.DeepEqual(value, defaultValue)

	valueStr := fmt.Sprintf("%v", value)

	if isDefault {
		_, _ = defaultColor.Printf("%s = %s\n", name, valueStr)
	} else {
		_, _ = modifiedColor.Printf("%s = %s  (modified from default: %v)\n", name, valueStr, defaultValue)
	}
}

// redactPassword redacts password if not empty
func redactPassword(password string) string {
	if password == "" {
		return ""
	}
	return "***REDACTED***"
}
