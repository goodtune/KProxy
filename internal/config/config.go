package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the complete application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	DNS      DNSConfig      `mapstructure:"dns"`
	DHCP     DHCPConfig     `mapstructure:"dhcp"`
	TLS      TLSConfig      `mapstructure:"tls"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Policy   PolicyConfig   `mapstructure:"policy"`
	Usage    UsageConfig    `mapstructure:"usage_tracking"`
	Response ResponseConfig `mapstructure:"response_modification"`
	Admin    AdminConfig    `mapstructure:"admin"`
}

// ServerConfig defines server ports and addresses
type ServerConfig struct {
	DNSPort      int    `mapstructure:"dns_port"`
	DNSEnableUDP bool   `mapstructure:"dns_enable_udp"`
	DNSEnableTCP bool   `mapstructure:"dns_enable_tcp"`
	HTTPPort     int    `mapstructure:"http_port"`
	HTTPSPort    int    `mapstructure:"https_port"`
	AdminPort    int    `mapstructure:"admin_port"`
	AdminDomain  string `mapstructure:"admin_domain"`
	MetricsPort  int    `mapstructure:"metrics_port"`
	BindAddress  string `mapstructure:"bind_address"`
	ProxyIP      string `mapstructure:"proxy_ip"` // IP address returned in DNS intercept responses
}

// DNSConfig defines DNS server settings
type DNSConfig struct {
	UpstreamServers []string `mapstructure:"upstream_servers"`
	InterceptTTL    uint32   `mapstructure:"intercept_ttl"`
	BypassTTLCap    uint32   `mapstructure:"bypass_ttl_cap"`
	BlockTTL        uint32   `mapstructure:"block_ttl"`
	UpstreamTimeout string   `mapstructure:"upstream_timeout"`
	GlobalBypass    []string `mapstructure:"global_bypass"`
}

// DHCPConfig defines DHCP server settings
type DHCPConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	Port           int      `mapstructure:"port"`
	BindAddress    string   `mapstructure:"bind_address"`
	ServerIP       string   `mapstructure:"server_ip"`        // DHCP server identifier
	SubnetMask     string   `mapstructure:"subnet_mask"`      // Network mask
	Gateway        string   `mapstructure:"gateway"`          // Default gateway
	DNSServers     []string `mapstructure:"dns_servers"`      // DNS servers to advertise
	LeaseTime      string   `mapstructure:"lease_time"`       // Default lease duration
	RangeStart     string   `mapstructure:"range_start"`      // Start of IP pool
	RangeEnd       string   `mapstructure:"range_end"`        // End of IP pool
	BootFileName   string   `mapstructure:"boot_filename"`    // TFTP boot filename (e.g., "pxelinux.0")
	BootServerName string   `mapstructure:"boot_server_name"` // Boot server hostname
	TFTPIP         string   `mapstructure:"tftp_ip"`          // TFTP server IP
	BootURI        string   `mapstructure:"boot_uri"`         // HTTP boot URI (UEFI HTTP boot)
}

// TLSConfig defines certificate authority settings
type TLSConfig struct {
	CACert           string `mapstructure:"ca_cert"`
	CAKey            string `mapstructure:"ca_key"`
	IntermediateCert string `mapstructure:"intermediate_cert"`
	IntermediateKey  string `mapstructure:"intermediate_key"`
	CertCacheSize    int    `mapstructure:"cert_cache_size"`
	CertCacheTTL     string `mapstructure:"cert_cache_ttl"`
	CertValidity     string `mapstructure:"cert_validity"`
}

// StorageConfig defines storage backend settings
type StorageConfig struct {
	Path string `mapstructure:"path"`
	Type string `mapstructure:"type"`
}

// LoggingConfig defines logging behavior
type LoggingConfig struct {
	Level                   string `mapstructure:"level"`
	Format                  string `mapstructure:"format"`
	RequestLogRetentionDays int    `mapstructure:"request_log_retention_days"`
}

// PolicyConfig defines policy engine defaults
type PolicyConfig struct {
	DefaultAction    string   `mapstructure:"default_action"`
	DefaultAllow     bool     `mapstructure:"default_allow"`
	UseMACAddress    bool     `mapstructure:"use_mac_address"`
	ARPCacheTTL      string   `mapstructure:"arp_cache_ttl"`
	OPAPolicyDir     string   `mapstructure:"opa_policy_dir"`
	OPAPolicySource  string   `mapstructure:"opa_policy_source"`  // "filesystem" or "remote"
	OPAPolicyURLs    []string `mapstructure:"opa_policy_urls"`    // URLs for remote policies
	OPAHTTPTimeout   string   `mapstructure:"opa_http_timeout"`   // Timeout for HTTP requests
	OPAHTTPRetries   int      `mapstructure:"opa_http_retries"`   // Number of retries
}

// UsageConfig defines usage tracking settings
type UsageConfig struct {
	InactivityTimeout  string `mapstructure:"inactivity_timeout"`
	MinSessionDuration string `mapstructure:"min_session_duration"`
	DailyResetTime     string `mapstructure:"daily_reset_time"`
}

// ResponseConfig defines response modification settings
type ResponseConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	DisabledHosts       []string `mapstructure:"disabled_hosts"`
	AllowedContentTypes []string `mapstructure:"allowed_content_types"`
}

// AdminConfig defines admin interface settings
type AdminConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Port            int    `mapstructure:"port"`
	BindAddress     string `mapstructure:"bind_address"`
	InitialUsername string `mapstructure:"initial_username"`
	InitialPassword string `mapstructure:"initial_password"`
	JWTSecret       string `mapstructure:"jwt_secret"`
	SessionTimeout  string `mapstructure:"session_timeout"`
	RateLimit       int    `mapstructure:"rate_limit"`
	RateLimitWindow string `mapstructure:"rate_limit_window"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure viper
	v.SetConfigFile(configPath)
	v.SetEnvPrefix("KPROXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults and environment variables
	}

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate config
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.dns_port", 53)
	v.SetDefault("server.dns_enable_udp", true)
	v.SetDefault("server.dns_enable_tcp", true)
	v.SetDefault("server.http_port", 80)
	v.SetDefault("server.https_port", 443)
	v.SetDefault("server.admin_port", 8443)
	v.SetDefault("server.admin_domain", "kproxy.home.local")
	v.SetDefault("server.metrics_port", 9090)
	v.SetDefault("server.bind_address", "0.0.0.0")

	// DNS defaults
	v.SetDefault("dns.upstream_servers", []string{"8.8.8.8:53", "1.1.1.1:53"})
	v.SetDefault("dns.intercept_ttl", 60)
	v.SetDefault("dns.bypass_ttl_cap", 300)
	v.SetDefault("dns.block_ttl", 60)
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
	v.SetDefault("storage.path", "/var/lib/kproxy/kproxy.bolt")
	v.SetDefault("storage.type", "bolt")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.request_log_retention_days", 30)

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

	// Admin defaults
	v.SetDefault("admin.initial_username", "admin")
	v.SetDefault("admin.initial_password", "changeme")
	v.SetDefault("admin.session_timeout", "24h")
	v.SetDefault("admin.rate_limit", 100)
}

// validate validates the configuration
func validate(cfg *Config) error {
	// Validate required fields
	if cfg.Server.DNSPort <= 0 || cfg.Server.DNSPort > 65535 {
		return fmt.Errorf("invalid DNS port: %d", cfg.Server.DNSPort)
	}
	if cfg.Server.HTTPPort <= 0 || cfg.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.HTTPSPort <= 0 || cfg.Server.HTTPSPort > 65535 {
		return fmt.Errorf("invalid HTTPS port: %d", cfg.Server.HTTPSPort)
	}

	// Validate upstream DNS servers
	if len(cfg.DNS.UpstreamServers) == 0 {
		return fmt.Errorf("at least one upstream DNS server is required")
	}

	// Validate storage path
	if cfg.Storage.Path == "" {
		return fmt.Errorf("storage path is required")
	}

	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "bolt"
	}

	// Ensure storage directory exists
	storageDir := filepath.Dir(cfg.Storage.Path)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	return nil
}
