package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/storage/redis"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	checkSourceIP  string
	checkSourceMAC string
	checkDay       string
	checkTime      string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check policy decisions interactively",
	Long:  `Check what policy decisions KProxy would make for DNS queries or HTTP requests.`,
}

var checkDNSCmd = &cobra.Command{
	Use:   "dns [flags] DOMAIN",
	Short: "Check DNS policy decision",
	Long:  `Check what DNS action KProxy would take for a given domain and source IP.`,
	Example: `  kproxy -config config.yaml check dns -source-ip 192.168.1.100 www.example.com
  kproxy check dns -source-ip 192.168.1.100 -source-mac aa:bb:cc:dd:ee:ff youtube.com`,
	Args: cobra.ExactArgs(1),
	RunE: runCheckDNS,
}

var checkHTTPCmd = &cobra.Command{
	Use:   "http [flags] URL",
	Short: "Check HTTP/proxy policy decision",
	Long:  `Check what action KProxy would take for a given HTTP/HTTPS request.`,
	Example: `  kproxy -config config.yaml check http -source-ip 192.168.1.100 http://www.example.com/
  kproxy check http -source-ip 192.168.1.101 -day monday -time 18:30 http://www.youtube.com/watch`,
	Args: cobra.ExactArgs(1),
	RunE: runCheckHTTP,
}

func init() {
	// DNS check flags
	checkDNSCmd.Flags().StringVar(&checkSourceIP, "source-ip", "", "Source IP address (required)")
	checkDNSCmd.Flags().StringVar(&checkSourceMAC, "source-mac", "", "Source MAC address (optional)")
	checkDNSCmd.MarkFlagRequired("source-ip")

	// HTTP check flags
	checkHTTPCmd.Flags().StringVar(&checkSourceIP, "source-ip", "", "Source IP address (required)")
	checkHTTPCmd.Flags().StringVar(&checkSourceMAC, "source-mac", "", "Source MAC address (optional)")
	checkHTTPCmd.Flags().StringVar(&checkDay, "day", "", "Day of week (monday, tuesday, etc.) - defaults to current day")
	checkHTTPCmd.Flags().StringVar(&checkTime, "time", "", "Time of day (HH:MM) - defaults to current time")
	checkHTTPCmd.MarkFlagRequired("source-ip")

	// Add subcommands
	checkCmd.AddCommand(checkDNSCmd)
	checkCmd.AddCommand(checkHTTPCmd)
	rootCmd.AddCommand(checkCmd)
}

func runCheckDNS(cmd *cobra.Command, args []string) error {
	domain := args[0]

	// Parse source IP
	clientIP := net.ParseIP(checkSourceIP)
	if clientIP == nil {
		return fmt.Errorf("invalid source IP address: %s", checkSourceIP)
	}

	// Parse source MAC (optional)
	var clientMAC net.HardwareAddr
	var err error
	if checkSourceMAC != "" {
		clientMAC, err = net.ParseMAC(checkSourceMAC)
		if err != nil {
			return fmt.Errorf("invalid source MAC address: %s", checkSourceMAC)
		}
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create a quiet logger for check mode
	logger := zerolog.New(os.Stderr).Level(zerolog.ErrorLevel).With().Timestamp().Logger()

	// Initialize minimal storage (for usage tracking in policies)
	store, err := openStorage(cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()

	// Initialize Policy Engine
	opaConfig := opa.Config{
		Source:      cfg.Policy.OPAPolicySource,
		PolicyDir:   cfg.Policy.OPAPolicyDir,
		PolicyURLs:  cfg.Policy.OPAPolicyURLs,
		HTTPTimeout: parseDuration(cfg.Policy.OPAHTTPTimeout, 30*time.Second),
		HTTPRetries: cfg.Policy.OPAHTTPRetries,
	}

	policyEngine, err := policy.NewEngine(store.Usage(), opaConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Policy Engine: %w", err)
	}

	// Get DNS action
	action := policyEngine.GetDNSAction(clientIP, clientMAC, domain)

	// Display result with colors
	printDNSResult(domain, clientIP, clientMAC, action)

	return nil
}

func runCheckHTTP(cmd *cobra.Command, args []string) error {
	urlStr := args[0]

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", urlStr)
	}

	// Parse source IP
	clientIP := net.ParseIP(checkSourceIP)
	if clientIP == nil {
		return fmt.Errorf("invalid source IP address: %s", checkSourceIP)
	}

	// Parse source MAC (optional)
	var clientMAC net.HardwareAddr
	if checkSourceMAC != "" {
		clientMAC, err = net.ParseMAC(checkSourceMAC)
		if err != nil {
			return fmt.Errorf("invalid source MAC address: %s", checkSourceMAC)
		}
	}

	// Parse time (if provided)
	var checkDateTime time.Time
	if checkDay != "" || checkTime != "" {
		checkDateTime, err = parseCheckTime(checkDay, checkTime)
		if err != nil {
			return fmt.Errorf("invalid time specification: %w", err)
		}
	} else {
		checkDateTime = time.Now()
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create a quiet logger for check mode
	logger := zerolog.New(os.Stderr).Level(zerolog.ErrorLevel).With().Timestamp().Logger()

	// Initialize minimal storage (for usage tracking in policies)
	store, err := openStorage(cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer store.Close()

	// Initialize Policy Engine
	opaConfig := opa.Config{
		Source:      cfg.Policy.OPAPolicySource,
		PolicyDir:   cfg.Policy.OPAPolicyDir,
		PolicyURLs:  cfg.Policy.OPAPolicyURLs,
		HTTPTimeout: parseDuration(cfg.Policy.OPAHTTPTimeout, 30*time.Second),
		HTTPRetries: cfg.Policy.OPAHTTPRetries,
	}

	policyEngine, err := policy.NewEngine(store.Usage(), opaConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Policy Engine: %w", err)
	}

	// Set custom clock for time-based policies
	policyEngine.SetClock(&mockClock{now: checkDateTime})

	// Build proxy request
	host := parsedURL.Host
	if parsedURL.Port() == "" {
		if parsedURL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	req := &policy.ProxyRequest{
		ClientIP:  clientIP,
		ClientMAC: clientMAC,
		Host:      parsedURL.Hostname(),
		Path:      parsedURL.Path,
		Method:    "GET",
		UserAgent: "kproxy-check",
		Encrypted: parsedURL.Scheme == "https",
	}

	// Evaluate policy
	decision := policyEngine.Evaluate(req)

	// Display result with colors
	printHTTPResult(parsedURL, clientIP, clientMAC, checkDateTime, decision)

	return nil
}

// printDNSResult prints the DNS check result with colors
func printDNSResult(domain string, clientIP net.IP, clientMAC net.HardwareAddr, action policy.DNSAction) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("DNS POLICY CHECK")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	fmt.Printf("Domain:     %s\n", domain)
	fmt.Printf("Source IP:  %s\n", clientIP)
	if clientMAC != nil {
		fmt.Printf("Source MAC: %s\n", clientMAC)
	} else {
		fmt.Printf("Source MAC: (not provided)\n")
	}
	fmt.Println()

	cyan.Print("Decision:   ")
	switch action {
	case policy.DNSActionBypass:
		green.Println("BYPASS")
		fmt.Println("            → Query will be forwarded to upstream DNS")
		fmt.Println("            → Real IP address will be returned")
		fmt.Println("            → Traffic will NOT go through KProxy")
	case policy.DNSActionIntercept:
		yellow.Println("INTERCEPT")
		fmt.Println("            → KProxy IP will be returned")
		fmt.Println("            → Traffic will be routed through KProxy")
		fmt.Println("            → Proxy policies will be evaluated")
	case policy.DNSActionBlock:
		red.Println("BLOCK")
		fmt.Println("            → DNS query will be blocked")
		fmt.Println("            → 0.0.0.0 or NXDOMAIN will be returned")
	default:
		fmt.Printf("UNKNOWN (%d)\n", action)
	}

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

// printHTTPResult prints the HTTP check result with colors
func printHTTPResult(parsedURL *url.URL, clientIP net.IP, clientMAC net.HardwareAddr, checkTime time.Time, decision *policy.PolicyDecision) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("HTTP/PROXY POLICY CHECK")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	fmt.Printf("URL:        %s\n", parsedURL.String())
	fmt.Printf("Host:       %s\n", parsedURL.Hostname())
	fmt.Printf("Path:       %s\n", parsedURL.Path)
	fmt.Printf("Source IP:  %s\n", clientIP)
	if clientMAC != nil {
		fmt.Printf("Source MAC: %s\n", clientMAC)
	} else {
		fmt.Printf("Source MAC: (not provided)\n")
	}
	fmt.Printf("Check Time: %s (%s)\n", checkTime.Format("2006-01-02 15:04"), checkTime.Weekday())
	fmt.Println()

	cyan.Print("Decision:   ")
	switch decision.Action {
	case policy.ActionAllow:
		green.Println("ALLOW")
		fmt.Println("            → Request will be allowed")
	case policy.ActionBlock:
		red.Println("BLOCK")
		fmt.Println("            → Request will be blocked")
	default:
		fmt.Printf("%s\n", decision.Action)
	}

	if decision.Reason != "" {
		fmt.Printf("Reason:     %s\n", decision.Reason)
	}

	if decision.MatchedRuleID != "" {
		fmt.Printf("Matched Rule: %s\n", decision.MatchedRuleID)
	}

	if decision.Category != "" {
		fmt.Printf("Category:   %s\n", decision.Category)
	}

	if decision.UsageLimitID != "" {
		fmt.Printf("Usage Limit: %s\n", decision.UsageLimitID)
	}

	if decision.InjectTimer {
		yellow.Printf("Timer:      Yes (Time Remaining: %d minutes)\n", int(decision.TimeRemaining.Minutes()))
	}

	if decision.BlockPage != "" {
		fmt.Printf("Block Page: %s\n", decision.BlockPage)
	}

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

// parseCheckTime parses day and time flags into a time.Time
func parseCheckTime(dayStr, timeStr string) (time.Time, error) {
	now := time.Now()

	// Parse time (HH:MM)
	hour := now.Hour()
	minute := now.Minute()

	if timeStr != "" {
		parts := strings.Split(timeStr, ":")
		if len(parts) != 2 {
			return time.Time{}, fmt.Errorf("time must be in HH:MM format")
		}

		var err error
		_, err = fmt.Sscanf(timeStr, "%d:%d", &hour, &minute)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid time format: %s", timeStr)
		}

		if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
			return time.Time{}, fmt.Errorf("invalid time: hour must be 0-23, minute must be 0-59")
		}
	}

	// Parse day of week
	targetDay := now.Weekday()
	if dayStr != "" {
		dayStr = strings.ToLower(dayStr)
		switch dayStr {
		case "sunday", "sun":
			targetDay = time.Sunday
		case "monday", "mon":
			targetDay = time.Monday
		case "tuesday", "tue":
			targetDay = time.Tuesday
		case "wednesday", "wed":
			targetDay = time.Wednesday
		case "thursday", "thu":
			targetDay = time.Thursday
		case "friday", "fri":
			targetDay = time.Friday
		case "saturday", "sat":
			targetDay = time.Saturday
		default:
			return time.Time{}, fmt.Errorf("invalid day: %s", dayStr)
		}
	}

	// Calculate target date
	daysUntilTarget := int(targetDay - now.Weekday())
	if daysUntilTarget < 0 {
		daysUntilTarget += 7
	}

	targetDate := now.AddDate(0, 0, daysUntilTarget)
	result := time.Date(targetDate.Year(), targetDate.Month(), targetDate.Day(), hour, minute, 0, 0, now.Location())

	return result, nil
}

// mockClock implements policy.Clock for testing with custom time
type mockClock struct {
	now time.Time
}

func (c *mockClock) Now() time.Time {
	return c.now
}
