package main

import (
	"context"
	"encoding/json"
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
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	checkSourceIP  string
	checkSourceMAC string
	checkDay       string
	checkTime      string
	checkMethod    string
	checkUsage     string
	checkShowFacts bool
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
  kproxy check http -source-ip 192.168.1.101 -day monday -time 18:30 http://www.youtube.com/watch
  kproxy check http -source-ip 192.168.1.101 -method POST -usage "entertainment=45,gaming=30" https://youtube.com/`,
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
	checkHTTPCmd.Flags().StringVar(&checkMethod, "method", "GET", "HTTP method (GET, POST, PUT, DELETE, etc.)")
	checkHTTPCmd.Flags().StringVar(&checkUsage, "usage", "", "Current usage in minutes per category (e.g., 'entertainment=45,gaming=30,educational=15')")
	checkHTTPCmd.Flags().BoolVar(&checkShowFacts, "show-facts", false, "Show the complete facts/input sent to OPA for evaluation")
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

	// Initialize OPA engine directly (DNS doesn't need storage/usage data)
	opaConfig := opa.Config{
		Source:      cfg.Policy.OPAPolicySource,
		PolicyDir:   cfg.Policy.OPAPolicyDir,
		PolicyURLs:  cfg.Policy.OPAPolicyURLs,
		HTTPTimeout: parseDuration(cfg.Policy.OPAHTTPTimeout, 30*time.Second),
		HTTPRetries: cfg.Policy.OPAHTTPRetries,
	}

	opaEngine, err := opa.NewEngine(opaConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize OPA engine: %w", err)
	}

	// Build DNS facts
	clientMACStr := ""
	if clientMAC != nil {
		clientMACStr = clientMAC.String()
	}

	facts := map[string]interface{}{
		"client_ip":  clientIP.String(),
		"client_mac": clientMACStr,
		"domain":     domain,
	}

	// Evaluate with OPA
	ctx := context.Background()
	actionStr, err := opaEngine.EvaluateDNS(ctx, facts)
	if err != nil {
		return fmt.Errorf("OPA evaluation failed: %w", err)
	}

	// Convert string action to DNSAction
	var action policy.DNSAction
	switch actionStr {
	case "BYPASS":
		action = policy.DNSActionBypass
	case "BLOCK":
		action = policy.DNSActionBlock
	case "INTERCEPT":
		action = policy.DNSActionIntercept
	default:
		return fmt.Errorf("unknown DNS action from OPA: %s", actionStr)
	}

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

	// Parse usage data (if provided)
	usageData, err := parseUsageData(checkUsage)
	if err != nil {
		return fmt.Errorf("invalid usage data: %w", err)
	}

	// Validate method
	method := strings.ToUpper(checkMethod)
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
	}
	if !validMethods[method] {
		return fmt.Errorf("invalid HTTP method: %s", checkMethod)
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create a quiet logger for check mode
	logger := zerolog.New(os.Stderr).Level(zerolog.ErrorLevel).With().Timestamp().Logger()

	// Initialize OPA engine directly (no storage needed if we're providing usage data)
	opaConfig := opa.Config{
		Source:      cfg.Policy.OPAPolicySource,
		PolicyDir:   cfg.Policy.OPAPolicyDir,
		PolicyURLs:  cfg.Policy.OPAPolicyURLs,
		HTTPTimeout: parseDuration(cfg.Policy.OPAHTTPTimeout, 30*time.Second),
		HTTPRetries: cfg.Policy.OPAHTTPRetries,
	}

	opaEngine, err := opa.NewEngine(opaConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize OPA engine: %w", err)
	}

	// Build facts manually (bypassing the policy engine's fact gathering)
	clientMACStr := ""
	if clientMAC != nil {
		clientMACStr = clientMAC.String()
	}

	currentTime := map[string]interface{}{
		"day_of_week": int(checkDateTime.Weekday()),
		"hour":        checkDateTime.Hour(),
		"minute":      checkDateTime.Minute(),
	}

	facts := map[string]interface{}{
		"client_ip":  clientIP.String(),
		"client_mac": clientMACStr,
		"host":       parsedURL.Hostname(),
		"path":       parsedURL.Path,
		"method":     method,
		"time":       currentTime,
		"usage":      usageData,
	}

	// Display facts being sent to OPA (if requested)
	if checkShowFacts {
		printFacts(facts)
	}

	// Evaluate with OPA directly
	ctx := context.Background()
	opaDecision, err := opaEngine.EvaluateProxy(ctx, facts)
	if err != nil {
		return fmt.Errorf("OPA evaluation failed: %w", err)
	}

	// Convert OPA decision to PolicyDecision
	decision := &policy.PolicyDecision{
		Action:        policy.Action(opaDecision.Action),
		Reason:        opaDecision.Reason,
		BlockPage:     opaDecision.BlockPage,
		MatchedRuleID: opaDecision.MatchedRuleID,
		Category:      opaDecision.Category,
		InjectTimer:   opaDecision.InjectTimer,
		TimeRemaining: time.Duration(opaDecision.TimeRemainingMinutes) * time.Minute,
		UsageLimitID:  opaDecision.UsageLimitID,
	}

	// Display result with colors
	printHTTPResult(parsedURL, clientIP, clientMAC, checkDateTime, method, usageData, decision)

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

// parseUsageData parses the usage flag into a map of category usage
func parseUsageData(usageStr string) (map[string]interface{}, error) {
	// Default categories with 0 usage
	usageData := map[string]interface{}{
		"educational":  map[string]interface{}{"today_minutes": 0},
		"entertainment": map[string]interface{}{"today_minutes": 0},
		"social-media":  map[string]interface{}{"today_minutes": 0},
		"gaming":        map[string]interface{}{"today_minutes": 0},
	}

	if usageStr == "" {
		return usageData, nil
	}

	// Parse comma-separated key=value pairs
	pairs := strings.Split(usageStr, ",")
	for _, pair := range pairs {
		parts := strings.Split(strings.TrimSpace(pair), "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid usage format: %s (expected 'category=minutes')", pair)
		}

		category := strings.TrimSpace(parts[0])
		minutesStr := strings.TrimSpace(parts[1])

		var minutes int
		_, err := fmt.Sscanf(minutesStr, "%d", &minutes)
		if err != nil {
			return nil, fmt.Errorf("invalid minutes value for category %s: %s", category, minutesStr)
		}

		if minutes < 0 {
			return nil, fmt.Errorf("minutes cannot be negative for category %s", category)
		}

		usageData[category] = map[string]interface{}{
			"today_minutes": minutes,
		}
	}

	return usageData, nil
}

// printHTTPResult prints the HTTP check result with colors
func printHTTPResult(parsedURL *url.URL, clientIP net.IP, clientMAC net.HardwareAddr, checkTime time.Time, method string, usageData map[string]interface{}, decision *policy.PolicyDecision) {
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
	fmt.Printf("Method:     %s\n", method)
	fmt.Printf("Source IP:  %s\n", clientIP)
	if clientMAC != nil {
		fmt.Printf("Source MAC: %s\n", clientMAC)
	} else {
		fmt.Printf("Source MAC: (not provided)\n")
	}
	fmt.Printf("Check Time: %s (%s)\n", checkTime.Format("2006-01-02 15:04"), checkTime.Weekday())

	// Display usage data if any non-zero values
	hasUsage := false
	for _, v := range usageData {
		if usageMap, ok := v.(map[string]interface{}); ok {
			if minutes, ok := usageMap["today_minutes"].(int); ok && minutes > 0 {
				hasUsage = true
				break
			}
		}
	}

	if hasUsage {
		fmt.Printf("Usage:      ")
		first := true
		for category, v := range usageData {
			if usageMap, ok := v.(map[string]interface{}); ok {
				if minutes, ok := usageMap["today_minutes"].(int); ok && minutes > 0 {
					if !first {
						fmt.Printf(", ")
					}
					fmt.Printf("%s=%dm", category, minutes)
					first = false
				}
			}
		}
		fmt.Println()
	}

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

// printFacts prints the facts being sent to OPA (for debugging)
func printFacts(facts map[string]interface{}) {
	cyan := color.New(color.FgCyan, color.Bold)
	gray := color.New(color.FgHiBlack)

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("OPA INPUT (facts sent to policy evaluation)")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Pretty print the facts
	gray.Println("JSON representation:")
	jsonBytes, _ := json.MarshalIndent(facts, "", "  ")
	fmt.Println(string(jsonBytes))

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}
