package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/database"
)

// UsageTracker interface for usage tracking
type UsageTracker interface {
	RecordActivity(deviceID, limitID string) error
	GetUsageStats(deviceID, limitID string, dailyLimit time.Duration, resetTime time.Time) (*UsageStats, error)
}

// UsageStats represents current usage statistics
type UsageStats struct {
	TodayUsage     time.Duration
	RemainingToday time.Duration
	LimitExceeded  bool
}

// Engine handles policy evaluation and enforcement
type Engine struct {
	db            *database.DB
	devices       map[string]*Device
	devicesByMAC  map[string]*Device
	profiles      map[string]*Profile
	bypassRules   []*BypassRule
	globalBypass  []string
	defaultAction Action
	useMACAddress bool
	usageTracker  UsageTracker
	mu            sync.RWMutex
}

// NewEngine creates a new policy engine
func NewEngine(db *database.DB, globalBypass []string, defaultAction string, useMACAddress bool) (*Engine, error) {
	e := &Engine{
		db:            db,
		devices:       make(map[string]*Device),
		devicesByMAC:  make(map[string]*Device),
		profiles:      make(map[string]*Profile),
		bypassRules:   make([]*BypassRule, 0),
		globalBypass:  globalBypass,
		useMACAddress: useMACAddress,
	}

	// Set default action
	switch strings.ToUpper(defaultAction) {
	case "ALLOW":
		e.defaultAction = ActionAllow
	case "BLOCK":
		e.defaultAction = ActionBlock
	default:
		e.defaultAction = ActionBlock
	}

	// Load initial data
	if err := e.Reload(); err != nil {
		return nil, fmt.Errorf("failed to load initial policy data: %w", err)
	}

	return e, nil
}

// Reload reloads all policy data from the database
func (e *Engine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Load devices
	if err := e.loadDevices(); err != nil {
		return fmt.Errorf("failed to load devices: %w", err)
	}

	// Load profiles
	if err := e.loadProfiles(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Load bypass rules
	if err := e.loadBypassRules(); err != nil {
		return fmt.Errorf("failed to load bypass rules: %w", err)
	}

	return nil
}

// loadDevices loads all devices from the database
func (e *Engine) loadDevices() error {
	rows, err := e.db.Query(`
		SELECT id, name, identifiers, profile_id, active, created_at, updated_at
		FROM devices
		WHERE active = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	devices := make(map[string]*Device)
	devicesByMAC := make(map[string]*Device)

	for rows.Next() {
		var device Device
		var identifiersJSON string
		var active int

		err := rows.Scan(
			&device.ID,
			&device.Name,
			&identifiersJSON,
			&device.ProfileID,
			&active,
			&device.CreatedAt,
			&device.UpdatedAt,
		)
		if err != nil {
			return err
		}

		device.Active = active == 1

		// Parse identifiers
		if err := json.Unmarshal([]byte(identifiersJSON), &device.Identifiers); err != nil {
			return fmt.Errorf("failed to parse identifiers for device %s: %w", device.ID, err)
		}

		devices[device.ID] = &device

		// Index by MAC address
		for _, identifier := range device.Identifiers {
			if isMACAddress(identifier) {
				devicesByMAC[strings.ToLower(identifier)] = &device
			}
		}
	}

	e.devices = devices
	e.devicesByMAC = devicesByMAC

	return nil
}

// loadProfiles loads all profiles with their rules
func (e *Engine) loadProfiles() error {
	rows, err := e.db.Query(`
		SELECT id, name, default_allow, created_at, updated_at
		FROM profiles
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	profiles := make(map[string]*Profile)

	for rows.Next() {
		var profile Profile
		var defaultAllow int

		err := rows.Scan(
			&profile.ID,
			&profile.Name,
			&defaultAllow,
			&profile.CreatedAt,
			&profile.UpdatedAt,
		)
		if err != nil {
			return err
		}

		profile.DefaultAllow = defaultAllow == 1

		// Load rules for this profile
		if err := e.loadProfileRules(&profile); err != nil {
			return fmt.Errorf("failed to load rules for profile %s: %w", profile.ID, err)
		}

		// Load time rules
		if err := e.loadProfileTimeRules(&profile); err != nil {
			return fmt.Errorf("failed to load time rules for profile %s: %w", profile.ID, err)
		}

		// Load usage limits
		if err := e.loadProfileUsageLimits(&profile); err != nil {
			return fmt.Errorf("failed to load usage limits for profile %s: %w", profile.ID, err)
		}

		profiles[profile.ID] = &profile
	}

	e.profiles = profiles
	return nil
}

// loadProfileRules loads rules for a specific profile
func (e *Engine) loadProfileRules(profile *Profile) error {
	rows, err := e.db.Query(`
		SELECT id, domain, paths, action, priority, category, inject_timer
		FROM rules
		WHERE profile_id = ?
		ORDER BY priority DESC
	`, profile.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var rule Rule
		var pathsJSON sql.NullString
		var injectTimer int

		err := rows.Scan(
			&rule.ID,
			&rule.Domain,
			&pathsJSON,
			&rule.Action,
			&rule.Priority,
			&rule.Category,
			&injectTimer,
		)
		if err != nil {
			return err
		}

		rule.InjectTimer = injectTimer == 1

		// Parse paths
		if pathsJSON.Valid && pathsJSON.String != "" {
			if err := json.Unmarshal([]byte(pathsJSON.String), &rule.Paths); err != nil {
				return fmt.Errorf("failed to parse paths for rule %s: %w", rule.ID, err)
			}
		}

		rules = append(rules, rule)
	}

	profile.Rules = rules
	return nil
}

// loadProfileTimeRules loads time rules for a specific profile
func (e *Engine) loadProfileTimeRules(profile *Profile) error {
	rows, err := e.db.Query(`
		SELECT id, days_of_week, start_time, end_time, rule_ids
		FROM time_rules
		WHERE profile_id = ?
	`, profile.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var timeRules []TimeRule
	for rows.Next() {
		var timeRule TimeRule
		var daysJSON, ruleIDsJSON string

		err := rows.Scan(
			&timeRule.ID,
			&daysJSON,
			&timeRule.StartTime,
			&timeRule.EndTime,
			&ruleIDsJSON,
		)
		if err != nil {
			return err
		}

		// Parse days of week
		if err := json.Unmarshal([]byte(daysJSON), &timeRule.DaysOfWeek); err != nil {
			return fmt.Errorf("failed to parse days_of_week for time rule %s: %w", timeRule.ID, err)
		}

		// Parse rule IDs
		if ruleIDsJSON != "" {
			if err := json.Unmarshal([]byte(ruleIDsJSON), &timeRule.RuleIDs); err != nil {
				return fmt.Errorf("failed to parse rule_ids for time rule %s: %w", timeRule.ID, err)
			}
		}

		timeRules = append(timeRules, timeRule)
	}

	profile.TimeRules = timeRules
	return nil
}

// loadProfileUsageLimits loads usage limits for a specific profile
func (e *Engine) loadProfileUsageLimits(profile *Profile) error {
	rows, err := e.db.Query(`
		SELECT id, category, domains, daily_minutes, reset_time, inject_timer
		FROM usage_limits
		WHERE profile_id = ?
	`, profile.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var usageLimits []UsageLimit
	for rows.Next() {
		var limit UsageLimit
		var domainsJSON sql.NullString
		var injectTimer int

		err := rows.Scan(
			&limit.ID,
			&limit.Category,
			&domainsJSON,
			&limit.DailyMinutes,
			&limit.ResetTime,
			&injectTimer,
		)
		if err != nil {
			return err
		}

		limit.InjectTimer = injectTimer == 1

		// Parse domains
		if domainsJSON.Valid && domainsJSON.String != "" {
			if err := json.Unmarshal([]byte(domainsJSON.String), &limit.Domains); err != nil {
				return fmt.Errorf("failed to parse domains for usage limit %s: %w", limit.ID, err)
			}
		}

		usageLimits = append(usageLimits, limit)
	}

	profile.UsageLimits = usageLimits
	return nil
}

// loadBypassRules loads all bypass rules
func (e *Engine) loadBypassRules() error {
	rows, err := e.db.Query(`
		SELECT id, domain, reason, enabled, device_ids
		FROM bypass_rules
		WHERE enabled = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var bypassRules []*BypassRule
	for rows.Next() {
		var rule BypassRule
		var deviceIDsJSON sql.NullString
		var enabled int

		err := rows.Scan(
			&rule.ID,
			&rule.Domain,
			&rule.Reason,
			&enabled,
			&deviceIDsJSON,
		)
		if err != nil {
			return err
		}

		rule.Enabled = enabled == 1

		// Parse device IDs
		if deviceIDsJSON.Valid && deviceIDsJSON.String != "" {
			if err := json.Unmarshal([]byte(deviceIDsJSON.String), &rule.DeviceIDs); err != nil {
				return fmt.Errorf("failed to parse device_ids for bypass rule %s: %w", rule.ID, err)
			}
		}

		bypassRules = append(bypassRules, &rule)
	}

	e.bypassRules = bypassRules
	return nil
}

// IdentifyDevice identifies a device by IP address or MAC address
func (e *Engine) IdentifyDevice(clientIP net.IP, clientMAC net.HardwareAddr) *Device {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.identifyDevice(clientIP, clientMAC)
}

// identifyDevice is the internal implementation (requires lock)
func (e *Engine) identifyDevice(clientIP net.IP, clientMAC net.HardwareAddr) *Device {
	// Try MAC address first (most reliable)
	if clientMAC != nil && e.useMACAddress {
		if device := e.devicesByMAC[strings.ToLower(clientMAC.String())]; device != nil {
			return device
		}
	}

	// Fall back to IP address
	for _, device := range e.devices {
		for _, identifier := range device.Identifiers {
			// Check if it's a CIDR range
			if strings.Contains(identifier, "/") {
				if ipRange, err := netip.ParsePrefix(identifier); err == nil {
					clientAddr, err := netip.ParseAddr(clientIP.String())
					if err == nil && ipRange.Contains(clientAddr) {
						return device
					}
				}
			} else if identifier == clientIP.String() {
				return device
			}
		}
	}

	return nil
}

// GetDNSAction determines the DNS action for a query
func (e *Engine) GetDNSAction(clientIP net.IP, domain string) DNSAction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	device := e.identifyDevice(clientIP, nil)

	// 1. Check global bypass list (system-critical domains)
	if e.isGlobalBypass(domain) {
		return DNSActionBypass
	}

	// 2. Check device-specific bypass rules
	if device != nil {
		for _, rule := range e.bypassRules {
			if !rule.Enabled {
				continue
			}
			if len(rule.DeviceIDs) > 0 && !contains(rule.DeviceIDs, device.ID) {
				continue
			}
			if e.matchDomain(domain, rule.Domain) {
				return DNSActionBypass
			}
		}
	}

	// 3. Default: intercept and route through proxy
	return DNSActionIntercept
}

// isGlobalBypass checks if a domain matches the global bypass list
func (e *Engine) isGlobalBypass(domain string) bool {
	for _, pattern := range e.globalBypass {
		if e.matchDomain(domain, pattern) {
			return true
		}
	}
	return false
}

// matchDomain checks if a domain matches a pattern (with wildcard support)
func (e *Engine) matchDomain(domain, pattern string) bool {
	// Normalize both to lowercase
	domain = strings.ToLower(domain)
	pattern = strings.ToLower(pattern)

	// Exact match
	if domain == pattern {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		matched, err := regexp.MatchString(regexPattern, domain)
		if err == nil && matched {
			return true
		}
	}

	// Suffix matching (e.g., pattern ".example.com" matches "sub.example.com")
	if strings.HasPrefix(pattern, ".") {
		if domain == pattern[1:] || strings.HasSuffix(domain, pattern) {
			return true
		}
	}

	return false
}

// SetUsageTracker sets the usage tracker for the policy engine
func (e *Engine) SetUsageTracker(tracker UsageTracker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.usageTracker = tracker
}

// Evaluate evaluates a proxy request against the policy
func (e *Engine) Evaluate(req *ProxyRequest) *PolicyDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	device := e.identifyDevice(req.ClientIP, req.ClientMAC)
	if device == nil {
		return &PolicyDecision{
			Action: e.defaultAction,
			Reason: "unknown device",
		}
	}

	profile := e.profiles[device.ProfileID]
	if profile == nil {
		return &PolicyDecision{
			Action: e.defaultAction,
			Reason: "no profile assigned",
		}
	}

	// 1. Check time-of-access rules
	if !e.isWithinAllowedTime(profile, time.Now()) {
		return &PolicyDecision{
			Action:    ActionBlock,
			Reason:    "outside allowed hours",
			BlockPage: "time_restriction",
		}
	}

	// 2. Evaluate domain/path rules (already sorted by priority)
	for _, rule := range profile.Rules {
		if e.matchesRule(req.Host, req.Path, &rule) {
			// 3. If allowing, check usage limits for this rule's category
			if rule.Action == ActionAllow {
				limitDecision := e.checkUsageLimits(device, profile, req.Host, rule.Category)
				if limitDecision != nil {
					return limitDecision
				}
			}

			return &PolicyDecision{
				Action:        rule.Action,
				Reason:        fmt.Sprintf("matched rule: %s", rule.ID),
				MatchedRuleID: rule.ID,
				Category:      rule.Category,
				InjectTimer:   rule.InjectTimer,
			}
		}
	}

	// 4. Apply default action
	if profile.DefaultAllow {
		return &PolicyDecision{Action: ActionAllow, Reason: "default allow"}
	}
	return &PolicyDecision{Action: ActionBlock, Reason: "default deny", BlockPage: "default_block"}
}

// checkUsageLimits checks if usage limits are exceeded
func (e *Engine) checkUsageLimits(device *Device, profile *Profile, host, category string) *PolicyDecision {
	if e.usageTracker == nil {
		return nil // Usage tracking not enabled
	}

	for _, limit := range profile.UsageLimits {
		// Check if this limit applies to the current request
		if !e.limitApplies(&limit, host, category) {
			continue
		}

		// Parse reset time
		resetTime, err := time.Parse("15:04", limit.ResetTime)
		if err != nil {
			resetTime = time.Time{} // Default to midnight
		}

		// Get usage stats
		limitDuration := time.Duration(limit.DailyMinutes) * time.Minute
		stats, err := e.usageTracker.GetUsageStats(device.ID, limit.ID, limitDuration, resetTime)
		if err != nil {
			// Log error but don't block on tracking errors
			continue
		}

		// Check if limit is exceeded
		if stats.LimitExceeded {
			return &PolicyDecision{
				Action:       ActionBlock,
				Reason:       fmt.Sprintf("daily usage limit exceeded: %v/%v used", stats.TodayUsage.Round(time.Minute), limitDuration),
				BlockPage:    "usage_limit",
				Category:     category,
				UsageLimitID: limit.ID,
			}
		}

		// Record activity for this limit
		if err := e.usageTracker.RecordActivity(device.ID, limit.ID); err != nil {
			// Log error but don't block on tracking errors
		}

		// Return decision with usage info for timer injection
		return &PolicyDecision{
			Action:        ActionAllow,
			Reason:        fmt.Sprintf("usage limit: %v remaining of %v", stats.RemainingToday.Round(time.Minute), limitDuration),
			InjectTimer:   limit.InjectTimer,
			TimeRemaining: stats.RemainingToday,
			Category:      category,
			UsageLimitID:  limit.ID,
		}
	}

	return nil
}

// limitApplies checks if a usage limit applies to the current request
func (e *Engine) limitApplies(limit *UsageLimit, host, category string) bool {
	// Check if limit matches by category
	if limit.Category != "" && limit.Category == category {
		return true
	}

	// Check if limit matches by specific domain
	for _, domain := range limit.Domains {
		if e.matchDomain(host, domain) {
			return true
		}
	}

	return false
}

// matchesRule checks if a request matches a rule
func (e *Engine) matchesRule(host, path string, rule *Rule) bool {
	// Domain matching
	if !e.matchDomain(host, rule.Domain) {
		return false
	}

	// Path matching
	if len(rule.Paths) == 0 || contains(rule.Paths, "*") {
		return true
	}

	for _, rulePath := range rule.Paths {
		if strings.HasPrefix(path, rulePath) {
			return true
		}
		// Also support glob-style matching
		if matched, _ := filepath.Match(rulePath, path); matched {
			return true
		}
	}

	return false
}

// isWithinAllowedTime checks if current time is within allowed time windows
func (e *Engine) isWithinAllowedTime(profile *Profile, now time.Time) bool {
	if len(profile.TimeRules) == 0 {
		return true // No time restrictions
	}

	weekday := int(now.Weekday())

	for _, timeRule := range profile.TimeRules {
		// Check if current day is in allowed days
		if !containsInt(timeRule.DaysOfWeek, weekday) {
			continue
		}

		// Parse start and end times
		startTime, err := parseTimeOfDay(timeRule.StartTime)
		if err != nil {
			continue
		}

		endTime, err := parseTimeOfDay(timeRule.EndTime)
		if err != nil {
			continue
		}

		// Get current time of day
		currentTime := now.Hour()*60 + now.Minute()

		// Check if within time window
		if currentTime >= startTime && currentTime < endTime {
			return true
		}
	}

	return false
}

// Helper functions

func isMACAddress(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

func parseTimeOfDay(timeStr string) (int, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format: %s", timeStr)
	}

	var hour, minute int
	if _, err := fmt.Sscanf(timeStr, "%d:%d", &hour, &minute); err != nil {
		return 0, err
	}

	return hour*60 + minute, nil
}
