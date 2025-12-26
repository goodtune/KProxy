package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
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
	deviceStore   storage.DeviceStore
	profileStore  storage.ProfileStore
	ruleStore     storage.RuleStore
	timeRuleStore storage.TimeRuleStore
	limitStore    storage.UsageLimitStore
	bypassStore   storage.BypassRuleStore
	devices       map[string]*Device
	devicesByMAC  map[string]*Device
	profiles      map[string]*Profile
	bypassRules   []*BypassRule
	globalBypass  []string
	defaultAction Action
	useMACAddress bool
	usageTracker  UsageTracker
	logger        zerolog.Logger
	mu            sync.RWMutex

	// OPA engine for policy evaluation
	opaEngine *opa.Engine
	policyDir string
}

// NewEngine creates a new policy engine
func NewEngine(store storage.Store, globalBypass []string, defaultAction string, useMACAddress bool, policyDir string, logger zerolog.Logger) (*Engine, error) {
	e := &Engine{
		deviceStore:   store.Devices(),
		profileStore:  store.Profiles(),
		ruleStore:     store.Rules(),
		timeRuleStore: store.TimeRules(),
		limitStore:    store.UsageLimits(),
		bypassStore:   store.BypassRules(),
		devices:       make(map[string]*Device),
		devicesByMAC:  make(map[string]*Device),
		profiles:      make(map[string]*Profile),
		bypassRules:   make([]*BypassRule, 0),
		globalBypass:  globalBypass,
		useMACAddress: useMACAddress,
		policyDir:     policyDir,
		logger:        logger.With().Str("component", "policy").Logger(),
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

	// Initialize OPA engine
	opaEngine, err := opa.NewEngine(policyDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OPA engine: %w", err)
	}
	e.opaEngine = opaEngine

	// Load initial data
	if err := e.Reload(); err != nil {
		return nil, fmt.Errorf("failed to load initial policy data: %w", err)
	}

	return e, nil
}

// Reload reloads all policy data from storage
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

// loadDevices loads all devices from storage
func (e *Engine) loadDevices() error {
	ctx := context.Background()
	storedDevices, err := e.deviceStore.ListActive(ctx)
	if err != nil {
		return err
	}

	devices := make(map[string]*Device)
	devicesByMAC := make(map[string]*Device)

	for _, storedDevice := range storedDevices {
		device := Device{
			ID:          storedDevice.ID,
			Name:        storedDevice.Name,
			Identifiers: storedDevice.Identifiers,
			ProfileID:   storedDevice.ProfileID,
			Active:      storedDevice.Active,
			CreatedAt:   storedDevice.CreatedAt,
			UpdatedAt:   storedDevice.UpdatedAt,
		}

		devices[device.ID] = &device

		// Index by MAC address
		for _, identifier := range device.Identifiers {
			if isMACAddress(identifier) {
				devicesByMAC[strings.ToLower(identifier)] = &device
			}
		}

		e.logger.Info().
			Str("device_id", device.ID).
			Str("device_name", device.Name).
			Strs("identifiers", device.Identifiers).
			Str("profile_id", device.ProfileID).
			Msg("Loaded device")
	}

	e.devices = devices
	e.devicesByMAC = devicesByMAC

	e.logger.Info().
		Int("total_devices", len(devices)).
		Int("devices_with_mac", len(devicesByMAC)).
		Msg("Device loading complete")

	return nil
}

// loadProfiles loads all profiles with their rules
func (e *Engine) loadProfiles() error {
	ctx := context.Background()
	storedProfiles, err := e.profileStore.List(ctx)
	if err != nil {
		return err
	}

	profiles := make(map[string]*Profile)

	for _, storedProfile := range storedProfiles {
		profile := Profile{
			ID:           storedProfile.ID,
			Name:         storedProfile.Name,
			DefaultAllow: storedProfile.DefaultAllow,
			CreatedAt:    storedProfile.CreatedAt,
			UpdatedAt:    storedProfile.UpdatedAt,
		}

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
	ctx := context.Background()
	storedRules, err := e.ruleStore.ListByProfile(ctx, profile.ID)
	if err != nil {
		return err
	}

	rules := make([]Rule, 0, len(storedRules))
	for _, storedRule := range storedRules {
		rule := Rule{
			ID:          storedRule.ID,
			Domain:      storedRule.Domain,
			Paths:       storedRule.Paths,
			Action:      Action(storedRule.Action), // Convert from storage.Action to policy.Action
			Priority:    storedRule.Priority,
			Category:    storedRule.Category,
			InjectTimer: storedRule.InjectTimer,
		}
		rules = append(rules, rule)

		e.logger.Info().
			Str("profile_id", profile.ID).
			Str("rule_id", rule.ID).
			Str("domain", rule.Domain).
			Str("action", string(rule.Action)).
			Int("priority", rule.Priority).
			Msg("Loaded rule")
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	profile.Rules = rules

	e.logger.Info().
		Str("profile_id", profile.ID).
		Str("profile_name", profile.Name).
		Int("total_rules", len(rules)).
		Bool("default_allow", profile.DefaultAllow).
		Msg("Profile rules loaded")

	return nil
}

// loadProfileTimeRules loads time rules for a specific profile
func (e *Engine) loadProfileTimeRules(profile *Profile) error {
	ctx := context.Background()
	storedRules, err := e.timeRuleStore.ListByProfile(ctx, profile.ID)
	if err != nil {
		return err
	}

	timeRules := make([]TimeRule, 0, len(storedRules))
	for _, storedRule := range storedRules {
		timeRules = append(timeRules, TimeRule{
			ID:         storedRule.ID,
			DaysOfWeek: storedRule.DaysOfWeek,
			StartTime:  storedRule.StartTime,
			EndTime:    storedRule.EndTime,
			RuleIDs:    storedRule.RuleIDs,
		})
	}

	profile.TimeRules = timeRules
	return nil
}

// loadProfileUsageLimits loads usage limits for a specific profile
func (e *Engine) loadProfileUsageLimits(profile *Profile) error {
	ctx := context.Background()
	storedLimits, err := e.limitStore.ListByProfile(ctx, profile.ID)
	if err != nil {
		return err
	}

	usageLimits := make([]UsageLimit, 0, len(storedLimits))
	for _, storedLimit := range storedLimits {
		usageLimits = append(usageLimits, UsageLimit{
			ID:           storedLimit.ID,
			Category:     storedLimit.Category,
			Domains:      storedLimit.Domains,
			DailyMinutes: storedLimit.DailyMinutes,
			ResetTime:    storedLimit.ResetTime,
			InjectTimer:  storedLimit.InjectTimer,
		})
	}

	profile.UsageLimits = usageLimits
	return nil
}

// loadBypassRules loads all bypass rules
func (e *Engine) loadBypassRules() error {
	ctx := context.Background()
	storedRules, err := e.bypassStore.ListEnabled(ctx)
	if err != nil {
		return err
	}

	bypassRules := make([]*BypassRule, 0, len(storedRules))
	for _, storedRule := range storedRules {
		rule := BypassRule{
			ID:        storedRule.ID,
			Domain:    storedRule.Domain,
			Reason:    storedRule.Reason,
			Enabled:   storedRule.Enabled,
			DeviceIDs: storedRule.DeviceIDs,
		}
		bypassRules = append(bypassRules, &rule)

		e.logger.Info().
			Str("rule_id", rule.ID).
			Str("domain", rule.Domain).
			Strs("device_ids", rule.DeviceIDs).
			Str("reason", rule.Reason).
			Msg("Loaded bypass rule")
	}

	e.bypassRules = bypassRules

	e.logger.Info().
		Int("total_bypass_rules", len(bypassRules)).
		Msg("Bypass rule loading complete")

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
	clientIPStr := clientIP.String()

	e.logger.Debug().
		Str("client_ip", clientIPStr).
		Str("client_mac", func() string {
			if clientMAC != nil {
				return clientMAC.String()
			}
			return "nil"
		}()).
		Int("total_devices", len(e.devices)).
		Msg("Attempting to identify device")

	// Try MAC address first (most reliable)
	if clientMAC != nil && e.useMACAddress {
		if device := e.devicesByMAC[strings.ToLower(clientMAC.String())]; device != nil {
			e.logger.Debug().
				Str("device_id", device.ID).
				Str("device_name", device.Name).
				Str("method", "mac").
				Msg("Device identified")
			return device
		}
	}

	// Fall back to IP address
	for _, device := range e.devices {
		for _, identifier := range device.Identifiers {
			e.logger.Debug().
				Str("client_ip", clientIPStr).
				Str("identifier", identifier).
				Str("device_id", device.ID).
				Msg("Comparing IP identifier")

			// Check if it's a CIDR range
			if strings.Contains(identifier, "/") {
				if ipRange, err := netip.ParsePrefix(identifier); err == nil {
					clientAddr, err := netip.ParseAddr(clientIPStr)
					if err == nil && ipRange.Contains(clientAddr) {
						e.logger.Info().
							Str("device_id", device.ID).
							Str("device_name", device.Name).
							Str("client_ip", clientIPStr).
							Str("matched_cidr", identifier).
							Str("method", "cidr").
							Msg("Device identified")
						return device
					}
				}
			} else if identifier == clientIPStr {
				e.logger.Info().
					Str("device_id", device.ID).
					Str("device_name", device.Name).
					Str("client_ip", clientIPStr).
					Str("matched_ip", identifier).
					Str("method", "ip").
					Msg("Device identified")
				return device
			}
		}
	}

	e.logger.Info().
		Str("client_ip", clientIPStr).
		Msg("Device not identified - no match found")

	return nil
}

// SetUsageTracker sets the usage tracker for the policy engine
func (e *Engine) SetUsageTracker(tracker UsageTracker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.usageTracker = tracker
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
