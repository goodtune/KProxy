package policy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// UsageTracker interface for usage tracking
type UsageTracker interface {
	RecordActivity(deviceID, category string) error
	GetCategoryUsage(deviceID, category string) (time.Duration, error)
}

// Engine handles policy evaluation by gathering facts and calling OPA
type Engine struct {
	usageStore    storage.UsageStore
	usageTracker  UsageTracker
	opaEngine     *opa.Engine
	clock         Clock
	logger        zerolog.Logger
}

// NewEngine creates a new fact-based policy engine
func NewEngine(usageStore storage.UsageStore, opaConfig opa.Config, logger zerolog.Logger) (*Engine, error) {
	e := &Engine{
		usageStore: usageStore,
		clock:      RealClock{}, // Use real time by default
		logger:     logger.With().Str("component", "policy").Logger(),
	}

	// Initialize OPA engine
	opaEngine, err := opa.NewEngine(opaConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OPA engine: %w", err)
	}
	e.opaEngine = opaEngine

	logger.Info().
		Str("opa_source", opaConfig.Source).
		Msg("Fact-based Policy Engine initialized")

	return e, nil
}

// SetClock sets the clock for time-based policy evaluation (for testing)
func (e *Engine) SetClock(clock Clock) {
	e.clock = clock
}

// SetUsageTracker sets the usage tracker for the policy engine
func (e *Engine) SetUsageTracker(tracker UsageTracker) {
	e.usageTracker = tracker
}

// GetDNSAction determines the DNS action for a query using OPA
// Just gathers facts and asks OPA
func (e *Engine) GetDNSAction(clientIP net.IP, clientMAC net.HardwareAddr, domain string) DNSAction {
	// Build facts
	facts := e.buildDNSFacts(clientIP, clientMAC, domain)

	// Evaluate with OPA
	ctx := context.Background()
	action, err := e.opaEngine.EvaluateDNS(ctx, facts)
	if err != nil {
		e.logger.Error().Err(err).Msg("OPA DNS evaluation failed, falling back to intercept")
		return DNSActionIntercept
	}

	// Convert string action to DNSAction
	switch action {
	case "BYPASS":
		return DNSActionBypass
	case "BLOCK":
		return DNSActionBlock
	case "INTERCEPT":
		return DNSActionIntercept
	default:
		e.logger.Warn().Str("action", action).Msg("Unknown DNS action from OPA, defaulting to intercept")
		return DNSActionIntercept
	}
}

// Evaluate evaluates a proxy request against the policy using OPA
// Just gathers facts (including current usage) and asks OPA
func (e *Engine) Evaluate(req *ProxyRequest) *PolicyDecision {
	// Build facts
	facts := e.buildProxyFacts(req)

	// Evaluate with OPA
	ctx := context.Background()
	opaDecision, err := e.opaEngine.EvaluateProxy(ctx, facts)
	if err != nil {
		e.logger.Error().Err(err).Msg("OPA proxy evaluation failed, falling back to block")
		return &PolicyDecision{
			Action: ActionBlock,
			Reason: fmt.Sprintf("OPA evaluation error: %v", err),
		}
	}

	// Convert OPA decision to PolicyDecision
	decision := &PolicyDecision{
		Action:        Action(opaDecision.Action),
		Reason:        opaDecision.Reason,
		BlockPage:     opaDecision.BlockPage,
		MatchedRuleID: opaDecision.MatchedRuleID,
		Category:      opaDecision.Category,
		InjectTimer:   opaDecision.InjectTimer,
		TimeRemaining: time.Duration(opaDecision.TimeRemainingMinutes) * time.Minute,
		UsageLimitID:  opaDecision.UsageLimitID,
	}

	// If decision is ALLOW and we have a category with usage tracking, record activity
	if decision.Action == ActionAllow && e.usageTracker != nil && decision.Category != "" {
		// Get device ID from OPA (we'll need to query OPA for this)
		// For now, use a composite key of IP+MAC
		deviceID := e.makeDeviceKey(req.ClientIP, req.ClientMAC)
		_ = e.usageTracker.RecordActivity(deviceID, decision.Category)
	}

	return decision
}

// buildDNSFacts gathers facts for DNS evaluation
func (e *Engine) buildDNSFacts(clientIP net.IP, clientMAC net.HardwareAddr, domain string) map[string]interface{} {
	clientMACStr := ""
	if clientMAC != nil {
		clientMACStr = clientMAC.String()
	}

	return map[string]interface{}{
		"client_ip":  clientIP.String(),
		"client_mac": clientMACStr,
		"domain":     domain,
	}
}

// buildProxyFacts gathers facts for proxy request evaluation
func (e *Engine) buildProxyFacts(req *ProxyRequest) map[string]interface{} {
	clientMACStr := ""
	if req.ClientMAC != nil {
		clientMACStr = req.ClientMAC.String()
	}

	// Get current time info from clock
	now := e.clock.Now()
	currentTime := map[string]interface{}{
		"day_of_week": int(now.Weekday()),
		"hour":        now.Hour(),
		"minute":      now.Minute(),
	}

	// Gather usage facts from database
	usageFacts := e.gatherUsageFacts(req.ClientIP, req.ClientMAC)

	return map[string]interface{}{
		"client_ip":  req.ClientIP.String(),
		"client_mac": clientMACStr,
		"host":       req.Host,
		"path":       req.Path,
		"method":     req.Method,
		"time":       currentTime,
		"usage":      usageFacts,
	}
}

// gatherUsageFacts queries the database for current usage
func (e *Engine) gatherUsageFacts(clientIP net.IP, clientMAC net.HardwareAddr) map[string]interface{} {
	if e.usageTracker == nil {
		return map[string]interface{}{}
	}

	// Create device key
	deviceID := e.makeDeviceKey(clientIP, clientMAC)

	// Query usage for common categories
	// In the future, this could be dynamically determined from policy
	categories := []string{"educational", "entertainment", "social-media", "gaming"}

	usageFacts := make(map[string]interface{})
	for _, category := range categories {
		duration, err := e.usageTracker.GetCategoryUsage(deviceID, category)
		if err != nil {
			// No usage data yet, default to 0
			usageFacts[category] = map[string]interface{}{
				"today_minutes": 0,
			}
		} else {
			usageFacts[category] = map[string]interface{}{
				"today_minutes": int(duration.Minutes()),
			}
		}
	}

	return usageFacts
}

// makeDeviceKey creates a composite key for device identification
// This is temporary - ideally OPA should handle device identification
func (e *Engine) makeDeviceKey(clientIP net.IP, clientMAC net.HardwareAddr) string {
	if clientMAC != nil {
		return clientMAC.String()
	}
	return clientIP.String()
}

// Reload reloads the OPA policies
// No longer needs to load database config - just reload OPA policies
func (e *Engine) Reload() error {
	// For filesystem policies: OPA will reload on file changes
	// For remote policies: Can implement periodic re-fetch here
	e.logger.Info().Msg("Policy reload requested (OPA policies are reloaded automatically)")
	return nil
}
