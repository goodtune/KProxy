package policy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// buildDNSInput builds OPA input for DNS action evaluation
func (e *Engine) buildDNSInput(clientIP net.IP, domain string) map[string]interface{} {
	// Build devices map
	devicesMap := make(map[string]interface{})
	for id, device := range e.devices {
		devicesMap[id] = map[string]interface{}{
			"id":          device.ID,
			"name":        device.Name,
			"identifiers": device.Identifiers,
			"profile_id":  device.ProfileID,
			"active":      device.Active,
		}
	}

	// Build bypass rules array
	bypassRulesArray := make([]interface{}, 0, len(e.bypassRules))
	for _, rule := range e.bypassRules {
		bypassRulesArray = append(bypassRulesArray, map[string]interface{}{
			"id":         rule.ID,
			"domain":     rule.Domain,
			"enabled":    rule.Enabled,
			"device_ids": rule.DeviceIDs,
			"reason":     rule.Reason,
		})
	}

	return map[string]interface{}{
		"client_ip":        clientIP.String(),
		"domain":           domain,
		"global_bypass":    e.globalBypass,
		"bypass_rules":     bypassRulesArray,
		"devices":          devicesMap,
		"use_mac_address":  e.useMACAddress,
	}
}

// buildProxyInput builds OPA input for proxy request evaluation
func (e *Engine) buildProxyInput(req *ProxyRequest) map[string]interface{} {
	// Build devices map
	devicesMap := make(map[string]interface{})
	for id, device := range e.devices {
		devicesMap[id] = map[string]interface{}{
			"id":          device.ID,
			"name":        device.Name,
			"identifiers": device.Identifiers,
			"profile_id":  device.ProfileID,
			"active":      device.Active,
		}
	}

	// Build profiles map
	profilesMap := make(map[string]interface{})
	for id, profile := range e.profiles {
		// Convert rules
		rulesArray := make([]interface{}, len(profile.Rules))
		for i, rule := range profile.Rules {
			rulesArray[i] = map[string]interface{}{
				"id":           rule.ID,
				"domain":       rule.Domain,
				"paths":        rule.Paths,
				"action":       string(rule.Action),
				"priority":     rule.Priority,
				"category":     rule.Category,
				"inject_timer": rule.InjectTimer,
			}
		}

		// Convert time rules
		timeRulesArray := make([]interface{}, len(profile.TimeRules))
		for i, timeRule := range profile.TimeRules {
			timeRulesArray[i] = map[string]interface{}{
				"id":           timeRule.ID,
				"days_of_week": timeRule.DaysOfWeek,
				"start_time":   timeRule.StartTime,
				"end_time":     timeRule.EndTime,
				"rule_ids":     timeRule.RuleIDs,
			}
		}

		// Convert usage limits
		usageLimitsArray := make([]interface{}, len(profile.UsageLimits))
		for i, limit := range profile.UsageLimits {
			usageLimitsArray[i] = map[string]interface{}{
				"id":            limit.ID,
				"category":      limit.Category,
				"domains":       limit.Domains,
				"daily_minutes": limit.DailyMinutes,
				"reset_time":    limit.ResetTime,
				"inject_timer":  limit.InjectTimer,
			}
		}

		profilesMap[id] = map[string]interface{}{
			"id":            profile.ID,
			"name":          profile.Name,
			"default_allow": profile.DefaultAllow,
			"rules":         rulesArray,
			"time_rules":    timeRulesArray,
			"usage_limits":  usageLimitsArray,
		}
	}

	// Build usage stats map if usage tracker is available
	usageStatsMap := make(map[string]interface{})
	if e.usageTracker != nil {
		// Identify device to get relevant usage limits
		device := e.identifyDevice(req.ClientIP, req.ClientMAC)
		if device != nil {
			profile := e.profiles[device.ProfileID]
			if profile != nil {
				for _, limit := range profile.UsageLimits {
					// Parse reset time
					resetTime, err := time.Parse("15:04", limit.ResetTime)
					if err != nil {
						resetTime = time.Time{}
					}

					// Get usage stats
					limitDuration := time.Duration(limit.DailyMinutes) * time.Minute
					stats, err := e.usageTracker.GetUsageStats(device.ID, limit.ID, limitDuration, resetTime)
					if err == nil {
						usageStatsMap[limit.ID] = map[string]interface{}{
							"today_usage_minutes": int(stats.TodayUsage.Minutes()),
							"remaining_minutes":   int(stats.RemainingToday.Minutes()),
							"limit_exceeded":      stats.LimitExceeded,
						}
					}
				}
			}
		}
	}

	// Get current time info
	now := time.Now()
	currentTime := map[string]interface{}{
		"day_of_week": int(now.Weekday()),
		"minutes":     now.Hour()*60 + now.Minute(),
	}

	clientMAC := ""
	if req.ClientMAC != nil {
		clientMAC = req.ClientMAC.String()
	}

	return map[string]interface{}{
		"client_ip":       req.ClientIP.String(),
		"client_mac":      clientMAC,
		"host":            req.Host,
		"path":            req.Path,
		"method":          req.Method,
		"user_agent":      req.UserAgent,
		"encrypted":       req.Encrypted,
		"current_time":    currentTime,
		"devices":         devicesMap,
		"profiles":        profilesMap,
		"usage_stats":     usageStatsMap,
		"use_mac_address": e.useMACAddress,
		"default_action":  string(e.defaultAction),
	}
}

// GetDNSAction determines the DNS action for a query using OPA
func (e *Engine) GetDNSAction(clientIP net.IP, domain string) DNSAction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Build OPA input
	input := e.buildDNSInput(clientIP, domain)

	// Evaluate with OPA
	ctx := context.Background()
	action, err := e.opaEngine.EvaluateDNS(ctx, input)
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
func (e *Engine) Evaluate(req *ProxyRequest) *PolicyDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Build OPA input
	input := e.buildProxyInput(req)

	// Evaluate with OPA
	ctx := context.Background()
	opaDecision, err := e.opaEngine.EvaluateProxy(ctx, input)
	if err != nil {
		e.logger.Error().Err(err).Msg("OPA proxy evaluation failed, falling back to default action")
		return &PolicyDecision{
			Action: e.defaultAction,
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

	// If decision is ALLOW and we have usage tracking, record activity
	if decision.Action == ActionAllow && e.usageTracker != nil && decision.UsageLimitID != "" {
		device := e.identifyDevice(req.ClientIP, req.ClientMAC)
		if device != nil {
			_ = e.usageTracker.RecordActivity(device.ID, decision.UsageLimitID)
		}
	}

	return decision
}
