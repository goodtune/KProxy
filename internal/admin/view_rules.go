package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// RulesViews handles rules-related API requests.
type RulesViews struct {
	ruleStore       storage.RuleStore
	timeRuleStore   storage.TimeRuleStore
	usageLimitStore storage.UsageLimitStore
	bypassRuleStore storage.BypassRuleStore
	policyEngine    *policy.Engine
	logger          zerolog.Logger
}

// NewRulesViews creates a new rules views instance.
func NewRulesViews(
	ruleStore storage.RuleStore,
	timeRuleStore storage.TimeRuleStore,
	usageLimitStore storage.UsageLimitStore,
	bypassRuleStore storage.BypassRuleStore,
	policyEngine *policy.Engine,
	logger zerolog.Logger,
) *RulesViews {
	return &RulesViews{
		ruleStore:       ruleStore,
		timeRuleStore:   timeRuleStore,
		usageLimitStore: usageLimitStore,
		bypassRuleStore: bypassRuleStore,
		policyEngine:    policyEngine,
		logger:          logger.With().Str("handler", "rules").Logger(),
	}
}

// === Regular Rules ===

// ListAllRules returns all rules across all profiles.
func (v *RulesViews) ListAllRules(ctx *gin.Context) {
	rules, err := v.ruleStore.ListAll(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list all rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve rules",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// ListRules returns all rules for a profile.
func (v *RulesViews) ListRules(ctx *gin.Context) {
	profileID := ctx.Param("id")

	rules, err := v.ruleStore.ListByProfile(ctx.Request.Context(), profileID)
	if err != nil {
		v.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve rules",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// GetRule returns a single rule by ID.
func (v *RulesViews) GetRule(ctx *gin.Context) {
	profileID := ctx.Param("id")
	ruleID := ctx.Param("ruleID")

	rule, err := v.ruleStore.Get(ctx.Request.Context(), profileID, ruleID)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Rule not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to get rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve rule",
		})
		return
	}

	ctx.JSON(http.StatusOK, rule)
}

// CreateRule creates a new rule.
func (v *RulesViews) CreateRule(ctx *gin.Context) {
	profileID := ctx.Param("id")

	var rule storage.Rule
	if err := ctx.ShouldBindJSON(&rule); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate rule
	if rule.Domain == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Domain is required",
		})
		return
	}

	// Generate ID if not provided
	if rule.ID == "" {
		rule.ID = generateID("rule")
	}

	rule.ProfileID = profileID

	if err := v.ruleStore.Upsert(ctx.Request.Context(), rule); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create rule",
		})
		return
	}

	// Reload policy engine
	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine after rule creation")
	}

	v.logger.Info().Str("id", rule.ID).Str("domain", rule.Domain).Msg("Rule created")
	ctx.JSON(http.StatusCreated, rule)
}

// UpdateRule updates an existing rule.
func (v *RulesViews) UpdateRule(ctx *gin.Context) {
	profileID := ctx.Param("id")
	ruleID := ctx.Param("ruleID")

	// Get existing rule
	existing, err := v.ruleStore.Get(ctx.Request.Context(), profileID, ruleID)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Rule not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to get rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve rule",
		})
		return
	}

	var updates storage.Rule
	if err := ctx.ShouldBindJSON(&updates); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Preserve ID and profile ID
	updates.ID = existing.ID
	updates.ProfileID = existing.ProfileID

	// Validate updates
	if updates.Domain == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Domain is required",
		})
		return
	}

	if err := v.ruleStore.Upsert(ctx.Request.Context(), updates); err != nil {
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to update rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to update rule",
		})
		return
	}

	// Reload policy engine
	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine after rule update")
	}

	v.logger.Info().Str("id", ruleID).Msg("Rule updated")
	ctx.JSON(http.StatusOK, updates)
}

// DeleteRule deletes a rule.
func (v *RulesViews) DeleteRule(ctx *gin.Context) {
	profileID := ctx.Param("id")
	ruleID := ctx.Param("ruleID")

	if err := v.ruleStore.Delete(ctx.Request.Context(), profileID, ruleID); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Rule not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete rule",
		})
		return
	}

	// Reload policy engine
	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine after rule deletion")
	}

	v.logger.Info().Str("id", ruleID).Msg("Rule deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Rule deleted successfully",
	})
}

// === Time Rules ===

// ListTimeRules returns all time rules for a profile.
func (v *RulesViews) ListTimeRules(ctx *gin.Context) {
	profileID := ctx.Param("id")

	timeRules, err := v.timeRuleStore.ListByProfile(ctx.Request.Context(), profileID)
	if err != nil {
		v.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list time rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve time rules",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"time_rules": timeRules,
		"count":      len(timeRules),
	})
}

// CreateTimeRule creates a new time rule.
func (v *RulesViews) CreateTimeRule(ctx *gin.Context) {
	profileID := ctx.Param("id")

	var timeRule storage.TimeRule
	if err := ctx.ShouldBindJSON(&timeRule); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	if timeRule.ID == "" {
		timeRule.ID = generateID("timerule")
	}
	timeRule.ProfileID = profileID

	if err := v.timeRuleStore.Upsert(ctx.Request.Context(), timeRule); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create time rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create time rule",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", timeRule.ID).Msg("Time rule created")
	ctx.JSON(http.StatusCreated, timeRule)
}

// DeleteTimeRule deletes a time rule.
func (v *RulesViews) DeleteTimeRule(ctx *gin.Context) {
	profileID := ctx.Param("id")
	ruleID := ctx.Param("ruleID")

	if err := v.timeRuleStore.Delete(ctx.Request.Context(), profileID, ruleID); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Time rule not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete time rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete time rule",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", ruleID).Msg("Time rule deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Time rule deleted successfully",
	})
}

// === Usage Limits ===

// ListUsageLimits returns all usage limits for a profile.
func (v *RulesViews) ListUsageLimits(ctx *gin.Context) {
	profileID := ctx.Param("id")

	limits, err := v.usageLimitStore.ListByProfile(ctx.Request.Context(), profileID)
	if err != nil {
		v.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list usage limits")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve usage limits",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"usage_limits": limits,
		"count":        len(limits),
	})
}

// CreateUsageLimit creates a new usage limit.
func (v *RulesViews) CreateUsageLimit(ctx *gin.Context) {
	profileID := ctx.Param("id")

	var limit storage.UsageLimit
	if err := ctx.ShouldBindJSON(&limit); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	if limit.ID == "" {
		limit.ID = generateID("limit")
	}
	limit.ProfileID = profileID

	if err := v.usageLimitStore.Upsert(ctx.Request.Context(), limit); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create usage limit")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create usage limit",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", limit.ID).Msg("Usage limit created")
	ctx.JSON(http.StatusCreated, limit)
}

// DeleteUsageLimit deletes a usage limit.
func (v *RulesViews) DeleteUsageLimit(ctx *gin.Context) {
	profileID := ctx.Param("id")
	limitID := ctx.Param("limitID")

	if err := v.usageLimitStore.Delete(ctx.Request.Context(), profileID, limitID); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Usage limit not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("limitID", limitID).Msg("Failed to delete usage limit")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete usage limit",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", limitID).Msg("Usage limit deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Usage limit deleted successfully",
	})
}

// === Bypass Rules ===

// ListBypassRules returns all bypass rules.
func (v *RulesViews) ListBypassRules(ctx *gin.Context) {
	rules, err := v.bypassRuleStore.List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list bypass rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve bypass rules",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"bypass_rules": rules,
		"count":        len(rules),
	})
}

// CreateBypassRule creates a new bypass rule.
func (v *RulesViews) CreateBypassRule(ctx *gin.Context) {
	var rule storage.BypassRule
	if err := ctx.ShouldBindJSON(&rule); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	if rule.Domain == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Domain is required",
		})
		return
	}

	if rule.ID == "" {
		rule.ID = generateID("bypass")
	}

	// Default new bypass rules to enabled
	// Note: This means rules are enabled by default unless explicitly disabled in the request
	rule.Enabled = true

	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	if err := v.bypassRuleStore.Upsert(ctx.Request.Context(), rule); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create bypass rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create bypass rule",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", rule.ID).Str("domain", rule.Domain).Msg("Bypass rule created")
	ctx.JSON(http.StatusCreated, rule)
}

// DeleteBypassRule deletes a bypass rule.
func (v *RulesViews) DeleteBypassRule(ctx *gin.Context) {
	ruleID := ctx.Param("id")

	if err := v.bypassRuleStore.Delete(ctx.Request.Context(), ruleID); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Bypass rule not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete bypass rule")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete bypass rule",
		})
		return
	}

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	v.logger.Info().Str("id", ruleID).Msg("Bypass rule deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Bypass rule deleted successfully",
	})
}
