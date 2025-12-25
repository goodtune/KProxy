package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// RulesHandler handles rules-related API requests.
type RulesHandler struct {
	ruleStore        storage.RuleStore
	timeRuleStore    storage.TimeRuleStore
	usageLimitStore  storage.UsageLimitStore
	bypassRuleStore  storage.BypassRuleStore
	policyEngine     *policy.Engine
	logger           zerolog.Logger
}

// NewRulesHandler creates a new rules handler.
func NewRulesHandler(
	ruleStore storage.RuleStore,
	timeRuleStore storage.TimeRuleStore,
	usageLimitStore storage.UsageLimitStore,
	bypassRuleStore storage.BypassRuleStore,
	policyEngine *policy.Engine,
	logger zerolog.Logger,
) *RulesHandler {
	return &RulesHandler{
		ruleStore:       ruleStore,
		timeRuleStore:   timeRuleStore,
		usageLimitStore: usageLimitStore,
		bypassRuleStore: bypassRuleStore,
		policyEngine:    policyEngine,
		logger:          logger.With().Str("handler", "rules").Logger(),
	}
}

// === Regular Rules ===

// ListRules returns all rules for a profile.
func (h *RulesHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	rules, err := h.ruleStore.ListByProfile(ctx, profileID)
	if err != nil {
		h.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list rules")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve rules")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

// GetRule returns a single rule by ID.
func (h *RulesHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]
	ruleID := vars["ruleID"]

	rule, err := h.ruleStore.Get(ctx, profileID, ruleID)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Rule not found")
			return
		}
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to get rule")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve rule")
		return
	}

	writeJSON(w, http.StatusOK, rule)
}

// CreateRule creates a new rule.
func (h *RulesHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	var rule storage.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate rule
	if rule.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	// Generate ID if not provided
	if rule.ID == "" {
		rule.ID = generateID("rule")
	}

	rule.ProfileID = profileID

	if err := h.ruleStore.Upsert(ctx, rule); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create rule")
		writeError(w, http.StatusInternalServerError, "Failed to create rule")
		return
	}

	// Reload policy engine
	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine after rule creation")
	}

	h.logger.Info().Str("id", rule.ID).Str("domain", rule.Domain).Msg("Rule created")
	writeJSON(w, http.StatusCreated, rule)
}

// UpdateRule updates an existing rule.
func (h *RulesHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]
	ruleID := vars["ruleID"]

	// Get existing rule
	existing, err := h.ruleStore.Get(ctx, profileID, ruleID)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Rule not found")
			return
		}
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to get rule")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve rule")
		return
	}

	var updates storage.Rule
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Preserve ID and profile ID
	updates.ID = existing.ID
	updates.ProfileID = existing.ProfileID

	// Validate updates
	if updates.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	if err := h.ruleStore.Upsert(ctx, updates); err != nil {
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to update rule")
		writeError(w, http.StatusInternalServerError, "Failed to update rule")
		return
	}

	// Reload policy engine
	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine after rule update")
	}

	h.logger.Info().Str("id", ruleID).Msg("Rule updated")
	writeJSON(w, http.StatusOK, updates)
}

// DeleteRule deletes a rule.
func (h *RulesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]
	ruleID := vars["ruleID"]

	if err := h.ruleStore.Delete(ctx, profileID, ruleID); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Rule not found")
			return
		}
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete rule")
		writeError(w, http.StatusInternalServerError, "Failed to delete rule")
		return
	}

	// Reload policy engine
	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine after rule deletion")
	}

	h.logger.Info().Str("id", ruleID).Msg("Rule deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Rule deleted successfully",
	})
}

// === Time Rules ===

// ListTimeRules returns all time rules for a profile.
func (h *RulesHandler) ListTimeRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	timeRules, err := h.timeRuleStore.ListByProfile(ctx, profileID)
	if err != nil {
		h.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list time rules")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve time rules")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"time_rules": timeRules,
		"count":      len(timeRules),
	})
}

// CreateTimeRule creates a new time rule.
func (h *RulesHandler) CreateTimeRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	var timeRule storage.TimeRule
	if err := json.NewDecoder(r.Body).Decode(&timeRule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if timeRule.ID == "" {
		timeRule.ID = generateID("timerule")
	}
	timeRule.ProfileID = profileID

	if err := h.timeRuleStore.Upsert(ctx, timeRule); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create time rule")
		writeError(w, http.StatusInternalServerError, "Failed to create time rule")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", timeRule.ID).Msg("Time rule created")
	writeJSON(w, http.StatusCreated, timeRule)
}

// DeleteTimeRule deletes a time rule.
func (h *RulesHandler) DeleteTimeRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]
	ruleID := vars["ruleID"]

	if err := h.timeRuleStore.Delete(ctx, profileID, ruleID); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Time rule not found")
			return
		}
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete time rule")
		writeError(w, http.StatusInternalServerError, "Failed to delete time rule")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", ruleID).Msg("Time rule deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Time rule deleted successfully",
	})
}

// === Usage Limits ===

// ListUsageLimits returns all usage limits for a profile.
func (h *RulesHandler) ListUsageLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	limits, err := h.usageLimitStore.ListByProfile(ctx, profileID)
	if err != nil {
		h.logger.Error().Err(err).Str("profileID", profileID).Msg("Failed to list usage limits")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve usage limits")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"usage_limits": limits,
		"count":        len(limits),
	})
}

// CreateUsageLimit creates a new usage limit.
func (h *RulesHandler) CreateUsageLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]

	var limit storage.UsageLimit
	if err := json.NewDecoder(r.Body).Decode(&limit); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if limit.ID == "" {
		limit.ID = generateID("limit")
	}
	limit.ProfileID = profileID

	if err := h.usageLimitStore.Upsert(ctx, limit); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create usage limit")
		writeError(w, http.StatusInternalServerError, "Failed to create usage limit")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", limit.ID).Msg("Usage limit created")
	writeJSON(w, http.StatusCreated, limit)
}

// DeleteUsageLimit deletes a usage limit.
func (h *RulesHandler) DeleteUsageLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	profileID := vars["profileID"]
	limitID := vars["limitID"]

	if err := h.usageLimitStore.Delete(ctx, profileID, limitID); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Usage limit not found")
			return
		}
		h.logger.Error().Err(err).Str("limitID", limitID).Msg("Failed to delete usage limit")
		writeError(w, http.StatusInternalServerError, "Failed to delete usage limit")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", limitID).Msg("Usage limit deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Usage limit deleted successfully",
	})
}

// === Bypass Rules ===

// ListBypassRules returns all bypass rules.
func (h *RulesHandler) ListBypassRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rules, err := h.bypassRuleStore.List(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list bypass rules")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve bypass rules")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bypass_rules": rules,
		"count":        len(rules),
	})
}

// CreateBypassRule creates a new bypass rule.
func (h *RulesHandler) CreateBypassRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var rule storage.BypassRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if rule.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
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

	if err := h.bypassRuleStore.Upsert(ctx, rule); err != nil {
		h.logger.Error().Err(err).Msg("Failed to create bypass rule")
		writeError(w, http.StatusInternalServerError, "Failed to create bypass rule")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", rule.ID).Str("domain", rule.Domain).Msg("Bypass rule created")
	writeJSON(w, http.StatusCreated, rule)
}

// DeleteBypassRule deletes a bypass rule.
func (h *RulesHandler) DeleteBypassRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["id"]

	if err := h.bypassRuleStore.Delete(ctx, ruleID); err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Bypass rule not found")
			return
		}
		h.logger.Error().Err(err).Str("ruleID", ruleID).Msg("Failed to delete bypass rule")
		writeError(w, http.StatusInternalServerError, "Failed to delete bypass rule")
		return
	}

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
	}

	h.logger.Info().Str("id", ruleID).Msg("Bypass rule deleted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Bypass rule deleted successfully",
	})
}
