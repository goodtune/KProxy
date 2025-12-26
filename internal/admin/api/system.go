package api

import (
	"net/http"
	"runtime"
	"time"

	"github.com/goodtune/kproxy/internal/policy"
	"github.com/rs/zerolog"
)

// SystemHandler handles system control API requests.
type SystemHandler struct {
	policyEngine *policy.Engine
	startTime    time.Time
	logger       zerolog.Logger
}

// NewSystemHandler creates a new system handler.
func NewSystemHandler(policyEngine *policy.Engine, logger zerolog.Logger) *SystemHandler {
	return &SystemHandler{
		policyEngine: policyEngine,
		startTime:    time.Now(),
		logger:       logger.With().Str("handler", "system").Logger(),
	}
}

// ReloadPolicy reloads the policy engine from storage.
func (h *SystemHandler) ReloadPolicy(w http.ResponseWriter, r *http.Request) {
	h.logger.Info().Msg("Manual policy reload requested")

	if err := h.policyEngine.Reload(); err != nil {
		h.logger.Error().Err(err).Msg("Failed to reload policy engine")
		writeError(w, http.StatusInternalServerError, "Failed to reload policy: "+err.Error())
		return
	}

	h.logger.Info().Msg("Policy engine reloaded successfully")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Policy engine reloaded successfully",
		"timestamp": time.Now(),
	})
}

// GetHealth returns the health status of the system.
func (h *SystemHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(h.startTime)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	health := map[string]interface{}{
		"status": "healthy",
		"uptime_seconds": int(uptime.Seconds()),
		"uptime_human": uptime.String(),
		"timestamp": time.Now(),
		"memory": map[string]interface{}{
			"alloc_mb": memStats.Alloc / 1024 / 1024,
			"total_alloc_mb": memStats.TotalAlloc / 1024 / 1024,
			"sys_mb": memStats.Sys / 1024 / 1024,
			"num_gc": memStats.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
	}

	writeJSON(w, http.StatusOK, health)
}

// GetSystemInfo returns general system information.
func (h *SystemHandler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(h.startTime)

	info := map[string]interface{}{
		"version": "0.1.0", // TODO: Get from build info
		"go_version": runtime.Version(),
		"uptime": uptime.String(),
		"uptime_seconds": int(uptime.Seconds()),
		"start_time": h.startTime,
		"num_cpu": runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	writeJSON(w, http.StatusOK, info)
}

// GetConfig returns a safe subset of the current configuration.
// Sensitive values like passwords and secrets are omitted.
func (h *SystemHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	// Return a safe subset of configuration
	// This is a placeholder - in a real implementation, you would
	// read from the actual config and redact sensitive values

	config := map[string]interface{}{
		"message": "Configuration viewer not yet implemented",
		"note": "This endpoint will return sanitized configuration in a future update",
	}

	writeJSON(w, http.StatusOK, config)
}
