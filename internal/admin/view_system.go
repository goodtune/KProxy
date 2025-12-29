package admin

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// SystemViews handles system control API requests.
type SystemViews struct {
	store        storage.Store
	policyEngine *policy.Engine
	startTime    time.Time
	logger       zerolog.Logger
}

// NewSystemViews creates a new system views instance.
func NewSystemViews(store storage.Store, policyEngine *policy.Engine, logger zerolog.Logger) *SystemViews {
	return &SystemViews{
		store:        store,
		policyEngine: policyEngine,
		startTime:    time.Now(),
		logger:       logger.With().Str("handler", "system").Logger(),
	}
}

// ReloadPolicy reloads the policy engine from storage.
func (v *SystemViews) ReloadPolicy(ctx *gin.Context) {
	v.logger.Info().Msg("Manual policy reload requested")

	if err := v.policyEngine.Reload(); err != nil {
		v.logger.Error().Err(err).Msg("Failed to reload policy engine")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to reload policy: " + err.Error(),
		})
		return
	}

	v.logger.Info().Msg("Policy engine reloaded successfully")
	ctx.JSON(http.StatusOK, gin.H{
		"message":   "Policy engine reloaded successfully",
		"timestamp": time.Now(),
	})
}

// GetHealth returns the health status of the system.
func (v *SystemViews) GetHealth(ctx *gin.Context) {
	uptime := time.Since(v.startTime)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	health := gin.H{
		"status":         "healthy",
		"uptime_seconds": int(uptime.Seconds()),
		"uptime_human":   uptime.String(),
		"timestamp":      time.Now(),
		"memory": gin.H{
			"alloc_mb":       memStats.Alloc / 1024 / 1024,
			"total_alloc_mb": memStats.TotalAlloc / 1024 / 1024,
			"sys_mb":         memStats.Sys / 1024 / 1024,
			"num_gc":         memStats.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
	}

	ctx.JSON(http.StatusOK, health)
}

// GetSystemInfo returns general system information.
func (v *SystemViews) GetSystemInfo(ctx *gin.Context) {
	uptime := time.Since(v.startTime)

	info := gin.H{
		"version":        "0.1.0", // TODO: Get from build info
		"go_version":     runtime.Version(),
		"uptime":         uptime.String(),
		"uptime_seconds": int(uptime.Seconds()),
		"start_time":     v.startTime,
		"num_cpu":        runtime.NumCPU(),
		"num_goroutine":  runtime.NumGoroutine(),
	}

	ctx.JSON(http.StatusOK, info)
}

// GetConfig returns a safe subset of the current configuration.
// Sensitive values like passwords and secrets are omitted.
func (v *SystemViews) GetConfig(ctx *gin.Context) {
	// Return a safe subset of configuration
	// This is a placeholder - in a real implementation, you would
	// read from the actual config and redact sensitive values

	config := gin.H{
		"message": "Configuration viewer not yet implemented",
		"note":    "This endpoint will return sanitized configuration in a future update",
	}

	ctx.JSON(http.StatusOK, config)
}

// Export returns a complete dump of all system configuration.
// This includes devices, profiles, rules (all types), and system metadata.
func (v *SystemViews) Export(ctx *gin.Context) {
	v.logger.Info().Msg("System configuration export requested")

	// Fetch all devices
	devices, err := v.store.Devices().List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to fetch devices")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to export devices: " + err.Error(),
		})
		return
	}

	// Fetch all profiles
	profiles, err := v.store.Profiles().List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to fetch profiles")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to export profiles: " + err.Error(),
		})
		return
	}

	// Fetch all regular rules
	rules, err := v.store.Rules().ListAll(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to fetch rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to export rules: " + err.Error(),
		})
		return
	}

	// Fetch time rules for all profiles
	var timeRules []storage.TimeRule
	for _, profile := range profiles {
		tr, err := v.store.TimeRules().ListByProfile(ctx.Request.Context(), profile.ID)
		if err != nil {
			v.logger.Error().Err(err).Str("profileID", profile.ID).Msg("Failed to fetch time rules")
			continue
		}
		timeRules = append(timeRules, tr...)
	}

	// Fetch usage limits for all profiles
	var usageLimits []storage.UsageLimit
	for _, profile := range profiles {
		limits, err := v.store.UsageLimits().ListByProfile(ctx.Request.Context(), profile.ID)
		if err != nil {
			v.logger.Error().Err(err).Str("profileID", profile.ID).Msg("Failed to fetch usage limits")
			continue
		}
		usageLimits = append(usageLimits, limits...)
	}

	// Fetch all bypass rules
	bypassRules, err := v.store.BypassRules().List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to fetch bypass rules")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to export bypass rules: " + err.Error(),
		})
		return
	}

	// Build export response
	export := gin.H{
		"exported_at": time.Now(),
		"version":     "1.0",
		"system": gin.H{
			"uptime":        time.Since(v.startTime).String(),
			"go_version":    runtime.Version(),
			"num_cpu":       runtime.NumCPU(),
			"num_goroutine": runtime.NumGoroutine(),
		},
		"data": gin.H{
			"devices": gin.H{
				"count": len(devices),
				"items": devices,
			},
			"profiles": gin.H{
				"count": len(profiles),
				"items": profiles,
			},
			"rules": gin.H{
				"count": len(rules),
				"items": rules,
			},
			"time_rules": gin.H{
				"count": len(timeRules),
				"items": timeRules,
			},
			"usage_limits": gin.H{
				"count": len(usageLimits),
				"items": usageLimits,
			},
			"bypass_rules": gin.H{
				"count": len(bypassRules),
				"items": bypassRules,
			},
		},
		"summary": gin.H{
			"total_devices":      len(devices),
			"total_profiles":     len(profiles),
			"total_rules":        len(rules),
			"total_time_rules":   len(timeRules),
			"total_usage_limits": len(usageLimits),
			"total_bypass_rules": len(bypassRules),
		},
	}

	v.logger.Info().
		Int("devices", len(devices)).
		Int("profiles", len(profiles)).
		Int("rules", len(rules)).
		Int("time_rules", len(timeRules)).
		Int("usage_limits", len(usageLimits)).
		Int("bypass_rules", len(bypassRules)).
		Msg("System configuration exported successfully")

	ctx.JSON(http.StatusOK, export)
}
