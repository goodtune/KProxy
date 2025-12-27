package admin

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/rs/zerolog"
)

// SystemViews handles system control API requests.
type SystemViews struct {
	policyEngine *policy.Engine
	startTime    time.Time
	logger       zerolog.Logger
}

// NewSystemViews creates a new system views instance.
func NewSystemViews(policyEngine *policy.Engine, logger zerolog.Logger) *SystemViews {
	return &SystemViews{
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
