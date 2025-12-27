package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// SessionsViews handles session-related API requests.
type SessionsViews struct {
	usageStore storage.UsageStore
	logger     zerolog.Logger
}

// NewSessionsViews creates a new sessions views instance.
func NewSessionsViews(usageStore storage.UsageStore, logger zerolog.Logger) *SessionsViews {
	return &SessionsViews{
		usageStore: usageStore,
		logger:     logger.With().Str("handler", "sessions").Logger(),
	}
}

// ListActiveSessions returns all active usage tracking sessions.
func (v *SessionsViews) ListActiveSessions(ctx *gin.Context) {
	sessions, err := v.usageStore.ListActiveSessions(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list active sessions")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve sessions",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// GetSession returns a specific session by ID.
func (v *SessionsViews) GetSession(ctx *gin.Context) {
	id := ctx.Param("id")

	session, err := v.usageStore.GetSession(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Session not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get session")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve session",
		})
		return
	}

	ctx.JSON(http.StatusOK, session)
}

// TerminateSession terminates an active session.
func (v *SessionsViews) TerminateSession(ctx *gin.Context) {
	id := ctx.Param("id")

	// Check if session exists
	session, err := v.usageStore.GetSession(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Session not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get session")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve session",
		})
		return
	}

	// Mark session as inactive
	session.Active = false
	session.LastActivity = time.Now()

	if err := v.usageStore.UpsertSession(ctx.Request.Context(), *session); err != nil {
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to terminate session")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to terminate session",
		})
		return
	}

	v.logger.Info().Str("id", id).Str("device", session.DeviceID).Msg("Session terminated")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Session terminated successfully",
	})
}

// GetDailyUsage returns usage statistics for a specific date.
func (v *SessionsViews) GetDailyUsage(ctx *gin.Context) {
	date := ctx.Param("date")

	// Validate date format
	if _, err := time.Parse("2006-01-02", date); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid date format (expected YYYY-MM-DD)",
		})
		return
	}

	usages, err := v.usageStore.ListDailyUsage(ctx.Request.Context(), date)
	if err != nil {
		v.logger.Error().Err(err).Str("date", date).Msg("Failed to get daily usage")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve usage data",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"date":   date,
		"usages": usages,
		"count":  len(usages),
	})
}

// GetTodayUsage returns usage statistics for today.
func (v *SessionsViews) GetTodayUsage(ctx *gin.Context) {
	today := time.Now().Format("2006-01-02")

	usages, err := v.usageStore.ListDailyUsage(ctx.Request.Context(), today)
	if err != nil {
		v.logger.Error().Err(err).Str("date", today).Msg("Failed to get today's usage")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve usage data",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"date":   today,
		"usages": usages,
		"count":  len(usages),
	})
}
