package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// LogsViews handles log-related API requests.
type LogsViews struct {
	logStore storage.LogStore
	logger   zerolog.Logger
}

// NewLogsViews creates a new logs views instance.
func NewLogsViews(logStore storage.LogStore, logger zerolog.Logger) *LogsViews {
	return &LogsViews{
		logStore: logStore,
		logger:   logger.With().Str("handler", "logs").Logger(),
	}
}

// QueryRequestLogs returns filtered request logs.
func (v *LogsViews) QueryRequestLogs(ctx *gin.Context) {
	// Parse query parameters
	query := ctx.Request.URL.Query()
	filter := storage.RequestLogFilter{
		DeviceID: query.Get("device_id"),
		Domain:   query.Get("domain"),
		Limit:    100, // Default limit
		Offset:   0,
	}

	// Parse action
	if actionStr := query.Get("action"); actionStr != "" {
		filter.Action = storage.Action(actionStr)
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	// Parse time range
	if startStr := query.Get("start_time"); startStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startStr); err == nil {
			filter.StartTime = &startTime
		}
	}
	if endStr := query.Get("end_time"); endStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endStr); err == nil {
			filter.EndTime = &endTime
		}
	}

	logs, err := v.logStore.QueryRequestLogs(ctx.Request.Context(), filter)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to query request logs")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve logs",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"count": len(logs),
	})
}

// QueryDNSLogs returns filtered DNS logs.
func (v *LogsViews) QueryDNSLogs(ctx *gin.Context) {
	// Parse query parameters
	query := ctx.Request.URL.Query()
	filter := storage.DNSLogFilter{
		DeviceID: query.Get("device_id"),
		Domain:   query.Get("domain"),
		Action:   query.Get("action"),
		Limit:    100, // Default limit
		Offset:   0,
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	// Parse time range
	if startStr := query.Get("start_time"); startStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startStr); err == nil {
			filter.StartTime = &startTime
		}
	}
	if endStr := query.Get("end_time"); endStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endStr); err == nil {
			filter.EndTime = &endTime
		}
	}

	logs, err := v.logStore.QueryDNSLogs(ctx.Request.Context(), filter)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to query DNS logs")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve logs",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"count": len(logs),
	})
}

// DeleteOldRequestLogs deletes request logs older than specified time.
func (v *LogsViews) DeleteOldRequestLogs(ctx *gin.Context) {
	daysStr := ctx.Param("days")

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid days parameter",
		})
		return
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	deleted, err := v.logStore.DeleteRequestLogsBefore(ctx.Request.Context(), cutoff)
	if err != nil {
		v.logger.Error().Err(err).Int("days", days).Msg("Failed to delete request logs")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete logs",
		})
		return
	}

	v.logger.Info().Int("deleted", deleted).Int("days", days).Msg("Deleted old request logs")
	ctx.JSON(http.StatusOK, gin.H{
		"deleted": deleted,
		"message": "Old request logs deleted successfully",
	})
}

// DeleteOldDNSLogs deletes DNS logs older than specified time.
func (v *LogsViews) DeleteOldDNSLogs(ctx *gin.Context) {
	daysStr := ctx.Param("days")

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid days parameter",
		})
		return
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	deleted, err := v.logStore.DeleteDNSLogsBefore(ctx.Request.Context(), cutoff)
	if err != nil {
		v.logger.Error().Err(err).Int("days", days).Msg("Failed to delete DNS logs")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete logs",
		})
		return
	}

	v.logger.Info().Int("deleted", deleted).Int("days", days).Msg("Deleted old DNS logs")
	ctx.JSON(http.StatusOK, gin.H{
		"deleted": deleted,
		"message": "Old DNS logs deleted successfully",
	})
}
