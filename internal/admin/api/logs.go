package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// LogsHandler handles log-related API requests.
type LogsHandler struct {
	logStore storage.LogStore
	logger   zerolog.Logger
}

// NewLogsHandler creates a new logs handler.
func NewLogsHandler(logStore storage.LogStore, logger zerolog.Logger) *LogsHandler {
	return &LogsHandler{
		logStore: logStore,
		logger:   logger.With().Str("handler", "logs").Logger(),
	}
}

// QueryRequestLogs returns filtered request logs.
func (h *LogsHandler) QueryRequestLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
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

	logs, err := h.logStore.QueryRequestLogs(ctx, filter)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to query request logs")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve logs")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// QueryDNSLogs returns filtered DNS logs.
func (h *LogsHandler) QueryDNSLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()
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

	logs, err := h.logStore.QueryDNSLogs(ctx, filter)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to query DNS logs")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve logs")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// DeleteOldRequestLogs deletes request logs older than specified time.
func (h *LogsHandler) DeleteOldRequestLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	daysStr := vars["days"]

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		writeError(w, http.StatusBadRequest, "Invalid days parameter")
		return
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	deleted, err := h.logStore.DeleteRequestLogsBefore(ctx, cutoff)
	if err != nil {
		h.logger.Error().Err(err).Int("days", days).Msg("Failed to delete request logs")
		writeError(w, http.StatusInternalServerError, "Failed to delete logs")
		return
	}

	h.logger.Info().Int("deleted", deleted).Int("days", days).Msg("Deleted old request logs")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": deleted,
		"message": "Old request logs deleted successfully",
	})
}

// DeleteOldDNSLogs deletes DNS logs older than specified time.
func (h *LogsHandler) DeleteOldDNSLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	daysStr := vars["days"]

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		writeError(w, http.StatusBadRequest, "Invalid days parameter")
		return
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	deleted, err := h.logStore.DeleteDNSLogsBefore(ctx, cutoff)
	if err != nil {
		h.logger.Error().Err(err).Int("days", days).Msg("Failed to delete DNS logs")
		writeError(w, http.StatusInternalServerError, "Failed to delete logs")
		return
	}

	h.logger.Info().Int("deleted", deleted).Int("days", days).Msg("Deleted old DNS logs")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": deleted,
		"message": "Old DNS logs deleted successfully",
	})
}
