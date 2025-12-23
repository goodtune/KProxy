package api

import (
	"net/http"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// SessionsHandler handles session-related API requests.
type SessionsHandler struct {
	usageStore storage.UsageStore
	logger     zerolog.Logger
}

// NewSessionsHandler creates a new sessions handler.
func NewSessionsHandler(usageStore storage.UsageStore, logger zerolog.Logger) *SessionsHandler {
	return &SessionsHandler{
		usageStore: usageStore,
		logger:     logger.With().Str("handler", "sessions").Logger(),
	}
}

// ListActiveSessions returns all active usage tracking sessions.
func (h *SessionsHandler) ListActiveSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessions, err := h.usageStore.ListActiveSessions(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list active sessions")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// GetSession returns a specific session by ID.
func (h *SessionsHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	session, err := h.usageStore.GetSession(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Session not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get session")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve session")
		return
	}

	writeJSON(w, http.StatusOK, session)
}

// TerminateSession terminates an active session.
func (h *SessionsHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	id := vars["id"]

	// Check if session exists
	session, err := h.usageStore.GetSession(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			writeError(w, http.StatusNotFound, "Session not found")
			return
		}
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to get session")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve session")
		return
	}

	// Mark session as inactive
	session.Active = false
	session.LastActivity = time.Now()

	if err := h.usageStore.UpsertSession(ctx, *session); err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("Failed to terminate session")
		writeError(w, http.StatusInternalServerError, "Failed to terminate session")
		return
	}

	h.logger.Info().Str("id", id).Str("device", session.DeviceID).Msg("Session terminated")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Session terminated successfully",
	})
}

// GetDailyUsage returns usage statistics for a specific date.
func (h *SessionsHandler) GetDailyUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	date := vars["date"]

	// Validate date format
	if _, err := time.Parse("2006-01-02", date); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid date format (expected YYYY-MM-DD)")
		return
	}

	usages, err := h.usageStore.ListDailyUsage(ctx, date)
	if err != nil {
		h.logger.Error().Err(err).Str("date", date).Msg("Failed to get daily usage")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve usage data")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"date":   date,
		"usages": usages,
		"count":  len(usages),
	})
}

// GetTodayUsage returns usage statistics for today.
func (h *SessionsHandler) GetTodayUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	today := time.Now().Format("2006-01-02")

	usages, err := h.usageStore.ListDailyUsage(ctx, today)
	if err != nil {
		h.logger.Error().Err(err).Str("date", today).Msg("Failed to get today's usage")
		writeError(w, http.StatusInternalServerError, "Failed to retrieve usage data")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"date":   today,
		"usages": usages,
		"count":  len(usages),
	})
}
