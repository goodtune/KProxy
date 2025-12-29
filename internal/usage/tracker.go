package usage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

const (
	// DefaultInactivityTimeout is the duration after which a session is considered inactive
	DefaultInactivityTimeout = 2 * time.Minute

	// DefaultMinSessionDuration is the minimum duration to count a session
	DefaultMinSessionDuration = 10 * time.Second
)

// Tracker manages usage tracking sessions
type Tracker struct {
	usageStore          storage.UsageStore
	sessions            map[string]*Session // key: sessionID
	deviceLimitSessions map[string]string   // key: deviceID:limitID -> sessionID
	inactivityTimeout   time.Duration
	minSessionDuration  time.Duration
	logger              zerolog.Logger
	mu                  sync.RWMutex
}

// Config holds tracker configuration
type Config struct {
	InactivityTimeout  time.Duration
	MinSessionDuration time.Duration
}

// NewTracker creates a new usage tracker
func NewTracker(usageStore storage.UsageStore, config Config, logger zerolog.Logger) *Tracker {
	if config.InactivityTimeout == 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.MinSessionDuration == 0 {
		config.MinSessionDuration = DefaultMinSessionDuration
	}

	t := &Tracker{
		usageStore:          usageStore,
		sessions:            make(map[string]*Session),
		deviceLimitSessions: make(map[string]string),
		inactivityTimeout:   config.InactivityTimeout,
		minSessionDuration:  config.MinSessionDuration,
		logger:              logger.With().Str("component", "usage-tracker").Logger(),
	}

	// Start cleanup goroutine
	go t.cleanupInactiveSessions()

	return t
}

// RecordActivity records activity for a device and usage limit
func (t *Tracker) RecordActivity(deviceID, limitID string) error {
	_, err := t.recordActivityInternal(deviceID, limitID)
	return err
}

// recordActivityInternal records activity and returns the session
func (t *Tracker) recordActivityInternal(deviceID, limitID string) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := deviceID + ":" + limitID
	sessionID, exists := t.deviceLimitSessions[key]

	now := time.Now()

	var session *Session

	if exists {
		session = t.sessions[sessionID]

		// Check if session is still active (within inactivity timeout)
		if now.Sub(session.LastActivity) <= t.inactivityTimeout {
			// Continue existing session
			elapsed := now.Sub(session.LastActivity)
			session.AccumulatedSeconds += int64(elapsed.Seconds())
			session.LastActivity = now

			t.logger.Debug().
				Str("session_id", sessionID).
				Str("device_id", deviceID).
				Str("limit_id", limitID).
				Int64("accumulated_seconds", session.AccumulatedSeconds).
				Msg("Activity recorded in existing session")

			return session, nil
		}

		// Session timed out, finalize it
		t.logger.Debug().
			Str("session_id", sessionID).
			Str("device_id", deviceID).
			Dur("inactivity", now.Sub(session.LastActivity)).
			Msg("Session timed out")

		if err := t.finalizeSession(session); err != nil {
			t.logger.Error().Err(err).Str("session_id", sessionID).Msg("Failed to finalize timed-out session")
		}
	}

	// Start new session
	session = &Session{
		ID:                 generateSessionID(),
		DeviceID:           deviceID,
		LimitID:            limitID,
		StartedAt:          now,
		LastActivity:       now,
		AccumulatedSeconds: 0,
		Active:             true,
	}

	t.sessions[session.ID] = session
	t.deviceLimitSessions[key] = session.ID

	// Save to storage
	if err := t.saveSession(session); err != nil {
		t.logger.Error().Err(err).Str("session_id", session.ID).Msg("Failed to save new session")
		return session, err
	}

	t.logger.Info().
		Str("session_id", session.ID).
		Str("device_id", deviceID).
		Str("limit_id", limitID).
		Msg("Started new usage session")

	return session, nil
}

// GetTodayUsage returns the total usage for today for a device and limit
func (t *Tracker) GetTodayUsage(deviceID, limitID string, resetTime time.Time) (time.Duration, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Get today's date at reset time
	now := time.Now()
	today := getResetDate(now, resetTime)

	// Query storage for today's usage
	dailyUsage, err := t.usageStore.GetDailyUsage(context.Background(), today.Format("2006-01-02"), deviceID, limitID)
	if err != nil && !errorsIsNotFound(err) {
		return 0, fmt.Errorf("failed to query daily usage: %w", err)
	}

	var usage time.Duration
	if err == nil && dailyUsage != nil {
		usage = time.Duration(dailyUsage.TotalSeconds) * time.Second
	}

	// Add current active session time if exists
	key := deviceID + ":" + limitID
	if sessionID, exists := t.deviceLimitSessions[key]; exists {
		if session := t.sessions[sessionID]; session != nil && session.Active {
			// Add accumulated time plus time since last activity
			elapsed := now.Sub(session.LastActivity)
			if elapsed <= t.inactivityTimeout {
				currentSessionTime := time.Duration(session.AccumulatedSeconds)*time.Second + elapsed
				usage += currentSessionTime
			}
		}
	}

	return usage, nil
}

// GetUsageStats returns current usage statistics for a device and limit
func (t *Tracker) GetUsageStats(deviceID, limitID string, dailyLimit time.Duration, resetTime time.Time) (*UsageStats, error) {
	todayUsage, err := t.GetTodayUsage(deviceID, limitID, resetTime)
	if err != nil {
		return nil, err
	}

	stats := &UsageStats{
		TodayUsage:     todayUsage,
		RemainingToday: dailyLimit - todayUsage,
		LimitExceeded:  todayUsage >= dailyLimit,
	}

	if stats.RemainingToday < 0 {
		stats.RemainingToday = 0
	}

	return stats, nil
}

// GetCategoryUsage returns the total usage for a category today (category = limitID)
// This is a simplified version that assumes daily reset at midnight
func (t *Tracker) GetCategoryUsage(deviceID, category string) (time.Duration, error) {
	// Use midnight as reset time (simplified)
	resetTime := time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
	return t.GetTodayUsage(deviceID, category, resetTime)
}

// StopSession manually stops a session
func (t *Tracker) StopSession(sessionID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	session, exists := t.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return t.finalizeSession(session)
}

// finalizeSession finalizes a session (must be called with lock held)
func (t *Tracker) finalizeSession(session *Session) error {
	if !session.Active {
		return nil // Already finalized
	}

	// Check minimum duration
	totalDuration := time.Duration(session.AccumulatedSeconds) * time.Second
	if totalDuration < t.minSessionDuration {
		t.logger.Debug().
			Str("session_id", session.ID).
			Dur("duration", totalDuration).
			Dur("min_duration", t.minSessionDuration).
			Msg("Session too short, not counting")

		session.Active = false
		delete(t.sessions, session.ID)
		delete(t.deviceLimitSessions, session.DeviceID+":"+session.LimitID)

		// Delete from storage
		_ = t.usageStore.DeleteSession(context.Background(), session.ID)

		return nil
	}

	// Mark as inactive
	session.Active = false

	// Update storage
	if err := t.usageStore.UpsertSession(context.Background(), storage.UsageSession{
		ID:                 session.ID,
		DeviceID:           session.DeviceID,
		LimitID:            session.LimitID,
		StartedAt:          session.StartedAt,
		LastActivity:       session.LastActivity,
		AccumulatedSeconds: session.AccumulatedSeconds,
		Active:             session.Active,
	}); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Aggregate to daily usage
	if err := t.aggregateToDailyUsage(session); err != nil {
		return fmt.Errorf("failed to aggregate to daily usage: %w", err)
	}

	// Remove from active tracking
	delete(t.sessions, session.ID)
	delete(t.deviceLimitSessions, session.DeviceID+":"+session.LimitID)

	t.logger.Info().
		Str("session_id", session.ID).
		Str("device_id", session.DeviceID).
		Str("limit_id", session.LimitID).
		Int64("total_seconds", session.AccumulatedSeconds).
		Msg("Finalized usage session")

	return nil
}

// saveSession saves a new session to storage
func (t *Tracker) saveSession(session *Session) error {
	return t.usageStore.UpsertSession(context.Background(), storage.UsageSession{
		ID:                 session.ID,
		DeviceID:           session.DeviceID,
		LimitID:            session.LimitID,
		StartedAt:          session.StartedAt,
		LastActivity:       session.LastActivity,
		AccumulatedSeconds: session.AccumulatedSeconds,
		Active:             session.Active,
	})
}

// aggregateToDailyUsage adds session time to daily usage totals
func (t *Tracker) aggregateToDailyUsage(session *Session) error {
	// Get the date for this session (based on when it started)
	date := session.StartedAt.Format("2006-01-02")

	if err := t.usageStore.IncrementDailyUsage(context.Background(), date, session.DeviceID, session.LimitID, session.AccumulatedSeconds); err != nil {
		return fmt.Errorf("failed to aggregate daily usage: %w", err)
	}

	// Record usage minutes metric (get category from limit ID if possible)
	// For now, use "unknown" category - could be enhanced to query storage for category
	minutesUsed := float64(session.AccumulatedSeconds) / 60.0
	metrics.UsageMinutesConsumed.WithLabelValues(session.DeviceID, "session").Add(minutesUsed)

	t.logger.Debug().
		Str("date", date).
		Str("device_id", session.DeviceID).
		Str("limit_id", session.LimitID).
		Int64("seconds", session.AccumulatedSeconds).
		Msg("Aggregated session to daily usage")

	return nil
}

func errorsIsNotFound(err error) bool {
	return errors.Is(err, storage.ErrNotFound)
}

// cleanupInactiveSessions periodically checks for and finalizes inactive sessions
func (t *Tracker) cleanupInactiveSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.Lock()

		now := time.Now()
		for sessionID, session := range t.sessions {
			if !session.Active {
				continue
			}

			// Check if session has been inactive too long
			if now.Sub(session.LastActivity) > t.inactivityTimeout {
				t.logger.Debug().
					Str("session_id", sessionID).
					Str("device_id", session.DeviceID).
					Dur("inactive", now.Sub(session.LastActivity)).
					Msg("Cleaning up inactive session")

				if err := t.finalizeSession(session); err != nil {
					t.logger.Error().Err(err).Str("session_id", sessionID).Msg("Failed to finalize inactive session")
				}
			}
		}

		t.mu.Unlock()
	}
}

// getResetDate calculates the reset date based on current time and reset time
func getResetDate(now time.Time, resetTime time.Time) time.Time {
	// Parse reset time (should be HH:MM format)
	resetHour := resetTime.Hour()
	resetMinute := resetTime.Minute()

	// Get today at reset time
	today := time.Date(now.Year(), now.Month(), now.Day(), resetHour, resetMinute, 0, 0, now.Location())

	// If we haven't reached reset time today, yesterday is still the current "day"
	if now.Before(today) {
		return today.AddDate(0, 0, -1)
	}

	return today
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// This should never happen with a working system RNG
		panic(fmt.Sprintf("failed to generate random session ID: %v", err))
	}
	return hex.EncodeToString(bytes)
}
