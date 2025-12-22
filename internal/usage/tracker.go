package usage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/database"
	"github.com/goodtune/kproxy/internal/metrics"
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
	db                 *database.DB
	sessions           map[string]*Session // key: sessionID
	deviceLimitSessions map[string]string   // key: deviceID:limitID -> sessionID
	inactivityTimeout  time.Duration
	minSessionDuration time.Duration
	logger             zerolog.Logger
	mu                 sync.RWMutex
}

// Config holds tracker configuration
type Config struct {
	InactivityTimeout  time.Duration
	MinSessionDuration time.Duration
}

// NewTracker creates a new usage tracker
func NewTracker(db *database.DB, config Config, logger zerolog.Logger) *Tracker {
	if config.InactivityTimeout == 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.MinSessionDuration == 0 {
		config.MinSessionDuration = DefaultMinSessionDuration
	}

	t := &Tracker{
		db:                  db,
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

	// Save to database
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

	// Query database for today's usage
	var totalSeconds sql.NullInt64
	err := t.db.QueryRow(`
		SELECT total_seconds
		FROM daily_usage
		WHERE date = ? AND device_id = ? AND limit_id = ?
	`, today.Format("2006-01-02"), deviceID, limitID).Scan(&totalSeconds)

	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query daily usage: %w", err)
	}

	usage := time.Duration(totalSeconds.Int64) * time.Second

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

	// Get active session if exists
	t.mu.RLock()
	key := deviceID + ":" + limitID
	if sessionID, exists := t.deviceLimitSessions[key]; exists {
		if session := t.sessions[sessionID]; session != nil && session.Active {
			stats.ActiveSession = session
		}
	}
	t.mu.RUnlock()

	return stats, nil
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

		// Delete from database
		_, _ = t.db.Exec("DELETE FROM usage_sessions WHERE id = ?", session.ID)

		return nil
	}

	// Mark as inactive
	session.Active = false

	// Update database
	_, err := t.db.Exec(`
		UPDATE usage_sessions
		SET active = 0, accumulated_seconds = ?
		WHERE id = ?
	`, session.AccumulatedSeconds, session.ID)

	if err != nil {
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

// saveSession saves a new session to the database
func (t *Tracker) saveSession(session *Session) error {
	_, err := t.db.Exec(`
		INSERT INTO usage_sessions (id, device_id, limit_id, started_at, last_activity, accumulated_seconds, active)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, session.ID, session.DeviceID, session.LimitID, session.StartedAt, session.LastActivity, session.AccumulatedSeconds, 1)

	return err
}

// aggregateToDailyUsage adds session time to daily usage totals
func (t *Tracker) aggregateToDailyUsage(session *Session) error {
	// Get the date for this session (based on when it started)
	date := session.StartedAt.Format("2006-01-02")

	// Insert or update daily usage
	_, err := t.db.Exec(`
		INSERT INTO daily_usage (date, device_id, limit_id, total_seconds)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(date, device_id, limit_id)
		DO UPDATE SET total_seconds = total_seconds + excluded.total_seconds
	`, date, session.DeviceID, session.LimitID, session.AccumulatedSeconds)

	if err != nil {
		return fmt.Errorf("failed to aggregate daily usage: %w", err)
	}

	// Record usage minutes metric (get category from limit ID if possible)
	// For now, use "unknown" category - could be enhanced to query the database for category
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
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
