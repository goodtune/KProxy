package usage

import (
	"time"

	"github.com/goodtune/kproxy/internal/database"
	"github.com/rs/zerolog"
)

// ResetScheduler manages daily usage resets
type ResetScheduler struct {
	db        *database.DB
	resetTime time.Time // Time of day to reset (only hour and minute are used)
	logger    zerolog.Logger
	stopChan  chan struct{}
}

// NewResetScheduler creates a new reset scheduler
func NewResetScheduler(db *database.DB, resetTime string, logger zerolog.Logger) (*ResetScheduler, error) {
	// Parse reset time (HH:MM format)
	parsedTime, err := time.Parse("15:04", resetTime)
	if err != nil {
		return nil, err
	}

	rs := &ResetScheduler{
		db:        db,
		resetTime: parsedTime,
		logger:    logger.With().Str("component", "reset-scheduler").Logger(),
		stopChan:  make(chan struct{}),
	}

	return rs, nil
}

// Start begins the reset scheduler
func (rs *ResetScheduler) Start() {
	go rs.run()
	rs.logger.Info().
		Str("reset_time", rs.resetTime.Format("15:04")).
		Msg("Daily usage reset scheduler started")
}

// Stop stops the reset scheduler
func (rs *ResetScheduler) Stop() {
	close(rs.stopChan)
	rs.logger.Info().Msg("Daily usage reset scheduler stopped")
}

// run is the main scheduler loop
func (rs *ResetScheduler) run() {
	for {
		// Calculate next reset time
		nextReset := rs.calculateNextReset()
		waitDuration := time.Until(nextReset)

		rs.logger.Info().
			Time("next_reset", nextReset).
			Dur("wait_duration", waitDuration).
			Msg("Scheduled next daily reset")

		// Wait until reset time or stop signal
		select {
		case <-time.After(waitDuration):
			rs.performReset()
		case <-rs.stopChan:
			return
		}
	}
}

// calculateNextReset calculates the next reset time
func (rs *ResetScheduler) calculateNextReset() time.Time {
	now := time.Now()

	// Get today's reset time
	todayReset := time.Date(
		now.Year(), now.Month(), now.Day(),
		rs.resetTime.Hour(), rs.resetTime.Minute(), 0, 0,
		now.Location(),
	)

	// If we've already passed today's reset time, schedule for tomorrow
	if now.After(todayReset) {
		return todayReset.AddDate(0, 0, 1)
	}

	return todayReset
}

// performReset performs the daily usage reset
func (rs *ResetScheduler) performReset() {
	rs.logger.Info().Msg("Performing daily usage reset")

	// Note: We don't actually delete old data - daily_usage table keeps historical data
	// The reset is automatic because GetTodayUsage queries based on current date

	// Optional: Clean up old daily_usage entries (older than retention period)
	retentionDays := 90 // Keep 90 days of history
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02")

	result, err := rs.db.Exec(`
		DELETE FROM daily_usage
		WHERE date < ?
	`, cutoffDate)

	if err != nil {
		rs.logger.Error().Err(err).Msg("Failed to clean up old daily usage data")
		return
	}

	rowsDeleted, _ := result.RowsAffected()
	rs.logger.Info().
		Int64("rows_deleted", rowsDeleted).
		Str("cutoff_date", cutoffDate).
		Msg("Daily usage reset complete, old data cleaned up")

	// Also clean up old finalized sessions
	result, err = rs.db.Exec(`
		DELETE FROM usage_sessions
		WHERE active = 0 AND started_at < ?
	`, cutoffDate)

	if err != nil {
		rs.logger.Error().Err(err).Msg("Failed to clean up old sessions")
		return
	}

	sessionsDeleted, _ := result.RowsAffected()
	rs.logger.Info().
		Int64("sessions_deleted", sessionsDeleted).
		Msg("Old sessions cleaned up")
}
