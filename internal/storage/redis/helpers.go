package redis

import (
	"fmt"
	"strconv"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
)

// parseUsageSession converts a Redis hash to UsageSession
func parseUsageSession(data map[string]string) (*storage.UsageSession, error) {
	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	startedAt, err := time.Parse(time.RFC3339Nano, data["started_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse started_at: %w", err)
	}

	lastActivity, err := time.Parse(time.RFC3339Nano, data["last_activity"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse last_activity: %w", err)
	}

	accumulatedSeconds, err := strconv.ParseInt(data["accumulated_seconds"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse accumulated_seconds: %w", err)
	}

	active, err := strconv.ParseBool(data["active"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse active: %w", err)
	}

	return &storage.UsageSession{
		ID:                 data["id"],
		DeviceID:           data["device_id"],
		LimitID:            data["limit_id"],
		StartedAt:          startedAt,
		LastActivity:       lastActivity,
		AccumulatedSeconds: accumulatedSeconds,
		Active:             active,
	}, nil
}

// parseDailyUsage converts a Redis hash to DailyUsage
func parseDailyUsage(data map[string]string) (*storage.DailyUsage, error) {
	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	totalSeconds, err := strconv.ParseInt(data["total_seconds"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse total_seconds: %w", err)
	}

	return &storage.DailyUsage{
		Date:         data["date"],
		DeviceID:     data["device_id"],
		LimitID:      data["limit_id"],
		TotalSeconds: totalSeconds,
	}, nil
}

// parseDHCPLease converts a Redis hash to DHCPLease
func parseDHCPLease(data map[string]string) (*storage.DHCPLease, error) {
	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, data["expires_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, data["created_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	updatedAt, err := time.Parse(time.RFC3339Nano, data["updated_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return &storage.DHCPLease{
		MAC:       data["mac"],
		IP:        data["ip"],
		Hostname:  data["hostname"],
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}
