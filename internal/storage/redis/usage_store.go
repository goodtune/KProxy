package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/redis/go-redis/v9"
)

type usageStore struct {
	client *redis.Client
}

// UpsertSession creates or updates a usage session
func (s *usageStore) UpsertSession(ctx context.Context, session storage.UsageSession) error {
	script := redis.NewScript(upsertSessionScript)

	sessionKey := fmt.Sprintf("kproxy:session:%s", session.ID)
	activeSet := "kproxy:sessions:active"
	deviceKey := fmt.Sprintf("kproxy:sessions:device:%s:%s", session.DeviceID, session.LimitID)

	active := "0"
	if session.Active {
		active = "1"
	}

	keys := []string{sessionKey, activeSet, deviceKey}
	args := []interface{}{
		session.ID,
		session.DeviceID,
		session.LimitID,
		session.StartedAt.Format(time.RFC3339Nano),
		session.LastActivity.Format(time.RFC3339Nano),
		session.AccumulatedSeconds,
		active,
	}

	return script.Run(ctx, s.client, keys, args...).Err()
}

// DeleteSession removes a session by ID
func (s *usageStore) DeleteSession(ctx context.Context, id string) error {
	sessionKey := fmt.Sprintf("kproxy:session:%s", id)

	// Get session to find device/limit for cleanup
	data, err := s.client.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		return err
	}

	// Delete session key
	if err := s.client.Del(ctx, sessionKey).Err(); err != nil {
		return err
	}

	// Remove from active set
	if err := s.client.SRem(ctx, "kproxy:sessions:active", id).Err(); err != nil {
		return err
	}

	// Remove device mapping if we have the data
	if deviceID, ok := data["device_id"]; ok {
		if limitID, ok := data["limit_id"]; ok {
			deviceKey := fmt.Sprintf("kproxy:sessions:device:%s:%s", deviceID, limitID)
			s.client.Del(ctx, deviceKey)
		}
	}

	return nil
}

// GetSession retrieves a session by ID
func (s *usageStore) GetSession(ctx context.Context, id string) (*storage.UsageSession, error) {
	sessionKey := fmt.Sprintf("kproxy:session:%s", id)

	data, err := s.client.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	return parseUsageSession(data)
}

// ListActiveSessions returns all active sessions
func (s *usageStore) ListActiveSessions(ctx context.Context) ([]storage.UsageSession, error) {
	// Get all active session IDs
	sessionIDs, err := s.client.SMembers(ctx, "kproxy:sessions:active").Result()
	if err != nil {
		return nil, err
	}

	if len(sessionIDs) == 0 {
		return []storage.UsageSession{}, nil
	}

	// Use pipeline for efficient batch retrieval
	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(sessionIDs))

	for i, id := range sessionIDs {
		sessionKey := fmt.Sprintf("kproxy:session:%s", id)
		cmds[i] = pipe.HGetAll(ctx, sessionKey)
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	// Parse results
	sessions := make([]storage.UsageSession, 0, len(sessionIDs))
	for _, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil || len(data) == 0 {
			continue
		}

		session, err := parseUsageSession(data)
		if err == nil {
			sessions = append(sessions, *session)
		}
	}

	return sessions, nil
}

// GetDailyUsage retrieves daily usage for a specific date, device, and limit
func (s *usageStore) GetDailyUsage(ctx context.Context, date string, deviceID, limitID string) (*storage.DailyUsage, error) {
	usageKey := fmt.Sprintf("kproxy:usage:daily:%s:%s:%s", date, deviceID, limitID)

	data, err := s.client.HGetAll(ctx, usageKey).Result()
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	return parseDailyUsage(data)
}

// ListDailyUsage returns all daily usage entries for a specific date
func (s *usageStore) ListDailyUsage(ctx context.Context, date string) ([]storage.DailyUsage, error) {
	indexKey := fmt.Sprintf("kproxy:usage:daily:index:%s", date)

	// Get all device:limit pairs for this date
	pairs, err := s.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return nil, err
	}

	if len(pairs) == 0 {
		return []storage.DailyUsage{}, nil
	}

	// Use pipeline for batch retrieval
	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(pairs))

	for i, pair := range pairs {
		usageKey := fmt.Sprintf("kproxy:usage:daily:%s:%s", date, pair)
		cmds[i] = pipe.HGetAll(ctx, usageKey)
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	// Parse results
	usages := make([]storage.DailyUsage, 0, len(pairs))
	for _, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil || len(data) == 0 {
			continue
		}

		usage, err := parseDailyUsage(data)
		if err == nil {
			usages = append(usages, *usage)
		}
	}

	return usages, nil
}

// IncrementDailyUsage atomically increments (or creates) daily usage
func (s *usageStore) IncrementDailyUsage(ctx context.Context, date string, deviceID, limitID string, seconds int64) error {
	script := redis.NewScript(incrementDailyUsageScript)

	usageKey := fmt.Sprintf("kproxy:usage:daily:%s:%s:%s", date, deviceID, limitID)
	indexKey := fmt.Sprintf("kproxy:usage:daily:index:%s", date)

	keys := []string{usageKey, indexKey}
	args := []interface{}{date, deviceID, limitID, seconds}

	return script.Run(ctx, s.client, keys, args...).Err()
}

// DeleteDailyUsageBefore deletes daily usage entries before the specified date
// NOTE: With Redis TTL (90 days), this is mostly a no-op for automatic cleanup
// We keep this for compatibility but it won't do much since TTL handles expiration
func (s *usageStore) DeleteDailyUsageBefore(ctx context.Context, cutoffDate string) (int, error) {
	// With TTL, keys expire automatically after 90 days
	// This operation is kept for interface compatibility but is effectively a no-op
	// In a real implementation, you could scan and delete keys manually if needed
	return 0, nil
}

// DeleteInactiveSessionsBefore deletes inactive sessions before the specified time
// NOTE: With Redis TTL (90 days on inactive sessions), this is mostly a no-op
// We keep this for compatibility but TTL handles expiration automatically
func (s *usageStore) DeleteInactiveSessionsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	// With TTL, inactive sessions expire automatically after 90 days
	// This operation is kept for interface compatibility but is effectively a no-op

	// If we wanted to implement this, we'd need to scan all sessions and check StartedAt
	// For now, we rely on TTL for cleanup

	// Optional: Scan and delete manually for immediate cleanup
	var cursor uint64
	var deletedCount int

	for {
		var keys []string
		var err error
		keys, cursor, err = s.client.Scan(ctx, cursor, "kproxy:session:*", 100).Result()
		if err != nil {
			return deletedCount, err
		}

		if len(keys) > 0 {
			// Use pipeline to check each session
			pipe := s.client.Pipeline()
			cmds := make([]*redis.MapStringStringCmd, len(keys))
			for i, key := range keys {
				cmds[i] = pipe.HGetAll(ctx, key)
			}

			if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
				return deletedCount, err
			}

			// Check which sessions should be deleted
			toDelete := make([]string, 0)
			for i, cmd := range cmds {
				data, err := cmd.Result()
				if err != nil || len(data) == 0 {
					continue
				}

				// Parse active and started_at
				active := data["active"] == "1"
				if active {
					continue // Skip active sessions
				}

				startedAt, err := time.Parse(time.RFC3339Nano, data["started_at"])
				if err != nil {
					continue
				}

				if startedAt.Before(cutoff) {
					toDelete = append(toDelete, keys[i])
					// Also extract session ID for cleanup
					if sessionID, ok := data["id"]; ok {
						// Remove from active set (should already be removed, but just in case)
						s.client.SRem(ctx, "kproxy:sessions:active", sessionID)

						// Remove device mapping
						if deviceID, ok := data["device_id"]; ok {
							if limitID, ok := data["limit_id"]; ok {
								deviceKey := fmt.Sprintf("kproxy:sessions:device:%s:%s", deviceID, limitID)
								s.client.Del(ctx, deviceKey)
							}
						}
					}
				}
			}

			// Delete the sessions
			if len(toDelete) > 0 {
				deleted, err := s.client.Del(ctx, toDelete...).Result()
				if err != nil {
					return deletedCount, err
				}
				deletedCount += int(deleted)
			}
		}

		if cursor == 0 {
			break
		}
	}

	return deletedCount, nil
}
