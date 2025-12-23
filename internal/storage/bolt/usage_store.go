package bolt

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type usageStore struct {
	db *bbolt.DB
}

func (s *usageStore) UpsertSession(ctx context.Context, session storage.UsageSession) error {
	return putBucketValue(ctx, s.db, bucketSessions, session.ID, session)
}

func (s *usageStore) DeleteSession(ctx context.Context, id string) error {
	return deleteBucketValue(ctx, s.db, bucketSessions, id)
}

func (s *usageStore) GetSession(ctx context.Context, id string) (*storage.UsageSession, error) {
	return getBucketValue[storage.UsageSession](ctx, s.db, bucketSessions, id)
}

func (s *usageStore) GetDailyUsage(ctx context.Context, date string, deviceID, limitID string) (*storage.DailyUsage, error) {
	key := dailyUsageKey(date, deviceID, limitID)
	return getBucketValue[storage.DailyUsage](ctx, s.db, bucketDailyUsage, key)
}

func (s *usageStore) IncrementDailyUsage(ctx context.Context, date string, deviceID, limitID string, seconds int64) error {
	key := dailyUsageKey(date, deviceID, limitID)
	return s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketDailyUsage))
		if b == nil {
			return fmt.Errorf("daily usage bucket missing")
		}
		var usage storage.DailyUsage
		if existing := b.Get([]byte(key)); existing != nil {
			if err := unmarshal(existing, &usage); err != nil {
				return err
			}
		} else {
			usage = storage.DailyUsage{
				Date:     date,
				DeviceID: deviceID,
				LimitID:  limitID,
			}
		}
		usage.TotalSeconds += seconds
		data, err := marshal(usage)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})
}

func (s *usageStore) DeleteDailyUsageBefore(ctx context.Context, cutoffDate string) (int, error) {
	cutoff, err := time.Parse("2006-01-02", cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("invalid cutoff date: %w", err)
	}
	deleted := 0
	return deleted, s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketDailyUsage))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var usage storage.DailyUsage
			if err := unmarshal(v, &usage); err != nil {
				return err
			}
			dateValue, err := time.Parse("2006-01-02", usage.Date)
			if err != nil {
				continue
			}
			if dateValue.Before(cutoff) {
				if err := c.Delete(); err != nil {
					return err
				}
				deleted++
			}
		}
		return nil
	})
}

func (s *usageStore) DeleteInactiveSessionsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	deleted := 0
	return deleted, s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketSessions))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var session storage.UsageSession
			if err := unmarshal(v, &session); err != nil {
				return err
			}
			if !session.Active && session.StartedAt.Before(cutoff) {
				if err := c.Delete(); err != nil {
					return err
				}
				deleted++
			}
		}
		return nil
	})
}

func dailyUsageKey(date, deviceID, limitID string) string {
	return fmt.Sprintf("%s/%s/%s", date, deviceID, limitID)
}
