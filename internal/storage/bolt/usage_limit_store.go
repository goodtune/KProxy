package bolt

import (
	"bytes"
	"context"
	"fmt"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type usageLimitStore struct {
	db *bbolt.DB
}

func (s *usageLimitStore) Get(ctx context.Context, profileID, id string) (*storage.UsageLimit, error) {
	key := usageLimitKey(profileID, id)
	return getBucketValue[storage.UsageLimit](ctx, s.db, bucketUsageLimits, key)
}

func (s *usageLimitStore) ListByProfile(ctx context.Context, profileID string) ([]storage.UsageLimit, error) {
	prefix := []byte(usageLimitPrefix(profileID))
	limits := make([]storage.UsageLimit, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketUsageLimits))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var limit storage.UsageLimit
			if err := unmarshal(v, &limit); err != nil {
				return err
			}
			limits = append(limits, limit)
		}
		return nil
	})
	return limits, err
}

func (s *usageLimitStore) Upsert(ctx context.Context, limit storage.UsageLimit) error {
	if limit.ProfileID == "" {
		return fmt.Errorf("usage limit profile_id is required")
	}
	key := usageLimitKey(limit.ProfileID, limit.ID)
	return putBucketValue(ctx, s.db, bucketUsageLimits, key, limit)
}

func (s *usageLimitStore) Delete(ctx context.Context, profileID, id string) error {
	key := usageLimitKey(profileID, id)
	return deleteBucketValue(ctx, s.db, bucketUsageLimits, key)
}

func usageLimitKey(profileID, id string) string {
	return fmt.Sprintf("%s/%s", profileID, id)
}

func usageLimitPrefix(profileID string) string {
	return fmt.Sprintf("%s/", profileID)
}
