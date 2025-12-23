package bolt

import (
	"bytes"
	"context"
	"fmt"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type timeRuleStore struct {
	db *bbolt.DB
}

func (s *timeRuleStore) Get(ctx context.Context, profileID, id string) (*storage.TimeRule, error) {
	key := timeRuleKey(profileID, id)
	return getBucketValue[storage.TimeRule](ctx, s.db, bucketTimeRules, key)
}

func (s *timeRuleStore) ListByProfile(ctx context.Context, profileID string) ([]storage.TimeRule, error) {
	prefix := []byte(timeRulePrefix(profileID))
	rules := make([]storage.TimeRule, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketTimeRules))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var rule storage.TimeRule
			if err := unmarshal(v, &rule); err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (s *timeRuleStore) Upsert(ctx context.Context, rule storage.TimeRule) error {
	if rule.ProfileID == "" {
		return fmt.Errorf("time rule profile_id is required")
	}
	key := timeRuleKey(rule.ProfileID, rule.ID)
	return putBucketValue(ctx, s.db, bucketTimeRules, key, rule)
}

func (s *timeRuleStore) Delete(ctx context.Context, profileID, id string) error {
	key := timeRuleKey(profileID, id)
	return deleteBucketValue(ctx, s.db, bucketTimeRules, key)
}

func timeRuleKey(profileID, id string) string {
	return fmt.Sprintf("%s/%s", profileID, id)
}

func timeRulePrefix(profileID string) string {
	return fmt.Sprintf("%s/", profileID)
}
