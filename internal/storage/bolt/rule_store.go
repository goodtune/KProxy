package bolt

import (
	"bytes"
	"context"
	"fmt"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type ruleStore struct {
	db *bbolt.DB
}

func (s *ruleStore) Get(ctx context.Context, profileID, id string) (*storage.Rule, error) {
	key := ruleKey(profileID, id)
	return getBucketValue[storage.Rule](ctx, s.db, bucketRules, key)
}

func (s *ruleStore) ListByProfile(ctx context.Context, profileID string) ([]storage.Rule, error) {
	prefix := []byte(rulePrefix(profileID))
	rules := make([]storage.Rule, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucketRules))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var rule storage.Rule
			if err := unmarshal(v, &rule); err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (s *ruleStore) ListAll(ctx context.Context) ([]storage.Rule, error) {
	return listBucket[storage.Rule](ctx, s.db, bucketRules)
}

func (s *ruleStore) Upsert(ctx context.Context, rule storage.Rule) error {
	if rule.ProfileID == "" {
		return fmt.Errorf("rule profile_id is required")
	}
	key := ruleKey(rule.ProfileID, rule.ID)
	return putBucketValue(ctx, s.db, bucketRules, key, rule)
}

func (s *ruleStore) Delete(ctx context.Context, profileID, id string) error {
	key := ruleKey(profileID, id)
	return deleteBucketValue(ctx, s.db, bucketRules, key)
}

func ruleKey(profileID, id string) string {
	return fmt.Sprintf("%s/%s", profileID, id)
}

func rulePrefix(profileID string) string {
	return fmt.Sprintf("%s/", profileID)
}
