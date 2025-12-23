package bolt

import (
	"context"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type bypassRuleStore struct {
	db *bbolt.DB
}

func (s *bypassRuleStore) Get(ctx context.Context, id string) (*storage.BypassRule, error) {
	return getBucketValue[storage.BypassRule](ctx, s.db, bucketBypassRules, id)
}

func (s *bypassRuleStore) List(ctx context.Context) ([]storage.BypassRule, error) {
	return listBucket[storage.BypassRule](ctx, s.db, bucketBypassRules)
}

func (s *bypassRuleStore) ListEnabled(ctx context.Context) ([]storage.BypassRule, error) {
	rules, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	enabled := make([]storage.BypassRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled, nil
}

func (s *bypassRuleStore) Upsert(ctx context.Context, rule storage.BypassRule) error {
	return putBucketValue(ctx, s.db, bucketBypassRules, rule.ID, rule)
}

func (s *bypassRuleStore) Delete(ctx context.Context, id string) error {
	return deleteBucketValue(ctx, s.db, bucketBypassRules, id)
}
