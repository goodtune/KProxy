package bolt

import (
	"context"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type profileStore struct {
	db *bbolt.DB
}

func (s *profileStore) Get(ctx context.Context, id string) (*storage.Profile, error) {
	return getBucketValue[storage.Profile](ctx, s.db, bucketProfiles, id)
}

func (s *profileStore) List(ctx context.Context) ([]storage.Profile, error) {
	return listBucket[storage.Profile](ctx, s.db, bucketProfiles)
}

func (s *profileStore) Upsert(ctx context.Context, profile storage.Profile) error {
	return putBucketValue(ctx, s.db, bucketProfiles, profile.ID, profile)
}

func (s *profileStore) Delete(ctx context.Context, id string) error {
	return deleteBucketValue(ctx, s.db, bucketProfiles, id)
}
