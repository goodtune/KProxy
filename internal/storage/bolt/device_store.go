package bolt

import (
	"context"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type deviceStore struct {
	db *bbolt.DB
}

func (s *deviceStore) Get(ctx context.Context, id string) (*storage.Device, error) {
	return getBucketValue[storage.Device](ctx, s.db, bucketDevices, id)
}

func (s *deviceStore) List(ctx context.Context) ([]storage.Device, error) {
	return listBucket[storage.Device](ctx, s.db, bucketDevices)
}

func (s *deviceStore) ListActive(ctx context.Context) ([]storage.Device, error) {
	devices, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	active := make([]storage.Device, 0, len(devices))
	for _, device := range devices {
		if device.Active {
			active = append(active, device)
		}
	}
	return active, nil
}

func (s *deviceStore) Upsert(ctx context.Context, device storage.Device) error {
	return putBucketValue(ctx, s.db, bucketDevices, device.ID, device)
}

func (s *deviceStore) Delete(ctx context.Context, id string) error {
	return deleteBucketValue(ctx, s.db, bucketDevices, id)
}
