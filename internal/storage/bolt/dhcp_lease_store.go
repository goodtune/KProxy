package bolt

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type dhcpLeaseStore struct {
	db *bbolt.DB
}

func (s *dhcpLeaseStore) Get(ctx context.Context, mac string) (*storage.DHCPLease, error) {
	return getBucketValue[storage.DHCPLease](ctx, s.db, bucketDHCPLeases, mac)
}

func (s *dhcpLeaseStore) GetByMAC(ctx context.Context, mac string) (*storage.DHCPLease, error) {
	return s.Get(ctx, mac)
}

func (s *dhcpLeaseStore) GetByIP(ctx context.Context, ip string) (*storage.DHCPLease, error) {
	leases, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, lease := range leases {
		if lease.IP == ip {
			return &lease, nil
		}
	}

	return nil, storage.ErrNotFound
}

func (s *dhcpLeaseStore) List(ctx context.Context) ([]storage.DHCPLease, error) {
	return listBucket[storage.DHCPLease](ctx, s.db, bucketDHCPLeases)
}

func (s *dhcpLeaseStore) Create(ctx context.Context, lease *storage.DHCPLease) error {
	now := time.Now()

	// Check if lease exists
	existing, err := s.Get(ctx, lease.MAC)
	if err == nil && existing != nil {
		// Update existing lease
		lease.CreatedAt = existing.CreatedAt
		lease.UpdatedAt = now
	} else {
		// Create new lease
		lease.CreatedAt = now
		lease.UpdatedAt = now
	}

	return putBucketValue(ctx, s.db, bucketDHCPLeases, lease.MAC, *lease)
}

func (s *dhcpLeaseStore) Delete(ctx context.Context, mac string) error {
	return deleteBucketValue(ctx, s.db, bucketDHCPLeases, mac)
}

func (s *dhcpLeaseStore) DeleteExpired(ctx context.Context) (int, error) {
	var deleted int

	err := s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketDHCPLeases))
		if bucket == nil {
			return fmt.Errorf("bucket %s not found", bucketDHCPLeases)
		}

		var toDelete []string
		now := time.Now()

		// Collect expired leases
		err := bucket.ForEach(func(k, v []byte) error {
			var lease storage.DHCPLease
			if err := unmarshal(v, &lease); err != nil {
				return err
			}

			if now.After(lease.ExpiresAt) {
				toDelete = append(toDelete, string(k))
			}

			return nil
		})
		if err != nil {
			return err
		}

		// Delete expired leases
		for _, key := range toDelete {
			if err := bucket.Delete([]byte(key)); err != nil {
				return err
			}
			deleted++
		}

		return nil
	})

	return deleted, err
}
