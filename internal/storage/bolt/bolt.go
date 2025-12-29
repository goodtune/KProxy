package bolt

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

const (
	// Removed: bucketDevices, bucketProfiles, bucketRules, bucketTimeRules, bucketUsageLimits, bucketBypassRules
	// Configuration now in OPA policies
	// Removed: bucketLogsHTTP, bucketLogsDNS, bucketAdminUsers
	// Logs written to structured loggers, admin UI removed
	bucketSessions   = "usage_sessions"
	bucketDailyUsage = "usage_daily"
	bucketDHCPLeases = "dhcp_leases"
)

// Store implements the storage.Store interface using bbolt.
type Store struct {
	db *bbolt.DB
}

// Open opens a BoltDB-backed store.
func Open(path string) (*Store, error) {
	if err := ensureDir(path); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	store := &Store{db: db}
	if err := store.ensureBuckets(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return storage.EnsureDir(dir)
}

func (s *Store) ensureBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		buckets := [][]byte{
			// Removed config buckets: devices, profiles, rules, time_rules, usage_limits, bypass_rules
			// Removed log buckets: logs_http, logs_dns
			// Removed admin bucket: admin_users
			[]byte(bucketSessions),
			[]byte(bucketDailyUsage),
			[]byte(bucketDHCPLeases),
		}

		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}

		return nil
	})
}

// Close closes the underlying store database.
func (s *Store) Close() error {
	return s.db.Close()
}

// REMOVED: Devices, Profiles, Rules, TimeRules, UsageLimits, BypassRules stores
// Configuration now managed in OPA policies
// REMOVED: Logs, AdminUsers stores
// Logs written to structured loggers, admin UI removed

// Usage returns the usage store.
func (s *Store) Usage() storage.UsageStore { return &usageStore{db: s.db} }

// DHCPLeases returns the DHCP lease store.
func (s *Store) DHCPLeases() storage.DHCPLeaseStore { return &dhcpLeaseStore{db: s.db} }

func marshal(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal value: %w", err)
	}
	return data, nil
}

func unmarshal(data []byte, out any) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unmarshal value: %w", err)
	}
	return nil
}

func listBucket[T any](ctx context.Context, db *bbolt.DB, bucket string) ([]T, error) {
	items := make([]T, 0)
	return items, db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var item T
			if err := unmarshal(v, &item); err != nil {
				return err
			}
			items = append(items, item)
			return nil
		})
	})
}

func getBucketValue[T any](ctx context.Context, db *bbolt.DB, bucket string, key string) (*T, error) {
	var item *T
	err := db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return storage.ErrNotFound
		}
		value := b.Get([]byte(key))
		if value == nil {
			return storage.ErrNotFound
		}
		var result T
		if err := unmarshal(value, &result); err != nil {
			return err
		}
		item = &result
		return nil
	})
	if err != nil {
		return nil, err
	}
	return item, nil
}

func putBucketValue(ctx context.Context, db *bbolt.DB, bucket string, key string, value any) error {
	data, err := marshal(value)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket missing: %s", bucket)
		}
		return b.Put([]byte(key), data)
	})
}

func deleteBucketValue(ctx context.Context, db *bbolt.DB, bucket string, key string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return storage.ErrNotFound
		}
		value := b.Get([]byte(key))
		if value == nil {
			return storage.ErrNotFound
		}
		return b.Delete([]byte(key))
	})
}
