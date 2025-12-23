package bolt

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type adminUserStore struct {
	db *bbolt.DB
}

// Get retrieves an admin user by username.
func (s *adminUserStore) Get(ctx context.Context, username string) (*storage.AdminUser, error) {
	var user storage.AdminUser

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAdminUsers))
		if bucket == nil {
			return storage.ErrNotFound
		}

		data := bucket.Get([]byte(username))
		if data == nil {
			return storage.ErrNotFound
		}

		return unmarshal(data, &user)
	})

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// List retrieves all admin users.
func (s *adminUserStore) List(ctx context.Context) ([]storage.AdminUser, error) {
	var users []storage.AdminUser

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAdminUsers))
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var user storage.AdminUser
			if err := unmarshal(v, &user); err != nil {
				return err
			}
			users = append(users, user)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return users, nil
}

// Upsert creates or updates an admin user.
func (s *adminUserStore) Upsert(ctx context.Context, user storage.AdminUser) error {
	// Set timestamps
	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now

	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAdminUsers))
		if bucket == nil {
			return fmt.Errorf("admin_users bucket not found")
		}

		data, err := marshal(user)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(user.Username), data)
	})
}

// Delete removes an admin user by username.
func (s *adminUserStore) Delete(ctx context.Context, username string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAdminUsers))
		if bucket == nil {
			return storage.ErrNotFound
		}

		if bucket.Get([]byte(username)) == nil {
			return storage.ErrNotFound
		}

		return bucket.Delete([]byte(username))
	})
}

// UpdateLastLogin updates the last login timestamp for a user.
func (s *adminUserStore) UpdateLastLogin(ctx context.Context, username string, loginTime time.Time) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAdminUsers))
		if bucket == nil {
			return storage.ErrNotFound
		}

		data := bucket.Get([]byte(username))
		if data == nil {
			return storage.ErrNotFound
		}

		var user storage.AdminUser
		if err := unmarshal(data, &user); err != nil {
			return err
		}

		user.LastLogin = &loginTime
		user.UpdatedAt = time.Now()

		newData, err := marshal(user)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(username), newData)
	})
}
