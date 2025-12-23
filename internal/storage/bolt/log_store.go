package bolt

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"go.etcd.io/bbolt"
)

type logStore struct {
	db *bbolt.DB
}

func (s *logStore) AddRequestLog(ctx context.Context, log storage.RequestLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}
	if log.ID == "" {
		key, err := logKey("request", log.Timestamp)
		if err != nil {
			return err
		}
		log.ID = key
	}
	data, err := marshal(log)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		bucket := tx.Bucket([]byte(bucketLogsHTTP))
		if bucket == nil {
			return fmt.Errorf("request log bucket missing")
		}
		if err := bucket.Put([]byte(log.ID), data); err != nil {
			return err
		}
		return s.addRequestIndexes(tx, log)
	})
}

func (s *logStore) AddDNSLog(ctx context.Context, log storage.DNSLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}
	if log.ID == "" {
		key, err := logKey("dns", log.Timestamp)
		if err != nil {
			return err
		}
		log.ID = key
	}
	data, err := marshal(log)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		bucket := tx.Bucket([]byte(bucketLogsDNS))
		if bucket == nil {
			return fmt.Errorf("dns log bucket missing")
		}
		if err := bucket.Put([]byte(log.ID), data); err != nil {
			return err
		}
		return s.addDNSIndexes(tx, log)
	})
}

func (s *logStore) DeleteRequestLogsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	deleted := 0
	return deleted, s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		bucket := tx.Bucket([]byte(bucketLogsHTTP))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var log storage.RequestLog
			if err := unmarshal(v, &log); err != nil {
				return err
			}
			if log.Timestamp.Before(cutoff) {
				if err := c.Delete(); err != nil {
					return err
				}
				deleted++
			}
		}
		return nil
	})
}

func (s *logStore) DeleteDNSLogsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	deleted := 0
	return deleted, s.db.Update(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		bucket := tx.Bucket([]byte(bucketLogsDNS))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var log storage.DNSLog
			if err := unmarshal(v, &log); err != nil {
				return err
			}
			if log.Timestamp.Before(cutoff) {
				if err := c.Delete(); err != nil {
					return err
				}
				deleted++
			}
		}
		return nil
	})
}

func (s *logStore) addRequestIndexes(tx *bbolt.Tx, log storage.RequestLog) error {
	deviceKey := normalizeIndexKey(log.DeviceID)
	deviceBucket, err := ensureIndexBucket(tx, bucketIndexesHTTP, bucketIndexDevice, deviceKey)
	if err != nil {
		return err
	}
	if err := deviceBucket.Put([]byte(log.ID), []byte{}); err != nil {
		return err
	}

	actionBucket, err := ensureIndexBucket(tx, bucketIndexesHTTP, bucketIndexAction, normalizeIndexKey(string(log.Action)))
	if err != nil {
		return err
	}
	if err := actionBucket.Put([]byte(log.ID), []byte{}); err != nil {
		return err
	}

	hostBucket, err := ensureIndexBucket(tx, bucketIndexesHTTP, bucketIndexDomain, normalizeIndexKey(log.Host))
	if err != nil {
		return err
	}
	return hostBucket.Put([]byte(log.ID), []byte{})
}

func (s *logStore) addDNSIndexes(tx *bbolt.Tx, log storage.DNSLog) error {
	deviceKey := normalizeIndexKey(log.DeviceID)
	deviceBucket, err := ensureIndexBucket(tx, bucketIndexesDNS, bucketIndexDevice, deviceKey)
	if err != nil {
		return err
	}
	if err := deviceBucket.Put([]byte(log.ID), []byte{}); err != nil {
		return err
	}

	actionBucket, err := ensureIndexBucket(tx, bucketIndexesDNS, bucketIndexAction, normalizeIndexKey(log.Action))
	if err != nil {
		return err
	}
	if err := actionBucket.Put([]byte(log.ID), []byte{}); err != nil {
		return err
	}

	domainBucket, err := ensureIndexBucket(tx, bucketIndexesDNS, bucketIndexDomain, normalizeIndexKey(log.Domain))
	if err != nil {
		return err
	}
	return domainBucket.Put([]byte(log.ID), []byte{})
}
