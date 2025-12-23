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

func (s *logStore) QueryRequestLogs(ctx context.Context, filter storage.RequestLogFilter) ([]storage.RequestLog, error) {
	var logs []storage.RequestLog

	return logs, s.db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		bucket := tx.Bucket([]byte(bucketLogsHTTP))
		if bucket == nil {
			return nil
		}

		// Collect IDs from index if filtering
		var logIDs []string
		if filter.DeviceID != "" || filter.Domain != "" || filter.Action != "" {
			logIDs = s.getRequestLogIDsFromIndex(tx, filter)
		}

		// Iterate logs
		c := bucket.Cursor()
		count := 0
		skipped := 0

		for k, v := c.Last(); k != nil; k, v = c.Prev() { // Reverse order (newest first)
			if filter.Limit > 0 && count >= filter.Limit {
				break
			}

			var log storage.RequestLog
			if err := unmarshal(v, &log); err != nil {
				continue
			}

			// Apply filters
			if filter.StartTime != nil && log.Timestamp.Before(*filter.StartTime) {
				continue
			}
			if filter.EndTime != nil && log.Timestamp.After(*filter.EndTime) {
				continue
			}
			if len(logIDs) > 0 && !contains(logIDs, log.ID) {
				continue
			}

			// Apply offset
			if skipped < filter.Offset {
				skipped++
				continue
			}

			logs = append(logs, log)
			count++
		}

		return nil
	})
}

func (s *logStore) QueryDNSLogs(ctx context.Context, filter storage.DNSLogFilter) ([]storage.DNSLog, error) {
	var logs []storage.DNSLog

	return logs, s.db.View(func(tx *bbolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		bucket := tx.Bucket([]byte(bucketLogsDNS))
		if bucket == nil {
			return nil
		}

		// Collect IDs from index if filtering
		var logIDs []string
		if filter.DeviceID != "" || filter.Domain != "" || filter.Action != "" {
			logIDs = s.getDNSLogIDsFromIndex(tx, filter)
		}

		// Iterate logs
		c := bucket.Cursor()
		count := 0
		skipped := 0

		for k, v := c.Last(); k != nil; k, v = c.Prev() { // Reverse order (newest first)
			if filter.Limit > 0 && count >= filter.Limit {
				break
			}

			var log storage.DNSLog
			if err := unmarshal(v, &log); err != nil {
				continue
			}

			// Apply filters
			if filter.StartTime != nil && log.Timestamp.Before(*filter.StartTime) {
				continue
			}
			if filter.EndTime != nil && log.Timestamp.After(*filter.EndTime) {
				continue
			}
			if len(logIDs) > 0 && !contains(logIDs, log.ID) {
				continue
			}

			// Apply offset
			if skipped < filter.Offset {
				skipped++
				continue
			}

			logs = append(logs, log)
			count++
		}

		return nil
	})
}

func (s *logStore) getRequestLogIDsFromIndex(tx *bbolt.Tx, filter storage.RequestLogFilter) []string {
	var ids []string

	indexBucket := tx.Bucket([]byte(bucketIndexesHTTP))
	if indexBucket == nil {
		return ids
	}

	// Use the most selective index
	var bucket *bbolt.Bucket
	if filter.DeviceID != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexDevice))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(filter.DeviceID)))
		}
	} else if filter.Domain != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexDomain))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(filter.Domain)))
		}
	} else if filter.Action != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexAction))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(string(filter.Action))))
		}
	}

	if bucket != nil {
		c := bucket.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			ids = append(ids, string(k))
		}
	}

	return ids
}

func (s *logStore) getDNSLogIDsFromIndex(tx *bbolt.Tx, filter storage.DNSLogFilter) []string {
	var ids []string

	indexBucket := tx.Bucket([]byte(bucketIndexesDNS))
	if indexBucket == nil {
		return ids
	}

	// Use the most selective index
	var bucket *bbolt.Bucket
	if filter.DeviceID != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexDevice))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(filter.DeviceID)))
		}
	} else if filter.Domain != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexDomain))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(filter.Domain)))
		}
	} else if filter.Action != "" {
		bucket = indexBucket.Bucket([]byte(bucketIndexAction))
		if bucket != nil {
			bucket = bucket.Bucket([]byte(normalizeIndexKey(filter.Action)))
		}
	}

	if bucket != nil {
		c := bucket.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			ids = append(ids, string(k))
		}
	}

	return ids
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
