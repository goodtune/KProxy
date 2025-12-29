package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/redis/go-redis/v9"
)

// Store implements the storage.Store interface using Redis
type Store struct {
	client     *redis.Client
	usageStore *usageStore
	dhcpStore  *dhcpLeaseStore
}

// Open creates a new Redis-backed storage instance
func Open(cfg config.RedisConfig) (*Store, error) {
	// Parse timeouts
	dialTimeout, err := time.ParseDuration(cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid dial_timeout: %w", err)
	}

	readTimeout, err := time.ParseDuration(cfg.ReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid read_timeout: %w", err)
	}

	writeTimeout, err := time.ParseDuration(cfg.WriteTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid write_timeout: %w", err)
	}

	// Determine address
	addr := cfg.Host
	if cfg.Port > 0 {
		addr = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	}

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	})

	// Ping to verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Initialize stores
	store := &Store{
		client:     client,
		usageStore: &usageStore{client: client},
		dhcpStore:  &dhcpLeaseStore{client: client},
	}

	return store, nil
}

// Close closes the Redis connection
func (s *Store) Close() error {
	return s.client.Close()
}

// Usage returns the UsageStore implementation
func (s *Store) Usage() storage.UsageStore {
	return s.usageStore
}

// DHCPLeases returns the DHCPLeaseStore implementation
func (s *Store) DHCPLeases() storage.DHCPLeaseStore {
	return s.dhcpStore
}
