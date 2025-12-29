package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/redis/go-redis/v9"
)

type dhcpLeaseStore struct {
	client *redis.Client
}

// Get retrieves a DHCP lease by MAC address
func (s *dhcpLeaseStore) Get(ctx context.Context, mac string) (*storage.DHCPLease, error) {
	return s.GetByMAC(ctx, mac)
}

// GetByMAC retrieves a DHCP lease by MAC address
func (s *dhcpLeaseStore) GetByMAC(ctx context.Context, mac string) (*storage.DHCPLease, error) {
	macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", mac)

	data, err := s.client.HGetAll(ctx, macKey).Result()
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, storage.ErrNotFound
	}

	return parseDHCPLease(data)
}

// GetByIP retrieves a DHCP lease by IP address using secondary index
func (s *dhcpLeaseStore) GetByIP(ctx context.Context, ip string) (*storage.DHCPLease, error) {
	ipKey := fmt.Sprintf("kproxy:dhcp:ip:%s", ip)

	// Get MAC from IP index
	mac, err := s.client.Get(ctx, ipKey).Result()
	if err == redis.Nil {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Get lease by MAC
	return s.GetByMAC(ctx, mac)
}

// List retrieves all DHCP leases
func (s *dhcpLeaseStore) List(ctx context.Context) ([]storage.DHCPLease, error) {
	leasesSet := "kproxy:dhcp:leases"

	// Get all MAC addresses
	macs, err := s.client.SMembers(ctx, leasesSet).Result()
	if err != nil {
		return nil, err
	}

	if len(macs) == 0 {
		return []storage.DHCPLease{}, nil
	}

	// Use pipeline for batch retrieval
	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(macs))

	for i, mac := range macs {
		macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", mac)
		cmds[i] = pipe.HGetAll(ctx, macKey)
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	// Parse results
	leases := make([]storage.DHCPLease, 0, len(macs))
	for _, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil || len(data) == 0 {
			continue
		}

		lease, err := parseDHCPLease(data)
		if err == nil {
			leases = append(leases, *lease)
		}
	}

	return leases, nil
}

// Create creates or updates a DHCP lease
func (s *dhcpLeaseStore) Create(ctx context.Context, lease *storage.DHCPLease) error {
	script := redis.NewScript(createDHCPLeaseScript)

	macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", lease.MAC)
	ipKey := fmt.Sprintf("kproxy:dhcp:ip:%s", lease.IP)
	leasesSet := "kproxy:dhcp:leases"

	// Calculate TTL from ExpiresAt
	ttlSeconds := int64(0)
	if !lease.ExpiresAt.IsZero() {
		ttl := time.Until(lease.ExpiresAt)
		if ttl > 0 {
			ttlSeconds = int64(ttl.Seconds())
		}
	}

	// Set UpdatedAt to now if not set
	if lease.UpdatedAt.IsZero() {
		lease.UpdatedAt = time.Now()
	}

	// Set CreatedAt to now if not set (will be overridden by Lua script if lease exists)
	if lease.CreatedAt.IsZero() {
		lease.CreatedAt = time.Now()
	}

	keys := []string{macKey, ipKey, leasesSet}
	args := []interface{}{
		lease.MAC,
		lease.IP,
		lease.Hostname,
		lease.ExpiresAt.Format(time.RFC3339Nano),
		ttlSeconds,
		lease.UpdatedAt.Format(time.RFC3339Nano),
		lease.CreatedAt.Format(time.RFC3339Nano),
	}

	return script.Run(ctx, s.client, keys, args...).Err()
}

// Delete deletes a DHCP lease by MAC address
func (s *dhcpLeaseStore) Delete(ctx context.Context, mac string) error {
	macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", mac)

	// Get the lease to find the IP for index cleanup
	data, err := s.client.HGetAll(ctx, macKey).Result()
	if err != nil && err != redis.Nil {
		return err
	}

	// Delete the lease
	if err := s.client.Del(ctx, macKey).Err(); err != nil {
		return err
	}

	// Remove from leases set
	if err := s.client.SRem(ctx, "kproxy:dhcp:leases", mac).Err(); err != nil {
		return err
	}

	// Delete IP index if we have the IP
	if ip, ok := data["ip"]; ok {
		ipKey := fmt.Sprintf("kproxy:dhcp:ip:%s", ip)
		s.client.Del(ctx, ipKey)
	}

	return nil
}

// DeleteExpired deletes expired DHCP leases
// NOTE: With Redis TTL, this is mostly a no-op since keys expire automatically
// We keep this for interface compatibility
func (s *dhcpLeaseStore) DeleteExpired(ctx context.Context) (int, error) {
	// With TTL, expired leases are automatically removed by Redis
	// This operation is kept for interface compatibility but is effectively a no-op

	// Optional: Scan and manually delete for immediate cleanup
	leasesSet := "kproxy:dhcp:leases"
	now := time.Now()

	// Get all MAC addresses
	macs, err := s.client.SMembers(ctx, leasesSet).Result()
	if err != nil {
		return 0, err
	}

	if len(macs) == 0 {
		return 0, nil
	}

	// Use pipeline to check each lease
	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(macs))

	for i, mac := range macs {
		macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", mac)
		cmds[i] = pipe.HGetAll(ctx, macKey)
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return 0, err
	}

	// Check which leases are expired
	var deletedCount int

	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil || len(data) == 0 {
			// Key might have already expired via TTL
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339Nano, data["expires_at"])
		if err != nil {
			continue
		}

		if now.After(expiresAt) {
			mac := macs[i]

			// Delete the lease
			macKey := fmt.Sprintf("kproxy:dhcp:mac:%s", mac)
			s.client.Del(ctx, macKey)

			// Delete IP index
			if ip, ok := data["ip"]; ok {
				ipKey := fmt.Sprintf("kproxy:dhcp:ip:%s", ip)
				s.client.Del(ctx, ipKey)
			}

			// Remove from leases set
			s.client.SRem(ctx, leasesSet, mac)

			deletedCount++
		}
	}

	return deletedCount, nil
}
