package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goodtune/kproxy/internal/config"
	"github.com/goodtune/kproxy/internal/storage"
)

func setupTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()

	// Create miniredis instance
	mr := miniredis.RunT(t)

	// miniredis.Addr() returns "host:port", so we use it directly
	// We need to modify the Redis client creation to handle this
	cfg := config.RedisConfig{
		Host:         mr.Addr(), // Full address "host:port"
		Port:         0,         // Not used when host contains port
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  "5s",
		ReadTimeout:  "3s",
		WriteTimeout: "3s",
	}

	store, err := Open(cfg)
	if err != nil {
		t.Fatalf("Failed to open Redis store: %v", err)
	}

	return store, mr
}

func TestUsageStore_UpsertSession(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	usageStore := store.Usage()

	session := storage.UsageSession{
		ID:                 "test-session-1",
		DeviceID:           "device-1",
		LimitID:            "entertainment",
		StartedAt:          time.Now(),
		LastActivity:       time.Now(),
		AccumulatedSeconds: 120,
		Active:             true,
	}

	// Upsert session
	err := usageStore.UpsertSession(ctx, session)
	if err != nil {
		t.Fatalf("UpsertSession failed: %v", err)
	}

	// Retrieve session
	retrieved, err := usageStore.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("Expected ID %s, got %s", session.ID, retrieved.ID)
	}
	if retrieved.DeviceID != session.DeviceID {
		t.Errorf("Expected DeviceID %s, got %s", session.DeviceID, retrieved.DeviceID)
	}
	if retrieved.AccumulatedSeconds != session.AccumulatedSeconds {
		t.Errorf("Expected AccumulatedSeconds %d, got %d", session.AccumulatedSeconds, retrieved.AccumulatedSeconds)
	}
	if !retrieved.Active {
		t.Error("Expected Active to be true")
	}
}

func TestUsageStore_ListActiveSessions(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	usageStore := store.Usage()

	// Create active session
	activeSession := storage.UsageSession{
		ID:                 "active-1",
		DeviceID:           "device-1",
		LimitID:            "entertainment",
		StartedAt:          time.Now(),
		LastActivity:       time.Now(),
		AccumulatedSeconds: 60,
		Active:             true,
	}

	// Create inactive session
	inactiveSession := storage.UsageSession{
		ID:                 "inactive-1",
		DeviceID:           "device-2",
		LimitID:            "educational",
		StartedAt:          time.Now().Add(-2 * time.Hour),
		LastActivity:       time.Now().Add(-2 * time.Hour),
		AccumulatedSeconds: 120,
		Active:             false,
	}

	_ = usageStore.UpsertSession(ctx, activeSession)
	_ = usageStore.UpsertSession(ctx, inactiveSession)

	// List active sessions
	sessions, err := usageStore.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("ListActiveSessions failed: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("Expected 1 active session, got %d", len(sessions))
	}

	if sessions[0].ID != activeSession.ID {
		t.Errorf("Expected active session ID %s, got %s", activeSession.ID, sessions[0].ID)
	}
}

func TestUsageStore_IncrementDailyUsage(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	usageStore := store.Usage()

	date := "2024-01-15"
	deviceID := "device-1"
	limitID := "entertainment"

	// Increment new entry
	err := usageStore.IncrementDailyUsage(ctx, date, deviceID, limitID, 60)
	if err != nil {
		t.Fatalf("IncrementDailyUsage failed: %v", err)
	}

	// Get usage
	usage, err := usageStore.GetDailyUsage(ctx, date, deviceID, limitID)
	if err != nil {
		t.Fatalf("GetDailyUsage failed: %v", err)
	}

	if usage.TotalSeconds != 60 {
		t.Errorf("Expected TotalSeconds 60, got %d", usage.TotalSeconds)
	}

	// Increment again
	err = usageStore.IncrementDailyUsage(ctx, date, deviceID, limitID, 30)
	if err != nil {
		t.Fatalf("Second IncrementDailyUsage failed: %v", err)
	}

	// Get updated usage
	usage, err = usageStore.GetDailyUsage(ctx, date, deviceID, limitID)
	if err != nil {
		t.Fatalf("Second GetDailyUsage failed: %v", err)
	}

	if usage.TotalSeconds != 90 {
		t.Errorf("Expected TotalSeconds 90, got %d", usage.TotalSeconds)
	}
}

func TestUsageStore_ListDailyUsage(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	usageStore := store.Usage()

	date := "2024-01-15"

	// Add multiple usage entries for same date
	_ = usageStore.IncrementDailyUsage(ctx, date, "device-1", "entertainment", 60)
	_ = usageStore.IncrementDailyUsage(ctx, date, "device-2", "educational", 120)
	_ = usageStore.IncrementDailyUsage(ctx, date, "device-1", "educational", 30)

	// List all usage for date
	usages, err := usageStore.ListDailyUsage(ctx, date)
	if err != nil {
		t.Fatalf("ListDailyUsage failed: %v", err)
	}

	if len(usages) != 3 {
		t.Fatalf("Expected 3 usage entries, got %d", len(usages))
	}
}

func TestDHCPLeaseStore_Create(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	dhcpStore := store.DHCPLeases()

	lease := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		IP:        "192.168.1.100",
		Hostname:  "test-device",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create lease
	err := dhcpStore.Create(ctx, lease)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get by MAC
	retrieved, err := dhcpStore.GetByMAC(ctx, lease.MAC)
	if err != nil {
		t.Fatalf("GetByMAC failed: %v", err)
	}

	if retrieved.MAC != lease.MAC {
		t.Errorf("Expected MAC %s, got %s", lease.MAC, retrieved.MAC)
	}
	if retrieved.IP != lease.IP {
		t.Errorf("Expected IP %s, got %s", lease.IP, retrieved.IP)
	}
	if retrieved.Hostname != lease.Hostname {
		t.Errorf("Expected Hostname %s, got %s", lease.Hostname, retrieved.Hostname)
	}
}

func TestDHCPLeaseStore_GetByIP(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	dhcpStore := store.DHCPLeases()

	lease := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		IP:        "192.168.1.100",
		Hostname:  "test-device",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = dhcpStore.Create(ctx, lease)

	// Get by IP (secondary index)
	retrieved, err := dhcpStore.GetByIP(ctx, lease.IP)
	if err != nil {
		t.Fatalf("GetByIP failed: %v", err)
	}

	if retrieved.MAC != lease.MAC {
		t.Errorf("Expected MAC %s, got %s", lease.MAC, retrieved.MAC)
	}
}

func TestDHCPLeaseStore_List(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	dhcpStore := store.DHCPLeases()

	// Create multiple leases
	lease1 := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:01",
		IP:        "192.168.1.101",
		Hostname:  "device-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	lease2 := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:02",
		IP:        "192.168.1.102",
		Hostname:  "device-2",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = dhcpStore.Create(ctx, lease1)
	_ = dhcpStore.Create(ctx, lease2)

	// List all leases
	leases, err := dhcpStore.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(leases) != 2 {
		t.Fatalf("Expected 2 leases, got %d", len(leases))
	}
}

func TestDHCPLeaseStore_Delete(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	dhcpStore := store.DHCPLeases()

	lease := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		IP:        "192.168.1.100",
		Hostname:  "test-device",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_ = dhcpStore.Create(ctx, lease)

	// Delete lease
	err := dhcpStore.Delete(ctx, lease.MAC)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	_, err = dhcpStore.GetByMAC(ctx, lease.MAC)
	if err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}

	// Verify IP index also deleted
	_, err = dhcpStore.GetByIP(ctx, lease.IP)
	if err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound for IP index, got %v", err)
	}
}

func TestDHCPLeaseStore_CreatePreservesCreatedAt(t *testing.T) {
	store, _ := setupTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	dhcpStore := store.DHCPLeases()

	originalCreatedAt := time.Now().Add(-1 * time.Hour)

	lease := &storage.DHCPLease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		IP:        "192.168.1.100",
		Hostname:  "test-device",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: originalCreatedAt,
		UpdatedAt: time.Now(),
	}

	// Create initial lease
	_ = dhcpStore.Create(ctx, lease)

	// Update lease
	lease.Hostname = "updated-device"
	lease.UpdatedAt = time.Now()
	_ = dhcpStore.Create(ctx, lease)

	// Verify CreatedAt was preserved
	retrieved, err := dhcpStore.GetByMAC(ctx, lease.MAC)
	if err != nil {
		t.Fatalf("GetByMAC failed: %v", err)
	}

	// Allow 1 second tolerance for timestamp comparison
	if retrieved.CreatedAt.Sub(originalCreatedAt).Abs() > time.Second {
		t.Errorf("CreatedAt was not preserved. Original: %v, Retrieved: %v",
			originalCreatedAt, retrieved.CreatedAt)
	}

	if retrieved.Hostname != "updated-device" {
		t.Errorf("Hostname was not updated. Expected 'updated-device', got '%s'", retrieved.Hostname)
	}
}
