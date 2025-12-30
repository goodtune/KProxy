package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// setupTestRedis creates a miniredis instance for testing Lua scripts
func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return client, mr
}

func TestUpsertSessionScript(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer client.Close()
	defer mr.Close()

	ctx := context.Background()

	tests := []struct {
		name       string
		sessionID  string
		deviceID   string
		limitID    string
		active     string
		wantInSet  bool
		wantDevKey bool
	}{
		{
			name:       "create active session",
			sessionID:  "session-1",
			deviceID:   "device-1",
			limitID:    "entertainment",
			active:     "1",
			wantInSet:  true,
			wantDevKey: true,
		},
		{
			name:       "create inactive session",
			sessionID:  "session-2",
			deviceID:   "device-2",
			limitID:    "gaming",
			active:     "0",
			wantInSet:  false,
			wantDevKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionKey := "kproxy:session:" + tt.sessionID
			activeSet := "kproxy:sessions:active"
			deviceKey := "kproxy:sessions:device:" + tt.deviceID + ":" + tt.limitID

			now := time.Now().Unix()

			// Execute the script
			result := client.Eval(ctx, upsertSessionScript, []string{
				sessionKey,
				activeSet,
				deviceKey,
			}, tt.sessionID, tt.deviceID, tt.limitID, now, now, "120", tt.active)

			if result.Err() != nil {
				t.Fatalf("Script execution failed: %v", result.Err())
			}

			// Verify session data was set
			data := client.HGetAll(ctx, sessionKey)
			if data.Err() != nil {
				t.Fatalf("Failed to get session data: %v", data.Err())
			}

			sessionData := data.Val()
			if sessionData["id"] != tt.sessionID {
				t.Errorf("Expected id=%s, got %s", tt.sessionID, sessionData["id"])
			}
			if sessionData["device_id"] != tt.deviceID {
				t.Errorf("Expected device_id=%s, got %s", tt.deviceID, sessionData["device_id"])
			}
			if sessionData["limit_id"] != tt.limitID {
				t.Errorf("Expected limit_id=%s, got %s", tt.limitID, sessionData["limit_id"])
			}
			if sessionData["active"] != tt.active {
				t.Errorf("Expected active=%s, got %s", tt.active, sessionData["active"])
			}

			// Verify active set membership
			isMember := client.SIsMember(ctx, activeSet, tt.sessionID)
			if isMember.Err() != nil {
				t.Fatalf("Failed to check set membership: %v", isMember.Err())
			}
			if isMember.Val() != tt.wantInSet {
				t.Errorf("Expected set membership=%v, got %v", tt.wantInSet, isMember.Val())
			}

			// Verify device key
			deviceExists := client.Exists(ctx, deviceKey)
			if deviceExists.Err() != nil {
				t.Fatalf("Failed to check device key: %v", deviceExists.Err())
			}
			exists := deviceExists.Val() > 0
			if exists != tt.wantDevKey {
				t.Errorf("Expected device key exists=%v, got %v", tt.wantDevKey, exists)
			}

			// Verify TTL for inactive sessions
			if tt.active == "0" {
				ttl := client.TTL(ctx, sessionKey)
				if ttl.Err() != nil {
					t.Fatalf("Failed to get TTL: %v", ttl.Err())
				}
				if ttl.Val() <= 0 {
					t.Errorf("Expected TTL to be set for inactive session, got %v", ttl.Val())
				}
			}
		})
	}
}

func TestUpsertSessionScript_DeactivateSession(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer client.Close()
	defer mr.Close()

	ctx := context.Background()

	sessionID := "session-1"
	deviceID := "device-1"
	limitID := "entertainment"
	sessionKey := "kproxy:session:" + sessionID
	activeSet := "kproxy:sessions:active"
	deviceKey := "kproxy:sessions:device:" + deviceID + ":" + limitID

	now := time.Now().Unix()

	// First, create an active session
	result := client.Eval(ctx, upsertSessionScript, []string{
		sessionKey,
		activeSet,
		deviceKey,
	}, sessionID, deviceID, limitID, now, now, "120", "1")

	if result.Err() != nil {
		t.Fatalf("Failed to create active session: %v", result.Err())
	}

	// Verify it's in the active set
	isMember := client.SIsMember(ctx, activeSet, sessionID)
	if !isMember.Val() {
		t.Fatal("Session should be in active set")
	}

	// Now deactivate the session
	result = client.Eval(ctx, upsertSessionScript, []string{
		sessionKey,
		activeSet,
		deviceKey,
	}, sessionID, deviceID, limitID, now, now, "180", "0")

	if result.Err() != nil {
		t.Fatalf("Failed to deactivate session: %v", result.Err())
	}

	// Verify it's removed from active set
	isMember = client.SIsMember(ctx, activeSet, sessionID)
	if isMember.Val() {
		t.Error("Session should not be in active set after deactivation")
	}

	// Verify device key is deleted
	exists := client.Exists(ctx, deviceKey)
	if exists.Val() > 0 {
		t.Error("Device key should be deleted after deactivation")
	}

	// Verify TTL is set
	ttl := client.TTL(ctx, sessionKey)
	if ttl.Val() <= 0 {
		t.Error("TTL should be set on deactivated session")
	}
}

func TestIncrementDailyUsageScript(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer client.Close()
	defer mr.Close()

	ctx := context.Background()

	tests := []struct {
		name           string
		date           string
		deviceID       string
		limitID        string
		seconds        int64
		existingUsage  int64
		expectedTotal  int64
		shouldBeInIndex bool
	}{
		{
			name:           "create new usage entry",
			date:           "2025-01-01",
			deviceID:       "device-1",
			limitID:        "entertainment",
			seconds:        60,
			existingUsage:  0,
			expectedTotal:  60,
			shouldBeInIndex: true,
		},
		{
			name:           "increment existing usage",
			date:           "2025-01-01",
			deviceID:       "device-2",
			limitID:        "gaming",
			seconds:        30,
			existingUsage:  90,
			expectedTotal:  120,
			shouldBeInIndex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usageKey := "kproxy:usage:daily:" + tt.date + ":" + tt.deviceID + ":" + tt.limitID
			indexKey := "kproxy:usage:daily:index:" + tt.date

			// Pre-populate existing usage if needed
			if tt.existingUsage > 0 {
				client.HSet(ctx, usageKey,
					"date", tt.date,
					"device_id", tt.deviceID,
					"limit_id", tt.limitID,
					"total_seconds", tt.existingUsage,
				)
				// Set TTL and add to index as the script would have done initially
				client.Expire(ctx, usageKey, 7776000*time.Second)
				indexValue := tt.deviceID + ":" + tt.limitID
				client.SAdd(ctx, indexKey, indexValue)
				client.Expire(ctx, indexKey, 7776000*time.Second)
			}

			// Execute the script
			result := client.Eval(ctx, incrementDailyUsageScript, []string{
				usageKey,
				indexKey,
			}, tt.date, tt.deviceID, tt.limitID, tt.seconds)

			if result.Err() != nil {
				t.Fatalf("Script execution failed: %v", result.Err())
			}

			// Verify usage data
			data := client.HGetAll(ctx, usageKey)
			if data.Err() != nil {
				t.Fatalf("Failed to get usage data: %v", data.Err())
			}

			usageData := data.Val()
			if usageData["date"] != tt.date {
				t.Errorf("Expected date=%s, got %s", tt.date, usageData["date"])
			}
			if usageData["device_id"] != tt.deviceID {
				t.Errorf("Expected device_id=%s, got %s", tt.deviceID, usageData["device_id"])
			}
			if usageData["limit_id"] != tt.limitID {
				t.Errorf("Expected limit_id=%s, got %s", tt.limitID, usageData["limit_id"])
			}

			// Check total_seconds
			totalSeconds := client.HGet(ctx, usageKey, "total_seconds")
			if totalSeconds.Err() != nil {
				t.Fatalf("Failed to get total_seconds: %v", totalSeconds.Err())
			}
			actual, err := totalSeconds.Int64()
			if err != nil {
				t.Fatalf("Failed to parse total_seconds: %v", err)
			}
			if actual != tt.expectedTotal {
				t.Errorf("Expected total_seconds=%d, got %d", tt.expectedTotal, actual)
			}

			// Verify index membership
			indexValue := tt.deviceID + ":" + tt.limitID
			isMember := client.SIsMember(ctx, indexKey, indexValue)
			if isMember.Err() != nil {
				t.Fatalf("Failed to check index membership: %v", isMember.Err())
			}
			if isMember.Val() != tt.shouldBeInIndex {
				t.Errorf("Expected index membership=%v, got %v", tt.shouldBeInIndex, isMember.Val())
			}

			// Verify TTL is set
			ttl := client.TTL(ctx, usageKey)
			if ttl.Err() != nil {
				t.Fatalf("Failed to get TTL: %v", ttl.Err())
			}
			if ttl.Val() <= 0 {
				t.Error("Expected TTL to be set on usage key")
			}
		})
	}
}

func TestCreateDHCPLeaseScript(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer client.Close()
	defer mr.Close()

	ctx := context.Background()

	tests := []struct {
		name            string
		mac             string
		ip              string
		hostname        string
		ttlSeconds      int64
		existingCreated string
		expectCreated   string
	}{
		{
			name:            "create new lease",
			mac:             "aa:bb:cc:dd:ee:ff",
			ip:              "192.168.1.100",
			hostname:        "laptop",
			ttlSeconds:      3600,
			existingCreated: "",
			expectCreated:   "2025-01-01T00:00:00Z",
		},
		{
			name:            "update existing lease",
			mac:             "11:22:33:44:55:66",
			ip:              "192.168.1.101",
			hostname:        "phone",
			ttlSeconds:      7200,
			existingCreated: "2024-12-01T00:00:00Z",
			expectCreated:   "2024-12-01T00:00:00Z", // Should preserve original
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macKey := "kproxy:dhcp:mac:" + tt.mac
			ipKey := "kproxy:dhcp:ip:" + tt.ip
			leasesSet := "kproxy:dhcp:leases"

			// Pre-populate existing lease if needed
			if tt.existingCreated != "" {
				client.HSet(ctx, macKey, "created_at", tt.existingCreated)
			}

			expiresAt := time.Now().Add(time.Duration(tt.ttlSeconds) * time.Second).Format(time.RFC3339)
			updatedAt := time.Now().Format(time.RFC3339)
			createdAt := tt.expectCreated

			// Execute the script
			result := client.Eval(ctx, createDHCPLeaseScript, []string{
				macKey,
				ipKey,
				leasesSet,
			}, tt.mac, tt.ip, tt.hostname, expiresAt, tt.ttlSeconds, updatedAt, createdAt)

			if result.Err() != nil {
				t.Fatalf("Script execution failed: %v", result.Err())
			}

			// Verify lease data
			data := client.HGetAll(ctx, macKey)
			if data.Err() != nil {
				t.Fatalf("Failed to get lease data: %v", data.Err())
			}

			leaseData := data.Val()
			if leaseData["mac"] != tt.mac {
				t.Errorf("Expected mac=%s, got %s", tt.mac, leaseData["mac"])
			}
			if leaseData["ip"] != tt.ip {
				t.Errorf("Expected ip=%s, got %s", tt.ip, leaseData["ip"])
			}
			if leaseData["hostname"] != tt.hostname {
				t.Errorf("Expected hostname=%s, got %s", tt.hostname, leaseData["hostname"])
			}
			if leaseData["created_at"] != tt.expectCreated {
				t.Errorf("Expected created_at=%s, got %s", tt.expectCreated, leaseData["created_at"])
			}

			// Verify IP index
			ipToMac := client.Get(ctx, ipKey)
			if ipToMac.Err() != nil {
				t.Fatalf("Failed to get IP index: %v", ipToMac.Err())
			}
			if ipToMac.Val() != tt.mac {
				t.Errorf("Expected IP index to point to %s, got %s", tt.mac, ipToMac.Val())
			}

			// Verify leases set membership
			isMember := client.SIsMember(ctx, leasesSet, tt.mac)
			if isMember.Err() != nil {
				t.Fatalf("Failed to check leases set: %v", isMember.Err())
			}
			if !isMember.Val() {
				t.Error("MAC should be in leases set")
			}

			// Verify TTL if set
			if tt.ttlSeconds > 0 {
				ttl := client.TTL(ctx, macKey)
				if ttl.Err() != nil {
					t.Fatalf("Failed to get TTL: %v", ttl.Err())
				}
				if ttl.Val() <= 0 {
					t.Error("Expected TTL to be set on lease")
				}
			}
		})
	}
}

func TestCreateDHCPLeaseScript_PreserveCreatedAt(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer client.Close()
	defer mr.Close()

	ctx := context.Background()

	mac := "aa:bb:cc:dd:ee:ff"
	ip := "192.168.1.100"
	macKey := "kproxy:dhcp:mac:" + mac
	ipKey := "kproxy:dhcp:ip:" + ip
	leasesSet := "kproxy:dhcp:leases"

	originalCreated := "2024-01-01T00:00:00Z"

	// Create initial lease
	result := client.Eval(ctx, createDHCPLeaseScript, []string{
		macKey,
		ipKey,
		leasesSet,
	}, mac, ip, "laptop", "2025-01-01T00:00:00Z", 3600, "2024-01-01T00:00:00Z", originalCreated)

	if result.Err() != nil {
		t.Fatalf("Failed to create initial lease: %v", result.Err())
	}

	// Update the lease with a different created_at
	newCreated := "2025-01-01T00:00:00Z"
	result = client.Eval(ctx, createDHCPLeaseScript, []string{
		macKey,
		ipKey,
		leasesSet,
	}, mac, ip, "laptop-updated", "2025-01-02T00:00:00Z", 3600, "2025-01-01T00:00:00Z", newCreated)

	if result.Err() != nil {
		t.Fatalf("Failed to update lease: %v", result.Err())
	}

	// Verify created_at was preserved
	createdAt := client.HGet(ctx, macKey, "created_at")
	if createdAt.Err() != nil {
		t.Fatalf("Failed to get created_at: %v", createdAt.Err())
	}
	if createdAt.Val() != originalCreated {
		t.Errorf("Expected created_at to be preserved as %s, got %s", originalCreated, createdAt.Val())
	}
}
