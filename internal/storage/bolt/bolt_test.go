package bolt

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
)

func TestDeviceStoreListActive(t *testing.T) {
	store := openTestStore(t)
	defer func() { _ = store.Close() }()

	devices := []storage.Device{
		{ID: "device-a", Name: "Device A", Active: true},
		{ID: "device-b", Name: "Device B", Active: false},
		{ID: "device-c", Name: "Device C", Active: true},
	}

	for _, device := range devices {
		if err := store.Devices().Upsert(context.Background(), device); err != nil {
			t.Fatalf("upsert device: %v", err)
		}
	}

	active, err := store.Devices().ListActive(context.Background())
	if err != nil {
		t.Fatalf("list active devices: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active devices, got %d", len(active))
	}
}

func TestUsageStoreDailyUsage(t *testing.T) {
	store := openTestStore(t)
	defer func() { _ = store.Close() }()

	usageStore := store.Usage()
	date := "2024-01-02"

	if err := usageStore.IncrementDailyUsage(context.Background(), date, "device-a", "limit-a", 120); err != nil {
		t.Fatalf("increment daily usage: %v", err)
	}

	usage, err := usageStore.GetDailyUsage(context.Background(), date, "device-a", "limit-a")
	if err != nil {
		t.Fatalf("get daily usage: %v", err)
	}
	if usage.TotalSeconds != 120 {
		t.Fatalf("expected total seconds 120, got %d", usage.TotalSeconds)
	}

	deleted, err := usageStore.DeleteDailyUsageBefore(context.Background(), "2024-01-03")
	if err != nil {
		t.Fatalf("delete daily usage before: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted entry, got %d", deleted)
	}
}

func TestLogStoreCleanup(t *testing.T) {
	store := openTestStore(t)
	defer func() { _ = store.Close() }()

	logStore := store.Logs()
	oldTime := time.Now().Add(-48 * time.Hour)

	if err := logStore.AddRequestLog(context.Background(), storage.RequestLog{
		Timestamp: oldTime,
		DeviceID:  "device-a",
		Host:      "example.com",
		Path:      "/",
		Method:    "GET",
		Action:    storage.ActionAllow,
	}); err != nil {
		t.Fatalf("add request log: %v", err)
	}

	if err := logStore.AddDNSLog(context.Background(), storage.DNSLog{
		Timestamp: oldTime,
		DeviceID:  "device-a",
		Domain:    "example.com",
		Action:    "INTERCEPT",
	}); err != nil {
		t.Fatalf("add dns log: %v", err)
	}

	deletedRequests, err := logStore.DeleteRequestLogsBefore(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("delete request logs: %v", err)
	}
	if deletedRequests != 1 {
		t.Fatalf("expected 1 deleted request log, got %d", deletedRequests)
	}

	deletedDNS, err := logStore.DeleteDNSLogsBefore(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("delete dns logs: %v", err)
	}
	if deletedDNS != 1 {
		t.Fatalf("expected 1 deleted dns log, got %d", deletedDNS)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	path := filepath.Join(t.TempDir(), "kproxy.bolt")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}
