package policy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/kproxy/internal/policy/opa"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/storage/bolt"
	"github.com/rs/zerolog"
)

// Test network configuration
const (
	serverIP         = "172.16.1.1"
	adultClientIP    = "172.16.2.100" // From 172.16.2.0/24
	childClientIP    = "172.16.3.100" // From 172.16.3.0/24
	testDomain       = "www.example.com"
	testApexDomain   = "example.com"
	testSubdomain    = "mail.example.com"
)

// TestPolicyEnforcement_BaselineNoConfig tests that with no devices, profiles, or rules,
// all DNS lookups are blocked/blackholed.
func TestPolicyEnforcement_BaselineNoConfig(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
	}{
		{"adult client - www.example.com", adultClientIP, testDomain, ActionBlock},
		{"child client - www.example.com", childClientIP, testDomain, ActionBlock},
		{"adult client - example.com", adultClientIP, testApexDomain, ActionBlock},
		{"child client - example.com", childClientIP, testApexDomain, ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v (reason: %s)",
					decision.Action, tt.want, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_AdultDefaultAllow tests that with adult devices defined with
// default_allow=true, adult clients get intercepted and allowed, while undefined
// child clients are blocked.
func TestPolicyEnforcement_AdultDefaultAllow(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create adult profile with default allow
	adultProfile := storage.Profile{
		ID:           "adult-profile",
		Name:         "Adult Profile",
		DefaultAllow: true,
	}
	if err := store.Profiles().Upsert(context.Background(), adultProfile); err != nil {
		t.Fatalf("failed to create adult profile: %v", err)
	}

	// Create adult device in 172.16.2.0/24 subnet
	adultDevice := storage.Device{
		ID:          "adult-device",
		Name:        "Adult Device",
		Identifiers: []string{"172.16.2.0/24"}, // Covers adult subnet
		ProfileID:   "adult-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), adultDevice); err != nil {
		t.Fatalf("failed to create adult device: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:     "adult client - allowed by default",
			clientIP: adultClientIP,
			domain:   testDomain,
			want:     ActionAllow,
			wantMsg:  "should be allowed (default_allow=true)",
		},
		{
			name:     "child client - no device match",
			clientIP: childClientIP,
			domain:   testDomain,
			want:     ActionBlock,
			wantMsg:  "should be blocked (no matching device)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_ChildDefaultBlock tests that with child devices defined with
// default_allow=false, adult clients are blocked (no device match), while child clients
// are intercepted but blocked by policy.
func TestPolicyEnforcement_ChildDefaultBlock(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create child profile with default block
	childProfile := storage.Profile{
		ID:           "child-profile",
		Name:         "Child Profile",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), childProfile); err != nil {
		t.Fatalf("failed to create child profile: %v", err)
	}

	// Create child device in 172.16.3.0/24 subnet
	childDevice := storage.Device{
		ID:          "child-device",
		Name:        "Child Device",
		Identifiers: []string{"172.16.3.0/24"}, // Covers child subnet
		ProfileID:   "child-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), childDevice); err != nil {
		t.Fatalf("failed to create child device: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:     "adult client - no device match",
			clientIP: adultClientIP,
			domain:   testDomain,
			want:     ActionBlock,
			wantMsg:  "should be blocked (no matching device)",
		},
		{
			name:     "child client - blocked by default",
			clientIP: childClientIP,
			domain:   testDomain,
			want:     ActionBlock,
			wantMsg:  "should be blocked (default_allow=false, no allow rules)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_ExactDomainMatching tests that rules with exact domain matches
// (e.g., "example.com") only match that exact domain, not subdomains.
func TestPolicyEnforcement_ExactDomainMatching(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create child profile with default block
	childProfile := storage.Profile{
		ID:           "child-profile",
		Name:         "Child Profile",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), childProfile); err != nil {
		t.Fatalf("failed to create child profile: %v", err)
	}

	// Create child device
	childDevice := storage.Device{
		ID:          "child-device",
		Name:        "Child Device",
		Identifiers: []string{"172.16.3.0/24"},
		ProfileID:   "child-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), childDevice); err != nil {
		t.Fatalf("failed to create child device: %v", err)
	}

	// Create rule to allow "example.com" (exact match)
	rule := storage.Rule{
		ID:        "rule-exact",
		ProfileID: "child-profile",
		Domain:    "example.com", // Exact match only
		Paths:    []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:     "example.com - exact match, should allow",
			clientIP: childClientIP,
			domain:   "example.com",
			want:     ActionAllow,
			wantMsg:  "exact domain match should allow",
		},
		{
			name:     "www.example.com - not exact match, should block",
			clientIP: childClientIP,
			domain:   "www.example.com",
			want:     ActionBlock,
			wantMsg:  "subdomain should not match exact domain rule",
		},
		{
			name:     "mail.example.com - not exact match, should block",
			clientIP: childClientIP,
			domain:   "mail.example.com",
			want:     ActionBlock,
			wantMsg:  "subdomain should not match exact domain rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_LeadingDotMatching tests that rules with leading dot
// (e.g., ".example.com") match both the apex domain and all subdomains.
func TestPolicyEnforcement_LeadingDotMatching(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create child profile with default block
	childProfile := storage.Profile{
		ID:           "child-profile",
		Name:         "Child Profile",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), childProfile); err != nil {
		t.Fatalf("failed to create child profile: %v", err)
	}

	// Create child device
	childDevice := storage.Device{
		ID:          "child-device",
		Name:        "Child Device",
		Identifiers: []string{"172.16.3.0/24"},
		ProfileID:   "child-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), childDevice); err != nil {
		t.Fatalf("failed to create child device: %v", err)
	}

	// Create rule to allow ".example.com" (leading dot - matches domain and subdomains)
	rule := storage.Rule{
		ID:        "rule-dot",
		ProfileID: "child-profile",
		Domain:    ".example.com", // Leading dot
		Paths:    []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:     "example.com - should match leading dot rule",
			clientIP: childClientIP,
			domain:   "example.com",
			want:     ActionAllow,
			wantMsg:  "apex domain should match .example.com rule",
		},
		{
			name:     "www.example.com - should match leading dot rule",
			clientIP: childClientIP,
			domain:   "www.example.com",
			want:     ActionAllow,
			wantMsg:  "subdomain should match .example.com rule",
		},
		{
			name:     "mail.example.com - should match leading dot rule",
			clientIP: childClientIP,
			domain:   "mail.example.com",
			want:     ActionAllow,
			wantMsg:  "subdomain should match .example.com rule",
		},
		{
			name:     "notexample.com - should not match",
			clientIP: childClientIP,
			domain:   "notexample.com",
			want:     ActionBlock,
			wantMsg:  "different domain should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_WildcardMatching tests that rules with wildcard
// (e.g., "*.example.com") match only subdomains, not the apex domain.
func TestPolicyEnforcement_WildcardMatching(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create child profile with default block
	childProfile := storage.Profile{
		ID:           "child-profile",
		Name:         "Child Profile",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), childProfile); err != nil {
		t.Fatalf("failed to create child profile: %v", err)
	}

	// Create child device
	childDevice := storage.Device{
		ID:          "child-device",
		Name:        "Child Device",
		Identifiers: []string{"172.16.3.0/24"},
		ProfileID:   "child-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), childDevice); err != nil {
		t.Fatalf("failed to create child device: %v", err)
	}

	// Create rule to allow "*.example.com" (wildcard - subdomains only)
	rule := storage.Rule{
		ID:        "rule-wildcard",
		ProfileID: "child-profile",
		Domain:    "*.example.com", // Wildcard
		Paths:    []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:     "example.com - should NOT match wildcard (needs subdomain)",
			clientIP: childClientIP,
			domain:   "example.com",
			want:     ActionBlock,
			wantMsg:  "apex domain should not match *.example.com",
		},
		{
			name:     "www.example.com - should match wildcard",
			clientIP: childClientIP,
			domain:   "www.example.com",
			want:     ActionAllow,
			wantMsg:  "subdomain should match *.example.com",
		},
		{
			name:     "mail.example.com - should match wildcard",
			clientIP: childClientIP,
			domain:   "mail.example.com",
			want:     ActionAllow,
			wantMsg:  "subdomain should match *.example.com",
		},
		{
			name:     "api.example.com - should match wildcard",
			clientIP: childClientIP,
			domain:   "api.example.com",
			want:     ActionAllow,
			wantMsg:  "subdomain should match *.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(tt.clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_RulePriority tests that rules with higher priority
// are evaluated first.
func TestPolicyEnforcement_RulePriority(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create profile with default allow
	profile := storage.Profile{
		ID:           "test-profile",
		Name:         "Test Profile",
		DefaultAllow: true,
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device
	device := storage.Device{
		ID:          "test-device",
		Name:        "Test Device",
		Identifiers: []string{adultClientIP},
		ProfileID:   "test-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Create high priority block rule for specific subdomain
	highPriorityRule := storage.Rule{
		ID:        "rule-high",
		ProfileID: "test-profile",
		Domain:    "blocked.example.com",
		Action:    storage.ActionBlock,
		Priority:  200, // Higher priority
	}
	if err := store.Rules().Upsert(context.Background(), highPriorityRule); err != nil {
		t.Fatalf("failed to create high priority rule: %v", err)
	}

	// Create low priority allow rule for all subdomains
	lowPriorityRule := storage.Rule{
		ID:        "rule-low",
		ProfileID: "test-profile",
		Domain:    "*.example.com",
		Action:    storage.ActionAllow,
		Priority:  100, // Lower priority
	}
	if err := store.Rules().Upsert(context.Background(), lowPriorityRule); err != nil {
		t.Fatalf("failed to create low priority rule: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		domain   string
		want     Action
		wantMsg  string
	}{
		{
			name:    "blocked.example.com - high priority block rule wins",
			domain:  "blocked.example.com",
			want:    ActionBlock,
			wantMsg: "high priority block should override lower priority allow",
		},
		{
			name:    "www.example.com - low priority allow rule applies",
			domain:  "www.example.com",
			want:    ActionAllow,
			wantMsg: "should be allowed by wildcard rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(adultClientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_DeviceIdentification tests that devices can be identified
// by exact IP, CIDR range, and MAC address.
func TestPolicyEnforcement_DeviceIdentification(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create profile
	profile := storage.Profile{
		ID:           "test-profile",
		Name:         "Test Profile",
		DefaultAllow: true,
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device with multiple identifier types
	device := storage.Device{
		ID: "test-device",
		Name: "Test Device",
		Identifiers: []string{
			"172.16.2.50",      // Exact IP
			"172.16.3.0/24",    // CIDR range
			"aa:bb:cc:dd:ee:ff", // MAC address
		},
		ProfileID: "test-profile",
		Active:    true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name     string
		clientIP string
		macAddr  string
		want     Action
		wantMsg  string
	}{
		{
			name:     "exact IP match",
			clientIP: "172.16.2.50",
			macAddr:  "",
			want:     ActionAllow,
			wantMsg:  "should match by exact IP",
		},
		{
			name:     "CIDR range match",
			clientIP: "172.16.3.100",
			macAddr:  "",
			want:     ActionAllow,
			wantMsg:  "should match by CIDR range",
		},
		{
			name:     "MAC address match",
			clientIP: "192.168.1.100", // Different IP
			macAddr:  "aa:bb:cc:dd:ee:ff",
			want:     ActionAllow,
			wantMsg:  "should match by MAC address",
		},
		{
			name:     "no match",
			clientIP: "10.0.0.1",
			macAddr:  "11:22:33:44:55:66",
			want:     ActionBlock,
			wantMsg:  "should not match any identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macAddr, _ := net.ParseMAC(tt.macAddr)
			req := &ProxyRequest{
				ClientIP:  net.ParseIP(tt.clientIP),
				ClientMAC: macAddr,
				Host:      testDomain,
				Path:      "/",
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_PathMatching tests that rules can match specific paths.
func TestPolicyEnforcement_PathMatching(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create profile with default block
	profile := storage.Profile{
		ID:           "test-profile",
		Name:         "Test Profile",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device
	device := storage.Device{
		ID:          "test-device",
		Name:        "Test Device",
		Identifiers: []string{adultClientIP},
		ProfileID:   "test-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Create rule to allow only /public path on example.com
	rule := storage.Rule{
		ID:        "rule-path",
		ProfileID: "test-profile",
		Domain:    "example.com",
		Paths:    []string{"/public"},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	engine := newTestEngine(t, store)

	tests := []struct {
		name    string
		domain  string
		path    string
		want    Action
		wantMsg string
	}{
		{
			name:    "example.com/public - should allow",
			domain:  "example.com",
			path:    "/public",
			want:    ActionAllow,
			wantMsg: "matching path should allow",
		},
		{
			name:    "example.com/public/file - should allow (prefix match)",
			domain:  "example.com",
			path:    "/public/file.txt",
			want:    ActionAllow,
			wantMsg: "path prefix should match",
		},
		{
			name:    "example.com/ - should block",
			domain:  "example.com",
			path:    "/",
			want:    ActionBlock,
			wantMsg: "different path should not match",
		},
		{
			name:    "example.com/private - should block",
			domain:  "example.com",
			path:    "/private",
			want:    ActionBlock,
			wantMsg: "different path should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(adultClientIP),
				Host:     tt.domain,
				Path:     tt.path,
			}
			decision := engine.Evaluate(req)
			if decision.Action != tt.want {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.want, tt.wantMsg, decision.Reason)
			}
		})
	}
}

// TestPolicyEnforcement_DynamicRuleChanges tests adding and removing rules dynamically.
// This simulates the scenarios from the Python integration tests:
// 1. Device with default block - requests blocked
// 2. Add allow rule - requests allowed
// 3. Remove rule - blocking restored
func TestPolicyEnforcement_DynamicRuleChanges(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create profile with default block
	profile := storage.Profile{
		ID:           "test-profile",
		Name:         "Test Profile",
		DefaultAllow: false, // Block by default
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device with this profile
	device := storage.Device{
		ID:          "test-device",
		Name:        "Test Device",
		Identifiers: []string{childClientIP}, // Use child client IP
		ProfileID:   "test-profile",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	engine := newTestEngine(t, store)

	// Step 1: Verify blocking with no rules (default_allow=false)
	t.Run("initial_blocking", func(t *testing.T) {
		req := &ProxyRequest{
			ClientIP: net.ParseIP(childClientIP),
			Host:     testDomain,
			Path:     "/",
		}
		decision := engine.Evaluate(req)
		if decision.Action != ActionBlock {
			t.Errorf("Expected BLOCK with default_allow=false, got %v (reason: %s)",
				decision.Action, decision.Reason)
		}
	})

	// Step 2: Add allow rule for www.example.com
	rule := storage.Rule{
		ID:        "test-rule",
		ProfileID: "test-profile",
		Domain:    testDomain,
		Paths:     []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	// Reload policy engine to pick up new rule
	if err := engine.Reload(); err != nil {
		t.Fatalf("failed to reload engine: %v", err)
	}

	// Step 3: Verify request is now allowed
	t.Run("allowed_after_rule_added", func(t *testing.T) {
		req := &ProxyRequest{
			ClientIP: net.ParseIP(childClientIP),
			Host:     testDomain,
			Path:     "/",
		}
		decision := engine.Evaluate(req)
		if decision.Action != ActionAllow {
			t.Errorf("Expected ALLOW after adding rule, got %v (reason: %s)",
				decision.Action, decision.Reason)
		}
	})

	// Step 4: Remove the allow rule
	if err := store.Rules().Delete(context.Background(), "test-profile", "test-rule"); err != nil {
		t.Fatalf("failed to delete rule: %v", err)
	}

	// Reload policy engine to pick up rule removal
	if err := engine.Reload(); err != nil {
		t.Fatalf("failed to reload engine: %v", err)
	}

	// Step 5: Verify blocking is restored
	t.Run("blocking_restored_after_rule_removed", func(t *testing.T) {
		req := &ProxyRequest{
			ClientIP: net.ParseIP(childClientIP),
			Host:     testDomain,
			Path:     "/",
		}
		decision := engine.Evaluate(req)
		if decision.Action != ActionBlock {
			t.Errorf("Expected BLOCK after removing rule, got %v (reason: %s)",
				decision.Action, decision.Reason)
		}
	})

	// Step 6: Test wildcard rule matching (from test_wildcard_domain_matching)
	wildcardRule := storage.Rule{
		ID:        "wildcard-rule",
		ProfileID: "test-profile",
		Domain:    "*.example.com",
		Paths:     []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), wildcardRule); err != nil {
		t.Fatalf("failed to create wildcard rule: %v", err)
	}

	if err := engine.Reload(); err != nil {
		t.Fatalf("failed to reload engine: %v", err)
	}

	t.Run("wildcard_rule_matches_subdomain", func(t *testing.T) {
		req := &ProxyRequest{
			ClientIP: net.ParseIP(childClientIP),
			Host:     testDomain, // www.example.com
			Path:     "/",
		}
		decision := engine.Evaluate(req)
		if decision.Action != ActionAllow {
			t.Errorf("Expected ALLOW for www.example.com with *.example.com rule, got %v (reason: %s)",
				decision.Action, decision.Reason)
		}
	})

	t.Run("wildcard_rule_does_not_match_apex", func(t *testing.T) {
		req := &ProxyRequest{
			ClientIP: net.ParseIP(childClientIP),
			Host:     testApexDomain, // example.com
			Path:     "/",
		}
		decision := engine.Evaluate(req)
		if decision.Action != ActionBlock {
			t.Errorf("Expected BLOCK for example.com with *.example.com rule (wildcard needs subdomain), got %v (reason: %s)",
				decision.Action, decision.Reason)
		}
	})
}

// Helper functions

func openTestStore(t *testing.T) storage.Store {
	t.Helper()

	path := filepath.Join(t.TempDir(), "kproxy-test.bolt")
	store, err := bolt.Open(path)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}
	return store
}

// TestPolicyEnforcement_TimeRestrictions tests that time rules properly restrict
// access to specific domains outside of allowed hours.
// This test matches the real-world parental control configuration with:
// - Profile with default_allow=false (block by default)
// - Rule to ALLOW .example.com
// - TimeRule restricting that rule to 06:00-23:20
// Expected behavior:
// - During 06:00-23:20: Access to .example.com should be ALLOWED
// - Outside 06:00-23:20: Access to .example.com should be BLOCKED with time-related reason
// - Other domains: BLOCKED (no matching rule, default_allow=false)
func TestPolicyEnforcement_TimeRestrictions(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create "Kids" profile with default_allow=false (realistic parental control)
	profile := storage.Profile{
		ID:           "profile-kids",
		Name:         "Kids",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device for Kids Network (192.168.5.0/24)
	device := storage.Device{
		ID:          "dev-kids",
		Name:        "Kids Network",
		Identifiers: []string{"192.168.5.0/24"},
		ProfileID:   "profile-kids",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Create ALLOW rule for .example.com
	rule := storage.Rule{
		ID:        "rule-example",
		ProfileID: "profile-kids",
		Domain:    ".example.com",
		Paths:     []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
	}
	if err := store.Rules().Upsert(context.Background(), rule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	// Create TimeRule restricting the above rule to 06:00-23:20 (all days)
	timeRule := storage.TimeRule{
		ID:         "timerule-kids",
		ProfileID:  "profile-kids",
		DaysOfWeek: []int{0, 1, 2, 3, 4, 5, 6}, // All days
		StartTime:  "06:00",
		EndTime:    "23:20",
		RuleIDs:    []string{"rule-example"}, // Apply only to this specific rule
	}
	if err := store.TimeRules().Upsert(context.Background(), timeRule); err != nil {
		t.Fatalf("failed to create time rule: %v", err)
	}

	engine := newTestEngine(t, store)

	// Test client from Kids Network
	clientIP := "192.168.5.100"

	tests := []struct {
		name                 string
		domain               string
		dayOfWeek            int    // 0=Sunday, 1=Monday, etc.
		minutesSinceMidnight int    // Time of day in minutes (e.g., 360 = 06:00)
		wantAction           Action
		wantReason           string // Expected exact reason (empty = don't check)
		wantReasonNot        string // Reason must NOT equal this (empty = don't check)
		description          string
	}{
		{
			name:             "access_during_allowed_hours_morning",
			domain:           "www.example.com",
			dayOfWeek:        2, // Tuesday
			minutesSinceMidnight: 360, // 06:00 (start of allowed period)
			wantAction:       ActionAllow,
			description:      "should ALLOW at start of time window (06:00)",
		},
		{
			name:             "access_during_allowed_hours_midday",
			domain:           "example.com",
			dayOfWeek:        3, // Wednesday
			minutesSinceMidnight: 600, // 10:00 (middle of allowed period)
			wantAction:       ActionAllow,
			description:      "should ALLOW during time window (10:00)",
		},
		{
			name:             "access_during_allowed_hours_evening",
			domain:           "mail.example.com",
			dayOfWeek:        4, // Thursday
			minutesSinceMidnight: 1400, // 23:20 (end of allowed period)
			wantAction:       ActionAllow,
			description:      "should ALLOW at end of time window (23:20)",
		},
		{
			name:                 "access_before_allowed_hours",
			domain:               "www.example.com",
			dayOfWeek:            2, // Tuesday
			minutesSinceMidnight: 300, // 05:00 (before allowed period)
			wantAction:           ActionBlock,
			wantReason:           "outside allowed hours",
			description:          "should BLOCK before time window (05:00) with time restriction reason",
		},
		{
			name:                 "access_after_allowed_hours",
			domain:               "example.com",
			dayOfWeek:            5, // Friday
			minutesSinceMidnight: 1410, // 23:30 (after allowed period)
			wantAction:           ActionBlock,
			wantReason:           "outside allowed hours",
			description:          "should BLOCK after time window (23:30) with time restriction reason",
		},
		{
			name:                 "access_late_night",
			domain:               "mail.example.com",
			dayOfWeek:            6, // Saturday
			minutesSinceMidnight: 120, // 02:00 (well outside allowed period)
			wantAction:           ActionBlock,
			wantReason:           "outside allowed hours",
			description:          "should BLOCK late at night (02:00) with time restriction reason",
		},
		{
			name:                 "different_domain_no_rule",
			domain:               "other.com",
			dayOfWeek:            2, // Tuesday
			minutesSinceMidnight: 300, // 05:00 (outside time window for .example.com)
			wantAction:           ActionBlock,
			wantReason:           "default deny",
			wantReasonNot:        "outside allowed hours",
			description:          "different domain should be blocked with default deny, not time restriction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the test clock to specific time
			testTime := time.Date(2025, 1, int(tt.dayOfWeek)+4, // Sunday=0, so offset to get right weekday
				tt.minutesSinceMidnight/60,        // hours
				tt.minutesSinceMidnight%60,        // minutes
				0, 0, time.Local)
			engine.SetClock(&TestClock{CurrentTime: testTime})

			req := &ProxyRequest{
				ClientIP: net.ParseIP(clientIP),
				Host:     tt.domain,
				Path:     "/",
			}
			decision := engine.Evaluate(req)

			// Check action
			if decision.Action != tt.wantAction {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.wantAction, tt.description, decision.Reason)
			}

			// Check exact reason match
			if tt.wantReason != "" {
				if decision.Reason != tt.wantReason {
					t.Errorf("Evaluate() reason = %q, want %q: %s",
						decision.Reason, tt.wantReason, tt.description)
				}
			}

			// Check reason does NOT equal unwanted value
			if tt.wantReasonNot != "" {
				if decision.Reason == tt.wantReasonNot {
					t.Errorf("Evaluate() reason = %q, must not equal %q: %s",
						decision.Reason, tt.wantReasonNot, tt.description)
				}
			}
		})
	}
}

// TestPolicyEnforcement_BypassAction tests that BYPASS rules work correctly
// Reproduces issue where BYPASS rules cause "no results from proxy query"
func TestPolicyEnforcement_BypassAction(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()

	// Create "Kids" profile with default_allow=false (block by default)
	profile := storage.Profile{
		ID:           "profile-kids",
		Name:         "Kids",
		DefaultAllow: false,
	}
	if err := store.Profiles().Upsert(context.Background(), profile); err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Create device for Kids Network (192.168.5.0/24)
	device := storage.Device{
		ID:          "dev-kids",
		Name:        "Kids Network",
		Identifiers: []string{"192.168.5.0/24"},
		ProfileID:   "profile-kids",
		Active:      true,
	}
	if err := store.Devices().Upsert(context.Background(), device); err != nil {
		t.Fatalf("failed to create device: %v", err)
	}

	// Create BYPASS rule for slackb.com (exact match, no leading dot)
	bypassRule := storage.Rule{
		ID:        "rule-slackb",
		ProfileID: "profile-kids",
		Domain:    "slackb.com",
		Paths:     []string{}, // Empty = match all paths
		Action:    storage.ActionBypass,
		Priority:  100,
		Category:  "",
	}
	if err := store.Rules().Upsert(context.Background(), bypassRule); err != nil {
		t.Fatalf("failed to create bypass rule: %v", err)
	}

	// Create ALLOW rule for .example.com for comparison
	allowRule := storage.Rule{
		ID:        "rule-example",
		ProfileID: "profile-kids",
		Domain:    ".example.com",
		Paths:     []string{},
		Action:    storage.ActionAllow,
		Priority:  100,
		Category:  "test",
	}
	if err := store.Rules().Upsert(context.Background(), allowRule); err != nil {
		t.Fatalf("failed to create allow rule: %v", err)
	}

	engine := newTestEngine(t, store)

	// Test client from Kids Network
	clientIP := "192.168.5.100"

	tests := []struct {
		name         string
		host         string
		path         string
		wantAction   Action
		wantReason   string
		description  string
	}{
		{
			name:        "bypass_rule_exact_domain",
			host:        "slackb.com",
			path:        "/traces/v1/list_of_spans/proto",
			wantAction:  ActionBypass,
			wantReason:  "matched rule: rule-slackb",
			description: "BYPASS rule for slackb.com should work",
		},
		{
			name:        "allow_rule_with_leading_dot",
			host:        "www.example.com",
			path:        "/",
			wantAction:  ActionAllow,
			wantReason:  "matched rule: rule-example",
			description: "ALLOW rule for .example.com should work",
		},
		{
			name:        "no_matching_rule_default_deny",
			host:        "other.com",
			path:        "/",
			wantAction:  ActionBlock,
			wantReason:  "default deny",
			description: "No matching rule should use default_allow=false -> BLOCK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProxyRequest{
				ClientIP: net.ParseIP(clientIP),
				Host:     tt.host,
				Path:     tt.path,
				Method:   "POST",
			}

			decision := engine.Evaluate(req)

			// Check action
			if decision.Action != tt.wantAction {
				t.Errorf("Evaluate() action = %v, want %v: %s (reason: %s)",
					decision.Action, tt.wantAction, tt.description, decision.Reason)
			}

			// Check reason
			if tt.wantReason != "" {
				if decision.Reason != tt.wantReason {
					t.Errorf("Evaluate() reason = %q, want %q: %s",
						decision.Reason, tt.wantReason, tt.description)
				}
			}
		})
	}
}

func newTestEngine(t *testing.T, store storage.Store) *Engine {
	t.Helper()

	// Create a disabled logger for tests
	logger := zerolog.New(nil).Level(zerolog.Disabled)

	// Create OPA config pointing to local policies directory
	opaConfig := opa.Config{
		Source:    "filesystem",
		PolicyDir: "../../policies",
	}

	// Create engine with default block action and MAC address matching
	engine, err := NewEngine(store, []string{}, "block", true, opaConfig, logger)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	return engine
}
