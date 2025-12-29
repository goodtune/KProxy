package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Action represents an action stored in rules/logs.
type Action string

const (
	ActionAllow  Action = "ALLOW"
	ActionBlock  Action = "BLOCK"
	ActionBypass Action = "BYPASS"
)

// UnmarshalJSON implements json.Unmarshaler to normalize action to uppercase.
func (a *Action) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	// Normalize to uppercase
	normalized := Action(strings.ToUpper(s))

	// Validate against known actions
	switch normalized {
	case ActionAllow, ActionBlock, ActionBypass:
		*a = normalized
		return nil
	default:
		return fmt.Errorf("invalid action: %s (must be ALLOW, BLOCK, or BYPASS)", s)
	}
}

// MarshalJSON implements json.Marshaler to ensure uppercase output.
func (a Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(a))
}

// REMOVED: Device, Profile, Rule, TimeRule, UsageLimit, BypassRule
// These types are no longer stored in database
// Configuration is now defined in OPA policies (policies/config.rego)

// UsageSession represents a tracked usage session.
type UsageSession struct {
	ID                 string    `json:"id"`
	DeviceID           string    `json:"device_id"`
	LimitID            string    `json:"limit_id"`
	StartedAt          time.Time `json:"started_at"`
	LastActivity       time.Time `json:"last_activity"`
	AccumulatedSeconds int64     `json:"accumulated_seconds"`
	Active             bool      `json:"active"`
}

// DailyUsage aggregates usage per day/device/limit.
type DailyUsage struct {
	Date         string `json:"date"`
	DeviceID     string `json:"device_id"`
	LimitID      string `json:"limit_id"`
	TotalSeconds int64  `json:"total_seconds"`
}

// RequestLog represents an HTTP request log entry.
type RequestLog struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     string    `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	UserAgent    string    `json:"user_agent"`
	StatusCode   int       `json:"status_code"`
	ResponseSize int64     `json:"response_size"`
	DurationMS   int64     `json:"duration_ms"`
	Action       Action    `json:"action"`
	MatchedRule  string    `json:"matched_rule_id"`
	Reason       string    `json:"reason"`
	Category     string    `json:"category"`
	Encrypted    bool      `json:"encrypted"`
}

// DNSLog represents a DNS query log entry.
type DNSLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ClientIP   string    `json:"client_ip"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	Domain     string    `json:"domain"`
	QueryType  string    `json:"query_type"`
	Action     string    `json:"action"`
	ResponseIP string    `json:"response_ip"`
	Upstream   string    `json:"upstream"`
	LatencyMS  int64     `json:"latency_ms"`
}

// AdminUser represents an admin user for the web interface.
type AdminUser struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// DHCPLease represents a DHCP IP address lease.
type DHCPLease struct {
	MAC       string    `json:"mac"`        // Client MAC address (key)
	IP        string    `json:"ip"`         // Assigned IP address
	Hostname  string    `json:"hostname"`   // Client hostname
	ExpiresAt time.Time `json:"expires_at"` // Lease expiration time
	CreatedAt time.Time `json:"created_at"` // When lease was created
	UpdatedAt time.Time `json:"updated_at"` // Last update time
}

// IsExpired checks if the lease has expired
func (l *DHCPLease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}
