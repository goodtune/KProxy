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
// REMOVED: RequestLog, DNSLog, AdminUser
// Logs now written to structured loggers, admin UI removed

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
