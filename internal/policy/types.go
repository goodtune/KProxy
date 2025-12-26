package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Action represents the policy decision action
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

// DNSAction represents the DNS resolution action
type DNSAction int

const (
	DNSActionIntercept DNSAction = iota // Return proxy IP, route through KProxy
	DNSActionBypass                     // Forward to upstream, return real IP
	DNSActionBlock                      // Return 0.0.0.0 / NXDOMAIN
)

// Device represents a monitored device
type Device struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Identifiers []string  `json:"identifiers"` // MAC addresses, IP ranges
	ProfileID   string    `json:"profile_id"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Profile contains access rules for a device or group
type Profile struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Rules        []Rule       `json:"rules"`
	DefaultAllow bool         `json:"default_allow"`
	TimeRules    []TimeRule   `json:"time_rules"`
	UsageLimits  []UsageLimit `json:"usage_limits"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// Rule defines domain/path filtering
type Rule struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`       // "youtube.com", "*.google.com"
	Paths       []string `json:"paths"`        // ["/watch", "/shorts"] or ["*"]
	Action      Action   `json:"action"`       // ALLOW, BLOCK
	Priority    int      `json:"priority"`     // Higher = evaluated first
	Category    string   `json:"category"`     // "social", "gaming", "homework"
	InjectTimer bool     `json:"inject_timer"` // Show time remaining overlay
}

// TimeRule restricts access by time of day
type TimeRule struct {
	ID         string   `json:"id"`
	DaysOfWeek []int    `json:"days_of_week"` // 0=Sunday, 6=Saturday
	StartTime  string   `json:"start_time"`   // "08:00"
	EndTime    string   `json:"end_time"`     // "21:00"
	RuleIDs    []string `json:"rule_ids"`     // Rules this applies to, empty = all
}

// UsageLimit tracks time spent on specific categories/domains
type UsageLimit struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`      // "gaming", "social"
	Domains      []string `json:"domains"`       // Specific domains if not using category
	DailyMinutes int      `json:"daily_minutes"` // 0 = unlimited
	ResetTime    string   `json:"reset_time"`    // "00:00" local time
	InjectTimer  bool     `json:"inject_timer"`  // Show countdown overlay
}

// BypassRule defines domains that should bypass the proxy
type BypassRule struct {
	ID        string   `json:"id"`
	Domain    string   `json:"domain"` // "bank.example.com", "*.apple.com"
	Reason    string   `json:"reason"` // "Banking", "OS Updates"
	Enabled   bool     `json:"enabled"`
	DeviceIDs []string `json:"device_ids"` // Empty = all devices
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Action        Action
	Reason        string
	BlockPage     string
	InjectTimer   bool
	TimeRemaining time.Duration
	MatchedRuleID string
	Category      string
	UsageLimitID  string
}

// ProxyRequest represents an HTTP request to be evaluated
type ProxyRequest struct {
	ClientIP  net.IP
	ClientMAC net.HardwareAddr
	Host      string
	Path      string
	Method    string
	UserAgent string
	Encrypted bool
}

// DNSRequest represents a DNS query to be evaluated
type DNSRequest struct {
	ClientIP net.IP
	Domain   string
	QType    string
}
