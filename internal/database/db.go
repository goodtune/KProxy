package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database connection
type DB struct {
	*sql.DB
}

// New creates a new database connection and runs migrations
func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite limitation
	db.SetMaxIdleConns(1)

	// Run migrations
	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &DB{db}, nil
}

// runMigrations applies all database migrations
func runMigrations(db *sql.DB) error {
	// Create migrations table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			version INTEGER NOT NULL UNIQUE,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get current version
	var currentVersion int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	// Apply migrations in order
	migrations := getMigrations()
	for version, migration := range migrations {
		if version <= currentVersion {
			continue
		}

		// Begin transaction
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %d: %w", version, err)
		}

		// Execute migration
		if _, err := tx.Exec(migration); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to execute migration %d: %w", version, err)
		}

		// Record migration
		if _, err := tx.Exec("INSERT INTO migrations (version) VALUES (?)", version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to record migration %d: %w", version, err)
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", version, err)
		}
	}

	return nil
}

// getMigrations returns all database migrations
func getMigrations() map[int]string {
	return map[int]string{
		1: migration001Devices,
		2: migration002Profiles,
		3: migration003Rules,
		4: migration004TimeRules,
		5: migration005UsageLimits,
		6: migration006RequestLogs,
		7: migration007DNSLogs,
		8: migration008DailyUsage,
		9: migration009Sessions,
		10: migration010BypassRules,
	}
}

// Migration schemas
const migration001Devices = `
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	identifiers TEXT NOT NULL, -- JSON array of MAC/IP identifiers
	profile_id TEXT,
	active INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_profile ON devices(profile_id);
CREATE INDEX idx_devices_active ON devices(active);
`

const migration002Profiles = `
CREATE TABLE IF NOT EXISTS profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	default_allow INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

const migration003Rules = `
CREATE TABLE IF NOT EXISTS rules (
	id TEXT PRIMARY KEY,
	profile_id TEXT NOT NULL,
	domain TEXT NOT NULL,
	paths TEXT, -- JSON array of paths
	action TEXT NOT NULL, -- ALLOW or BLOCK
	priority INTEGER NOT NULL DEFAULT 0,
	category TEXT,
	inject_timer INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE INDEX idx_rules_profile ON rules(profile_id);
CREATE INDEX idx_rules_priority ON rules(priority DESC);
CREATE INDEX idx_rules_domain ON rules(domain);
`

const migration004TimeRules = `
CREATE TABLE IF NOT EXISTS time_rules (
	id TEXT PRIMARY KEY,
	profile_id TEXT NOT NULL,
	days_of_week TEXT NOT NULL, -- JSON array of integers 0-6
	start_time TEXT NOT NULL, -- HH:MM format
	end_time TEXT NOT NULL, -- HH:MM format
	rule_ids TEXT, -- JSON array of rule IDs (empty = all rules)
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE INDEX idx_time_rules_profile ON time_rules(profile_id);
`

const migration005UsageLimits = `
CREATE TABLE IF NOT EXISTS usage_limits (
	id TEXT PRIMARY KEY,
	profile_id TEXT NOT NULL,
	category TEXT,
	domains TEXT, -- JSON array of domains
	daily_minutes INTEGER NOT NULL DEFAULT 0,
	reset_time TEXT NOT NULL DEFAULT '00:00',
	inject_timer INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE INDEX idx_usage_limits_profile ON usage_limits(profile_id);
`

const migration006RequestLogs = `
CREATE TABLE IF NOT EXISTS request_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	device_id TEXT NOT NULL,
	device_name TEXT,
	client_ip TEXT NOT NULL,
	method TEXT NOT NULL,
	host TEXT NOT NULL,
	path TEXT NOT NULL,
	query TEXT,
	user_agent TEXT,
	content_type TEXT,
	status_code INTEGER,
	response_size INTEGER,
	duration_ms INTEGER,
	action TEXT NOT NULL,
	matched_rule_id TEXT,
	reason TEXT,
	category TEXT,
	encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_logs_timestamp ON request_logs(timestamp);
CREATE INDEX idx_logs_device ON request_logs(device_id, timestamp);
CREATE INDEX idx_logs_host ON request_logs(host, timestamp);
CREATE INDEX idx_logs_action ON request_logs(action, timestamp);
`

const migration007DNSLogs = `
CREATE TABLE IF NOT EXISTS dns_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	client_ip TEXT NOT NULL,
	device_id TEXT,
	device_name TEXT,
	domain TEXT NOT NULL,
	query_type TEXT NOT NULL,
	action TEXT NOT NULL, -- INTERCEPT, BYPASS, BLOCK
	response_ip TEXT,
	upstream TEXT,
	latency_ms INTEGER
);

CREATE INDEX idx_dns_timestamp ON dns_logs(timestamp);
CREATE INDEX idx_dns_device ON dns_logs(device_id, timestamp);
CREATE INDEX idx_dns_domain ON dns_logs(domain, timestamp);
CREATE INDEX idx_dns_action ON dns_logs(action, timestamp);
`

const migration008DailyUsage = `
CREATE TABLE IF NOT EXISTS daily_usage (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	date DATE NOT NULL,
	device_id TEXT NOT NULL,
	limit_id TEXT NOT NULL,
	total_seconds INTEGER NOT NULL DEFAULT 0,
	UNIQUE(date, device_id, limit_id)
);

CREATE INDEX idx_usage_device_date ON daily_usage(device_id, date);
`

const migration009Sessions = `
CREATE TABLE IF NOT EXISTS usage_sessions (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL,
	limit_id TEXT NOT NULL,
	started_at DATETIME NOT NULL,
	last_activity DATETIME NOT NULL,
	accumulated_seconds INTEGER NOT NULL DEFAULT 0,
	active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_sessions_device ON usage_sessions(device_id, active);
CREATE INDEX idx_sessions_limit ON usage_sessions(limit_id, active);
`

const migration010BypassRules = `
CREATE TABLE IF NOT EXISTS bypass_rules (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	reason TEXT,
	enabled INTEGER NOT NULL DEFAULT 1,
	device_ids TEXT, -- JSON array of device IDs (empty = all devices)
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bypass_domain ON bypass_rules(domain);
CREATE INDEX idx_bypass_enabled ON bypass_rules(enabled);
`
