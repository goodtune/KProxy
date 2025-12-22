-- Sample Data for KProxy Testing
-- This script creates sample devices, profiles, rules, and bypass rules
-- Run this after initializing the database to test KProxy functionality

-- ============================================================================
-- PROFILES
-- ============================================================================

-- Child Profile (restrictive - default deny)
INSERT OR REPLACE INTO profiles (id, name, default_allow, created_at, updated_at)
VALUES ('child-profile', 'Child Profile', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Teen Profile (moderate - default deny with more allowed sites)
INSERT OR REPLACE INTO profiles (id, name, default_allow, created_at, updated_at)
VALUES ('teen-profile', 'Teen Profile', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Adult Profile (permissive - default allow)
INSERT OR REPLACE INTO profiles (id, name, default_allow, created_at, updated_at)
VALUES ('adult-profile', 'Adult Profile', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- ============================================================================
-- DEVICES
-- ============================================================================

-- Child's Laptop (using child profile)
INSERT OR REPLACE INTO devices (id, name, identifiers, profile_id, active, created_at, updated_at)
VALUES (
  'child-laptop',
  'Child A Laptop',
  '["192.168.1.100", "aa:bb:cc:dd:ee:01"]',
  'child-profile',
  1,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Child's Tablet (using child profile)
INSERT OR REPLACE INTO devices (id, name, identifiers, profile_id, active, created_at, updated_at)
VALUES (
  'child-tablet',
  'Child A Tablet',
  '["192.168.1.101", "aa:bb:cc:dd:ee:02"]',
  'child-profile',
  1,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Teen's Phone (using teen profile)
INSERT OR REPLACE INTO devices (id, name, identifiers, profile_id, active, created_at, updated_at)
VALUES (
  'teen-phone',
  'Teen B Phone',
  '["192.168.1.110", "aa:bb:cc:dd:ee:10"]',
  'teen-profile',
  1,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Parent's Laptop (using adult profile)
INSERT OR REPLACE INTO devices (id, name, identifiers, profile_id, active, created_at, updated_at)
VALUES (
  'parent-laptop',
  'Parent Laptop',
  '["192.168.1.200", "aa:bb:cc:dd:ee:20"]',
  'adult-profile',
  1,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- ============================================================================
-- RULES FOR CHILD PROFILE (Restrictive)
-- ============================================================================

-- Allow educational sites
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-allow-wikipedia', 'child-profile', '*.wikipedia.org', '["*"]', 'ALLOW', 100, 'education', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-allow-khan', 'child-profile', '*.khanacademy.org', '["*"]', 'ALLOW', 100, 'education', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-allow-google-edu', 'child-profile', 'classroom.google.com', '["*"]', 'ALLOW', 100, 'education', 0);

-- Allow YouTube but only for specific content (with time tracking)
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-allow-youtube', 'child-profile', '*.youtube.com', '["*"]', 'ALLOW', 80, 'video', 1);

-- Allow specific gaming sites (with time limits)
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-allow-minecraft', 'child-profile', 'minecraft.net', '["*"]', 'ALLOW', 70, 'gaming', 1);

-- Block social media
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-block-facebook', 'child-profile', '*.facebook.com', '["*"]', 'BLOCK', 90, 'social', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-block-instagram', 'child-profile', '*.instagram.com', '["*"]', 'BLOCK', 90, 'social', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-block-tiktok', 'child-profile', '*.tiktok.com', '["*"]', 'BLOCK', 90, 'social', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-block-twitter', 'child-profile', '*.twitter.com', '["*"]', 'BLOCK', 90, 'social', 0);

-- Block adult content
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('child-block-adult', 'child-profile', '*.pornhub.com', '["*"]', 'BLOCK', 100, 'adult', 0);

-- ============================================================================
-- RULES FOR TEEN PROFILE (Moderate)
-- ============================================================================

-- Allow educational sites
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-wikipedia', 'teen-profile', '*.wikipedia.org', '["*"]', 'ALLOW', 100, 'education', 0);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-google', 'teen-profile', '*.google.com', '["*"]', 'ALLOW', 100, 'search', 0);

-- Allow YouTube
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-youtube', 'teen-profile', '*.youtube.com', '["*"]', 'ALLOW', 80, 'video', 1);

-- Allow social media (with time tracking)
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-instagram', 'teen-profile', '*.instagram.com', '["*"]', 'ALLOW', 70, 'social', 1);

INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-twitter', 'teen-profile', '*.twitter.com', '["*"]', 'ALLOW', 70, 'social', 1);

-- Allow gaming
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-allow-gaming', 'teen-profile', '*.roblox.com', '["*"]', 'ALLOW', 60, 'gaming', 1);

-- Block adult content
INSERT OR REPLACE INTO rules (id, profile_id, domain, paths, action, priority, category, inject_timer)
VALUES ('teen-block-adult', 'teen-profile', '*.pornhub.com', '["*"]', 'BLOCK', 100, 'adult', 0);

-- ============================================================================
-- RULES FOR ADULT PROFILE (Permissive)
-- ============================================================================

-- Block nothing by default (default_allow = 1)
-- Only add specific blocks if needed

-- ============================================================================
-- TIME RULES (School Hours Restriction)
-- ============================================================================

-- Child can only access during after-school hours on weekdays
INSERT OR REPLACE INTO time_rules (id, profile_id, days_of_week, start_time, end_time, rule_ids)
VALUES (
  'child-weekday-access',
  'child-profile',
  '[1,2,3,4,5]',  -- Monday through Friday
  '15:00',  -- 3 PM
  '20:00',  -- 8 PM
  '[]'  -- Apply to all rules
);

-- Child can access all day on weekends
INSERT OR REPLACE INTO time_rules (id, profile_id, days_of_week, start_time, end_time, rule_ids)
VALUES (
  'child-weekend-access',
  'child-profile',
  '[0,6]',  -- Sunday and Saturday
  '08:00',  -- 8 AM
  '20:00',  -- 8 PM
  '[]'  -- Apply to all rules
);

-- Teen has more lenient time rules (after school until late)
INSERT OR REPLACE INTO time_rules (id, profile_id, days_of_week, start_time, end_time, rule_ids)
VALUES (
  'teen-weekday-access',
  'teen-profile',
  '[1,2,3,4,5]',  -- Monday through Friday
  '15:00',  -- 3 PM
  '22:00',  -- 10 PM
  '[]'
);

INSERT OR REPLACE INTO time_rules (id, profile_id, days_of_week, start_time, end_time, rule_ids)
VALUES (
  'teen-weekend-access',
  'teen-profile',
  '[0,6]',  -- Sunday and Saturday
  '08:00',  -- 8 AM
  '23:00',  -- 11 PM
  '[]'
);

-- ============================================================================
-- USAGE LIMITS
-- ============================================================================

-- Child: 60 minutes per day for gaming
INSERT OR REPLACE INTO usage_limits (id, profile_id, category, domains, daily_minutes, reset_time, inject_timer)
VALUES (
  'child-gaming-limit',
  'child-profile',
  'gaming',
  '[]',  -- Use category instead of specific domains
  60,    -- 60 minutes per day
  '00:00',
  1      -- Show timer overlay
);

-- Child: 120 minutes per day for video (YouTube)
INSERT OR REPLACE INTO usage_limits (id, profile_id, category, domains, daily_minutes, reset_time, inject_timer)
VALUES (
  'child-video-limit',
  'child-profile',
  'video',
  '[]',
  120,   -- 120 minutes per day
  '00:00',
  1      -- Show timer overlay
);

-- Teen: 120 minutes per day for social media
INSERT OR REPLACE INTO usage_limits (id, profile_id, category, domains, daily_minutes, reset_time, inject_timer)
VALUES (
  'teen-social-limit',
  'teen-profile',
  'social',
  '[]',
  120,   -- 120 minutes per day
  '00:00',
  1      -- Show timer overlay
);

-- Teen: 180 minutes per day for gaming
INSERT OR REPLACE INTO usage_limits (id, profile_id, category, domains, daily_minutes, reset_time, inject_timer)
VALUES (
  'teen-gaming-limit',
  'teen-profile',
  'gaming',
  '[]',
  180,   -- 180 minutes per day
  '00:00',
  1      -- Show timer overlay
);

-- ============================================================================
-- BYPASS RULES (DNS-level bypass)
-- ============================================================================

-- Banking sites (bypass for all devices)
INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-banking-boa', '*.bankofamerica.com', 'Banking', 1, '[]');

INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-banking-chase', '*.chase.com', 'Banking', 1, '[]');

INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-banking-wells', '*.wellsfargo.com', 'Banking', 1, '[]');

-- OS Updates (bypass for all devices)
INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-apple', '*.apple.com', 'OS Updates', 1, '[]');

INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-microsoft', '*.microsoft.com', 'OS Updates', 1, '[]');

INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-windows-update', '*.windowsupdate.com', 'OS Updates', 1, '[]');

-- Gaming consoles (specific device bypass)
INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-xbox', '*.xboxlive.com', 'Xbox Live', 1, '["child-tablet"]');

INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-playstation', '*.playstation.com', 'PlayStation Network', 1, '[]');

-- VPN/Security (disabled by default)
INSERT OR REPLACE INTO bypass_rules (id, domain, reason, enabled, device_ids)
VALUES ('bypass-vpn', '*.nordvpn.com', 'VPN Service', 0, '[]');

-- ============================================================================
-- Summary
-- ============================================================================

SELECT 'Sample data loaded successfully!' as message;
SELECT COUNT(*) as device_count FROM devices;
SELECT COUNT(*) as profile_count FROM profiles;
SELECT COUNT(*) as rule_count FROM rules;
SELECT COUNT(*) as bypass_rule_count FROM bypass_rules;
SELECT COUNT(*) as time_rule_count FROM time_rules;
SELECT COUNT(*) as usage_limit_count FROM usage_limits;
