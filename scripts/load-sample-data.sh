#!/bin/bash
# Script to load sample data into KProxy database

set -e

# Default database path
DB_PATH="${KPROXY_DB_PATH:-/var/lib/kproxy/kproxy.db}"

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database not found at $DB_PATH"
    echo "Please ensure KProxy has been initialized first."
    exit 1
fi

echo "Loading sample data into KProxy database..."
echo "Database: $DB_PATH"

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="$SCRIPT_DIR/sample-data.sql"

# Check if sqlite3 is available
if command -v sqlite3 &> /dev/null; then
    # Use sqlite3 CLI
    sqlite3 "$DB_PATH" < "$SQL_FILE"
    echo "Sample data loaded successfully using sqlite3!"
else
    echo "Error: sqlite3 command not found"
    echo "Please install sqlite3 or run the SQL file manually"
    exit 1
fi

echo ""
echo "Sample data summary:"
sqlite3 "$DB_PATH" "SELECT 'Devices: ' || COUNT(*) FROM devices; SELECT 'Profiles: ' || COUNT(*) FROM profiles; SELECT 'Rules: ' || COUNT(*) FROM rules; SELECT 'Bypass Rules: ' || COUNT(*) FROM bypass_rules; SELECT 'Time Rules: ' || COUNT(*) FROM time_rules; SELECT 'Usage Limits: ' || COUNT(*) FROM usage_limits;"

echo ""
echo "Test the system by configuring a client device to use this KProxy server's IP as DNS."
echo "Suggested test IPs:"
echo "  - 192.168.1.100 (Child Laptop - restrictive profile)"
echo "  - 192.168.1.110 (Teen Phone - moderate profile)"
echo "  - 192.168.1.200 (Parent Laptop - permissive profile)"
