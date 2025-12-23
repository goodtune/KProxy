#!/bin/sh
# Pre-installation script for kproxy package

set -e

# Create kproxy user and group if they don't exist
if ! getent group kproxy >/dev/null 2>&1; then
    echo "Creating kproxy group..."
    groupadd --system kproxy
fi

if ! getent passwd kproxy >/dev/null 2>&1; then
    echo "Creating kproxy user..."
    useradd --system --gid kproxy --home-dir /var/lib/kproxy \
        --no-create-home --shell /bin/false \
        --comment "KProxy Service User" kproxy
fi

# Create required directories
mkdir -p /etc/kproxy/ca
mkdir -p /var/lib/kproxy
mkdir -p /var/log/kproxy

# Set ownership
chown -R kproxy:kproxy /etc/kproxy/ca
chown -R kproxy:kproxy /var/lib/kproxy
chown -R kproxy:kproxy /var/log/kproxy

exit 0
