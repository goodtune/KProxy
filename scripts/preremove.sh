#!/bin/sh
# Pre-removal script for kproxy package

set -e

# Stop and disable kproxy service if it's running
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet kproxy; then
        echo "Stopping kproxy service..."
        systemctl stop kproxy
    fi

    if systemctl is-enabled --quiet kproxy 2>/dev/null; then
        echo "Disabling kproxy service..."
        systemctl disable kproxy
    fi
fi

exit 0
