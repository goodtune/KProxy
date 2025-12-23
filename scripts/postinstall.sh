#!/bin/sh
# Post-installation script for kproxy package

set -e

echo "==================================================================="
echo "KProxy has been installed successfully!"
echo "==================================================================="
echo ""

# Check if CA certificates exist
if [ ! -f /etc/kproxy/ca/root-ca.crt ] || [ ! -f /etc/kproxy/ca/root-ca.key ]; then
    echo "IMPORTANT: CA certificates not found!"
    echo "You must generate CA certificates before starting kproxy:"
    echo ""
    echo "  1. Copy the generate-ca.sh script from the repository or"
    echo "     create your own CA certificates"
    echo ""
    echo "  2. Place the following files in /etc/kproxy/ca/:"
    echo "     - root-ca.crt"
    echo "     - root-ca.key"
    echo "     - intermediate-ca.crt"
    echo "     - intermediate-ca.key"
    echo ""
    echo "  3. Ensure proper permissions:"
    echo "     sudo chown -R kproxy:kproxy /etc/kproxy/ca"
    echo "     sudo chmod 600 /etc/kproxy/ca/*.key"
    echo "     sudo chmod 644 /etc/kproxy/ca/*.crt"
    echo ""
fi

# Check if config file exists and set permissions
if [ -f /etc/kproxy/config.yaml ]; then
    chown kproxy:kproxy /etc/kproxy/config.yaml
    chmod 644 /etc/kproxy/config.yaml
    echo "Configuration file: /etc/kproxy/config.yaml"
    echo "Example configuration: /etc/kproxy/config.example.yaml"
    echo ""
fi

# Set proper permissions on directories
chown -R kproxy:kproxy /var/lib/kproxy
chmod 755 /var/lib/kproxy

chown -R kproxy:kproxy /var/log/kproxy
chmod 755 /var/log/kproxy

# Reload systemd daemon
if command -v systemctl >/dev/null 2>&1; then
    echo "Reloading systemd daemon..."
    systemctl daemon-reload

    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Review and edit the configuration file:"
    echo "     sudo nano /etc/kproxy/config.yaml"
    echo ""
    echo "  2. Generate CA certificates (if not already done):"
    echo "     See instructions above"
    echo ""
    echo "  3. Enable and start the kproxy service:"
    echo "     sudo systemctl enable kproxy"
    echo "     sudo systemctl start kproxy"
    echo ""
    echo "  4. Check service status:"
    echo "     sudo systemctl status kproxy"
    echo ""
    echo "  5. View logs:"
    echo "     sudo journalctl -u kproxy -f"
    echo ""
fi

echo "==================================================================="
echo "SECURITY NOTICE:"
echo "- Default admin credentials are admin/changeme"
echo "- Change these immediately after first login!"
echo "- Admin interface: https://kproxy.home.local:8443"
echo "==================================================================="
echo ""

exit 0
