# KProxy Systemd Integration

This directory contains systemd unit files for running KProxy with socket activation and sd_notify support.

## Features

### Socket Activation

Socket activation allows systemd to:
- **Listen on privileged ports (80, 443, 53) without running as root**
- **Zero-downtime restarts** - systemd holds connections during restart
- **On-demand activation** - start kproxy only when traffic arrives (optional)
- **Improved security** - service runs as unprivileged user

### sd_notify Protocol

KProxy uses sd_notify to:
- **Signal readiness** - systemd knows when kproxy is ready to serve
- **Enable watchdog** - systemd can monitor kproxy health (optional)
- **Coordinate dependencies** - other services can wait for kproxy to be ready

## Installation

### 1. Create User and Directories

```bash
# Create kproxy user
sudo useradd -r -s /bin/false -d /var/lib/kproxy kproxy

# Create directories
sudo mkdir -p /etc/kproxy
sudo mkdir -p /var/lib/kproxy
sudo mkdir -p /var/log/kproxy

# Set ownership
sudo chown -R kproxy:kproxy /var/lib/kproxy
sudo chown -R kproxy:kproxy /var/log/kproxy
```

### 2. Install Binary and Configuration

```bash
# Build kproxy
make build

# Install binary
sudo cp bin/kproxy /usr/local/bin/
sudo chmod +x /usr/local/bin/kproxy

# Install configuration
sudo cp configs/config.example.yaml /etc/kproxy/config.yaml
sudo chown root:kproxy /etc/kproxy/config.yaml
sudo chmod 640 /etc/kproxy/config.yaml

# Install OPA policies
sudo cp -r policies /etc/kproxy/
sudo chown -R root:kproxy /etc/kproxy/policies
sudo chmod -R 644 /etc/kproxy/policies/*.rego

# Install CA certificates (if not using systemd socket activation for TLS)
sudo make generate-ca
sudo chown -R kproxy:kproxy /etc/kproxy/ca
```

### 3. Install Systemd Units

```bash
# Copy unit files
sudo cp systemd/kproxy.socket /etc/systemd/system/
sudo cp systemd/kproxy.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 4. Configure Ports (Optional)

Edit `/etc/systemd/system/kproxy.socket` to adjust ports if needed:

```ini
# Example: Use non-standard ports
ListenStream=8080          # HTTP
ListenStream=8443          # HTTPS
ListenDatagram=5353        # DNS UDP
ListenStream=5353          # DNS TCP
ListenStream=9090          # Metrics
```

### 5. Enable and Start

```bash
# Enable socket activation (starts on boot)
sudo systemctl enable kproxy.socket

# Start the socket (starts listening immediately)
sudo systemctl start kproxy.socket

# Check status
sudo systemctl status kproxy.socket
```

The service will automatically start when the first connection arrives on any socket.

To start the service immediately:

```bash
sudo systemctl start kproxy.service
```

## Usage

### Managing the Service

```bash
# Start socket activation
sudo systemctl start kproxy.socket

# Stop the service (socket keeps listening)
sudo systemctl stop kproxy.service

# Stop socket and service
sudo systemctl stop kproxy.socket

# Restart service (zero-downtime with socket activation)
sudo systemctl restart kproxy.service

# Reload configuration (if supported)
sudo systemctl reload kproxy.service

# View status
sudo systemctl status kproxy.service

# View logs
sudo journalctl -u kproxy.service -f
```

### Zero-Downtime Restart

With socket activation, systemd holds incoming connections while kproxy restarts:

```bash
# Restart without dropping connections
sudo systemctl restart kproxy.service
```

Systemd will:
1. Stop kproxy.service
2. Keep sockets open and queue new connections
3. Start new kproxy.service
4. Hand off queued connections to new process

### Monitoring

```bash
# View service status
systemctl status kproxy.service

# View socket status
systemctl status kproxy.socket

# View logs
journalctl -u kproxy.service -n 100 --no-pager

# Follow logs in real-time
journalctl -u kproxy.service -f

# View only errors
journalctl -u kproxy.service -p err -n 50
```

### Metrics

Access Prometheus metrics:

```bash
curl http://localhost:9090/metrics
```

## Configuration

### Systemd-Specific Settings

Edit `/etc/systemd/system/kproxy.service` to customize:

#### Resource Limits

```ini
[Service]
# File descriptor limit
LimitNOFILE=65536

# Process limit
LimitNPROC=512

# Memory limit (optional)
MemoryMax=2G

# CPU quota (optional)
CPUQuota=200%
```

#### Security Hardening

The provided service file includes basic security hardening. Adjust based on your needs:

```ini
[Service]
# Filesystem access
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/kproxy
ReadOnlyPaths=/etc/kproxy

# Reduce capabilities (socket activation means no CAP_NET_BIND_SERVICE needed)
AmbientCapabilities=
CapabilityBoundingSet=

# System call filtering
SystemCallFilter=@system-service
```

#### Watchdog (Optional)

Enable systemd watchdog for health monitoring:

```ini
[Service]
WatchdogSec=30s
```

KProxy will need to periodically call `systemd.NotifyWatchdog()` to prevent restart.

## Troubleshooting

### Service fails to start

Check logs:
```bash
sudo journalctl -u kproxy.service -n 50
```

Common issues:
- Configuration file errors: Check `/etc/kproxy/config.yaml`
- Permission issues: Ensure kproxy user has access to required files
- Redis connection: Ensure Redis is running and accessible

### Sockets not binding

Check socket status:
```bash
sudo systemctl status kproxy.socket
```

Verify ports are not in use:
```bash
sudo ss -tulpn | grep -E ':(80|443|53|9090)'
```

### Permission denied errors

Ensure kproxy user has proper permissions:
```bash
# Check file permissions
sudo ls -la /etc/kproxy/
sudo ls -la /var/lib/kproxy/
sudo ls -la /var/log/kproxy/

# Fix if needed
sudo chown -R kproxy:kproxy /var/lib/kproxy
sudo chown -R kproxy:kproxy /var/log/kproxy
```

### Socket activation not working

Verify systemd version (needs 227+ for named file descriptors):
```bash
systemctl --version
```

Check environment variables passed to service:
```bash
sudo systemctl show -p Environment kproxy.service
```

## Migration from Direct Execution

If you're currently running kproxy directly or with a different init system:

### Before (Direct Execution)
- Requires root or CAP_NET_BIND_SERVICE for ports 80, 443, 53
- No automatic restart on failure
- Manual process management

### After (Systemd Socket Activation)
- **No special privileges needed** - systemd handles port binding
- **Automatic restart** on failure
- **Zero-downtime restarts** - no dropped connections
- **Better monitoring** - integrated with journald and systemd status
- **Resource limits** - controlled via systemd unit
- **Security hardening** - filesystem isolation, capability restrictions

## Advanced Configuration

### Custom Socket Options

Edit `/etc/systemd/system/kproxy.socket`:

```ini
[Socket]
# Listen on specific interface
ListenStream=192.168.1.1:80

# IPv6 configuration
BindIPv6Only=both

# TCP options
KeepAlive=yes
NoDelay=yes

# Queue size
Backlog=512

# Reuse port for load balancing
ReusePort=true
```

### Multiple Instances

Run multiple kproxy instances (e.g., for different networks):

```bash
# Create instance-specific units
sudo cp kproxy.socket kproxy@instance1.socket
sudo cp kproxy.service kproxy@instance1.service

# Edit ports and config paths in instance1 units
# Start instance
sudo systemctl start kproxy@instance1.socket
```

### DHCP Socket Activation

To enable DHCP socket activation, uncomment in `kproxy.socket`:

```ini
[Socket]
# DHCP socket
ListenDatagram=67
FileDescriptorName=dhcp
```

Note: DHCP socket activation support may be limited by the underlying DHCP library.

## Benefits Summary

✅ **No root privileges required** for binding privileged ports
✅ **Zero-downtime restarts** with connection queuing
✅ **Automatic service startup** on first connection (optional)
✅ **Better security** - run as unprivileged user with minimal capabilities
✅ **Integrated monitoring** - systemd status, journald logs, watchdog
✅ **Resource control** - limits, quotas, cgroups
✅ **Dependency management** - proper startup ordering
✅ **Graceful shutdown** - coordinated with systemd

## References

- [systemd.socket documentation](https://www.freedesktop.org/software/systemd/man/systemd.socket.html)
- [systemd.service documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [systemd socket activation](https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html)
- [sd_notify protocol](https://www.freedesktop.org/software/systemd/man/sd_notify.html)
