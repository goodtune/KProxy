package systemd

import (
	"fmt"
	"net"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
)

// Listeners holds all systemd-activated listeners
type Listeners struct {
	HTTP     net.Listener
	HTTPS    net.Listener
	DNSUdp   net.PacketConn
	DNSTcp   net.Listener
	DHCP     net.PacketConn
	Metrics  net.Listener
	Activated bool
}

// GetListeners retrieves systemd socket-activated file descriptors
// Returns nil listeners if not running under socket activation
func GetListeners() (*Listeners, error) {
	listeners := &Listeners{
		Activated: false,
	}

	// Check if systemd socket activation is available
	fds := activation.Files(false) // false = don't unset env vars
	if len(fds) == 0 {
		return listeners, nil
	}

	listeners.Activated = true

	// Get named listeners from systemd
	// The order and names are defined in kproxy.socket unit file
	// using FileDescriptorName= directives

	// Try to get listeners by name (requires systemd 227+)
	listenersMap, err := activation.ListenersWithNames()
	if err != nil {
		return nil, fmt.Errorf("failed to get systemd listeners: %w", err)
	}

	// Map named file descriptors to our listener structure
	// Expected names: http, https, dns-udp, dns-tcp, dhcp, metrics

	if lns, ok := listenersMap["http"]; ok && len(lns) > 0 {
		listeners.HTTP = lns[0]
	}

	if lns, ok := listenersMap["https"]; ok && len(lns) > 0 {
		listeners.HTTPS = lns[0]
	}

	if lns, ok := listenersMap["dns-tcp"]; ok && len(lns) > 0 {
		listeners.DNSTcp = lns[0]
	}

	if lns, ok := listenersMap["metrics"]; ok && len(lns) > 0 {
		listeners.Metrics = lns[0]
	}

	// For UDP sockets (DNS and DHCP), we need PacketConn
	// activation.Listeners() returns net.Listener, but for UDP we need to
	// convert them to PacketConn

	if lns, ok := listenersMap["dns-udp"]; ok && len(lns) > 0 {
		if pc, ok := lns[0].(net.PacketConn); ok {
			listeners.DNSUdp = pc
		} else {
			// Try to get the underlying UDPConn
			if udpLn, ok := lns[0].(*net.UnixListener); !ok {
				// For UDP, systemd passes it as a raw file descriptor
				// We need to use activation.PacketConns() instead
				// Let's get packet conns separately
			}
		}
	}

	if lns, ok := listenersMap["dhcp"]; ok && len(lns) > 0 {
		if pc, ok := lns[0].(net.PacketConn); ok {
			listeners.DHCP = pc
		}
	}

	// For UDP sockets, we need to use PacketConns
	// Let's get all packet conns and match by address
	packetConns, err := activation.PacketConns()
	if err == nil && len(packetConns) > 0 {
		// We need to identify which PacketConn is for DNS and which is for DHCP
		// This is done by checking the local address
		for _, pc := range packetConns {
			addr := pc.LocalAddr()
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				// Port 53 = DNS, Port 67 = DHCP
				switch udpAddr.Port {
				case 53:
					listeners.DNSUdp = pc
				case 67:
					listeners.DHCP = pc
				}
			}
		}
	}

	return listeners, nil
}

// NotifyReady sends READY=1 notification to systemd
// This tells systemd that the service has finished starting up
func NotifyReady() error {
	sent, err := daemon.SdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		return fmt.Errorf("failed to send sd_notify: %w", err)
	}
	if !sent {
		// Not running under systemd, or notification not sent
		// This is not an error
	}
	return nil
}

// NotifyStopping sends STOPPING=1 notification to systemd
// This tells systemd that the service is shutting down
func NotifyStopping() error {
	sent, err := daemon.SdNotify(false, daemon.SdNotifyStopping)
	if err != nil {
		return fmt.Errorf("failed to send sd_notify stopping: %w", err)
	}
	if !sent {
		// Not running under systemd
	}
	return nil
}

// NotifyWatchdog sends WATCHDOG=1 notification to systemd
// This should be called periodically to prevent watchdog timeout
func NotifyWatchdog() error {
	sent, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog)
	if err != nil {
		return fmt.Errorf("failed to send sd_notify watchdog: %w", err)
	}
	if !sent {
		// Not running under systemd
	}
	return nil
}

// IsSystemdService returns true if running as a systemd service
func IsSystemdService() bool {
	// Check if NOTIFY_SOCKET is set
	return daemon.SdNotifyNoSocket() != nil
}
