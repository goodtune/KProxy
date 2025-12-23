# Pull Request: Add GoReleaser Configuration for Multi-Platform Releases and Packaging

## Summary

This PR adds comprehensive GoReleaser configuration to enable automated releases of KProxy with proper packaging for multiple platforms.

## Changes

### 1. GoReleaser Configuration (`.goreleaser.yaml`)
- **Linux builds**: amd64 and arm64 with CGO enabled for SQLite support
- **macOS builds**: amd64 and arm64 with native compilation
- **Windows builds**: amd64 with MinGW cross-compilation
- **Package formats**: DEB and RPM packages for Linux
- **Archives**: tar.gz for Linux/macOS, zip for Windows
- **Checksums**: SHA256 checksums for all artifacts
- **GitHub Releases**: Automated release notes and asset publishing

### 2. Linux Package Integration
- **DEB packages** for Debian/Ubuntu with proper dependency management
- **RPM packages** for RHEL/CentOS/Fedora
- **Systemd service integration** using existing service file
- **Directory structure**:
  - `/etc/kproxy/config.yaml` - Main configuration (with noreplace flag)
  - `/etc/kproxy/ca/` - CA certificates directory
  - `/var/lib/kproxy/` - Database and runtime data
  - `/var/log/kproxy/` - Log directory
  - `/usr/local/bin/kproxy` - Binary

### 3. Installation Scripts
- **`scripts/preinstall.sh`**: Creates `kproxy` system user/group and required directories
- **`scripts/postinstall.sh`**: Sets permissions, provides setup instructions, checks for CA certificates
- **`scripts/preremove.sh`**: Stops and disables service before package removal

### 4. Default Production Configuration
- **`configs/config.yaml`**: Production-ready configuration with sensible defaults
- Includes security best practices and common bypass domains
- Clear documentation and warnings about changing default credentials

### 5. GitHub Actions Workflow (Needs Manual Addition)
A GitHub Actions workflow file has been created at `.github/workflows/release.yml` but cannot be pushed via the API due to workflow permissions. This file needs to be added manually or through the web interface.

**Workflow features**:
- Triggers on version tags (`v*`)
- Sets up cross-compilation toolchains (GCC, MinGW, OSXCross)
- Runs GoReleaser to build all platforms
- Publishes to GitHub Releases

**To add the workflow**:
1. Copy `.github/workflows/release.yml` from the local branch
2. Commit it directly to the repository through the web UI or with appropriate permissions

## Package Installation

Once released, users can install KProxy using standard package managers:

### Debian/Ubuntu
```bash
wget https://github.com/goodtune/kproxy/releases/download/v1.0.0/kproxy_1.0.0_linux_x86_64.deb
sudo dpkg -i kproxy_1.0.0_linux_x86_64.deb
```

### RHEL/CentOS/Fedora
```bash
wget https://github.com/goodtune/kproxy/releases/download/v1.0.0/kproxy_1.0.0_linux_x86_64.rpm
sudo rpm -i kproxy_1.0.0_linux_x86_64.rpm
```

### Post-Installation Steps
1. Generate CA certificates (required):
   ```bash
   # Copy scripts/generate-ca.sh and run it
   sudo ./generate-ca.sh
   ```

2. Review configuration:
   ```bash
   sudo nano /etc/kproxy/config.yaml
   ```

3. Enable and start service:
   ```bash
   sudo systemctl enable kproxy
   sudo systemctl start kproxy
   ```

4. Check status:
   ```bash
   sudo systemctl status kproxy
   sudo journalctl -u kproxy -f
   ```

## Testing Checklist

- [ ] GoReleaser configuration is valid
- [ ] Cross-compilation works for all platforms
- [ ] DEB package installs correctly on Ubuntu/Debian
- [ ] RPM package installs correctly on RHEL/Fedora
- [ ] Systemd service starts successfully
- [ ] Default configuration works out of the box
- [ ] Installation scripts create proper users and directories
- [ ] GitHub Actions workflow runs successfully on tag push

## Release Process

To create a release:

1. Ensure all changes are merged to main
2. Create and push a version tag:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```
3. GitHub Actions will automatically:
   - Build binaries for all platforms
   - Create DEB and RPM packages
   - Generate checksums
   - Create GitHub Release with all artifacts
   - Generate changelog from commits

## Notes

- **CGO Dependency**: All builds include CGO support due to SQLite dependency
- **Cross-Compilation**: Uses platform-specific toolchains for proper CGO builds
- **Package Naming**: Follows standard conventions (`kproxy_version_os_arch.{deb,rpm}`)
- **Service User**: Packages create a dedicated `kproxy` system user for security
- **Configuration**: Config file marked as `noreplace` to preserve user changes on upgrade

## Breaking Changes

None - this is a new feature that doesn't affect existing functionality.

## Related Issues

This enables easier distribution and deployment of KProxy, making it accessible to users who prefer package managers over building from source.
