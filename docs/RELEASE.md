# Release Process

KProxy uses GoReleaser with GitHub Actions to automate releases. The workflow is triggered when you create a release in GitHub.

## Creating a Release

### Step 1: Create a Git Tag

```bash
# Create a new tag (e.g., v0.1.0)
git tag -a v0.1.0 -m "Release version 0.1.0"

# Push the tag to GitHub
git push origin v0.1.0
```

### Step 2: Create a GitHub Release

1. Go to the GitHub repository: https://github.com/goodtune/kproxy
2. Click on "Releases" in the right sidebar
3. Click "Draft a new release"
4. Select the tag you just pushed (e.g., `v0.1.0`)
5. Enter a release title (e.g., "KProxy v0.1.0")
6. Add release notes describing changes
7. Click "Publish release"

### Step 3: Automated Build & Publish

Once you publish the release, GitHub Actions will automatically:

1. **Trigger the Release Workflow** (`.github/workflows/release.yml`)
2. **Build binaries** for multiple platforms:
   - Linux: amd64, arm64
   - macOS: amd64 (Intel), arm64 (Apple Silicon)
   - Windows: amd64
3. **Create packages**:
   - `.deb` packages (Debian/Ubuntu)
   - `.rpm` packages (RHEL/CentOS/Fedora)
   - `.tar.gz` archives (Linux/macOS)
   - `.zip` archives (Windows)
4. **Upload artifacts** to the GitHub release
5. **Generate checksums** (`checksums.txt`)
6. **Generate changelog** from commit messages

### Step 4: Verify the Release

After the workflow completes (usually 2-5 minutes):

1. Go back to the release page
2. Verify all artifacts are attached:
   - Archives: `kproxy_v0.1.0_Linux_x86_64.tar.gz`, etc.
   - Packages: `kproxy_v0.1.0_linux_x86_64.deb`, `kproxy_v0.1.0_linux_x86_64.rpm`
   - Checksums: `checksums.txt`
3. Verify the changelog is populated
4. Test download and installation

## Release Workflow Details

### Trigger
- **Event**: `release` with type `created`
- **When**: Triggered when you click "Publish release" in GitHub UI

### What Gets Built
- Configured in `.goreleaser.yaml`
- Cross-compiled binaries for multiple OS/arch combinations
- Linux packages with systemd integration
- Archives with example configs and docs

### Permissions Required
- `contents: write` - Upload release artifacts
- `packages: write` - Publish to GitHub Packages (if enabled)

## Version Numbering

Follow Semantic Versioning (SemVer):

- **MAJOR.MINOR.PATCH** (e.g., `v1.2.3`)
- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

Examples:
- `v0.1.0` - Initial release
- `v0.2.0` - New feature added
- `v0.2.1` - Bug fix
- `v1.0.0` - First stable release

## Pre-releases

To create a pre-release (alpha, beta, rc):

1. Use a tag with pre-release suffix: `v0.2.0-beta.1`
2. In GitHub release creation, check "This is a pre-release"
3. GoReleaser will automatically detect and mark it as pre-release

## Troubleshooting

### Workflow fails with "permission denied"
- Check that `GITHUB_TOKEN` permissions are correct in workflow file
- Ensure repository settings allow Actions to write to releases

### Missing artifacts
- Check the Actions tab for workflow run logs
- Verify `.goreleaser.yaml` configuration
- Ensure all required files exist (configs, scripts, etc.)

### Build failures
- Verify code compiles locally: `make build`
- Check Go version matches workflow (currently Go 1.24)
- Review workflow logs for specific error messages

## Manual Release (Emergency)

If GitHub Actions is unavailable, you can release manually:

```bash
# Ensure you have goreleaser installed
brew install goreleaser  # macOS
# or download from https://goreleaser.com/install/

# Create tag
git tag -a v0.1.0 -m "Release v0.1.0"

# Run goreleaser locally
export GITHUB_TOKEN="your-github-token"
goreleaser release --clean

# This will build and upload to GitHub
```

## References

- [GoReleaser Documentation](https://goreleaser.com/intro/)
- [GitHub Releases Documentation](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [Semantic Versioning](https://semver.org/)
