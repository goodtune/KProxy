# Build Notes

## Missing go.sum Entries After Adding Lego Library

**Issue**: The `go.sum` file is incomplete for the lego ACME library dependencies due to network issues during `go get`.

**Symptoms**:
```
missing go.sum entry for module providing package golang.org/x/crypto/ocsp
missing go.sum entry for module providing package github.com/cenkalti/backoff/v5
missing go.sum entry for module providing package github.com/go-jose/go-jose/v4
```

**Fix**: Run the following on your local machine with working network:

```bash
# Clean module cache for lego
go clean -modcache

# Download all dependencies and update go.sum
go mod download
go mod tidy

# Verify it builds
make build

# Commit the updated go.sum
git add go.sum
git commit -m "fix: complete go.sum entries for lego dependencies"
git push
```

This will populate `go.sum` with all required transitive dependencies for the lego library.
