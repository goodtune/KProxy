# KProxy Admin Interface Tests

Playwright-based end-to-end tests for the KProxy admin interface using Python.
The suite deliberately runs as one long browser session so that data created in
earlier steps (profiles, devices, etc.) can be exercised and cleaned up later
in the flow.

## Setup

1. **Install dependencies with uv** (run from the repository root):
   ```bash
   uv pip install -r requirements.txt
   ```

2. **Install Playwright browsers**:
   ```bash
   uv run playwright install chromium
   ```

## Running Tests

### Preferred: isolated container runtime

`tox` (via the `playwright` env) builds the kproxy binary, launches it inside a
throw‑away container, and runs the browser test against the exposed admin port.
Use the following command for verbose local runs (the trailing `-- -v` passes
`-v` through to `pytest`):

```bash
tox -vv -- -v
```

If you prefer not to use tox, ensure KProxy is running locally with the admin
interface on `https://localhost:8443` (or set `ADMIN_URL` / `ADMIN_HTTPS_PORT`
to the appropriate origin) and run:

```bash
uv run pytest -v tests/test_admin_e2e.py
```

Headed/slow‑mo executions for debugging use the usual Playwright flags, for
example:

```bash
uv run pytest tests/test_admin_e2e.py --headed --slowmo 500
```

## Test Coverage

All coverage lives in `tests/test_admin_e2e.py::test_admin_full_flow`.  
The test uses `pytest-subtests` to break the run into descriptive steps while
sharing the same authenticated browser session.

The flow currently asserts:

- Login view rendering, invalid credential handling, and a successful login
- Dashboard tiles and navigation links
- Profile creation, tab switching, editing, and deletion (after associated
  devices are removed)
- Device creation, editing, validation/cancel paths, and deletion
- Logs UI (request ↔ DNS tabs, filters, refresh, clear logs modal)
- Sessions UI (tab switching, refresh button)
- Sidebar navigation between sections
- Logout plus a guard that redirects unauthenticated users back to `/admin/login`

## Screenshots

Screenshots are saved to the `screenshots/` directory using incremented filenames
(`01_login_page.png`, `02_invalid_login.png`, etc.) so the entire user journey
can be reviewed chronologically after each run.

Screenshots are particularly useful for:
- Visual confirmation of test failures
- Debugging UI issues
- Documenting the current state of bugs
- Comparing before/after when fixing issues

## Configuration

Environment variables:

- `ADMIN_URL` – Complete admin origin (default `https://localhost:8443`)
- `ADMIN_USERNAME` – Username for login (default `admin`)
- `ADMIN_PASSWORD` – Password for login (default `changeme`)

When running under `tox`, these values are derived automatically from the
container's exposed ports.

## Proxy Policy Tests

The `test_proxy_policy.py` file contains tests that verify KProxy's actual proxy
functionality and policy enforcement.

**Important**: KProxy is a **transparent intercepting proxy**, not a forward proxy.
This means:
- Requests are made **directly to KProxy's IP:port**
- The **Host header** specifies the target domain (e.g., `www.example.com`)
- KProxy intercepts the request, applies policy, and proxies to the real destination

### Test Coverage

- **HTTP/HTTPS Blocking**: Verifies requests are blocked when no allow rule exists
- **Allow Rule Application**: Tests that adding an allow rule permits traffic
- **Policy Reload**: Ensures policy changes take effect after reload
- **Rule Removal**: Confirms blocking is restored when allow rules are removed
- **Wildcard Matching**: Tests that `*.example.com` rules match subdomains

### Running Proxy Tests

```bash
# Run proxy tests only
pytest tests/test_proxy_policy.py -v -m proxy

# Run with custom KProxy endpoints
KPROXY_HOST=localhost \
KPROXY_HTTP_PORT=8080 \
KPROXY_HTTPS_PORT=9443 \
pytest tests/test_proxy_policy.py -v
```

### Additional Environment Variables

- `KPROXY_HOST` – KProxy server host (default `localhost`)
- `KPROXY_HTTP_PORT` – KProxy HTTP port (default `8080`)
- `KPROXY_HTTPS_PORT` – KProxy HTTPS port (default `9443`)

### How It Works

The tests make requests **directly to KProxy** with the Host header set:

```python
# Example: HTTP request to www.example.com via KProxy
response = requests.get(
    "http://localhost:8080/",
    headers={"Host": "www.example.com"}
)
```

KProxy:
1. Receives the request on port 8080
2. Reads the Host header to determine target domain
3. Applies policy rules based on device and domain
4. Either blocks the request or proxies it to the real `www.example.com`
5. Returns the response (or a block page)

### What the Tests Do

1. **Setup**: Create a test profile with `default_allow=false` (block by default)
2. **Create Device**: Register a test device using the blocking profile
3. **Test Blocking**: Make HTTP/HTTPS requests to KProxy with Host header, verify they're blocked
4. **Add Allow Rule**: Create an allow rule for `www.example.com` via admin API
5. **Test Allowing**: Verify requests now succeed and return example.com content
6. **Cleanup**: Remove rules and verify blocking is restored

These tests verify the complete transparent proxy workflow end-to-end.
