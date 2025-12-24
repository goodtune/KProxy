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
container’s exposed ports.
