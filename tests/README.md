# KProxy Admin Interface Tests

Playwright-based end-to-end tests for the KProxy admin interface using Python.

## Setup

1. **Install dependencies with uv**:
   ```bash
   uv pip install -r requirements.txt
   ```

2. **Install Playwright browsers**:
   ```bash
   uv run playwright install chromium
   ```

## Running Tests

### Preferred: Isolated container runtime

Use `tox` with `tox-docker` to build the kproxy binary, run it inside a disposable container with a pristine data directory, and execute the Playwright suite against the exposed admin port:

```bash
tox -e playwright
```

`tox-docker` exposes the following environment variables with host/port pairs for services inside the container:

- `APP_HTTP_PORT` – HTTP proxy port (8080/tcp)
- `APP_HTTPS_PORT` – HTTPS proxy port (9443/tcp)
- `APP_DNS_PORT` – DNS/TCP testing port (1053/tcp)
- `ADMIN_HTTPS_PORT` – Admin interface HTTPS port (8444/tcp)

Tests automatically read `ADMIN_HTTPS_PORT` to construct the correct base URL, so no manual configuration is needed.

### Manual host runtime

Make sure KProxy is running locally with the admin interface enabled on `https://localhost:8444`.

### Run all tests:
```bash
uv run pytest
```

### Run tests with browser visible (headed mode):
```bash
uv run pytest --headed
```

### Run a specific test:
```bash
uv run pytest test_admin_login.py::test_login_redirects_to_dashboard
```

### Run tests with more verbose output:
```bash
uv run pytest -vv
```

### Debug mode (opens Playwright Inspector):
```bash
uv run pytest --headed --slowmo 1000
```

## Test Coverage

- `test_login_page_loads`: Verifies login page renders correctly
- `test_login_redirects_to_dashboard`: Tests successful login and redirect (**this test validates the reported issue**)
- `test_login_with_invalid_credentials`: Tests error handling for bad credentials
- `test_dashboard_requires_authentication`: Verifies auth middleware protects dashboard
- `test_logout_clears_session`: Tests logout functionality and session cleanup

## Screenshots

Tests automatically capture screenshots at key points during execution. Screenshots are saved to the `screenshots/` directory with descriptive names:

- `01_login_page_loaded.png` - Initial login page
- `02_before_login.png` - Login page before entering credentials
- `03_credentials_filled.png` - After filling in username/password
- `04_after_submit.png` - Immediately after clicking submit
- `05_dashboard_page_BUG.png` - Dashboard page showing the bug
- `06_BUG_login_form_still_visible.png` - Captured when login form appears on dashboard (the bug)
- ... and more

Screenshots are particularly useful for:
- Visual confirmation of test failures
- Debugging UI issues
- Documenting the current state of bugs
- Comparing before/after when fixing issues

## Configuration

Test configuration is in `test_admin_login.py`:
- `ADMIN_URL`: Admin interface URL (default: `https://localhost:8443`)
- `ADMIN_USERNAME`: Admin username (default: `admin`)
- `ADMIN_PASSWORD`: Admin password (default: `changeme`)

## Known Issue Being Tested

The test `test_login_redirects_to_dashboard` specifically validates the issue where:
1. User logs in successfully at `/admin/login`
2. Browser redirects to `/admin/dashboard`
3. **BUG**: Dashboard shows the login form instead of dashboard content

The test checks that:
- The login form (`#loginForm`) is NOT visible on the dashboard
- Dashboard-specific elements (sidebar, stats cards, logout button) ARE visible
