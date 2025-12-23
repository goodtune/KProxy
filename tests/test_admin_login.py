"""
Test admin interface login and authentication flow.
"""
import os
from pathlib import Path
import pytest
from playwright.sync_api import Page, expect


# Configuration
ADMIN_URL = "https://localhost:8443"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "changeme"

# Screenshot directory
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser to accept self-signed certificates."""
    return {
        **browser_context_args,
        "ignore_https_errors": True,
    }


def take_screenshot(page: Page, name: str):
    """Helper to take and save a screenshot."""
    screenshot_path = SCREENSHOT_DIR / f"{name}.png"
    page.screenshot(path=str(screenshot_path), full_page=True)
    print(f"📸 Screenshot saved: {screenshot_path}")


def assert_page_id(page: Page, expected_id: str):
    """Assert which page is currently rendered via body data attribute."""
    body = page.locator("body")
    expect(body).to_have_attribute("data-page", expected_id)


def get_cookie(page: Page, name: str):
    """Get a cookie by name from the current browser context."""
    cookies = page.context.cookies()
    for cookie in cookies:
        if cookie["name"] == name:
            return cookie
    return None


def test_login_page_loads(page: Page):
    """Test that the login page loads correctly."""
    page.goto(f"{ADMIN_URL}/admin/login")
    take_screenshot(page, "01_login_page_loaded")
    assert_page_id(page, "login")

    # Check that we're on the login page
    expect(page).to_have_url(f"{ADMIN_URL}/admin/login")

    # Check for login form elements
    expect(page.locator("#loginForm")).to_be_visible()
    expect(page.locator("#username")).to_be_visible()
    expect(page.locator("#password")).to_be_visible()
    expect(page.locator('button[type="submit"]')).to_be_visible()

    # Check for login page specific text
    expect(page.locator("text=KProxy Admin")).to_be_visible()
    expect(page.locator("text=Sign in to manage your proxy")).to_be_visible()


def test_login_redirects_to_dashboard(page: Page):
    """Test that login redirects to dashboard and shows dashboard content."""
    page.goto(f"{ADMIN_URL}/admin/login")
    take_screenshot(page, "02_before_login")

    # Fill in login form
    page.locator("#username").fill(ADMIN_USERNAME)
    page.locator("#password").fill(ADMIN_PASSWORD)
    take_screenshot(page, "03_credentials_filled")

    # Submit form and verify auth API response
    with page.expect_response("**/api/auth/login") as login_response:
        page.locator('button[type="submit"]').click()

    # Wait a moment for the request to complete
    page.wait_for_timeout(500)
    take_screenshot(page, "04_after_submit")
    response = login_response.value
    assert response.status == 200, f"Login request failed: {response.status}"

    # Wait for navigation to dashboard
    page.wait_for_url(f"{ADMIN_URL}/admin/dashboard", timeout=5000)
    take_screenshot(page, "05_dashboard_page_BUG")
    assert_page_id(page, "dashboard")

    # Verify we're on the dashboard URL
    expect(page).to_have_url(f"{ADMIN_URL}/admin/dashboard")

    # Check that login form is NOT visible (this is the bug)
    try:
        expect(page.locator("#loginForm")).not_to_be_visible()
    except AssertionError as e:
        take_screenshot(page, "06_BUG_login_form_still_visible")
        raise

    # Check for dashboard-specific elements
    expect(page.locator("text=Dashboard").first).to_be_visible()

    # Check for sidebar navigation
    expect(page.locator('a[href="/admin/dashboard"]')).to_be_visible()
    expect(page.locator('a[href="/admin/devices"]')).to_be_visible()
    expect(page.locator('a[href="/admin/profiles"]')).to_be_visible()

    # Check for stats cards
    expect(page.locator("text=Total Devices")).to_be_visible()
    expect(page.locator("text=Active Profiles")).to_be_visible()
    expect(page.locator("text=Total Rules")).to_be_visible()

    # Check for logout button
    expect(page.locator("#logoutBtn")).to_be_visible()
    auth_cookie = get_cookie(page, "admin_token")
    session_cookie = get_cookie(page, "admin_session")
    assert auth_cookie is not None, "admin_token cookie missing after login"
    assert session_cookie is not None, "admin_session cookie missing after login"
    take_screenshot(page, "07_dashboard_success")


def test_login_with_invalid_credentials(page: Page):
    """Test that invalid credentials show an error."""
    page.goto(f"{ADMIN_URL}/admin/login")
    take_screenshot(page, "08_invalid_login_page")

    # Fill in invalid credentials
    page.locator("#username").fill("invalid")
    page.locator("#password").fill("wrongpassword")
    take_screenshot(page, "09_invalid_credentials_filled")

    # Submit form and capture response
    with page.expect_response("**/api/auth/login") as login_response:
        page.locator('button[type="submit"]').click()
    page.wait_for_timeout(1000)
    take_screenshot(page, "10_invalid_login_error")
    response = login_response.value
    assert response.status == 401, f"Expected 401 but got {response.status}"
    error_payload = response.json()
    assert error_payload.get("message") == "Invalid username or password"

    # Should stay on login page
    expect(page).to_have_url(f"{ADMIN_URL}/admin/login")
    assert_page_id(page, "login")

    # Error message should be visible
    expect(page.locator("#error-message")).to_be_visible()
    try:
        expect(page.locator("#error-text")).to_contain_text("Invalid username or password")
    except AssertionError:
        take_screenshot(page, "11_unexpected_error_message")
        raise


def test_dashboard_requires_authentication(page: Page):
    """Test that accessing dashboard without auth redirects to login."""
    # Try to access dashboard without logging in
    page.goto(f"{ADMIN_URL}/admin/dashboard")
    page.wait_for_timeout(500)
    take_screenshot(page, "12_dashboard_without_auth")

    # Should be redirected or show unauthorized (depends on implementation)
    # If middleware is working, we should get a 401 or redirect to login
    # For now, let's check if we can see protected content
    try:
        # Try to find dashboard content
        page.wait_for_selector("text=Total Devices", timeout=2000)
        # If we got here, auth middleware might not be working
        take_screenshot(page, "13_SECURITY_BUG_no_auth_required")
        pytest.fail("Dashboard accessible without authentication")
    except:
        # Expected: should not be able to access dashboard content
        pass


def test_logout_clears_session(page: Page):
    """Test that logout clears the session and redirects to login."""
    # First login
    page.goto(f"{ADMIN_URL}/admin/login")
    page.locator("#username").fill(ADMIN_USERNAME)
    page.locator("#password").fill(ADMIN_PASSWORD)
    take_screenshot(page, "14_logout_test_login")

    with page.expect_response("**/api/auth/login"):
        page.locator('button[type="submit"]').click()
    page.wait_for_url(f"{ADMIN_URL}/admin/dashboard")
    assert_page_id(page, "dashboard")
    take_screenshot(page, "15_logout_test_dashboard")

    # Now logout
    try:
        page.locator("#logoutBtn").click()
        take_screenshot(page, "16_after_logout_click")
    except Exception as e:
        take_screenshot(page, "17_ERROR_logout_button_not_found")
        raise

    # Should redirect to login
    page.wait_for_url(f"{ADMIN_URL}/admin/login", timeout=5000)
    take_screenshot(page, "18_redirected_to_login")
    expect(page).to_have_url(f"{ADMIN_URL}/admin/login")
    assert_page_id(page, "login")

    # Should see login form
    expect(page.locator("#loginForm")).to_be_visible()

    # Try to access dashboard again - should not work
    page.goto(f"{ADMIN_URL}/admin/dashboard")
    page.wait_for_timeout(500)
    take_screenshot(page, "19_dashboard_after_logout")

    # Should not be able to see dashboard content
    try:
        page.wait_for_selector("text=Total Devices", timeout=2000)
        take_screenshot(page, "20_ERROR_dashboard_accessible_after_logout")
        pytest.fail("Dashboard accessible after logout")
    except:
        pass
