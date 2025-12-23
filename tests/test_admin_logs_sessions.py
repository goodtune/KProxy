"""
Test admin interface logs and sessions functionality.
"""
import os
from pathlib import Path
import pytest
from playwright.sync_api import Page, expect


# Configuration
ADMIN_URL = os.environ.get("ADMIN_URL", "https://localhost:8444")
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "changeme"

# Screenshot directory
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)


def take_screenshot(page: Page, name: str):
    """Helper to take and save a screenshot."""
    screenshot_path = SCREENSHOT_DIR / f"{name}.png"
    page.screenshot(path=str(screenshot_path), full_page=True)
    print(f"📸 Screenshot saved: {screenshot_path}")


def assert_page_id(page: Page, expected_id: str):
    """Assert which page is currently rendered via body data attribute."""
    body = page.locator("body")
    expect(body).to_have_attribute("data-page", expected_id)


@pytest.fixture
def authenticated_page(page: Page):
    """Fixture that provides an authenticated page."""
    # Login
    page.goto(f"{ADMIN_URL}/admin/login")
    page.locator("#username").fill(ADMIN_USERNAME)
    page.locator("#password").fill(ADMIN_PASSWORD)

    with page.expect_response("**/api/auth/login"):
        page.locator('button[type="submit"]').click()

    page.wait_for_url(f"{ADMIN_URL}/admin/dashboard", timeout=5000)
    return page


# LOGS TESTS

def test_logs_page_loads(authenticated_page: Page):
    """Test that the logs page loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    take_screenshot(authenticated_page, "logs_01_page_loaded")
    assert_page_id(authenticated_page, "logs")

    # Check for page title
    expect(authenticated_page.locator("text=System Logs")).to_be_visible()

    # Check for tabs
    expect(authenticated_page.locator('[data-tab="request"]')).to_be_visible()
    expect(authenticated_page.locator('[data-tab="dns"]')).to_be_visible()

    # Check for filters
    expect(authenticated_page.locator("#filterDomain")).to_be_visible()
    expect(authenticated_page.locator("#filterDevice")).to_be_visible()
    expect(authenticated_page.locator("#filterAction")).to_be_visible()


def test_logs_request_tab(authenticated_page: Page):
    """Test request logs tab functionality."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(1000)
    take_screenshot(authenticated_page, "logs_02_request_tab")

    # Request logs should be active by default
    request_table = authenticated_page.locator("#requestLogsTable")
    expect(request_table).not_to_have_class("hidden")

    # Check for table headers
    expect(authenticated_page.locator("text=Host")).to_be_visible()
    expect(authenticated_page.locator("text=Path")).to_be_visible()
    expect(authenticated_page.locator("text=Method")).to_be_visible()
    expect(authenticated_page.locator("text=Action")).to_be_visible()


def test_logs_dns_tab(authenticated_page: Page):
    """Test DNS logs tab functionality."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_03_before_dns_tab")

    # Click DNS tab
    authenticated_page.locator('[data-tab="dns"]').click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_04_dns_tab")

    # DNS table should be visible
    dns_table = authenticated_page.locator("#dnsLogsTable")
    expect(dns_table).not_to_have_class("hidden")

    # Request table should be hidden
    request_table = authenticated_page.locator("#requestLogsTable")
    expect(request_table).to_have_class("hidden")


def test_logs_filter_functionality(authenticated_page: Page):
    """Test log filtering."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_05_before_filter")

    # Fill in filters
    authenticated_page.locator("#filterDomain").fill("example.com")
    authenticated_page.locator("#filterAction").select_option("allow")
    take_screenshot(authenticated_page, "logs_06_filters_filled")

    # Apply filters
    authenticated_page.locator("#applyFiltersBtn").click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_07_filters_applied")

    # Log count should be visible
    expect(authenticated_page.locator("#logCount")).to_be_visible()


def test_logs_pagination(authenticated_page: Page):
    """Test log pagination controls."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_08_pagination")

    # Pagination buttons should exist
    prev_btn = authenticated_page.locator("#prevPageBtn")
    next_btn = authenticated_page.locator("#nextPageBtn")

    expect(prev_btn).to_be_visible()
    expect(next_btn).to_be_visible()

    # Previous should be disabled initially
    expect(prev_btn).to_be_disabled()


def test_logs_refresh_button(authenticated_page: Page):
    """Test refresh button."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_09_before_refresh")

    # Click refresh
    authenticated_page.locator("#refreshBtn").click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_10_after_refresh")

    # Should still be on logs page
    assert_page_id(authenticated_page, "logs")


def test_logs_clear_modal(authenticated_page: Page):
    """Test clear logs modal."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "logs_11_before_clear_modal")

    # Open modal
    authenticated_page.locator("#clearLogsBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "logs_12_clear_modal_opened")

    # Modal should be visible
    modal = authenticated_page.locator("#clearLogsModal")
    expect(modal).not_to_have_class("hidden")

    # Check form elements
    expect(authenticated_page.locator("#clearDays")).to_be_visible()
    expect(authenticated_page.locator("#clearLogType")).to_be_visible()

    # Cancel button should close modal
    authenticated_page.locator("#cancelClearBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "logs_13_modal_cancelled")

    expect(modal).to_have_class("hidden")


# SESSIONS TESTS

def test_sessions_page_loads(authenticated_page: Page):
    """Test that the sessions page loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    take_screenshot(authenticated_page, "sessions_01_page_loaded")
    assert_page_id(authenticated_page, "sessions")

    # Check for page title
    expect(authenticated_page.locator("text=Sessions & Usage")).to_be_visible()

    # Check for tabs
    expect(authenticated_page.locator('[data-tab="active"]')).to_be_visible()
    expect(authenticated_page.locator('[data-tab="usage"]')).to_be_visible()


def test_sessions_active_tab(authenticated_page: Page):
    """Test active sessions tab functionality."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    authenticated_page.wait_for_timeout(1000)
    take_screenshot(authenticated_page, "sessions_02_active_tab")

    # Active sessions should be visible by default
    active_tab = authenticated_page.locator("#activeTab")
    expect(active_tab).not_to_have_class("hidden")

    # Check for table
    sessions_table = authenticated_page.locator("#sessionsTableBody")
    expect(sessions_table).to_be_visible()

    # Should show either sessions or empty message
    has_sessions = sessions_table.locator("tr").count() > 0
    has_empty = sessions_table.locator("text=No active sessions").is_visible()
    assert has_sessions or has_empty, "Should show sessions or empty message"


def test_sessions_usage_tab(authenticated_page: Page):
    """Test daily usage tab functionality."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_03_before_usage_tab")

    # Click usage tab
    authenticated_page.locator('[data-tab="usage"]').click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_04_usage_tab")

    # Usage tab should be visible
    usage_tab = authenticated_page.locator("#usageTab")
    expect(usage_tab).not_to_have_class("hidden")

    # Active tab should be hidden
    active_tab = authenticated_page.locator("#activeTab")
    expect(active_tab).to_have_class("hidden")

    # Date picker should be visible
    expect(authenticated_page.locator("#usageDate")).to_be_visible()
    expect(authenticated_page.locator("#loadUsageBtn")).to_be_visible()


def test_sessions_date_picker(authenticated_page: Page):
    """Test date picker in usage tab."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    authenticated_page.wait_for_timeout(500)

    # Go to usage tab
    authenticated_page.locator('[data-tab="usage"]').click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_05_date_picker")

    # Date input should have today's date by default
    date_input = authenticated_page.locator("#usageDate")
    expect(date_input).not_to_be_empty()

    # Click load button
    authenticated_page.locator("#loadUsageBtn").click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_06_usage_loaded")

    # Usage table should be visible
    usage_table = authenticated_page.locator("#usageTableBody")
    expect(usage_table).to_be_visible()


def test_sessions_refresh_button(authenticated_page: Page):
    """Test refresh button in sessions."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_07_before_refresh")

    # Click refresh
    authenticated_page.locator("#refreshBtn").click()
    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "sessions_08_after_refresh")

    # Should still be on sessions page
    assert_page_id(authenticated_page, "sessions")


def test_sessions_terminate_button_exists(authenticated_page: Page):
    """Test that terminate button exists if sessions present."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    authenticated_page.wait_for_timeout(1000)
    take_screenshot(authenticated_page, "sessions_09_check_terminate")

    # Check if any sessions have terminate buttons
    sessions_table = authenticated_page.locator("#sessionsTableBody")
    terminate_buttons = sessions_table.locator('button:has-text("Terminate")')

    # If there are sessions, terminate buttons should exist
    session_rows = sessions_table.locator("tr")
    if session_rows.count() > 0 and not sessions_table.locator("text=No active sessions").is_visible():
        expect(terminate_buttons.first).to_be_visible()


def test_logs_sessions_navigation(authenticated_page: Page):
    """Test navigation between logs and sessions pages."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    take_screenshot(authenticated_page, "navigation_01_on_logs")

    # Logs link should be highlighted
    logs_link = authenticated_page.locator('a[href="/admin/logs"]')
    expect(logs_link).to_have_class("block px-4 py-2 rounded bg-gray-700 hover:bg-gray-600")

    # Navigate to sessions
    authenticated_page.locator('a[href="/admin/sessions"]').click()
    authenticated_page.wait_for_url(f"{ADMIN_URL}/admin/sessions")
    take_screenshot(authenticated_page, "navigation_02_on_sessions")

    assert_page_id(authenticated_page, "sessions")

    # Sessions link should be highlighted
    sessions_link = authenticated_page.locator('a[href="/admin/sessions"]')
    expect(sessions_link).to_have_class("block px-4 py-2 rounded bg-gray-700 hover:bg-gray-600")


def test_sidebar_navigation_from_logs(authenticated_page: Page):
    """Test sidebar navigation from logs page."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/logs")
    take_screenshot(authenticated_page, "logs_14_sidebar_test")

    # Navigate to devices
    authenticated_page.locator('a[href="/admin/devices"]').click()
    authenticated_page.wait_for_url(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "logs_15_navigated_devices")

    assert_page_id(authenticated_page, "devices")


def test_sidebar_navigation_from_sessions(authenticated_page: Page):
    """Test sidebar navigation from sessions page."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/sessions")
    take_screenshot(authenticated_page, "sessions_10_sidebar_test")

    # Navigate to profiles
    authenticated_page.locator('a[href="/admin/profiles"]').click()
    authenticated_page.wait_for_url(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "sessions_11_navigated_profiles")

    assert_page_id(authenticated_page, "profiles")
