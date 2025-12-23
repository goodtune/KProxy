"""
Test admin interface device management functionality.
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


def test_devices_page_loads(authenticated_page: Page):
    """Test that the devices page loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_01_page_loaded")
    assert_page_id(authenticated_page, "devices")

    # Check for page title
    expect(authenticated_page.locator("text=Device Management")).to_be_visible()

    # Check for new device button
    expect(authenticated_page.locator("#newDeviceBtn")).to_be_visible()

    # Check for devices table
    expect(authenticated_page.locator("#devicesTableBody")).to_be_visible()


def test_create_device(authenticated_page: Page):
    """Test creating a new device."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_02_before_create")

    # Click new device button
    authenticated_page.locator("#newDeviceBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "devices_03_modal_opened")

    # Check modal is visible
    modal = authenticated_page.locator("#deviceModal")
    expect(modal).not_to_have_class("hidden")

    # Fill in device details
    authenticated_page.locator("#deviceName").fill("Test Device")
    authenticated_page.locator("#deviceDescription").fill("Playwright test device")
    authenticated_page.locator("#deviceIdentifiers").fill("192.168.1.100\naa:bb:cc:dd:ee:ff")

    # Note: Profile select might be empty if no profiles exist
    # We'll handle that by allowing empty profile
    take_screenshot(authenticated_page, "devices_04_form_filled")

    # Submit form
    with authenticated_page.expect_response("**/api/devices") as response_info:
        authenticated_page.locator('#deviceForm button[type="submit"]').click()

    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "devices_05_after_create")

    response = response_info.value
    assert response.status in [200, 201], f"Create device failed: {response.status}"

    # Modal should be hidden
    expect(modal).to_have_class("hidden")

    # Device should appear in the table
    expect(authenticated_page.locator("text=Test Device")).to_be_visible()


def test_edit_device(authenticated_page: Page):
    """Test editing an existing device."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_06_before_edit")

    # Wait for devices to load
    authenticated_page.wait_for_timeout(500)

    # Find and click edit button for the first device
    edit_button = authenticated_page.locator('button:has-text("Edit")').first
    if edit_button.is_visible():
        edit_button.click()
        authenticated_page.wait_for_timeout(300)
        take_screenshot(authenticated_page, "devices_07_edit_modal")

        # Modal should be visible
        modal = authenticated_page.locator("#deviceModal")
        expect(modal).not_to_have_class("hidden")

        # Modify the name
        name_input = authenticated_page.locator("#deviceName")
        current_name = name_input.input_value()
        name_input.fill(current_name + " (edited)")
        take_screenshot(authenticated_page, "devices_08_edit_filled")

        # Submit
        with authenticated_page.expect_response("**/api/devices/*") as response_info:
            authenticated_page.locator('#deviceForm button[type="submit"]').click()

        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "devices_09_after_edit")

        response = response_info.value
        assert response.status == 200, f"Edit device failed: {response.status}"

        # Check updated name is visible
        expect(authenticated_page.locator(f"text={current_name} (edited)")).to_be_visible()
    else:
        pytest.skip("No devices available to edit")


def test_delete_device(authenticated_page: Page):
    """Test deleting a device."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_10_before_delete")

    # Wait for devices to load
    authenticated_page.wait_for_timeout(500)

    # Count initial devices
    table_body = authenticated_page.locator("#devicesTableBody")
    initial_rows = table_body.locator("tr").count()

    if initial_rows > 0:
        # Click delete button for first device
        delete_button = authenticated_page.locator('button:has-text("Delete")').first

        # Handle confirmation dialog
        authenticated_page.on("dialog", lambda dialog: dialog.accept())

        delete_button.click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "devices_11_after_delete")

        # Should have one fewer device
        final_rows = table_body.locator("tr").count()
        assert final_rows == initial_rows - 1 or table_body.locator("text=No devices found").is_visible()
    else:
        pytest.skip("No devices available to delete")


def test_cancel_device_creation(authenticated_page: Page):
    """Test canceling device creation."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_12_before_cancel")

    # Open modal
    authenticated_page.locator("#newDeviceBtn").click()
    authenticated_page.wait_for_timeout(300)

    modal = authenticated_page.locator("#deviceModal")
    expect(modal).not_to_have_class("hidden")

    # Fill in some data
    authenticated_page.locator("#deviceName").fill("This should not be saved")

    # Click cancel
    authenticated_page.locator("#cancelBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "devices_13_after_cancel")

    # Modal should be hidden
    expect(modal).to_have_class("hidden")

    # Device should not appear in table
    expect(authenticated_page.locator("text=This should not be saved")).not_to_be_visible()


def test_device_validation(authenticated_page: Page):
    """Test device form validation."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_14_validation_test")

    # Open modal
    authenticated_page.locator("#newDeviceBtn").click()
    authenticated_page.wait_for_timeout(300)

    # Try to submit empty form
    submit_btn = authenticated_page.locator('#deviceForm button[type="submit"]')
    submit_btn.click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "devices_15_validation_error")

    # Modal should still be visible (form validation failed)
    modal = authenticated_page.locator("#deviceModal")
    expect(modal).not_to_have_class("hidden")

    # Fill required fields
    authenticated_page.locator("#deviceName").fill("Valid Device")
    authenticated_page.locator("#deviceIdentifiers").fill("192.168.1.200")
    take_screenshot(authenticated_page, "devices_16_validation_passed")

    # Now submission should work
    with authenticated_page.expect_response("**/api/devices"):
        submit_btn.click()

    authenticated_page.wait_for_timeout(500)

    # Modal should be hidden now
    expect(modal).to_have_class("hidden")


def test_device_active_toggle(authenticated_page: Page):
    """Test device active status checkbox."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_17_active_toggle_test")

    # Open new device modal
    authenticated_page.locator("#newDeviceBtn").click()
    authenticated_page.wait_for_timeout(300)

    # Check that active checkbox is checked by default
    active_checkbox = authenticated_page.locator("#deviceActive")
    expect(active_checkbox).to_be_checked()

    # Uncheck it
    active_checkbox.uncheck()
    expect(active_checkbox).not_to_be_checked()

    # Fill and submit
    authenticated_page.locator("#deviceName").fill("Inactive Device")
    authenticated_page.locator("#deviceIdentifiers").fill("192.168.1.201")

    with authenticated_page.expect_response("**/api/devices"):
        authenticated_page.locator('#deviceForm button[type="submit"]').click()

    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "devices_18_inactive_created")

    # Should show as inactive in the table
    expect(authenticated_page.locator("text=Inactive")).to_be_visible()


def test_sidebar_navigation(authenticated_page: Page):
    """Test sidebar navigation from devices page."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "devices_19_sidebar_test")

    # Check sidebar links are visible
    expect(authenticated_page.locator('a[href="/admin/dashboard"]')).to_be_visible()
    expect(authenticated_page.locator('a[href="/admin/devices"]')).to_be_visible()
    expect(authenticated_page.locator('a[href="/admin/profiles"]')).to_be_visible()

    # Current page (devices) should be highlighted
    devices_link = authenticated_page.locator('a[href="/admin/devices"]')
    expect(devices_link).to_have_class("block px-4 py-2 rounded bg-gray-700 hover:bg-gray-600")

    # Navigate to dashboard
    authenticated_page.locator('a[href="/admin/dashboard"]').click()
    authenticated_page.wait_for_url(f"{ADMIN_URL}/admin/dashboard")
    take_screenshot(authenticated_page, "devices_20_navigated_dashboard")

    assert_page_id(authenticated_page, "dashboard")
