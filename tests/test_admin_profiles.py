"""
Test admin interface profile management functionality.
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


def test_profiles_page_loads(authenticated_page: Page):
    """Test that the profiles page loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_01_page_loaded")
    assert_page_id(authenticated_page, "profiles")

    # Check for page title
    expect(authenticated_page.locator("text=Profile Management")).to_be_visible()

    # Check for new profile button
    expect(authenticated_page.locator("#newProfileBtn")).to_be_visible()

    # Check for profiles grid
    expect(authenticated_page.locator("#profilesGrid")).to_be_visible()


def test_create_profile(authenticated_page: Page):
    """Test creating a new profile."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_02_before_create")

    # Click new profile button
    authenticated_page.locator("#newProfileBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "profiles_03_modal_opened")

    # Check modal is visible
    modal = authenticated_page.locator("#profileModal")
    expect(modal).not_to_have_class("hidden")

    # Check that only settings tab is visible for new profile
    rules_tab = authenticated_page.locator('[data-tab="rules"]')
    expect(rules_tab).to_have_class("hidden")

    # Fill in profile details
    authenticated_page.locator("#profileName").fill("Test Profile")
    authenticated_page.locator("#profileDescription").fill("Playwright test profile")
    authenticated_page.locator("#profileDefaultAllow").check()
    take_screenshot(authenticated_page, "profiles_04_form_filled")

    # Submit form
    with authenticated_page.expect_response("**/api/profiles") as response_info:
        authenticated_page.locator('#profileForm button[type="submit"]').click()

    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "profiles_05_after_create")

    response = response_info.value
    assert response.status in [200, 201], f"Create profile failed: {response.status}"

    # Modal should be hidden
    expect(modal).to_have_class("hidden")

    # Profile should appear in the grid
    expect(authenticated_page.locator("text=Test Profile")).to_be_visible()


def test_open_existing_profile(authenticated_page: Page):
    """Test opening an existing profile shows all tabs."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_06_before_open")

    # Wait for profiles to load
    authenticated_page.wait_for_timeout(500)

    # Check if there are any profiles
    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_07_profile_opened")

        # Modal should be visible
        modal = authenticated_page.locator("#profileModal")
        expect(modal).not_to_have_class("hidden")

        # All tabs should be visible for existing profile
        expect(authenticated_page.locator('[data-tab="settings"]')).to_be_visible()
        expect(authenticated_page.locator('[data-tab="rules"]')).to_be_visible()
        expect(authenticated_page.locator('[data-tab="time-rules"]')).to_be_visible()
        expect(authenticated_page.locator('[data-tab="usage-limits"]')).to_be_visible()
    else:
        pytest.skip("No profiles available to open")


def test_profile_tabs_switching(authenticated_page: Page):
    """Test switching between tabs in profile modal."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    authenticated_page.wait_for_timeout(500)

    # Open first profile
    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_08_tabs_switching")

        # Settings tab should be active by default
        settings_tab_btn = authenticated_page.locator('[data-tab="settings"]')
        expect(settings_tab_btn).to_have_class("tab-btn border-b-2 border-blue-500 py-2 px-1 text-sm font-medium text-blue-600")
        expect(authenticated_page.locator("#settingsTab")).not_to_have_class("hidden")

        # Click Rules tab
        authenticated_page.locator('[data-tab="rules"]').click()
        authenticated_page.wait_for_timeout(300)
        take_screenshot(authenticated_page, "profiles_09_rules_tab")

        expect(authenticated_page.locator("#rulesTab")).not_to_have_class("hidden")
        expect(authenticated_page.locator("#settingsTab")).to_have_class("hidden")

        # Click Time Rules tab
        authenticated_page.locator('[data-tab="time-rules"]').click()
        authenticated_page.wait_for_timeout(300)
        take_screenshot(authenticated_page, "profiles_10_time_rules_tab")

        expect(authenticated_page.locator("#timeRulesTab")).not_to_have_class("hidden")
        expect(authenticated_page.locator("#rulesTab")).to_have_class("hidden")

        # Click Usage Limits tab
        authenticated_page.locator('[data-tab="usage-limits"]').click()
        authenticated_page.wait_for_timeout(300)
        take_screenshot(authenticated_page, "profiles_11_usage_limits_tab")

        expect(authenticated_page.locator("#usageLimitsTab")).not_to_have_class("hidden")
        expect(authenticated_page.locator("#timeRulesTab")).to_have_class("hidden")
    else:
        pytest.skip("No profiles available")


def test_edit_profile(authenticated_page: Page):
    """Test editing a profile."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_12_before_edit")

    # Wait for profiles to load
    authenticated_page.wait_for_timeout(500)

    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)

        # Modify profile name
        name_input = authenticated_page.locator("#profileName")
        current_name = name_input.input_value()
        name_input.fill(current_name + " (edited)")
        take_screenshot(authenticated_page, "profiles_13_edit_filled")

        # Submit
        with authenticated_page.expect_response("**/api/profiles/*") as response_info:
            authenticated_page.locator('#profileForm button[type="submit"]').click()

        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_14_after_edit")

        response = response_info.value
        assert response.status == 200, f"Edit profile failed: {response.status}"

        # Profile grid should reload and show updated name
        expect(authenticated_page.locator(f"text={current_name} (edited)")).to_be_visible()
    else:
        pytest.skip("No profiles available to edit")


def test_delete_profile(authenticated_page: Page):
    """Test deleting a profile."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_15_before_delete")

    # Wait for profiles to load
    authenticated_page.wait_for_timeout(500)

    # Count initial profiles
    grid = authenticated_page.locator("#profilesGrid")
    initial_cards = grid.locator("> div").count()

    if initial_cards > 0:
        # Click delete button for first profile
        delete_button = grid.locator('button:has-text("Delete")').first

        # Handle confirmation dialog
        authenticated_page.on("dialog", lambda dialog: dialog.accept())

        delete_button.click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_16_after_delete")

        # Should have one fewer profile
        final_cards = grid.locator("> div").count()
        assert final_cards == initial_cards - 1 or grid.locator("text=No profiles found").is_visible()
    else:
        pytest.skip("No profiles available to delete")


def test_profile_default_allow_toggle(authenticated_page: Page):
    """Test profile default_allow checkbox."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_17_default_allow_test")

    # Create new profile
    authenticated_page.locator("#newProfileBtn").click()
    authenticated_page.wait_for_timeout(300)

    # Check default_allow checkbox
    default_allow = authenticated_page.locator("#profileDefaultAllow")
    default_allow.check()
    expect(default_allow).to_be_checked()

    # Fill and submit
    authenticated_page.locator("#profileName").fill("Allow All Profile")
    authenticated_page.locator("#profileDescription").fill("Default allow test")

    with authenticated_page.expect_response("**/api/profiles"):
        authenticated_page.locator('#profileForm button[type="submit"]').click()

    authenticated_page.wait_for_timeout(500)
    take_screenshot(authenticated_page, "profiles_18_allow_all_created")

    # Should show "Default: Allow" in the profile card
    expect(authenticated_page.locator("text=Default: Allow")).to_be_visible()


def test_profile_validation(authenticated_page: Page):
    """Test profile form validation."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_19_validation_test")

    # Open modal
    authenticated_page.locator("#newProfileBtn").click()
    authenticated_page.wait_for_timeout(300)

    # Try to submit empty form
    submit_btn = authenticated_page.locator('#profileForm button[type="submit"]')
    submit_btn.click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "profiles_20_validation_error")

    # Modal should still be visible (form validation failed)
    modal = authenticated_page.locator("#profileModal")
    expect(modal).not_to_have_class("hidden")

    # Fill required field
    authenticated_page.locator("#profileName").fill("Valid Profile")
    take_screenshot(authenticated_page, "profiles_21_validation_passed")

    # Now submission should work
    with authenticated_page.expect_response("**/api/profiles"):
        submit_btn.click()

    authenticated_page.wait_for_timeout(500)

    # Modal should be hidden now
    expect(modal).to_have_class("hidden")


def test_close_profile_modal(authenticated_page: Page):
    """Test closing profile modal with close button."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_22_before_close")

    # Open modal
    authenticated_page.locator("#newProfileBtn").click()
    authenticated_page.wait_for_timeout(300)

    modal = authenticated_page.locator("#profileModal")
    expect(modal).not_to_have_class("hidden")

    # Fill in some data
    authenticated_page.locator("#profileName").fill("This should not be saved")

    # Click close button
    authenticated_page.locator("#closeModalBtn").click()
    authenticated_page.wait_for_timeout(300)
    take_screenshot(authenticated_page, "profiles_23_after_close")

    # Modal should be hidden
    expect(modal).to_have_class("hidden")

    # Profile should not appear in grid
    expect(authenticated_page.locator("text=This should not be saved")).not_to_be_visible()


def test_rules_tab_loads_rules(authenticated_page: Page):
    """Test that rules tab loads and displays rules."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    authenticated_page.wait_for_timeout(500)

    # Open first profile
    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)

        # Click rules tab
        authenticated_page.locator('[data-tab="rules"]').click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_24_rules_loaded")

        # Check for rules table
        expect(authenticated_page.locator("#rulesTableBody")).to_be_visible()

        # Should either show rules or "No rules defined" message
        table_body = authenticated_page.locator("#rulesTableBody")
        has_rules = table_body.locator("tr").count() > 0
        has_empty_msg = table_body.locator("text=No rules defined").is_visible()

        assert has_rules or has_empty_msg, "Rules tab should show rules or empty message"
    else:
        pytest.skip("No profiles available")


def test_time_rules_tab_loads(authenticated_page: Page):
    """Test that time rules tab loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    authenticated_page.wait_for_timeout(500)

    # Open first profile
    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)

        # Click time rules tab
        authenticated_page.locator('[data-tab="time-rules"]').click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_25_time_rules_loaded")

        # Check for time rules container
        expect(authenticated_page.locator("#timeRulesTableBody")).to_be_visible()

        # Check for new time rule button
        expect(authenticated_page.locator("#newTimeRuleBtn")).to_be_visible()
    else:
        pytest.skip("No profiles available")


def test_usage_limits_tab_loads(authenticated_page: Page):
    """Test that usage limits tab loads correctly."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    authenticated_page.wait_for_timeout(500)

    # Open first profile
    profile_card = authenticated_page.locator("#profilesGrid > div").first
    if profile_card.is_visible():
        profile_card.click()
        authenticated_page.wait_for_timeout(500)

        # Click usage limits tab
        authenticated_page.locator('[data-tab="usage-limits"]').click()
        authenticated_page.wait_for_timeout(500)
        take_screenshot(authenticated_page, "profiles_26_usage_limits_loaded")

        # Check for usage limits container
        expect(authenticated_page.locator("#usageLimitsTableBody")).to_be_visible()

        # Check for new usage limit button
        expect(authenticated_page.locator("#newUsageLimitBtn")).to_be_visible()
    else:
        pytest.skip("No profiles available")


def test_sidebar_navigation_from_profiles(authenticated_page: Page):
    """Test sidebar navigation from profiles page."""
    authenticated_page.goto(f"{ADMIN_URL}/admin/profiles")
    take_screenshot(authenticated_page, "profiles_27_sidebar_test")

    # Current page (profiles) should be highlighted
    profiles_link = authenticated_page.locator('a[href="/admin/profiles"]')
    expect(profiles_link).to_have_class("block px-4 py-2 rounded bg-gray-700 hover:bg-gray-600")

    # Navigate to devices
    authenticated_page.locator('a[href="/admin/devices"]').click()
    authenticated_page.wait_for_url(f"{ADMIN_URL}/admin/devices")
    take_screenshot(authenticated_page, "profiles_28_navigated_devices")

    assert_page_id(authenticated_page, "devices")
