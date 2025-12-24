"""
Sequential Playwright test that exercises every admin view using subtests.
"""
import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


ADMIN_URL = os.environ.get("ADMIN_URL", "https://localhost:8443")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
LOGIN_URL_RE = re.compile(rf"{re.escape(ADMIN_URL)}/admin/login.*")
WAIT_KWARGS = {"timeout": 10000}

SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Allow self-signed admin certs."""
    return {**browser_context_args, "ignore_https_errors": True}


def take_screenshot(page: Page, counter: dict, name: str):
    """Persist numbered screenshots to keep a chronological record."""
    counter["value"] += 1
    safe = re.sub(r"[^0-9A-Za-z_-]+", "_", name).strip("_") or "screenshot"
    path = SCREENSHOT_DIR / f"{counter['value']:02d}_{safe}.png"
    page.screenshot(path=str(path), full_page=True)
    print(f"📸 Screenshot saved: {path}")


def assert_page_id(page: Page, expected_id: str):
    body = page.locator("body")
    expect(body).to_have_attribute("data-page", expected_id)


def wait_for_options(page: Page, selector: str):
    page.wait_for_function(
        "(sel) => { const el = document.querySelector(sel); return !!el && el.options.length > 1; }",
        arg=selector,
    )


@pytest.mark.e2e
def test_admin_full_flow(page: Page, subtests):
    """
    Drive the entire admin UI in one authenticated browser session so that every
    view and primary workflow is exercised in dependency order.
    """
    screenshots = {"value": 0}
    state = {
        "profile_name": "Playwright Profile",
        "device_name": "Playwright Device",
    }

    with subtests.test("login page loads"):
        page.goto(f"{ADMIN_URL}/admin/login")
        assert_page_id(page, "login")
        expect(page.locator("#loginForm")).to_be_visible()
        expect(page.locator("#username")).to_be_visible()
        expect(page.locator("#password")).to_be_visible()
        take_screenshot(page, screenshots, "login_page")

    with subtests.test("invalid login rejected"):
        page.locator("#username").fill("wrong")
        page.locator("#password").fill("password")
        with page.expect_response("**/api/auth/login") as resp:
            page.locator('button[type="submit"]').click()
        expect(page.locator("#error-message")).to_be_visible()
        assert resp.value.status == 401
        take_screenshot(page, screenshots, "invalid_login")
        page.reload()
        page.wait_for_load_state("networkidle")

    with subtests.test("successful login to dashboard"):
        page.locator("#username").fill(ADMIN_USERNAME)
        page.locator("#password").fill(ADMIN_PASSWORD)
        with page.expect_response("**/api/auth/login") as resp:
            page.locator('button[type="submit"]').click()
        assert resp.value.status == 200
        page.wait_for_url(f"{ADMIN_URL}/admin/dashboard")
        assert_page_id(page, "dashboard")
        cookies = {cookie["name"]: cookie for cookie in page.context.cookies()}
        assert "admin_token" in cookies
        take_screenshot(page, screenshots, "dashboard_after_login")

    with subtests.test("dashboard widgets render"):
        dashboard_header = page.locator("main h2").filter(has_text="Dashboard").first
        expect(dashboard_header).to_be_visible()
        expect(page.locator('a[href="/admin/devices"]')).to_be_visible()
        expect(page.locator("text=Total Devices")).to_be_visible()
        expect(page.locator("text=Active Profiles")).to_be_visible()
        take_screenshot(page, screenshots, "dashboard_widgets")

    with subtests.test("profiles view creates base profile"):
        page.goto(f"{ADMIN_URL}/admin/profiles")
        assert_page_id(page, "profiles")
        expect(page.locator("#newProfileBtn")).to_be_visible()
        take_screenshot(page, screenshots, "profiles_page")

        page.locator("#newProfileBtn").click()
        modal = page.locator("#profileModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        page.locator("#profileName").fill(state["profile_name"])
        page.locator("#profileDescription").fill("Playwright smoke profile")
        page.locator("#profileDefaultAllow").check()
        with page.expect_response("**/api/profiles") as resp:
            page.locator('#profileForm button[type="submit"]').click()
        profile = resp.value.json()
        state["profile_id"] = profile["id"]
        expect(modal).to_have_class(re.compile(r"\bhidden\b"))
        expect(page.locator(f"text={state['profile_name']}")).to_be_visible()
        take_screenshot(page, screenshots, "profile_created")

    with subtests.test("profiles view edits profile and tabs"):
        card = page.locator("#profilesGrid > div").filter(has_text=state["profile_name"]).first
        card.wait_for(state="visible")
        card.click()
        modal = page.locator("#profileModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        expect(page.locator('[data-tab="rules"]')).to_be_visible()
        expect(page.locator('[data-tab="usage-limits"]')).to_be_visible()
        page.locator('[data-tab="rules"]').click()
        expect(page.locator("#rulesTab")).not_to_have_class("hidden")
        page.locator('[data-tab="time-rules"]').click()
        expect(page.locator("#timeRulesTab")).not_to_have_class("hidden")
        take_screenshot(page, screenshots, "profile_tabs")

        page.locator('[data-tab="settings"]').click()
        name_input = page.locator("#profileName")
        name_input.wait_for(state="visible")
        new_name = f"{state['profile_name']} Updated"
        name_input.fill(new_name)
        with page.expect_response(f"**/api/profiles/{state['profile_id']}") as resp:
            page.locator('#profileForm button[type="submit"]').click()
        assert resp.value.status == 200
        state["profile_name"] = new_name
        take_screenshot(page, screenshots, "profile_updated")
        page.locator("#closeModalBtn").click()
        expect(modal).to_have_class(re.compile(r"\bhidden\b"))

    with subtests.test("devices view creates device tied to profile"):
        page.goto(f"{ADMIN_URL}/admin/devices")
        assert_page_id(page, "devices")
        page.locator("#newDeviceBtn").click()
        modal = page.locator("#deviceModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        wait_for_options(page, "#deviceProfile")
        page.locator("#deviceName").fill(state["device_name"])
        page.locator("#deviceDescription").fill("Playwright managed device")
        page.locator("#deviceIdentifiers").fill("192.168.50.10\naa:bb:cc:dd:ee:ff")
        page.locator("#deviceProfile").select_option(value=state["profile_id"])
        with page.expect_response("**/api/devices") as resp:
            page.locator('#deviceForm button[type="submit"]').click()
        device = resp.value.json()
        state["device_id"] = device["id"]
        expect(modal).to_have_class(re.compile(r"\bhidden\b"))
        row = page.locator(f'#devicesTableBody tr:has-text("{state["device_name"]}")').first
        row.wait_for(state="visible")
        expect(row).to_be_visible()
        take_screenshot(page, screenshots, "device_created")

    with subtests.test("devices view edits device and validates modal"):
        row = page.locator(f'#devicesTableBody tr:has-text("{state["device_name"]}")').first
        row.wait_for(state="visible")
        edit_button = row.locator('button:has-text("Edit")')
        expect(edit_button).to_be_visible()
        edit_button.click()
        modal = page.locator("#deviceModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        updated_name = f"{state['device_name']} Updated"
        page.locator("#deviceName").fill(updated_name)
        with page.expect_response(f"**/api/devices/{state['device_id']}") as resp:
            page.locator('#deviceForm button[type="submit"]').click()
        assert resp.value.status == 200
        state["device_name"] = updated_name
        take_screenshot(page, screenshots, "device_edited")

        page.locator("#newDeviceBtn").click()
        modal = page.locator("#deviceModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        page.locator('#deviceForm button[type="submit"]').click()
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        page.locator("#cancelBtn").click()
        expect(modal).to_have_class(re.compile(r"\bhidden\b"))
        take_screenshot(page, screenshots, "device_validation_cancel")

    with subtests.test("devices view deletes device first"):
        row = page.locator(f'#devicesTableBody tr:has-text("{state["device_name"]}")').first
        row.wait_for(state="visible")
        delete_button = row.locator('button:has-text("Delete")')
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_response(f"**/api/devices/{state['device_id']}") as resp:
            delete_button.click()
        assert resp.value.status in (200, 204)
        row.wait_for(state="detached")
        take_screenshot(page, screenshots, "device_deleted")

    with subtests.test("profiles view deletes profile after device removal"):
        page.goto(f"{ADMIN_URL}/admin/profiles")
        assert_page_id(page, "profiles")
        card = page.locator("#profilesGrid > div").filter(has_text=state["profile_name"]).first
        card.wait_for(state="visible")
        delete_btn = card.locator('button:has-text("Delete")')
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_response(f"**/api/profiles/{state['profile_id']}") as resp:
            delete_btn.click()
        assert resp.value.status in (200, 204)
        expect(page.locator(f"text={state['profile_name']}")).to_have_count(0)
        take_screenshot(page, screenshots, "profile_deleted")

    with subtests.test("logs view interactions"):
        page.goto(f"{ADMIN_URL}/admin/logs")
        assert_page_id(page, "logs")
        expect(page.locator("text=System Logs")).to_be_visible()
        expect(page.locator("#requestLogsTable")).to_be_visible()
        page.locator('[data-tab="dns"]').click()
        expect(page.locator("#dnsLogsTable")).to_be_visible()
        page.locator('[data-tab="request"]').click()
        page.locator("#filterDomain").fill("example.com")
        page.locator("#filterAction").select_option("allow")
        page.locator("#applyFiltersBtn").click()
        expect(page.locator("#logCount")).to_be_visible()
        page.locator("#refreshBtn").click()
        take_screenshot(page, screenshots, "logs_filters")

        page.locator("#clearLogsBtn").click()
        modal = page.locator("#clearLogsModal")
        expect(modal).not_to_have_class(re.compile(r"\bhidden\b"))
        page.locator("#cancelClearBtn").click()
        expect(modal).to_have_class(re.compile(r"\bhidden\b"))

    with subtests.test("sessions view interactions"):
        page.goto(f"{ADMIN_URL}/admin/sessions")
        assert_page_id(page, "sessions")
        expect(page.locator("text=Sessions & Usage")).to_be_visible()
        expect(page.locator('[data-tab="active"]')).to_be_visible()
        page.locator('[data-tab="usage"]').click()
        expect(page.locator("#usageTab")).not_to_have_class("hidden")
        page.locator("#refreshBtn").click()
        take_screenshot(page, screenshots, "sessions_page")

    with subtests.test("sidebar navigation works"):
        page.locator('a[href="/admin/dashboard"]').click()
        page.wait_for_url(f"{ADMIN_URL}/admin/dashboard")
        assert_page_id(page, "dashboard")
        page.locator('a[href="/admin/logs"]').click()
        page.wait_for_url(f"{ADMIN_URL}/admin/logs")
        assert_page_id(page, "logs")
        take_screenshot(page, screenshots, "sidebar_navigation")

    with subtests.test("logout and auth required"):
        page.locator("#logoutBtn").click()
        page.wait_for_url(LOGIN_URL_RE, wait_until="networkidle", **WAIT_KWARGS)
        assert_page_id(page, "login")
        take_screenshot(page, screenshots, "logged_out")
        page.goto(f"{ADMIN_URL}/admin/dashboard")
        page.wait_for_url(LOGIN_URL_RE, wait_until="networkidle", **WAIT_KWARGS)
        assert_page_id(page, "login")
