"""
Pytest configuration and fixtures for Playwright tests.
"""
import pytest
from playwright.sync_api import Page, BrowserContext


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context to accept self-signed certificates."""
    return {
        **browser_context_args,
        "ignore_https_errors": True,
    }


@pytest.fixture
def page(page: Page):
    """Configure page with shorter timeouts for CI."""
    # Set default timeout to 3 seconds (less than pytest's 5 second timeout)
    page.set_default_timeout(3000)
    # Set navigation timeout specifically
    page.set_default_navigation_timeout(3000)
    return page


@pytest.fixture
def context(context: BrowserContext):
    """Configure context with shorter timeouts for CI."""
    # Set default timeout for all pages in this context
    context.set_default_timeout(3000)
    context.set_default_navigation_timeout(3000)
    return context
