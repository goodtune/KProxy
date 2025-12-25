"""
Pytest configuration and fixtures for Playwright tests.
"""
import os
from typing import Tuple

import pytest
from playwright.sync_api import BrowserContext, Page


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="run integration tests that require a running KProxy instance",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: integration tests requiring running KProxy instance"
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is specified."""
    if not config.getoption("--run-integration", default=False):
        skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


def _parse_endpoint(value: str) -> Tuple[str, str]:
    """Split tox-docker endpoint env values into host/port."""
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.strip()
    host = "localhost"
    port = value
    if value.startswith("["):
        closing = value.find("]")
        if closing != -1:
            host = value[1:closing]
            remainder = value[closing + 1 :]
            if remainder.startswith(":"):
                port = remainder[1:]
            else:
                port = ""
    elif ":" in value:
        host, port = value.rsplit(":", 1)
    return host or "localhost", port


def _get_admin_url() -> str:
    """Determine admin URL from tox-docker exposed ports or fallbacks."""
    endpoint = os.environ.get("ADMIN_HTTPS_PORT")
    if endpoint:
        host, port = _parse_endpoint(endpoint)
        if port:
            return f"https://{host}:{port}"

    host = os.environ.get("TOX_DOCKER_KPROXY_HOST")
    port = os.environ.get("TOX_DOCKER_KPROXY_PORT_8444_TCP")
    if host and port:
        return f"https://{host}:{port}"

    direct = os.environ.get("ADMIN_URL")
    if direct:
        return direct

    return "https://localhost:8444"


# Ensure test modules importing ADMIN_URL env var see the generated value.
os.environ.setdefault("ADMIN_URL", _get_admin_url())


@pytest.fixture(scope="session")
def admin_url() -> str:
    return _get_admin_url()


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args, admin_url):
    """Configure browser context to accept self-signed certificates."""
    return {
        **browser_context_args,
        "ignore_https_errors": True,
        # Set base URL for Playwright traces/logs
        "base_url": admin_url,
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
