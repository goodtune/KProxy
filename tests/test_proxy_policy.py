"""
Test KProxy policy enforcement by making HTTP/HTTPS requests to KProxy.

KProxy is a transparent intercepting proxy, so requests are made directly
to KProxy's host:port with the Host header set to the target domain.

These are integration tests that require a running KProxy instance.
The same scenarios are covered in Golang unit tests in internal/policy/engine_test.go
(see TestPolicyEnforcement_DynamicRuleChanges).

These integration tests are skipped by default. To run them against a live instance:
  pytest tests/test_proxy_policy.py --run-integration
"""
import os
import time

import pytest
import requests


# Environment configuration
ADMIN_URL = os.environ.get("ADMIN_URL", "https://localhost:8444")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

# KProxy transparent proxy endpoints
KPROXY_HOST = os.environ.get("KPROXY_HOST", "localhost")
KPROXY_HTTP_PORT = os.environ.get("KPROXY_HTTP_PORT", "8080")
KPROXY_HTTPS_PORT = os.environ.get("KPROXY_HTTPS_PORT", "9443")

# Test target domain
TEST_DOMAIN = "www.example.com"


class AdminClient:
    """Client for KProxy admin API."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # Accept self-signed certs
        self.token = None
        self._login(username, password)

    def _login(self, username: str, password: str):
        """Login to admin interface and get auth token."""
        response = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        # Token is set as cookie
        self.token = self.session.cookies.get("admin_token")
        if not self.token:
            raise RuntimeError("Login did not return admin_token cookie")

    def create_device(self, name: str, identifiers: list, profile_id: str) -> dict:
        """Create a device."""
        response = self.session.post(
            f"{self.base_url}/api/devices",
            json={
                "name": name,
                "identifiers": identifiers,
                "profile_id": profile_id,
                "enabled": True,
            }
        )
        response.raise_for_status()
        return response.json()

    def create_profile(self, name: str, default_allow: bool = False) -> dict:
        """Create a profile."""
        response = self.session.post(
            f"{self.base_url}/api/profiles",
            json={
                "name": name,
                "description": f"Test profile for {name}",
                "default_allow": default_allow,
            }
        )
        response.raise_for_status()
        return response.json()

    def create_rule(self, profile_id: str, domain: str, action: str, priority: int = 100) -> dict:
        """Create a domain rule."""
        response = self.session.post(
            f"{self.base_url}/api/profiles/{profile_id}/rules",
            json={
                "domain": domain,
                "action": action,
                "priority": priority,
            }
        )
        response.raise_for_status()
        return response.json()

    def delete_rule(self, profile_id: str, rule_id: str):
        """Delete a rule."""
        response = self.session.delete(
            f"{self.base_url}/api/profiles/{profile_id}/rules/{rule_id}"
        )
        response.raise_for_status()

    def delete_device(self, device_id: str):
        """Delete a device."""
        response = self.session.delete(f"{self.base_url}/api/devices/{device_id}")
        response.raise_for_status()

    def delete_profile(self, profile_id: str):
        """Delete a profile."""
        response = self.session.delete(f"{self.base_url}/api/profiles/{profile_id}")
        response.raise_for_status()

    def reload_policy(self):
        """Trigger policy reload."""
        response = self.session.post(f"{self.base_url}/api/system/reload")
        response.raise_for_status()


@pytest.fixture(scope="module")
def admin_client():
    """Provide authenticated admin client."""
    # Disable urllib3 warnings about self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    client = AdminClient(ADMIN_URL, ADMIN_USERNAME, ADMIN_PASSWORD)
    yield client


@pytest.fixture
def test_profile(admin_client):
    """Create a test profile with default block."""
    profile = admin_client.create_profile(
        name="Proxy Test Profile",
        default_allow=False  # Block by default
    )
    yield profile
    # Cleanup
    try:
        admin_client.delete_profile(profile["id"])
    except Exception as e:
        print(f"Warning: Failed to cleanup profile: {e}")


@pytest.fixture
def test_device(admin_client, test_profile):
    """Create a test device using the test profile."""
    # Use a generic IP that represents our test client
    # In a real setup, this would match the client's IP
    device = admin_client.create_device(
        name="Proxy Test Device",
        identifiers=["192.168.1.100"],  # Example IP
        profile_id=test_profile["id"]
    )
    yield device
    # Cleanup
    try:
        admin_client.delete_device(device["id"])
    except Exception as e:
        print(f"Warning: Failed to cleanup device: {e}")


def make_kproxy_request(host: str, port: str, target_domain: str, use_https: bool = False, timeout: int = 5) -> requests.Response:
    """
    Make a request to KProxy with the target domain in the Host header.

    KProxy is a transparent intercepting proxy, so we make requests directly
    to KProxy's IP:port with the Host header set to the target domain.
    """
    # Build the URL to KProxy's endpoint
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{host}:{port}/"

    # Set the Host header to the target domain
    headers = {
        "Host": target_domain
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            verify=False,  # Accept self-signed certs from KProxy
            timeout=timeout,
            allow_redirects=True
        )
        return response
    except requests.exceptions.RequestException as e:
        # Return a mock response object with error details
        class ErrorResponse:
            def __init__(self, error):
                self.status_code = 0
                self.error = error
                self.text = str(error)
                self.ok = False

            def raise_for_status(self):
                raise self.error

        return ErrorResponse(e)


@pytest.mark.integration
@pytest.mark.proxy
def test_http_blocking_and_allowing(admin_client, test_profile, test_device):
    """
    Test HTTP request blocking and allowing through KProxy.

    This test:
    1. Verifies requests to example.com are blocked by default
    2. Adds an allow rule for example.com
    3. Verifies requests now succeed
    4. Removes the allow rule
    5. Verifies blocking is restored
    """
    # Step 1: Verify blocking (default_allow=False, no allow rules)
    print(f"\n1. Testing HTTP blocking to {TEST_DOMAIN}")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTP_PORT,
        target_domain=TEST_DOMAIN,
        use_https=False
    )

    # With blocking, we expect either:
    # - Status 403 (Forbidden) from KProxy block page
    # - Status 502/503 (Bad Gateway/Service Unavailable) if proxy blocks connection
    # - Connection error if proxy refuses
    assert response.status_code in [0, 403, 502, 503], \
        f"Expected blocking response, got {response.status_code}"
    print(f"   ✓ Request blocked as expected (status: {response.status_code})")

    # Step 2: Add allow rule for example.com
    print(f"2. Adding allow rule for {TEST_DOMAIN}")
    rule = admin_client.create_rule(
        profile_id=test_profile["id"],
        domain=TEST_DOMAIN,
        action="allow",
        priority=100
    )
    print(f"   ✓ Rule created: {rule['id']}")

    # Trigger policy reload
    admin_client.reload_policy()
    print("   ✓ Policy reloaded")

    # Give proxy a moment to apply new policy
    time.sleep(1)

    # Step 3: Verify request now succeeds
    print(f"3. Testing HTTP request after allow rule")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTP_PORT,
        target_domain=TEST_DOMAIN,
        use_https=False
    )

    assert response.status_code == 200, \
        f"Expected 200 after allow rule, got {response.status_code}"
    assert "Example Domain" in response.text or "example" in response.text.lower(), \
        "Response does not appear to be from example.com"
    print(f"   ✓ Request succeeded (status: {response.status_code})")

    # Step 4: Remove allow rule
    print(f"4. Removing allow rule")
    admin_client.delete_rule(test_profile["id"], rule["id"])
    admin_client.reload_policy()
    print("   ✓ Rule removed and policy reloaded")

    # Give proxy a moment to apply policy change
    time.sleep(1)

    # Step 5: Verify blocking is restored
    print(f"5. Verifying blocking is restored")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTP_PORT,
        target_domain=TEST_DOMAIN,
        use_https=False
    )

    assert response.status_code in [0, 403, 502, 503], \
        f"Expected blocking response after rule removal, got {response.status_code}"
    print(f"   ✓ Blocking restored (status: {response.status_code})")


@pytest.mark.integration
@pytest.mark.proxy
def test_https_blocking_and_allowing(admin_client, test_profile, test_device):
    """
    Test HTTPS request blocking and allowing through KProxy.

    This test verifies that HTTPS interception and policy enforcement work correctly.
    """
    # Step 1: Verify blocking
    print(f"\n1. Testing HTTPS blocking to {TEST_DOMAIN}")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTPS_PORT,
        target_domain=TEST_DOMAIN,
        use_https=True
    )

    assert response.status_code in [0, 403, 502, 503], \
        f"Expected blocking response, got {response.status_code}"
    print(f"   ✓ HTTPS request blocked as expected (status: {response.status_code})")

    # Step 2: Add allow rule
    print(f"2. Adding allow rule for {TEST_DOMAIN}")
    rule = admin_client.create_rule(
        profile_id=test_profile["id"],
        domain=TEST_DOMAIN,
        action="allow",
        priority=100
    )
    print(f"   ✓ Rule created: {rule['id']}")

    admin_client.reload_policy()
    print("   ✓ Policy reloaded")
    time.sleep(1)

    # Step 3: Verify request succeeds
    print(f"3. Testing HTTPS request after allow rule")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTPS_PORT,
        target_domain=TEST_DOMAIN,
        use_https=True
    )

    assert response.status_code == 200, \
        f"Expected 200 after allow rule, got {response.status_code}"
    assert "Example Domain" in response.text or "example" in response.text.lower(), \
        "Response does not appear to be from example.com"
    print(f"   ✓ HTTPS request succeeded (status: {response.status_code})")

    # Cleanup
    print(f"4. Cleaning up rule")
    admin_client.delete_rule(test_profile["id"], rule["id"])
    admin_client.reload_policy()
    print("   ✓ Rule removed")


@pytest.mark.integration
@pytest.mark.proxy
def test_wildcard_domain_matching(admin_client, test_profile, test_device):
    """
    Test that wildcard domain rules work correctly.

    This verifies that rules like '*.example.com' properly match subdomains.
    """
    # Add wildcard allow rule for *.example.com
    print(f"\n1. Adding wildcard allow rule for *.example.com")
    rule = admin_client.create_rule(
        profile_id=test_profile["id"],
        domain="*.example.com",
        action="allow",
        priority=100
    )
    print(f"   ✓ Rule created: {rule['id']}")

    admin_client.reload_policy()
    time.sleep(1)

    # Test that www.example.com is allowed
    print(f"2. Testing that www.example.com matches wildcard")
    response = make_kproxy_request(
        host=KPROXY_HOST,
        port=KPROXY_HTTP_PORT,
        target_domain=TEST_DOMAIN,
        use_https=False
    )

    assert response.status_code == 200, \
        f"Expected 200 for www.example.com with *.example.com rule, got {response.status_code}"
    print(f"   ✓ www.example.com allowed by wildcard rule")

    # Cleanup
    admin_client.delete_rule(test_profile["id"], rule["id"])
    admin_client.reload_policy()
    print("   ✓ Test complete")


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v", "-s", "-m", "proxy"])
