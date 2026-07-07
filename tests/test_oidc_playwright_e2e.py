"""End-to-end OIDC authorization flow tests using Playwright.

These tests target running local services (auth provider + auth client).
Default target is localhost to avoid cross-host state/cookie mismatches.
"""

import os
from urllib.request import urlopen

import pytest

playwright_sync_api = pytest.importorskip(
    "playwright.sync_api",
    reason="Playwright is required for e2e browser tests.",
)

sync_playwright = playwright_sync_api.sync_playwright
TimeoutError = playwright_sync_api.TimeoutError

BASE_URL = os.getenv("OIDC_TEST_CLIENT_URL", "http://localhost:3000").rstrip("/")
LOGIN_URL = f"{BASE_URL}/login"
USERNAME = "test@test.de"


def _service_reachable(url: str) -> bool:
    """Return True if URL is reachable in current environment."""
    try:
        with urlopen(url, timeout=3):
            return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def ensure_local_client() -> None:
    """Skip e2e tests when auth client service is not running."""
    if not _service_reachable(LOGIN_URL):
        pytest.skip(
            f"OIDC test client is not reachable at {LOGIN_URL}. "
            "Start local stack before running browser e2e tests.",
        )


@pytest.fixture()
def page():
    """Provide a fresh browser context per test for isolated auth state."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        tab = context.new_page()
        yield tab
        context.close()
        browser.close()


def _perform_login(tab, password: str) -> tuple[str, str]:
    """Open login page, submit credentials, and return current URL + body text."""
    tab.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
    tab.wait_for_selector(
        'input[placeholder="Email"], input[name="email"], input[type="email"]',
        timeout=15000,
    )
    tab.locator(
        'input[placeholder="Email"], input[name="email"], input[type="email"]'
    ).first.fill(USERNAME)
    tab.locator(
        'input[placeholder="Password"], input[name="password"], input[type="password"]'
    ).first.fill(password)
    tab.locator('button[type="submit"], button:has-text("Login")').first.click()

    # Some responses are redirect-heavy; tolerate slow network idle.
    try:
        tab.wait_for_load_state("networkidle", timeout=10000)
    except TimeoutError:
        pass

    body = tab.inner_text("body")
    return tab.url, body


@pytest.mark.e2e
def test_rejects_invalid_password(ensure_local_client, page) -> None:
    """Invalid credentials should keep user on login with clear error."""
    url, body = _perform_login(page, password="ass")

    assert "/login" in url
    assert "Invalid credentials" in body


@pytest.mark.e2e
def test_accepts_valid_password_and_returns_tokens(ensure_local_client, page) -> None:
    """Valid credentials should complete code flow and populate session info."""
    url, body = _perform_login(page, password="PWD")

    assert url.rstrip("/") == BASE_URL
    assert "Logged in as: test@test.de" in body
    assert "access_token" in body
    assert "State mismatch" not in body
