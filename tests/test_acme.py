"""
Tests for chum.core.acme module.

These tests cover both DNS-01 and DNS-PERSIST-01 challenge types.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# Import guards - acme/josepy may not be installed
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_acme_available():
    """Mock the ACME library as available."""
    with patch.dict("sys.modules", {
        "josepy": MagicMock(),
        "acme": MagicMock(),
        "acme.challenges": MagicMock(),
        "acme.client": MagicMock(),
        "acme.crypto_util": MagicMock(),
        "acme.errors": MagicMock(),
        "acme.messages": MagicMock(),
    }):
        yield


# ---------------------------------------------------------------------------
# ChallengeType enum tests
# ---------------------------------------------------------------------------


def test_challenge_type_values():
    """Test ChallengeType enum values."""
    from chum.core.acme import ChallengeType

    assert ChallengeType.DNS_01.value == "dns-01"
    assert ChallengeType.DNS_PERSIST_01.value == "dns-persist-01"


def test_challenge_type_enum_members():
    """Test that ChallengeType has expected members."""
    from chum.core.acme import ChallengeType

    assert hasattr(ChallengeType, "DNS_01")
    assert hasattr(ChallengeType, "DNS_PERSIST_01")


# ---------------------------------------------------------------------------
# AcmeClient initialization tests
# ---------------------------------------------------------------------------


def test_acme_client_raises_without_dependencies():
    """Test that AcmeClient raises if acme/josepy not installed."""
    from chum.core import acme

    # Temporarily pretend ACME is not available
    original = acme._ACME_AVAILABLE
    acme._ACME_AVAILABLE = False
    try:
        with pytest.raises(acme.AcmeError) as exc_info:
            acme.AcmeClient(email="test@example.com")
        assert "acme" in str(exc_info.value).lower()
    finally:
        acme._ACME_AVAILABLE = original


def test_acme_client_staging_flag():
    """Test that staging flag sets correct directory URL."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com", staging=True)
    assert "staging" in client._directory_url


def test_acme_client_custom_directory():
    """Test that custom directory URL is used."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    custom_url = "https://custom-acme.example.com/directory"
    client = acme.AcmeClient(email="test@example.com", directory_url=custom_url)
    assert client._directory_url == custom_url


# ---------------------------------------------------------------------------
# generate_persist_record tests
# ---------------------------------------------------------------------------


def test_generate_persist_record_requires_registration():
    """Test that generate_persist_record raises if not registered."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")
    with pytest.raises(acme.AcmeError) as exc_info:
        client.generate_persist_record("example.com")
    assert "register" in str(exc_info.value).lower()


def test_generate_persist_record_basic():
    """Test basic generate_persist_record output."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    # Mock the registration state
    mock_acme_client = MagicMock()
    mock_acme_client.net.account.uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    client._acme_client = mock_acme_client
    client._account_key = MagicMock()

    record = client.generate_persist_record("example.com")

    assert record["fqdn"] == "_validation-persist.example.com"
    assert "acme-v02.api.letsencrypt.org" in record["value"]
    assert "accounturi=" in record["value"]
    assert record["account_uri"] == mock_acme_client.net.account.uri


def test_generate_persist_record_with_policy():
    """Test generate_persist_record with policy parameter."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    mock_acme_client = MagicMock()
    mock_acme_client.net.account.uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    client._acme_client = mock_acme_client
    client._account_key = MagicMock()

    record = client.generate_persist_record("example.com", policy="wildcard")

    assert "policy=wildcard" in record["value"]
    assert record["policy"] == "wildcard"


def test_generate_persist_record_with_persist_until():
    """Test generate_persist_record with persist_until parameter."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    mock_acme_client = MagicMock()
    mock_acme_client.net.account.uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    client._acme_client = mock_acme_client
    client._account_key = MagicMock()

    persist_until = "2027-12-01T00:00:00Z"
    record = client.generate_persist_record("example.com", persist_until=persist_until)

    assert f"persistUntil={persist_until}" in record["value"]
    assert record["persist_until"] == persist_until


def test_generate_persist_record_with_all_options():
    """Test generate_persist_record with all optional parameters."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    mock_acme_client = MagicMock()
    mock_acme_client.net.account.uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    client._acme_client = mock_acme_client
    client._account_key = MagicMock()

    persist_until = "2027-12-01T00:00:00Z"
    record = client.generate_persist_record(
        "example.com",
        policy="subdomain",
        persist_until=persist_until,
    )

    assert record["fqdn"] == "_validation-persist.example.com"
    assert "policy=subdomain" in record["value"]
    assert f"persistUntil={persist_until}" in record["value"]
    assert record["policy"] == "subdomain"
    assert record["persist_until"] == persist_until


def test_generate_persist_record_invalid_policy():
    """Test that invalid policy raises error."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    mock_acme_client = MagicMock()
    mock_acme_client.net.account.uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    client._acme_client = mock_acme_client
    client._account_key = MagicMock()

    with pytest.raises(acme.AcmeError) as exc_info:
        client.generate_persist_record("example.com", policy="invalid")
    assert "invalid" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# account_uri property tests
# ---------------------------------------------------------------------------


def test_account_uri_before_registration():
    """Test account_uri returns None before registration."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")
    assert client.account_uri is None


def test_account_uri_after_registration():
    """Test account_uri returns correct value after registration."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")

    mock_acme_client = MagicMock()
    expected_uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
    mock_acme_client.net.account.uri = expected_uri
    client._acme_client = mock_acme_client

    assert client.account_uri == expected_uri


# ---------------------------------------------------------------------------
# obtain_wildcard_persist tests
# ---------------------------------------------------------------------------


def test_obtain_wildcard_persist_requires_registration():
    """Test that obtain_wildcard_persist raises if not registered."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")
    with pytest.raises(acme.AcmeError) as exc_info:
        client.obtain_wildcard_persist("example.com")
    assert "register" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# _get_dns_persist_challenge helper tests
# ---------------------------------------------------------------------------


def test_get_dns_persist_challenge_found():
    """Test _get_dns_persist_challenge finds dns-persist-01 challenge."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")
    client._acme_client = MagicMock()

    # Create a mock authorization with dns-persist-01 challenge
    mock_chall = MagicMock()
    mock_chall.typ = "dns-persist-01"

    mock_challenge_body = MagicMock()
    mock_challenge_body.chall = mock_chall

    mock_authz = MagicMock()
    mock_authz.body.challenges = [mock_challenge_body]

    result = client._get_dns_persist_challenge(mock_authz)
    assert result == mock_challenge_body


def test_get_dns_persist_challenge_not_found():
    """Test _get_dns_persist_challenge returns None when not available."""
    from chum.core import acme

    if not acme._ACME_AVAILABLE:
        pytest.skip("acme/josepy not installed")

    client = acme.AcmeClient(email="test@example.com")
    client._acme_client = MagicMock()

    # Create a mock authorization with only dns-01 challenge
    mock_chall = MagicMock()
    mock_chall.typ = "dns-01"

    mock_challenge_body = MagicMock()
    mock_challenge_body.chall = mock_chall

    mock_authz = MagicMock()
    mock_authz.body.challenges = [mock_challenge_body]

    result = client._get_dns_persist_challenge(mock_authz)
    assert result is None


# ---------------------------------------------------------------------------
# Staging URL tests
# ---------------------------------------------------------------------------


def test_staging_url_constant():
    """Test that staging URL is correct."""
    from chum.core.acme import _LE_STAGING

    assert "staging" in _LE_STAGING
    assert "letsencrypt" in _LE_STAGING


def test_production_url_constant():
    """Test that production URL is correct."""
    from chum.core.acme import _LE_PROD

    assert "staging" not in _LE_PROD
    assert "letsencrypt" in _LE_PROD
