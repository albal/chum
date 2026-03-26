"""
Tests for chum.core.store
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from chum.core.certificate import CertificateInfo, CertificateStatus
from chum.core.store import CertificateStore


def _make_info(
    cn: str,
    days_left: int = 60,
    status: CertificateStatus = CertificateStatus.ACTIVE,
) -> CertificateInfo:
    now = datetime.datetime.now(datetime.timezone.utc)
    return CertificateInfo(
        common_name=cn,
        sans=[cn],
        serial="deadbeef",
        not_before=now - datetime.timedelta(days=1),
        not_after=now + datetime.timedelta(days=days_left),
        fingerprint_sha256="aabbcc",
        status=status,
    )


def test_store_save_and_get(tmp_path):
    store_path = tmp_path / "store.json"
    store = CertificateStore(store_path)
    info = _make_info("*.example.com")
    store.save(info)

    loaded = store.get("*.example.com")
    assert loaded is not None
    assert loaded.common_name == "*.example.com"
    assert loaded.serial == "deadbeef"


def test_store_persists_to_disk(tmp_path):
    store_path = tmp_path / "store.json"
    store = CertificateStore(store_path)
    store.save(_make_info("*.persist.test"))

    # Re-open from disk
    store2 = CertificateStore(store_path)
    loaded = store2.get("*.persist.test")
    assert loaded is not None


def test_store_list(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    store.save(_make_info("*.a.com"))
    store.save(_make_info("*.b.com"))
    records = store.list()
    cns = {r.common_name for r in records}
    assert "*.a.com" in cns
    assert "*.b.com" in cns


def test_store_delete(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    store.save(_make_info("*.delete.me"))
    assert store.get("*.delete.me") is not None

    result = store.delete("*.delete.me")
    assert result is True
    assert store.get("*.delete.me") is None


def test_store_delete_nonexistent(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    assert store.delete("nonexistent") is False


def test_store_get_missing(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    assert store.get("*.nothere.com") is None


def test_store_expiring_soon(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    store.save(_make_info("*.expiring.soon", days_left=10))
    store.save(_make_info("*.fine.cert", days_left=90))

    expiring = store.expiring_soon(days=30)
    cns = {r.common_name for r in expiring}
    assert "*.expiring.soon" in cns
    assert "*.fine.cert" not in cns


def test_store_overwrites_existing(tmp_path):
    store = CertificateStore(tmp_path / "store.json")
    info1 = _make_info("*.overwrite.com", days_left=60)
    info1.serial = "old_serial"
    store.save(info1)

    info2 = _make_info("*.overwrite.com", days_left=90)
    info2.serial = "new_serial"
    store.save(info2)

    loaded = store.get("*.overwrite.com")
    assert loaded.serial == "new_serial"


def test_store_empty_on_first_create(tmp_path):
    store = CertificateStore(tmp_path / "fresh.json")
    assert store.list() == []


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


def test_store_handles_pending_certificate(tmp_path):
    """Test store handles certificate without not_after (pending)."""
    store = CertificateStore(tmp_path / "store.json")
    info = CertificateInfo(
        common_name="*.pending.com",
        sans=["*.pending.com"],
        status=CertificateStatus.PENDING,
    )
    store.save(info)

    loaded = store.get("*.pending.com")
    assert loaded is not None
    assert loaded.status == CertificateStatus.PENDING
    assert loaded.days_remaining is None


def test_store_expiring_soon_skips_pending(tmp_path):
    """Test expiring_soon skips certificates without not_after."""
    store = CertificateStore(tmp_path / "store.json")

    # Add pending cert (no not_after)
    pending = CertificateInfo(
        common_name="*.pending.com",
        sans=["*.pending.com"],
        status=CertificateStatus.PENDING,
    )
    store.save(pending)

    # Add expiring cert
    store.save(_make_info("*.expiring.com", days_left=5))

    expiring = store.expiring_soon(days=30)
    cns = {r.common_name for r in expiring}
    assert "*.expiring.com" in cns
    assert "*.pending.com" not in cns


def test_store_preserves_revoked_status(tmp_path):
    """Test that revoked status is preserved after reload."""
    store_path = tmp_path / "store.json"
    store = CertificateStore(store_path)

    info = _make_info("*.revoked.com", days_left=60)
    info.status = CertificateStatus.REVOKED
    store.save(info)

    # Re-open store from disk
    store2 = CertificateStore(store_path)
    loaded = store2.get("*.revoked.com")
    assert loaded is not None
    assert loaded.status == CertificateStatus.REVOKED


def test_store_handles_expired_certificate(tmp_path):
    """Test store correctly handles expired certificates."""
    store = CertificateStore(tmp_path / "store.json")

    # Create an expired certificate
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="*.expired.com",
        sans=["*.expired.com"],
        serial="expired123",
        not_before=now - datetime.timedelta(days=100),
        not_after=now - datetime.timedelta(days=10),
        status=CertificateStatus.ACTIVE,
    )
    store.save(info)

    loaded = store.get("*.expired.com")
    assert loaded is not None
    # Status should be refreshed to EXPIRED
    assert loaded.status == CertificateStatus.EXPIRED
    assert loaded.days_remaining == 0


def test_store_all_fields_persist(tmp_path):
    """Test all certificate fields persist correctly."""
    store_path = tmp_path / "store.json"
    store = CertificateStore(store_path)

    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="*.full.com",
        sans=["*.full.com", "full.com", "192.168.1.1"],
        serial="abc123def456",
        not_before=now - datetime.timedelta(days=10),
        not_after=now + datetime.timedelta(days=80),
        fingerprint_sha256="1234567890abcdef",
        status=CertificateStatus.ACTIVE,
        cert_path=Path("/path/to/cert.crt"),
        key_path=Path("/path/to/key.key"),
        chain_path=Path("/path/to/chain.pem"),
    )
    store.save(info)

    # Re-open and verify all fields
    store2 = CertificateStore(store_path)
    loaded = store2.get("*.full.com")

    assert loaded.common_name == "*.full.com"
    assert loaded.sans == ["*.full.com", "full.com", "192.168.1.1"]
    assert loaded.serial == "abc123def456"
    assert loaded.fingerprint_sha256 == "1234567890abcdef"
    assert loaded.cert_path == Path("/path/to/cert.crt")
    assert loaded.key_path == Path("/path/to/key.key")
    assert loaded.chain_path == Path("/path/to/chain.pem")

