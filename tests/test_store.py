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
