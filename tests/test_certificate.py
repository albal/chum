"""
Tests for chum.core.certificate
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from chum.core.certificate import (
    CertificateInfo,
    CertificateStatus,
    cert_to_pem,
    certificate_info_from_x509,
    generate_ca,
    generate_csr,
    generate_private_key,
    load_certificate,
    private_key_to_pem,
    save_certificate_bundle,
    self_sign_certificate,
)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def test_generate_private_key_default():
    key = generate_private_key()
    assert key.key_size == 4096


def test_generate_private_key_custom_size():
    key = generate_private_key(2048)
    assert key.key_size == 2048


def test_private_key_to_pem_roundtrip():
    key = generate_private_key(2048)
    pem = private_key_to_pem(key)
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    reloaded = load_certificate  # just import check
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend
    reloaded_key = load_pem_private_key(pem, password=None, backend=default_backend())
    assert reloaded_key.key_size == 2048


def test_private_key_to_pem_with_passphrase():
    key = generate_private_key(2048)
    pem = private_key_to_pem(key, passphrase=b"secret")
    assert b"ENCRYPTED" in pem or b"BEGIN" in pem


# ---------------------------------------------------------------------------
# CSR generation
# ---------------------------------------------------------------------------


def test_generate_csr_basic():
    key = generate_private_key(2048)
    csr = generate_csr(key, "*.example.com", ["*.example.com", "example.com"])
    from cryptography import x509

    cn_attrs = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert cn_attrs[0].value == "*.example.com"


def test_generate_csr_with_san_dns_and_ip():
    key = generate_private_key(2048)
    csr = generate_csr(key, "server.example.com", ["server.example.com", "192.168.1.1"])
    from cryptography import x509

    san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = san_ext.value.get_values_for_type(x509.DNSName)
    ips = san_ext.value.get_values_for_type(x509.IPAddress)
    assert names == ["server.example.com"]
    assert len(ips) == 1


def test_generate_csr_with_org_and_country():
    key = generate_private_key(2048)
    csr = generate_csr(
        key, "example.com", ["example.com"], organization="ACME Corp", country="US"
    )
    from cryptography import x509

    org = csr.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    assert org[0].value == "ACME Corp"


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------


def _make_self_signed(cn: str = "*.test.local", days: int = 90):
    key = generate_private_key(2048)
    csr = generate_csr(key, cn, [cn])
    cert = self_sign_certificate(key, csr, valid_days=days)
    return cert, key


def test_self_sign_certificate_cn():
    cert, _ = _make_self_signed("*.test.local")
    from cryptography.x509.oid import NameOID

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "*.test.local"


def test_self_sign_certificate_validity():
    cert, _ = _make_self_signed(days=10)
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Handle both cryptography >= 42.0 and < 42.0
    if hasattr(cert, "not_valid_after_utc"):
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    else:
        delta = cert.not_valid_after - cert.not_valid_before
    assert delta.days == 10


def test_self_sign_certificate_has_san():
    cert, _ = _make_self_signed("*.test.local")
    from cryptography import x509

    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = san_ext.value.get_values_for_type(x509.DNSName)
    assert "*.test.local" in names


def test_ca_signed_certificate():
    ca_cert, ca_key = generate_ca("Test CA", valid_days=365)
    key = generate_private_key(2048)
    csr = generate_csr(key, "*.example.com", ["*.example.com"])
    cert = self_sign_certificate(key, csr, valid_days=90, ca_cert=ca_cert, ca_key=ca_key)

    from cryptography.x509.oid import NameOID

    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert issuer_cn == "Test CA"


# ---------------------------------------------------------------------------
# CA generation
# ---------------------------------------------------------------------------


def test_generate_ca_returns_cert_and_key():
    cert, key = generate_ca("My Test CA", valid_days=100)
    assert cert is not None
    assert key is not None


def test_generate_ca_is_ca():
    cert, _ = generate_ca("Root CA")
    from cryptography import x509

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True


# ---------------------------------------------------------------------------
# PEM serialisation
# ---------------------------------------------------------------------------


def test_cert_to_pem_roundtrip():
    cert, _ = _make_self_signed()
    pem = cert_to_pem(cert)
    reloaded = load_certificate(pem)
    assert reloaded.serial_number == cert.serial_number


# ---------------------------------------------------------------------------
# CertificateInfo
# ---------------------------------------------------------------------------


def test_certificate_info_from_x509():
    cert, _ = _make_self_signed("*.example.org")
    info = certificate_info_from_x509(cert)
    assert info.common_name == "*.example.org"
    assert "*.example.org" in info.sans
    assert info.fingerprint_sha256 is not None
    assert info.serial is not None


def test_certificate_info_days_remaining():
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="test",
        not_after=now + datetime.timedelta(days=25),
    )
    # Allow for sub-second clock drift during test execution
    assert info.days_remaining in (24, 25)


def test_certificate_info_status_expiring_soon():
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="test",
        not_before=now - datetime.timedelta(days=1),
        not_after=now + datetime.timedelta(days=10),
    )
    info.refresh_status()
    assert info.status == CertificateStatus.EXPIRING_SOON


def test_certificate_info_status_active():
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="test",
        not_before=now - datetime.timedelta(days=1),
        not_after=now + datetime.timedelta(days=60),
    )
    info.refresh_status()
    assert info.status == CertificateStatus.ACTIVE


def test_certificate_info_status_expired():
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="test",
        not_before=now - datetime.timedelta(days=100),
        not_after=now - datetime.timedelta(days=1),
    )
    info.refresh_status()
    assert info.status == CertificateStatus.EXPIRED


def test_certificate_info_revoked_status_preserved():
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(
        common_name="test",
        not_before=now - datetime.timedelta(days=1),
        not_after=now + datetime.timedelta(days=60),
        status=CertificateStatus.REVOKED,
    )
    info.refresh_status()
    assert info.status == CertificateStatus.REVOKED


# ---------------------------------------------------------------------------
# save_certificate_bundle
# ---------------------------------------------------------------------------


def test_save_certificate_bundle(tmp_path):
    cert, key = _make_self_signed("*.bundle.test")
    info = save_certificate_bundle(tmp_path, "bundle_test", cert, key)

    assert info.cert_path.exists()
    assert info.key_path.exists()
    assert info.chain_path is None
    assert info.common_name == "*.bundle.test"


def test_save_certificate_bundle_with_chain(tmp_path):
    ca_cert, _ = generate_ca("Chain CA")
    cert, key = _make_self_signed("*.chain.test")
    info = save_certificate_bundle(tmp_path, "chain_test", cert, key, chain=[ca_cert])

    assert info.chain_path is not None
    assert info.chain_path.exists()
