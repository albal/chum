"""
Certificate lifecycle management.

Handles generation, renewal, revocation and status tracking of
wildcard TLS certificates.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertificateStatus(str, Enum):
    """Lifecycle state of a certificate."""

    PENDING = "pending"
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class CertificateInfo:
    """Metadata about a managed certificate."""

    common_name: str
    sans: List[str] = field(default_factory=list)
    serial: Optional[str] = None
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    fingerprint_sha256: Optional[str] = None
    status: CertificateStatus = CertificateStatus.PENDING
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None
    chain_path: Optional[Path] = None

    @property
    def days_remaining(self) -> Optional[int]:
        """Days until the certificate expires, or None if not yet issued."""
        if self.not_after is None:
            return None
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after_utc = self.not_after
        if not_after_utc.tzinfo is None:
            not_after_utc = not_after_utc.replace(tzinfo=datetime.timezone.utc)
        delta = not_after_utc - now
        return max(0, delta.days)

    def refresh_status(self, expiry_warning_days: int = 30) -> None:
        """Recompute ``status`` based on validity dates."""
        if self.status == CertificateStatus.REVOKED:
            return
        remaining = self.days_remaining
        if remaining is None:
            self.status = CertificateStatus.PENDING
        elif remaining == 0:
            self.status = CertificateStatus.EXPIRED
        elif remaining <= expiry_warning_days:
            self.status = CertificateStatus.EXPIRING_SOON
        else:
            self.status = CertificateStatus.ACTIVE


def generate_private_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def private_key_to_pem(key: rsa.RSAPrivateKey, passphrase: Optional[bytes] = None) -> bytes:
    """Serialise a private key to PEM, optionally encrypted."""
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )


def load_private_key(pem: bytes, passphrase: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(pem, password=passphrase, backend=default_backend())


def generate_csr(
    key: rsa.RSAPrivateKey,
    common_name: str,
    sans: Sequence[str],
    organization: str = "",
    country: str = "",
) -> x509.CertificateSigningRequest:
    """
    Build a Certificate Signing Request for ``common_name`` with the
    supplied Subject Alternative Names.

    SANs may be either DNS names (plain strings) or IP address strings
    (e.g. ``"192.168.1.1"``).
    """
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    san_values: List[Union[x509.DNSName, x509.IPAddress]] = []
    for san in sans:
        try:
            san_values.append(x509.IPAddress(ipaddress.ip_address(san)))
        except ValueError:
            san_values.append(x509.DNSName(san))

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(name_attrs))
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
    )
    return builder.sign(key, hashes.SHA256(), default_backend())


def self_sign_certificate(
    key: rsa.RSAPrivateKey,
    csr: x509.CertificateSigningRequest,
    valid_days: int = 90,
    ca_cert: Optional[x509.Certificate] = None,
    ca_key: Optional[rsa.RSAPrivateKey] = None,
) -> x509.Certificate:
    """
    Issue a certificate from *csr*.  When *ca_cert* and *ca_key* are
    provided the certificate is signed by that CA, otherwise a
    self-signed certificate is produced.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = ca_cert.subject if ca_cert else csr.subject
    signing_key = ca_key if ca_key else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
    )

    # Copy SANs from the CSR
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )

    return builder.sign(signing_key, hashes.SHA256(), default_backend())


def generate_ca(
    common_name: str = "Chum Internal CA",
    valid_days: int = 3650,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a self-signed CA certificate and return ``(cert, key)``."""
    key = generate_private_key(4096)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert, key


def _get_cert_not_before(cert: x509.Certificate) -> datetime.datetime:
    """Get certificate not_before time as UTC datetime (handles cryptography < 42.0)."""
    # cryptography >= 42.0 has not_valid_before_utc, older versions have not_valid_before
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    dt = cert.not_valid_before
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _get_cert_not_after(cert: x509.Certificate) -> datetime.datetime:
    """Get certificate not_after time as UTC datetime (handles cryptography < 42.0)."""
    # cryptography >= 42.0 has not_valid_after_utc, older versions have not_valid_after
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    dt = cert.not_valid_after
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def certificate_info_from_x509(cert: x509.Certificate, key_path: Optional[Path] = None) -> CertificateInfo:
    """Build a :class:`CertificateInfo` from a loaded x509 certificate object."""
    sans: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else ""

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial_hex = format(cert.serial_number, "x")

    info = CertificateInfo(
        common_name=common_name,
        sans=sans,
        serial=serial_hex,
        not_before=_get_cert_not_before(cert),
        not_after=_get_cert_not_after(cert),
        fingerprint_sha256=fingerprint,
        key_path=key_path,
    )
    info.refresh_status()
    return info


def load_certificate(pem: bytes) -> x509.Certificate:
    """Load an x509 certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(pem, default_backend())


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Serialise a certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def save_certificate_bundle(
    directory: Path,
    name: str,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
    chain: Optional[List[x509.Certificate]] = None,
    passphrase: Optional[bytes] = None,
) -> CertificateInfo:
    """
    Write *cert*, *key* and optional *chain* to *directory*/<name>.{crt,key,chain.crt}.
    Returns a populated :class:`CertificateInfo`.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"

    cert_path.write_bytes(cert_to_pem(cert))
    key_path.write_bytes(private_key_to_pem(key, passphrase))
    os.chmod(key_path, 0o600)

    chain_path: Optional[Path] = None
    if chain:
        chain_path = directory / f"{name}.chain.crt"
        chain_path.write_bytes(b"".join(cert_to_pem(c) for c in chain))

    info = certificate_info_from_x509(cert, key_path=key_path)
    info.cert_path = cert_path
    info.chain_path = chain_path
    return info
