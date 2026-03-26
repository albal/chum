"""
ACME client wrapper for obtaining wildcard certificates via Let's Encrypt
(or any RFC 8555-compatible CA) using the DNS-01 challenge.

This module wraps the ``acme`` and ``josepy`` libraries and provides a
thin, testable interface for the rest of Chum.  DNS challenge hooks are
delegated to a user-supplied callable so that any DNS provider can be
integrated.

Usage example::

    from chum.core.acme import AcmeClient

    def set_txt(domain, value):
        # add _acme-challenge.<domain> TXT record = value
        ...

    def del_txt(domain, value):
        # remove the TXT record
        ...

    client = AcmeClient(
        email="admin@example.com",
        directory_url="https://acme-v02.api.letsencrypt.org/directory",
    )
    client.register()
    cert_pem, chain_pem, key_pem = client.obtain_wildcard(
        domain="example.com",
        dns_set_hook=set_txt,
        dns_del_hook=del_txt,
    )
"""

from __future__ import annotations

import logging
import time
from typing import Callable, List, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional runtime dependency guard – acme/josepy are large packages; we
# import them lazily so that the rest of Chum works without them.
# ---------------------------------------------------------------------------
try:
    import josepy as jose  # type: ignore
    from acme import challenges, client, crypto_util, errors, messages  # type: ignore
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    _ACME_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ACME_AVAILABLE = False


_LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
_LE_PROD = "https://acme-v02.api.letsencrypt.org/directory"


class AcmeError(Exception):
    """Raised when an ACME operation fails."""


class AcmeClient:
    """
    Thin ACME v2 client focused on DNS-01 wildcard certificate issuance.

    Parameters
    ----------
    email:
        Contact e-mail address registered with the ACME CA.
    directory_url:
        URL of the ACME directory endpoint.  Defaults to the
        Let's Encrypt v2 production endpoint.
    account_key_pem:
        PEM bytes of an existing ACME account key.  When omitted a new
        2048-bit RSA key is generated on first :meth:`register`.
    staging:
        Convenience flag; when ``True`` the Let's Encrypt *staging*
        directory is used regardless of *directory_url*.
    """

    def __init__(
        self,
        email: str,
        directory_url: str = _LE_PROD,
        account_key_pem: Optional[bytes] = None,
        staging: bool = False,
    ) -> None:
        if not _ACME_AVAILABLE:
            raise AcmeError(
                "The 'acme' and 'josepy' packages are required for ACME support. "
                "Install them with: pip install acme josepy"
            )
        self._email = email
        self._directory_url = _LE_STAGING if staging else directory_url
        self._account_key_pem = account_key_pem
        self._acme_client: Optional[client.ClientV2] = None
        self._account_key: Optional[jose.JWKRSA] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self) -> bytes:
        """
        Register (or recover) an ACME account and return the account key PEM.
        """
        self._account_key = self._load_or_create_account_key()
        net = client.ClientNetwork(self._account_key, user_agent="chum/0.1")
        directory = messages.Directory.from_json(
            net.get(self._directory_url).json()
        )
        self._acme_client = client.ClientV2(directory, net=net)
        registration = messages.NewRegistration.from_data(
            email=self._email, terms_of_service_agreed=True
        )
        try:
            self._acme_client.new_account(registration)
            log.info("ACME account registered for %s", self._email)
        except errors.ConflictError:
            log.info("ACME account already exists for %s", self._email)

        return self._account_key.key.private_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
            format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
        )

    def obtain_wildcard(
        self,
        domain: str,
        dns_set_hook: Callable[[str, str], None],
        dns_del_hook: Callable[[str, str], None],
        poll_interval: float = 5.0,
        poll_timeout: float = 120.0,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Obtain a wildcard certificate for ``*.domain`` (and ``domain``).

        Parameters
        ----------
        domain:
            The bare domain, e.g. ``"example.com"``.
        dns_set_hook:
            Callable ``(fqdn, txt_value)`` that creates the DNS TXT record
            ``_acme-challenge.<fqdn>`` with the given value.
        dns_del_hook:
            Callable ``(fqdn, txt_value)`` that removes the DNS TXT record.
        poll_interval:
            Seconds between challenge status polls.
        poll_timeout:
            Maximum seconds to wait for challenge validation.

        Returns
        -------
        tuple of (cert_pem, chain_pem, key_pem)
        """
        if self._acme_client is None:
            raise AcmeError("Call register() before obtain_wildcard()")

        wildcard = f"*.{domain}"
        # Generate a new certificate key and CSR
        cert_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        csr_pem = crypto_util.make_csr(
            cert_key.private_bytes(
                encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
                format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
            ),
            [wildcard, domain],
        )

        order = self._acme_client.new_order(csr_pem)
        authzs = order.authorizations

        txt_records: List[Tuple[str, str]] = []
        try:
            for authz in authzs:
                dns01 = self._get_dns_challenge(authz)
                validation = self._acme_client.client.net.key.thumbprint(
                    hash_function=jose.SHA256
                )
                token = jose.b64encode(dns01.chall.token).decode()
                txt_value = f"{token}.{validation.decode()}"
                fqdn = f"_acme-challenge.{authz.body.identifier.value}"
                log.info("Setting DNS TXT record: %s = %s", fqdn, txt_value)
                dns_set_hook(fqdn, txt_value)
                txt_records.append((fqdn, txt_value))
                self._acme_client.answer_challenge(dns01, dns01.chall.response(self._account_key))

            order = self._poll_order(order, poll_interval, poll_timeout)
            finalized = self._acme_client.finalize_order(
                order, deadline=__import__("datetime").datetime.now() + __import__("datetime").timedelta(seconds=poll_timeout)
            )
        finally:
            for fqdn, txt_value in txt_records:
                try:
                    dns_del_hook(fqdn, txt_value)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Failed to clean up DNS record %s: %s", fqdn, exc)

        cert_pem = finalized.fullchain_pem.encode() if isinstance(finalized.fullchain_pem, str) else finalized.fullchain_pem
        key_pem = cert_key.private_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
            format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
        )
        # Split fullchain into leaf cert + chain
        pem_parts = self._split_pem_chain(cert_pem)
        leaf_pem = pem_parts[0] if pem_parts else cert_pem
        chain_pem = b"".join(pem_parts[1:]) if len(pem_parts) > 1 else b""
        return leaf_pem, chain_pem, key_pem

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_or_create_account_key(self) -> jose.JWKRSA:
        if self._account_key_pem:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            private_key = load_pem_private_key(self._account_key_pem, password=None, backend=default_backend())
            return jose.JWKRSA(key=private_key)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return jose.JWKRSA(key=private_key)

    def _get_dns_challenge(self, authz: messages.AuthorizationResource):
        for challenge_body in authz.body.challenges:
            if isinstance(challenge_body.chall, challenges.DNS01):
                return challenge_body
        raise AcmeError(f"No DNS-01 challenge found for {authz.body.identifier.value}")

    def _poll_order(self, order, interval: float, timeout: float):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            order, _ = self._acme_client.poll(order)
            if order.body.status == messages.STATUS_VALID:
                return order
            if order.body.status == messages.STATUS_INVALID:
                raise AcmeError(f"Order validation failed: {order.body.error}")
            time.sleep(interval)
        raise AcmeError(f"Order validation timed out after {timeout}s")

    @staticmethod
    def _split_pem_chain(pem_data: bytes) -> List[bytes]:
        """Split a PEM chain into individual certificate PEM blocks."""
        import re
        pattern = re.compile(
            rb"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?)",
            re.DOTALL,
        )
        return pattern.findall(pem_data)
