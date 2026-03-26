"""
ACME client wrapper for obtaining wildcard certificates via Let's Encrypt
(or any RFC 8555-compatible CA) using the DNS-01 or DNS-PERSIST-01 challenge.

This module wraps the ``acme`` and ``josepy`` libraries and provides a
thin, testable interface for the rest of Chum.  DNS challenge hooks are
delegated to a user-supplied callable so that any DNS provider can be
integrated.

**DNS-01 Challenge** (Traditional):
    Requires creating a new TXT record ``_acme-challenge.<domain>`` for each
    certificate issuance/renewal. The record is deleted after validation.

**DNS-PERSIST-01 Challenge** (New):
    Creates a long-lasting TXT record at ``_validation-persist.<domain>`` that
    authorizes a specific ACME account to issue certificates indefinitely.
    No DNS changes are needed for renewals. See:
    https://letsencrypt.org/2026/02/18/dns-persist-01.html

Usage example (DNS-01)::

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

Usage example (DNS-PERSIST-01)::

    from chum.core.acme import AcmeClient

    client = AcmeClient(
        email="admin@example.com",
        directory_url="https://acme-v02.api.letsencrypt.org/directory",
    )
    account_key_pem = client.register()

    # Generate and display the persistent DNS record (one-time setup)
    record = client.generate_persist_record(
        domain="example.com",
        policy="wildcard",  # optional: "wildcard" or "subdomain"
        persist_until="2027-12-01T00:00:00Z",  # optional expiry
    )
    print(f"Create TXT record: {record['fqdn']} = {record['value']}")

    # After creating the DNS record, obtain certificates without DNS hooks
    cert_pem, chain_pem, key_pem = client.obtain_wildcard_persist(
        domain="example.com",
    )
"""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


class ChallengeType(Enum):
    """ACME challenge types supported by Chum."""

    DNS_01 = "dns-01"
    DNS_PERSIST_01 = "dns-persist-01"

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
    # DNS-PERSIST-01 Support
    # ------------------------------------------------------------------

    @property
    def account_uri(self) -> Optional[str]:
        """
        Return the ACME account URI, if registered.

        This URI is needed for the DNS-PERSIST-01 TXT record.
        """
        if self._acme_client is None:
            return None
        # The account URI is stored in the client after registration
        try:
            return self._acme_client.net.account.uri
        except AttributeError:
            return None

    def generate_persist_record(
        self,
        domain: str,
        policy: Optional[str] = None,
        persist_until: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generate the DNS TXT record value for DNS-PERSIST-01 authorization.

        This is a one-time setup step. After creating this DNS record, you can
        use :meth:`obtain_wildcard_persist` for all future certificate issuances
        and renewals without needing to update DNS.

        Parameters
        ----------
        domain:
            The domain to authorize, e.g. ``"example.com"``.
        policy:
            Optional authorization policy. Supported values:

            - ``None`` (default): Only the exact domain is authorized.
            - ``"wildcard"``: Authorizes wildcard certificates (``*.domain``).
            - ``"subdomain"``: Authorizes any subdomain certificates.
        persist_until:
            Optional ISO 8601 timestamp for when the authorization expires,
            e.g. ``"2027-12-01T00:00:00Z"``. If not set, the authorization
            persists indefinitely (until the DNS record is removed).

        Returns
        -------
        dict with keys:
            - ``fqdn``: The fully qualified domain name for the TXT record
              (e.g., ``_validation-persist.example.com``)
            - ``value``: The TXT record value to set
            - ``issuer_domain``: The CA issuer domain (e.g., ``letsencrypt.org``)
            - ``account_uri``: The ACME account URI
            - ``policy``: The policy string, if provided
            - ``persist_until``: The expiry timestamp, if provided

        Raises
        ------
        AcmeError
            If the client has not been registered yet.

        Example
        -------
        ::

            client = AcmeClient(email="admin@example.com")
            client.register()
            record = client.generate_persist_record(
                "example.com",
                policy="wildcard",
                persist_until="2027-12-01T00:00:00Z",
            )
            # Create this TXT record in your DNS provider:
            # _validation-persist.example.com TXT "letsencrypt.org; accounturi=https://..."
        """
        if self._acme_client is None:
            raise AcmeError("Call register() before generate_persist_record()")

        account_uri = self.account_uri
        if not account_uri:
            raise AcmeError("Account URI not available. Registration may have failed.")

        # Determine the issuer domain from the directory URL
        import urllib.parse

        parsed = urllib.parse.urlparse(self._directory_url)
        issuer_domain = parsed.netloc

        # Build the TXT record value
        # Format: "issuer-domain; accounturi=<account-uri>[; policy=<policy>][; persistUntil=<timestamp>]"
        parts = [issuer_domain, f"accounturi={account_uri}"]

        if policy:
            if policy not in ("wildcard", "subdomain"):
                raise AcmeError(f"Invalid policy: {policy}. Must be 'wildcard' or 'subdomain'.")
            parts.append(f"policy={policy}")

        if persist_until:
            parts.append(f"persistUntil={persist_until}")

        txt_value = "; ".join(parts)
        fqdn = f"_validation-persist.{domain}"

        result = {
            "fqdn": fqdn,
            "value": txt_value,
            "issuer_domain": issuer_domain,
            "account_uri": account_uri,
        }
        if policy:
            result["policy"] = policy
        if persist_until:
            result["persist_until"] = persist_until

        return result

    def obtain_wildcard_persist(
        self,
        domain: str,
        poll_interval: float = 5.0,
        poll_timeout: float = 120.0,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Obtain a wildcard certificate using DNS-PERSIST-01 challenge.

        This method assumes you have already created a persistent DNS TXT record
        at ``_validation-persist.<domain>`` using :meth:`generate_persist_record`.
        No DNS hooks are required as the CA will verify the existing record.

        Parameters
        ----------
        domain:
            The bare domain, e.g. ``"example.com"``.
        poll_interval:
            Seconds between challenge status polls.
        poll_timeout:
            Maximum seconds to wait for challenge validation.

        Returns
        -------
        tuple of (cert_pem, chain_pem, key_pem)

        Raises
        ------
        AcmeError
            If registration has not been performed, or if the DNS-PERSIST-01
            challenge is not available or fails validation.

        Notes
        -----
        The DNS-PERSIST-01 challenge type must be supported by the CA. As of
        2026, Let's Encrypt supports this challenge type. If the CA does not
        support it, this method will raise an error and you should use the
        traditional :meth:`obtain_wildcard` with DNS-01 instead.
        """
        if self._acme_client is None:
            raise AcmeError("Call register() before obtain_wildcard_persist()")

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

        for authz in authzs:
            # Look for DNS-PERSIST-01 challenge
            dns_persist = self._get_dns_persist_challenge(authz)
            if dns_persist is None:
                # Fall back to checking if it's already valid (pre-authorized)
                if authz.body.status == messages.STATUS_VALID:
                    log.info(
                        "Authorization already valid for %s (DNS-PERSIST-01 record verified)",
                        authz.body.identifier.value,
                    )
                    continue
                raise AcmeError(
                    f"DNS-PERSIST-01 challenge not available for {authz.body.identifier.value}. "
                    "Ensure the CA supports DNS-PERSIST-01 or use obtain_wildcard() with DNS-01."
                )

            log.info(
                "Answering DNS-PERSIST-01 challenge for %s",
                authz.body.identifier.value,
            )
            # Answer the challenge - CA will verify the existing _validation-persist TXT record
            self._acme_client.answer_challenge(
                dns_persist, dns_persist.chall.response(self._account_key)
            )

        order = self._poll_order(order, poll_interval, poll_timeout)
        finalized = self._acme_client.finalize_order(
            order,
            deadline=__import__("datetime").datetime.now()
            + __import__("datetime").timedelta(seconds=poll_timeout),
        )

        cert_pem = (
            finalized.fullchain_pem.encode()
            if isinstance(finalized.fullchain_pem, str)
            else finalized.fullchain_pem
        )
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

    def _get_dns_persist_challenge(self, authz: messages.AuthorizationResource):
        """
        Find the DNS-PERSIST-01 challenge in an authorization, if available.

        Returns the challenge body, or None if DNS-PERSIST-01 is not offered.
        The DNS-PERSIST-01 challenge type identifier is "dns-persist-01".
        """
        for challenge_body in authz.body.challenges:
            # DNS-PERSIST-01 may not have a dedicated class in the acme library yet,
            # so we check the challenge type string.
            chall_type = getattr(challenge_body.chall, "typ", None)
            if chall_type == "dns-persist-01":
                return challenge_body
            # Also check the challenge class name as a fallback
            if hasattr(challenge_body.chall, "__class__"):
                class_name = challenge_body.chall.__class__.__name__
                if "DNSPersist" in class_name or "dns_persist" in class_name.lower():
                    return challenge_body
        return None

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
