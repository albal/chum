"""
HP Printer plugin.

Deploys TLS certificates to HP LaserJet / OfficeJet printers via their
embedded web server (EWS).  Most HP business-class printers expose a
certificate management page under ``/hp/device/security/certificates``
or a Redfish-compatible REST endpoint.

Connection parameters (passed as **kwargs to plugin methods):

host : str
    Hostname or IP address of the printer.
username : str, optional
    EWS administrator username (default ``"admin"``).
password : str
    EWS administrator password.
verify_ssl : bool, optional
    Verify the printer's TLS certificate (default ``False`` because the
    printer may use a self-signed cert before we deploy ours).
port : int, optional
    HTTPS port (default 443).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from chum.plugins.base import BasePlugin, DeployResult

log = logging.getLogger(__name__)


class HPPrinterPlugin(BasePlugin):
    """Certificate deployment plugin for HP network printers."""

    NAME = "hp_printer"
    DESCRIPTION = "Deploy certificates to HP LaserJet/OfficeJet printers via EWS"
    VERSION = "0.1.0"

    # ------------------------------------------------------------------
    # BasePlugin interface
    # ------------------------------------------------------------------

    def deploy(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None,
        **kwargs: Any,
    ) -> DeployResult:
        """Upload certificate + key to the HP EWS certificate store."""
        if requests is None:
            return DeployResult(
                success=False,
                message="The 'requests' package is required. Install with: pip install requests",
            )

        host = kwargs.get("host")
        if not host:
            return DeployResult(success=False, message="'host' parameter is required")

        username = kwargs.get("username", "admin")
        password = kwargs.get("password", "")
        port = int(kwargs.get("port", 443))
        verify_ssl = bool(kwargs.get("verify_ssl", False))

        base_url = f"https://{host}:{port}"
        session = requests.Session()
        session.verify = verify_ssl

        try:
            # Authenticate
            login_url = f"{base_url}/hp/device/SignIn/Index"
            session.post(
                login_url,
                data={"agentIdSelect": "hp_EWS_login_page", "UserId": username, "Pwd": password},
                timeout=15,
            )

            # Build multipart payload
            combined_pem = cert_pem
            if chain_pem:
                combined_pem = cert_pem + chain_pem

            files = {
                "cert": ("certificate.pem", combined_pem, "application/x-pem-file"),
                "key": ("private.key", key_pem, "application/x-pem-file"),
            }
            upload_url = f"{base_url}/hp/device/security/certificates/import"
            resp = session.post(upload_url, files=files, timeout=30)
            resp.raise_for_status()
            log.info("HP Printer %s: certificate uploaded successfully", host)
            return DeployResult(
                success=True,
                message=f"Certificate deployed to HP printer at {host}",
                details={"status_code": resp.status_code},
            )
        except Exception as exc:  # noqa: BLE001
            log.error("HP Printer %s: deployment failed: %s", host, exc)
            return DeployResult(success=False, message=str(exc))

    def get_current_cert(self, **kwargs: Any) -> Optional[bytes]:
        """Fetch the active certificate from the HP EWS."""
        if requests is None:
            return None

        host = kwargs.get("host")
        if not host:
            return None

        port = int(kwargs.get("port", 443))
        verify_ssl = bool(kwargs.get("verify_ssl", False))

        try:
            import ssl
            import socket
            cert_der = ssl.get_server_certificate((host, port)).encode()
            return cert_der
        except Exception as exc:  # noqa: BLE001
            log.warning("HP Printer %s: could not retrieve certificate: %s", host, exc)
            return None

    def verify(self, cert_pem: bytes, **kwargs: Any) -> bool:
        """Check that the certificate served by the printer matches *cert_pem*."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives import hashes

        host = kwargs.get("host")
        if not host:
            return False

        current = self.get_current_cert(**kwargs)
        if not current:
            return False

        try:
            expected = load_pem_x509_certificate(cert_pem, default_backend())
            actual = load_pem_x509_certificate(current, default_backend())
            return (
                expected.fingerprint(hashes.SHA256()) == actual.fingerprint(hashes.SHA256())
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("HP Printer %s: certificate verification error: %s", host, exc)
            return False

    def revoke(self, **kwargs: Any) -> DeployResult:
        """
        HP printers do not support remote certificate deletion via the
        EWS API; this method is a no-op placeholder.
        """
        host = kwargs.get("host", "unknown")
        return DeployResult(
            success=False,
            message=(
                f"HP Printer ({host}): remote certificate revocation is not "
                "supported via EWS. Please reset the certificate from the "
                "printer control panel."
            ),
        )
