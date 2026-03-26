"""
Dell iDRAC plugin.

Deploys TLS certificates to Dell PowerEdge servers via the iDRAC
Redfish REST API (iDRAC 9 / Redfish 1.x).

References:
    https://developer.dell.com/apis/3788/versions/6.xx/openapi.yaml
    PATCH /redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol
    POST  /redfish/v1/Managers/iDRAC.Embedded.1/Actions/
          Oem/DellManager.ImportSystemConfigurationPreview

Connection parameters (passed as **kwargs):

host : str
    Hostname or IP address of the iDRAC interface.
username : str, optional
    iDRAC username (default ``"root"``).
password : str
    iDRAC password.
port : int, optional
    HTTPS port (default 443).
verify_ssl : bool, optional
    Verify the iDRAC TLS certificate (default ``False``).
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

_REDFISH_BASE = "/redfish/v1"
_IDRAC_MANAGER = f"{_REDFISH_BASE}/Managers/iDRAC.Embedded.1"
_CERT_SERVICE = f"{_REDFISH_BASE}/CertificateService"
_CERT_COLLECTION = (
    f"{_REDFISH_BASE}/Managers/iDRAC.Embedded.1/NetworkProtocol/"
    "HTTPS/Certificates"
)


class IDRACPlugin(BasePlugin):
    """Certificate deployment plugin for Dell iDRAC interfaces (Redfish API)."""

    NAME = "idrac"
    DESCRIPTION = "Deploy certificates to Dell iDRAC interfaces via the Redfish API"
    VERSION = "0.1.0"

    def deploy(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None,
        **kwargs: Any,
    ) -> DeployResult:
        """Upload certificate and key to iDRAC via the Redfish API."""
        session = self._build_session(**kwargs)
        if session is None:
            return DeployResult(success=False, message="Could not create requests session")

        base_url = self._base_url(**kwargs)

        combined_cert = cert_pem
        if chain_pem:
            combined_cert = cert_pem + chain_pem

        # iDRAC Redfish CertificateService.GenerateCSR / ImportCertificate action
        payload = {
            "CertificateType": "PEM",
            "CertificateString": combined_cert.decode(),
            "KeyString": key_pem.decode(),
        }

        try:
            # First try Redfish CertificateService ImportCertificate
            action_url = (
                f"{base_url}{_IDRAC_MANAGER}/Actions/Oem/DellManager.ImportCertificate"
            )
            resp = session.post(action_url, json=payload, timeout=30)

            if resp.status_code == 404:
                # Older iDRAC firmware: use the SSL certificate upload path
                resp = session.post(
                    f"{base_url}{_CERT_COLLECTION}",
                    json=payload,
                    timeout=30,
                )

            if resp.status_code in (200, 201, 204):
                log.info("iDRAC %s: certificate deployed", kwargs.get("host"))
                return DeployResult(
                    success=True,
                    message=f"Certificate deployed to iDRAC at {kwargs.get('host')}",
                    details={"status_code": resp.status_code},
                )

            # Fall back to SCP (Server Configuration Profile) import
            return self._deploy_via_scp(session, base_url, combined_cert, key_pem, **kwargs)

        except Exception as exc:  # noqa: BLE001
            log.error("iDRAC %s: deployment failed: %s", kwargs.get("host"), exc)
            return DeployResult(success=False, message=str(exc))

    def get_current_cert(self, **kwargs: Any) -> Optional[bytes]:
        """Retrieve the current iDRAC HTTPS certificate via TLS handshake."""
        host = kwargs.get("host")
        if not host:
            return None
        port = int(kwargs.get("port", 443))
        try:
            import ssl  # noqa: PLC0415

            cert_pem = ssl.get_server_certificate((host, port))
            return cert_pem.encode()
        except Exception as exc:  # noqa: BLE001
            log.warning("iDRAC %s: could not retrieve certificate: %s", host, exc)
            return None

    def verify(self, cert_pem: bytes, **kwargs: Any) -> bool:
        """Check that the iDRAC certificate matches *cert_pem*."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives import hashes

        current = self.get_current_cert(**kwargs)
        if not current:
            return False
        try:
            expected = load_pem_x509_certificate(cert_pem, default_backend())
            actual = load_pem_x509_certificate(current, default_backend())
            return expected.fingerprint(hashes.SHA256()) == actual.fingerprint(hashes.SHA256())
        except Exception as exc:  # noqa: BLE001
            log.warning("iDRAC verify error: %s", exc)
            return False

    def revoke(self, **kwargs: Any) -> DeployResult:
        """
        iDRAC does not support remote certificate deletion.  This is a
        no-op placeholder; the operator must reset via the iDRAC GUI or
        racadm.
        """
        host = kwargs.get("host", "unknown")
        return DeployResult(
            success=False,
            message=(
                f"iDRAC ({host}): remote certificate revocation is not supported "
                "via the Redfish API. Use the iDRAC GUI or "
                "'racadm sslresetcfg' to revert to a self-signed certificate."
            ),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _base_url(**kwargs: Any) -> str:
        host = kwargs.get("host", "")
        port = int(kwargs.get("port", 443))
        return f"https://{host}:{port}"

    @staticmethod
    def _build_session(**kwargs: Any) -> Optional[Any]:
        if requests is None:
            return None

        username = kwargs.get("username", "root")
        password = kwargs.get("password", "")
        verify_ssl = bool(kwargs.get("verify_ssl", False))

        session = requests.Session()
        session.verify = verify_ssl
        session.auth = (username, password)
        session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )
        return session

    def _deploy_via_scp(
        self,
        session: Any,
        base_url: str,
        cert_pem: bytes,
        key_pem: bytes,
        **kwargs: Any,
    ) -> DeployResult:
        """Fall back to SCP (Server Configuration Profile) import."""
        scp_payload = {
            "ImportBuffer": (
                "<SystemConfiguration>"
                "<Component FQDD='iDRAC.Embedded.1'>"
                f"<Attribute Name='WebServer.1#CustomCertificate'>{cert_pem.decode()}</Attribute>"
                f"<Attribute Name='WebServer.1#CustomPrivateKey'>{key_pem.decode()}</Attribute>"
                "</Component>"
                "</SystemConfiguration>"
            ),
            "ShutdownType": "NoReboot",
            "TimeToWait": 300,
            "EndHostPowerState": "On",
        }
        action_url = (
            f"{base_url}{_IDRAC_MANAGER}/Actions/Oem/DellManager.ImportSystemConfigurationPreview"
        )
        try:
            resp = session.post(action_url, json=scp_payload, timeout=60)
            if resp.status_code in (200, 202):
                return DeployResult(
                    success=True,
                    message=f"Certificate queued for deployment via SCP to {kwargs.get('host')}",
                    details={"status_code": resp.status_code},
                )
            return DeployResult(
                success=False,
                message=f"SCP import failed: HTTP {resp.status_code} {resp.text}",
            )
        except Exception as exc:  # noqa: BLE001
            return DeployResult(success=False, message=f"SCP import error: {exc}")
