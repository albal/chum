"""
Proxmox VE plugin.

Deploys TLS certificates to Proxmox VE nodes via the Proxmox REST API.
Supports both single-node and clustered (Proxmox VE 7+) deployments.

References:
    https://pve.proxmox.com/pve-docs/api-viewer/index.html
    PUT /nodes/{node}/certificates/custom

Connection parameters (passed as **kwargs):

host : str
    Proxmox VE hostname or IP.
node : str, optional
    Proxmox node name (default ``"pve"``).
username : str, optional
    Username in ``user@realm`` format (default ``"root@pam"``).
password : str
    Password for the Proxmox user.
api_token : str, optional
    Proxmox API token in ``user@realm!tokenid=secret`` format.
    Takes precedence over password when provided.
port : int, optional
    API port (default 8006).
verify_ssl : bool, optional
    Whether to verify the Proxmox TLS certificate (default ``False``).
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


class ProxmoxPlugin(BasePlugin):
    """Certificate deployment plugin for Proxmox VE."""

    NAME = "proxmox"
    DESCRIPTION = "Deploy certificates to Proxmox VE nodes via the REST API"
    VERSION = "0.1.0"

    def deploy(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None,
        **kwargs: Any,
    ) -> DeployResult:
        """Upload certificate and key to a Proxmox VE node."""
        if requests is None:
            return DeployResult(
                success=False,
                message="The 'requests' package is required. Install with: pip install requests",
            )

        host = kwargs.get("host")
        if not host:
            return DeployResult(success=False, message="'host' parameter is required")

        node = kwargs.get("node", "pve")
        port = int(kwargs.get("port", 8006))
        verify_ssl = bool(kwargs.get("verify_ssl", False))
        base_url = f"https://{host}:{port}/api2/json"

        session = requests.Session()
        session.verify = verify_ssl

        try:
            ticket, csrf = self._authenticate(session, base_url, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return DeployResult(success=False, message=f"Authentication failed: {exc}")

        combined_cert = cert_pem
        if chain_pem:
            combined_cert = cert_pem + chain_pem

        try:
            url = f"{base_url}/nodes/{node}/certificates/custom"
            resp = session.put(
                url,
                data={
                    "certificates": combined_cert.decode(),
                    "key": key_pem.decode(),
                    "force": 1,
                    "restart": 1,
                },
                headers={"CSRFPreventionToken": csrf},
                cookies={"PVEAuthCookie": ticket},
                timeout=30,
            )
            resp.raise_for_status()
            log.info("Proxmox %s (node %s): certificate deployed", host, node)
            return DeployResult(
                success=True,
                message=f"Certificate deployed to Proxmox node '{node}' at {host}",
                details={"node": node, "status_code": resp.status_code},
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Proxmox %s: deployment failed: %s", host, exc)
            return DeployResult(success=False, message=str(exc))

    def get_current_cert(self, **kwargs: Any) -> Optional[bytes]:
        """Retrieve the current node certificate via the Proxmox REST API."""
        if requests is None:
            return None

        host = kwargs.get("host")
        if not host:
            return None

        node = kwargs.get("node", "pve")
        port = int(kwargs.get("port", 8006))
        verify_ssl = bool(kwargs.get("verify_ssl", False))
        base_url = f"https://{host}:{port}/api2/json"

        session = requests.Session()
        session.verify = verify_ssl

        try:
            ticket, csrf = self._authenticate(session, base_url, **kwargs)
            resp = session.get(
                f"{base_url}/nodes/{node}/certificates/info",
                cookies={"PVEAuthCookie": ticket},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            for item in data:
                if item.get("filename") == "pve-ssl.pem":
                    pem = item.get("pem", "")
                    if pem:
                        return pem.encode()
        except Exception as exc:  # noqa: BLE001
            log.warning("Proxmox %s: could not retrieve certificate: %s", host, exc)
        return None

    def verify(self, cert_pem: bytes, **kwargs: Any) -> bool:
        """Check that the deployed certificate matches *cert_pem*."""
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
            log.warning("Proxmox verify error: %s", exc)
            return False

    def revoke(self, **kwargs: Any) -> DeployResult:
        """Remove the custom certificate and revert to the Proxmox default."""
        if requests is None:
            return DeployResult(success=False, message="'requests' package required")

        host = kwargs.get("host")
        if not host:
            return DeployResult(success=False, message="'host' parameter is required")

        node = kwargs.get("node", "pve")
        port = int(kwargs.get("port", 8006))
        verify_ssl = bool(kwargs.get("verify_ssl", False))
        base_url = f"https://{host}:{port}/api2/json"

        session = requests.Session()
        session.verify = verify_ssl

        try:
            ticket, csrf = self._authenticate(session, base_url, **kwargs)
            resp = session.delete(
                f"{base_url}/nodes/{node}/certificates/custom",
                headers={"CSRFPreventionToken": csrf},
                cookies={"PVEAuthCookie": ticket},
                timeout=15,
            )
            resp.raise_for_status()
            return DeployResult(
                success=True,
                message=f"Custom certificate removed from Proxmox node '{node}' at {host}",
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Proxmox %s: revoke failed: %s", host, exc)
            return DeployResult(success=False, message=str(exc))

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _authenticate(session: Any, base_url: str, **kwargs: Any):  # type: ignore[return]
        """Return (ticket, csrf_token) for the Proxmox session."""
        api_token = kwargs.get("api_token")
        if api_token:
            # API token format: user@realm!tokenid=secret
            return api_token, ""

        username = kwargs.get("username", "root@pam")
        password = kwargs.get("password", "")

        resp = session.post(
            f"{base_url}/access/ticket",
            data={"username": username, "password": password},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        return data["ticket"], data["CSRFPreventionToken"]
