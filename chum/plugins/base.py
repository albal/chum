"""
Base plugin interface.

All device plugins – both built-in and external – must subclass
:class:`BasePlugin` and implement the abstract methods.

Minimal external plugin example::

    from chum.plugins.base import BasePlugin, DeployResult

    class MyDevicePlugin(BasePlugin):
        NAME = "mydevice"
        DESCRIPTION = "My device description"

        def deploy(self, cert_pem, key_pem, chain_pem=None, **kwargs):
            # upload cert to device ...
            return DeployResult(success=True, message="Deployed!")

        def get_current_cert(self, **kwargs):
            # fetch current cert from device; return None if not found
            return None

        def verify(self, cert_pem, **kwargs):
            return True

        def revoke(self, **kwargs):
            return DeployResult(success=True, message="Revoked")
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class DeployResult:
    """Result of a :meth:`BasePlugin.deploy` or :meth:`BasePlugin.revoke` call."""

    success: bool
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        status = "OK" if self.success else "FAILED"
        parts = [f"[{status}]"]
        if self.message:
            parts.append(self.message)
        return " ".join(parts)


class BasePlugin(ABC):
    """
    Abstract base class for Chum device plugins.

    Each plugin is responsible for deploying a wildcard TLS certificate
    (and its private key) to a specific class of device.  Plugins are
    instantiated once per deployment target; all connection parameters
    are passed as keyword arguments to the individual methods.

    Class attributes
    ----------------
    NAME:
        Short, unique plugin identifier (e.g. ``"proxmox"``).
    DESCRIPTION:
        Human-readable description shown in ``chum plugin list``.
    VERSION:
        Semver string.
    """

    NAME: str = ""
    DESCRIPTION: str = ""
    VERSION: str = "0.1.0"

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def deploy(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None,
        **kwargs: Any,
    ) -> DeployResult:
        """
        Deploy the certificate and key to the target device.

        Parameters
        ----------
        cert_pem:
            PEM-encoded certificate.
        key_pem:
            PEM-encoded private key.
        chain_pem:
            Optional PEM-encoded certificate chain (intermediate CAs).
        **kwargs:
            Device-specific connection parameters (host, username,
            password, etc.).

        Returns
        -------
        DeployResult
        """

    @abstractmethod
    def get_current_cert(self, **kwargs: Any) -> Optional[bytes]:
        """
        Fetch the current certificate from the device.

        Returns the PEM-encoded certificate, or ``None`` if no
        certificate is installed or the device cannot be reached.
        """

    @abstractmethod
    def verify(self, cert_pem: bytes, **kwargs: Any) -> bool:
        """
        Confirm that *cert_pem* matches the certificate currently
        installed on the device.
        """

    @abstractmethod
    def revoke(self, **kwargs: Any) -> DeployResult:
        """
        Remove or replace the certificate on the device (e.g. revert
        to a self-signed fallback).
        """

    # ------------------------------------------------------------------
    # Convenience helpers (may be overridden)
    # ------------------------------------------------------------------

    def info(self) -> Dict[str, str]:
        """Return plugin metadata as a plain dictionary."""
        return {
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.NAME!r} version={self.VERSION!r}>"
