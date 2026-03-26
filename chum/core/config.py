"""
Configuration management for Chum.

Settings are read from (in priority order):
1. Environment variables prefixed ``CHUM_``
2. A YAML/JSON config file (default ``~/.chum/config.yaml``)
3. Built-in defaults

All settings are accessible through the :class:`Config` singleton.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path.home() / ".chum" / "config.yaml"
_DEFAULT_STORE_PATH = Path.home() / ".chum" / "store.json"
_DEFAULT_PLUGIN_DIR = Path.home() / ".chum" / "plugins"
_DEFAULT_CERT_DIR = Path.home() / ".chum" / "certs"


def _try_load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML or JSON config file, returning an empty dict on failure."""
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        log.warning("Could not parse config file %s", path)
        return {}


class Config:
    """
    Application-wide configuration container.

    Parameters
    ----------
    path:
        Path to the YAML/JSON config file.  Environment variables always
        take precedence over file values.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        config_path = Path(path) if path else Path(os.environ.get("CHUM_CONFIG", _DEFAULT_CONFIG_PATH))
        self._data: Dict[str, Any] = _try_load_yaml(config_path)

    # ------------------------------------------------------------------
    # Core paths
    # ------------------------------------------------------------------

    @property
    def store_path(self) -> Path:
        return Path(
            os.environ.get("CHUM_STORE_PATH")
            or self._data.get("store_path")
            or _DEFAULT_STORE_PATH
        )

    @property
    def plugin_dir(self) -> Path:
        return Path(
            os.environ.get("CHUM_PLUGIN_DIR")
            or self._data.get("plugin_dir")
            or _DEFAULT_PLUGIN_DIR
        )

    @property
    def cert_dir(self) -> Path:
        return Path(
            os.environ.get("CHUM_CERT_DIR")
            or self._data.get("cert_dir")
            or _DEFAULT_CERT_DIR
        )

    # ------------------------------------------------------------------
    # ACME
    # ------------------------------------------------------------------

    @property
    def acme_email(self) -> Optional[str]:
        return os.environ.get("CHUM_ACME_EMAIL") or self._data.get("acme_email")

    @property
    def acme_directory_url(self) -> str:
        return (
            os.environ.get("CHUM_ACME_DIRECTORY_URL")
            or self._data.get("acme_directory_url")
            or "https://acme-v02.api.letsencrypt.org/directory"
        )

    @property
    def acme_staging(self) -> bool:
        env = os.environ.get("CHUM_ACME_STAGING")
        if env is not None:
            return env.lower() in ("1", "true", "yes")
        return bool(self._data.get("acme_staging", False))

    @property
    def acme_challenge_type(self) -> str:
        """
        ACME challenge type to use: 'dns-01' (default) or 'dns-persist-01'.

        DNS-PERSIST-01 allows certificate issuance without per-request DNS
        updates, using a pre-configured persistent TXT record.
        """
        return (
            os.environ.get("CHUM_ACME_CHALLENGE_TYPE")
            or self._data.get("acme_challenge_type")
            or "dns-01"
        )

    @property
    def acme_persist_policy(self) -> Optional[str]:
        """
        Policy for DNS-PERSIST-01 authorization.

        - None (default): Only the exact domain is authorized.
        - 'wildcard': Authorizes wildcard certificates (*.domain).
        - 'subdomain': Authorizes any subdomain certificates.
        """
        return (
            os.environ.get("CHUM_ACME_PERSIST_POLICY")
            or self._data.get("acme_persist_policy")
        )

    @property
    def acme_persist_until(self) -> Optional[str]:
        """
        ISO 8601 timestamp for DNS-PERSIST-01 authorization expiry.

        If not set, the authorization persists indefinitely (until the
        DNS record is manually removed).
        """
        return (
            os.environ.get("CHUM_ACME_PERSIST_UNTIL")
            or self._data.get("acme_persist_until")
        )

    # ------------------------------------------------------------------
    # CA (local/self-signed mode)
    # ------------------------------------------------------------------

    @property
    def ca_cert_path(self) -> Optional[Path]:
        v = os.environ.get("CHUM_CA_CERT_PATH") or self._data.get("ca_cert_path")
        return Path(v) if v else None

    @property
    def ca_key_path(self) -> Optional[Path]:
        v = os.environ.get("CHUM_CA_KEY_PATH") or self._data.get("ca_key_path")
        return Path(v) if v else None

    # ------------------------------------------------------------------
    # Expiry warning
    # ------------------------------------------------------------------

    @property
    def expiry_warning_days(self) -> int:
        v = os.environ.get("CHUM_EXPIRY_WARNING_DAYS") or self._data.get("expiry_warning_days")
        return int(v) if v else 30

    # ------------------------------------------------------------------
    # Raw access
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Get a raw config value by key (file only; no env var expansion)."""
        return self._data.get(key, default)
