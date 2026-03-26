"""
Certificate store.

Persists :class:`~chum.core.certificate.CertificateInfo` records to a
JSON-backed file so that chum can track the lifecycle of every managed
certificate across restarts.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from chum.core.certificate import CertificateInfo, CertificateStatus

_DATE_FMT = "%Y-%m-%dT%H:%M:%S%z"


def _serialize(info: CertificateInfo) -> dict:
    return {
        "common_name": info.common_name,
        "sans": info.sans,
        "serial": info.serial,
        "not_before": info.not_before.strftime(_DATE_FMT) if info.not_before else None,
        "not_after": info.not_after.strftime(_DATE_FMT) if info.not_after else None,
        "fingerprint_sha256": info.fingerprint_sha256,
        "status": info.status.value,
        "cert_path": str(info.cert_path) if info.cert_path else None,
        "key_path": str(info.key_path) if info.key_path else None,
        "chain_path": str(info.chain_path) if info.chain_path else None,
    }


def _deserialize(data: dict) -> CertificateInfo:
    def _dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        dt = datetime.strptime(s, _DATE_FMT)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    info = CertificateInfo(
        common_name=data["common_name"],
        sans=data.get("sans", []),
        serial=data.get("serial"),
        not_before=_dt(data.get("not_before")),
        not_after=_dt(data.get("not_after")),
        fingerprint_sha256=data.get("fingerprint_sha256"),
        status=CertificateStatus(data.get("status", CertificateStatus.PENDING.value)),
        cert_path=Path(data["cert_path"]) if data.get("cert_path") else None,
        key_path=Path(data["key_path"]) if data.get("key_path") else None,
        chain_path=Path(data["chain_path"]) if data.get("chain_path") else None,
    )
    return info


class CertificateStore:
    """
    JSON-backed store for :class:`~chum.core.certificate.CertificateInfo` records.

    The store is keyed by *common_name*.  A single certificate per
    common name is supported; replace it by calling :meth:`save` again.
    """

    def __init__(self, store_path: Path) -> None:
        self._path = Path(store_path)
        self._records: Dict[str, CertificateInfo] = {}
        if self._path.exists():
            self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, info: CertificateInfo) -> None:
        """Persist *info*, overwriting any existing entry for the same CN."""
        info.refresh_status()
        self._records[info.common_name] = info
        self._flush()

    def get(self, common_name: str) -> Optional[CertificateInfo]:
        """Return the :class:`CertificateInfo` for *common_name*, or ``None``."""
        return self._records.get(common_name)

    def delete(self, common_name: str) -> bool:
        """Remove the entry for *common_name*.  Returns ``True`` if it existed."""
        if common_name in self._records:
            del self._records[common_name]
            self._flush()
            return True
        return False

    def list(self) -> List[CertificateInfo]:
        """Return all stored :class:`CertificateInfo` records."""
        for info in self._records.values():
            info.refresh_status()
        return list(self._records.values())

    def expiring_soon(self, days: int = 30) -> List[CertificateInfo]:
        """Return certificates whose expiry is within *days* days."""
        results = []
        for info in self.list():
            remaining = info.days_remaining
            if remaining is not None and remaining <= days:
                results.append(info)
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        for entry in raw:
            info = _deserialize(entry)
            self._records[info.common_name] = info

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps([_serialize(v) for v in self._records.values()], indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)
