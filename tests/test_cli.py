"""
Tests for the Chum CLI (chum.cli).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from chum.cli import build_parser, main
from chum.core.certificate import (
    generate_ca,
    generate_csr,
    generate_private_key,
    save_certificate_bundle,
    self_sign_certificate,
)
from chum.core.config import Config
from chum.core.store import CertificateStore


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _issue_cert(config: Config, cn: str = "*.cli-test.local") -> None:
    """Issue a self-signed cert and register it in the store."""
    key = generate_private_key(2048)
    csr = generate_csr(key, cn, [cn])
    cert = self_sign_certificate(key, csr, valid_days=90)
    config.cert_dir.mkdir(parents=True, exist_ok=True)
    safe_cn = cn.lstrip("*").lstrip(".")
    info = save_certificate_bundle(config.cert_dir, safe_cn, cert, key)
    store = CertificateStore(config.store_path)
    store.save(info)


# ---------------------------------------------------------------------------
# Parser smoke tests
# ---------------------------------------------------------------------------


def test_parser_cert_issue():
    parser = build_parser()
    args = parser.parse_args(["cert", "issue", "--cn", "*.example.com"])
    assert args.cn == "*.example.com"
    assert args.cert_command == "issue"


def test_parser_deploy():
    parser = build_parser()
    args = parser.parse_args(["deploy", "--plugin", "proxmox", "--cert", "*.example.com", "--host", "10.0.0.1"])
    assert args.plugin == "proxmox"
    assert args.host == "10.0.0.1"


def test_parser_plugin_list():
    parser = build_parser()
    args = parser.parse_args(["plugin", "list"])
    assert args.plugin_command == "list"


def test_parser_ca_init():
    parser = build_parser()
    args = parser.parse_args(["ca", "init", "--cn", "My CA", "--days", "365"])
    assert args.cn == "My CA"
    assert args.days == 365


# ---------------------------------------------------------------------------
# cert issue / list / show / revoke
# ---------------------------------------------------------------------------


def test_cert_issue_self_signed(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        rc = main(["cert", "issue", "--cn", "*.issue-test.local", "--self-signed", "--days", "10"])
    assert rc == 0
    store = CertificateStore(tmp_path / "store.json")
    info = store.get("*.issue-test.local")
    assert info is not None
    assert info.days_remaining is not None and info.days_remaining <= 10


def test_cert_list(tmp_path, capsys):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.list-test.local", "--self-signed"])
        rc = main(["cert", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "*.list-test.local" in out


def test_cert_show(tmp_path, capsys):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.show-test.local", "--self-signed"])
        rc = main(["cert", "show", "*.show-test.local"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "*.show-test.local" in out
    assert "Serial" in out


def test_cert_show_missing(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        rc = main(["cert", "show", "*.nonexistent.com"])
    assert rc == 1


def test_cert_revoke(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.revoke-test.local", "--self-signed"])
        rc = main(["cert", "revoke", "*.revoke-test.local"])
    assert rc == 0

    store = CertificateStore(tmp_path / "store.json")
    from chum.core.certificate import CertificateStatus
    info = store.get("*.revoke-test.local")
    assert info.status == CertificateStatus.REVOKED


def test_cert_renew(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.renew-test.local", "--self-signed", "--days", "5"])
        rc = main(["cert", "renew", "*.renew-test.local", "--days", "60"])
    assert rc == 0

    store = CertificateStore(tmp_path / "store.json")
    info = store.get("*.renew-test.local")
    assert info.days_remaining is not None and info.days_remaining > 50


# ---------------------------------------------------------------------------
# ca init
# ---------------------------------------------------------------------------


def test_ca_init(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        rc = main(["ca", "init", "--cn", "Test CA", "--days", "100"])
    assert rc == 0
    assert (tmp_path / "certs" / "ca" / "ca.crt").exists()
    assert (tmp_path / "certs" / "ca" / "ca.key").exists()


# ---------------------------------------------------------------------------
# plugin list
# ---------------------------------------------------------------------------


def test_plugin_list(capsys):
    rc = main(["plugin", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "proxmox" in out
    assert "idrac" in out


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------


def test_deploy_unknown_plugin(tmp_path, capsys):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.deploy-test.local", "--self-signed"])
        rc = main(
            ["deploy", "--plugin", "nonexistent", "--cert", "*.deploy-test.local", "--host", "10.0.0.1"]
        )
    assert rc == 1


def test_deploy_cert_not_in_store(tmp_path):
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        rc = main(["deploy", "--plugin", "proxmox", "--cert", "*.nothere.com", "--host", "10.0.0.1"])
    assert rc == 1
