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


def test_deploy_successful(tmp_path):
    """Test successful deployment with a mocked plugin."""
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        # Issue a cert first
        main(["cert", "issue", "--cn", "*.deploy-success.local", "--self-signed"])

        # Mock the plugin deploy to succeed
        with patch("chum.plugins.hp_printer.HPPrinterPlugin.deploy") as mock_deploy:
            from chum.plugins.base import DeployResult
            mock_deploy.return_value = DeployResult(success=True, message="Deployed")
            rc = main(
                ["deploy", "--plugin", "hp_printer", "--cert", "*.deploy-success.local", "--host", "192.168.1.1"]
            )
    assert rc == 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_unknown_plugin(tmp_path, capsys):
    """Test verify with unknown plugin name."""
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.verify-test.local", "--self-signed"])
        rc = main(
            ["verify", "--plugin", "nonexistent", "--cert", "*.verify-test.local", "--host", "10.0.0.1"]
        )
    assert rc == 1
    err = capsys.readouterr().err
    assert "Error" in err


def test_verify_cert_not_in_store(tmp_path, capsys):
    """Test verify when certificate is not in store."""
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        rc = main(["verify", "--plugin", "proxmox", "--cert", "*.nothere.com", "--host", "10.0.0.1"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not found" in err.lower()


def test_verify_success(tmp_path, capsys):
    """Test successful verification with mocked plugin."""
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.verify-success.local", "--self-signed"])

        with patch("chum.plugins.hp_printer.HPPrinterPlugin.verify") as mock_verify:
            mock_verify.return_value = True
            rc = main(
                ["verify", "--plugin", "hp_printer", "--cert", "*.verify-success.local", "--host", "192.168.1.1"]
            )
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASSED" in out


def test_verify_failure(tmp_path, capsys):
    """Test failed verification with mocked plugin."""
    env = {
        "CHUM_CERT_DIR": str(tmp_path / "certs"),
        "CHUM_STORE_PATH": str(tmp_path / "store.json"),
    }
    with patch.dict("os.environ", env):
        main(["cert", "issue", "--cn", "*.verify-fail.local", "--self-signed"])

        with patch("chum.plugins.hp_printer.HPPrinterPlugin.verify") as mock_verify:
            mock_verify.return_value = False
            rc = main(
                ["verify", "--plugin", "hp_printer", "--cert", "*.verify-fail.local", "--host", "192.168.1.1"]
            )
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAILED" in out


# ---------------------------------------------------------------------------
# plugin install / update
# ---------------------------------------------------------------------------


def test_plugin_install_success(tmp_path, capsys):
    """Test successful plugin installation."""
    env = {
        "CHUM_PLUGIN_DIR": str(tmp_path / "plugins"),
    }
    with patch.dict("os.environ", env):
        with patch("chum.core.plugin_manager.PluginManager.install_plugin") as mock_install:
            mock_install.return_value = "test-plugin"
            rc = main(["plugin", "install", "https://github.com/test/plugin.git"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "installed" in out.lower()


def test_plugin_install_failure(tmp_path, capsys):
    """Test plugin installation failure."""
    from chum.core.plugin_manager import PluginError
    env = {
        "CHUM_PLUGIN_DIR": str(tmp_path / "plugins"),
    }
    with patch.dict("os.environ", env):
        with patch("chum.core.plugin_manager.PluginManager.install_plugin") as mock_install:
            mock_install.side_effect = PluginError("Clone failed")
            rc = main(["plugin", "install", "https://github.com/test/plugin.git"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Error" in err


def test_plugin_update_success(tmp_path, capsys):
    """Test successful plugin update."""
    env = {
        "CHUM_PLUGIN_DIR": str(tmp_path / "plugins"),
    }
    with patch.dict("os.environ", env):
        with patch("chum.core.plugin_manager.PluginManager.update_plugin") as mock_update:
            mock_update.return_value = None  # Success
            rc = main(["plugin", "update", "test-plugin"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "updated" in out.lower()


def test_plugin_update_failure(tmp_path, capsys):
    """Test plugin update failure."""
    from chum.core.plugin_manager import PluginError
    env = {
        "CHUM_PLUGIN_DIR": str(tmp_path / "plugins"),
    }
    with patch.dict("os.environ", env):
        with patch("chum.core.plugin_manager.PluginManager.update_plugin") as mock_update:
            mock_update.side_effect = PluginError("Plugin not found")
            rc = main(["plugin", "update", "nonexistent-plugin"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Error" in err


# ---------------------------------------------------------------------------
# CLI helper functions
# ---------------------------------------------------------------------------


def test_plugin_kwargs_extracts_options():
    """Test _plugin_kwargs extracts --option key=value pairs."""
    from chum.cli import _plugin_kwargs
    import argparse

    args = argparse.Namespace(
        host="10.0.0.1",
        username="admin",
        password="secret",
        option=["custom_key=custom_value", "another=value2"],
        node=None,
        namespace=None,
        secret_name=None,
        token=None,
        api_url=None,
        port=None,
        verify_ssl=None,
    )
    kwargs = _plugin_kwargs(args)
    assert kwargs["host"] == "10.0.0.1"
    assert kwargs["username"] == "admin"
    assert kwargs["password"] == "secret"
    assert kwargs["custom_key"] == "custom_value"
    assert kwargs["another"] == "value2"


def test_plugin_kwargs_handles_missing_attributes():
    """Test _plugin_kwargs handles args without optional attributes."""
    from chum.cli import _plugin_kwargs
    import argparse

    args = argparse.Namespace()  # Empty namespace
    kwargs = _plugin_kwargs(args)
    assert kwargs == {}


# ---------------------------------------------------------------------------
# Parser edge cases
# ---------------------------------------------------------------------------


def test_parser_verify_command():
    """Test parser handles verify command."""
    parser = build_parser()
    args = parser.parse_args(["verify", "--plugin", "proxmox", "--cert", "*.example.com", "--host", "10.0.0.1"])
    assert args.command == "verify"
    assert args.plugin == "proxmox"
    assert args.cert == "*.example.com"
    assert args.host == "10.0.0.1"


def test_parser_plugin_install():
    """Test parser handles plugin install command."""
    parser = build_parser()
    args = parser.parse_args(["plugin", "install", "https://github.com/test/plugin.git"])
    assert args.command == "plugin"
    assert args.plugin_command == "install"
    assert args.git_url == "https://github.com/test/plugin.git"


def test_parser_plugin_update():
    """Test parser handles plugin update command."""
    parser = build_parser()
    args = parser.parse_args(["plugin", "update", "my-plugin"])
    assert args.command == "plugin"
    assert args.plugin_command == "update"
    assert args.name == "my-plugin"


def test_parser_with_option_flags():
    """Test parser handles --option flags correctly."""
    parser = build_parser()
    args = parser.parse_args([
        "deploy",
        "--plugin", "proxmox",
        "--cert", "*.example.com",
        "--host", "10.0.0.1",
        "-o", "key1=val1",
        "-o", "key2=val2",
    ])
    assert args.option == ["key1=val1", "key2=val2"]

