"""
Tests for chum.core.plugin_manager
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch, MagicMock

import pytest

from chum.plugins.base import BasePlugin, DeployResult
from chum.core.plugin_manager import PluginManager, PluginError


# ---------------------------------------------------------------------------
# Minimal stub plugin for testing
# ---------------------------------------------------------------------------


class _StubPlugin(BasePlugin):
    NAME = "stub"
    DESCRIPTION = "Test stub"
    VERSION = "0.0.1"

    def deploy(self, cert_pem, key_pem, chain_pem=None, **kwargs):
        return DeployResult(success=True, message="stub deployed")

    def get_current_cert(self, **kwargs):
        return None

    def verify(self, cert_pem, **kwargs):
        return True

    def revoke(self, **kwargs):
        return DeployResult(success=True, message="stub revoked")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_builtin_plugins_loaded():
    manager = PluginManager()
    plugins = manager.list_plugins()
    assert "proxmox" in plugins
    assert "hp_printer" in plugins
    assert "openshift" in plugins
    assert "idrac" in plugins


def test_get_known_plugin():
    manager = PluginManager()
    cls = manager.get("proxmox")
    from chum.plugins.proxmox import ProxmoxPlugin

    assert cls is ProxmoxPlugin


def test_get_unknown_plugin_raises():
    manager = PluginManager()
    with pytest.raises(PluginError, match="Unknown plugin"):
        manager.get("nonexistent_plugin")


def test_register_custom_plugin():
    manager = PluginManager()
    manager.register("stub", _StubPlugin)
    assert "stub" in manager.list_plugins()
    assert manager.get("stub") is _StubPlugin


def test_register_non_plugin_raises():
    manager = PluginManager()
    with pytest.raises(PluginError):
        manager.register("bad", object)  # type: ignore


def test_load_external_plugin_from_manifest(tmp_path):
    """
    Simulate an external plugin directory with a plugin.json manifest and
    a minimal Python module.
    """
    pkg_dir = tmp_path / "chum_testplugin"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "plugin.py").write_text(
        """
from chum.plugins.base import BasePlugin, DeployResult

class TestExternalPlugin(BasePlugin):
    NAME = "testexternal"
    DESCRIPTION = "External test plugin"
    def deploy(self, cert_pem, key_pem, chain_pem=None, **kwargs):
        return DeployResult(success=True)
    def get_current_cert(self, **kwargs):
        return None
    def verify(self, cert_pem, **kwargs):
        return True
    def revoke(self, **kwargs):
        return DeployResult(success=True)
"""
    )

    manifest = {
        "name": "testexternal",
        "version": "1.0.0",
        "description": "External test plugin",
        "module": "chum_testplugin.plugin",
        "class": "TestExternalPlugin",
    }
    manifest_path = tmp_path / "plugin.json"
    manifest_path.write_text(json.dumps(manifest))

    manager = PluginManager(plugin_dir=tmp_path.parent)  # parent contains `tmp_path` as subdir

    # Manually invoke _load_from_manifest
    manager._load_from_manifest(tmp_path, manifest_path)

    assert "testexternal" in manager.list_plugins()
    cls = manager.get("testexternal")
    plugin = cls()
    result = plugin.deploy(b"cert", b"key")
    assert result.success


def test_load_external_plugin_missing_fields(tmp_path):
    incomplete_manifest = {"name": "incomplete"}
    manifest_path = tmp_path / "plugin.json"
    manifest_path.write_text(json.dumps(incomplete_manifest))

    manager = PluginManager(plugin_dir=tmp_path)
    with pytest.raises(PluginError, match="must have"):
        manager._load_from_manifest(tmp_path, manifest_path)


def test_load_external_plugins_skips_missing_manifest(tmp_path):
    """A subdirectory without plugin.json should be silently skipped."""
    sub = tmp_path / "no_manifest_plugin"
    sub.mkdir()
    (sub / "somefile.py").write_text("")

    manager = PluginManager(plugin_dir=tmp_path)
    manager.load_external_plugins()  # should not raise
    # The stub dirs should not appear in the registry
    assert "no_manifest_plugin" not in manager.list_plugins()


def test_install_plugin_git_clone(tmp_path, monkeypatch):
    """
    install_plugin should call git clone and then load the manifest.
    """
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()

    fake_clone_target = plugin_dir / "myplugin"
    fake_clone_target.mkdir()

    # Write a valid plugin.json and stub module in the target
    pkg = fake_clone_target / "chum_myplugin"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "plugin.py").write_text(
        """
from chum.plugins.base import BasePlugin, DeployResult
class MyPlugin(BasePlugin):
    NAME = "myplugin"
    DESCRIPTION = "My Plugin"
    def deploy(self, cert_pem, key_pem, chain_pem=None, **kwargs):
        return DeployResult(success=True)
    def get_current_cert(self, **kwargs): return None
    def verify(self, cert_pem, **kwargs): return True
    def revoke(self, **kwargs): return DeployResult(success=True)
"""
    )
    (fake_clone_target / "plugin.json").write_text(
        json.dumps(
            {
                "name": "myplugin",
                "version": "1.0.0",
                "description": "My Plugin",
                "module": "chum_myplugin.plugin",
                "class": "MyPlugin",
            }
        )
    )

    # Patch git clone so it does nothing (directory already "exists")
    manager = PluginManager(plugin_dir=plugin_dir)

    def fake_git_clone(url, dest):
        pass  # target already pre-created above

    def fake_git_pull(directory):
        pass

    monkeypatch.setattr(PluginManager, "_git_clone", staticmethod(fake_git_clone))
    monkeypatch.setattr(PluginManager, "_git_pull", staticmethod(fake_git_pull))

    name = manager.install_plugin("https://git.example.com/myplugin.git", name="myplugin")
    assert name == "myplugin"
    assert "myplugin" in manager.list_plugins()
