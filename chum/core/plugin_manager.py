"""
Plugin manager.

Discovers, loads and manages Chum device plugins.  Plugins can be
installed in two ways:

1. **Built-in** – shipped inside the ``chum.plugins`` package.
2. **External** – checked out from git into the configured plugin
   directory.  Each external plugin is a Python package that provides
   an entry-point or a ``plugin.json`` manifest alongside a module that
   subclasses :class:`~chum.plugins.base.BasePlugin`.

External plugin layout example::

    chum-plugin-mydevice/
    ├── plugin.json          ← manifest (name, version, module)
    └── chum_mydevice/
        ├── __init__.py
        └── plugin.py        ← subclass of BasePlugin

``plugin.json`` schema::

    {
        "name": "mydevice",
        "version": "1.0.0",
        "description": "Support for My Device",
        "module": "chum_mydevice.plugin",
        "class": "MyDevicePlugin"
    }
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from chum.plugins.base import BasePlugin

log = logging.getLogger(__name__)


class PluginError(Exception):
    """Raised on plugin loading or management failures."""


class PluginManager:
    """
    Central registry for Chum device plugins.

    Parameters
    ----------
    plugin_dir:
        Directory where external (git-cloned) plugins are stored.
        Defaults to ``~/.chum/plugins``.
    """

    # Built-in plugins shipped with Chum
    _BUILTIN_PLUGINS: Dict[str, str] = {
        "hp_printer": "chum.plugins.hp_printer.HPPrinterPlugin",
        "proxmox": "chum.plugins.proxmox.ProxmoxPlugin",
        "openshift": "chum.plugins.openshift.OpenShiftPlugin",
        "idrac": "chum.plugins.idrac.IDRACPlugin",
    }

    def __init__(self, plugin_dir: Optional[Path] = None) -> None:
        self._plugin_dir = Path(plugin_dir) if plugin_dir else Path.home() / ".chum" / "plugins"
        self._registry: Dict[str, Type[BasePlugin]] = {}
        self._load_builtins()

    # ------------------------------------------------------------------
    # Registration / discovery
    # ------------------------------------------------------------------

    def _load_builtins(self) -> None:
        for name, dotted in self._BUILTIN_PLUGINS.items():
            try:
                cls = self._import_dotted(dotted)
                self._registry[name] = cls
                log.debug("Loaded built-in plugin: %s", name)
            except (ImportError, AttributeError) as exc:
                log.warning("Could not load built-in plugin %s: %s", name, exc)

    def load_external_plugins(self) -> None:
        """
        Scan *plugin_dir* for external plugins and load them into the
        registry.  Subdirectories containing a ``plugin.json`` manifest
        are treated as plugins.
        """
        if not self._plugin_dir.is_dir():
            return
        for entry in sorted(self._plugin_dir.iterdir()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "plugin.json"
            if not manifest_path.exists():
                continue
            try:
                self._load_from_manifest(entry, manifest_path)
            except PluginError as exc:
                log.warning("Failed to load external plugin from %s: %s", entry, exc)

    def _load_from_manifest(self, plugin_dir: Path, manifest_path: Path) -> None:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        name = manifest.get("name")
        module_path = manifest.get("module")
        class_name = manifest.get("class")

        if not name or not module_path or not class_name:
            raise PluginError(
                f"plugin.json at {manifest_path} must have 'name', 'module', and 'class' keys"
            )

        # Add plugin directory to sys.path if needed
        if str(plugin_dir) not in sys.path:
            sys.path.insert(0, str(plugin_dir))

        try:
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            raise PluginError(f"Cannot import {class_name} from {module_path}: {exc}") from exc

        if not issubclass(cls, BasePlugin):
            raise PluginError(f"{cls} does not subclass BasePlugin")

        self._registry[name] = cls
        log.info(
            "Loaded external plugin: %s v%s from %s",
            name,
            manifest.get("version", "?"),
            plugin_dir,
        )

    # ------------------------------------------------------------------
    # Git integration
    # ------------------------------------------------------------------

    def install_plugin(self, git_url: str, name: Optional[str] = None) -> str:
        """
        Clone *git_url* into the plugin directory and load the plugin.

        Parameters
        ----------
        git_url:
            URL of the git repository containing the plugin.
        name:
            Optional subdirectory name.  When omitted the last path
            component of *git_url* (without ``.git``) is used.

        Returns
        -------
        str
            The plugin name registered in the plugin registry.
        """
        self._plugin_dir.mkdir(parents=True, exist_ok=True)
        if name is None:
            name = git_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        target = self._plugin_dir / name
        if target.exists():
            log.info("Plugin directory %s exists; pulling latest changes", target)
            self._git_pull(target)
        else:
            log.info("Cloning plugin from %s into %s", git_url, target)
            self._git_clone(git_url, target)

        manifest_path = target / "plugin.json"
        if not manifest_path.exists():
            raise PluginError(f"No plugin.json found in {target}")

        self._load_from_manifest(target, manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return manifest["name"]

    def update_plugin(self, name: str) -> None:
        """Pull the latest version of an installed external plugin."""
        plugin_dir = self._plugin_dir / name
        if not plugin_dir.is_dir():
            raise PluginError(f"Plugin directory not found: {plugin_dir}")
        self._git_pull(plugin_dir)
        manifest_path = plugin_dir / "plugin.json"
        if manifest_path.exists():
            self._load_from_manifest(plugin_dir, manifest_path)

    @staticmethod
    def _git_clone(url: str, dest: Path) -> None:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise PluginError(f"git clone failed: {result.stderr.strip()}")

    @staticmethod
    def _git_pull(directory: Path) -> None:
        result = subprocess.run(
            ["git", "-C", str(directory), "pull", "--ff-only"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise PluginError(f"git pull failed: {result.stderr.strip()}")

    # ------------------------------------------------------------------
    # Registry access
    # ------------------------------------------------------------------

    def get(self, name: str) -> Type[BasePlugin]:
        """Return the plugin class registered under *name*."""
        if name not in self._registry:
            raise PluginError(
                f"Unknown plugin: '{name}'.  Available: {', '.join(self.list_plugins())}"
            )
        return self._registry[name]

    def list_plugins(self) -> List[str]:
        """Return the names of all registered plugins."""
        return sorted(self._registry.keys())

    def register(self, name: str, cls: Type[BasePlugin]) -> None:
        """Manually register a plugin class (useful for testing)."""
        if not issubclass(cls, BasePlugin):
            raise PluginError(f"{cls} does not subclass BasePlugin")
        self._registry[name] = cls

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _import_dotted(dotted: str) -> Type[BasePlugin]:
        """Import a class given its fully-qualified dotted name."""
        module_name, class_name = dotted.rsplit(".", 1)
        module = importlib.import_module(module_name)
        return getattr(module, class_name)
