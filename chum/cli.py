"""
Chum CLI.

Entry point for the ``chum`` command-line tool.

Usage::

    chum cert list
    chum cert issue  --cn "*.example.com" --san example.com [--self-signed]
    chum cert renew  *.example.com
    chum cert show   *.example.com
    chum cert revoke *.example.com

    chum deploy --plugin proxmox --host 10.0.0.1 --cert "*.example.com" [options]
    chum verify --plugin proxmox --host 10.0.0.1 --cert "*.example.com" [options]

    chum plugin list
    chum plugin install <git-url>
    chum plugin update  <name>

    chum ca init [--cn "My CA"]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from chum import __version__
from chum.core.certificate import (
    CertificateInfo,
    generate_ca,
    generate_csr,
    generate_private_key,
    load_certificate,
    private_key_to_pem,
    cert_to_pem,
    save_certificate_bundle,
    self_sign_certificate,
)
from chum.core.config import Config
from chum.core.plugin_manager import PluginManager, PluginError
from chum.core.store import CertificateStore

log = logging.getLogger("chum")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def _load_ca(config: Config):
    """Load CA cert+key from config, returning (cert, key) or (None, None)."""
    if config.ca_cert_path and config.ca_key_path:
        ca_cert_pem = config.ca_cert_path.read_bytes()
        ca_key_pem = config.ca_key_path.read_bytes()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend

        ca_cert = load_certificate(ca_cert_pem)
        ca_key = load_pem_private_key(ca_key_pem, password=None, backend=default_backend())
        return ca_cert, ca_key
    return None, None


def _plugin_kwargs(args: argparse.Namespace) -> dict:
    """Build plugin kwargs from CLI args and any --option key=value pairs."""
    kwargs: dict = {}
    if getattr(args, "host", None):
        kwargs["host"] = args.host
    if getattr(args, "username", None):
        kwargs["username"] = args.username
    if getattr(args, "password", None):
        kwargs["password"] = args.password
    if getattr(args, "node", None):
        kwargs["node"] = args.node
    if getattr(args, "namespace", None):
        kwargs["namespace"] = args.namespace
    if getattr(args, "secret_name", None):
        kwargs["secret_name"] = args.secret_name
    if getattr(args, "token", None):
        kwargs["token"] = args.token
    if getattr(args, "api_url", None):
        kwargs["api_url"] = args.api_url
    if getattr(args, "port", None):
        kwargs["port"] = args.port
    if getattr(args, "verify_ssl", None) is not None:
        kwargs["verify_ssl"] = args.verify_ssl

    # Parse extra --option key=value pairs
    for opt in getattr(args, "option", []):
        if "=" in opt:
            k, v = opt.split("=", 1)
            kwargs[k.strip()] = v.strip()
    return kwargs


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def cmd_cert_list(args: argparse.Namespace, config: Config) -> int:
    store = CertificateStore(config.store_path)
    records = store.list()
    if not records:
        print("No certificates in store.")
        return 0
    header = f"{'COMMON NAME':<40} {'STATUS':<15} {'DAYS LEFT':>9} {'SERIAL'}"
    print(header)
    print("-" * len(header))
    for info in records:
        days = info.days_remaining
        days_str = str(days) if days is not None else "-"
        serial = (info.serial or "-")[:16]
        print(f"{info.common_name:<40} {info.status.value:<15} {days_str:>9} {serial}")
    return 0


def cmd_cert_issue(args: argparse.Namespace, config: Config) -> int:
    cn = args.cn
    sans: List[str] = args.san or []
    if cn not in sans:
        sans = [cn] + sans

    key = generate_private_key(args.key_size)
    csr = generate_csr(key, cn, sans, organization=args.org or "", country=args.country or "")

    ca_cert, ca_key = (None, None) if args.self_signed else _load_ca(config)
    cert = self_sign_certificate(key, csr, valid_days=args.days, ca_cert=ca_cert, ca_key=ca_key)

    config.cert_dir.mkdir(parents=True, exist_ok=True)
    safe_cn = cn.lstrip("*").lstrip(".")  # strip wildcard prefix for filenames
    info = save_certificate_bundle(
        config.cert_dir, safe_cn, cert, key, chain=None
    )

    store = CertificateStore(config.store_path)
    store.save(info)

    print(f"Certificate issued: {cn}")
    print(f"  Cert:  {info.cert_path}")
    print(f"  Key:   {info.key_path}")
    print(f"  Days:  {info.days_remaining}")
    print(f"  Serial:{info.serial}")
    return 0


def cmd_cert_renew(args: argparse.Namespace, config: Config) -> int:
    store = CertificateStore(config.store_path)
    info = store.get(args.cn)
    if info is None:
        print(f"Certificate not found in store: {args.cn}", file=sys.stderr)
        return 1

    key = generate_private_key(args.key_size)
    csr = generate_csr(key, info.common_name, info.sans)
    ca_cert, ca_key = _load_ca(config)
    cert = self_sign_certificate(key, csr, valid_days=args.days, ca_cert=ca_cert, ca_key=ca_key)

    config.cert_dir.mkdir(parents=True, exist_ok=True)
    safe_cn = info.common_name.lstrip("*").lstrip(".")
    new_info = save_certificate_bundle(config.cert_dir, safe_cn, cert, key)
    store.save(new_info)

    print(f"Certificate renewed: {info.common_name}")
    print(f"  New expiry: {new_info.not_after}")
    print(f"  Serial:     {new_info.serial}")
    return 0


def cmd_cert_show(args: argparse.Namespace, config: Config) -> int:
    store = CertificateStore(config.store_path)
    info = store.get(args.cn)
    if info is None:
        print(f"Certificate not found: {args.cn}", file=sys.stderr)
        return 1

    print(f"Common Name : {info.common_name}")
    print(f"SANs        : {', '.join(info.sans)}")
    print(f"Serial      : {info.serial}")
    print(f"Not Before  : {info.not_before}")
    print(f"Not After   : {info.not_after}")
    print(f"Days Left   : {info.days_remaining}")
    print(f"Status      : {info.status.value}")
    print(f"Fingerprint : {info.fingerprint_sha256}")
    print(f"Cert Path   : {info.cert_path}")
    print(f"Key Path    : {info.key_path}")
    return 0


def cmd_cert_revoke(args: argparse.Namespace, config: Config) -> int:
    store = CertificateStore(config.store_path)
    info = store.get(args.cn)
    if info is None:
        print(f"Certificate not found: {args.cn}", file=sys.stderr)
        return 1
    from chum.core.certificate import CertificateStatus

    info.status = CertificateStatus.REVOKED
    store.save(info)
    print(f"Certificate marked as revoked: {args.cn}")
    return 0


def cmd_deploy(args: argparse.Namespace, config: Config) -> int:
    manager = PluginManager(config.plugin_dir)
    manager.load_external_plugins()

    try:
        plugin_cls = manager.get(args.plugin)
    except PluginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    store = CertificateStore(config.store_path)
    info = store.get(args.cert)
    if info is None:
        print(f"Certificate '{args.cert}' not found in store.", file=sys.stderr)
        return 1

    if info.cert_path is None or not info.cert_path.exists():
        print(f"Certificate file missing for '{args.cert}'.", file=sys.stderr)
        return 1

    cert_pem = info.cert_path.read_bytes()
    key_pem = info.key_path.read_bytes() if info.key_path and info.key_path.exists() else b""
    chain_pem = info.chain_path.read_bytes() if info.chain_path and info.chain_path.exists() else None

    plugin = plugin_cls()
    kwargs = _plugin_kwargs(args)

    print(f"Deploying '{args.cert}' using plugin '{args.plugin}' to {kwargs.get('host', '?')} ...")
    result = plugin.deploy(cert_pem, key_pem, chain_pem=chain_pem, **kwargs)
    print(f"Result: {result}")
    return 0 if result.success else 1


def cmd_verify(args: argparse.Namespace, config: Config) -> int:
    manager = PluginManager(config.plugin_dir)
    manager.load_external_plugins()

    try:
        plugin_cls = manager.get(args.plugin)
    except PluginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    store = CertificateStore(config.store_path)
    info = store.get(args.cert)
    if info is None:
        print(f"Certificate '{args.cert}' not found in store.", file=sys.stderr)
        return 1

    if info.cert_path is None or not info.cert_path.exists():
        print(f"Certificate file missing for '{args.cert}'.", file=sys.stderr)
        return 1

    cert_pem = info.cert_path.read_bytes()
    plugin = plugin_cls()
    kwargs = _plugin_kwargs(args)

    print(f"Verifying '{args.cert}' on {kwargs.get('host', '?')} using plugin '{args.plugin}' ...")
    ok = plugin.verify(cert_pem, **kwargs)
    print("Verification:", "PASSED ✓" if ok else "FAILED ✗")
    return 0 if ok else 1


def cmd_plugin_list(args: argparse.Namespace, config: Config) -> int:
    manager = PluginManager(config.plugin_dir)
    manager.load_external_plugins()
    plugins = manager.list_plugins()
    if not plugins:
        print("No plugins registered.")
        return 0
    print(f"{'NAME':<20} {'DESCRIPTION'}")
    print("-" * 60)
    for name in plugins:
        cls = manager.get(name)
        print(f"{name:<20} {cls.DESCRIPTION}")
    return 0


def cmd_plugin_install(args: argparse.Namespace, config: Config) -> int:
    manager = PluginManager(config.plugin_dir)
    try:
        name = manager.install_plugin(args.git_url, name=getattr(args, "name", None))
        print(f"Plugin '{name}' installed successfully.")
        return 0
    except PluginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_plugin_update(args: argparse.Namespace, config: Config) -> int:
    manager = PluginManager(config.plugin_dir)
    try:
        manager.update_plugin(args.name)
        print(f"Plugin '{args.name}' updated.")
        return 0
    except PluginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_ca_init(args: argparse.Namespace, config: Config) -> int:
    cn = getattr(args, "cn", "Chum Internal CA")
    ca_cert, ca_key = generate_ca(common_name=cn, valid_days=args.days)

    out_dir = config.cert_dir / "ca"
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_cert_path = out_dir / "ca.crt"
    ca_key_path = out_dir / "ca.key"

    ca_cert_path.write_bytes(cert_to_pem(ca_cert))
    ca_key_path.write_bytes(private_key_to_pem(ca_key))
    import os

    os.chmod(ca_key_path, 0o600)

    print(f"CA initialised:")
    print(f"  Cert: {ca_cert_path}")
    print(f"  Key:  {ca_key_path}")
    print()
    print("Add the following to ~/.chum/config.yaml to use this CA:")
    print(f"  ca_cert_path: {ca_cert_path}")
    print(f"  ca_key_path:  {ca_key_path}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chum",
        description="Chum – Certificate Lifecycle Management",
    )
    parser.add_argument("--version", action="version", version=f"chum {__version__}")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to config file (default: ~/.chum/config.yaml)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ------------------------------------------------------------------
    # cert sub-commands
    # ------------------------------------------------------------------
    cert_parser = sub.add_parser("cert", help="Certificate management")
    cert_sub = cert_parser.add_subparsers(dest="cert_command", metavar="ACTION")
    cert_sub.required = True

    # cert list
    cert_sub.add_parser("list", help="List all managed certificates")

    # cert issue
    issue = cert_sub.add_parser("issue", help="Issue a new certificate")
    issue.add_argument("--cn", required=True, help="Common name (e.g. *.example.com)")
    issue.add_argument("--san", action="append", metavar="SAN", help="Subject alternative name (repeatable)")
    issue.add_argument("--days", type=int, default=90, help="Validity period in days (default 90)")
    issue.add_argument("--key-size", type=int, default=4096, dest="key_size")
    issue.add_argument("--org", help="Organisation name")
    issue.add_argument("--country", help="Country code")
    issue.add_argument("--self-signed", action="store_true", dest="self_signed", help="Issue a self-signed cert even if a CA is configured")

    # cert renew
    renew = cert_sub.add_parser("renew", help="Renew an existing certificate")
    renew.add_argument("cn", help="Common name of the certificate to renew")
    renew.add_argument("--days", type=int, default=90)
    renew.add_argument("--key-size", type=int, default=4096, dest="key_size")

    # cert show
    show = cert_sub.add_parser("show", help="Show certificate details")
    show.add_argument("cn", help="Common name")

    # cert revoke
    revoke = cert_sub.add_parser("revoke", help="Mark a certificate as revoked")
    revoke.add_argument("cn", help="Common name")

    # ------------------------------------------------------------------
    # deploy
    # ------------------------------------------------------------------
    deploy = sub.add_parser("deploy", help="Deploy a certificate to a device")
    deploy.add_argument("--plugin", required=True, help="Plugin name (e.g. proxmox)")
    deploy.add_argument("--cert", required=True, help="Common name of the certificate to deploy")
    deploy.add_argument("--host", help="Device hostname or IP")
    deploy.add_argument("--username", help="Device username")
    deploy.add_argument("--password", help="Device password")
    deploy.add_argument("--port", type=int)
    deploy.add_argument("--node", help="Proxmox node name")
    deploy.add_argument("--namespace", help="Kubernetes namespace")
    deploy.add_argument("--secret-name", dest="secret_name", help="Kubernetes secret name")
    deploy.add_argument("--token", help="Bearer token (OpenShift/Kubernetes)")
    deploy.add_argument("--api-url", dest="api_url", help="API server URL (OpenShift/Kubernetes)")
    deploy.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", default=None)
    deploy.add_argument("--option", "-o", action="append", metavar="KEY=VALUE", help="Extra plugin option")

    # ------------------------------------------------------------------
    # verify
    # ------------------------------------------------------------------
    verify = sub.add_parser("verify", help="Verify a deployed certificate")
    verify.add_argument("--plugin", required=True)
    verify.add_argument("--cert", required=True)
    verify.add_argument("--host")
    verify.add_argument("--username")
    verify.add_argument("--password")
    verify.add_argument("--port", type=int)
    verify.add_argument("--node")
    verify.add_argument("--namespace")
    verify.add_argument("--secret-name", dest="secret_name")
    verify.add_argument("--token")
    verify.add_argument("--api-url", dest="api_url")
    verify.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", default=None)
    verify.add_argument("--option", "-o", action="append", metavar="KEY=VALUE")

    # ------------------------------------------------------------------
    # plugin sub-commands
    # ------------------------------------------------------------------
    plugin_parser = sub.add_parser("plugin", help="Manage plugins")
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_command", metavar="ACTION")
    plugin_sub.required = True

    plugin_sub.add_parser("list", help="List available plugins")

    install = plugin_sub.add_parser("install", help="Install a plugin from a git repository")
    install.add_argument("git_url", metavar="GIT_URL", help="Git URL of the plugin")
    install.add_argument("--name", help="Override directory/name for the plugin")

    update = plugin_sub.add_parser("update", help="Update an installed plugin")
    update.add_argument("name", help="Plugin name")

    # ------------------------------------------------------------------
    # ca sub-commands
    # ------------------------------------------------------------------
    ca_parser = sub.add_parser("ca", help="Certificate Authority management")
    ca_sub = ca_parser.add_subparsers(dest="ca_command", metavar="ACTION")
    ca_sub.required = True

    ca_init = ca_sub.add_parser("init", help="Initialise a new internal CA")
    ca_init.add_argument("--cn", default="Chum Internal CA", help="CA common name")
    ca_init.add_argument("--days", type=int, default=3650, help="CA validity period in days")

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    config = Config(Path(args.config) if args.config else None)

    command = args.command

    if command == "cert":
        actions = {
            "list": cmd_cert_list,
            "issue": cmd_cert_issue,
            "renew": cmd_cert_renew,
            "show": cmd_cert_show,
            "revoke": cmd_cert_revoke,
        }
        handler = actions.get(args.cert_command)
        if handler is None:
            parser.error(f"Unknown cert action: {args.cert_command}")
        return handler(args, config)

    if command == "deploy":
        return cmd_deploy(args, config)

    if command == "verify":
        return cmd_verify(args, config)

    if command == "plugin":
        actions = {
            "list": cmd_plugin_list,
            "install": cmd_plugin_install,
            "update": cmd_plugin_update,
        }
        handler = actions.get(args.plugin_command)
        if handler is None:
            parser.error(f"Unknown plugin action: {args.plugin_command}")
        return handler(args, config)

    if command == "ca":
        ca_actions = {
            "init": cmd_ca_init,
        }
        handler = ca_actions.get(args.ca_command)
        if handler is None:
            parser.error(f"Unknown CA action: {args.ca_command}")
        return handler(args, config)

    parser.error(f"Unknown command: {command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
