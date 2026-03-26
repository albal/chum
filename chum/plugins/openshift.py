"""
OpenShift / Kubernetes plugin.

Deploys TLS certificates to OpenShift clusters by creating or updating
a ``kubernetes.io/tls`` Secret and, optionally, patching the default
router ingress certificate.

This plugin supports two modes:

1. **Secret mode** (default): create/update a named Secret.
2. **Router mode**: patch the OpenShift Ingress operator's
   ``defaultCertificate`` to point at the new Secret, replacing the
   wildcard cert used by all Routes.

Connection parameters (passed as **kwargs):

kubeconfig : str, optional
    Path to a kubeconfig file.  Falls back to the in-cluster service
    account if omitted.
context : str, optional
    Kubeconfig context to use.
namespace : str, optional
    Target namespace for the Secret (default ``"openshift-ingress"``).
secret_name : str, optional
    Name of the TLS secret (default ``"custom-router-cert"``).
patch_router : bool, optional
    When ``True`` (default for OpenShift), also patch the IngressController
    to use the new secret as its defaultCertificate.
api_url : str, optional
    Alternative approach: direct API server URL.
token : str, optional
    Bearer token for direct API access.
verify_ssl : bool, optional
    Verify the API server certificate (default ``True``).
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from chum.plugins.base import BasePlugin, DeployResult

log = logging.getLogger(__name__)


class OpenShiftPlugin(BasePlugin):
    """Certificate deployment plugin for OpenShift / Kubernetes clusters."""

    NAME = "openshift"
    DESCRIPTION = "Deploy wildcard certificates to OpenShift clusters via the Kubernetes API"
    VERSION = "0.1.0"

    # OpenShift-specific IngressController API path
    _INGRESS_API = (
        "/apis/operator.openshift.io/v1/namespaces/openshift-ingress-operator/ingresscontrollers/default"
    )

    def deploy(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None,
        **kwargs: Any,
    ) -> DeployResult:
        """Create/update a TLS Secret and optionally patch the IngressController."""
        client = self._build_client(**kwargs)
        if client is None:
            return DeployResult(
                success=False,
                message="Could not build Kubernetes API client. Check kubeconfig or token.",
            )

        namespace = kwargs.get("namespace", "openshift-ingress")
        secret_name = kwargs.get("secret_name", "custom-router-cert")

        combined_cert = cert_pem
        if chain_pem:
            combined_cert = cert_pem + chain_pem

        cert_b64 = base64.b64encode(combined_cert).decode()
        key_b64 = base64.b64encode(key_pem).decode()

        secret_body = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": secret_name, "namespace": namespace},
            "type": "kubernetes.io/tls",
            "data": {"tls.crt": cert_b64, "tls.key": key_b64},
        }

        try:
            result = self._apply_secret(client, namespace, secret_name, secret_body)
            if not result.success:
                return result

            if kwargs.get("patch_router", True):
                patch_result = self._patch_ingress_controller(client, secret_name, namespace)
                if not patch_result.success:
                    return DeployResult(
                        success=False,
                        message=(
                            f"Secret created but IngressController patch failed: "
                            f"{patch_result.message}"
                        ),
                    )

            return DeployResult(
                success=True,
                message=f"Certificate deployed to OpenShift cluster (secret: {namespace}/{secret_name})",
                details={"namespace": namespace, "secret_name": secret_name},
            )
        except Exception as exc:  # noqa: BLE001
            log.error("OpenShift deployment failed: %s", exc)
            return DeployResult(success=False, message=str(exc))

    def get_current_cert(self, **kwargs: Any) -> Optional[bytes]:
        """Fetch the TLS certificate from the named Secret."""
        client = self._build_client(**kwargs)
        if client is None:
            return None

        namespace = kwargs.get("namespace", "openshift-ingress")
        secret_name = kwargs.get("secret_name", "custom-router-cert")

        try:
            resp = client.get(f"/api/v1/namespaces/{namespace}/secrets/{secret_name}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json().get("data", {})
            cert_b64 = data.get("tls.crt")
            if cert_b64:
                return base64.b64decode(cert_b64)
        except Exception as exc:  # noqa: BLE001
            log.warning("OpenShift get_current_cert error: %s", exc)
        return None

    def verify(self, cert_pem: bytes, **kwargs: Any) -> bool:
        """Check that the Secret's certificate matches *cert_pem*."""
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
            log.warning("OpenShift verify error: %s", exc)
            return False

    def revoke(self, **kwargs: Any) -> DeployResult:
        """Delete the TLS Secret from the cluster."""
        client = self._build_client(**kwargs)
        if client is None:
            return DeployResult(success=False, message="Could not build Kubernetes API client")

        namespace = kwargs.get("namespace", "openshift-ingress")
        secret_name = kwargs.get("secret_name", "custom-router-cert")

        try:
            resp = client.delete(f"/api/v1/namespaces/{namespace}/secrets/{secret_name}")
            if resp.status_code in (200, 204, 404):
                return DeployResult(
                    success=True,
                    message=f"Secret {namespace}/{secret_name} deleted",
                )
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.error("OpenShift revoke error: %s", exc)
            return DeployResult(success=False, message=str(exc))
        return DeployResult(success=True, message="Revoked")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_client(self, **kwargs: Any) -> Optional[Any]:
        """Return a simple requests Session configured for the API server."""
        if requests is None:
            log.error("'requests' package is required")
            return None

        api_url = kwargs.get("api_url")
        token = kwargs.get("token")
        verify_ssl = kwargs.get("verify_ssl", True)

        if api_url and token:
            session = requests.Session()
            session.verify = verify_ssl
            session.headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )
            session.base_url = api_url  # type: ignore[attr-defined]
            # Monkey-patch HTTP methods to prepend base_url
            _orig_get = session.get
            _orig_post = session.post
            _orig_put = session.put
            _orig_patch = session.patch
            _orig_delete = session.delete

            def _get(path: str, **kw: Any):
                return _orig_get(api_url + path, **kw)

            def _post(path: str, **kw: Any):
                return _orig_post(api_url + path, **kw)

            def _put(path: str, **kw: Any):
                return _orig_put(api_url + path, **kw)

            def _patch(path: str, **kw: Any):
                return _orig_patch(api_url + path, **kw)

            def _delete(path: str, **kw: Any):
                return _orig_delete(api_url + path, **kw)

            session.get = _get  # type: ignore[method-assign]
            session.post = _post  # type: ignore[method-assign]
            session.put = _put  # type: ignore[method-assign]
            session.patch = _patch  # type: ignore[method-assign]
            session.delete = _delete  # type: ignore[method-assign]
            return session

        # Fall back to kubeconfig via kubernetes python client
        kubeconfig = kwargs.get("kubeconfig")
        context = kwargs.get("context")
        try:
            from kubernetes import client as k8s_client, config as k8s_config  # type: ignore  # noqa: PLC0415

            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig, context=context)
            else:
                try:
                    k8s_config.load_incluster_config()
                except k8s_config.ConfigException:
                    k8s_config.load_kube_config(context=context)
            return k8s_client.CoreV1Api()
        except ImportError:
            log.error("'kubernetes' package required when not using api_url/token")
        except Exception as exc:  # noqa: BLE001
            log.error("Could not load kubeconfig: %s", exc)
        return None

    @staticmethod
    def _apply_secret(client: Any, namespace: str, name: str, body: dict) -> DeployResult:
        """Create or replace a Kubernetes Secret."""
        import json  # noqa: PLC0415

        path = f"/api/v1/namespaces/{namespace}/secrets/{name}"
        resp = client.get(path)
        if resp.status_code == 404:
            resp = client.post(f"/api/v1/namespaces/{namespace}/secrets", json=body)
        else:
            resp = client.put(path, json=body)

        if resp.status_code in (200, 201):
            return DeployResult(success=True, message="Secret applied")
        return DeployResult(
            success=False,
            message=f"Failed to apply secret: HTTP {resp.status_code} {resp.text}",
        )

    @staticmethod
    def _patch_ingress_controller(client: Any, secret_name: str, namespace: str) -> DeployResult:
        """Patch the OpenShift default IngressController to use *secret_name*."""
        patch = {
            "spec": {
                "defaultCertificate": {"name": secret_name},
            }
        }
        resp = client.patch(
            OpenShiftPlugin._INGRESS_API,
            json=patch,
            headers={"Content-Type": "application/merge-patch+json"},
        )
        if resp.status_code in (200, 201):
            return DeployResult(success=True, message="IngressController patched")
        return DeployResult(
            success=False,
            message=f"IngressController patch failed: HTTP {resp.status_code} {resp.text}",
        )
