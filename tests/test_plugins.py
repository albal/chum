"""
Tests for the built-in device plugins.

These tests mock HTTP calls so no real devices are needed.
"""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from chum.plugins.base import DeployResult
from chum.plugins.hp_printer import HPPrinterPlugin
from chum.plugins.proxmox import ProxmoxPlugin
from chum.plugins.openshift import OpenShiftPlugin
from chum.plugins.idrac import IDRACPlugin

# Minimal valid-looking PEM bytes (not a real cert/key but sufficient for mocking)
FAKE_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
FAKE_KEY_PEM = b"-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n"


# ---------------------------------------------------------------------------
# BasePlugin / DeployResult
# ---------------------------------------------------------------------------


def test_deploy_result_str_ok():
    r = DeployResult(success=True, message="Great")
    assert "[OK]" in str(r)
    assert "Great" in str(r)


def test_deploy_result_str_failed():
    r = DeployResult(success=False, message="Oops")
    assert "[FAILED]" in str(r)


# ---------------------------------------------------------------------------
# HP Printer plugin
# ---------------------------------------------------------------------------


class TestHPPrinterPlugin:
    def setup_method(self):
        self.plugin = HPPrinterPlugin()

    def test_plugin_metadata(self):
        assert self.plugin.NAME == "hp_printer"
        assert "HP" in self.plugin.DESCRIPTION

    def test_deploy_missing_host(self):
        result = self.plugin.deploy(FAKE_CERT_PEM, FAKE_KEY_PEM)
        assert not result.success
        assert "host" in result.message.lower()

    @patch("chum.plugins.hp_printer.requests")
    def test_deploy_success(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session
        session.post.return_value.status_code = 200
        session.post.return_value.raise_for_status = MagicMock()

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="192.168.1.10", password="admin"
        )
        assert result.success

    @patch("chum.plugins.hp_printer.requests")
    def test_deploy_failure_raises(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session
        session.post.side_effect = Exception("connection refused")

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="192.168.1.10", password="admin"
        )
        assert not result.success
        assert "connection refused" in result.message

    def test_revoke_not_supported(self):
        result = self.plugin.revoke(host="192.168.1.10")
        assert not result.success
        assert "not supported" in result.message.lower()

    def test_get_current_cert_missing_host(self):
        assert self.plugin.get_current_cert() is None

    @patch("ssl.get_server_certificate")
    def test_get_current_cert_success(self, mock_ssl):
        mock_ssl.return_value = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        result = self.plugin.get_current_cert(host="192.168.1.10")
        assert result is not None


# ---------------------------------------------------------------------------
# Proxmox plugin
# ---------------------------------------------------------------------------


class TestProxmoxPlugin:
    def setup_method(self):
        self.plugin = ProxmoxPlugin()

    def test_plugin_metadata(self):
        assert self.plugin.NAME == "proxmox"

    def test_deploy_missing_host(self):
        result = self.plugin.deploy(FAKE_CERT_PEM, FAKE_KEY_PEM)
        assert not result.success

    @patch("chum.plugins.proxmox.requests")
    def test_deploy_success(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session

        # Simulate ticket response
        auth_resp = MagicMock()
        auth_resp.json.return_value = {
            "data": {"ticket": "PVE:root@pam:ABCD", "CSRFPreventionToken": "TOKEN"}
        }
        auth_resp.raise_for_status = MagicMock()

        put_resp = MagicMock()
        put_resp.status_code = 200
        put_resp.raise_for_status = MagicMock()

        session.post.return_value = auth_resp
        session.put.return_value = put_resp

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="10.0.0.1", password="secret"
        )
        assert result.success

    @patch("chum.plugins.proxmox.requests")
    def test_authentication_failure(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session
        session.post.side_effect = Exception("401 Unauthorized")

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="10.0.0.1", password="wrong"
        )
        assert not result.success
        assert "Authentication" in result.message

    def test_revoke_missing_host(self):
        result = self.plugin.revoke()
        assert not result.success

    @patch("chum.plugins.proxmox.requests")
    def test_revoke_success(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session

        auth_resp = MagicMock()
        auth_resp.json.return_value = {
            "data": {"ticket": "PVE:root@pam:ABCD", "CSRFPreventionToken": "TOKEN"}
        }
        auth_resp.raise_for_status = MagicMock()
        session.post.return_value = auth_resp

        del_resp = MagicMock()
        del_resp.status_code = 200
        del_resp.raise_for_status = MagicMock()
        session.delete.return_value = del_resp

        result = self.plugin.revoke(host="10.0.0.1", password="secret")
        assert result.success


# ---------------------------------------------------------------------------
# OpenShift plugin
# ---------------------------------------------------------------------------


class TestOpenShiftPlugin:
    def setup_method(self):
        self.plugin = OpenShiftPlugin()

    def test_plugin_metadata(self):
        assert self.plugin.NAME == "openshift"

    def test_deploy_no_client(self):
        """Without api_url/token and without kubernetes package the client is None."""
        with patch.object(self.plugin, "_build_client", return_value=None):
            result = self.plugin.deploy(FAKE_CERT_PEM, FAKE_KEY_PEM)
            assert not result.success

    def _make_mock_client(self):
        """Create a fake session client that mimics the patched session."""
        client = MagicMock()
        get_resp = MagicMock()
        get_resp.status_code = 404

        put_resp = MagicMock()
        put_resp.status_code = 201

        post_resp = MagicMock()
        post_resp.status_code = 201

        patch_resp = MagicMock()
        patch_resp.status_code = 200

        client.get.return_value = get_resp
        client.post.return_value = post_resp
        client.put.return_value = put_resp
        client.patch.return_value = patch_resp
        return client

    def test_deploy_with_mock_client(self):
        mock_client = self._make_mock_client()
        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            result = self.plugin.deploy(
                FAKE_CERT_PEM,
                FAKE_KEY_PEM,
                api_url="https://api.cluster.example.com:6443",
                token="mytoken",
            )
            assert result.success

    def test_get_current_cert_not_found(self):
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(status_code=404)
        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            result = self.plugin.get_current_cert()
            assert result is None

    def test_revoke_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.delete.return_value = MagicMock(status_code=200)
        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            result = self.plugin.revoke()
            assert result.success


# ---------------------------------------------------------------------------
# Dell iDRAC plugin
# ---------------------------------------------------------------------------


class TestIDRACPlugin:
    def setup_method(self):
        self.plugin = IDRACPlugin()

    def test_plugin_metadata(self):
        assert self.plugin.NAME == "idrac"
        assert "iDRAC" in self.plugin.DESCRIPTION

    def test_deploy_missing_host(self):
        result = self.plugin.deploy(FAKE_CERT_PEM, FAKE_KEY_PEM)
        # No session is created without requests, but we can check graceful failure
        # If requests is available, we still need a host to avoid an empty URL
        assert result is not None  # should not crash

    @patch("chum.plugins.idrac.requests")
    def test_deploy_success_redfish(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session

        post_resp = MagicMock()
        post_resp.status_code = 200
        session.post.return_value = post_resp

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="10.0.0.2", password="calvin"
        )
        assert result.success

    @patch("chum.plugins.idrac.requests")
    def test_deploy_falls_back_to_scp(self, mock_requests):
        session = MagicMock()
        mock_requests.Session.return_value = session

        # First POST returns 404 (no Redfish ImportCertificate action)
        # Second POST also 404 (no /Certificates collection)
        # Falls back to SCP
        not_found = MagicMock()
        not_found.status_code = 404

        scp_resp = MagicMock()
        scp_resp.status_code = 202

        session.post.side_effect = [not_found, not_found, scp_resp]

        result = self.plugin.deploy(
            FAKE_CERT_PEM, FAKE_KEY_PEM, host="10.0.0.2", password="calvin"
        )
        assert result.success

    def test_revoke_not_supported(self):
        result = self.plugin.revoke(host="10.0.0.2")
        assert not result.success
        assert "not supported" in result.message.lower()

    def test_get_current_cert_missing_host(self):
        assert self.plugin.get_current_cert() is None

    @patch("ssl.get_server_certificate")
    def test_get_current_cert_success(self, mock_ssl):
        mock_ssl.return_value = (
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        )
        result = self.plugin.get_current_cert(host="10.0.0.2")
        assert result is not None


# ---------------------------------------------------------------------------
# Plugin verify() method tests
# ---------------------------------------------------------------------------


class TestHPPrinterVerify:
    """Tests for HPPrinterPlugin.verify() method."""

    def setup_method(self):
        self.plugin = HPPrinterPlugin()

    def test_verify_missing_host(self):
        """Test verify returns False when host is not provided."""
        result = self.plugin.verify(FAKE_CERT_PEM)
        assert result is False

    @patch("ssl.get_server_certificate")
    def test_verify_no_current_cert(self, mock_ssl):
        """Test verify returns False when no cert can be retrieved."""
        mock_ssl.side_effect = ssl.SSLError("Connection refused")
        result = self.plugin.verify(FAKE_CERT_PEM, host="192.168.1.10")
        assert result is False

    @patch("ssl.get_server_certificate")
    @patch("cryptography.x509.load_pem_x509_certificate")
    def test_verify_certificates_match(self, mock_load_cert, mock_ssl):
        """Test verify returns True when fingerprints match."""
        mock_ssl.return_value = FAKE_CERT_PEM.decode()

        mock_cert = MagicMock()
        mock_cert.fingerprint.return_value = b"matching_fingerprint"
        mock_load_cert.return_value = mock_cert

        result = self.plugin.verify(FAKE_CERT_PEM, host="192.168.1.10")
        assert result is True

    @patch("ssl.get_server_certificate")
    @patch("cryptography.x509.load_pem_x509_certificate")
    def test_verify_certificates_mismatch(self, mock_load_cert, mock_ssl):
        """Test verify returns False when fingerprints don't match."""
        mock_ssl.return_value = FAKE_CERT_PEM.decode()

        # Create different fingerprints
        mock_expected_cert = MagicMock()
        mock_expected_cert.fingerprint.return_value = b"expected_fingerprint"
        mock_actual_cert = MagicMock()
        mock_actual_cert.fingerprint.return_value = b"different_fingerprint"

        mock_load_cert.side_effect = [mock_expected_cert, mock_actual_cert]

        result = self.plugin.verify(FAKE_CERT_PEM, host="192.168.1.10")
        assert result is False

    @patch("ssl.get_server_certificate")
    @patch("cryptography.x509.load_pem_x509_certificate")
    def test_verify_handles_exception(self, mock_load_cert, mock_ssl):
        """Test verify returns False when certificate parsing fails."""
        mock_ssl.return_value = FAKE_CERT_PEM.decode()
        mock_load_cert.side_effect = ValueError("Invalid certificate")

        result = self.plugin.verify(FAKE_CERT_PEM, host="192.168.1.10")
        assert result is False


class TestProxmoxVerify:
    """Tests for ProxmoxPlugin.verify() method."""

    def setup_method(self):
        self.plugin = ProxmoxPlugin()

    def test_verify_missing_host(self):
        """Test verify returns False when host is not provided."""
        result = self.plugin.verify(FAKE_CERT_PEM)
        assert result is False

    @patch.object(ProxmoxPlugin, "get_current_cert")
    @patch("cryptography.x509.load_pem_x509_certificate")
    def test_verify_certificates_match(self, mock_load_cert, mock_get_cert):
        """Test verify returns True when fingerprints match."""
        mock_get_cert.return_value = FAKE_CERT_PEM

        mock_cert = MagicMock()
        mock_cert.fingerprint.return_value = b"matching_fingerprint"
        mock_load_cert.return_value = mock_cert

        result = self.plugin.verify(FAKE_CERT_PEM, host="10.0.0.1")
        assert result is True

    @patch.object(ProxmoxPlugin, "get_current_cert")
    def test_verify_no_current_cert(self, mock_get_cert):
        """Test verify returns False when no cert can be retrieved."""
        mock_get_cert.return_value = None

        result = self.plugin.verify(FAKE_CERT_PEM, host="10.0.0.1")
        assert result is False


class TestOpenShiftVerify:
    """Tests for OpenShiftPlugin.verify() method."""

    def setup_method(self):
        self.plugin = OpenShiftPlugin()

    def test_verify_no_client(self):
        """Test verify returns False when no client can be built."""
        with patch.object(self.plugin, "_build_client", return_value=None):
            result = self.plugin.verify(FAKE_CERT_PEM)
            assert result is False

    def test_verify_with_mock_client_cert_exists(self):
        """Test verify returns True when secret exists with matching cert."""
        mock_client = MagicMock()
        # Mock successful secret retrieval with matching cert
        import base64
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "tls.crt": base64.b64encode(FAKE_CERT_PEM).decode()
            }
        }
        mock_client.get.return_value = mock_resp

        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            # Mock the certificate loading to avoid real parsing
            with patch("cryptography.x509.load_pem_x509_certificate") as mock_load:
                mock_cert = MagicMock()
                mock_cert.fingerprint.return_value = b"matching_fingerprint"
                mock_load.return_value = mock_cert
                result = self.plugin.verify(FAKE_CERT_PEM)
                assert result is True

    def test_verify_with_mock_client_cert_not_found(self):
        """Test verify returns False when secret doesn't exist."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            result = self.plugin.verify(FAKE_CERT_PEM)
            assert result is False


class TestIDRACVerify:
    """Tests for IDRACPlugin.verify() method."""

    def setup_method(self):
        self.plugin = IDRACPlugin()

    def test_verify_missing_host(self):
        """Test verify returns False when host is not provided."""
        result = self.plugin.verify(FAKE_CERT_PEM)
        assert result is False

    @patch("ssl.get_server_certificate")
    @patch("cryptography.x509.load_pem_x509_certificate")
    def test_verify_certificates_match(self, mock_load_cert, mock_ssl):
        """Test verify returns True when fingerprints match."""
        mock_ssl.return_value = FAKE_CERT_PEM.decode()

        mock_cert = MagicMock()
        mock_cert.fingerprint.return_value = b"matching_fingerprint"
        mock_load_cert.return_value = mock_cert

        result = self.plugin.verify(FAKE_CERT_PEM, host="10.0.0.2")
        assert result is True

    @patch("ssl.get_server_certificate")
    def test_verify_no_current_cert(self, mock_ssl):
        """Test verify returns False when no cert can be retrieved."""
        mock_ssl.side_effect = ssl.SSLError("Connection refused")
        result = self.plugin.verify(FAKE_CERT_PEM, host="10.0.0.2")
        assert result is False


# ---------------------------------------------------------------------------
# Plugin get_current_cert() additional tests
# ---------------------------------------------------------------------------


class TestProxmoxGetCurrentCert:
    """Tests for ProxmoxPlugin.get_current_cert() method."""

    def setup_method(self):
        self.plugin = ProxmoxPlugin()

    def test_get_current_cert_missing_host(self):
        """Test get_current_cert returns None when host is missing."""
        result = self.plugin.get_current_cert()
        assert result is None

    @patch("chum.plugins.proxmox.requests")
    def test_get_current_cert_success(self, mock_requests):
        """Test get_current_cert retrieves certificate successfully."""
        session = MagicMock()
        mock_requests.Session.return_value = session

        # Mock auth response
        auth_resp = MagicMock()
        auth_resp.json.return_value = {
            "data": {"ticket": "PVE:root@pam:ABCD", "CSRFPreventionToken": "TOKEN"}
        }
        auth_resp.raise_for_status = MagicMock()
        session.post.return_value = auth_resp

        # Mock cert retrieval - data is a list of cert entries
        get_resp = MagicMock()
        get_resp.json.return_value = {
            "data": [
                {"filename": "pve-ssl.pem", "pem": FAKE_CERT_PEM.decode()}
            ]
        }
        get_resp.raise_for_status = MagicMock()
        session.get.return_value = get_resp

        result = self.plugin.get_current_cert(host="10.0.0.1", password="secret")
        assert result is not None

    @patch("chum.plugins.proxmox.requests")
    def test_get_current_cert_auth_failure(self, mock_requests):
        """Test get_current_cert returns None on auth failure."""
        session = MagicMock()
        mock_requests.Session.return_value = session
        session.post.side_effect = Exception("401 Unauthorized")

        result = self.plugin.get_current_cert(host="10.0.0.1", password="wrong")
        assert result is None


class TestOpenShiftGetCurrentCert:
    """Tests for OpenShiftPlugin.get_current_cert() method."""

    def setup_method(self):
        self.plugin = OpenShiftPlugin()

    def test_get_current_cert_no_client(self):
        """Test get_current_cert returns None when no client."""
        with patch.object(self.plugin, "_build_client", return_value=None):
            result = self.plugin.get_current_cert()
            assert result is None

    def test_get_current_cert_secret_exists(self):
        """Test get_current_cert returns cert from existing secret."""
        import base64
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "tls.crt": base64.b64encode(FAKE_CERT_PEM).decode()
            }
        }
        mock_client.get.return_value = mock_resp

        with patch.object(self.plugin, "_build_client", return_value=mock_client):
            result = self.plugin.get_current_cert()
            assert result is not None

