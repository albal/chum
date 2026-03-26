"""
Tests for chum.core.config module.

These tests cover:
- Config initialization with various paths
- Environment variable precedence over file values
- All config properties (paths, ACME settings, CA settings, etc.)
- _try_load_yaml helper function with YAML and JSON parsing
- Edge cases (missing files, invalid content, etc.)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from chum.core.config import Config, _try_load_yaml


# ---------------------------------------------------------------------------
# _try_load_yaml tests
# ---------------------------------------------------------------------------


def test_try_load_yaml_nonexistent_file(tmp_path):
    """Test _try_load_yaml returns empty dict for nonexistent file."""
    result = _try_load_yaml(tmp_path / "nonexistent.yaml")
    assert result == {}


def test_try_load_yaml_empty_file(tmp_path):
    """Test _try_load_yaml returns empty dict for empty file."""
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("")
    result = _try_load_yaml(empty_file)
    assert result == {}


def test_try_load_yaml_json_fallback(tmp_path):
    """Test _try_load_yaml falls back to JSON when YAML not installed."""
    json_file = tmp_path / "config.json"
    json_file.write_text(json.dumps({"key": "value"}))

    # Mock yaml import failure
    with patch.dict("sys.modules", {"yaml": None}):
        result = _try_load_yaml(json_file)
    assert result == {"key": "value"}


def test_try_load_yaml_valid_json(tmp_path):
    """Test _try_load_yaml parses valid JSON."""
    json_file = tmp_path / "config.json"
    json_file.write_text('{"store_path": "/custom/store.json"}')

    result = _try_load_yaml(json_file)
    assert result["store_path"] == "/custom/store.json"


def test_try_load_yaml_invalid_json(tmp_path, caplog):
    """Test _try_load_yaml handles invalid JSON gracefully."""
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{ this is not valid json }")

    # Remove yaml to ensure JSON parsing is attempted
    with patch.dict("sys.modules", {"yaml": None}):
        result = _try_load_yaml(invalid_file)
    assert result == {}
    # Should have logged a warning
    assert "Could not parse" in caplog.text


def test_try_load_yaml_with_yaml_installed(tmp_path):
    """Test _try_load_yaml uses YAML parser if available."""
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("key: value\nlist:\n  - item1\n  - item2")

    # This test only works if pyyaml is installed
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed")

    result = _try_load_yaml(yaml_file)
    assert result["key"] == "value"
    assert result["list"] == ["item1", "item2"]


# ---------------------------------------------------------------------------
# Config initialization tests
# ---------------------------------------------------------------------------


def test_config_init_default_path():
    """Test Config uses default path when none provided."""
    # Clear CHUM_CONFIG env var to ensure default is used
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml") as mock_load:
            mock_load.return_value = {}
            config = Config()
            # Should have called with default path
            assert mock_load.called


def test_config_init_custom_path(tmp_path):
    """Test Config uses provided path."""
    config_file = tmp_path / "custom.yaml"
    config_file.write_text('{"store_path": "/custom/path.json"}')

    config = Config(path=config_file)
    assert config._data.get("store_path") == "/custom/path.json"


def test_config_init_env_var_config_path(tmp_path):
    """Test Config respects CHUM_CONFIG environment variable."""
    config_file = tmp_path / "env_config.yaml"
    config_file.write_text('{"acme_email": "env@example.com"}')

    with patch.dict(os.environ, {"CHUM_CONFIG": str(config_file)}):
        config = Config()
    assert config._data.get("acme_email") == "env@example.com"


# ---------------------------------------------------------------------------
# Core path property tests
# ---------------------------------------------------------------------------


def test_store_path_default():
    """Test store_path returns default when not configured."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert str(config.store_path).endswith("store.json")
            assert ".chum" in str(config.store_path)


def test_store_path_from_file(tmp_path):
    """Test store_path reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"store_path": "/custom/store.json"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.store_path == Path("/custom/store.json")


def test_store_path_env_var_precedence(tmp_path):
    """Test CHUM_STORE_PATH env var takes precedence over file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"store_path": "/file/store.json"}')

    with patch.dict(os.environ, {"CHUM_STORE_PATH": "/env/store.json"}):
        config = Config(path=config_file)
        assert config.store_path == Path("/env/store.json")


def test_plugin_dir_default():
    """Test plugin_dir returns default when not configured."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert "plugins" in str(config.plugin_dir)


def test_plugin_dir_from_env():
    """Test plugin_dir respects CHUM_PLUGIN_DIR env var."""
    with patch.dict(os.environ, {"CHUM_PLUGIN_DIR": "/custom/plugins"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.plugin_dir == Path("/custom/plugins")


def test_cert_dir_default():
    """Test cert_dir returns default when not configured."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert "certs" in str(config.cert_dir)


def test_cert_dir_from_env():
    """Test cert_dir respects CHUM_CERT_DIR env var."""
    with patch.dict(os.environ, {"CHUM_CERT_DIR": "/my/certs"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.cert_dir == Path("/my/certs")


# ---------------------------------------------------------------------------
# ACME property tests
# ---------------------------------------------------------------------------


def test_acme_email_default_none():
    """Test acme_email returns None when not configured."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_email is None


def test_acme_email_from_file(tmp_path):
    """Test acme_email reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_email": "file@example.com"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.acme_email == "file@example.com"


def test_acme_email_env_var_precedence(tmp_path):
    """Test CHUM_ACME_EMAIL env var takes precedence."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_email": "file@example.com"}')

    with patch.dict(os.environ, {"CHUM_ACME_EMAIL": "env@example.com"}):
        config = Config(path=config_file)
        assert config.acme_email == "env@example.com"


def test_acme_directory_url_default():
    """Test acme_directory_url returns Let's Encrypt production URL by default."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert "letsencrypt" in config.acme_directory_url
    assert "staging" not in config.acme_directory_url


def test_acme_directory_url_from_env():
    """Test acme_directory_url respects env var."""
    with patch.dict(os.environ, {"CHUM_ACME_DIRECTORY_URL": "https://custom.acme/dir"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_directory_url == "https://custom.acme/dir"


def test_acme_staging_default_false():
    """Test acme_staging defaults to False."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is False


def test_acme_staging_from_file_true(tmp_path):
    """Test acme_staging reads from config file (true)."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_staging": true}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.acme_staging is True


def test_acme_staging_env_var_true():
    """Test CHUM_ACME_STAGING env var with 'true'."""
    with patch.dict(os.environ, {"CHUM_ACME_STAGING": "true"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is True


def test_acme_staging_env_var_1():
    """Test CHUM_ACME_STAGING env var with '1'."""
    with patch.dict(os.environ, {"CHUM_ACME_STAGING": "1"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is True


def test_acme_staging_env_var_yes():
    """Test CHUM_ACME_STAGING env var with 'yes'."""
    with patch.dict(os.environ, {"CHUM_ACME_STAGING": "yes"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is True


def test_acme_staging_env_var_false():
    """Test CHUM_ACME_STAGING env var with 'false'."""
    with patch.dict(os.environ, {"CHUM_ACME_STAGING": "false"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is False


def test_acme_staging_env_var_0():
    """Test CHUM_ACME_STAGING env var with '0'."""
    with patch.dict(os.environ, {"CHUM_ACME_STAGING": "0"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_staging is False


def test_acme_challenge_type_default():
    """Test acme_challenge_type defaults to 'dns-01'."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_challenge_type == "dns-01"


def test_acme_challenge_type_from_file(tmp_path):
    """Test acme_challenge_type reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_challenge_type": "dns-persist-01"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.acme_challenge_type == "dns-persist-01"


def test_acme_challenge_type_from_env():
    """Test acme_challenge_type respects CHUM_ACME_CHALLENGE_TYPE."""
    with patch.dict(os.environ, {"CHUM_ACME_CHALLENGE_TYPE": "dns-persist-01"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_challenge_type == "dns-persist-01"


def test_acme_persist_policy_default_none():
    """Test acme_persist_policy defaults to None."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_persist_policy is None


def test_acme_persist_policy_from_file(tmp_path):
    """Test acme_persist_policy reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_persist_policy": "wildcard"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.acme_persist_policy == "wildcard"


def test_acme_persist_policy_from_env():
    """Test acme_persist_policy respects CHUM_ACME_PERSIST_POLICY."""
    with patch.dict(os.environ, {"CHUM_ACME_PERSIST_POLICY": "subdomain"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_persist_policy == "subdomain"


def test_acme_persist_until_default_none():
    """Test acme_persist_until defaults to None."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_persist_until is None


def test_acme_persist_until_from_file(tmp_path):
    """Test acme_persist_until reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"acme_persist_until": "2027-12-01T00:00:00Z"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.acme_persist_until == "2027-12-01T00:00:00Z"


def test_acme_persist_until_from_env():
    """Test acme_persist_until respects CHUM_ACME_PERSIST_UNTIL."""
    with patch.dict(os.environ, {"CHUM_ACME_PERSIST_UNTIL": "2028-01-01T00:00:00Z"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.acme_persist_until == "2028-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# CA property tests
# ---------------------------------------------------------------------------


def test_ca_cert_path_default_none():
    """Test ca_cert_path defaults to None."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.ca_cert_path is None


def test_ca_cert_path_from_file(tmp_path):
    """Test ca_cert_path reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"ca_cert_path": "/path/to/ca.crt"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.ca_cert_path == Path("/path/to/ca.crt")


def test_ca_cert_path_from_env():
    """Test ca_cert_path respects CHUM_CA_CERT_PATH."""
    with patch.dict(os.environ, {"CHUM_CA_CERT_PATH": "/env/ca.crt"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.ca_cert_path == Path("/env/ca.crt")


def test_ca_key_path_default_none():
    """Test ca_key_path defaults to None."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.ca_key_path is None


def test_ca_key_path_from_file(tmp_path):
    """Test ca_key_path reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"ca_key_path": "/path/to/ca.key"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.ca_key_path == Path("/path/to/ca.key")


def test_ca_key_path_from_env():
    """Test ca_key_path respects CHUM_CA_KEY_PATH."""
    with patch.dict(os.environ, {"CHUM_CA_KEY_PATH": "/env/ca.key"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.ca_key_path == Path("/env/ca.key")


# ---------------------------------------------------------------------------
# Expiry warning tests
# ---------------------------------------------------------------------------


def test_expiry_warning_days_default():
    """Test expiry_warning_days defaults to 30."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.expiry_warning_days == 30


def test_expiry_warning_days_from_file(tmp_path):
    """Test expiry_warning_days reads from config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"expiry_warning_days": 14}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.expiry_warning_days == 14


def test_expiry_warning_days_from_env():
    """Test expiry_warning_days respects CHUM_EXPIRY_WARNING_DAYS."""
    with patch.dict(os.environ, {"CHUM_EXPIRY_WARNING_DAYS": "7"}):
        with patch("chum.core.config._try_load_yaml", return_value={}):
            config = Config()
            assert config.expiry_warning_days == 7


def test_expiry_warning_days_string_from_file(tmp_path):
    """Test expiry_warning_days handles string values in file."""
    config_file = tmp_path / "config.yaml"
    # JSON numbers come through as ints, but we test string handling
    config_file.write_text('{"expiry_warning_days": "21"}')

    with patch.dict(os.environ, {}, clear=True):
        config = Config(path=config_file)
    assert config.expiry_warning_days == 21


# ---------------------------------------------------------------------------
# Raw access tests
# ---------------------------------------------------------------------------


def test_get_existing_key(tmp_path):
    """Test get() returns value for existing key."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text('{"custom_key": "custom_value"}')

    config = Config(path=config_file)
    assert config.get("custom_key") == "custom_value"


def test_get_missing_key_with_default():
    """Test get() returns default for missing key."""
    with patch("chum.core.config._try_load_yaml", return_value={}):
        config = Config()
    assert config.get("nonexistent", "default_val") == "default_val"


def test_get_missing_key_without_default():
    """Test get() returns None for missing key without default."""
    with patch("chum.core.config._try_load_yaml", return_value={}):
        config = Config()
    assert config.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


def test_config_with_nested_yaml(tmp_path):
    """Test Config handles nested structures in YAML."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed")

    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
acme_email: nested@example.com
custom:
  nested:
    key: value
""")

    config = Config(path=config_file)
    assert config.acme_email == "nested@example.com"
    assert config.get("custom") == {"nested": {"key": "value"}}


def test_config_env_var_precedence_for_all_settings(tmp_path):
    """Test that environment variables take precedence for multiple settings at once."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""{
        "store_path": "/file/store.json",
        "plugin_dir": "/file/plugins",
        "cert_dir": "/file/certs",
        "acme_email": "file@example.com"
    }""")

    env = {
        "CHUM_STORE_PATH": "/env/store.json",
        "CHUM_PLUGIN_DIR": "/env/plugins",
        "CHUM_CERT_DIR": "/env/certs",
        "CHUM_ACME_EMAIL": "env@example.com",
    }
    with patch.dict(os.environ, env):
        config = Config(path=config_file)
        assert config.store_path == Path("/env/store.json")
        assert config.plugin_dir == Path("/env/plugins")
        assert config.cert_dir == Path("/env/certs")
        assert config.acme_email == "env@example.com"
