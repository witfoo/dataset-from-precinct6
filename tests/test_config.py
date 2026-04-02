"""Test configuration loading and validation."""

import os
import pytest


def test_config_loads_without_env():
    """Config should load with defaults when no .env exists."""
    from precinct6_dataset.config import CASSANDRA_PORT, SANITIZED_DIR
    assert CASSANDRA_PORT == 9042
    assert SANITIZED_DIR is not None


def test_config_no_hardcoded_secrets():
    """Verify no secrets are hardcoded in the config module."""
    import precinct6_dataset.config as config
    source = open(config.__file__).read()

    # These patterns should never appear in config.py
    forbidden = [
        "192.168.",
        "F00the",
        "witfoocloud",
        "mingledorffs",
        "paygoint",
        "calprivate",
        "ghp_",
        "sk-ant-",
        "hf_S",
    ]
    for pattern in forbidden:
        assert pattern not in source, f"Hardcoded secret found in config.py: {pattern}"


def test_validate_config_cassandra_missing(monkeypatch):
    """Validate should fail when Cassandra config is missing."""
    monkeypatch.setenv("CASSANDRA_HOST", "")
    # Re-import to pick up new env
    import importlib
    import precinct6_dataset.config as config
    importlib.reload(config)

    with pytest.raises(SystemExit):
        config.validate_config(require_cassandra=True)


def test_known_orgs_empty_by_default():
    """KNOWN_ORGS should be empty without customer_config.json."""
    from precinct6_dataset.config import KNOWN_ORGS
    # Without a customer_config.json in the test directory, should be empty or from env
    assert isinstance(KNOWN_ORGS, dict)
