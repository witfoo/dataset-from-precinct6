"""Configuration — 100% environment-variable driven.

All configuration is loaded from environment variables, a .env file, or
customer_config.json. No secrets, credentials, customer names, IPs, or
domains are hardcoded in this file or anywhere in the codebase.

Loading priority (highest wins):
1. Environment variables
2. .env file in project root
3. customer_config.json in project root
4. Built-in defaults (only for non-sensitive values)
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Project root (directory containing pyproject.toml or .env)
PROJECT_ROOT = Path.cwd()

# Load .env if present
_env_path = PROJECT_ROOT / ".env"
if _env_path.exists():
    load_dotenv(_env_path)


# =============================================================================
# API Keys (from environment only — never hardcoded)
# =============================================================================

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
HF_TOKEN = os.getenv("HF_TOKEN", "")


# =============================================================================
# Cassandra Connection (from environment only)
# =============================================================================

CASSANDRA_HOST = os.getenv("CASSANDRA_HOST", "")
CASSANDRA_PORT = int(os.getenv("CASSANDRA_PORT", "9042"))
CASSANDRA_USER = os.getenv("CASSANDRA_USER", "")
CASSANDRA_PASSWORD = os.getenv("CASSANDRA_PASSWORD", "")
CASSANDRA_SSL = os.getenv("CASSANDRA_SSL", "true").lower() in ("true", "1", "yes")
CASSANDRA_FETCH_SIZE = int(os.getenv("CASSANDRA_FETCH_SIZE", "1000"))


# =============================================================================
# Customer-Specific Mappings (from customer_config.json or environment)
# =============================================================================

def _load_customer_config() -> dict:
    """Load customer_config.json if it exists."""
    config_path = PROJECT_ROOT / "customer_config.json"
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
        # Strip _comment keys
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return {}


_customer_config = _load_customer_config()

# Organization slug -> sanitized name (e.g., {"my_org": "ORG-0001"})
KNOWN_ORGS: dict[str, str] = {}
_orgs_env = os.getenv("ORGS", "")
if _orgs_env:
    try:
        KNOWN_ORGS = json.loads(_orgs_env)
    except json.JSONDecodeError:
        pass
elif "organizations" in _customer_config:
    KNOWN_ORGS = _customer_config["organizations"]

# Organization display names -> sanitized name
KNOWN_ORG_DISPLAY: dict[str, str] = {}
_org_display_env = os.getenv("ORG_DISPLAY_NAMES", "")
if _org_display_env:
    try:
        KNOWN_ORG_DISPLAY = json.loads(_org_display_env)
    except json.JSONDecodeError:
        pass
elif "organization_display_names" in _customer_config:
    KNOWN_ORG_DISPLAY = _customer_config["organization_display_names"]

# Customer domains to sanitize
KNOWN_DOMAINS: list[str] = []
_domains_env = os.getenv("CUSTOMER_DOMAINS", "")
if _domains_env:
    KNOWN_DOMAINS = [d.strip() for d in _domains_env.split(",") if d.strip()]
elif "customer_domains" in _customer_config:
    KNOWN_DOMAINS = [d for d in _customer_config["customer_domains"] if not d.startswith("_")]

# Organization ID integer mappings
KNOWN_ORG_IDS: dict[int, int] = {}
_org_ids_env = os.getenv("ORG_ID_MAPPINGS", "")
if _org_ids_env:
    try:
        KNOWN_ORG_IDS = {int(k): int(v) for k, v in json.loads(_org_ids_env).items()}
    except (json.JSONDecodeError, ValueError):
        pass
elif "organization_ids" in _customer_config:
    raw = _customer_config["organization_ids"]
    KNOWN_ORG_IDS = {int(k): int(v) for k, v in raw.items() if not str(k).startswith("_")}


# =============================================================================
# Data Directories
# =============================================================================

DATA_DIR = Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data")))
RAW_DIR = Path(os.getenv("RAW_DIR", str(DATA_DIR / "raw")))
SANITIZED_DIR = Path(os.getenv("SANITIZED_DIR", str(DATA_DIR / "sanitized")))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(DATA_DIR / "output")))
GRAPH_OUTPUT_DIR = OUTPUT_DIR / "graph"
SIGNAL_OUTPUT_DIR = OUTPUT_DIR / "signal"
REGISTRY_DB_PATH = DATA_DIR / "pii_registry.db"


# =============================================================================
# Sanitization Settings
# =============================================================================

CLAUDE_REVIEW_MODEL = os.getenv("CLAUDE_REVIEW_MODEL", "claude-sonnet-4-20250514")
CLAUDE_REVIEW_SAMPLE_RATE = float(os.getenv("CLAUDE_REVIEW_SAMPLE_RATE", "0.05"))
CLAUDE_REVIEW_BATCH_SIZE = int(os.getenv("CLAUDE_REVIEW_BATCH_SIZE", "5"))
CLAUDE_REVIEW_CONCURRENCY = int(os.getenv("CLAUDE_REVIEW_CONCURRENCY", "5"))
CLAUDE_ESCALATION_THRESHOLD = float(os.getenv("CLAUDE_ESCALATION_THRESHOLD", "0.02"))

ML_NER_CONFIDENCE_THRESHOLD = float(os.getenv("ML_NER_CONFIDENCE_THRESHOLD", "0.75"))
PRESIDIO_SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.5"))

# Lead rules catalog
LEAD_RULES_CATALOG = Path(os.getenv("LEAD_RULES_CATALOG", str(DATA_DIR / "lead_rules_catalog.json")))


# =============================================================================
# Validation
# =============================================================================

def validate_config(require_cassandra: bool = False, require_anthropic: bool = False):
    """Validate that required configuration is present.

    Call this before operations that need specific config values.
    Raises SystemExit with a helpful message if required values are missing.
    """
    errors = []

    if require_cassandra:
        if not CASSANDRA_HOST:
            errors.append("CASSANDRA_HOST is required. Set it in .env or as an environment variable.")
        if not CASSANDRA_USER:
            errors.append("CASSANDRA_USER is required. Set it in .env or as an environment variable.")
        if not CASSANDRA_PASSWORD:
            errors.append("CASSANDRA_PASSWORD is required. Set it in .env or as an environment variable.")

    if require_anthropic:
        if not ANTHROPIC_API_KEY:
            errors.append("ANTHROPIC_API_KEY is required for Claude review. Set it in .env or as an environment variable.")

    if errors:
        print("Configuration errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(f"\nSee .env.example for all configuration options.", file=sys.stderr)
        sys.exit(1)
