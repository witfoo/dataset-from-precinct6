"""PII Mapping Registry — SQLite-backed consistent mapping of real to sanitized values.

Every real PII value maps to exactly one sanitized replacement. The same real value
always produces the same sanitized output, preserving graph topology and relationships.
"""

import hashlib
import hmac
import ipaddress
import os
import sqlite3
import struct
from pathlib import Path
from typing import Optional

from precinct6_dataset.config import REGISTRY_DB_PATH


# Secret key for deterministic IP mapping.
# Set REGISTRY_SECRET env var for reproducible mappings across runs.
# If unset, a random key is generated (non-reproducible but secure).
_env_secret = os.getenv("REGISTRY_SECRET", "")
_DEFAULT_SECRET = _env_secret.encode() if _env_secret else os.urandom(32)


class PIIRegistry:
    """Thread-safe, persistent mapping of original PII values to sanitized replacements."""

    CATEGORIES = [
        "org", "domain", "ipv4_priv", "ipv4_pub", "hostname", "fqdn",
        "username", "email", "sid", "aws_account", "arn", "machine_account",
        "credential", "org_id", "agent_id",
    ]

    def __init__(self, db_path: Path = None, secret: bytes = None):
        self.db_path = db_path or REGISTRY_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.secret = secret or _DEFAULT_SECRET
        self._conn = None
        self._counters = {}
        self._cache = {}  # in-memory cache for fast lookups
        self._init_db()

    def _init_db(self):
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS mappings (
                category TEXT NOT NULL,
                original TEXT NOT NULL,
                sanitized TEXT NOT NULL,
                PRIMARY KEY (category, original)
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_mappings_original
            ON mappings(original)
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS counters (
                category TEXT PRIMARY KEY,
                next_id INTEGER NOT NULL DEFAULT 1
            )
        """)
        self._conn.commit()

        # Load existing counters
        for row in self._conn.execute("SELECT category, next_id FROM counters"):
            self._counters[row[0]] = row[1]

        # Load existing mappings into cache
        for row in self._conn.execute("SELECT category, original, sanitized FROM mappings"):
            key = (row[0], self._normalize(row[1]))
            self._cache[key] = row[2]

    def _normalize(self, value: str) -> str:
        """Normalize a value for consistent lookup."""
        return value.strip().lower()

    def _next_id(self, category: str) -> int:
        """Get and increment the counter for a category."""
        current = self._counters.get(category, 1)
        self._counters[category] = current + 1
        self._conn.execute(
            "INSERT OR REPLACE INTO counters (category, next_id) VALUES (?, ?)",
            (category, current + 1),
        )
        return current

    def get(self, category: str, original: str) -> Optional[str]:
        """Look up existing mapping. Returns None if not found."""
        key = (category, self._normalize(original))
        return self._cache.get(key)

    def get_or_create(self, category: str, original: str) -> str:
        """Get existing mapping or create a new one."""
        existing = self.get(category, original)
        if existing is not None:
            return existing

        # Don't register our own sanitized replacement tokens as PII
        from precinct6_dataset.allowlists import is_sanitized_token
        if is_sanitized_token(original):
            return original

        sanitized = self._generate_replacement(category, original)
        norm_key = (category, self._normalize(original))
        self._cache[norm_key] = sanitized

        self._conn.execute(
            "INSERT OR IGNORE INTO mappings (category, original, sanitized) VALUES (?, ?, ?)",
            (category, original, sanitized),
        )
        self._conn.commit()
        return sanitized

    def _generate_replacement(self, category: str, original: str) -> str:
        """Generate a sanitized replacement value for the given category."""
        seq = self._next_id(category)

        if category == "org":
            return f"ORG-{seq:04d}"
        elif category == "domain":
            return f"domain-{seq:04d}.example.net"
        elif category == "ipv4_priv":
            return self._map_private_ip(original)
        elif category == "ipv4_pub":
            return self._map_public_ip(original, seq)
        elif category == "hostname":
            return f"HOST-{seq:04d}"
        elif category == "fqdn":
            return f"host-{seq:04d}.example.internal"
        elif category == "username":
            return f"USER-{seq:04d}"
        elif category == "email":
            return f"user-{seq:04d}@example.net"
        elif category == "sid":
            return f"S-1-5-21-1000000000-2000000000-3000000000-{seq:04d}"
        elif category == "aws_account":
            return f"{100000000000 + seq}"
        elif category == "arn":
            acct = f"{100000000000 + seq}"
            return f"arn:aws:iam::{acct}:sanitized/{seq}"
        elif category == "machine_account":
            return f"MACHINE-{seq:04d}$"
        elif category == "credential":
            return f"CRED-{seq:04d}"
        elif category == "org_id":
            return str(10000 + seq)
        elif category == "agent_id":
            return f"AGENT-{seq:04d}"
        else:
            return f"REDACTED-{category.upper()}-{seq:04d}"

    def _map_private_ip(self, original: str) -> str:
        """Map a private IP to another private IP, preserving subnet grouping."""
        try:
            addr = ipaddress.IPv4Address(original)
        except ValueError:
            return f"10.0.0.{self._next_id('ipv4_priv_fallback')}"

        # Use HMAC to deterministically map
        mac = hmac.new(self.secret, original.encode(), hashlib.sha256).digest()

        # Determine which private range the original is in
        octets = list(addr.packed)
        if octets[0] == 10:
            # 10.x.x.x -> 10.{h1}.{h2}.{h3}
            h1 = mac[0] % 256
            h2 = mac[1] % 256
            h3 = max(1, mac[2] % 255)  # avoid .0
            return f"10.{h1}.{h2}.{h3}"
        elif octets[0] == 172 and 16 <= octets[1] <= 31:
            # 172.16-31.x.x -> 172.{16+h1%16}.{h2}.{h3}
            h1 = 16 + (mac[0] % 16)
            h2 = mac[1] % 256
            h3 = max(1, mac[2] % 255)
            return f"172.{h1}.{h2}.{h3}"
        elif octets[0] == 192 and octets[1] == 168:
            # 192.168.x.x -> 192.168.{h1}.{h2}
            h1 = mac[0] % 256
            h2 = max(1, mac[1] % 255)
            return f"192.168.{h1}.{h2}"
        else:
            return f"10.{mac[0] % 256}.{mac[1] % 256}.{max(1, mac[2] % 255)}"

    def _map_public_ip(self, original: str, seq: int) -> str:
        """Map a public IP to RFC 5737 TEST-NET addresses."""
        # Three TEST-NET ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        # Total 762 unique addresses. For overflow, use 100.64.0.0/10 (CGN range)
        if seq <= 254:
            return f"192.0.2.{seq}"
        elif seq <= 508:
            return f"198.51.100.{seq - 254}"
        elif seq <= 762:
            return f"203.0.113.{seq - 508}"
        else:
            # Overflow into CGN range
            overflow = seq - 762
            o3 = (overflow // 256) % 256
            o4 = max(1, overflow % 256)
            return f"100.64.{o3}.{o4}"

    def lookup(self, original: str) -> Optional[str]:
        """Look up an original value across ALL categories. Returns sanitized or None."""
        norm = self._normalize(original)
        for cat in self.CATEGORIES:
            key = (cat, norm)
            if key in self._cache:
                return self._cache[key]
        return None

    def all_entries(self):
        """Iterate all (category, original, sanitized) tuples from DB."""
        rows = self._conn.execute(
            "SELECT category, original, sanitized FROM mappings"
        ).fetchall()
        for category, original, sanitized in rows:
            yield category, original, sanitized

    def get_all_originals(self) -> set[str]:
        """Return all original values across all categories."""
        originals = set()
        for row in self._conn.execute("SELECT original FROM mappings"):
            originals.add(row[0])
        return originals

    def get_all_mappings(self) -> list[tuple[str, str, str]]:
        """Return all (category, original, sanitized) tuples."""
        return list(self._conn.execute(
            "SELECT category, original, sanitized FROM mappings"
        ))

    def get_category_mappings(self, category: str) -> dict[str, str]:
        """Return all original->sanitized mappings for a category."""
        result = {}
        for row in self._conn.execute(
            "SELECT original, sanitized FROM mappings WHERE category = ?",
            (category,),
        ):
            result[row[0]] = row[1]
        return result

    def stats(self) -> dict[str, int]:
        """Return count of mappings per category."""
        result = {}
        for row in self._conn.execute(
            "SELECT category, COUNT(*) FROM mappings GROUP BY category"
        ):
            result[row[0]] = row[1]
        return result

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
