"""Sanitization pipeline orchestrator — combines all 4 layers.

Streaming architecture: processes and writes file by file to avoid
loading all records into memory. ML and Claude layers run on samples
read back from the sanitized output.

Pipeline flow:
1. Pre-scan: Build PII registry from structured fields across all data
2. Layer 1+2: Streaming structured + message sanitization (write as we go)
3. Layer 3: ML/NER residual detection on a sample
4. Layer 4: Claude API review on a stratified sample
5. If new PII found: re-stream through Layers 1+2
"""

import json
import random
from pathlib import Path
from typing import Optional

import orjson
from tqdm import tqdm

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.sanitize_structured import sanitize_record_structured
from precinct6_dataset.sanitize_message import sanitize_message_field, build_aho_automaton, aho_sweep
from precinct6_dataset.sanitize_ml import MLSanitizer
from precinct6_dataset.sanitize_claude import ClaudeReviewer
from precinct6_dataset.config import (
    RAW_DIR, SANITIZED_DIR, REGISTRY_DB_PATH,
    KNOWN_ORGS, KNOWN_ORG_DISPLAY, KNOWN_DOMAINS,
)
from precinct6_dataset.patterns import (
    IPV4, EMAIL, FQDN, WINDOWS_SID, MACHINE_ACCOUNT,
    is_private_ip, is_sanitized_ip, is_loopback_ip,
)
from precinct6_dataset.allowlists import is_allowed, is_public_domain


class SanitizationPipeline:
    """Orchestrates the full 4-layer sanitization pipeline with streaming I/O."""

    def __init__(
        self,
        registry: PIIRegistry = None,
        use_ml: bool = True,
        use_claude: bool = True,
        raw_dir: Path = None,
        output_dir: Path = None,
        ml_sample_size: int = 5000,
    ):
        self.registry = registry or PIIRegistry()
        self.raw_dir = raw_dir or RAW_DIR
        self.output_dir = output_dir or SANITIZED_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.ml_sanitizer = MLSanitizer() if use_ml else None
        self.claude_reviewer = ClaudeReviewer() if use_claude else None
        self.ml_sample_size = ml_sample_size

        self._stats = {
            "total_records": 0,
            "artifacts": 0,
            "incidents": 0,
            "other": 0,
            "prescan_pii_entries": 0,
            "layer3_new_pii": 0,
            "layer4_new_pii": 0,
            "resanitized": 0,
        }

    def run(self):
        """Run the full sanitization pipeline."""
        print("=" * 60)
        print("SANITIZATION PIPELINE")
        print("=" * 60)

        # Phase 1: Pre-scan to build registry
        print("\n[Phase 1] Pre-scanning data to build PII registry...")
        self._prescan()
        print(f"  Registry entries: {sum(self.registry.stats().values())}")
        for cat, count in sorted(self.registry.stats().items()):
            print(f"    {cat}: {count}")

        # Build Aho-Corasick automaton from registry for fast multi-pattern matching
        print("  Building Aho-Corasick automaton...")
        self._aho_automaton, self._aho_patterns = build_aho_automaton(self.registry)
        if self._aho_automaton:
            print(f"  Automaton built with {len(self._aho_patterns):,} patterns")
        # Store patterns on registry for access in aho_sweep via _aho_corasick_sweep
        self.registry._aho_patterns = self._aho_patterns

        # Phase 2: Streaming Layers 1-2 (read raw → sanitize → write)
        print("\n[Phase 2] Applying Layers 1-2 (streaming)...")
        self._stream_sanitize()
        print(f"  Processed: {self._stats['artifacts']} artifacts, "
              f"{self._stats['incidents']} incidents, "
              f"{self._stats['other']} other")

        # Phase 3: ML/NER detection on sample
        if self.ml_sanitizer:
            print(f"\n[Phase 3] Running ML/NER on sample of {self.ml_sample_size} records...")
            self.ml_sanitizer.initialize()
            new_pii = self._apply_layer_3_sample()
            if new_pii > 0:
                print(f"  Found {new_pii} new PII entries — re-sanitizing...")
                self._stream_resanitize()
        else:
            print("\n[Phase 3] Skipped (ML disabled)")

        # Phase 4: Claude API review on sample
        if self.claude_reviewer:
            print("\n[Phase 4] Running Claude API review (sampled)...")
            new_pii = self._apply_layer_4_sample()
            if new_pii > 0:
                print(f"  Found {new_pii} new PII entries — re-sanitizing...")
                self._stream_resanitize()
        else:
            print("\n[Phase 4] Skipped (Claude disabled)")

        print("\n" + "=" * 60)
        print("SANITIZATION COMPLETE")
        print(f"  Total records: {self._stats['total_records']}")
        print(f"  Registry entries: {sum(self.registry.stats().values())}")
        print(f"  Layer 3 new PII: {self._stats['layer3_new_pii']}")
        print(f"  Layer 4 new PII: {self._stats['layer4_new_pii']}")
        print("=" * 60)

        return self._stats

    def _prescan(self):
        """Pre-scan all raw data to build initial PII registry."""
        for org_name in list(KNOWN_ORGS.keys()) + list(KNOWN_ORG_DISPLAY.keys()):
            self.registry.get_or_create("org", org_name)
        for domain in KNOWN_DOMAINS:
            self.registry.get_or_create("domain", domain)

        raw_files = sorted(self.raw_dir.rglob("*.jsonl"))
        for jsonl_file in tqdm(raw_files, desc="  Pre-scan"):
            with open(jsonl_file, "rb") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = orjson.loads(line)
                        self._prescan_record(record)
                    except Exception:
                        continue

        self._stats["prescan_pii_entries"] = sum(self.registry.stats().values())

    # Safe usernames/domains that should NOT be registered as PII
    _SAFE_USERNAMES = {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "-", "", "root", "nobody", "daemon", "bin", "sys", "adm",
    }
    _SAFE_DOMAINS = {
        "NT AUTHORITY", "BUILTIN", "NT SERVICE", "Window Manager",
        "Font Driver Host", "IIS APPPOOL", "WORKGROUP",
    }

    def _prescan_record(self, record: dict):
        """Deep recursive pre-scan: extract PII from ALL fields, not just known ones."""
        self._deep_prescan(record, depth=0)

    def _deep_prescan(self, obj, depth=0):
        """Recursively scan ALL fields for PII-shaped values."""
        if depth > 20:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    self._classify_and_register(key, value)
                elif isinstance(value, (dict, list)):
                    self._deep_prescan(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._deep_prescan(item, depth + 1)
                elif isinstance(item, str):
                    self._classify_and_register("", item)

    def _classify_and_register(self, key: str, value: str):
        """Heuristically classify a string value and register if PII."""
        value = value.strip()
        if not value or len(value) < 3 or len(value) > 500:
            return
        if is_allowed(value):
            return

        # IP address (exact match)
        if IPV4.fullmatch(value):
            if not is_sanitized_ip(value) and not is_loopback_ip(value):
                cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
                self.registry.get_or_create(cat, value)
            return

        # Email (exact match)
        if EMAIL.fullmatch(value):
            self.registry.get_or_create("email", value)
            return

        # Windows SID
        if WINDOWS_SID.fullmatch(value):
            self.registry.get_or_create("sid", value)
            return

        # Machine account (HOSTNAME$)
        if MACHINE_ACCOUNT.fullmatch(value):
            self.registry.get_or_create("machine_account", value)
            return

        # FQDN (2+ dot segments, not public domain)
        if "." in value and FQDN.fullmatch(value) and not is_public_domain(value):
            self.registry.get_or_create("fqdn", value)
            return

        # Field-name hinted classification (only for short simple values)
        if len(value) > 100 or " " in value:
            return  # Long or multi-word values are likely descriptions, not PII atoms

        key_lower = key.lower()
        if any(h in key_lower for h in ("ip", "addr", "address")):
            if IPV4.fullmatch(value):
                cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
                self.registry.get_or_create(cat, value)
        elif any(h in key_lower for h in ("host", "computer", "server", "workstation", "machine")):
            if len(value) >= 3 and value != "-" and not is_allowed(value):
                self.registry.get_or_create("hostname", value)
        elif any(h in key_lower for h in ("user", "account", "principal", "subject", "target")):
            if value.upper() not in self._SAFE_USERNAMES and not is_allowed(value):
                self.registry.get_or_create("username", value)
        elif any(h in key_lower for h in ("org", "organization", "company", "tenant")):
            if value not in self._SAFE_DOMAINS and not is_allowed(value):
                self.registry.get_or_create("org", value)
        elif key_lower in ("domain",):
            if value not in self._SAFE_DOMAINS and not is_allowed(value):
                self.registry.get_or_create("org", value)

        if "credential" in record and record["credential"]:
            self.registry.get_or_create("credential", str(record["credential"]))

        if "nodes" in record and isinstance(record["nodes"], dict):
            for node in record["nodes"].values():
                if isinstance(node, dict):
                    self._prescan_record(node)

        if "leads" in record and isinstance(record["leads"], dict):
            for lead in record["leads"].values():
                if isinstance(lead, dict):
                    if "artifact" in lead:
                        self._prescan_record(lead["artifact"])

    def _stream_sanitize(self):
        """Stream through raw files, sanitize, and write output."""
        artifacts_out = open(self.output_dir / "artifacts.jsonl", "wb")
        incidents_out = open(self.output_dir / "incidents.jsonl", "wb")
        other_out = open(self.output_dir / "other.jsonl", "wb")

        try:
            raw_files = sorted(self.raw_dir.rglob("*.jsonl"))
            for jsonl_file in tqdm(raw_files, desc="  Sanitize"):
                with open(jsonl_file, "rb") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            record = orjson.loads(line)
                        except Exception:
                            continue

                        sanitized = self._sanitize_record(record)
                        out_bytes = orjson.dumps(sanitized)

                        # Route to appropriate output file
                        if "nodes" in sanitized and "edges" in sanitized:
                            incidents_out.write(out_bytes)
                            incidents_out.write(b"\n")
                            self._stats["incidents"] += 1
                        elif "messageType" in sanitized or "messagetype" in sanitized:
                            artifacts_out.write(out_bytes)
                            artifacts_out.write(b"\n")
                            self._stats["artifacts"] += 1
                        else:
                            other_out.write(out_bytes)
                            other_out.write(b"\n")
                            self._stats["other"] += 1

                        self._stats["total_records"] += 1
        finally:
            artifacts_out.close()
            incidents_out.close()
            other_out.close()

        # Remove empty files
        for name in ["artifacts.jsonl", "incidents.jsonl", "other.jsonl"]:
            fpath = self.output_dir / name
            if fpath.exists() and fpath.stat().st_size == 0:
                fpath.unlink()

    def _sanitize_record(self, record: dict) -> dict:
        """Apply Layers 1-2 to a single record."""
        # Layer 1: Structured fields
        sanitized = sanitize_record_structured(record, self.registry)

        # Layer 2: Message field (format-specific + generic + Aho-Corasick)
        if "message" in sanitized and sanitized["message"]:
            sanitized["message"] = sanitize_message_field(
                sanitized["message"],
                self.registry,
                stream_name=record.get("streamName", record.get("streamname", "")),
                message_type=record.get("messageType", record.get("messagetype", "")),
                pipeline_name=record.get("pipelineName", record.get("pipelinename", "")),
                aho_automaton=self._aho_automaton,
            )

        # Recursively sanitize ALL nested string fields via Aho-Corasick
        self._sanitize_nested_messages(sanitized)

        return sanitized

    # Fields that are product identifiers / metadata — never Aho-Corasick sweep these
    _PROTECTED_FIELDS = frozenset({
        "streamName", "streamname", "stream_name",
        "messageType", "messagetype", "message_type",
        "pipelineEntrypoint", "pipelineName", "pipelinename", "pipeline",
        "fieldExtractorName", "fieldextractorname",
        "ruleCategory", "rulecategory", "ruleName", "rulename",
        "status_name", "statusName",
        "mo_name", "moName",
        "name",  # incident names like "Convoluted Bandicoot 241304"
        "sensitivity",
        "severityCode", "severity",
        "type", "subtype",
        "_partition", "_created_at", "_created_at_uuid", "_org_id",
        "channel", "api", "version", "type", "kind",
        "event_data_type", "event_id", "opcode",
    })

    def _sanitize_nested_messages(self, obj, depth=0):
        """Recursively sanitize string fields — message/details get full parsing,
        other strings get Aho-Corasick sweep, but product identifiers are protected."""
        if depth > 10:
            return
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                val = obj[key]
                if key in ("message", "details", "description", "log_message",
                           "error_message", "event_message") and isinstance(val, str) and val:
                    obj[key] = sanitize_message_field(
                        val, self.registry,
                        stream_name=obj.get("streamname", obj.get("streamName", "")),
                        message_type=obj.get("messagetype", obj.get("messageType", "")),
                        pipeline_name=obj.get("pipelinename", obj.get("pipelineName", "")),
                        aho_automaton=self._aho_automaton,
                    )
                elif key in self._PROTECTED_FIELDS:
                    pass  # Never sweep product identifiers
                elif isinstance(val, str) and len(val) > 10 and self._aho_automaton:
                    # Run Aho-Corasick on non-protected string fields as safety net
                    obj[key] = aho_sweep(val, self._aho_automaton, self._aho_patterns)
                elif isinstance(val, (dict, list)):
                    self._sanitize_nested_messages(val, depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str) and len(item) > 10 and self._aho_automaton:
                    obj[i] = aho_sweep(item, self._aho_automaton, self._aho_patterns)
                elif isinstance(item, (dict, list)):
                    self._sanitize_nested_messages(item, depth + 1)

    def _apply_layer_3_sample(self) -> int:
        """Run ML/NER detection on a sample of sanitized artifacts."""
        artifacts_file = self.output_dir / "artifacts.jsonl"
        if not artifacts_file.exists():
            return 0

        # Reservoir sample from the sanitized artifacts
        sample = []
        with open(artifacts_file, "rb") as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                if len(sample) < self.ml_sample_size:
                    try:
                        sample.append(orjson.loads(line))
                    except Exception:
                        pass
                else:
                    j = random.randint(0, i)
                    if j < self.ml_sample_size:
                        try:
                            sample[j] = orjson.loads(line)
                        except Exception:
                            pass

        print(f"  Sampled {len(sample)} records for ML scan")
        new_count = 0
        for record in tqdm(sample, desc="  ML scan"):
            _findings, has_new = self.ml_sanitizer.scan_record(record, self.registry)
            if has_new:
                new_count += 1

        self._stats["layer3_new_pii"] = new_count
        return new_count

    def _apply_layer_4_sample(self) -> int:
        """Run Claude API review on a stratified sample."""
        artifacts_file = self.output_dir / "artifacts.jsonl"
        if not artifacts_file.exists():
            return 0

        # Read a sample for Claude review
        sample = []
        with open(artifacts_file, "rb") as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                if random.random() < 0.001:  # ~0.1% for Claude (expensive)
                    try:
                        sample.append(orjson.loads(line))
                    except Exception:
                        pass
                if len(sample) >= 500:
                    break

        if not sample:
            return 0

        print(f"  Sampled {len(sample)} records for Claude review")
        result = self.claude_reviewer.review_records_stratified(
            sample, self.registry, sample_rate=1.0  # review all in the sample
        )
        self._stats["layer4_new_pii"] = result["new_registry_entries"]
        return result["new_registry_entries"]

    def _stream_resanitize(self):
        """Re-stream through sanitized files, applying updated registry."""
        # Rebuild Aho-Corasick automaton with new registry entries
        self._aho_automaton, self._aho_patterns = build_aho_automaton(self.registry)
        self.registry._aho_patterns = self._aho_patterns

        for filename in ["artifacts.jsonl", "incidents.jsonl", "other.jsonl"]:
            inpath = self.output_dir / filename
            if not inpath.exists():
                continue

            tmppath = self.output_dir / f"{filename}.tmp"
            count = 0
            with open(inpath, "rb") as fin, open(tmppath, "wb") as fout:
                for line in fin:
                    if not line.strip():
                        continue
                    try:
                        record = orjson.loads(line)
                        sanitized = self._sanitize_record(record)
                        fout.write(orjson.dumps(sanitized))
                        fout.write(b"\n")
                        count += 1
                    except Exception:
                        fout.write(line)

            tmppath.replace(inpath)
            self._stats["resanitized"] += count
            print(f"  Re-sanitized {count} records in {filename}")
