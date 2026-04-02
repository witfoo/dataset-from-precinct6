"""Verification system — detect PII leaks and validate data integrity."""

import json
import re
from pathlib import Path
from collections import defaultdict

import orjson

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, TEST_NET, KNOWN_CUSTOMER_DOMAINS, is_test_net_ip
from precinct6_dataset.config import SANITIZED_DIR, OUTPUT_DIR, KNOWN_DOMAINS, KNOWN_ORGS, KNOWN_ORG_DISPLAY
from precinct6_dataset.allowlists import is_allowed, VENDOR_TERMS, PROTOCOL_TERMS


class Verifier:
    """Verify sanitized output for PII leaks and data integrity."""

    def __init__(
        self,
        registry: PIIRegistry,
        sanitized_dir: Path = None,
        output_dir: Path = None,
    ):
        self.registry = registry
        self.sanitized_dir = sanitized_dir or SANITIZED_DIR
        self.output_dir = output_dir or OUTPUT_DIR
        self.violations = []
        self.warnings = []

    def run_all_checks(self) -> dict:
        """Run all verification checks and return a report."""
        print("=" * 60)
        print("VERIFICATION")
        print("=" * 60)

        print("\n[Check 1] Scanning for PII leaks (registry originals)...")
        self._check_registry_leaks()

        print("\n[Check 2] Scanning for known org patterns...")
        self._check_org_patterns()

        print("\n[Check 3] Scanning for unsanitized public IPs...")
        self._check_unsanitized_ips()

        print("\n[Check 4] Validating IP mapping consistency...")
        self._check_ip_consistency()

        print("\n[Check 5] Checking label distribution...")
        label_dist = self._check_label_distribution()

        print("\n[Check 6] Sampling random messages for manual review...")
        samples = self._sample_for_review()

        report = {
            "violations": len(self.violations),
            "warnings": len(self.warnings),
            "violation_details": self.violations[:50],  # cap at 50
            "warning_details": self.warnings[:50],
            "label_distribution": label_dist,
            "sample_messages": samples,
        }

        print(f"\n{'=' * 60}")
        print(f"RESULTS: {len(self.violations)} violations, {len(self.warnings)} warnings")
        if self.violations:
            print("\nVIOLATIONS (first 10):")
            for v in self.violations[:10]:
                print(f"  - {v}")
        print("=" * 60)

        return report

    def _scan_files(self):
        """Yield (filepath, line_number, text) for all output files."""
        # Skip our generated metadata files (contain our own descriptions, not customer data)
        skip_names = {"metadata.json", "verification_report.json", "manual_review_samples.txt"}
        for dir_path in [self.sanitized_dir, self.output_dir]:
            if not dir_path.exists():
                continue
            for filepath in dir_path.rglob("*"):
                if filepath.name in skip_names:
                    continue
                if filepath.is_file() and filepath.suffix in (".jsonl", ".json", ".csv", ".graphml"):
                    try:
                        with open(filepath, "r", errors="replace") as f:
                            for i, line in enumerate(f, 1):
                                yield filepath, i, line
                    except Exception:
                        continue

    def _check_registry_leaks(self):
        """Check that no original PII value appears in any output file."""
        originals = self.registry.get_all_originals()

        # Get all sanitized values so we can exclude them
        all_mappings = self.registry.get_all_mappings()
        sanitized_values = {m[2].lower() for m in all_mappings}

        # Filter to meaningful originals (skip very short ones that would false-positive)
        check_originals = {o for o in originals if len(o) >= 5}

        # Exclude values that are also sanitized replacement tokens
        # (e.g., if a sanitized IP was later seen and added as an original)
        check_originals = {o for o in check_originals if o.lower() not in sanitized_values}

        # Exclude values that are allowlisted technology terms (appear in passthrough fields)
        check_originals = {o for o in check_originals if not is_allowed(o)}

        # Build case-insensitive lookup
        originals_lower = {o.lower(): o for o in check_originals}

        leak_count = 0
        for filepath, line_num, text in self._scan_files():
            text_lower = text.lower()
            for orig_lower, orig in originals_lower.items():
                if orig_lower in text_lower:
                    # Verify it's not part of a larger safe token
                    self.violations.append(
                        f"LEAK: '{orig}' found in {filepath.name}:{line_num}"
                    )
                    leak_count += 1
                    if leak_count > 100:
                        self.violations.append("... (truncated, too many leaks)")
                        return

        if leak_count == 0:
            print("  PASS: No registry original values found in output")
        else:
            print(f"  FAIL: {leak_count} leaks detected")

    def _check_org_patterns(self):
        """Check for known organization patterns in output."""
        # Build patterns for org names and domains (use word boundaries)
        org_patterns = []
        for org in list(KNOWN_ORGS.keys()) + list(KNOWN_ORG_DISPLAY.keys()):
            if len(org) >= 4:  # Skip very short names like "ach" that false-positive
                org_patterns.append(re.compile(r'\b' + re.escape(org) + r'\b', re.IGNORECASE))

        for domain in KNOWN_DOMAINS:
            org_patterns.append(re.compile(re.escape(domain), re.IGNORECASE))

        leak_count = 0
        for filepath, line_num, text in self._scan_files():
            for pattern in org_patterns:
                if pattern.search(text):
                    self.violations.append(
                        f"ORG_LEAK: '{pattern.pattern}' found in {filepath.name}:{line_num}"
                    )
                    leak_count += 1
                    if leak_count > 50:
                        return

        if leak_count == 0:
            print("  PASS: No known org patterns found in output")
        else:
            print(f"  FAIL: {leak_count} org pattern leaks detected")

    def _check_unsanitized_ips(self):
        """Check for public IPs that aren't in TEST-NET ranges."""
        unsafe_count = 0
        for filepath, line_num, text in self._scan_files():
            for ip_match in IPV4.finditer(text):
                ip = ip_match.group(0)
                # Skip TEST-NET (our replacements)
                if is_test_net_ip(ip):
                    continue
                # Skip loopback
                if ip.startswith("127."):
                    continue
                # Skip CGN range (our overflow)
                if ip.startswith("100.64."):
                    continue
                # Private IPs are OK (they've been remapped)
                if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
                    continue
                # Skip 0.0.0.0 and broadcast
                if ip in ("0.0.0.0", "255.255.255.255"):
                    continue

                # This is an unsanitized public IP
                self.warnings.append(
                    f"UNSANITIZED_IP: {ip} in {filepath.name}:{line_num}"
                )
                unsafe_count += 1
                if unsafe_count > 50:
                    return

        if unsafe_count == 0:
            print("  PASS: No unsanitized public IPs found")
        else:
            print(f"  WARN: {unsafe_count} potentially unsanitized public IPs")

    def _check_ip_consistency(self):
        """Verify that each fake IP maps to exactly one original."""
        ip_mappings = {}
        for cat in ("ipv4_priv", "ipv4_pub"):
            for orig, sanitized in self.registry.get_category_mappings(cat).items():
                if sanitized in ip_mappings and ip_mappings[sanitized] != orig:
                    self.violations.append(
                        f"IP_COLLISION: {sanitized} maps to both "
                        f"'{ip_mappings[sanitized]}' and '{orig}'"
                    )
                ip_mappings[sanitized] = orig

        if not any("IP_COLLISION" in v for v in self.violations):
            print(f"  PASS: All {len(ip_mappings)} IP mappings are unique")

    def _check_label_distribution(self) -> dict:
        """Report label distribution."""
        dist = defaultdict(int)

        labeled_file = self.sanitized_dir / "artifacts_labeled.jsonl"
        if labeled_file.exists():
            with open(labeled_file, "rb") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = orjson.loads(line)
                        labels = record.get("_labels", {})
                        binary = labels.get("label_binary", "unknown")
                        dist[binary] += 1
                    except Exception:
                        continue

        total = sum(dist.values())
        print(f"  Label distribution (total: {total}):")
        for label, count in sorted(dist.items()):
            pct = (count / total * 100) if total > 0 else 0
            print(f"    {label}: {count} ({pct:.1f}%)")

        if total > 0 and dist.get("malicious", 0) == 0:
            self.warnings.append("No malicious labels found — check incident linkage")

        return dict(dist)

    def _sample_for_review(self, n: int = 100) -> list[str]:
        """Sample random sanitized message fields for human review."""
        import random

        messages = []
        artifacts_file = self.sanitized_dir / "artifacts_labeled.jsonl"
        if not artifacts_file.exists():
            artifacts_file = self.sanitized_dir / "artifacts.jsonl"
        if not artifacts_file.exists():
            return messages

        all_messages = []
        with open(artifacts_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = orjson.loads(line)
                    msg = record.get("message", "")
                    if msg:
                        all_messages.append(msg[:500])
                except Exception:
                    continue

        samples = random.sample(all_messages, min(n, len(all_messages)))

        # Write samples to file for human review
        review_file = self.output_dir / "manual_review_samples.txt"
        review_file.parent.mkdir(parents=True, exist_ok=True)
        with open(review_file, "w") as f:
            f.write("# Manual Review Samples\n")
            f.write("# Check each message for remaining PII\n\n")
            for i, msg in enumerate(samples, 1):
                f.write(f"--- Sample {i} ---\n{msg}\n\n")

        print(f"  Wrote {len(samples)} samples to {review_file.name}")
        return samples
