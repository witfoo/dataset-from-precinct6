"""Layer 4: Claude API-based PII review.

Sends stratified samples of sanitized records to Claude for final review.
Any findings feed back into the PII registry for re-sanitization.
"""

import json
import re
import random
from collections import defaultdict
from typing import Optional

import anthropic

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.config import (
    ANTHROPIC_API_KEY,
    CLAUDE_REVIEW_MODEL,
    CLAUDE_REVIEW_SAMPLE_RATE,
    CLAUDE_REVIEW_BATCH_SIZE,
    CLAUDE_REVIEW_CONCURRENCY,
    CLAUDE_ESCALATION_THRESHOLD,
)


REVIEW_PROMPT = """You are a cybersecurity data sanitization reviewer. Your task is to identify any remaining Personally Identifiable Information (PII) or organizationally identifying information in pre-sanitized security log data.

The data has already been processed through regex and ML-based sanitization. Your job is to find what those layers missed.

CATEGORIES TO CHECK:
1. Organization names or abbreviations that were not caught
2. Internal hostnames that reveal organizational structure (e.g., "ACME-DC01")
3. Employee names embedded in strings (e.g., "jsmith-laptop")
4. Custom policy or group names that reveal the organization
5. Internal domain names or URLs
6. Geographic identifiers tied to specific offices
7. Vendor-specific account references
8. AWS account IDs, API keys, or access tokens

IMPORTANT — Do NOT flag these (they are safe):
- Generic technology terms (tcp, http, ASA, VMware, Cisco, etc.)
- Sanitization tokens matching patterns: ORG-NNNN, HOST-NNNN, USER-NNNN, CRED-NNNN, MACHINE-NNNN$, DOMAIN-NNNN.example.net, AGENT-NNNN
- Timestamps, ports, protocol numbers, or event IDs
- MITRE ATT&CK technique IDs (T1xxx) or D3FEND references
- RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x)
- RFC 1918 private IPs that have been remapped (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Incident names like "Bitter Reindeer 230971" (auto-generated, not PII)
- Standard Windows SIDs starting with S-1-5-21-1000000000
- Public domain names (google.com, amazonaws.com, etc.)

For each finding, respond ONLY with a JSON array. Each element:
{
  "span": "the exact text found",
  "category": "org|hostname|username|domain|credential|ip|other",
  "confidence": 0.0 to 1.0,
  "reasoning": "brief explanation"
}

If nothing is found, respond with: []

DATA TO REVIEW:
```
{record_text}
```"""


def _extract_json_array(text: str) -> list[dict]:
    """Extract a JSON array from Claude's response, handling various formats."""
    # Strategy 1: Direct parse
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Strategy 2: Strip markdown code fences
    code_block = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if code_block:
        try:
            result = json.loads(code_block.group(1).strip())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find JSON array by bracket matching
    start = text.find("[")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "[":
                depth += 1
            elif text[i] == "]":
                depth -= 1
                if depth == 0:
                    try:
                        result = json.loads(text[start:i+1])
                        if isinstance(result, list):
                            return result
                    except json.JSONDecodeError:
                        pass
                    break

    return []


def _finding_to_registry_category(category: str) -> Optional[str]:
    """Map Claude finding category to registry category."""
    mapping = {
        "org": "org",
        "hostname": "hostname",
        "username": "username",
        "domain": "domain",
        "credential": "credential",
        "ip": "ipv4_pub",
        "other": None,
    }
    return mapping.get(category)


class ClaudeReviewer:
    """Claude API-based PII review for sanitized data."""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.async_client = None
        self.findings_by_format = defaultdict(list)
        self.total_reviewed = defaultdict(int)

    def review_batch_sync(self, records: list[str]) -> list[dict]:
        """Synchronously review a batch of records."""
        combined = "\n---RECORD BOUNDARY---\n".join(records)

        try:
            response = self.client.messages.create(
                model=CLAUDE_REVIEW_MODEL,
                max_tokens=4096,
                messages=[{
                    "role": "user",
                    "content": REVIEW_PROMPT.replace("{record_text}", combined),
                }],
            )

            text = response.content[0].text.strip()
            return _extract_json_array(text)

        except Exception as e:
            print(f"  Claude review error: {e}")
            return []

    def review_records_stratified(
        self,
        records: list[dict],
        registry: PIIRegistry,
        sample_rate: float = CLAUDE_REVIEW_SAMPLE_RATE,
    ) -> dict:
        """Review a stratified sample of records."""
        strata = defaultdict(list)
        for rec in records:
            key = (
                rec.get("messageType", rec.get("messagetype", "unknown")),
                rec.get("streamName", rec.get("streamname", "unknown")),
            )
            strata[key].append(rec)

        total_findings = []
        formats_with_issues = set()

        for stratum_key, stratum_records in strata.items():
            n_sample = max(1, int(len(stratum_records) * sample_rate))
            sample = random.sample(stratum_records, min(n_sample, len(stratum_records)))

            stratum_findings = []
            for i in range(0, len(sample), CLAUDE_REVIEW_BATCH_SIZE):
                batch = sample[i:i + CLAUDE_REVIEW_BATCH_SIZE]
                batch_texts = [json.dumps(r, indent=2)[:2000] for r in batch]
                findings = self.review_batch_sync(batch_texts)
                stratum_findings.extend(findings)

            self.total_reviewed[stratum_key] += len(sample)
            self.findings_by_format[stratum_key].extend(stratum_findings)

            if len(sample) > 0:
                issue_rate = len(stratum_findings) / len(sample)
                if issue_rate > CLAUDE_ESCALATION_THRESHOLD:
                    formats_with_issues.add(stratum_key)
                    print(f"  High PII rate ({issue_rate:.1%}) in {stratum_key}")

            total_findings.extend(stratum_findings)

        # Update registry with findings
        new_entries = 0
        for finding in total_findings:
            span = finding.get("span", "")
            category = finding.get("category", "other")
            confidence = finding.get("confidence", 0)

            if confidence < 0.5 or not span or len(span) < 3:
                continue

            reg_category = _finding_to_registry_category(category)
            if reg_category and not registry.get(reg_category, span):
                registry.get_or_create(reg_category, span)
                new_entries += 1

        return {
            "total_reviewed": sum(self.total_reviewed.values()),
            "total_findings": len(total_findings),
            "new_registry_entries": new_entries,
            "formats_with_issues": list(formats_with_issues),
            "strata_count": len(strata),
        }
