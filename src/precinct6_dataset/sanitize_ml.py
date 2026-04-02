"""Layer 3: ML/NER-based PII detection using Presidio and HuggingFace models.

This layer runs after Layers 1-2 to catch PII that regex patterns missed.
"""

import json
from typing import Optional

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.allowlists import is_allowed
from precinct6_dataset.patterns import IPV4, is_private_ip
from precinct6_dataset.config import PRESIDIO_SCORE_THRESHOLD, ML_NER_CONFIDENCE_THRESHOLD


class PresidioDetector:
    """PII detection using Microsoft Presidio."""

    def __init__(self, score_threshold: float = PRESIDIO_SCORE_THRESHOLD):
        self.score_threshold = score_threshold
        self.analyzer = None
        self._initialized = False

    def initialize(self):
        """Lazy initialization of Presidio (heavy imports)."""
        if self._initialized:
            return

        from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        })
        nlp_engine = provider.create_engine()

        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Add custom recognizers for cybersecurity-specific patterns
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="AWS_ACCOUNT_ID",
            name="aws_account_recognizer",
            patterns=[Pattern("aws_acct", r"(?<!\d)\d{12}(?!\d)", 0.4)],
            context=["aws", "account", "arn", "iam", "cloudtrail", "trustedadvisor"],
        ))

        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="MACHINE_ACCOUNT",
            name="machine_account_recognizer",
            patterns=[Pattern("machine", r"[A-Z][A-Z0-9-]{2,30}\$", 0.6)],
        ))

        self._initialized = True

    def detect(self, text: str) -> list[dict]:
        """Detect PII entities in text.

        Returns list of dicts with: entity_type, start, end, score, text
        """
        self.initialize()

        results = self.analyzer.analyze(
            text=text,
            language="en",
            score_threshold=self.score_threshold,
        )

        findings = []
        for result in results:
            span_text = text[result.start:result.end]

            # Skip if in allowlist
            if is_allowed(span_text):
                continue

            # Skip already-sanitized tokens
            if span_text.startswith(("ORG-", "HOST-", "USER-", "CRED-",
                                     "MACHINE-", "DOMAIN-", "AGENT-",
                                     "S-1-5-21-1000000000")):
                continue

            # Skip TEST-NET IPs (our replacements)
            if span_text.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "100.64.")):
                continue

            findings.append({
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": result.score,
                "text": span_text,
            })

        return findings


class HuggingFaceNERDetector:
    """PII detection using HuggingFace NER models."""

    def __init__(self, model_name: str = "dslim/bert-base-NER",
                 confidence_threshold: float = ML_NER_CONFIDENCE_THRESHOLD):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.pipeline = None
        self._initialized = False

    def initialize(self):
        """Lazy initialization of HuggingFace pipeline."""
        if self._initialized:
            return

        from transformers import pipeline
        self.pipeline = pipeline(
            "token-classification",
            model=self.model_name,
            aggregation_strategy="simple",
        )
        self._initialized = True

    def detect(self, text: str) -> list[dict]:
        """Detect named entities that might be PII.

        Returns list of dicts with: entity_type, start, end, score, text
        """
        self.initialize()

        # Truncate very long texts (BERT has 512 token limit)
        max_chars = 2000
        truncated = text[:max_chars] if len(text) > max_chars else text

        results = self.pipeline(truncated)

        findings = []
        for result in results:
            # Only interested in PER, ORG, LOC (potential PII)
            if result["entity_group"] not in ("PER", "ORG", "LOC"):
                continue

            if result["score"] < self.confidence_threshold:
                continue

            span_text = result["word"].strip()

            # Skip allowlisted terms
            if is_allowed(span_text):
                continue

            # Skip already-sanitized tokens
            if span_text.startswith(("ORG-", "HOST-", "USER-", "CRED-",
                                     "MACHINE-", "DOMAIN-")):
                continue

            findings.append({
                "entity_type": f"NER_{result['entity_group']}",
                "start": result["start"],
                "end": result["end"],
                "score": result["score"],
                "text": span_text,
            })

        return findings


class MLSanitizer:
    """Combined ML-based PII detection and sanitization."""

    def __init__(self, use_presidio: bool = True, use_hf_ner: bool = True):
        self.presidio = PresidioDetector() if use_presidio else None
        self.hf_ner = HuggingFaceNERDetector() if use_hf_ner else None
        self._new_findings = []

    def initialize(self):
        """Initialize all ML models."""
        if self.presidio:
            self.presidio.initialize()
        if self.hf_ner:
            self.hf_ner.initialize()

    def scan_text(self, text: str) -> list[dict]:
        """Scan text for PII using all available ML models.

        Returns combined findings from all models.
        """
        findings = []

        if self.presidio:
            findings.extend(self.presidio.detect(text))

        if self.hf_ner:
            findings.extend(self.hf_ner.detect(text))

        # Deduplicate overlapping findings
        findings = _deduplicate_findings(findings)

        return findings

    def scan_and_update_registry(
        self, text: str, registry: PIIRegistry
    ) -> tuple[list[dict], bool]:
        """Scan text and add new findings to registry.

        Returns (findings, has_new) where has_new indicates if new PII was found.
        """
        findings = self.scan_text(text)
        has_new = False

        for finding in findings:
            span = finding["text"]
            entity_type = finding["entity_type"]

            # Map entity type to registry category
            category = _entity_to_category(entity_type, span)
            if category and not registry.get(category, span):
                registry.get_or_create(category, span)
                has_new = True
                self._new_findings.append(finding)

        return findings, has_new

    def get_new_findings(self) -> list[dict]:
        """Return all new PII findings from scan_and_update_registry calls."""
        return self._new_findings

    def clear_findings(self):
        self._new_findings = []

    def scan_record(
        self, record: dict, registry: PIIRegistry
    ) -> tuple[list[dict], bool]:
        """Scan all text fields in a record for residual PII."""
        all_findings = []
        has_new = False

        for key, value in record.items():
            if isinstance(value, str) and len(value) > 3:
                findings, new = self.scan_and_update_registry(value, registry)
                all_findings.extend(findings)
                has_new = has_new or new
            elif isinstance(value, dict):
                f, n = self.scan_record(value, registry)
                all_findings.extend(f)
                has_new = has_new or n

        return all_findings, has_new


def _entity_to_category(entity_type: str, span: str) -> Optional[str]:
    """Map a Presidio/NER entity type to a registry category."""
    mapping = {
        "PERSON": "username",
        "NER_PER": "username",
        "ORGANIZATION": "org",
        "NER_ORG": "org",
        "LOCATION": None,  # locations in security logs are usually not PII
        "NER_LOC": None,
        "EMAIL_ADDRESS": "email",
        "IP_ADDRESS": "ipv4_pub",
        "AWS_ACCOUNT_ID": "aws_account",
        "MACHINE_ACCOUNT": "machine_account",
        "PHONE_NUMBER": None,
        "CREDIT_CARD": None,
        "US_SSN": None,
    }
    category = mapping.get(entity_type)

    # For IP addresses, classify as private or public
    if category == "ipv4_pub" and IPV4.fullmatch(span):
        if is_private_ip(span):
            return "ipv4_priv"

    return category


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate/overlapping findings, keeping highest confidence."""
    if not findings:
        return findings

    # Sort by start position, then by score (descending)
    findings.sort(key=lambda f: (f["start"], -f["score"]))

    result = []
    last_end = -1
    for f in findings:
        if f["start"] >= last_end:
            result.append(f)
            last_end = f["end"]
        elif f["score"] > result[-1]["score"]:
            # Higher confidence finding overlaps — replace
            result[-1] = f
            last_end = f["end"]

    return result
