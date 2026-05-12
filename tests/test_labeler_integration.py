"""End-to-end smoke test for the Labeler over a tiny synthetic dataset."""

import json
from pathlib import Path

import pytest
import orjson

from precinct6_dataset.label import Labeler


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with open(path, "wb") as f:
        for r in records:
            f.write(orjson.dumps(r))
            f.write(b"\n")


@pytest.fixture
def sanitized_dir(tmp_path: Path) -> Path:
    """Build a minimal sanitized/ directory with one incident and three artifacts."""
    # Incident: a Ransomware MO with a C2 Server set role
    incident = {
        "id": "INC-0001",
        "mo_name": "Ransomware",
        "suspicion_score": 0.85,
        "status_name": "Resolved",
        "status_id": 3,
        "sets": {
            "1": {"name": "C2 Server"},
            "2": {"name": "Ransomware Target"},
        },
        "leads": {
            "L-0001": {
                "observed_at": 1700000000.0,
                "artifact": {
                    "messageType": "firewall_action",
                    "streamName": "stealth_watch",
                    "clientIP": "192.0.2.10",
                    "serverIP": "203.0.113.20",
                    "action": "block",
                },
            },
        },
        "nodes": {},
        "edges": {},
    }
    _write_jsonl(tmp_path / "incidents.jsonl", [incident])

    # Three artifacts:
    #   1. matchedLeadRuleIds set -> should label suspicious
    #   2. no rules -> should label benign
    #   3. another rule-matched -> suspicious
    artifacts = [
        {
            "messageType": "firewall_action",
            "streamName": "stealth_watch",
            "clientIP": "192.0.2.30",
            "serverIP": "203.0.113.40",
            "matchedLeadRuleIds": [1],
        },
        {
            "messageType": "dns_event",
            "streamName": "bind_dns",
            "clientIP": "192.0.2.50",
            "serverIP": "203.0.113.60",
        },
        {
            "messageType": "firewall_action",
            "streamName": "stealth_watch",
            "clientIP": "192.0.2.70",
            "serverIP": "203.0.113.80",
            "matchedLeadRuleIds": [1],
        },
    ]
    _write_jsonl(tmp_path / "artifacts.jsonl", artifacts)
    return tmp_path


def test_labeler_produces_three_labels_and_extracts_malicious(sanitized_dir):
    labeler = Labeler(sanitized_dir=sanitized_dir)
    labeler.label_all()

    out_file = sanitized_dir / "artifacts_labeled.jsonl"
    assert out_file.exists()

    records = [json.loads(line) for line in open(out_file)]
    # 3 input artifacts + 1 malicious from incident lead
    assert len(records) == 4

    labels = [r["_labels"]["label_binary"] for r in records]
    assert labels.count("suspicious") == 2
    assert labels.count("benign") == 1
    assert labels.count("malicious") == 1


def test_malicious_record_carries_mitre_tactics_and_techniques(sanitized_dir):
    labeler = Labeler(sanitized_dir=sanitized_dir)
    labeler.label_all()

    records = [json.loads(line) for line in open(sanitized_dir / "artifacts_labeled.jsonl")]
    malicious = next(r for r in records if r["_labels"]["label_binary"] == "malicious")
    lab = malicious["_labels"]

    # Ransomware MO + C2 Server + Ransomware Target sets should yield non-empty MITRE
    assert lab["attack_tactics"], "expected attack_tactics for malicious incident-derived record"
    assert lab["attack_techniques"], "expected attack_techniques for malicious incident-derived record"
    # Specific expected mappings:
    assert "TA0040" in lab["attack_tactics"]    # Impact (from Ransomware MO + Ransomware Target)
    assert "TA0011" in lab["attack_tactics"]    # Command and Control (from C2 Server)
    assert "T1486" in lab["attack_techniques"]  # Data Encrypted for Impact
    assert lab["mo_name"] == "Ransomware"
    assert lab["disposition"] == "Resolved"
    assert lab["is_false_positive"] is False


def test_malicious_confidence_uses_suspicion_score(sanitized_dir):
    labeler = Labeler(sanitized_dir=sanitized_dir)
    labeler.label_all()

    records = [json.loads(line) for line in open(sanitized_dir / "artifacts_labeled.jsonl")]
    malicious = next(r for r in records if r["_labels"]["label_binary"] == "malicious")
    # suspicion_score=0.85 -> max(0.6, 0.85) = 0.85
    assert malicious["_labels"]["label_confidence"] == 0.85


def test_suspicious_records_have_nonzero_confidence(sanitized_dir):
    labeler = Labeler(sanitized_dir=sanitized_dir)
    labeler.label_all()

    records = [json.loads(line) for line in open(sanitized_dir / "artifacts_labeled.jsonl")]
    suspicious = [r for r in records if r["_labels"]["label_binary"] == "suspicious"]
    for r in suspicious:
        # 1 rule, possibly 0+ roles depending on catalog presence -> at least 0.5 (0.4 + 0.1)
        assert r["_labels"]["label_confidence"] >= 0.5


def test_benign_record_has_empty_attack_fields(sanitized_dir):
    labeler = Labeler(sanitized_dir=sanitized_dir)
    labeler.label_all()

    records = [json.loads(line) for line in open(sanitized_dir / "artifacts_labeled.jsonl")]
    benign = next(r for r in records if r["_labels"]["label_binary"] == "benign")
    assert benign["_labels"]["attack_tactics"] == []
    assert benign["_labels"]["attack_techniques"] == []
    assert benign["_labels"]["label_confidence"] == 0.5


def test_false_positive_lowers_confidence(tmp_path: Path):
    incident = {
        "id": "INC-FP",
        "mo_name": "Ransomware",
        "suspicion_score": 0.9,
        "status_name": "False Positive",
        "status_id": 99,
        "sets": {"1": {"name": "C2 Server"}},
        "leads": {
            "L-FP": {
                "observed_at": 1700000000.0,
                "artifact": {"messageType": "firewall_action", "streamName": "stealth_watch"},
            }
        },
        "nodes": {},
        "edges": {},
    }
    _write_jsonl(tmp_path / "incidents.jsonl", [incident])
    _write_jsonl(tmp_path / "artifacts.jsonl", [])

    labeler = Labeler(sanitized_dir=tmp_path)
    labeler.label_all()

    records = [json.loads(line) for line in open(tmp_path / "artifacts_labeled.jsonl")]
    assert records[0]["_labels"]["label_confidence"] == 0.3
    assert records[0]["_labels"]["is_false_positive"] is True
    assert records[0]["_labels"]["disposition"] == "False Positive"
