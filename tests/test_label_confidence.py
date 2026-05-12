"""Tests for the label_confidence heuristic."""

from precinct6_dataset.label import compute_label_confidence


def test_benign_returns_neutral():
    assert compute_label_confidence("benign") == 0.5
    # benign ignores the other inputs
    assert compute_label_confidence("benign", suspicion_score=0.9, n_rules_matched=5) == 0.5


def test_suspicious_floor_with_one_rule_zero_roles():
    # 0.4 + 0.1 + 0 = 0.5
    assert compute_label_confidence("suspicious", n_rules_matched=1, n_set_roles=0) == 0.5


def test_suspicious_scales_with_rules_and_roles():
    low = compute_label_confidence("suspicious", n_rules_matched=1, n_set_roles=1)
    high = compute_label_confidence("suspicious", n_rules_matched=4, n_set_roles=3)
    assert low < high


def test_suspicious_clamped_to_max_0_85():
    assert compute_label_confidence("suspicious", n_rules_matched=100, n_set_roles=100) == 0.85


def test_malicious_floor_at_0_6():
    # Even with no suspicion score, malicious gets a 0.6 floor
    assert compute_label_confidence("malicious", suspicion_score=0.0) == 0.6


def test_malicious_scales_with_suspicion():
    assert compute_label_confidence("malicious", suspicion_score=0.8) == 0.8


def test_malicious_clamped_to_max_0_95():
    assert compute_label_confidence("malicious", suspicion_score=1.5) == 0.95


def test_malicious_false_positive_lowered():
    # Analyst-flagged false positive overrides the score
    fp = compute_label_confidence("malicious", suspicion_score=0.9, is_false_positive=True)
    assert fp == 0.3


def test_unknown_label_treated_as_benign():
    assert compute_label_confidence("unknown") == 0.5
    assert compute_label_confidence("") == 0.5


def test_returns_float():
    # Important for parquet dtype consistency
    result = compute_label_confidence("malicious", suspicion_score=0.7)
    assert isinstance(result, float)
