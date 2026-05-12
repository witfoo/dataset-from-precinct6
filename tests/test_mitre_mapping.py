"""Tests for MITRE ATT&CK mapping helpers."""

from precinct6_dataset.mitre_mapping import (
    SET_ROLE_TO_TACTICS,
    MO_TO_TACTICS,
    SET_ROLE_TO_TECHNIQUES,
    MO_TO_TECHNIQUES,
    tactics_for_set_roles,
    techniques_for_set_roles,
    tactics_for_mo,
    techniques_for_mo,
    merge_unique,
)


def test_c2_server_maps_to_command_and_control():
    assert "TA0011" in tactics_for_set_roles(["C2 Server"])
    assert "T1071" in techniques_for_set_roles(["C2 Server"])


def test_phishing_maps_to_initial_access():
    assert "TA0001" in tactics_for_set_roles(["Phishing Site"])
    assert "T1566" in techniques_for_set_roles(["Phishing Site"])


def test_ransomware_mo_maps_to_impact():
    tactics = tactics_for_mo("Ransomware")
    assert "TA0040" in tactics  # Impact
    assert "TA0001" in tactics  # Initial Access
    assert "T1486" in techniques_for_mo("Ransomware")


def test_unknown_set_role_returns_empty():
    assert tactics_for_set_roles(["Made-Up Role"]) == []
    assert techniques_for_set_roles(["Made-Up Role"]) == []


def test_unknown_mo_returns_empty():
    assert tactics_for_mo("Not A Real MO") == []
    assert techniques_for_mo("") == []


def test_set_role_dedup_across_multiple_inputs():
    # Reconnaissance Host and Recon Hardware both map to TA0043 + TA0007
    tactics = tactics_for_set_roles(["Reconnaissance Host", "Recon Hardware"])
    assert tactics.count("TA0043") == 1
    assert tactics.count("TA0007") == 1


def test_merge_unique_preserves_order_and_dedupes():
    out = merge_unique(["a", "b"], ["b", "c"], ["a", "d"])
    assert out == ["a", "b", "c", "d"]


def test_merge_unique_skips_falsy():
    out = merge_unique(["a", "", None, "b"], None, [])
    assert out == ["a", "b"]


def test_set_role_tables_share_keys_with_techniques():
    # Every set role with a technique mapping should also appear in the tactics table.
    # (The reverse is not required: a tactic-only role like "Suspicious User" is fine.)
    missing = set(SET_ROLE_TO_TECHNIQUES) - set(SET_ROLE_TO_TACTICS)
    assert not missing, f"Roles in technique table but not tactic table: {missing}"


def test_mo_tables_share_keys():
    # MO entries with techniques should also have tactic mappings.
    missing = set(MO_TO_TECHNIQUES) - set(MO_TO_TACTICS)
    assert not missing, f"MOs in technique table but not tactic table: {missing}"


def test_all_tactic_ids_are_valid_format():
    # MITRE Enterprise tactic IDs are TA0001-TA0043
    valid_ids = {f"TA00{n:02d}" for n in range(1, 50)}
    for tactics in list(SET_ROLE_TO_TACTICS.values()) + list(MO_TO_TACTICS.values()):
        for t in tactics:
            assert t in valid_ids, f"Invalid tactic ID: {t}"


def test_all_technique_ids_have_t_prefix():
    for techs in list(SET_ROLE_TO_TECHNIQUES.values()) + list(MO_TO_TECHNIQUES.values()):
        for t in techs:
            assert t.startswith("T") and t[1:].isdigit(), f"Bad technique ID format: {t}"
