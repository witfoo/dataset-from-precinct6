"""Labeling system — attach security labels from WitFoo incident analysis.

Labels include:
- Binary classification (malicious/benign/suspicious/unknown)
- MITRE ATT&CK technique IDs
- MITRE D3FEND defense techniques
- Modus operandi (attack campaign type)
- Suspicion score
- Kill chain lifecycle stage
- Matched lead rule descriptions
- WitFoo classification set roles (Exploiting Host, Staging Target, etc.)
- Product and vendor attribution

The key insight: incidents contain EMBEDDED artifact data inside their leads.
These embedded artifacts ARE the malicious events. We extract them, label them
with metadata from the parent incident, and merge them into the signal dataset.

Additionally, artifacts with matchedLeadRuleIds are tagged as "suspicious" with
rule descriptions, even if they don't appear in any incident.
"""

import json
from pathlib import Path
from collections import defaultdict

import orjson

from precinct6_dataset.config import SANITIZED_DIR
from precinct6_dataset.mitre_mapping import (
    SET_ROLE_TO_TACTICS as MITRE_SET_ROLE_TO_TACTICS,
    SET_ROLE_TO_TECHNIQUES,
    MO_TO_TACTICS as MITRE_MO_TO_TACTICS,
    MO_TO_TECHNIQUES,
    tactics_for_set_roles,
    techniques_for_set_roles,
    tactics_for_mo,
    techniques_for_mo,
    merge_unique,
)


# Modus operandi to kill chain lifecycle stage mapping
MO_TO_LIFECYCLE = {
    "Data Theft": "complete-mission",
    "Ransomware": "complete-mission",
    "Credential Theft": "credential-access",
    "Lateral Movement": "move-laterally",
    "Reconnaissance": "initial-reconnaissance",
    "Privilege Escalation": "escalate-privilege",
    "Command and Control": "maintain-persistence",
    "Exfiltration": "complete-mission",
    "Initial Access": "initial-compromise",
    "Persistence": "maintain-persistence",
    "Defense Evasion": "move-laterally",
    "Discovery": "internal-reconnaissance",
    "Collection": "complete-mission",
    "Execution": "establish-foothold",
    "Impact": "complete-mission",
    "Phishing": "initial-compromise",
}

# Modus operandi to MITRE ATT&CK tactic IDs (TA0001-style codes from mitre_mapping.py)
MO_TO_TACTICS = MITRE_MO_TO_TACTICS

# MITRE ATT&CK tactic to lifecycle stage mapping
TACTIC_TO_LIFECYCLE = {
    "initial-access": "initial-compromise",
    "execution": "establish-foothold",
    "persistence": "maintain-persistence",
    "privilege-escalation": "escalate-privilege",
    "defense-evasion": "move-laterally",
    "credential-access": "credential-access",
    "discovery": "internal-reconnaissance",
    "lateral-movement": "move-laterally",
    "collection": "complete-mission",
    "command-and-control": "maintain-persistence",
    "exfiltration": "complete-mission",
    "impact": "complete-mission",
    "reconnaissance": "initial-reconnaissance",
    "resource-development": "initial-reconnaissance",
}


# WitFoo classification set ID to name/role mapping
SET_ID_TO_ROLE = {}  # Populated from catalog

# WitFoo set roles to lifecycle stage
SET_ROLE_TO_LIFECYCLE = {
    "Exploiting Host": "initial-compromise",
    "Exploiting Target": "initial-compromise",
    "Staging Host": "establish-foothold",
    "Staging Target": "establish-foothold",
    "Exfiltration Host": "complete-mission",
    "Exfiltration Target": "complete-mission",
    "C2 Server": "maintain-persistence",
    "Bot": "maintain-persistence",
    "Reconnaissance Host": "initial-reconnaissance",
    "Reconnaissance Target": "initial-reconnaissance",
    "Disruption Host": "complete-mission",
    "Disruption Target": "complete-mission",
    "Phishing Site": "initial-compromise",
    "Phished User": "initial-compromise",
    "Phished Host": "initial-compromise",
    "Ransomware Malware": "complete-mission",
    "Ransomware Target": "complete-mission",
    "Ransomware Source": "complete-mission",
    "Policy Violation User": "policy-violation",
    "Policy Violation Target": "policy-violation",
    "Policy Violation Host": "policy-violation",
    "Suspicious User": "unknown",
    "Malicious File": "establish-foothold",
    "Malicious Email": "initial-compromise",
}

# WitFoo set roles to MITRE ATT&CK tactic IDs (TA0001-style from mitre_mapping.py)
SET_ROLE_TO_TACTICS = MITRE_SET_ROLE_TO_TACTICS

# WitFoo status_name to disposition (UC ground-truth question)
STATUS_TO_DISPOSITION = {
    "Disrupted": "confirmed-malicious",
    "Investigating": "confirmed-malicious",
    "Resolved": "confirmed-malicious",
    "Dismissed": "dismissed",
    "False Positive": "false-positive",
    "Unprocessed": "automated",
}


def _extract_techniques_from_frameworks(frameworks: dict) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from a product's frameworks dict.

    WitFoo product frameworks contain keys like 'attck', 'attack', or 'mitre' with
    technique ID arrays. Format is typically ['T1003', 'T1003.001', ...].
    """
    techniques = []
    if not isinstance(frameworks, dict):
        return techniques
    for key in ("attck", "attack", "mitre_attack", "mitre"):
        val = frameworks.get(key)
        if isinstance(val, list):
            for t in val:
                if isinstance(t, str) and t.upper().startswith("T") and t[1:].split(".")[0].isdigit():
                    techniques.append(t.upper())
                elif isinstance(t, int):
                    techniques.append(f"T{t:04d}")
    return techniques


def compute_label_confidence(
    label_binary: str,
    suspicion_score: float = 0.0,
    n_rules_matched: int = 0,
    n_set_roles: int = 0,
    is_false_positive: bool = False,
) -> float:
    """Compute label_confidence in [0, 1] from label tier and corroborating evidence.

    Documented formula (see docs/labeling.md):
      - benign:     0.5 (no positive evidence either way)
      - suspicious: 0.4 + 0.1 * n_rules_matched + 0.05 * n_set_roles, clamped to [0.5, 0.85]
      - malicious:  max(0.6, suspicion_score), clamped to 0.95; lowered to 0.3 if False Positive
    """
    label = (label_binary or "").lower()
    if label == "malicious":
        if is_false_positive:
            return 0.3
        return float(min(0.95, max(0.6, suspicion_score)))
    if label == "suspicious":
        raw = 0.4 + 0.1 * n_rules_matched + 0.05 * n_set_roles
        return float(min(0.85, max(0.5, raw)))
    return 0.5


class Labeler:
    """Attach security labels to sanitized records using incident data and lead rules."""

    def __init__(self, sanitized_dir: Path = None):
        self.sanitized_dir = sanitized_dir or SANITIZED_DIR
        self.incident_labels = {}  # incident_id -> label dict
        self.malicious_artifacts = []  # list of (artifact_dict, labels) from incident leads
        self.rule_catalog = {}  # rule_id -> rule info
        self.set_catalog = {}  # set_id -> set name
        self.product_catalog = {}  # product_id -> product info
        self.stream_to_product = {}  # stream_name -> product info
        self._load_catalog()

    def _load_catalog(self):
        """Load lead rules, products, and sets from the catalog file."""
        catalog_path = Path("data/lead_rules_catalog.json")
        if not catalog_path.exists():
            print("  Warning: No lead_rules_catalog.json found, rule tagging disabled")
            return

        with open(catalog_path) as f:
            catalog = json.load(f)

        # Lead rules: id -> {description, criteria, client_set_id, server_set_id, product_id}
        for rule in catalog.get("lead_rules", []):
            self.rule_catalog[rule["id"]] = rule

        # Sets: id -> name
        self.set_catalog = {int(k): v for k, v in catalog.get("sets", {}).items()}

        # Products: id -> {name, vendor, streams, frameworks}
        for pid, prod in catalog.get("products", {}).items():
            self.product_catalog[int(pid)] = prod

        # Stream-to-product mapping
        self.stream_to_product = catalog.get("stream_to_product", {})

        print(f"  Loaded catalog: {len(self.rule_catalog)} rules, "
              f"{len(self.set_catalog)} sets, {len(self.product_catalog)} products, "
              f"{len(self.stream_to_product)} stream mappings")

    def _get_rule_labels(self, matched_rule_ids: list) -> dict:
        """Derive labels from matched lead rule IDs."""
        if not matched_rule_ids or not self.rule_catalog:
            return {}

        descriptions = []
        set_roles = []
        product_names = set()
        vendor_names = set()
        lifecycle_stages = set()

        for rid in matched_rule_ids:
            rule = self.rule_catalog.get(rid)
            if not rule:
                continue

            descriptions.append(rule.get("description", f"Rule-{rid}"))

            # Map set IDs to roles
            client_set_raw = rule.get("client_set_id", 0)
            server_set_raw = rule.get("server_set_id", 0)
            # Set IDs encode product_id * 1000 + base_set_id
            for set_raw in [client_set_raw, server_set_raw]:
                base_set = set_raw % 1000 if set_raw > 1000 else set_raw
                set_name = self.set_catalog.get(base_set, "")
                if set_name:
                    set_roles.append(set_name)
                    lifecycle = SET_ROLE_TO_LIFECYCLE.get(set_name, "")
                    if lifecycle:
                        lifecycle_stages.add(lifecycle)

            # Map product
            pid = rule.get("product_id", 0)
            prod = self.product_catalog.get(pid)
            if prod:
                product_names.add(prod.get("name", ""))
                vendor_names.add(prod.get("vendor", ""))

        return {
            "matched_rules": descriptions,
            "set_roles": list(set(set_roles)),
            "product_names": list(product_names),
            "vendor_names": list(vendor_names),
            "lifecycle_stages": list(lifecycle_stages),
        }

    def _get_stream_product(self, stream_name: str) -> dict:
        """Look up product/vendor for a stream name."""
        if not stream_name or not self.stream_to_product:
            return {}
        info = self.stream_to_product.get(stream_name.lower(), {})
        return {
            "product_name": info.get("product_name", ""),
            "vendor_name": info.get("vendor", ""),
        } if info else {}

    def build_index(self):
        """Extract malicious artifacts embedded in incident leads.

        Incidents contain full artifact data inside each lead — these are the
        artifacts that triggered the incident. We extract them and attach labels
        from the parent incident.
        """
        incidents_file = self.sanitized_dir / "incidents.jsonl"
        if not incidents_file.exists():
            print("  No incidents file found, skipping index build")
            return

        print("  Extracting malicious artifacts from incident leads...")
        seen_artifacts = set()  # deduplicate by lead id

        with open(incidents_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    incident = orjson.loads(line)
                except Exception:
                    continue

                inc_id = incident.get("id", "")
                labels = self._extract_incident_labels(incident)
                self.incident_labels[inc_id] = labels

                # Extract embedded artifacts from leads
                leads = incident.get("leads", {})
                if isinstance(leads, dict):
                    for lead_id, lead in leads.items():
                        if not isinstance(lead, dict):
                            continue
                        # Skip duplicates (same lead can appear in multiple incidents)
                        if lead_id in seen_artifacts:
                            continue
                        seen_artifacts.add(lead_id)

                        artifact = lead.get("artifact", {})
                        if not isinstance(artifact, dict) or not artifact:
                            continue

                        # Build a signal-compatible artifact record from the embedded data
                        signal_record = self._lead_artifact_to_signal(artifact, lead, labels)
                        self.malicious_artifacts.append(signal_record)

        print(f"  Indexed {len(self.incident_labels):,} incidents, "
              f"extracted {len(self.malicious_artifacts):,} malicious artifacts from leads")

    def _lead_artifact_to_signal(self, artifact: dict, lead: dict, labels: dict) -> dict:
        """Convert an embedded lead artifact into a signal-compatible record with labels."""
        # The embedded artifact has different field names than our extracted artifacts
        # Map common fields
        record = {}

        # Copy all artifact fields
        for k, v in artifact.items():
            record[k] = v

        # Ensure key fields exist with normalized names
        if "messageType" not in record and "messagetype" in record:
            record["messageType"] = record["messagetype"]
        if "streamName" not in record and "streamname" in record:
            record["streamName"] = record["streamname"]

        # Add timing from lead
        observed_at = lead.get("observed_at", 0)
        if observed_at:
            record["_created_at"] = float(observed_at)

        # Add source info
        record["_source"] = "incident_lead"
        record["_incident_id"] = labels.get("incident_id", "")

        # Compute label_confidence using documented formula in compute_label_confidence
        suspicion = float(labels.get("suspicion_score", 0.0) or 0.0)
        is_fp = labels.get("is_false_positive", False)
        label_confidence = compute_label_confidence(
            "malicious",
            suspicion_score=suspicion,
            is_false_positive=is_fp,
        )

        # Attach labels
        status_name = labels.get("status_name", "")
        record["_labels"] = {
            "label_binary": "malicious",
            "label_confidence": label_confidence,
            "attack_techniques": labels.get("attack_techniques", []),
            "attack_tactics": labels.get("attack_tactics", []),
            "defense_techniques": labels.get("defense_techniques", []),
            "set_roles": labels.get("set_role_names", []),
            "mo_name": labels.get("mo_name", ""),
            "suspicion_score": suspicion,
            "incident_ids": [labels.get("incident_id", "")],
            "lifecycle_stage": labels.get("lifecycle_stage", "unknown"),
            # disposition = raw Precinct status_name (e.g., "Resolved", "False Positive",
            # "Disrupted", "Investigating", "Dismissed", "Unprocessed"). Use the helper
            # STATUS_TO_DISPOSITION mapping if you need bucketed categories
            # (confirmed-malicious / false-positive / dismissed / automated).
            "disposition": status_name or "Unprocessed",
            "disposition_category": labels.get("disposition_category", "automated"),
            "status_name": status_name,
            "is_false_positive": bool(is_fp),
        }

        return record

    def _extract_incident_labels(self, incident: dict) -> dict:
        """Extract label information from an incident record.

        Pulls MITRE ATT&CK techniques and tactics from three sources:
        1. node.products.{pid}.frameworks (direct per-product framework data)
        2. lead_rules_catalog.json::products[pid].frameworks (fallback by product ID)
        3. SET_ROLE_TO_TACTICS / MO_TO_TACTICS mappings (derived from set roles + MO)
        """
        attack_techniques = set()
        attack_tactics = set()
        defense_techniques = set()
        set_role_names = []

        # Extract set role names from multiple sources:
        # 1. incident.sets — list of integer set IDs OR dict of set objects
        # 2. incident.nodes.{uuid}.sets — dict of full set objects (most reliable)
        # 3. Resolve integer IDs via self.set_catalog (loaded from lead_rules_catalog.json)
        sets = incident.get("sets", {})
        if isinstance(sets, dict):
            for set_obj in sets.values():
                if isinstance(set_obj, dict):
                    set_name = set_obj.get("name", "")
                    if set_name:
                        set_role_names.append(set_name)
        elif isinstance(sets, list):
            for s in sets:
                if isinstance(s, dict):
                    set_name = s.get("name", "")
                    if set_name:
                        set_role_names.append(set_name)
                elif isinstance(s, int):
                    # Integer set ID — look up name in catalog
                    name = self.set_catalog.get(s, "")
                    if name:
                        set_role_names.append(name)

        # Pull set names + frameworks from nodes (richer data than incident.sets)
        nodes = incident.get("nodes", {})
        if isinstance(nodes, dict):
            for node in nodes.values():
                if not isinstance(node, dict):
                    continue
                # Set roles from node.sets (dict of {set_id_str: {id, name, ...}})
                node_sets = node.get("sets", {})
                if isinstance(node_sets, dict):
                    for s in node_sets.values():
                        if isinstance(s, dict):
                            n = s.get("name", "")
                            if n and n not in set_role_names:
                                set_role_names.append(n)
                products = node.get("products", {})
                if isinstance(products, dict):
                    for pid_str, prod in products.items():
                        if isinstance(prod, dict):
                            fw = prod.get("frameworks", {})
                            for t in _extract_techniques_from_frameworks(fw):
                                attack_techniques.add(t)
                            # Defense techniques (D3FEND)
                            if isinstance(fw, dict):
                                for k in ("d3fend", "defense", "mitigation"):
                                    val = fw.get(k)
                                    if isinstance(val, list):
                                        for d in val:
                                            if isinstance(d, str):
                                                defense_techniques.add(d)
                        # Fallback: look up product in catalog
                        try:
                            pid = int(pid_str)
                            if pid in self.product_catalog:
                                fw = self.product_catalog[pid].get("frameworks", {})
                                if isinstance(fw, dict):
                                    for t in _extract_techniques_from_frameworks(fw):
                                        attack_techniques.add(t)
                        except (ValueError, TypeError):
                            pass

        # Derive tactics from all set role names (collected above)
        for t in tactics_for_set_roles(set_role_names):
            attack_tactics.add(t)

        # Modus operandi — add MO-derived tactics and techniques
        mo_name = incident.get("mo_name", "")
        for t in tactics_for_mo(mo_name):
            attack_tactics.add(t)
        for t in techniques_for_mo(mo_name):
            attack_techniques.add(t)
        # Set-role-derived techniques (heuristic priors)
        for t in techniques_for_set_roles(set_role_names):
            attack_techniques.add(t)

        # Suspicion score
        suspicion = incident.get("suspicion_score", 0)

        # Status & disposition
        status = incident.get("status_name", "Unprocessed")
        status_id = incident.get("status_id", 0)
        disposition = STATUS_TO_DISPOSITION.get(status, "automated")

        # Determine lifecycle stage (prefer MO, fall back to first set role)
        lifecycle = MO_TO_LIFECYCLE.get(mo_name, "unknown")
        if lifecycle == "unknown" and set_role_names:
            for role in set_role_names:
                if role in SET_ROLE_TO_LIFECYCLE:
                    lifecycle = SET_ROLE_TO_LIFECYCLE[role]
                    break

        # Determine if false positive
        is_false_positive = status == "False Positive"

        return {
            "attack_techniques": sorted(attack_techniques),
            "attack_tactics": sorted(attack_tactics),
            "defense_techniques": sorted(defense_techniques),
            "set_role_names": set_role_names,
            "mo_name": mo_name,
            "suspicion_score": suspicion,
            "status_name": status,
            "status_id": status_id,
            "disposition": status or "Unprocessed",  # raw status_name
            "disposition_category": disposition,  # bucketed: confirmed-malicious/false-positive/...
            "lifecycle_stage": lifecycle,
            "incident_id": incident.get("id", ""),
            "is_false_positive": is_false_positive,
        }

    def label_artifact(self, artifact: dict) -> dict:
        """Attach labels to an artifact using matched lead rules and product mapping."""
        # Check for matched lead rules
        matched_rule_ids = artifact.get("matchedLeadRuleIds", [])
        rule_labels = self._get_rule_labels(matched_rule_ids) if matched_rule_ids else {}
        matched_rules = rule_labels.get("matched_rules", [])

        # Get product/vendor from stream name
        stream_name = artifact.get("streamName", artifact.get("streamname", ""))
        stream_product = self._get_stream_product(stream_name)

        # Derive attack tactics from matched rules' set roles
        attack_tactics = set()
        for role in rule_labels.get("set_roles", []):
            for t in SET_ROLE_TO_TACTICS.get(role, []):
                attack_tactics.add(t)

        # Determine label: suspicious if rules matched, benign otherwise.
        # label_confidence follows the documented formula in compute_label_confidence.
        n_set_roles = len(rule_labels.get("set_roles", []))
        if matched_rule_ids and matched_rules:
            label_binary = "suspicious"
            label_confidence = compute_label_confidence(
                "suspicious",
                n_rules_matched=len(matched_rules),
                n_set_roles=n_set_roles,
            )
            lifecycle = rule_labels.get("lifecycle_stages", ["unknown"])
            lifecycle_stage = lifecycle[0] if lifecycle else "unknown"
            # suspicion_score stays at 0.0 for suspicious (only meaningful for malicious;
            # see docs/labeling.md). Use label_confidence for graded rule-level signal.
            suspicion = 0.0
        else:
            label_binary = "benign"
            label_confidence = compute_label_confidence("benign")
            lifecycle_stage = "none"
            suspicion = 0.0

        artifact["_labels"] = {
            "label_binary": label_binary,
            "label_confidence": label_confidence,
            "attack_techniques": [],
            "attack_tactics": list(attack_tactics) if isinstance(attack_tactics, set) else attack_tactics,
            "defense_techniques": [],
            "mo_name": "",
            "suspicion_score": suspicion,
            "incident_ids": [],
            "lifecycle_stage": lifecycle_stage,
            "disposition": "Unprocessed",  # raw status_name (events not in any incident)
            "disposition_category": "automated",
            "status_name": "",
            "is_false_positive": False,
            "matched_rules": matched_rules,
            "set_roles": rule_labels.get("set_roles", []),
            "product_name": stream_product.get("product_name", "") or
                           (rule_labels.get("product_names", [""])[0] if rule_labels.get("product_names") else ""),
            "vendor_name": stream_product.get("vendor_name", "") or
                          (rule_labels.get("vendor_names", [""])[0] if rule_labels.get("vendor_names") else ""),
        }
        return artifact

    def label_all(self):
        """Label all sanitized artifacts and append malicious artifacts from incidents."""
        self.build_index()

        artifacts_file = self.sanitized_dir / "artifacts.jsonl"
        if not artifacts_file.exists():
            print("  No artifacts file found")
            return

        output_file = self.sanitized_dir / "artifacts_labeled.jsonl"
        count = 0
        labeled_malicious = 0
        labeled_benign = 0

        with open(artifacts_file, "rb") as fin, open(output_file, "wb") as fout:
            # 1. Label existing artifacts as benign
            for line in fin:
                if not line.strip():
                    continue
                try:
                    record = orjson.loads(line)
                    labeled = self.label_artifact(record)
                    fout.write(orjson.dumps(labeled))
                    fout.write(b"\n")
                    count += 1
                    labeled_benign += 1
                except Exception:
                    continue

            # 2. Append malicious artifacts extracted from incident leads
            for record in self.malicious_artifacts:
                labels = record.get("_labels", {})
                # Skip false positives
                if labels.get("is_false_positive") or \
                   record.get("_labels", {}).get("label_binary") != "malicious":
                    # Check parent incident
                    pass

                try:
                    fout.write(orjson.dumps(record))
                    fout.write(b"\n")
                    count += 1
                    labeled_malicious += 1
                except Exception:
                    continue

        print(f"  Labeled {count:,} artifacts: "
              f"{labeled_malicious:,} malicious, {labeled_benign:,} benign, "
              f"{count - labeled_malicious - labeled_benign:,} unknown")
