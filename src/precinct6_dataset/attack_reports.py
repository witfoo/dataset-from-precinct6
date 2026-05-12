"""Generate natural-language attack reports from sanitized incident data.

Produces one paragraph per incident, deterministically composed from structured
fields in incidents.jsonl (mo_name, set roles, lead descriptions, matched rules,
MITRE mappings, timestamps).

This is a TEMPLATE-only generator — no LLM, no API key, fully reproducible.
Researchers can audit the exact derivation by reading this module.

Output: data/sanitized/attack_reports.jsonl
  One JSON object per incident with:
  - incident_id
  - report_text (the narrative paragraph)
  - report_source = "template"
  - mo_name, suspicion_score, status_name, disposition
  - attack_techniques, attack_tactics
  - lead_count, first_observed_at, last_observed_at
  - set_role_names
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import orjson

from precinct6_dataset.config import SANITIZED_DIR
from precinct6_dataset.label import (
    MO_TO_LIFECYCLE,
    SET_ROLE_TO_LIFECYCLE,
    STATUS_TO_DISPOSITION,
    _extract_techniques_from_frameworks,
)
from precinct6_dataset.mitre_mapping import (
    tactics_for_set_roles,
    tactics_for_mo,
    techniques_for_set_roles,
    techniques_for_mo,
    merge_unique,
)


def _format_timestamp(ts) -> str:
    """Convert Unix timestamp (int or float) to ISO 8601 UTC."""
    if not ts:
        return "unknown time"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return "unknown time"


def _extract_incident_summary(incident: dict) -> dict:
    """Extract structured summary fields from an incident."""
    inc_id = incident.get("id", "unknown")
    name = incident.get("name", "")
    mo_name = incident.get("mo_name", "Unknown")
    suspicion = incident.get("suspicion_score", 0)
    status = incident.get("status_name", "Unprocessed")
    disposition = STATUS_TO_DISPOSITION.get(status, "automated")

    first_obs = incident.get("first_observed_at", 0)
    last_obs = incident.get("last_observed_at", 0)

    # Collect set role names
    set_role_names = []
    sets = incident.get("sets", {})
    if isinstance(sets, dict):
        for s in sets.values():
            if isinstance(s, dict) and s.get("name"):
                set_role_names.append(s["name"])
    elif isinstance(sets, list):
        for s in sets:
            if isinstance(s, dict) and s.get("name"):
                set_role_names.append(s["name"])

    # MITRE tactics: union of set role tactics + MO tactics
    tactics = merge_unique(
        tactics_for_set_roles(set_role_names),
        tactics_for_mo(mo_name),
    )

    # Pull MITRE techniques from incident nodes + set role priors + MO priors
    tech_set = set()
    nodes = incident.get("nodes", {})
    node_count = 0
    if isinstance(nodes, dict):
        node_count = len(nodes)
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            products = node.get("products", {})
            if isinstance(products, dict):
                for prod in products.values():
                    if isinstance(prod, dict):
                        for t in _extract_techniques_from_frameworks(prod.get("frameworks", {})):
                            tech_set.add(t)
    techniques = merge_unique(
        sorted(tech_set),
        techniques_for_set_roles(set_role_names),
        techniques_for_mo(mo_name),
    )

    # Extract lead summaries
    leads = incident.get("leads", {})
    lead_count = len(leads) if isinstance(leads, dict) else 0
    lead_summaries = []  # list of {description, details, product_name, observed_at, set_id}
    matched_rules = set()  # deduped rule descriptions seen across leads
    products_observed = set()
    if isinstance(leads, dict):
        for lead in leads.values():
            if not isinstance(lead, dict):
                continue
            desc = (lead.get("description") or "").strip()
            details = (lead.get("details") or "").strip()
            obs = lead.get("observed_at", 0)
            prod = lead.get("product", {})
            prod_name = ""
            if isinstance(prod, dict):
                prod_name = prod.get("name", "")
                if prod_name:
                    products_observed.add(prod_name)
            lead_summaries.append({
                "description": desc,
                "details": details,
                "observed_at": obs,
                "product_name": prod_name,
                "set_id": lead.get("set_id", 0),
            })
            if desc:
                matched_rules.add(desc)

    # Edges (connections in the incident graph)
    edges = incident.get("edges", {})
    edge_count = len(edges) if isinstance(edges, dict) else 0

    return {
        "incident_id": inc_id,
        "name": name,
        "mo_name": mo_name,
        "suspicion_score": suspicion,
        "status_name": status,
        "disposition": disposition,
        "first_observed_at": first_obs,
        "last_observed_at": last_obs,
        "set_role_names": set_role_names,
        "attack_tactics": tactics,
        "attack_techniques": techniques,
        "node_count": node_count,
        "edge_count": edge_count,
        "lead_count": lead_count,
        "lead_summaries": lead_summaries,
        "matched_rules": sorted(matched_rules),
        "products_observed": sorted(products_observed),
        "lifecycle_stage": MO_TO_LIFECYCLE.get(mo_name, "unknown"),
    }


def _build_report_text(s: dict) -> str:
    """Compose a natural-language paragraph from the incident summary dict."""
    # Opening sentence
    inc_label = f"`{s['incident_id']}`"
    if s["name"]:
        inc_label += f" (`{s['name']}`)"
    sentences = []
    sentences.append(
        f"Incident {inc_label} was classified by WitFoo Precinct as **{s['mo_name']}** "
        f"with a suspicion score of {s['suspicion_score']:.2f} "
        f"and a final disposition of **{s['status_name']}** "
        f"(`disposition={s['disposition']}`)."
    )

    # Attack chain start
    first_obs_str = _format_timestamp(s["first_observed_at"])
    last_obs_str = _format_timestamp(s["last_observed_at"])
    duration = ""
    if s["first_observed_at"] and s["last_observed_at"]:
        try:
            delta = int(s["last_observed_at"]) - int(s["first_observed_at"])
            if delta > 0:
                if delta < 60:
                    duration = f" (duration: {delta}s)"
                elif delta < 3600:
                    duration = f" (duration: {delta // 60}m)"
                elif delta < 86400:
                    duration = f" (duration: {delta // 3600}h)"
                else:
                    duration = f" (duration: {delta // 86400}d)"
        except (ValueError, TypeError):
            pass

    sentences.append(
        f"The attack chain began at `{first_obs_str}` and was last observed at `{last_obs_str}`{duration}."
    )

    # Graph structure
    if s["node_count"] or s["edge_count"] or s["lead_count"]:
        graph_parts = []
        if s["lead_count"]:
            graph_parts.append(f"{s['lead_count']} triggering signal{'s' if s['lead_count'] != 1 else ''}")
        if s["node_count"]:
            graph_parts.append(f"{s['node_count']} node{'s' if s['node_count'] != 1 else ''}")
        if s["edge_count"]:
            graph_parts.append(f"{s['edge_count']} edge{'s' if s['edge_count'] != 1 else ''}")
        sentences.append(f"The incident graph contains {', '.join(graph_parts)}.")

    # Set roles
    if s["set_role_names"]:
        roles_str = ", ".join(s["set_role_names"][:6])
        if len(s["set_role_names"]) > 6:
            roles_str += f" (and {len(s['set_role_names']) - 6} more)"
        sentences.append(f"WitFoo classification roles assigned: {roles_str}.")

    # Detection rules
    if s["matched_rules"]:
        rules_str = ", ".join(f'"{r}"' for r in s["matched_rules"][:8])
        if len(s["matched_rules"]) > 8:
            rules_str += f", and {len(s['matched_rules']) - 8} more"
        sentences.append(f"Detection rules triggered: {rules_str}.")

    # Products observed
    if s["products_observed"]:
        prods_str = ", ".join(s["products_observed"][:6])
        if len(s["products_observed"]) > 6:
            prods_str += f" (and {len(s['products_observed']) - 6} more)"
        sentences.append(f"Security products that observed activity: {prods_str}.")

    # MITRE ATT&CK
    if s["attack_tactics"]:
        sentences.append(f"Mapped MITRE ATT&CK tactics: {', '.join(s['attack_tactics'])}.")
    if s["attack_techniques"]:
        techs_str = ", ".join(s["attack_techniques"][:10])
        if len(s["attack_techniques"]) > 10:
            techs_str += f", and {len(s['attack_techniques']) - 10} more"
        sentences.append(f"Mapped MITRE ATT&CK techniques: {techs_str}.")

    # Lifecycle
    if s["lifecycle_stage"] and s["lifecycle_stage"] != "unknown":
        sentences.append(
            f"Inferred kill-chain stage: `{s['lifecycle_stage']}`."
        )

    # First lead detail (helps researchers see actual evidence)
    if s["lead_summaries"]:
        first_lead = s["lead_summaries"][0]
        if first_lead["details"]:
            detail = first_lead["details"][:240]
            if len(first_lead["details"]) > 240:
                detail += "..."
            sentences.append(f"Sample triggering signal: `{detail}`.")

    # Closing provenance note
    sentences.append(
        "This report was generated deterministically from Precinct's structured incident "
        "metadata; it reflects Precinct's automated correlation engine output, not an "
        "independent threat-hunting investigation."
    )

    return " ".join(sentences)


def generate_attack_reports(sanitized_dir: Path = None, output_path: Path = None):
    """Generate attack_reports.jsonl from incidents.jsonl.

    Returns the number of reports generated.
    """
    sanitized_dir = sanitized_dir or SANITIZED_DIR
    incidents_file = sanitized_dir / "incidents.jsonl"
    output_path = output_path or (sanitized_dir / "attack_reports.jsonl")

    if not incidents_file.exists():
        print(f"  No incidents file found at {incidents_file}")
        return 0

    print(f"  Generating attack reports from {incidents_file}...")
    count = 0
    with open(incidents_file, "rb") as fin, open(output_path, "wb") as fout:
        for line in fin:
            if not line.strip():
                continue
            try:
                incident = orjson.loads(line)
            except Exception:
                continue

            summary = _extract_incident_summary(incident)
            report_text = _build_report_text(summary)

            report = {
                "incident_id": summary["incident_id"],
                "report_text": report_text,
                "report_source": "template",
                "mo_name": summary["mo_name"],
                "suspicion_score": summary["suspicion_score"],
                "status_name": summary["status_name"],
                "disposition": summary["disposition"],
                "attack_techniques": summary["attack_techniques"],
                "attack_tactics": summary["attack_tactics"],
                "lead_count": summary["lead_count"],
                "node_count": summary["node_count"],
                "edge_count": summary["edge_count"],
                "first_observed_at": summary["first_observed_at"],
                "last_observed_at": summary["last_observed_at"],
                "set_role_names": summary["set_role_names"],
                "matched_rules": summary["matched_rules"],
                "products_observed": summary["products_observed"],
                "lifecycle_stage": summary["lifecycle_stage"],
            }
            fout.write(orjson.dumps(report))
            fout.write(b"\n")
            count += 1

    print(f"  Wrote {count:,} attack reports to {output_path}")
    return count


if __name__ == "__main__":
    import sys
    san_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else SANITIZED_DIR
    generate_attack_reports(san_dir)
