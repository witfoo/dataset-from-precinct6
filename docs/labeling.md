# Labeling Methodology

## Three-Tier Labels

- **malicious**: Events embedded as leads inside confirmed security incidents
- **suspicious**: Events matching WitFoo's 261 lead detection rules but not in confirmed incidents
- **benign**: Events not matching any rules or incidents

All labels are derived from Precinct's automated correlation pipeline. None are human-verified -- the `disposition` column carries the analyst's incident status (e.g., `False Positive`, `Resolved`) where it exists, but coverage is uneven.

## Lead Detection Rules

261 rules that define what makes a security event suspicious. Each rule specifies:

- **Criteria**: Match conditions (streamName, messageType, action, severity, eventId)
- **Client/Server set roles**: Attack classification (Exploiting Host, C2 Server, etc.)
- **Product ID**: Which security product the rule applies to

See `data/lead_rules_catalog.json` for the complete catalog.

## MITRE ATT&CK Mapping

`attack_tactics` and `attack_techniques` are populated by mapping two sources:

1. **WitFoo set role names** attached to the event (from matched lead rules for `suspicious` events, or from the parent incident's sets for `malicious` events).
2. **Modus operandi** name on the parent incident (`malicious` events only).

The mapping is heuristic and lives in [`src/precinct6_dataset/mitre_mapping.py`](../src/precinct6_dataset/mitre_mapping.py). Tactic IDs are the standard MITRE ATT&CK Enterprise tactic codes; technique IDs are top-level techniques (no sub-techniques) representing the most likely category for a given role.

These mappings are **priors, not analyst-confirmed identifications**. A `C2 Server` set role yields `T1071` (Application Layer Protocol) with high prior probability, but the actual technique for a specific event may differ. Researchers wanting precise per-event technique attribution should treat the published values as a starting point.

For `benign` events, both lists are empty.

## Lifecycle Stage (Internal Kill Chain)

The `lifecycle_stage` field maps to WitFoo's internal kill-chain model:

1. `initial-compromise` — Initial access
2. `establish-foothold` — Execution and persistence
3. `escalate-privilege` — Privilege escalation
4. `internal-reconnaissance` — Discovery
5. `move-laterally` — Lateral movement
6. `maintain-persistence` — C2 and persistence
7. `complete-mission` — Exfiltration and impact
8. `policy-violation` — Policy violations

For incident-derived events the stage is set from the modus operandi; for rule-matched events it is set from the first set role attached to the matched rule.

## Label Confidence

`label_confidence` is a coarse heuristic in [0, 1] indicating how much corroborating signal Precinct found for the assigned label. **It is not a probability that the activity is malicious.**

| Label | Formula |
|-------|---------|
| `malicious` | `max(0.6, suspicion_score)` clamped to 0.95; lowered to 0.3 if analyst marked False Positive |
| `suspicious` | `0.4 + 0.1 * n_rules_matched + 0.05 * n_set_roles` clamped to 0.85 |
| `benign` | `0.5` (no positive evidence either way) |

See [`compute_label_confidence`](../src/precinct6_dataset/label.py) for the implementation. Earlier dataset builds (including the `precinct6-cybersecurity-100m` snapshot) hardcoded 0.5 / 0.6 / `suspicion_score`; regenerated datasets use the formulas above.

## Suspicion Score

`suspicion_score` is propagated unchanged from Precinct's incident-level score and is only meaningful on `malicious` events. For `suspicious` and `benign` events it is 0.0.

## Per-Edge Attribution in Graph Output

For provenance graph exports, `attack_tactics`, `attack_techniques`, `set_roles`, `mo_name`, `lifecycle_stage`, `label_binary`, `label_confidence`, `suspicion_score`, and `disposition` are attached at the **edge** level (in both NDJSON and GraphML). They describe the labels of the specific signal that produced the edge, not the dataset as a whole.
