# Labeling Methodology

## Three-Tier Labels

- **malicious**: Events embedded as leads inside confirmed security incidents
- **suspicious**: Events matching WitFoo's 261 lead detection rules but not in confirmed incidents
- **benign**: Events not matching any rules or incidents

## Lead Detection Rules

261 rules that define what makes a security event suspicious. Each rule specifies:
- **Criteria**: Match conditions (streamName, messageType, action, severity, eventId)
- **Client/Server set roles**: Attack classification (Exploiting Host, C2 Server, etc.)
- **Product ID**: Which security product the rule applies to

See `data/lead_rules_catalog.json` for the complete catalog.

## MITRE ATT&CK Mapping

The `lifecycle_stage` field maps to the APT kill chain:
1. `initial-compromise` — Initial access
2. `establish-foothold` — Execution and persistence
3. `escalate-privilege` — Privilege escalation
4. `internal-reconnaissance` — Discovery
5. `move-laterally` — Lateral movement
6. `maintain-persistence` — C2 and persistence
7. `complete-mission` — Exfiltration and impact
8. `policy-violation` — Policy violations
