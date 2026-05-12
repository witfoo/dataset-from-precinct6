"""MITRE ATT&CK mapping tables.

Maps WitFoo classification artifacts (set roles, modus operandi names,
kill-chain stages, and stream message types) onto MITRE ATT&CK tactic
and technique IDs.

These mappings are derived from the semantics of WitFoo set role names and
modus operandi categories, not from analyst-confirmed per-event labels.
The mapping is many-to-many: a single set role may indicate multiple
plausible tactics, and a single tactic may match multiple set roles.

Tactic IDs are the standard MITRE ATT&CK Enterprise tactic codes
(https://attack.mitre.org/tactics/enterprise/). Technique IDs are top-level
techniques only (no sub-techniques) and represent the most likely category
for a given role; researchers wanting precise per-event technique attribution
should treat these as priors rather than ground truth.
"""

# MITRE ATT&CK tactic IDs (Enterprise matrix)
TACTIC_RECONNAISSANCE = "TA0043"
TACTIC_RESOURCE_DEVELOPMENT = "TA0042"
TACTIC_INITIAL_ACCESS = "TA0001"
TACTIC_EXECUTION = "TA0002"
TACTIC_PERSISTENCE = "TA0003"
TACTIC_PRIVILEGE_ESCALATION = "TA0004"
TACTIC_DEFENSE_EVASION = "TA0005"
TACTIC_CREDENTIAL_ACCESS = "TA0006"
TACTIC_DISCOVERY = "TA0007"
TACTIC_LATERAL_MOVEMENT = "TA0008"
TACTIC_COLLECTION = "TA0009"
TACTIC_COMMAND_AND_CONTROL = "TA0011"
TACTIC_EXFILTRATION = "TA0010"
TACTIC_IMPACT = "TA0040"


# WitFoo set role -> list of MITRE ATT&CK tactic IDs.
# Roles are taken from data/lead_rules_catalog.json sets table (~95 unique names).
SET_ROLE_TO_TACTICS = {
    # Reconnaissance / scanning
    "Reconnaissance Host": [TACTIC_RECONNAISSANCE, TACTIC_DISCOVERY],
    "Reconnaissance Target": [TACTIC_RECONNAISSANCE, TACTIC_DISCOVERY],
    "Recon Hardware": [TACTIC_RECONNAISSANCE, TACTIC_DISCOVERY],
    "Recon Service": [TACTIC_RECONNAISSANCE, TACTIC_DISCOVERY],
    "Network Scanner": [TACTIC_DISCOVERY],
    # Initial access / exploitation
    "Exploiting Host": [TACTIC_INITIAL_ACCESS, TACTIC_EXECUTION],
    "Exploiting Target": [TACTIC_INITIAL_ACCESS],
    "Exploited Hardware": [TACTIC_INITIAL_ACCESS],
    "Exploited Service": [TACTIC_INITIAL_ACCESS],
    "Phishing Site": [TACTIC_INITIAL_ACCESS],
    "Phishing Email": [TACTIC_INITIAL_ACCESS],
    "Phishing Hardware": [TACTIC_INITIAL_ACCESS],
    "Phishing Service": [TACTIC_INITIAL_ACCESS],
    "Phished Host": [TACTIC_INITIAL_ACCESS],
    "Phished User": [TACTIC_INITIAL_ACCESS],
    # Execution / staging
    "Staging Host": [TACTIC_EXECUTION, TACTIC_PERSISTENCE],
    "Staging Target": [TACTIC_EXECUTION, TACTIC_PERSISTENCE],
    "Staging Hardware": [TACTIC_EXECUTION, TACTIC_PERSISTENCE],
    "Staging Service": [TACTIC_EXECUTION, TACTIC_PERSISTENCE],
    "Malicious File": [TACTIC_EXECUTION],
    "Malicious Email": [TACTIC_INITIAL_ACCESS, TACTIC_EXECUTION],
    # Command and control
    "C2 Server": [TACTIC_COMMAND_AND_CONTROL],
    "Bot": [TACTIC_COMMAND_AND_CONTROL],
    "Botnet Hardware": [TACTIC_COMMAND_AND_CONTROL],
    "Botnet Service": [TACTIC_COMMAND_AND_CONTROL],
    # Exfiltration
    "Exfiltration Host": [TACTIC_EXFILTRATION, TACTIC_COLLECTION],
    "Exfiltration Target": [TACTIC_EXFILTRATION],
    "Exfiltration Hardware": [TACTIC_EXFILTRATION],
    "Exfiltration Service": [TACTIC_EXFILTRATION],
    # Disruption / impact
    "Disruption Host": [TACTIC_IMPACT],
    "Disruption Target": [TACTIC_IMPACT],
    "Disruption Hardware": [TACTIC_IMPACT],
    "Disruption Service": [TACTIC_IMPACT],
    "Disrupted Service": [TACTIC_IMPACT],
    # Ransomware
    "Ransomware Source": [TACTIC_INITIAL_ACCESS, TACTIC_IMPACT],
    "Ransomware Target": [TACTIC_IMPACT],
    "Ransomware Malware": [TACTIC_EXECUTION, TACTIC_IMPACT],
    "Ransomware Hardware": [TACTIC_IMPACT],
    "Ransomware Service": [TACTIC_IMPACT],
    "Ransomware User": [TACTIC_IMPACT],
    # Financial
    "Financial Exploit Target": [TACTIC_IMPACT],
    "Financial Exploiting File": [TACTIC_EXECUTION, TACTIC_IMPACT],
    "Financial Exploiting Hardware": [TACTIC_IMPACT],
    "Financial Exploiting Host": [TACTIC_IMPACT],
    "Financial Exploiting Service": [TACTIC_IMPACT],
    "Financial Exploiting User": [TACTIC_IMPACT],
    "Financial Account": [TACTIC_COLLECTION],
    # ICS / SCADA
    "SCADA Exploit Target": [TACTIC_IMPACT],
    "SCADA Exploiting File": [TACTIC_EXECUTION, TACTIC_IMPACT],
    "SCADA Exploiting Hardware": [TACTIC_IMPACT],
    "SCADA Exploiting Host": [TACTIC_IMPACT],
    "SCADA Exploiting Service": [TACTIC_IMPACT],
    "SCADA Exploiting User": [TACTIC_IMPACT],
    # Suspicious user activity (ambiguous tactic — leave empty)
    "Suspicious User": [],
}


# Modus operandi (incident campaign type) -> list of MITRE ATT&CK tactic IDs.
# Source values come from incident.mo_name in the WitFoo Precinct schema.
MO_TO_TACTICS = {
    "Data Theft": [TACTIC_COLLECTION, TACTIC_EXFILTRATION],
    "Ransomware": [TACTIC_INITIAL_ACCESS, TACTIC_EXECUTION, TACTIC_IMPACT],
    "Credential Theft": [TACTIC_CREDENTIAL_ACCESS],
    "Lateral Movement": [TACTIC_LATERAL_MOVEMENT],
    "Reconnaissance": [TACTIC_RECONNAISSANCE, TACTIC_DISCOVERY],
    "Privilege Escalation": [TACTIC_PRIVILEGE_ESCALATION],
    "Command and Control": [TACTIC_COMMAND_AND_CONTROL],
    "Exfiltration": [TACTIC_EXFILTRATION],
    "Initial Access": [TACTIC_INITIAL_ACCESS],
    "Persistence": [TACTIC_PERSISTENCE],
    "Defense Evasion": [TACTIC_DEFENSE_EVASION],
    "Discovery": [TACTIC_DISCOVERY],
    "Collection": [TACTIC_COLLECTION],
    "Execution": [TACTIC_EXECUTION],
    "Impact": [TACTIC_IMPACT],
}


# Set role -> list of likely top-level MITRE technique IDs.
# These are heuristic priors, not analyst-confirmed identifications.
SET_ROLE_TO_TECHNIQUES = {
    "C2 Server": ["T1071", "T1095"],            # App Layer / Non-App Layer Protocol
    "Bot": ["T1071"],                            # Application Layer Protocol
    "Botnet Hardware": ["T1071"],
    "Botnet Service": ["T1071"],
    "Network Scanner": ["T1046"],                # Network Service Scanning
    "Reconnaissance Host": ["T1595"],            # Active Scanning
    "Reconnaissance Target": ["T1595"],
    "Recon Hardware": ["T1595"],
    "Recon Service": ["T1595"],
    "Phishing Site": ["T1566"],                  # Phishing
    "Phishing Email": ["T1566"],
    "Phishing Hardware": ["T1566"],
    "Phishing Service": ["T1566"],
    "Phished Host": ["T1566"],
    "Phished User": ["T1566"],
    "Malicious Email": ["T1566"],
    "Malicious File": ["T1204"],                 # User Execution
    "Exploiting Host": ["T1190"],                # Exploit Public-Facing App
    "Exploiting Target": ["T1190"],
    "Exploited Hardware": ["T1190"],
    "Exploited Service": ["T1190"],
    "Exfiltration Host": ["T1041"],              # Exfil over C2 channel
    "Exfiltration Target": ["T1041"],
    "Exfiltration Hardware": ["T1041"],
    "Exfiltration Service": ["T1041"],
    "Ransomware Source": ["T1486"],              # Data Encrypted for Impact
    "Ransomware Target": ["T1486"],
    "Ransomware Malware": ["T1486"],
    "Ransomware Hardware": ["T1486"],
    "Ransomware Service": ["T1486"],
    "Ransomware User": ["T1486"],
    "Disruption Host": ["T1499"],                # Endpoint DoS
    "Disruption Target": ["T1499"],
    "Disruption Hardware": ["T1499"],
    "Disruption Service": ["T1499"],
    "Staging Host": ["T1105"],                   # Ingress Tool Transfer
    "Staging Target": ["T1105"],
    "Staging Hardware": ["T1105"],
    "Staging Service": ["T1105"],
}


# Modus operandi -> list of likely top-level MITRE technique IDs.
MO_TO_TECHNIQUES = {
    "Data Theft": ["T1041", "T1567"],            # Exfil over C2 / over Web
    "Ransomware": ["T1486"],
    "Credential Theft": ["T1003", "T1110"],      # OS Cred Dumping / Brute Force
    "Lateral Movement": ["T1021"],               # Remote Services
    "Reconnaissance": ["T1595", "T1046"],
    "Privilege Escalation": ["T1068"],           # Exploitation for Priv Esc
    "Command and Control": ["T1071"],
    "Exfiltration": ["T1041"],
    "Initial Access": ["T1190", "T1566"],
    "Persistence": ["T1098"],                    # Account Manipulation
    "Defense Evasion": ["T1562"],                # Impair Defenses
    "Discovery": ["T1018", "T1046"],             # Remote System / Net Service
    "Collection": ["T1005"],                     # Data from Local System
    "Execution": ["T1059"],                      # Command and Scripting
    "Impact": ["T1486", "T1499"],
}


def tactics_for_set_roles(set_roles):
    """Collect deduplicated MITRE tactic IDs implied by a set of WitFoo set roles."""
    out = []
    seen = set()
    for role in set_roles or []:
        for tactic in SET_ROLE_TO_TACTICS.get(role.strip(), []):
            if tactic not in seen:
                seen.add(tactic)
                out.append(tactic)
    return out


def techniques_for_set_roles(set_roles):
    """Collect deduplicated MITRE technique IDs implied by a set of WitFoo set roles."""
    out = []
    seen = set()
    for role in set_roles or []:
        for tech in SET_ROLE_TO_TECHNIQUES.get(role.strip(), []):
            if tech not in seen:
                seen.add(tech)
                out.append(tech)
    return out


def tactics_for_mo(mo_name):
    """MITRE tactic IDs implied by an incident modus operandi name."""
    if not mo_name:
        return []
    return list(MO_TO_TACTICS.get(mo_name.strip(), []))


def techniques_for_mo(mo_name):
    """MITRE technique IDs implied by an incident modus operandi name."""
    if not mo_name:
        return []
    return list(MO_TO_TECHNIQUES.get(mo_name.strip(), []))


def merge_unique(*lists):
    """Concatenate iterables preserving order and removing duplicates."""
    out = []
    seen = set()
    for lst in lists:
        for item in lst or []:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return out
