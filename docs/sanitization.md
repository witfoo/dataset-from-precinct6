# Data Sanitization Methodology

The WitFoo Precinct6 cybersecurity datasets are derived from production Security Operations Center (SOC) data. All customer-identifying information has been removed through a comprehensive, iterative four-layer sanitization pipeline. Quality was prioritized over processing speed -- the dataset underwent multiple full re-sanitization cycles until convergence.

## Four-Layer Pipeline

### Layer 1: Structured Field Sanitization with Multi-Pattern Sweep

Known data fields are sanitized based on their semantic meaning using deterministic replacement rules. IP addresses are replaced with reserved documentation ranges (RFC 5737 for public IPs, HMAC-based remapping for private IPs that preserves subnet relationships). Hostnames, usernames, organization names, email addresses, Windows Security Identifiers, AWS account numbers, and credentials are each replaced with consistent sequential tokens (e.g., `HOST-0001`, `USER-0001`, `ORG-0001`). All replacements are consistent -- the same original value always maps to the same sanitized token across every record, preserving network relationships and graph topology essential for security research.

After field-level sanitization, every record is swept using an Aho-Corasick multi-pattern matching automaton built from the full registry of over 300,000 known PII values. This catches PII that appears in unexpected contexts such as concatenated strings, cross-field references, and embedded data structures. Product identifiers (vendor names, event types, pipeline names) are explicitly protected from this sweep to preserve the security-relevant metadata researchers need.

### Layer 2: Format-Specific Log Message Parsing

Raw security log messages come in diverse vendor-specific formats. Eight specialized parsers handle the major formats: Cisco ASA syslog, Microsoft Windows Security Event XML, Elastic WinLogBeat JSON, AWS CloudTrail, Palo Alto Networks, VMware vCenter, DNS resolution logs, and a comprehensive generic fallback parser. Each parser understands the exact structure of its format and sanitizes PII within structured fields like XML elements, nested JSON objects, and CSV columns -- contexts where simple pattern matching would be unreliable.

### Layer 3: Machine Learning Residual Detection

After rule-based sanitization, machine learning models scan a stratified random sample of sanitized records for residual PII that pattern-based approaches may miss. Two complementary models are used: Microsoft Presidio (powered by a spaCy natural language processing model) for entity recognition of persons, organizations, IP addresses, and email addresses; and a BERT-based Named Entity Recognition model for an independent second opinion on person, organization, and location entities. New discoveries are added to the PII registry and trigger a full re-sanitization pass across all records.

### Layer 4: Large Language Model Contextual Review

A stratified random sample of sanitized records is reviewed by Anthropic's Claude AI for contextual PII detection. The model is prompted to identify subtle PII that statistical pattern matching and NER models commonly miss: organization names or abbreviations embedded in log messages, internal hostnames that reveal organizational structure, employee names in file paths or service descriptions, Active Directory group names, and geographic identifiers tied to specific offices or data centers. Findings trigger additional registry updates and re-sanitization.

## Iterative Convergence

The four layers run in iterative cycles. PII discovered by the ML and AI layers in one cycle is added to the pattern-matching registry, ensuring it is caught automatically by Layer 1 in all subsequent cycles across the complete dataset -- not just in the sampled records. Cycles repeat until the ML and AI layers find near-zero new discoveries, indicating convergence.

## What Is Preserved

The sanitization preserves all security-relevant information needed for research: event timestamps, network port numbers, protocol types, severity levels, vendor-specific event codes (Cisco ASA codes, Windows Event IDs, AWS API names), action types (block, permit, logon, logoff), MITRE ATT&CK framework mappings, graph topology and connection patterns, and the identity of which security product generated each event.

## PII Categories

| Category | Pattern | Replacement |
|----------|---------|-------------|
| Public IPs | RFC 5737 TEST-NET | `192.0.2.x`, `198.51.100.x`, `203.0.113.x` |
| Private IPs | HMAC-remapped RFC 1918 | Subnet-preserving deterministic mapping |
| Hostnames | Sequential | `HOST-NNNN` |
| FQDNs | Sequential | `host-NNNN.example.internal` |
| Usernames | Sequential | `USER-NNNN` |
| Organizations | Sequential | `ORG-NNNN` |
| Emails | Sequential | `user-NNNN@example.net` |
| Windows SIDs | Standardized | `S-1-5-21-1000000000-2000000000-3000000000-NNNN` |
| AWS Accounts | Sequential | 12-digit numbers |
| ARNs | Sequential | `arn:aws:iam::NNNN:sanitized/NNNN` |
| Credentials | Sequential | `CRED-NNNN` |
| Machine Accounts | Sequential | `MACHINE-NNNN$` |
| Domains | Sequential | `domain-NNNN.example.net` |

## Consistency Guarantee

All replacements use a persistent SQLite registry. The same original value always maps to the same sanitized token across all records and all passes.

## Protected Fields

Product identifiers are explicitly protected from the Aho-Corasick sweep: `streamName`, `messageType`, `pipelineEntrypoint`, `severityCode`, etc.

## Scale

The final PII registry contains approximately 302,000 unique mappings across 14 categories. The pipeline processed over 114 million security event records from production enterprise networks monitored by 158 different security products across more than 70 vendors.

The sanitization pipeline is open source and available at [github.com/witfoo/dataset-from-precinct6](https://github.com/witfoo/dataset-from-precinct6) under the Apache 2.0 license, enabling other organizations to generate sanitized datasets from their own WitFoo Precinct deployments.
