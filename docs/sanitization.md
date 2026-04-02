# Sanitization Methodology

See the [README](../README.md) for an overview. This document provides implementation details.

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
