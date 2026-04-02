# Dataset from Precinct6

Generate labeled cybersecurity datasets from [WitFoo Precinct](https://www.witfoo.com/) 6.x deployments. Produces sanitized signal logs (Parquet) and provenance graphs (NDJSON/GraphML) for intrusion detection research, AI-driven defense simulation, and security alert classification.

## Features

- **Extract** security events and incidents from Precinct 6.x Cassandra databases
- **Sanitize** PII through a 4-layer pipeline (regex, format-specific parsers, ML/NER, Claude AI review)
- **Label** events as malicious/suspicious/benign using incident correlation and 261 lead detection rules
- **Export** to Parquet (signals) and NDJSON/GraphML (provenance graphs)
- **Optional sanitization** — skip PII removal for internal datasets
- **158 security products** supported across 70+ vendors (Cisco, CrowdStrike, Palo Alto, AWS, Microsoft, etc.)

## Quick Start

```bash
# Install
pip install precinct6-dataset

# For ML-based sanitization (Layer 3):
pip install precinct6-dataset[ml]
python -m spacy download en_core_web_lg

# For Claude AI review (Layer 4):
pip install precinct6-dataset[claude]

# For real-time monitoring dashboard:
pip install precinct6-dataset[monitor]

# Install everything:
pip install precinct6-dataset[all]
```

### Configure

```bash
# Copy the example configs
cp .env.example .env
cp customer_config.example.json customer_config.json

# Edit .env with your Cassandra connection details
# Edit customer_config.json with your organization names and domains
```

### Run

```bash
# Full pipeline: extract -> sanitize -> label -> export -> verify
precinct6-dataset pipeline --orgs your_org_slug

# Or run individual steps:
precinct6-dataset extract --orgs your_org_slug
precinct6-dataset sanitize
precinct6-dataset label
precinct6-dataset export
precinct6-dataset verify

# Skip sanitization for internal use:
precinct6-dataset pipeline --orgs your_org_slug --no-sanitize

# Run sanitization convergence cycles:
precinct6-dataset converge --max-cycles 5

# Monitor progress in real-time:
precinct6-dataset monitor
```

## Prerequisites

- **WitFoo Precinct 6.x** deployment with Cassandra access
- **Python 3.11+**
- **Network access** to your Precinct Cassandra cluster
- (Optional) **Anthropic API key** for Layer 4 Claude review
- (Optional) **HuggingFace token** for dataset upload

## Configuration

All configuration is via environment variables or config files. **No secrets are hardcoded.**

### `.env` — Connection details and API keys

```env
CASSANDRA_HOST=your-cassandra-host
CASSANDRA_PORT=9042
CASSANDRA_USER=cassandra
CASSANDRA_PASSWORD=your-password
CASSANDRA_SSL=true
ANTHROPIC_API_KEY=sk-ant-...    # Optional: for Claude review
```

### `customer_config.json` — Organization mappings

```json
{
  "organizations": {
    "your_org_slug": "ORG-0001"
  },
  "organization_display_names": {
    "Your Org Display Name": "ORG-0001"
  },
  "customer_domains": [
    "yourdomain.com"
  ]
}
```

See [docs/configuration.md](docs/configuration.md) for all options.

## Pipeline Architecture

```
Cassandra DB
    |
    v
[Extract] --> raw NDJSON files
    |
    v
[Sanitize - 4 layers]
    |  Layer 1: Structured field replacement + Aho-Corasick sweep (166K+ patterns)
    |  Layer 2: Format-specific message parsers (Cisco, Windows, AWS, PAN, etc.)
    |  Layer 3: ML/NER residual detection (Presidio + BERT NER) [optional]
    |  Layer 4: Claude AI contextual review [optional]
    |
    v
[Label] --> malicious / suspicious / benign (3-tier)
    |         + MITRE ATT&CK mappings
    |         + lead rule matches
    |         + product/vendor attribution
    |
    v
[Export] --> Parquet (signals) + NDJSON/GraphML (graphs)
    |
    v
[Verify] --> PII leak scan + integrity checks
```

### Three-Tier Labeling

| Label | Source | Description |
|-------|--------|-------------|
| **malicious** | Incident leads | Events embedded in confirmed security incidents |
| **suspicious** | Lead detection rules | Events matching 261 WitFoo detection rules |
| **benign** | Default | Events not matching any rules or incidents |

### Output Schema (Signals)

| Column | Description |
|--------|-------------|
| `timestamp` | Unix epoch timestamp |
| `message_type` | Event classification (e.g., `firewall_action`, `AssumeRole`) |
| `stream_name` | Source product stream |
| `src_ip`, `dst_ip` | Source/destination IP (sanitized) |
| `label_binary` | `malicious`, `suspicious`, or `benign` |
| `suspicion_score` | WitFoo suspicion score (0.0-1.0) |
| `matched_rules` | JSON array of matched detection rules |
| `set_roles` | JSON array of classification roles (Exploiting Host, C2 Server, etc.) |
| `product_name` | Security product name |
| `vendor_name` | Product vendor |
| `lifecycle_stage` | Kill chain stage |
| ... | See [docs/schema.md](docs/schema.md) for all 25 columns |

## Sanitization

The 4-layer sanitization pipeline removes all customer-identifying information while preserving security-relevant patterns:

- **IPs** -> RFC 5737 TEST-NET (public) or HMAC-remapped RFC 1918 (private)
- **Hostnames** -> `HOST-NNNN` / `host-NNNN.example.internal`
- **Usernames** -> `USER-NNNN` (system accounts preserved)
- **Organizations** -> `ORG-NNNN`
- **Emails** -> `user-NNNN@example.net`
- **Windows SIDs** -> Standardized replacement SIDs
- **AWS ARNs/Account IDs** -> Sequential replacements
- **Credentials** -> `CRED-NNNN`

All replacements are **consistent** — the same original value always maps to the same token, preserving graph topology. See [docs/sanitization.md](docs/sanitization.md) for details.

## Supported Security Products

The tool recognizes events from **158 products** including:

| Category | Products |
|----------|----------|
| Firewalls | Cisco ASA, Palo Alto, Fortinet, Checkpoint, Meraki, SonicWall, pfSense |
| Endpoint | CrowdStrike, Symantec, Carbon Black, SentinelOne, Deep Instinct |
| Network | Cisco Stealthwatch/Firepower, Suricata, TippingPoint, Vectra |
| Cloud | AWS CloudTrail/VPC/GuardDuty, Azure Security, Zscaler, Netskope |
| Identity | Windows AD, Cisco ISE, CyberArk, Duo, Okta, Beyond Trust |
| Email | ProofPoint, Mimecast, FireEye, Barracuda, Cisco IronPort |

Full catalog in `data/lead_rules_catalog.json`.

## Published Datasets

Datasets generated with this tool are available on HuggingFace:

- [witfoo/precinct6-cybersecurity](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity) — 2M signals
- [witfoo/precinct6-cybersecurity-100m](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m) — 84M signals

## Documentation

- [Architecture](docs/architecture.md) — Pipeline design and layer descriptions
- [Configuration](docs/configuration.md) — All environment variables and config options
- [Sanitization](docs/sanitization.md) — 4-layer PII removal methodology
- [Labeling](docs/labeling.md) — Three-tier labeling with MITRE ATT&CK mappings
- [Schema](docs/schema.md) — Output column definitions and graph formats
- [Cassandra Schema](docs/cassandra-schema.md) — Required Precinct 6.x database tables

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev,all]"
python -m spacy download en_core_web_lg

# Run tests
pytest

# Lint
ruff check src/
```

## License

[Apache License 2.0](LICENSE)

Copyright 2025 WitFoo, Inc.
