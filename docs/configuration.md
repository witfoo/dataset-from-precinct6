# Configuration Reference

All configuration is via environment variables, `.env` file, or `customer_config.json`. No secrets are hardcoded.

## Environment Variables

### Cassandra Connection (required for `extract`)

| Variable | Default | Description |
|----------|---------|-------------|
| `CASSANDRA_HOST` | (required) | Cassandra cluster hostname or IP |
| `CASSANDRA_PORT` | `9042` | Cassandra native transport port |
| `CASSANDRA_USER` | (required) | Cassandra username |
| `CASSANDRA_PASSWORD` | (required) | Cassandra password |
| `CASSANDRA_SSL` | `true` | Enable SSL/TLS connection |
| `CASSANDRA_FETCH_SIZE` | `1000` | Rows per Cassandra page fetch |

### API Keys (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (empty) | Required for Layer 4 (Claude AI review) |
| `HF_TOKEN` | (empty) | Required for HuggingFace upload |

### Data Directories

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `./data` | Base data directory |
| `RAW_DIR` | `./data/raw` | Extracted raw data |
| `SANITIZED_DIR` | `./data/sanitized` | Sanitized output |
| `OUTPUT_DIR` | `./data/output` | Final exported datasets |

### Sanitization Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_REVIEW_MODEL` | `claude-sonnet-4-20250514` | Claude model for Layer 4 |
| `CLAUDE_REVIEW_SAMPLE_RATE` | `0.05` | Fraction of records to sample |
| `ML_NER_CONFIDENCE_THRESHOLD` | `0.75` | Minimum NER confidence score |
| `PRESIDIO_SCORE_THRESHOLD` | `0.5` | Minimum Presidio detection score |
| `REGISTRY_SECRET` | (random) | HMAC key for deterministic IP mapping. Set for reproducible runs. |
| `LEAD_RULES_CATALOG` | `./data/lead_rules_catalog.json` | Path to WitFoo lead rules catalog |

### Customer Configuration (alternative to `customer_config.json`)

| Variable | Format | Description |
|----------|--------|-------------|
| `ORGS` | JSON | `{"org_slug": "ORG-0001"}` |
| `ORG_DISPLAY_NAMES` | JSON | `{"Org Name": "ORG-0001"}` |
| `CUSTOMER_DOMAINS` | comma-separated | `domain1.com,domain2.net` |
| `ORG_ID_MAPPINGS` | JSON | `{"12345": 10001}` |

## customer_config.json

For organizations with multiple org slugs and domains, a JSON config file is easier than environment variables:

```json
{
  "organizations": {
    "your_org_slug": "ORG-0001",
    "another_org": "ORG-0002"
  },
  "organization_display_names": {
    "Your Organization": "ORG-0001",
    "Another Org": "ORG-0002"
  },
  "customer_domains": [
    "yourdomain.com",
    "internal.yourdomain.com"
  ],
  "organization_ids": {
    "12345": 10001
  }
}
```

### Finding Your Configuration Values

1. **Organization slugs**: Check your Precinct 6.x admin panel under Organization settings, or query: `SELECT DISTINCT org_id FROM artifacts.full_artifact_partitions`
2. **Customer domains**: List all domains your organization owns that appear in log data
3. **Organization IDs**: Found in incident/node records as the `orgId` integer field
4. **Display names**: How your org name appears in log messages (case-sensitive)
