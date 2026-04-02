# Cassandra Schema Reference

The extraction tool queries these tables from a WitFoo Precinct 6.x Cassandra cluster.

## Keyspace: `artifacts`

### `full_artifact_partitions`
Partition index — lists all available data partitions by time period and organization.

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization slug |
| `partition` | text | Partition UUID |
| `day` | text | Time period identifier (e.g., `2024-07-26-11-10`) |
| `first_created_at` | timeuuid | Earliest record in partition |

**Primary key**: `(day, org_id, partition)`

### `artifacts`
Individual security events (signals/logs).

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization slug |
| `partition` | text | Partition UUID |
| `created_at` | timeuuid | Record creation timestamp |
| `artifact_json` | text | Full event JSON (see below) |

**Primary key**: `(org_id, partition, created_at)`

#### Artifact JSON Fields
Each `artifact_json` contains 50-85 fields depending on the source product. Common fields:

| Field | Description |
|-------|-------------|
| `messageType` | Event classification |
| `streamName` | Source product/integration |
| `message` | Raw log message |
| `clientIP` / `serverIP` | Source/destination IPs |
| `clientPort` / `serverPort` | Ports |
| `protocol` | Network protocol |
| `senderHost` / `serverHostname` | Hostnames |
| `userName` | Associated username |
| `organization` | Organization identifier |
| `action` | Event action (block, permit, logon, etc.) |
| `severityCode` | Severity level |
| `matchedLeadRuleIds` | Array of matched detection rule IDs |
| `pipelineEntrypoint` | Ingestion pipeline name |

## Keyspace: `precinct`

### `incidents`
Full incident graphs with embedded leads and nodes.

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization slug |
| `partition` | text | Incident partition UUID |
| `created_at` | timeuuid | Creation timestamp |
| `object` | text | Full incident JSON |

**Primary key**: `(org_id, partition, created_at)`

### `nodes`
Network entity records.

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization slug |
| `partition` | text | Partition identifier |
| `created_at` | timeuuid | Creation timestamp |
| `object` | text | Node JSON |

### `threat_hits`
Threat intelligence matches.

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization slug |
| `id` | text | Threat hit identifier |
| `object` | text | Threat hit JSON |

### `objects`
Configuration objects (products, lead rules, sets).

| Column | Type | Description |
|--------|------|-------------|
| `org_id` | text | Organization or config namespace |
| `partition` | text | Object type (`products`, `lead_rules`, `sets`, etc.) |
| `object` | text | Configuration JSON |

Key partitions:
- `org_id='ve', partition='lead_rules'` — 261 lead detection rules
- `org_id='ve', partition='sets'` — 106 classification sets
- `org_id='{org}', partition='products'` — Product catalog per org
