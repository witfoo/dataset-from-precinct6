# Output Schema

## Signal Columns (Parquet)

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | float64 | Unix epoch timestamp |
| `message_type` | string | Event classification |
| `stream_name` | string | Source product stream |
| `pipeline` | string | Ingestion pipeline |
| `src_ip` | string | Source IP (sanitized) |
| `dst_ip` | string | Destination IP (sanitized) |
| `src_port` | string | Source port |
| `dst_port` | string | Destination port |
| `protocol` | string | Network protocol |
| `src_host` | string | Source hostname (sanitized) |
| `dst_host` | string | Destination hostname (sanitized) |
| `username` | string | Username (sanitized) |
| `action` | string | Event action |
| `severity` | string | Severity level |
| `vendor_code` | string | Vendor event code |
| `message_sanitized` | string | Full sanitized log message |
| `label_binary` | string | `malicious` / `suspicious` / `benign` |
| `label_confidence` | float32 | Heuristic confidence in [0, 1] -- see [labeling.md](labeling.md#label-confidence) |
| `suspicion_score` | float32 | WitFoo Precinct incident score (0-1, only meaningful on `malicious`) |
| `attack_tactics` | string | JSON array of MITRE ATT&CK tactic IDs (e.g., `["TA0011"]`) |
| `attack_techniques` | string | JSON array of MITRE ATT&CK technique IDs (e.g., `["T1071"]`) |
| `mo_name` | string | Modus operandi (incident campaign type) |
| `lifecycle_stage` | string | WitFoo internal kill-chain stage |
| `matched_rules` | string | JSON array of matched rule descriptions |
| `set_roles` | string | JSON array of WitFoo classification roles (`C2 Server`, etc.) |
| `product_name` | string | Security product name |
| `vendor_name` | string | Product vendor |
| `disposition` | string | Analyst incident status (e.g., `False Positive`); empty if not in an incident |

## Graph Formats

### nodes.jsonl
```json
{"node_id": "HOST-0001", "type": "HOST", "attrs": {"ip": "192.0.2.1", "hostname": "HOST-0001"}}
```

### edges.jsonl
```json
{"src": "HOST-0001", "dst": "HOST-0002", "type": "EVENT", "timestamp": 1721992220.0, "attrs": {...}, "labels": {...}}
```

### incidents.jsonl
Full incident records with embedded nodes, edges, leads, and framework mappings.
