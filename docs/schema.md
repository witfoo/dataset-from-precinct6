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
| `label_binary` | string | malicious/suspicious/benign |
| `label_confidence` | float32 | Confidence score (0-1) |
| `suspicion_score` | float32 | WitFoo suspicion score (0-1) |
| `mo_name` | string | Modus operandi |
| `lifecycle_stage` | string | Kill chain stage |
| `matched_rules` | string | JSON array of matched rule descriptions |
| `set_roles` | string | JSON array of classification roles |
| `product_name` | string | Security product name |
| `vendor_name` | string | Product vendor |

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
