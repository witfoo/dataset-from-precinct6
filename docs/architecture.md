# Pipeline Architecture

See the [README](../README.md) for the pipeline diagram and overview.

## Stages

1. **Extract** — Pull artifacts and incidents from Precinct 6.x Cassandra
2. **Sanitize** — 4-layer PII removal with iterative convergence
3. **Label** — 3-tier classification using incidents and lead rules
4. **Export** — Parquet signals + NDJSON/GraphML provenance graphs
5. **Verify** — Automated PII leak detection and integrity checks

## Sanitization Layers

- **Layer 1**: Structured field sanitization (field-name semantic dispatch) + Aho-Corasick multi-pattern sweep
- **Layer 2**: Format-specific message parsers (8 parsers for Cisco ASA, Windows XML, WinLogBeat, CloudTrail, PAN, VMware, DNS, generic)
- **Layer 3**: ML/NER residual detection (Microsoft Presidio + BERT NER)
- **Layer 4**: Claude AI contextual review (stratified sampling)

## Convergence Loop

The pipeline runs iteratively — PII found by ML/Claude in one cycle is caught by Aho-Corasick in all subsequent cycles across the full dataset.
