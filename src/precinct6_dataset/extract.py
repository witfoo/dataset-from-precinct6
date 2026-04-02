"""Extract data from Cassandra artifacts and precinct keyspaces to NDJSON files."""

import json
import os
from pathlib import Path
from datetime import datetime
from uuid import UUID

import orjson
from tqdm import tqdm

from precinct6_dataset.db import CassandraConnector
from precinct6_dataset.config import RAW_DIR, KNOWN_ORGS


def _timeuuid_to_timestamp(timeuuid) -> float:
    """Convert a Cassandra timeuuid to a Unix timestamp."""
    if timeuuid is None:
        return 0.0
    if isinstance(timeuuid, UUID):
        # UUID v1 timestamp: 100-ns intervals since 1582-10-15
        ts = (timeuuid.time - 0x01B21DD213814000) / 1e7
        return ts
    return 0.0


def _serialize_record(record: dict) -> bytes:
    """Serialize a record to JSON bytes, handling UUID and other types."""
    def default(obj):
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)
    return orjson.dumps(record, default=default)


class ArtifactExtractor:
    """Extract artifacts from Cassandra to NDJSON files."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or RAW_DIR / "artifacts"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def extract_all(self, orgs: list[str] = None):
        """Extract all artifacts, optionally filtered by org."""
        target_orgs = orgs or list(KNOWN_ORGS.keys())

        with CassandraConnector("artifacts") as db:
            # Get all partitions
            print("Fetching partition index...")
            partitions = list(db.execute(
                "SELECT org_id, partition, day, first_created_at "
                "FROM full_artifact_partitions"
            ))
            print(f"Found {len(partitions)} partitions total")

            # Filter to target orgs
            partitions = [p for p in partitions if p.org_id in target_orgs]
            print(f"Filtered to {len(partitions)} partitions for orgs: {target_orgs}")

            # Group by org
            org_partitions = {}
            for p in partitions:
                org_partitions.setdefault(p.org_id, []).append(p)

            total_records = 0
            for org_id, parts in org_partitions.items():
                print(f"\nExtracting org: {org_id} ({len(parts)} partitions)")
                org_dir = self.output_dir / org_id
                org_dir.mkdir(parents=True, exist_ok=True)

                for part in tqdm(parts, desc=f"  {org_id}"):
                    partition_id = part.partition
                    records = self._extract_partition(db, org_id, partition_id)
                    if records:
                        outfile = org_dir / f"{partition_id}.jsonl"
                        with open(outfile, "wb") as f:
                            for rec in records:
                                f.write(_serialize_record(rec))
                                f.write(b"\n")
                        total_records += len(records)

            print(f"\nTotal artifacts extracted: {total_records}")
            return total_records

    def _extract_partition(self, db, org_id: str, partition: str) -> list[dict]:
        """Extract all artifacts from a single partition."""
        rows = db.execute(
            "SELECT created_at, artifact_json FROM artifacts "
            "WHERE org_id = %s AND partition = %s",
            (org_id, partition),
        )
        records = []
        for row in rows:
            try:
                artifact = orjson.loads(row.artifact_json)
                artifact["_partition"] = partition
                artifact["_created_at"] = _timeuuid_to_timestamp(row.created_at)
                artifact["_created_at_uuid"] = str(row.created_at) if row.created_at else None
                records.append(artifact)
            except Exception as e:
                print(f"  Warning: failed to parse artifact in {partition}: {e}")
        return records


class IncidentExtractor:
    """Extract incidents, nodes, and threat_hits from precinct keyspace."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or RAW_DIR / "precinct"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def extract_all(self, orgs: list[str] = None):
        """Extract all precinct data."""
        target_orgs = orgs or list(KNOWN_ORGS.keys())
        stats = {"incidents": 0, "nodes": 0, "threat_hits": 0, "incident_summaries": 0}

        with CassandraConnector("precinct") as db:
            for table, label in [
                ("incidents", "incidents"),
                ("nodes", "nodes"),
                ("threat_hits", "threat_hits"),
                ("incident_summary", "incident_summaries"),
            ]:
                print(f"\nExtracting {table}...")
                outdir = self.output_dir / table
                outdir.mkdir(parents=True, exist_ok=True)

                if table == "threat_hits":
                    # threat_hits has (org_id) as partition key + id clustering
                    rows = db.execute(f"SELECT org_id, id, object FROM {table}")
                else:
                    rows = db.execute(
                        f"SELECT org_id, partition, created_at, object FROM {table}"
                    )

                # Write per-org files
                org_files = {}
                count = 0
                for row in rows:
                    if row.org_id not in target_orgs:
                        continue

                    try:
                        obj = orjson.loads(row.object)
                    except Exception:
                        continue

                    if table != "threat_hits":
                        obj["_partition"] = row.partition
                        obj["_created_at"] = _timeuuid_to_timestamp(row.created_at)
                    else:
                        obj["_threat_id"] = row.id

                    obj["_org_id"] = row.org_id

                    if row.org_id not in org_files:
                        filepath = outdir / f"{row.org_id}.jsonl"
                        org_files[row.org_id] = open(filepath, "wb")

                    org_files[row.org_id].write(_serialize_record(obj))
                    org_files[row.org_id].write(b"\n")
                    count += 1

                for f in org_files.values():
                    f.close()

                stats[label] = count
                print(f"  Extracted {count} {table} records")

        print(f"\nExtraction summary: {stats}")
        return stats
