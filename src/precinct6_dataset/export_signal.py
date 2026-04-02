"""Export sanitized data as flat signal logs (CSV + Parquet)."""

import json
from pathlib import Path

import orjson
import pandas as pd

from precinct6_dataset.config import SIGNAL_OUTPUT_DIR, SANITIZED_DIR


class SignalExporter:
    """Export sanitized artifacts as flat tabular signal logs."""

    def __init__(self, sanitized_dir: Path = None, output_dir: Path = None):
        self.sanitized_dir = sanitized_dir or SANITIZED_DIR
        self.output_dir = output_dir or SIGNAL_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_all(self):
        """Export all labeled artifacts as CSV and Parquet."""
        labeled_file = self.sanitized_dir / "artifacts_labeled.jsonl"
        if not labeled_file.exists():
            labeled_file = self.sanitized_dir / "artifacts.jsonl"
        if not labeled_file.exists():
            print("  No artifacts file found")
            return

        print("  Reading artifacts...")
        rows = []
        with open(labeled_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = orjson.loads(line)
                    row = self._flatten_record(record)
                    rows.append(row)
                except Exception:
                    continue

        if not rows:
            print("  No records to export")
            return

        df = pd.DataFrame(rows)

        # Sort by timestamp
        if "timestamp" in df.columns:
            df = df.sort_values("timestamp", na_position="last")

        # CSV
        csv_file = self.output_dir / "signals.csv"
        df.to_csv(csv_file, index=False)
        print(f"  Wrote CSV: {csv_file.name} ({len(df)} rows)")

        # Parquet — coerce mixed-type columns to string
        parquet_file = self.output_dir / "signals.parquet"
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].astype(str)
        df.to_parquet(parquet_file, index=False)
        print(f"  Wrote Parquet: {parquet_file.name} ({len(df)} rows)")

        # Metadata
        self._export_metadata(df)

    def _flatten_record(self, record: dict) -> dict:
        """Flatten an artifact record into a tabular row."""
        labels = record.get("_labels", {})

        return {
            "timestamp": record.get("_created_at", 0),
            "message_type": record.get("messageType", record.get("messagetype", "")),
            "stream_name": record.get("streamName", record.get("streamname", "")),
            "pipeline": record.get("pipelineName", record.get("pipelinename", "")),
            "src_ip": record.get("clientIP", record.get("clientip", "")),
            "dst_ip": record.get("serverIP", record.get("serverip", "")),
            "src_port": record.get("clientPort", record.get("clientport", "")),
            "dst_port": record.get("serverPort", record.get("serverport", "")),
            "protocol": record.get("protocol", ""),
            "src_host": record.get("senderHost", record.get("senderhost", "")),
            "dst_host": record.get("serverHostname", record.get("serverhostname", "")),
            "username": record.get("userName", record.get("username", "")),
            "action": record.get("action", ""),
            "severity": record.get("severityLabel", record.get("severitylabel", "")),
            "vendor_code": record.get("vendorCode", record.get("vendorcode", "")),
            "message_sanitized": record.get("message", ""),
            # Labels
            "label_binary": labels.get("label_binary", "unknown"),
            "label_confidence": labels.get("label_confidence", 0),
            "attack_techniques": json.dumps(labels.get("attack_techniques", [])),
            "attack_tactics": json.dumps(labels.get("attack_tactics", [])),
            "mo_name": labels.get("mo_name", ""),
            "suspicion_score": labels.get("suspicion_score", 0),
            "lifecycle_stage": labels.get("lifecycle_stage", ""),
            # Lead rule tagging
            "matched_rules": json.dumps(labels.get("matched_rules", [])),
            "set_roles": json.dumps(labels.get("set_roles", [])),
            "product_name": labels.get("product_name", ""),
            "vendor_name": labels.get("vendor_name", ""),
        }

    def _export_metadata(self, df: pd.DataFrame):
        """Export signal dataset metadata."""
        metadata = {
            "total_records": len(df),
            "columns": list(df.columns),
            "message_type_distribution": df["message_type"].value_counts().to_dict(),
            "label_distribution": df["label_binary"].value_counts().to_dict(),
            "stream_distribution": df["stream_name"].value_counts().to_dict(),
            "formats": ["CSV", "Parquet"],
        }

        meta_file = self.output_dir / "metadata.json"
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)
        print(f"  Wrote metadata: {meta_file.name}")
