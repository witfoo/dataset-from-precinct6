"""Export sanitized data as provenance graphs.

Formats:
- DARPA CDM-style NDJSON (nodes.jsonl + edges.jsonl)
- NetworkX JSON (node-link format)
- GraphML
"""

import json
from pathlib import Path
from collections import defaultdict

import orjson
import networkx as nx

from precinct6_dataset.config import GRAPH_OUTPUT_DIR, SANITIZED_DIR


# Map WitFoo messageType to provenance graph edge types
MESSAGE_TYPE_TO_EDGE = {
    "firewall_action": "NETWORK_FLOW",
    "flow": "NETWORK_FLOW",
    "dns_event": "DNS_RESOLVE",
    "account_logon": "LOGON",
    "security_audit_event": "AUDIT_EVENT",
    "management_message": "SYSTEM_EVENT",
    "java_error": "SYSTEM_EVENT",
    # AWS CloudTrail
    "AssumeRole": "AUTH",
    "DescribeInstances": "API_CALL",
    "DescribeInstanceStatus": "API_CALL",
    "DescribeAccountAttributes": "API_CALL",
    "GetTopicAttributes": "API_CALL",
    "ListTagsForResource": "API_CALL",
    "ListClusters": "API_CALL",
    "DescribeVolumes": "API_CALL",
    "DescribeLoadBalancers": "API_CALL",
    "GenerateDataKey": "CRYPTO_OP",
    "GetBucketAcl": "API_CALL",
    "audit_log": "AUDIT_EVENT",
    # Windows events
    "4656": "FILE_ACCESS",
    "4658": "HANDLE_CLOSE",
    "4690": "HANDLE_DUP",
    "4793": "ACCOUNT_MGMT",
    "4799": "GROUP_MGMT",
}


class GraphExporter:
    """Export sanitized data as provenance graphs."""

    def __init__(self, sanitized_dir: Path = None, output_dir: Path = None):
        self.sanitized_dir = sanitized_dir or SANITIZED_DIR
        self.output_dir = output_dir or GRAPH_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nodes = {}  # node_id -> node dict
        self.edges = []  # list of edge dicts

    def export_all(self):
        """Export all data in graph formats."""
        print("  Building graph from artifacts and incidents...")
        self._build_from_artifacts()
        self._build_from_incidents()

        print(f"  Graph: {len(self.nodes)} nodes, {len(self.edges)} edges")

        # Export DARPA CDM-style NDJSON
        self._export_ndjson()

        # Export NetworkX formats
        self._export_networkx()

        # Copy sanitized incidents to output
        self._export_incidents()

        # Export metadata
        self._export_metadata()

    def _build_from_artifacts(self):
        """Build graph nodes and edges from artifact records."""
        labeled_file = self.sanitized_dir / "artifacts_labeled.jsonl"
        if not labeled_file.exists():
            labeled_file = self.sanitized_dir / "artifacts.jsonl"
        if not labeled_file.exists():
            return

        with open(labeled_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = orjson.loads(line)
                except Exception:
                    continue

                self._artifact_to_edge(record)

    def _artifact_to_edge(self, artifact: dict):
        """Convert an artifact record to graph nodes and an edge."""
        msg_type = artifact.get("messageType", artifact.get("messagetype", "unknown"))
        edge_type = MESSAGE_TYPE_TO_EDGE.get(msg_type, "EVENT")

        # Source node (client/sender)
        src_ip = artifact.get("clientIP", artifact.get("clientip", ""))
        src_host = artifact.get("senderHost", artifact.get("senderhost", ""))
        src_id = src_ip or src_host
        if src_id and src_id != "-":
            if src_id not in self.nodes:
                self.nodes[src_id] = {
                    "node_id": src_id,
                    "type": "HOST",
                    "attrs": {
                        "ip": src_ip,
                        "hostname": src_host,
                    },
                }

        # Destination node (server)
        dst_ip = artifact.get("serverIP", artifact.get("serverip", ""))
        dst_host = artifact.get("serverHostname", artifact.get("serverhostname", ""))
        dst_id = dst_ip or dst_host
        if dst_id and dst_id != "-":
            if dst_id not in self.nodes:
                self.nodes[dst_id] = {
                    "node_id": dst_id,
                    "type": "HOST",
                    "attrs": {
                        "ip": dst_ip,
                        "hostname": dst_host,
                    },
                }

        # Username node
        username = artifact.get("userName", artifact.get("username", ""))
        if username and username != "-" and username != "None":
            user_id = f"user:{username}"
            if user_id not in self.nodes:
                self.nodes[user_id] = {
                    "node_id": user_id,
                    "type": "CREDENTIAL",
                    "attrs": {"username": username},
                }

        # Create edge
        if src_id and dst_id and src_id != "-" and dst_id != "-":
            labels = artifact.get("_labels", {})
            edge = {
                "src": src_id,
                "dst": dst_id,
                "type": edge_type,
                "timestamp": artifact.get("_created_at", 0),
                "attrs": {
                    "message_type": msg_type,
                    "action": artifact.get("action", ""),
                    "protocol": artifact.get("protocol", ""),
                    "src_port": artifact.get("clientPort", artifact.get("clientport", "")),
                    "dst_port": artifact.get("serverPort", artifact.get("serverport", "")),
                    "stream": artifact.get("streamName", artifact.get("streamname", "")),
                },
                "labels": labels,
            }
            self.edges.append(edge)

    def _build_from_incidents(self):
        """Build graph from incident records (pre-formed graphs)."""
        incidents_file = self.sanitized_dir / "incidents.jsonl"
        if not incidents_file.exists():
            return

        with open(incidents_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    incident = orjson.loads(line)
                except Exception:
                    continue

                # Add nodes from incident
                nodes = incident.get("nodes", {})
                if isinstance(nodes, dict):
                    for node_id, node in nodes.items():
                        if isinstance(node, dict):
                            gnode = {
                                "node_id": node_id,
                                "type": node.get("type", "HOST").upper(),
                                "attrs": {
                                    "ip": node.get("ip_address", node.get("ip", "")),
                                    "hostname": node.get("hostname", ""),
                                    "credential": node.get("credential", ""),
                                },
                            }
                            self.nodes[node_id] = gnode

                # Add edges from incident
                edges = incident.get("edges", {})
                if isinstance(edges, dict):
                    for edge_id, edge in edges.items():
                        if isinstance(edge, dict):
                            self.edges.append({
                                "src": edge.get("source", ""),
                                "dst": edge.get("target", ""),
                                "type": "INCIDENT_LINK",
                                "timestamp": incident.get("created_at", 0),
                                "attrs": {
                                    "incident_id": incident.get("id", ""),
                                    "mo_name": incident.get("mo_name", ""),
                                    "status": incident.get("status_name", ""),
                                },
                                "labels": {
                                    "label_binary": "malicious",
                                    "suspicion_score": incident.get("suspicion_score", 0),
                                    "mo_name": incident.get("mo_name", ""),
                                },
                            })

    def _export_incidents(self):
        """Copy sanitized incidents to output as a separate NDJSON file."""
        incidents_file = self.sanitized_dir / "incidents.jsonl"
        if not incidents_file.exists():
            return

        out_file = self.output_dir / "incidents.jsonl"
        import shutil
        shutil.copy2(incidents_file, out_file)

        count = sum(1 for _ in open(out_file))
        size_mb = out_file.stat().st_size / 1024 / 1024
        print(f"  Wrote incidents: {out_file.name} ({count:,} incidents, {size_mb:.1f} MB)")

    def _export_ndjson(self):
        """Export as DARPA CDM-style NDJSON."""
        nodes_file = self.output_dir / "nodes.jsonl"
        edges_file = self.output_dir / "edges.jsonl"

        with open(nodes_file, "wb") as f:
            for node in self.nodes.values():
                f.write(orjson.dumps(node))
                f.write(b"\n")

        with open(edges_file, "wb") as f:
            for i, edge in enumerate(self.edges):
                edge["edge_id"] = f"e-{i:08d}"
                f.write(orjson.dumps(edge))
                f.write(b"\n")

        print(f"  Wrote NDJSON: {nodes_file.name} ({len(self.nodes)} nodes), "
              f"{edges_file.name} ({len(self.edges)} edges)")

    def _export_networkx(self):
        """Export as NetworkX JSON and GraphML."""
        G = nx.DiGraph()

        for node_id, node in self.nodes.items():
            attrs = {k: str(v) for k, v in node.get("attrs", {}).items() if v}
            attrs["type"] = node.get("type", "")
            G.add_node(node_id, **attrs)

        for edge in self.edges:
            src = edge.get("src", "")
            dst = edge.get("dst", "")
            if src and dst and src in G.nodes and dst in G.nodes:
                attrs = {k: str(v) for k, v in edge.get("attrs", {}).items() if v}
                attrs["type"] = edge.get("type", "")
                labels = edge.get("labels", {})
                if isinstance(labels, dict):
                    attrs["label_binary"] = str(labels.get("label_binary", ""))
                    attrs["suspicion_score"] = str(labels.get("suspicion_score", ""))
                G.add_edge(src, dst, **attrs)

        # Node-link JSON
        json_file = self.output_dir / "graph.json"
        data = nx.node_link_data(G)
        with open(json_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  Wrote NetworkX JSON: {json_file.name}")

        # GraphML
        graphml_file = self.output_dir / "graph.graphml"
        nx.write_graphml(G, str(graphml_file))
        print(f"  Wrote GraphML: {graphml_file.name}")

    def _export_metadata(self):
        """Export dataset metadata."""
        # Count labels
        label_counts = defaultdict(int)
        edge_type_counts = defaultdict(int)
        node_type_counts = defaultdict(int)

        for edge in self.edges:
            labels = edge.get("labels", {})
            binary = labels.get("label_binary", "unknown") if isinstance(labels, dict) else "unknown"
            label_counts[binary] += 1
            edge_type_counts[edge.get("type", "unknown")] += 1

        for node in self.nodes.values():
            node_type_counts[node.get("type", "unknown")] += 1

        metadata = {
            "dataset_name": "WitFoo Precinct6 Cybersecurity Dataset",
            "version": "1.0.0",
            "description": "Labeled provenance graphs and security signal logs for IDS research",
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "label_distribution": dict(label_counts),
            "edge_type_distribution": dict(edge_type_counts),
            "node_type_distribution": dict(node_type_counts),
            "sanitization": {
                "method": "4-layer (regex + format-parse + ML/NER + Claude review)",
                "ip_replacement": "RFC5737 TEST-NET for public, remapped RFC1918 for private",
                "org_replacement": "ORG-NNNN",
                "host_replacement": "HOST-NNNN / host-NNNN.example.internal",
            },
            "formats": ["NDJSON (nodes.jsonl + edges.jsonl)", "NetworkX JSON", "GraphML"],
        }

        meta_file = self.output_dir / "metadata.json"
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)
        print(f"  Wrote metadata: {meta_file.name}")
