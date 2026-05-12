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
        self._set_id_to_name = self._load_set_catalog()

    def _load_set_catalog(self) -> dict:
        """Load set_id -> name mapping from data/lead_rules_catalog.json."""
        import json as _json
        from pathlib import Path as _Path
        catalog_path = _Path("data/lead_rules_catalog.json")
        if not catalog_path.exists():
            return {}
        try:
            with open(catalog_path) as f:
                cat = _json.load(f)
            return {int(k): v for k, v in cat.get("sets", {}).items()}
        except Exception:
            return {}

    def _extract_set_role_names(self, incident: dict) -> list:
        """Extract set role names from incident.sets (int list / dict) and nodes."""
        names = []
        sets = incident.get("sets", {})
        if isinstance(sets, dict):
            for s in sets.values():
                if isinstance(s, dict) and s.get("name"):
                    names.append(s["name"])
        elif isinstance(sets, list):
            for s in sets:
                if isinstance(s, dict) and s.get("name"):
                    names.append(s["name"])
                elif isinstance(s, int):
                    n = self._set_id_to_name.get(s, "")
                    if n:
                        names.append(n)
        # Also pull from nodes.{uuid}.sets (richer data)
        nodes = incident.get("nodes", {})
        if isinstance(nodes, dict):
            for node in nodes.values():
                if not isinstance(node, dict):
                    continue
                node_sets = node.get("sets", {})
                if isinstance(node_sets, dict):
                    for s in node_sets.values():
                        if isinstance(s, dict):
                            n = s.get("name", "")
                            if n and n not in names:
                                names.append(n)
        return names

    def export_all(self, per_incident_graphml: bool = True, streaming_graphml: bool = True):
        """Export all data in graph formats.

        Args:
            per_incident_graphml: If True, emit one GraphML file per incident in
                incidents_graphml/{incident_id}.graphml.
            streaming_graphml: If True, use streaming GraphML writer for the
                summary graph (required for very large graphs).
        """
        print("  Building graph from artifacts and incidents...")
        self._build_from_artifacts()
        self._build_from_incidents()

        print(f"  Graph: {len(self.nodes)} nodes, {len(self.edges)} edges")

        # Export DARPA CDM-style NDJSON
        self._export_ndjson()

        # Per-incident GraphML files (small, loadable per incident)
        if per_incident_graphml:
            self._export_per_incident_graphml()

        # Summary GraphML — either streaming or NetworkX
        if streaming_graphml:
            self._export_summary_graphml_streaming()
        else:
            self._export_networkx()

        # Copy sanitized incidents to output
        self._export_incidents()

        # Generate attack reports
        self._export_attack_reports()

        # Export metadata
        self._export_metadata()

    def _export_per_incident_graphml(self):
        """Write one GraphML file per incident into incidents_graphml/."""
        from precinct6_dataset.streaming_graphml import (
            StreamingGraphMLWriter, SIGNAL_NODE_ATTRS, SIGNAL_EDGE_ATTRS,
        )
        from precinct6_dataset.label import (
            MO_TO_LIFECYCLE, SET_ROLE_TO_LIFECYCLE,
            STATUS_TO_DISPOSITION,
            _extract_techniques_from_frameworks,
        )
        from precinct6_dataset.mitre_mapping import (
            tactics_for_set_roles, tactics_for_mo,
            techniques_for_set_roles, techniques_for_mo,
            merge_unique,
        )

        incidents_file = self.sanitized_dir / "incidents.jsonl"
        if not incidents_file.exists():
            print("  No incidents file — skipping per-incident GraphML")
            return

        out_dir = self.output_dir / "incidents_graphml"
        out_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        with open(incidents_file, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    incident = orjson.loads(line)
                except Exception:
                    continue

                inc_id = incident.get("id", "")
                if not inc_id:
                    continue

                mo_name = incident.get("mo_name", "")
                status = incident.get("status_name", "Unprocessed")
                # disposition = raw Precinct status_name (consistent with signal export)
                disposition = status or "Unprocessed"
                disposition_category = STATUS_TO_DISPOSITION.get(status, "automated")
                suspicion = incident.get("suspicion_score", 0) or 0

                set_role_names = self._extract_set_role_names(incident)

                attack_tactics = merge_unique(
                    tactics_for_set_roles(set_role_names),
                    tactics_for_mo(mo_name),
                )

                tech_set = set()
                inodes = incident.get("nodes", {})
                if isinstance(inodes, dict):
                    for node in inodes.values():
                        if isinstance(node, dict):
                            for prod in (node.get("products") or {}).values():
                                if isinstance(prod, dict):
                                    for t in _extract_techniques_from_frameworks(prod.get("frameworks", {})):
                                        tech_set.add(t)
                attack_techniques = merge_unique(
                    sorted(tech_set),
                    techniques_for_set_roles(set_role_names),
                    techniques_for_mo(mo_name),
                )
                lifecycle = MO_TO_LIFECYCLE.get(mo_name, "unknown")

                # Write per-incident graphml
                out_file = out_dir / f"{inc_id}.graphml"
                with StreamingGraphMLWriter(out_file, SIGNAL_NODE_ATTRS, SIGNAL_EDGE_ATTRS) as w:
                    # Nodes
                    if isinstance(inodes, dict):
                        for nid, node in inodes.items():
                            if not isinstance(node, dict):
                                continue
                            node_sets = node.get("sets", {})
                            role_names = []
                            if isinstance(node_sets, dict):
                                for s in node_sets.values():
                                    if isinstance(s, dict) and s.get("name"):
                                        role_names.append(s["name"])
                            node_prods = []
                            for p in (node.get("products") or {}).values():
                                if isinstance(p, dict) and p.get("name"):
                                    node_prods.append(p["name"])
                            w.write_node(nid, {
                                "type": (node.get("type") or "HOST").upper(),
                                "ip": node.get("ip_address", node.get("ip", "")),
                                "hostname": node.get("hostname", ""),
                                "credential": node.get("credential", ""),
                                "set_roles": role_names,
                                "suspicion_score": node.get("suspicion_score", 0) or 0,
                                "products": node_prods,
                            })

                    # Edges
                    iedges = incident.get("edges", {})
                    if isinstance(iedges, dict):
                        for edge in iedges.values():
                            if not isinstance(edge, dict):
                                continue
                            w.write_edge(
                                edge.get("source", ""),
                                edge.get("target", ""),
                                {
                                    "type": "INCIDENT_LINK",
                                    "timestamp": incident.get("created_at", 0) or 0,
                                    "label_binary": "malicious",
                                    "label_confidence": max(0.7, min(1.0, suspicion)) if suspicion > 0 else 0.7,
                                    "suspicion_score": suspicion,
                                    "mo_name": mo_name,
                                    "attack_techniques": attack_techniques,
                                    "attack_tactics": attack_tactics,
                                    "set_roles": set_role_names,
                                    "lifecycle_stage": lifecycle,
                                    "disposition": disposition,
                                    "disposition_category": disposition_category,
                                    "status_name": status,
                                    "incident_id": inc_id,
                                },
                            )

                count += 1
                if count % 1000 == 0:
                    print(f"    ... wrote {count:,} per-incident GraphML files", flush=True)

        print(f"  Wrote {count:,} per-incident GraphML files to {out_dir.name}/")

    def _export_summary_graphml_streaming(self):
        """Stream summary GraphML using StreamingGraphMLWriter — scales to large datasets."""
        from precinct6_dataset.streaming_graphml import (
            StreamingGraphMLWriter, SIGNAL_NODE_ATTRS, SIGNAL_EDGE_ATTRS,
        )

        graphml_file = self.output_dir / "graph.graphml"
        with StreamingGraphMLWriter(graphml_file, SIGNAL_NODE_ATTRS, SIGNAL_EDGE_ATTRS) as w:
            for node_id, node in self.nodes.items():
                attrs = dict(node.get("attrs", {}))
                attrs["type"] = node.get("type", "")
                w.write_node(node_id, attrs)
            for edge in self.edges:
                src = edge.get("src", "")
                dst = edge.get("dst", "")
                if not src or not dst:
                    continue
                attrs = dict(edge.get("attrs", {}))
                attrs["type"] = edge.get("type", "")
                attrs["timestamp"] = edge.get("timestamp", 0)
                labels = edge.get("labels", {}) or {}
                for k in ("label_binary", "label_confidence", "suspicion_score",
                          "mo_name", "attack_techniques", "attack_tactics",
                          "set_roles", "lifecycle_stage", "disposition", "incident_id"):
                    if k in labels:
                        attrs[k] = labels[k]
                w.write_edge(src, dst, attrs)
        size_mb = graphml_file.stat().st_size / 1024 / 1024
        print(f"  Wrote streaming GraphML: {graphml_file.name} ({size_mb:.1f} MB)")

    def _export_attack_reports(self):
        """Generate attack_reports.jsonl from incidents."""
        from precinct6_dataset.attack_reports import generate_attack_reports
        incidents_file = self.sanitized_dir / "incidents.jsonl"
        if not incidents_file.exists():
            return
        out_file = self.output_dir / "attack_reports.jsonl"
        generate_attack_reports(self.sanitized_dir, out_file)

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
        """Build graph from incident records (pre-formed graphs).

        Each incident edge gets enriched labels: attack_techniques, attack_tactics,
        set_roles, lifecycle_stage, disposition. Each node gets per-entity labels
        (suspicion_score, set_roles, products).
        """
        from precinct6_dataset.label import (
            MO_TO_LIFECYCLE, SET_ROLE_TO_LIFECYCLE,
            STATUS_TO_DISPOSITION,
            _extract_techniques_from_frameworks,
        )
        from precinct6_dataset.mitre_mapping import (
            tactics_for_set_roles, tactics_for_mo,
            techniques_for_set_roles, techniques_for_mo,
            merge_unique,
        )

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

                # Compute incident-level labels (shared by all its edges)
                mo_name = incident.get("mo_name", "")
                status = incident.get("status_name", "Unprocessed")
                # disposition = raw Precinct status_name
                disposition = status or "Unprocessed"
                disposition_category = STATUS_TO_DISPOSITION.get(status, "automated")
                suspicion = incident.get("suspicion_score", 0) or 0

                # Resolve set role names from multiple sources
                set_role_names = self._extract_set_role_names(incident)

                # MITRE tactics: union of set-role-derived + MO-derived
                attack_tactics = merge_unique(
                    tactics_for_set_roles(set_role_names),
                    tactics_for_mo(mo_name),
                )

                # MITRE techniques: union of frameworks data + set-role priors + MO priors
                tech_set = set()
                nodes = incident.get("nodes", {})
                if isinstance(nodes, dict):
                    for node in nodes.values():
                        if not isinstance(node, dict):
                            continue
                        products = node.get("products", {})
                        if isinstance(products, dict):
                            for prod in products.values():
                                if isinstance(prod, dict):
                                    for t in _extract_techniques_from_frameworks(
                                        prod.get("frameworks", {})
                                    ):
                                        tech_set.add(t)
                attack_techniques = merge_unique(
                    sorted(tech_set),
                    techniques_for_set_roles(set_role_names),
                    techniques_for_mo(mo_name),
                )

                lifecycle = MO_TO_LIFECYCLE.get(mo_name, "unknown")
                if lifecycle == "unknown":
                    for role in set_role_names:
                        if role in SET_ROLE_TO_LIFECYCLE:
                            lifecycle = SET_ROLE_TO_LIFECYCLE[role]
                            break

                inc_id = incident.get("id", "")

                # Add nodes from incident (with per-entity labels)
                if isinstance(nodes, dict):
                    for node_id, node in nodes.items():
                        if isinstance(node, dict):
                            # Extract node-specific set roles
                            node_sets = node.get("sets", {})
                            node_set_roles = []
                            if isinstance(node_sets, dict):
                                for s in node_sets.values():
                                    if isinstance(s, dict) and s.get("name"):
                                        node_set_roles.append(s["name"])
                            elif isinstance(node_sets, list):
                                for s in node_sets:
                                    if isinstance(s, dict) and s.get("name"):
                                        node_set_roles.append(s["name"])

                            # Per-node products observed
                            node_products = []
                            node_prods = node.get("products", {})
                            if isinstance(node_prods, dict):
                                for p in node_prods.values():
                                    if isinstance(p, dict) and p.get("name"):
                                        node_products.append(p["name"])

                            gnode = {
                                "node_id": node_id,
                                "type": node.get("type", "HOST").upper(),
                                "attrs": {
                                    "ip": node.get("ip_address", node.get("ip", "")),
                                    "hostname": node.get("hostname", ""),
                                    "credential": node.get("credential", ""),
                                    "set_roles": node_set_roles,
                                    "suspicion_score": node.get("suspicion_score", 0) or 0,
                                    "products": node_products,
                                    "internal": node.get("internal", False),
                                    "managed": node.get("managed", False),
                                    "incident_id": inc_id,
                                },
                            }
                            self.nodes[node_id] = gnode

                # Add edges from incident (with enriched labels)
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
                                    "incident_id": inc_id,
                                    "mo_name": mo_name,
                                    "status": status,
                                    "edge_subtype": edge.get("subtype", ""),
                                    "started": edge.get("started", 0),
                                    "ended": edge.get("ended", 0),
                                    "count": edge.get("count", 0),
                                    "bytes": edge.get("bytes", 0),
                                },
                                "labels": {
                                    "label_binary": "malicious",
                                    "label_confidence": max(0.7, min(1.0, suspicion)) if suspicion > 0 else 0.7,
                                    "suspicion_score": suspicion,
                                    "mo_name": mo_name,
                                    "attack_techniques": attack_techniques,
                                    "attack_tactics": attack_tactics,
                                    "set_roles": set_role_names,
                                    "lifecycle_stage": lifecycle,
                                    "disposition": disposition,
                                    "disposition_category": disposition_category,
                                    "status_name": status,
                                    "incident_id": inc_id,
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
