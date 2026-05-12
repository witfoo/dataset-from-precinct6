"""Streaming GraphML writer — emits XML directly without holding graph in memory.

Handles large graphs (millions of edges) that would exhaust memory if loaded into
NetworkX. Used for the 100M dataset where a full in-memory GraphML build is infeasible.

Reference: GraphML spec http://graphml.graphdrawing.org/specification.html
"""

import xml.sax.saxutils as saxutils
from pathlib import Path
from typing import Iterable, Optional


_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n'
_GRAPHML_OPEN = (
    '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"\n'
    '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '  xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns '
    'http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">\n'
)


def _xml_escape(value) -> str:
    """Escape a value for safe XML output."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        # Use repr for complex types so they round-trip readably
        import json
        return saxutils.escape(json.dumps(value, separators=(",", ":")))
    return saxutils.escape(str(value))


def _key_decl(key_id: str, for_what: str, attr_name: str, attr_type: str = "string") -> str:
    return f'  <key id="{key_id}" for="{for_what}" attr.name="{attr_name}" attr.type="{attr_type}"/>\n'


class StreamingGraphMLWriter:
    """Write GraphML by streaming nodes and edges to disk.

    Usage:
        with StreamingGraphMLWriter(path, node_attrs, edge_attrs) as w:
            w.write_node(node_id, attrs_dict)
            w.write_edge(src_id, dst_id, attrs_dict)
    """

    def __init__(
        self,
        path: Path,
        node_attr_schema: dict[str, str],
        edge_attr_schema: dict[str, str],
        directed: bool = True,
    ):
        """
        node_attr_schema, edge_attr_schema: dict of attr_name -> attr_type
        ('string', 'int', 'long', 'float', 'double', 'boolean')
        """
        self.path = Path(path)
        self.node_attrs = node_attr_schema
        self.edge_attrs = edge_attr_schema
        self.directed = directed
        self._edge_idx = 0
        self._f = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(self.path, "w", encoding="utf-8")
        self._write_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._write_footer()
        self._f.close()
        self._f = None

    def _write_header(self):
        self._f.write(_HEADER)
        self._f.write(_GRAPHML_OPEN)

        # Declare keys for node attrs
        for name, typ in self.node_attrs.items():
            self._f.write(_key_decl(f"n_{name}", "node", name, typ))
        # Declare keys for edge attrs
        for name, typ in self.edge_attrs.items():
            self._f.write(_key_decl(f"e_{name}", "edge", name, typ))

        edgedefault = "directed" if self.directed else "undirected"
        self._f.write(f'  <graph id="G" edgedefault="{edgedefault}">\n')

    def _write_footer(self):
        self._f.write('  </graph>\n')
        self._f.write('</graphml>\n')

    def write_node(self, node_id: str, attrs: dict):
        """Stream a node element to the output."""
        self._f.write(f'    <node id="{_xml_escape(node_id)}">\n')
        for name in self.node_attrs:
            if name in attrs and attrs[name] is not None and attrs[name] != "":
                self._f.write(
                    f'      <data key="n_{name}">{_xml_escape(attrs[name])}</data>\n'
                )
        self._f.write('    </node>\n')

    def write_edge(self, src: str, dst: str, attrs: dict):
        """Stream an edge element to the output."""
        self._edge_idx += 1
        edge_id = f"e{self._edge_idx}"
        self._f.write(
            f'    <edge id="{edge_id}" source="{_xml_escape(src)}" target="{_xml_escape(dst)}">\n'
        )
        for name in self.edge_attrs:
            if name in attrs and attrs[name] is not None and attrs[name] != "":
                self._f.write(
                    f'      <data key="e_{name}">{_xml_escape(attrs[name])}</data>\n'
                )
        self._f.write('    </edge>\n')


# Standard schemas for our dataset's graphs


SIGNAL_NODE_ATTRS = {
    "type": "string",
    "ip": "string",
    "hostname": "string",
    "credential": "string",
    "set_roles": "string",
    "suspicion_score": "double",
    "products": "string",
    "report_text": "string",
}

SIGNAL_EDGE_ATTRS = {
    "type": "string",
    "timestamp": "double",
    "message_type": "string",
    "action": "string",
    "protocol": "string",
    "src_port": "string",
    "dst_port": "string",
    "stream": "string",
    "label_binary": "string",
    "label_confidence": "double",
    "suspicion_score": "double",
    "mo_name": "string",
    "attack_techniques": "string",
    "attack_tactics": "string",
    "set_roles": "string",
    "lifecycle_stage": "string",
    "disposition": "string",
    "incident_id": "string",
}
