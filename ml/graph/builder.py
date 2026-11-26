"""
API Call Graph Construction Engine and Graph Batching.
Transforms linear execution traces into directed, multi-relational attributed graphs
and provides disjoint block-diagonal batching for high-throughput GNN training.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import networkx as nx
import numpy as np
import torch

from ml.data.schema import ApiTrace, ApiCallEvent
from ml.graph.features import FeatureEncoder, NODE_FEATURE_DIM, EDGE_FEATURE_DIM

@dataclass
class GraphData:
    x: torch.Tensor                     # [N, NODE_FEATURE_DIM]
    edge_index: torch.Tensor            # [2, M]
    edge_attr: torch.Tensor             # [M, EDGE_FEATURE_DIM]
    y: torch.Tensor                     # [1]
    num_nodes: int
    num_edges: int
    sample_id: str
    label_name: str
    family: str
    node_metadata: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class BatchedGraphData:
    x: torch.Tensor
    edge_index: torch.Tensor
    edge_attr: torch.Tensor
    y: torch.Tensor
    batch: torch.Tensor
    num_graphs: int

def batch_graphs(graphs: List[GraphData]) -> BatchedGraphData:
    """Combines a list of disjoint GraphData instances into a single batched graph."""
    if not graphs:
        raise ValueError("Cannot batch empty graph list")

    x_list = []
    edge_index_list = []
    edge_attr_list = []
    y_list = []
    batch_list = []
    
    current_node_offset = 0

    for i, g in enumerate(graphs):
        x_list.append(g.x)
        edge_index_list.append(g.edge_index + current_node_offset)
        edge_attr_list.append(g.edge_attr)
        y_list.append(g.y.item())
        batch_list.append(torch.full((g.num_nodes,), i, dtype=torch.long))
        current_node_offset += g.num_nodes

    return BatchedGraphData(
        x=torch.cat(x_list, dim=0),
        edge_index=torch.cat(edge_index_list, dim=1),
        edge_attr=torch.cat(edge_attr_list, dim=0),
        y=torch.tensor(y_list, dtype=torch.long),
        batch=torch.cat(batch_list, dim=0),
        num_graphs=len(graphs)
    )

class GraphBuilder:
    """Builds directed attributed graphs from ApiTrace instances."""

    def __init__(self):
        self.encoder = FeatureEncoder()

    def build(self, trace: ApiTrace) -> GraphData:
        events = trace.events
        num_events = len(events)
        
        # Handle edge cases
        if num_events == 0:
            x = torch.zeros((1, NODE_FEATURE_DIM), dtype=torch.float32)
            edge_index = torch.zeros((2, 1), dtype=torch.long)
            edge_attr = torch.zeros((1, EDGE_FEATURE_DIM), dtype=torch.float32)
            y = torch.tensor([trace.metadata.label_id], dtype=torch.long)
            return GraphData(
                x=x, edge_index=edge_index, edge_attr=edge_attr, y=y,
                num_nodes=1, num_edges=1, sample_id=trace.metadata.sample_id,
                label_name=trace.metadata.label, family=trace.metadata.family,
                node_metadata=[{"id": 0, "api_name": "NOP", "category": "System_Util"}]
            )

        api_counts: Dict[str, int] = {}
        for ev in events:
            api_counts[ev.api_name] = api_counts.get(ev.api_name, 0) + 1
            
        max_duration = max(ev.timestamp_ms for ev in events) if events else 1.0

        node_feats = []
        node_meta = []
        for idx, ev in enumerate(events):
            rel_freq = api_counts[ev.api_name] / num_events
            feat = self.encoder.encode_node(ev, num_events, max_duration, rel_freq)
            node_feats.append(feat)
            node_meta.append({
                "id": idx,
                "api_name": ev.api_name,
                "category": ev.category,
                "timestamp_ms": ev.timestamp_ms,
                "thread_id": ev.thread_id,
                "is_sensitive": ev.is_sensitive,
                "arguments": ev.arguments
            })

        x = torch.tensor(np.array(node_feats), dtype=torch.float32)

        src_nodes = []
        dst_nodes = []
        edge_feats = []

        # A. Sequential Temporal Edges: (i -> i+1)
        for i in range(num_events - 1):
            src_nodes.append(i)
            dst_nodes.append(i + 1)
            delta = events[i + 1].timestamp_ms - events[i].timestamp_ms
            edge_feats.append(self.encoder.encode_edge(delta, edge_type=0))

        # B. Intra-Thread Continuation Edges
        thread_last_seen: Dict[int, int] = {}
        for idx, ev in enumerate(events):
            tid = ev.thread_id
            if tid in thread_last_seen:
                prev_idx = thread_last_seen[tid]
                if prev_idx != idx - 1:
                    src_nodes.append(prev_idx)
                    dst_nodes.append(idx)
                    delta = ev.timestamp_ms - events[prev_idx].timestamp_ms
                    edge_feats.append(self.encoder.encode_edge(delta, edge_type=1))
            thread_last_seen[tid] = idx

        # C. Resource / Target Sharing Edges
        resource_last_seen: Dict[str, int] = {}
        for idx, ev in enumerate(events):
            res_key = None
            if "path" in ev.arguments:
                res_key = f"file:{ev.arguments['path']}"
            elif "subkey" in ev.arguments:
                res_key = f"reg:{ev.arguments['subkey']}"
            elif "endpoint" in ev.arguments:
                res_key = f"net:{ev.arguments['endpoint']}"

            if res_key:
                if res_key in resource_last_seen:
                    prev_idx = resource_last_seen[res_key]
                    if prev_idx != idx - 1:
                        src_nodes.append(prev_idx)
                        dst_nodes.append(idx)
                        delta = ev.timestamp_ms - events[prev_idx].timestamp_ms
                        edge_feats.append(self.encoder.encode_edge(delta, edge_type=2))
                resource_last_seen[res_key] = idx

        if len(src_nodes) == 0:
            src_nodes = [0]
            dst_nodes = [0]
            edge_feats = [self.encoder.encode_edge(0.0, edge_type=0)]

        edge_index = torch.tensor([src_nodes, dst_nodes], dtype=torch.long)
        edge_attr = torch.tensor(np.array(edge_feats), dtype=torch.float32)
        y = torch.tensor([trace.metadata.label_id], dtype=torch.long)

        return GraphData(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            y=y,
            num_nodes=num_events,
            num_edges=len(src_nodes),
            sample_id=trace.metadata.sample_id,
            label_name=trace.metadata.label,
            family=trace.metadata.family,
            node_metadata=node_meta
        )

    @staticmethod
    def to_cytoscape_elements(graph_data: GraphData, max_nodes_display: int = 120) -> Dict[str, Any]:
        """Converts GraphData to Cytoscape.js format for interactive frontend exploration."""
        nodes = []
        edges = []
        total_nodes = graph_data.num_nodes
        selected_node_indices = set(range(min(total_nodes, max_nodes_display)))
        for m in graph_data.node_metadata:
            if m.get("is_sensitive", False):
                selected_node_indices.add(m["id"])

        for meta in graph_data.node_metadata:
            nid = meta["id"]
            if nid in selected_node_indices:
                nodes.append({
                    "data": {
                        "id": f"n{nid}",
                        "label": meta["api_name"],
                        "category": meta["category"],
                        "timestamp": meta["timestamp_ms"],
                        "thread_id": meta["thread_id"],
                        "is_sensitive": meta["is_sensitive"],
                        "arguments": meta["arguments"]
                    }
                })

        src_list = graph_data.edge_index[0].tolist()
        dst_list = graph_data.edge_index[1].tolist()
        edge_attr_list = graph_data.edge_attr.tolist()

        for e_idx, (s, d) in enumerate(zip(src_list, dst_list)):
            if s in selected_node_indices and d in selected_node_indices:
                attr = edge_attr_list[e_idx] if e_idx < len(edge_attr_list) else [0.0, 0.0]
                edge_type_code = round(attr[1] * 2.0)
                edge_type_str = "Sequential" if edge_type_code == 0 else ("IntraThread" if edge_type_code == 1 else "ResourceDep")
                edges.append({
                    "data": {
                        "id": f"e{e_idx}",
                        "source": f"n{s}",
                        "target": f"n{d}",
                        "edge_type": edge_type_str,
                        "time_delta_score": round(attr[0], 3)
                    }
                })

        return {
            "elements": {
                "nodes": nodes,
                "edges": edges
            },
            "summary": {
                "sample_id": graph_data.sample_id,
                "label": graph_data.label_name,
                "family": graph_data.family,
                "total_nodes": graph_data.num_nodes,
                "total_edges": graph_data.num_edges,
                "displayed_nodes": len(nodes),
                "displayed_edges": len(edges)
            }
        }
