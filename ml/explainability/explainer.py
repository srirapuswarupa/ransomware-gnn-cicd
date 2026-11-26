"""
Graph Explainability Engine.
Inspired by GNNExplainer (Amer et al., GraphShield) and feature attribution literature.
Identifies influential API nodes, critical subgraphs, and provides human-interpretable rationale.
"""
from typing import Dict, List, Any, Tuple
import numpy as np
import torch
import torch.nn.functional as F

from ml.models.gnn_modules import GNNClassifier
from ml.graph.builder import GraphData

class GraphExplainer:
    """
    Computes saliency and feature attribution for GNN predictions
    to extract critical subgraphs and explain model decisions.
    """
    def __init__(self, model: GNNClassifier, device: str = "cpu"):
        self.model = model.to(device)
        self.device = device

    def explain(self, graph_data: GraphData, top_k: int = 7) -> Dict[str, Any]:
        """
        Computes node importance attribution via gradient-based saliency
        and contextual heuristics from PASAC sensitive API markers.
        """
        self.model.eval()
        x = graph_data.x.clone().detach().to(self.device).requires_grad_(True)
        edge_index = graph_data.edge_index.to(self.device)
        
        # Forward pass
        logits, node_emb = self.model(x, edge_index)
        probs = F.softmax(logits, dim=-1).squeeze(0)
        predicted_class = int(torch.argmax(probs).item())
        class_names = ["Benign", "Suspicious", "Ransomware"]
        pred_label = class_names[predicted_class]

        # Compute gradient of target class score with respect to input features
        target_score = logits[0, predicted_class]
        self.model.zero_grad()
        target_score.backward(retain_graph=True)

        # Node attribution = L2 norm of (gradient * input_features)
        with torch.no_grad():
            node_grads = x.grad if x.grad is not None else torch.zeros_like(x)
            saliency = torch.norm(node_grads * x, dim=-1).cpu().numpy()
            
            # Normalize saliency
            max_sal = np.max(saliency) if len(saliency) > 0 and np.max(saliency) > 0 else 1.0
            norm_saliency = (saliency / max_sal).tolist()

        # Combine with node metadata
        node_scores = []
        for idx, meta in enumerate(graph_data.node_metadata):
            base_sal = norm_saliency[idx] if idx < len(norm_saliency) else 0.0
            # Contextual weight for sensitive APIs
            if meta.get("is_sensitive", False):
                base_sal = min(1.0, base_sal + 0.35)
                
            node_scores.append({
                "node_id": idx,
                "api_name": meta.get("api_name", "UNKNOWN"),
                "category": meta.get("category", "Unknown"),
                "timestamp_ms": meta.get("timestamp_ms", 0.0),
                "is_sensitive": meta.get("is_sensitive", False),
                "importance_score": round(float(base_sal), 4),
                "arguments": meta.get("arguments", {})
            })

        # Rank by importance
        ranked_nodes = sorted(node_scores, key=lambda n: n["importance_score"], reverse=True)
        top_influential = ranked_nodes[:top_k]

        # Extract critical subgraph edges
        top_node_ids = set(n["node_id"] for n in top_influential)
        subgraph_edges = []
        src_list = graph_data.edge_index[0].tolist()
        dst_list = graph_data.edge_index[1].tolist()
        for s, d in zip(src_list, dst_list):
            if s in top_node_ids and d in top_node_ids:
                subgraph_edges.append({"source": s, "target": d})

        # Generate human-readable explanation
        explanation_text = self._generate_narrative(pred_label, probs[predicted_class].item(), top_influential)

        return {
            "predicted_class": pred_label,
            "confidence": round(float(probs[predicted_class].item()), 4),
            "top_influential_calls": top_influential,
            "critical_subgraph": {
                "nodes": top_influential,
                "edges": subgraph_edges
            },
            "explanation_narrative": explanation_text
        }

    def _generate_narrative(self, label: str, confidence: float, top_nodes: List[Dict[str, Any]]) -> str:
        top_apis = [n["api_name"] for n in top_nodes[:4]]
        api_str = ", ".join(top_apis)
        categories = list(set(n["category"] for n in top_nodes))
        cat_str = ", ".join(categories)

        if label == "Ransomware":
            return (
                f"Prediction classified as RANSOMWARE with {confidence*100:.1f}% confidence. "
                f"The Graph Neural Network identified high structural activation across critical tactical stages: "
                f"specifically invoking [{api_str}], operating within functional domains ({cat_str}). "
                f"This pattern exhibits strong correlation with pre-attack system preparation, "
                f"shadow copy destruction, and rapid cryptographic file modification."
            )
        elif label == "Suspicious":
            return (
                f"Prediction classified as SUSPICIOUS with {confidence*100:.1f}% confidence. "
                f"The model detected anomalous behavior involving [{api_str}] ({cat_str}), "
                f"indicative of environment reconnaissance or privilege escalation, "
                f"though without pervasive file encryption sequences."
            )
        else:
            return (
                f"Prediction classified as BENIGN with {confidence*100:.1f}% confidence. "
                f"The API invocation graph reflects standard application execution characteristics, "
                f"primarily standard system utilities, file inspections, and normal library loading [{api_str}]."
            )
