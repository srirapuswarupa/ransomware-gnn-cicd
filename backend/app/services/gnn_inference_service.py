"""
GNN Inference Service.
Loads trained PyTorch checkpoints, converts traces to GraphData,
executes model predictions, and calculates nuanced multi-factor risk scores.
"""
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import torch
import torch.nn.functional as F

from backend.app.core.config import settings
from ml.data.schema import ApiTrace
from ml.preprocessing.normalizer import normalize_trace
from ml.graph.builder import GraphBuilder, GraphData
from ml.models.gnn_modules import GNNClassifier
from backend.app.schemas.prediction import PredictionResponse

class GNNInferenceService:
    def __init__(self):
        self.device = "cpu"
        self.builder = GraphBuilder()
        self.models: Dict[str, GNNClassifier] = {}
        self.active_model_name = settings.DEFAULT_MODEL
        self._load_all_models()

    def _load_all_models(self):
        """Loads available model checkpoints into memory."""
        for gnn_type in ["gat", "gcn", "graphsage"]:
            ckpt_path = settings.CHECKPOINTS_DIR / f"{gnn_type}_model.pt"
            if ckpt_path.exists():
                try:
                    ckpt = torch.load(ckpt_path, map_location=self.device)
                    model = GNNClassifier(
                        in_dim=ckpt.get("in_dim", 14),
                        hidden_dim=ckpt.get("hidden_dim", 64),
                        num_classes=ckpt.get("num_classes", 3),
                        gnn_type=gnn_type
                    )
                    model.load_state_dict(ckpt["model_state_dict"])
                    model.eval()
                    self.models[gnn_type] = model
                except Exception as e:
                    print(f"Failed to load checkpoint for {gnn_type}: {e}")

    def get_model(self, model_name: Optional[str] = None) -> Tuple[GNNClassifier, str]:
        name = (model_name or self.active_model_name).lower()
        if name not in self.models:
            # Fallback to whatever is loaded
            if self.models:
                name = list(self.models.keys())[0]
            else:
                raise RuntimeError("No trained GNN models available.")
        return self.models[name], name

    def predict_trace(self, trace_or_dict: Any, model_name: Optional[str] = None) -> Tuple[PredictionResponse, GraphData]:
        """Runs full GNN inference and computes risk metrics."""
        if isinstance(trace_or_dict, dict):
            trace = normalize_trace(trace_or_dict)
        elif isinstance(trace_or_dict, ApiTrace):
            trace = trace_or_dict
        else:
            raise ValueError("Input must be ApiTrace or dict")

        model, used_model_name = self.get_model(model_name)
        graph_data = self.builder.build(trace)

        x = graph_data.x.to(self.device)
        edge_index = graph_data.edge_index.to(self.device)

        t0 = time.perf_counter()
        with torch.no_grad():
            logits, _ = model(x, edge_index)
            inference_ms = (time.perf_counter() - t0) * 1000.0
            probs = F.softmax(logits, dim=-1).squeeze(0).cpu().numpy()

        class_names = ["Benign", "Suspicious", "Ransomware"]
        pred_idx = int(probs.argmax())
        pred_class = class_names[pred_idx]
        confidence = float(probs[pred_idx])

        # Compute Multi-Factor Security Risk Score (0 to 100)
        p_benign = float(probs[0])
        p_susp = float(probs[1])
        p_ransom = float(probs[2])

        total_calls = max(1, len(trace.events))
        sensitive_count = sum(1 for e in trace.events if e.is_sensitive)
        sens_ratio = sensitive_count / total_calls

        # Critical indicators
        has_shadow_tamper = any("vssadmin" in str(e.arguments).lower() or "bcdedit" in str(e.arguments).lower() for e in trace.events)
        has_encryption = any(e.category == "Cryptography" for e in trace.events)

        base_risk = (p_ransom * 80.0) + (p_susp * 45.0) + (sens_ratio * 15.0)
        if has_shadow_tamper:
            base_risk += 15.0
        if has_encryption and p_ransom > 0.3:
            base_risk += 10.0

        risk_score = round(min(100.0, max(0.0, base_risk)), 2)

        if risk_score >= settings.RISK_THRESHOLD_BLOCK:
            risk_level = "High"
        elif risk_score >= settings.RISK_THRESHOLD_WARN:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        resp = PredictionResponse(
            sample_id=trace.metadata.sample_id,
            predicted_class=pred_class,
            confidence=round(confidence, 4),
            probabilities={
                "benign": round(p_benign, 4),
                "suspicious": round(p_susp, 4),
                "ransomware": round(p_ransom, 4)
            },
            risk_score=risk_score,
            risk_level=risk_level,
            model_used=used_model_name,
            inference_time_ms=round(inference_ms, 2),
            total_calls_analyzed=total_calls,
            pasac_sensitive_count=sensitive_count,
            is_synthetic=trace.metadata.is_synthetic
        )
        return resp, graph_data

inference_service = GNNInferenceService()
