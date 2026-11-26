"""
Explainability Service Wrapper.
Executes GNNExplainer attribution and provides interpretability payloads for dashboard display.
"""
from typing import Dict, Any, Optional
from backend.app.services.gnn_inference_service import inference_service
from ml.explainability.explainer import GraphExplainer
from ml.preprocessing.normalizer import normalize_trace
from ml.graph.builder import GraphBuilder

class ExplainabilityService:
    def __init__(self):
        self.inference = inference_service
        self.builder = GraphBuilder()

    def explain_trace(self, trace_dict_or_obj: Any, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Generates node-level saliency scores, subgraphs, and human readable narrative."""
        if isinstance(trace_dict_or_obj, dict):
            trace = normalize_trace(trace_dict_or_obj)
        else:
            trace = trace_dict_or_obj

        model, used_name = self.inference.get_model(model_name)
        graph_data = self.builder.build(trace)
        
        explainer = GraphExplainer(model, device=self.inference.device)
        explanation = explainer.explain(graph_data, top_k=8)
        explanation["model_used"] = used_name
        explanation["sample_id"] = trace.metadata.sample_id
        return explanation

explainability_service = ExplainabilityService()
