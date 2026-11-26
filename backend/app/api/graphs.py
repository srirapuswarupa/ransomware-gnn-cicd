"""
API Call Graph Construction and Cytoscape.js Visualization Endpoints.
"""
from typing import Dict, Any
from fastapi import APIRouter, HTTPException

from ml.preprocessing.normalizer import normalize_trace
from ml.graph.builder import GraphBuilder
from backend.app.core.config import settings

router = APIRouter(prefix="/graphs", tags=["Graphs"])
builder = GraphBuilder()

@router.post("/build")
def build_graph_elements(trace_dict: Dict[str, Any]):
    """Converts a trace dictionary into Cytoscape.js elements for visualization."""
    try:
        norm_trace = normalize_trace(trace_dict)
        graph_data = builder.build(norm_trace)
        return builder.to_cytoscape_elements(graph_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph construction error: {str(e)}")

@router.get("/{sample_id}")
def get_graph_by_sample_id(sample_id: str):
    """Loads a sample from dataset and returns its interactive graph elements."""
    dataset_dir = settings.DATASET_DIR / "synthetic"
    matches = list(dataset_dir.rglob(f"{sample_id}.json"))
    if not matches:
        raise HTTPException(status_code=404, detail=f"Sample {sample_id} not found.")
    
    import json
    with open(matches[0], "r", encoding="utf-8") as f:
        trace_dict = json.load(f)
        
    norm_trace = normalize_trace(trace_dict)
    graph_data = builder.build(norm_trace)
    return builder.to_cytoscape_elements(graph_data)
