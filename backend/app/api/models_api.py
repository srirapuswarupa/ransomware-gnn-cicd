"""
Model Metadata, Metrics Comparison, and Active Model Switch Endpoints.
"""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.core.config import settings
from backend.app.services.gnn_inference_service import inference_service

router = APIRouter(prefix="/models", tags=["Models"])

class SwitchModelRequest(BaseModel):
    model_name: str

@router.get("/comparison")
def get_model_comparison_metrics():
    """Retrieves empirical evaluation metrics comparing GAT, GCN, GraphSAGE, and Random Forest."""
    metrics_file = settings.METRICS_DIR / "comparison_results.json"
    if not metrics_file.exists():
        raise HTTPException(status_code=404, detail="Model evaluation metrics file not found. Run training first.")
    with open(metrics_file, "r", encoding="utf-8") as f:
        return json.load(f)

@router.get("/active")
def get_active_model():
    """Returns currently selected inference backbone."""
    return {
        "active_model": inference_service.active_model_name,
        "available_models": list(inference_service.models.keys())
    }

@router.post("/switch")
def switch_active_model(req: SwitchModelRequest):
    """Switches the active inference model backbone."""
    name = req.model_name.lower()
    if name not in inference_service.models:
        raise HTTPException(status_code=400, detail=f"Model '{name}' not found. Choose from {list(inference_service.models.keys())}")
    inference_service.active_model_name = name
    return {"message": f"Active model switched to {name.upper()}", "active_model": name}
