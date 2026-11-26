"""
Inference, Early Warning, and Explainability Endpoints.
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.database.models import SampleRecord
from backend.app.schemas.prediction import PredictionRequest, PredictionResponse, EarlyWarningResponse
from backend.app.services.gnn_inference_service import inference_service
from backend.app.services.early_warning_service import early_warning_service
from backend.app.services.explainability_service import explainability_service

router = APIRouter(prefix="/inference", tags=["Inference"])

@router.post("/predict", response_model=PredictionResponse)
def predict_sample(req: PredictionRequest, db: Session = Depends(get_db)):
    """Runs GNN classification on an uploaded or provided API call trace."""
    try:
        resp, _ = inference_service.predict_trace(req.trace_data, model_name=req.model_type)
        
        # Save sample prediction record to DB if not already recorded
        existing = db.query(SampleRecord).filter(SampleRecord.sample_id == resp.sample_id).first()
        if not existing:
            meta = req.trace_data.get("metadata", {})
            rec = SampleRecord(
                sample_id=resp.sample_id,
                sha256=meta.get("sha256", "0"*64),
                label=meta.get("label", "unknown"),
                predicted_label=resp.predicted_class,
                confidence=resp.confidence,
                risk_score=resp.risk_score,
                risk_level=resp.risk_level,
                model_used=resp.model_used,
                total_calls=resp.total_calls_analyzed,
                duration_ms=meta.get("duration_ms", 0.0),
                is_synthetic=resp.is_synthetic
            )
            db.add(rec)
            db.commit()

        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

@router.post("/early-warning", response_model=EarlyWarningResponse)
def early_warning_analysis(req: PredictionRequest):
    """Evaluates incremental prefixes of a trace to simulate early runtime alerts."""
    try:
        return early_warning_service.analyze_prefix_trajectory(req.trace_data, model_name=req.model_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Early warning analysis failed: {str(e)}")

@router.post("/explain")
def explain_sample(req: PredictionRequest):
    """Computes GNNExplainer saliency and extracts critical subgraphs."""
    try:
        return explainability_service.explain_trace(req.trace_data, model_name=req.model_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explainability computation failed: {str(e)}")
