"""
Health Check and System Diagnostics Endpoint.
"""
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.services.gnn_inference_service import inference_service

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "active_model": inference_service.active_model_name,
        "available_models": list(inference_service.models.keys()),
        "thresholds": {
            "pass": settings.RISK_THRESHOLD_PASS,
            "warn": settings.RISK_THRESHOLD_WARN,
            "block": settings.RISK_THRESHOLD_BLOCK
        }
    }
