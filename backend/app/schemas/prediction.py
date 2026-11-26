"""
Pydantic Schemas for Prediction, Early Warning, and Model Status.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class PredictionRequest(BaseModel):
    trace_data: Dict[str, Any] = Field(..., description="Full or partial trace JSON payload")
    model_type: Optional[str] = Field(default="gat", description="gat, gcn, or graphsage")

class PredictionResponse(BaseModel):
    sample_id: str
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    risk_score: float
    risk_level: str
    model_used: str
    inference_time_ms: float
    total_calls_analyzed: int
    pasac_sensitive_count: int
    is_synthetic: bool

class EarlyWarningPrefix(BaseModel):
    cutoff_percentage: int
    calls_observed: int
    cutoff_timestamp_ms: float
    predicted_class: str
    confidence: float
    ransomware_probability: float
    risk_score: float

class EarlyWarningResponse(BaseModel):
    sample_id: str
    final_class: str
    early_alert_triggered: bool
    trigger_cutoff_percentage: Optional[int] = None
    trigger_timestamp_ms: Optional[float] = None
    trigger_call_index: Optional[int] = None
    lead_time_ms: Optional[float] = None
    lead_events_count: Optional[int] = None
    trajectory: List[EarlyWarningPrefix]
