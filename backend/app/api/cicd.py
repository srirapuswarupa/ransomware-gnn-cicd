"""
CI/CD Supply Chain Screening, Pipeline Runs, and Audit Trail Endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.database.models import ScanRunRecord, AuditLogRecord
from backend.app.schemas.cicd import CicdScanRequest, CicdScanResponse
from backend.app.services.cicd_scanner_service import cicd_scanner_service

router = APIRouter(prefix="/cicd", tags=["CI/CD"])

@router.post("/scan", response_model=CicdScanResponse)
def scan_artifact(req: CicdScanRequest, db: Session = Depends(get_db)):
    """Screens a build artifact or fixture against GNN behavioral security policies."""
    try:
        return cicd_scanner_service.scan_artifact(req, db=db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CI/CD Screening failed: {str(e)}")

@router.get("/runs")
def list_pipeline_runs(limit: int = 50, db: Session = Depends(get_db)):
    """Lists historical CI/CD artifact screening runs."""
    records = db.query(ScanRunRecord).order_by(ScanRunRecord.created_at.desc()).limit(limit).all()
    import json
    return [
        {
            "id": r.id,
            "run_id": r.run_id,
            "artifact_name": r.artifact_name,
            "pipeline_stage": r.pipeline_stage,
            "policy_decision": r.policy_decision,
            "risk_score": r.risk_score,
            "details": json.loads(r.details_json) if r.details_json else {},
            "created_at": r.created_at.isoformat() if r.created_at else ""
        }
        for r in records
    ]

@router.get("/audit-logs")
def list_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Lists tamper-evident immutable audit logs."""
    logs = db.query(AuditLogRecord).order_by(AuditLogRecord.created_at.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "action": l.action,
            "actor": l.actor,
            "details": l.details,
            "timestamp": l.created_at.isoformat() if l.created_at else ""
        }
        for l in logs
    ]
