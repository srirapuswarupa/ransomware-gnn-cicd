"""
SQLAlchemy ORM Database Schema.
Maintains persistent records for samples, predictions, CI/CD pipeline runs, and audit events.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from backend.app.database.session import Base

class SampleRecord(Base):
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True, index=True)
    sample_id = Column(String(100), unique=True, index=True)
    sha256 = Column(String(64), index=True)
    label = Column(String(50))              # benign, suspicious, ransomware
    predicted_label = Column(String(50))
    confidence = Column(Float)
    risk_score = Column(Float)
    risk_level = Column(String(20))         # Low, Medium, High
    model_used = Column(String(50))
    total_calls = Column(Integer)
    duration_ms = Column(Float)
    is_synthetic = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanRunRecord(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(100), unique=True, index=True)
    artifact_name = Column(String(200))
    pipeline_stage = Column(String(100), default="Pre-Deployment Screening")
    policy_decision = Column(String(20))    # PASS, WARN, BLOCK
    risk_score = Column(Float)
    details_json = Column(Text)             # Serialized execution and early warning details
    author = Column(String(100), default="ci-agent")
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), index=True)
    actor = Column(String(100), default="System")
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
