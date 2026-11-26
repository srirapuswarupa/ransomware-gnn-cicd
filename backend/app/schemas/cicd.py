"""
Pydantic Schemas for CI/CD Security Screening.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class CicdScanRequest(BaseModel):
    artifact_name: str = Field(..., description="Build artifact or binary name")
    commit_sha: Optional[str] = Field(default="head-sha", description="Git commit SHA")
    pipeline_stage: Optional[str] = Field(default="Staging Pre-Release", description="CI/CD Pipeline Stage")
    trace_data: Optional[Dict[str, Any]] = Field(default=None, description="Dynamic behavior trace")
    fixture_name: Optional[str] = Field(default=None, description="Pre-loaded fixture name: benign, suspicious, or ransomware")

class PolicyRuleViolation(BaseModel):
    rule_id: str
    severity: str
    description: str

class CicdScanResponse(BaseModel):
    run_id: str
    artifact_name: str
    pipeline_stage: str
    policy_decision: str       # PASS, WARN, BLOCK
    risk_score: float
    risk_level: str
    predicted_class: str
    confidence: float
    violations: List[PolicyRuleViolation]
    audit_id: int
    timestamp: str
