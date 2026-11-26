"""
CI/CD Supply Chain Security Scanner Service.
Groundwork inspired by STRIDE-Based CI/CD Threat Modeling (Dhandapani, 2025).
Evaluates software build artifacts against GNN behavioral detection policies,
rendering automated PASS, WARN, or BLOCK release gates with full audit trail.
"""
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.database.models import ScanRunRecord, AuditLogRecord
from backend.app.schemas.cicd import CicdScanRequest, CicdScanResponse, PolicyRuleViolation
from backend.app.services.gnn_inference_service import inference_service

class CicdScannerService:
    def __init__(self):
        self.inference = inference_service
        self.fixtures_dir = settings.BASE_DIR / "ci_cd" / "fixtures"

    def _load_fixture(self, fixture_name: str) -> Dict[str, Any]:
        """Loads a verified demonstration fixture trace."""
        clean_name = fixture_name.lower().replace("_artifact", "").replace(".json", "")
        fixture_file = self.fixtures_dir / f"{clean_name}_artifact.json"
        if not fixture_file.exists():
            raise FileNotFoundError(f"Fixture '{fixture_name}' not found at {fixture_file}")
        with open(fixture_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def scan_artifact(self, request: CicdScanRequest, db: Optional[Session] = None) -> CicdScanResponse:
        """
        Executes end-to-end security screening on a build artifact trace.
        Enforces configurable release gating rules.
        """
        run_id = f"RUN-{uuid.uuid4().hex[:10].upper()}"
        
        # Determine trace source
        if request.fixture_name:
            trace_dict = self._load_fixture(request.fixture_name)
        elif request.trace_data:
            trace_dict = request.trace_data
        else:
            # Default to benign fixture if none provided
            trace_dict = self._load_fixture("benign")

        # 1. Run GNN Inference
        pred_resp, graph_data = self.inference.predict_trace(trace_dict)
        risk_score = pred_resp.risk_score
        
        # 2. Evaluate Policy Rules & Detect Violations
        violations: List[PolicyRuleViolation] = []
        
        # SEC-01: Critical Ransomware Behavior Threshold
        if risk_score >= settings.RISK_THRESHOLD_BLOCK:
            violations.append(PolicyRuleViolation(
                rule_id="RULE-SEC-01",
                severity="CRITICAL",
                description=f"Risk score ({risk_score}/100) exceeds maximum permissible threshold ({settings.RISK_THRESHOLD_BLOCK})."
            ))

        # SEC-02: Destructive Defense Evasion & Shadow Copy Tampering
        events = trace_dict.get("events", [])
        shadow_calls = [e for e in events if "vssadmin" in str(e.get("arguments", "")).lower() or "bcdedit" in str(e.get("arguments", "")).lower()]
        if shadow_calls:
            violations.append(PolicyRuleViolation(
                rule_id="RULE-SEC-02",
                severity="CRITICAL",
                description="Detected prohibited execution of system recovery deletion commands (vssadmin/bcdedit)."
            ))

        # SEC-03: Suspicious Process Injection
        injection_calls = [e for e in events if e.get("api_name") in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]]
        if injection_calls and pred_resp.predicted_class != "Benign":
            violations.append(PolicyRuleViolation(
                rule_id="RULE-SEC-03",
                severity="HIGH",
                description="Unauthorized inter-process memory allocation and remote thread injection detected."
            ))

        # SEC-04: Medium Risk Warning
        if settings.RISK_THRESHOLD_WARN <= risk_score < settings.RISK_THRESHOLD_BLOCK:
            violations.append(PolicyRuleViolation(
                rule_id="RULE-SEC-04",
                severity="MEDIUM",
                description="Artifact exhibits suspicious behavioural markers requiring manual security authorization."
            ))

        # 3. Determine Final Gate Decision
        if any(v.severity == "CRITICAL" for v in violations) or risk_score >= settings.RISK_THRESHOLD_BLOCK:
            policy_decision = "BLOCK"
        elif any(v.severity in ["HIGH", "MEDIUM"] for v in violations) or risk_score >= settings.RISK_THRESHOLD_WARN:
            policy_decision = "WARN"
        else:
            policy_decision = "PASS"

        now_str = datetime.utcnow().isoformat()
        audit_id = 1

        # 4. Save to Database and Create Immutable Audit Log
        if db is not None:
            details_dict = {
                "predicted_class": pred_resp.predicted_class,
                "confidence": pred_resp.confidence,
                "probabilities": pred_resp.probabilities,
                "violations": [v.model_dump() for v in violations],
                "total_calls": pred_resp.total_calls_analyzed,
                "model_used": pred_resp.model_used
            }
            scan_rec = ScanRunRecord(
                run_id=run_id,
                artifact_name=request.artifact_name,
                pipeline_stage=request.pipeline_stage or "Pre-Deployment Screening",
                policy_decision=policy_decision,
                risk_score=risk_score,
                details_json=json.dumps(details_dict),
                author="pipeline-runner"
            )
            db.add(scan_rec)
            db.flush()

            audit_rec = AuditLogRecord(
                action=f"CI/CD Pipeline Decision: {policy_decision}",
                actor="CI-GNN-Policy-Engine",
                details=f"Artifact: {request.artifact_name} | Decision: {policy_decision} | Risk: {risk_score} | Violations: {len(violations)}"
            )
            db.add(audit_rec)
            db.commit()
            db.refresh(scan_rec)
            audit_id = scan_rec.id

        return CicdScanResponse(
            run_id=run_id,
            artifact_name=request.artifact_name,
            pipeline_stage=request.pipeline_stage or "Pre-Deployment Screening",
            policy_decision=policy_decision,
            risk_score=risk_score,
            risk_level=pred_resp.risk_level,
            predicted_class=pred_resp.predicted_class,
            confidence=pred_resp.confidence,
            violations=violations,
            audit_id=audit_id,
            timestamp=now_str
        )

cicd_scanner_service = CicdScannerService()
