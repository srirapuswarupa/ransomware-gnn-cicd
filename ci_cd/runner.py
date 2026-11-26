"""
Standalone CI/CD Pipeline Behavioral Security Runner.
Integrates directly into GitHub Actions, Jenkins, GitLab CI, or local pre-commit hooks.
Returns exit code 0 for PASS, 0 (with warning) for WARN, and 1 for BLOCK (failing CI step).
"""
import sys
import argparse
import json
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.schemas.cicd import CicdScanRequest
from backend.app.services.cicd_scanner_service import cicd_scanner_service
from backend.app.database.session import SessionLocal

def main():
    parser = argparse.ArgumentParser(description="GNN Behavioral Security CI/CD Screening Gate")
    parser.add_argument("--artifact", type=str, default="build_artifact.exe", help="Artifact name")
    parser.add_argument("--fixture", type=str, choices=["benign", "suspicious", "ransomware"], default="benign", help="Fixture name")
    parser.add_argument("--trace", type=str, default=None, help="Path to custom trace JSON file")
    parser.add_argument("--stage", type=str, default="Pre-Deployment Security Gate", help="Pipeline stage name")
    args = parser.parse_args()

    trace_data = None
    if args.trace:
        trace_path = Path(args.trace)
        if not trace_path.exists():
            print(f"Error: Trace file {args.trace} not found.", file=sys.stderr)
            sys.exit(2)
        with open(trace_path, "r", encoding="utf-8") as f:
            trace_data = json.load(f)

    db = SessionLocal()
    try:
        req = CicdScanRequest(
            artifact_name=args.artifact,
            fixture_name=args.fixture if not trace_data else None,
            trace_data=trace_data,
            pipeline_stage=args.stage
        )
        print(f"[*] Screening artifact: '{args.artifact}' ({args.stage})...")
        res = cicd_scanner_service.scan_artifact(req, db=db)

        print("\n" + "=" * 60)
        print(f"CI/CD GATE DECISION: {res.policy_decision}")
        print("=" * 60)
        print(f"Artifact Name:      {res.artifact_name}")
        print(f"Risk Score:         {res.risk_score} / 100 ({res.risk_level} Risk)")
        print(f"Behavioral Class:   {res.predicted_class} (Confidence: {res.confidence*100:.1f}%)")
        print(f"Audit Record ID:    {res.audit_id}")

        if res.violations:
            print("\nPolicy Violations Detected:")
            for v in res.violations:
                print(f"  [{v.severity}] {v.rule_id}: {v.description}")

        print("=" * 60)

        if res.policy_decision == "BLOCK":
            print("\n[!] CI/CD PIPELINE BLOCKED: Deployment halted due to critical security risk.")
            sys.exit(1)
        elif res.policy_decision == "WARN":
            print("\n[?] CI/CD WARNING: Deployment requires manual SecOps approval.")
            sys.exit(0)
        else:
            print("\n[+] CI/CD GATE PASSED: Artifact verified safe for release.")
            sys.exit(0)
    finally:
        db.close()

if __name__ == "__main__":
    main()
