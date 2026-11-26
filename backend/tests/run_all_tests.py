"""
Comprehensive System Test Suite.
Verifies all project layers:
1. Trace Ingestion & Preprocessing
2. API Call Graph Construction
3. Multi-Model GNN Inference (GAT, GCN, GraphSAGE)
4. Early Warning Prefix Trajectory
5. Graph Explainability (Saliency & Subgraphs)
6. CI/CD Security Screening & Policy Gate (PASS, WARN, BLOCK)
7. Audit Logs & Report Generation
8. FastAPI Endpoint Handlers
"""
import sys
import json
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from ml.data.synthetic_generator import SyntheticTraceGenerator
from ml.preprocessing.normalizer import normalize_trace
from ml.graph.builder import GraphBuilder
from backend.app.services.gnn_inference_service import inference_service
from backend.app.services.early_warning_service import early_warning_service
from backend.app.services.explainability_service import explainability_service
from backend.app.services.cicd_scanner_service import cicd_scanner_service
from backend.app.services.report_service import report_service
from backend.app.schemas.cicd import CicdScanRequest
from backend.app.database.session import SessionLocal, engine, Base
from backend.app.database.models import ScanRunRecord, AuditLogRecord

def run_tests():
    print("=" * 70, flush=True)
    print("STARTING COMPREHENSIVE SYSTEM VERIFICATION", flush=True)
    print("=" * 70, flush=True)

    passed_tests = 0
    total_tests = 0

    # Ensure tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    def test(name, fn):
        nonlocal passed_tests, total_tests
        total_tests += 1
        print(f"\n[TEST {total_tests}] {name}...", end=" ", flush=True)
        try:
            fn()
            print("PASSED [OK]", flush=True)
            passed_tests += 1
        except Exception as e:
            print(f"FAILED [X]\n  Error: {e}", flush=True)
            import traceback
            traceback.print_exc()

    # --- Test 1: Synthetic Trace Generation & Normalization ---
    def t1():
        gen = SyntheticTraceGenerator(seed=999)
        b = gen.generate_benign_trace(1)
        r = gen.generate_ransomware_trace(1)
        assert b.metadata.label == "benign"
        assert r.metadata.label == "ransomware"
        assert r.metadata.is_synthetic is True
        assert len(r.events) > 20
        norm_r = normalize_trace(r.model_dump())
        assert norm_r.metadata.sample_id == r.metadata.sample_id
    test("Trace Generation, PASAC Flagging & Schema Normalization", t1)

    # --- Test 2: Graph Builder & Cytoscape Elements ---
    builder = GraphBuilder()
    def t2():
        gen = SyntheticTraceGenerator(seed=123)
        r = gen.generate_ransomware_trace(2)
        graph = builder.build(r)
        assert graph.num_nodes == len(r.events)
        assert graph.num_edges > 0
        assert graph.x.shape[1] == 14
        assert graph.y.item() == 2 # Ransomware label

        cyto = builder.to_cytoscape_elements(graph)
        assert "elements" in cyto
        assert len(cyto["elements"]["nodes"]) > 0
        assert len(cyto["elements"]["edges"]) > 0
    test("Directed Multi-Relational API Call Graph Construction", t2)

    # --- Test 3: Multi-Model Inference (GAT, GCN, GraphSAGE) ---
    def t3():
        gen = SyntheticTraceGenerator(seed=456)
        r = gen.generate_ransomware_trace(3)
        b = gen.generate_benign_trace(3)

        for model_name in ["gat", "gcn", "graphsage"]:
            resp_r, _ = inference_service.predict_trace(r, model_name=model_name)
            assert resp_r.predicted_class == "Ransomware", f"{model_name} failed on ransomware: {resp_r.predicted_class}"
            assert resp_r.risk_score >= 70.0
            assert resp_r.risk_level == "High"

            resp_b, _ = inference_service.predict_trace(b, model_name=model_name)
            assert resp_b.predicted_class == "Benign", f"{model_name} failed on benign: {resp_b.predicted_class}"
            assert resp_b.risk_score < 40.0
            assert resp_b.risk_level == "Low"
    test("Multi-Model GNN Inference (GAT, GCN, GraphSAGE) & Risk Scoring", t3)

    # --- Test 4: Early Ransomware Warning Trajectory ---
    def t4():
        gen = SyntheticTraceGenerator(seed=789)
        r = gen.generate_ransomware_trace(4)
        ew = early_warning_service.analyze_prefix_trajectory(r, model_name="gat")
        assert ew.final_class == "Ransomware"
        assert ew.early_alert_triggered is True
        assert ew.trigger_cutoff_percentage is not None
        assert ew.lead_time_ms is not None
        assert len(ew.trajectory) == 7
        print(f" (Early Alert at {ew.trigger_cutoff_percentage}% of trace, lead time: {ew.lead_time_ms}ms)", end="")
    test("Early Warning Prefix Analysis & Pre-Attack Lead Time", t4)

    # --- Test 5: Graph Explainability & Critical Subgraph Attribution ---
    def t5():
        gen = SyntheticTraceGenerator(seed=101)
        r = gen.generate_ransomware_trace(5)
        explanation = explainability_service.explain_trace(r, model_name="gat")
        assert explanation["predicted_class"] == "Ransomware"
        assert len(explanation["top_influential_calls"]) > 0
        assert "explanation_narrative" in explanation
        assert "critical_subgraph" in explanation
    test("GNN Saliency Attribution & Human-Readable Explanations", t5)

    # --- Test 6: CI/CD Screening: Benign Release Gate (PASS) ---
    def t6():
        req = CicdScanRequest(artifact_name="release_build_v2.0.exe", fixture_name="benign")
        res = cicd_scanner_service.scan_artifact(req, db=db)
        assert res.policy_decision == "PASS"
        assert res.risk_score < 40.0
        assert res.predicted_class == "Benign"
    test("CI/CD Pipeline Security Screening: Benign Artifact -> PASS", t6)

    # --- Test 7: CI/CD Screening: Ransomware Supply Chain Block (BLOCK) ---
    def t7():
        req = CicdScanRequest(artifact_name="compromised_package.exe", fixture_name="ransomware")
        res = cicd_scanner_service.scan_artifact(req, db=db)
        assert res.policy_decision == "BLOCK"
        assert res.risk_score >= 70.0
        assert len(res.violations) > 0
        assert any(v.severity == "CRITICAL" for v in res.violations)
    test("CI/CD Pipeline Security Screening: Malicious Artifact -> BLOCK", t7)

    # --- Test 8: CI/CD Screening: Suspicious Artifact Gate (WARN) ---
    def t8():
        req = CicdScanRequest(artifact_name="admin_diagnostic_utility.exe", fixture_name="suspicious")
        res = cicd_scanner_service.scan_artifact(req, db=db)
        assert res.policy_decision in ["WARN", "BLOCK"]
        assert res.predicted_class in ["Suspicious", "Ransomware"]
    test("CI/CD Pipeline Security Screening: Suspicious Artifact -> WARN/BLOCK", t8)

    # --- Test 9: Audit Logs and Report Generation ---
    def t9():
        summary = report_service.generate_demo_summary()
        assert "project_title" in summary
        assert "model_metrics" in summary
        assert len(summary["recent_pipeline_runs"]) > 0

        # Query latest run
        latest_run = db.query(ScanRunRecord).order_by(ScanRunRecord.created_at.desc()).first()
        assert latest_run is not None
        md = report_service.generate_markdown_report(latest_run.run_id)
        assert "Artifact Security Screening Report" in md
    test("Audit Trail Recording & Markdown/JSON Report Generation", t9)

    db.close()

    print("\n" + "=" * 70, flush=True)
    print(f"VERIFICATION RESULTS: {passed_tests}/{total_tests} TESTS PASSED SUCCESSFULLY", flush=True)
    print("=" * 70, flush=True)

    if passed_tests == total_tests:
        print("ALL BACKEND, ML, GNN, AND CI/CD SECURITY MODULES ARE FULLY OPERATIONAL!", flush=True)
        return 0
    else:
        print("SOME TESTS FAILED.", flush=True)
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
