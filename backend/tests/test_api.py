"""
Integration Tests for FastAPI Backend Endpoints using httpx ASGITransport.
Verifies health, trace upload, GNN prediction, early warning, explainability, and CI/CD screening.
"""
import pytest
import httpx
from backend.app.main import app

@pytest.fixture
def client():
    transport = httpx.ASGITransport(app=app)
    with httpx.Client(transport=transport, base_url="http://testserver") as c:
        yield c

def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "gat" in data["available_models"]

def test_list_samples(client):
    response = client.get("/api/traces/samples?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert len(data["samples"]) > 0

def test_model_comparison_metrics(client):
    response = client.get("/api/models/comparison")
    assert response.status_code == 200
    data = response.json()
    assert "gat" in data
    assert "gcn" in data
    assert "graphsage" in data
    assert "random_forest" in data

def test_cicd_scan_benign_fixture(client):
    response = client.post("/api/cicd/scan", json={
        "artifact_name": "worker_build_v1.0.exe",
        "fixture_name": "benign"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["policy_decision"] == "PASS"
    assert data["risk_score"] < 40.0

def test_cicd_scan_ransomware_fixture(client):
    response = client.post("/api/cicd/scan", json={
        "artifact_name": "malicious_payload.exe",
        "fixture_name": "ransomware"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["policy_decision"] == "BLOCK"
    assert data["risk_score"] >= 70.0
    assert len(data["violations"]) > 0

def test_predict_and_explain_flow(client):
    # Load sample 1
    sample_resp = client.get("/api/traces/samples?limit=1")
    sample_id = sample_resp.json()["samples"][0]["sample_id"]
    
    trace_resp = client.get(f"/api/traces/samples/{sample_id}")
    assert trace_resp.status_code == 200
    trace_data = trace_resp.json()

    # Predict
    pred_resp = client.post("/api/inference/predict", json={
        "trace_data": trace_data,
        "model_type": "gat"
    })
    assert pred_resp.status_code == 200
    pred = pred_resp.json()
    assert pred["predicted_class"] in ["Benign", "Suspicious", "Ransomware"]
    assert "risk_score" in pred

    # Explain
    exp_resp = client.post("/api/inference/explain", json={
        "trace_data": trace_data,
        "model_type": "gat"
    })
    assert exp_resp.status_code == 200
    exp = exp_resp.json()
    assert "top_influential_calls" in exp
    assert "explanation_narrative" in exp

    # Early warning
    ew_resp = client.post("/api/inference/early-warning", json={
        "trace_data": trace_data,
        "model_type": "gat"
    })
    assert ew_resp.status_code == 200
    ew = ew_resp.json()
    assert "trajectory" in ew
    assert len(ew["trajectory"]) > 0

def test_reports_summary(client):
    response = client.get("/api/reports/demo-summary")
    assert response.status_code == 200
    data = response.json()
    assert "policy_thresholds" in data
