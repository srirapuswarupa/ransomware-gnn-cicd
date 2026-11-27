import json
from pathlib import Path
import streamlit as st
from backend.app.services.gnn_inference_service import inference_service

st.set_page_config(page_title="Ransomware GNN Detection", layout="wide")
st.title("🛡️ Ransomware Behavior Detection (GNN + CI/CD)")
st.write("Analyze Windows Win32 API call traces using Graph Neural Networks (GAT, GCN, GraphSAGE).")

# Sidebar controls
model_type = st.sidebar.selectbox(
    "Select GNN Model",
    options=list(inference_service.models.keys()) or ["gat", "gcn", "graphsage"]
)

input_mode = st.sidebar.radio(
    "Choose Trace Source",
    ["Sample Fixture", "Upload JSON Trace"]
)

trace_data = None

if input_mode == "Sample Fixture":
    fixture_choice = st.selectbox(
        "Select Sample Artifact",
        ["benign_artifact.json", "suspicious_artifact.json", "ransomware_artifact.json"]
    )
    fixture_path = Path("ci_cd/fixtures") / fixture_choice
    if fixture_path.exists():
        with open(fixture_path, "r", encoding="utf-8") as f:
            trace_data = json.load(f)
    else:
        st.error(f"Could not find {fixture_path}")
else:
    uploaded_file = st.file_uploader("Upload API Call Trace (.json)", type=["json"])
    if uploaded_file is not None:
        trace_data = json.load(uploaded_file)

if trace_data is not None:
    with st.expander("Preview Trace Metadata"):
        st.json(trace_data.get("metadata", {}))

    if st.button("Run GNN Behavioral Scan", type="primary"):
        with st.spinner("Constructing API Call Graph & Running Inference..."):
            try:
                result, _ = inference_service.predict_trace(trace_data, model_name=model_type)
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Predicted Class", result.predicted_class.upper())
                col2.metric("Risk Score", f"{result.risk_score:.2f} / 100")
                col3.metric("Confidence", f"{result.confidence * 100:.1f}%")

                if result.risk_level.lower() == "high" or result.predicted_class.lower() == "ransomware":
                    st.error(f"🚨 BLOCK: High Ransomware Risk Detected ({result.risk_level})")
                elif result.risk_level.lower() == "medium":
                    st.warning(f"⚠️ WARN: Suspicious Behavior Detected ({result.risk_level})")
                else:
                    st.success(f"✅ PASS: Artifact Appears Safe ({result.risk_level})")

            except Exception as e:
                st.error(f"Inference failed: {e}")
