# Ransomware Behavior Detection and Classification via Graph Neural Network-Based Malware Behavior Modeling (API Call Graphs), Applied to Cloud-Hosted CI/CD Pipeline Supply Chain Security

**A Complete Working Final-Year B.Tech Major Project**

---

## 1. Executive Summary

This project delivers a defensive DevSecOps cyber-defense system that detects and halts ransomware supply-chain injections in cloud-hosted continuous integration and delivery (CI/CD) pipelines. By transforming dynamic Windows Win32 API call logs into directed, multi-relational attributed graphs, the system applies Graph Neural Networks (GAT, GCN, GraphSAGE) and Pre-Attack Sensitive API Call (PASAC) heuristics to intercept ransomware during pre-attack reconnaissance and defense evasion, well before destructive file encryption commences.

The system combines:
1. **Dynamic Multi-Relational API Call Graphs:** Models sequential execution, intra-thread continuity, and shared resource dependencies with 14-dimensional node feature vectors.
2. **Comparative GNN Architectures:** Evaluates Graph Attention Networks (GAT), Graph Convolutional Networks (GCN), GraphSAGE, and Random Forest baselines under an identical train/validation/test split.
3. **Pre-Attack Early Warning (PASAC):** Evaluates incremental trace prefixes (10% to 100%) to measure early detection lead time before encryption.
4. **Explainable AI (GNNExplainer):** Computes gradient-based node saliency scores, extracts critical subgraphs, and generates human-readable decision narratives.
5. **Cloud CI/CD Pipeline Screening Gate:** Enforces automated release policies (PASS / WARN / BLOCK) with tamper-evident audit logging for GitHub Actions and Jenkins.
6. **Full-Stack Web Dashboard:** Interactive React 19 + TypeScript + Vite + Tailwind CSS interface with canvas-rendered graph explorer and metrics visualization.

---

## 2. Research Papers & Literature Foundation

This project builds directly upon nine foundational research papers:

1. **GraphShield (Amer et al., 2026):** Dynamic API call graph representation; temporal graph modeling; GCN/GAT/GIN architectures; GNNExplainer interpretability. *(Note: GraphShield's reported ~99.5% F1 is from its own dataset).*
2. **RansoGuard (Cen et al., 2025):** Pre-Attack Sensitive API Calls (PASAC) concept and sequence-based early detection before destructive activity.
3. **STRIDE CI/CD Threat Modeling (Dhandapani, 2025):** Threat modeling across CI/CD pipelines (GitHub, Jenkins, Docker, Kubernetes) and policy gating frameworks.
4. **Malware Detection with Graph Representation Learning Survey (Bilot et al., 2024):** Taxonomy of CFG, system-call, and entity graphs; GNN architectural trade-offs.
5. **Adaptive GNN Ransomware Detection (Li et al., 2024):** ADC-TextGCN on token co-occurrence graphs with adaptive neighborhood diffusion.
6. **Deep Learning API Sequence Extraction (Zhang et al., 2025):** Grayscale API sequence image transformation with CNN and Bi-LSTM deep learning.
7. **Virtualized Environment API Call Graphs (Lin et al., 2025):** Directed API call graph construction, Word2Vec embeddings, thread tracking, and GAT superiority.
8. **Graph Variational Autoencoders for API Graphs (Gunduz, 2022):** Android caller-callee graphs, Node2Vec, and GVAE graph embeddings.
9. **Graph-Contrast Ransomware Detection - GCRD (Satpathy & Swain, 2025):** Graph-based feature selection and contrastive learning on static PE attributes.

---

## 3. The Evidence-Based Research Gap Addressed

While existing literature investigates dynamic graph modeling, sequential sensitive APIs, and CI/CD threat modeling independently, **prior work does not demonstrate a single unified system integrating:**
- Runtime multi-relational API call graphs,
- GAT multi-head attention graph classification with dual global pooling,
- Pre-Attack Sensitive API Call (PASAC) prefix analysis with measurable early lead time,
- GNNExplainer gradient saliency for explainable security decisions, and
- Automated DevSecOps CI/CD release gating (PASS / WARN / BLOCK) with tamper-evident audit logs.

---

## 4. Empirical Evaluation Results (Our Test Split, $n=36$)

Trained on 240 structured behavioral traces (100 Benign, 40 Suspicious, 100 Ransomware across 14 realistic families) partitioned into a 70% Train, 15% Validation, and 15% Held-Out Test split:

| Model Architecture | Test Accuracy | Macro Precision | Macro Recall | Macro F1-Score | ROC-AUC | Avg Latency | Model Size |
|--------------------|---------------|-----------------|--------------|----------------|---------|-------------|------------|
| **GAT (Proposed)** | **100.0%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **2.84 ms** | **81.2 KB** |
| GCN | 100.0% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 2.15 ms | 79.1 KB |
| GraphSAGE | 100.0% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 2.42 ms | 112.6 KB |
| Random Forest (Baseline) | 100.0% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.82 ms | 150.0 KB |

### Early Warning Lead Time:
- **Alert Trigger Point:** 10% of execution.
- **Lead Time:** 27.65 ms before the first destructive mass file encryption (`MoveFileEx` / `.locked`).

---

## 5. Repository Structure

```
ransomware-gnn-cicd/
├── backend/
│   ├── app/
│   │   ├── api/             # REST endpoints (health, traces, inference, graphs, models, cicd, reports)
│   │   ├── core/            # Configuration and settings
│   │   ├── database/        # SQLAlchemy models (SampleRecord, ScanRunRecord, AuditLogRecord)
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # GNN inference, early warning, explainability, CI/CD scanner, reports
│   │   └── main.py          # FastAPI application entrypoint (serves API & static frontend)
│   └── tests/
│       └── run_all_tests.py # Comprehensive 9-test verification suite
├── ml/
│   ├── data/                # Schema, synthetic generator, loader, splitting
│   ├── preprocessing/       # Normalizer, PII sanitizer, PASAC taxonomy
│   ├── graph/               # GraphBuilder, feature encoding, Cytoscape elements
│   ├── models/              # Pure PyTorch GAT, GCN, GraphSAGE, and baselines
│   ├── training/            # Batched trainer, early stopping, evaluation metrics
│   ├── explainability/      # GNNExplainer gradient saliency and subgraphs
│   └── experiments/         # Saved model checkpoints (.pt) and metrics JSON
├── datasets/
│   ├── metadata.json        # Dataset catalog and licensing
│   └── synthetic/           # 240 structured JSON traces
├── ci_cd/
│   ├── github_actions/      # GitHub Actions CI workflow (workflow.yml)
│   ├── jenkins/             # Jenkins declarative pipeline (Jenkinsfile)
│   ├── policies/            # Configurable release gate rules (policy_rules.json)
│   ├── fixtures/            # Benign, suspicious, and ransomware test artifacts
│   └── runner.py            # Standalone CI/CD screening CLI runner
├── frontend/                # React 19 + TypeScript + Vite + Tailwind CSS dashboard
├── docs/                    # Full B.Tech Thesis, literature matrix, diagrams, viva Q&A
├── docker/                  # Dockerfiles for backend and frontend
├── docker-compose.yml       # Container composition
└── requirements.txt         # Pinned Python dependencies
```

---

## 6. Quick Start & Execution Commands

### A. Environment Setup
```powershell
# In project root:
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
```

### B. Run the Full-Stack Application
FastAPI serves both the backend API and the compiled React frontend simultaneously:

```powershell
Set-Location "C:\Users\srira\.gemini\antigravity\scratch\ransomware-gnn-cicd"
$env:PYTHONPATH = "C:\Users\srira\.gemini\antigravity\scratch\ransomware-gnn-cicd"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Web Dashboard:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### C. Run the Comprehensive Automated Test Suite
```powershell
.\.venv\Scripts\python.exe -u backend\tests\run_all_tests.py
```
*(Runs 9/9 unit, integration, and security verification tests).*

### D. Test the CI/CD Pipeline Security Gate via CLI
```powershell
# Screen Benign Build Artifact (Expected: PASS, exit code 0)
.\.venv\Scripts\python.exe -u ci_cd\runner.py --artifact "production_build_v1.0.exe" --fixture benign

# Screen Malicious Ransomware Artifact (Expected: BLOCK, exit code 1)
.\.venv\Scripts\python.exe -u ci_cd\runner.py --artifact "compromised_lib.dll" --fixture ransomware
```

---

## 7. Safety & Ethical Compliance

This defensive cybersecurity project adheres strictly to ethical guidelines:
- **No live ransomware** is compiled, downloaded, executed, or detonated on the development machine.
- All evaluation traces are generated by a **dynamic simulation engine** grounded in real ransomware kill-chains (LockBit, WannaCry, Conti) and explicitly labeled `is_synthetic: true`.
- No user files are ever damaged, locked, or deleted.

---

## 8. Academic Citation

If utilizing this codebase or methodology in academic research, please cite:
```bibtex
@btechthesis{antigravity2026ransomwareGNN,
  title={Ransomware Behavior Detection and Classification via Graph Neural Network-Based Malware Behavior Modeling (API Call Graphs), Applied to Cloud-Hosted CI/CD Pipeline Supply Chain Security},
  author={Antigravity Autonomous Engineering Team},
  year={2026},
  school={Department of Computer Science and Engineering}
}
```
