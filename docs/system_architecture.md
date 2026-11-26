# System Architecture and Design Diagrams

## 1. High-Level Logical System Architecture

```mermaid
flowchart TD
    subgraph Layer1["Layer 1: Data Ingestion & Import"]
        A1["Raw Trace Upload (JSON/CSV)"]
        A2["Synthetic Kill-Chain Generator"]
        A3["Pre-Packaged CI/CD Fixtures"]
    end

    subgraph Layer2["Layer 2: Preprocessing & PASAC Categorization"]
        B1["API Normalizer & Canonicalizer"]
        B2["PII / Path Sanitizer"]
        B3["PASAC Sensitive API Tagger (8 Categories)"]
    end

    subgraph Layer3["Layer 3: Multi-Relational Graph Construction"]
        C1["Sequential Temporal Edges (i -> i+1)"]
        C2["Intra-Thread Continuity Edges"]
        C3["Shared Resource Dependency Edges"]
        C4["14-Dimensional Attributed Node Feature Matrix"]
    end

    subgraph Layer4["Layer 4: GNN Detection & Behavioral Modeling"]
        D1["Graph Attention Network (GAT)"]
        D2["Graph Convolutional Network (GCN)"]
        D3["GraphSAGE"]
        D4["Dual Global Pooling (Mean + Max)"]
        D5["Multi-Class Softmax Classifier"]
    end

    subgraph Layer5["Layer 5: Behavioral Intelligence & Early Warning"]
        E1["Multi-Factor Security Risk Score (0 - 100)"]
        E2["Prefix Trajectory Analysis (PASAC Lead Time)"]
        E3["GNNExplainer Gradient Saliency & Critical Subgraphs"]
    end

    subgraph Layer6["Layer 6: Cloud CI/CD Supply Chain Integration"]
        F1["Automated Release Policy Gate"]
        F2["Decision Matrix (PASS / WARN / BLOCK)"]
        F3["Immutable Audit Log & Tamper-Evident Store"]
    end

    subgraph Layer7["Layer 7: Full-Stack Web Dashboard & API"]
        G1["FastAPI REST Engine"]
        G2["Interactive Graph Canvas Explorer"]
        G3["Model Performance & Confusion Matrix View"]
        G4["Automated Markdown/JSON Audit Reports"]
    end

    Layer1 --> Layer2
    Layer2 --> Layer3
    Layer3 --> Layer4
    Layer4 --> Layer5
    Layer5 --> Layer6
    Layer6 --> Layer7
    Layer5 --> Layer7
```

---

## 2. Data Flow Diagram (DFD Level 0 & Level 1)

### Level 0 Context Diagram

```mermaid
flowchart LR
    Dev["Developer / CI Pipeline"] -->|"Submits Build Artifact / API Trace"| System["Ransomware GNN Behavioral Screening System"]
    System -->|"Returns Release Decision (PASS/WARN/BLOCK), Risk Score, Audit Trail"| Dev
    SecOps["SecOps Analyst"] -->|"Inspects Subgraphs, Explanations & Model Metrics"| System
```

### Level 1 Detailed DFD

```mermaid
flowchart TD
    P1["1.0 Parse & Sanitize Trace"]
    P2["2.0 Construct Directed Graph & Embed Features"]
    P3["3.0 GNN Message Passing & Inference"]
    P4["4.0 Compute Early Warning & Lead Time"]
    P5["5.0 Extract GNNExplainer Critical Subgraphs"]
    P6["6.0 Evaluate Security Policy & Gate Release"]

    Store1[("Database: Samples & Traces")]
    Store2[("Model Checkpoints & Weights")]
    Store3[("Database: Scan Runs & Audit Logs")]

    InTrace["API Call Trace"] --> P1
    P1 --> Store1
    P1 --> P2
    P2 --> P3
    Store2 -.->|"Load Checkpoint"| P3
    P3 --> P4
    P3 --> P5
    P3 --> P6
    P4 --> P6
    P6 --> Store3
    P6 --> OutDecision["CI/CD Gate Decision (PASS/WARN/BLOCK)"]
```

---

## 3. Use-Case Diagram

```mermaid
flowchart TD
    subgraph Actors
        DevAgent["CI/CD Pipeline Runner"]
        SecurityAdmin["Security Engineer / SecOps"]
        Researcher["B.Tech Project Reviewer / Guide"]
    end

    subgraph UseCases["System Use Cases"]
        UC1["Upload / Import API Call Traces"]
        UC2["Trigger Automated CI/CD Artifact Screening"]
        UC3["Inspect Multi-Relational API Call Graphs"]
        UC4["Analyze Early Ransomware Warning Trajectory"]
        UC5["View GNN Saliency Subgraph Explanations"]
        UC6["Compare GNN Architectures (GAT vs GCN vs GraphSAGE)"]
        UC7["Enforce Release Gate Policy (PASS/WARN/BLOCK)"]
        UC8["Export Security Audit & Viva Defense Reports"]
    end

    DevAgent --> UC2
    SecurityAdmin --> UC1
    SecurityAdmin --> UC3
    SecurityAdmin --> UC4
    SecurityAdmin --> UC5
    SecurityAdmin --> UC7
    Researcher --> UC6
    Researcher --> UC8
```

---

## 4. Sequence Diagram: CI/CD Security Screening Workflow

```mermaid
sequenceDiagram
    autonumber
    actor CI as CI/CD Runner / Git Hook
    participant API as FastAPI Gateway
    participant Norm as Normalizer & Preprocessor
    participant Graph as Graph Builder
    participant GNN as GAT Inference Engine
    participant Early as Early Warning Service
    participant Policy as Policy Gate Engine
    participant DB as SQLite / Audit Store

    CI->>API: POST /api/cicd/scan (Artifact + Trace)
    API->>Norm: normalize_trace(raw_data)
    Norm-->>API: Clean ApiTrace Object
    API->>Graph: build(ApiTrace)
    Graph-->>API: Attributed GraphData (X, Edge_Index, Attr)
    API->>GNN: predict_trace(GraphData)
    GNN-->>API: Class Probs + Risk Score
    API->>Early: analyze_prefix_trajectory(Trace)
    Early-->>API: Pre-Attack Lead Time & Cutoff %
    API->>Policy: evaluate_rules(Risk Score, Violations)
    Policy-->>API: Policy Decision (PASS / WARN / BLOCK)
    API->>DB: Record ScanRunRecord + AuditLogRecord
    DB-->>API: Confirmed (Audit ID #)
    API-->>CI: CicdScanResponse (Status Code, Decision, Logs)
    alt Decision == BLOCK
        CI->>CI: Terminate Build (Exit Code 1)
    else Decision == PASS
        CI->>CI: Proceed to Deployment (Exit Code 0)
    end
```

---

## 5. Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    SAMPLES {
        int id PK
        string sample_id UK
        string sha256
        string label
        string predicted_label
        float confidence
        float risk_score
        string risk_level
        string model_used
        int total_calls
        float duration_ms
        boolean is_synthetic
        datetime created_at
    }

    SCAN_RUNS {
        int id PK
        string run_id UK
        string artifact_name
        string pipeline_stage
        string policy_decision
        float risk_score
        string details_json
        string author
        datetime created_at
    }

    AUDIT_LOGS {
        int id PK
        string action
        string actor
        string details
        datetime created_at
    }

    SCAN_RUNS ||--o{ AUDIT_LOGS : "triggers"
    SAMPLES ||--o{ SCAN_RUNS : "screens"
```

---

## 6. Model Training and Evaluation Pipeline

```mermaid
flowchart LR
    D1["Corpus: 240 Structured Traces"] --> S1["Stratified Split: 70% Train / 15% Val / 15% Test"]
    S1 --> G1["GraphBuilder: Build Disjoint Batched Graphs"]
    G1 --> T1["Batched Forward Pass (X, Edge_Index, Batch)"]
    T1 --> L1["CrossEntropy Loss + L2 Regularization"]
    L1 --> B1["Backpropagation & AdamW Optimizer"]
    B1 --> V1["Validation Epoch Evaluation (Early Stopping)"]
    V1 --> C1["Save Best Checkpoint (.pt)"]
    C1 --> E1["Held-Out Test Evaluation"]
    E1 --> M1["Compute Confusion Matrix, Precision, Recall, F1, ROC-AUC, Latency"]
```
