# Major Project Viva Preparation: Technical Questions and Answers

## 1. Domain & Theoretical Foundations

### Q1: What is the primary problem addressed by this project?
**A:** This project addresses the threat of ransomware and malicious code infiltrating cloud-hosted CI/CD software supply chains. Traditional static analysis (e.g., hash lookups, static signature scanners) fails against polymorphic, obfuscated, or fileless ransomware. Our system constructs dynamic API call graphs from runtime behavior and applies Graph Neural Networks (GNNs) with Pre-Attack Sensitive API Call (PASAC) modeling to intercept ransomware before destructive file encryption occurs, enforcing automated release gating in CI/CD pipelines.

### Q2: Why use Graph Neural Networks instead of traditional Recurrent Neural Networks (like RansoGuard) or CNNs (like Zhang et al.)?
**A:** 
- **Sequential models (RNN/LSTM)** assume a strictly linear, one-dimensional execution stream. However, real modern Windows software is multi-threaded and asynchronous. Calls from different threads interleave arbitrarily in execution logs.
- **Graph representations** explicitly decouple temporal concurrency from intra-thread continuity and shared-resource dependencies. By constructing directed edges for:
  1. Chronological execution ($e_t \to e_{t+1}$),
  2. Intra-thread continuity ($e_{\text{prev}} \to e_{\text{curr}}$ within same TID), and
  3. Shared-resource interaction (calls referencing the same file, registry key, or socket),
  GNNs capture topological caller-callee and data-dependency structures that sequential models flatten or miss.

---

## 2. Graph Construction & Feature Engineering

### Q3: How are the nodes and edges defined in your API call graph?
**A:**
- **Nodes ($V$):** Each node represents an API call event in the execution trace.
- **Node Feature Vector ($X \in \mathbb{R}^{14}$):**
  1. Normalized API Vocabulary Index (mapped across 65+ Windows APIs).
  2. Category One-Hot Encoding (9 dimensions: File_IO, File_Enumeration, Cryptography, Process_Memory, Registry_Service, Defense_Evasion, Network_C2, System_Discovery, System_Util).
  3. Normalized Call Frequency in Trace ($f_i / N$).
  4. Normalized Timestamp in Trace ($t_i / t_{\max}$).
  5. Pre-Attack Sensitive API (PASAC) Flag (binary $0$ or $1$).
  6. Thread ID Representation ($TID \pmod{10} / 10$).
- **Edges ($E$):** Directed multi-relational edges with edge attributes $[ \Delta t_{\text{norm}}, \text{type} ]$:
  - Type 0: Immediate temporal succession.
  - Type 1: Intra-thread continuity.
  - Type 2: Shared resource / target handle dependency.

### Q4: What is the PASAC concept from RansoGuard and how is it used here?
**A:** PASAC stands for **Pre-Attack Sensitive API Calls** (introduced by Cen et al., 2025). Ransomware execution exhibits distinct phases: reconnaissance, privilege escalation, defense evasion (e.g., deleting shadow copies), key exchange, and finally mass file encryption. APIs invoked *prior* to mass encryption (e.g., `IsDebuggerPresent`, `vssadmin delete shadows`, `CryptAcquireContext`, `FindFirstFile`) are tagged as PASACs. This allows the model to compute early warning indicators before destructive payload actions occur.

---

## 3. GNN Architecture & Message Passing

### Q5: Explain the difference between GCN, GAT, and GraphSAGE as implemented in your system.
**A:**
1. **GCN (Graph Convolutional Network):** Uses fixed, symmetric degree-normalized adjacency weights $\tilde{D}^{-1/2} \tilde{A} \tilde{D}^{-1/2}$. All neighbors are aggregated uniformly based solely on graph degree.
2. **GAT (Graph Attention Network):** Implements parameterized self-attention coefficients $\alpha_{ij} = \mathrm{softmax}_j(\mathrm{LeakyReLU}(a^T [W h_i \,\|\, W h_j]))$. This allows the model to learn which neighbor calls are critical (e.g., heavily weighting the transition from `vssadmin` to `CryptEncrypt` while down-weighting standard utility calls).
3. **GraphSAGE:** Samples neighbor representations and applies inductive mean aggregation combined with a self-node transformation: $\sigma(W_{\text{self}} h_v + W_{\text{neigh}} \mathrm{Mean}(h_{N(v)}))$.

### Q6: Why did you use dual global pooling (Mean + Max) instead of single pooling?
**A:** 
- **Global Mean Pooling** captures the broad, overall distribution and proportion of benign utility calls across the execution graph.
- **Global Max Pooling** captures the sharpest, most extreme feature activations (such as sudden bursts of cryptographic transformations or privilege escalations), regardless of graph size. Combining both $[h_{\text{mean}} \,\|\, h_{\text{max}}]$ provides the classifier with both macro-context and micro-anomaly signals.

---

## 4. Model Training & Evaluation Rigor

### Q7: How did you prevent data leakage during training and evaluation?
**A:**
1. **Strict Stratified Split:** Data is partitioned into Train (70%), Validation (15%), and Test (15%) before any model training or hyperparameter tuning.
2. **Independent Test Set:** The test split is held out entirely until final checkpoint evaluation; metrics are calculated exclusively on unseen samples.
3. **Feature Transformations:** All feature normalizations (e.g. min-max bounds and vocabulary mappings) are deterministic and defined strictly by the feature schema without leaking test distribution statistics.

### Q8: What empirical results did your implementation obtain?
**A:** On our held-out test split of 36 structured samples, GAT, GCN, and GraphSAGE all achieved:
- Test Accuracy: 100.0%
- Macro F1-Score: 1.0000
- ROC-AUC: 1.0000
- Average Inference Latency: 2.84 ms per sample
- Model Checkpoint Size: ~81 KB

*Crucial Academic Note for Viva:* These results reflect empirical performance on our structured research benchmark of 240 samples. They must be distinguished from the historical metrics reported in the foundational papers (e.g., GraphShield's 99.5% on their private dataset, or Gunduz's 96.7% on Android APKs).

---

## 5. Early Warning & Explainability

### Q9: How is the early detection lead time quantified in this project?
**A:** The system evaluates partial-trace prefixes at 10%, 25%, 40%, 55%, 70%, 85%, and 100% of execution. The earliest point where the risk score exceeds the alert threshold (65.0) is recorded as the trigger point. **Lead time** is calculated as the time difference (in milliseconds) and event difference (in API call counts) between this trigger point and the first destructive action (e.g., the first `MoveFileEx` / `.locked` file modification or ransom note creation). In our demonstration ransomware traces, alerts triggered at 10% of the trace with over 27 ms of lead time before mass encryption began.

### Q10: How does your GNNExplainer implementation work?
**A:** The explainer computes the gradient of the predicted class target logit with respect to the node feature inputs: $S_i = \|\nabla_{x_i} \hat{y}_{\text{pred}}\|_2 \times \|x_i\|_2$. Nodes with the highest saliency norm are identified as influential drivers of the prediction. The system extracts the critical subgraph formed by these top nodes and generates a human-interpretable narrative detailing the functional categories and API functions responsible for the classification.

---

## 6. Cloud CI/CD Supply Chain Security

### Q11: How does this system integrate into an enterprise CI/CD pipeline?
**A:** We provide a standalone CLI runner (`ci_cd/runner.py`) and FastAPI endpoints (`/api/cicd/scan`) that execute during the pre-deployment security gate of GitHub Actions or Jenkins. When an artifact is screened:
1. Its dynamic behavior trace is ingested and converted to a graph.
2. The GNN model predicts behavioral class and calculates a security risk score (0 to 100).
3. The policy engine evaluates organizational thresholds:
   - Risk < 39: **PASS** (Exit code 0, deployment proceeds).
   - Risk 40-69: **WARN** (Exit code 0, flag for SecOps review).
   - Risk $\ge$ 70 or shadow copy deletion: **BLOCK** (Exit code 1, build halts immediately).
4. An immutable audit record is stored in the database.

### Q12: What are the primary limitations of the current implementation?
**A:**
1. **Synthetic Behavioral Data:** All traces are generated by a dynamic simulation engine following real-world kill-chains. No real destructive malware was executed on the host, complying with safety and ethical guidelines.
2. **User-Mode API Scope:** The current schema models Windows Win32 user-mode APIs; it does not capture kernel driver hooks (ETW/Sysmon kernel events) or network PCAP traffic.
3. **Platform Scope:** Focus is primarily Windows x64; Android and Linux formats are supported architecturally but not yet populated in the primary corpus.
