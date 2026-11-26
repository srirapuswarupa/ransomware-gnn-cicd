# Comprehensive Literature Review Matrix (The Nine Foundational Papers)

This matrix compares the nine foundational research papers that form the academic and architectural baseline of our project. All metrics and findings reported below are attributed strictly to the respective papers and their own experimental evaluations.

| # | Paper Title | Authors | Year | Representation & Methodology | Primary Architecture | Reported Performance (Paper's Dataset) | Identified Limitations / Distinctions | Contribution to Proposed Project |
|---|-------------|---------|------|------------------------------|----------------------|-----------------------------------------|---------------------------------------|-----------------------------------|
| **1** | **GraphShield: Advanced Dynamic Graph-Based Malware Detection Using Graph Neural Networks** | Eslam Amer, Shaker El-Sappagh, Tamer Abuhamad, Bander Ali Saleh Al-Rimy, Alaa Mohasseb | 2026 | Dynamic API call graph representation; temporal graph modeling; BERT-based semantic grouping; graph stabilization | GCN, GAT, GIN, Hybrid GNN, GNNExplainer | F1-Score ~99.5%, FPR < 1.0% | Evaluated on private dynamic execution dataset; not integrated with CI/CD pipelines | Provided core foundation for dynamic directed API call graph modeling, multi-relational edges, and GNNExplainer attribution. |
| **2** | **RansoGuard: A RNN-Based Framework Leveraging Pre-Attack Sensitive APIs for Early Ransomware Detection** | Mingcan Cen, Frank Jiang, Robin Doss | 2025 | Pre-Attack Sensitive API Calls (PASAC); Bag-of-Words, Order-of-Words, Sequence-of-Words | Recurrent Neural Networks (RNN) / LSTM | Demonstrated early detection prior to file encryption | Sequential approach; does not model complex structural caller-callee topologies or shared resource dependencies | Provided the PASAC (Pre-Attack Sensitive API Calls) concept and early-warning lead-time prefix evaluation method. |
| **3** | **Enhancing Software Supply Chain Security Through STRIDE-Based Threat Modelling of CI/CD Pipelines** | Sowmiya Dhandapani | 2025 | STRIDE threat modeling across GitHub, Jenkins, Docker, Kubernetes; SLSA, NIST SSDF, OWASP CI/CD Top 10 | Security Policy Gating, OPA, Sigstore, Trivy | Qualitative threat mitigation framework | Threat-modeling and architectural paper; does not implement machine learning or graph ransomware detection | Provided the supply-chain threat taxonomy, CI/CD pipeline stage definitions, and automated policy release gating design. |
| **4** | **A Survey on Malware Detection with Graph Representation Learning** | Tristan Bilot, Nour El Madhoun, Khaldoun Al Agha, Anis Zouaoui | 2024 | Survey of CFG, FCG, PDG, system-call graphs, and system entity graphs; taxonomy of graph neural networks | GCN, GAT, GraphSAGE, GIN, Relational GNNs | Comprehensive review of public datasets (CICAndMal2017, CICMalDroid, MalNet) | Survey paper summarizing existing work; did not execute a single end-to-end cloud pipeline | Guided the architectural justification for comparing GAT, GCN, and GraphSAGE backbones with dual pooling. |
| **5** | **Ransomware Detection Model Based on Adaptive Graph Neural Network Learning** | Jun Li, Gengyu Yang, Yanhua Shao | 2024 | Heterogeneous text/token co-occurrence graph; TF-IDF and COIR-PMI; Adaptive Diffusion Convolution | ADC-TextGCN | Reported Accuracy: 96.6% | Graph is constructed from static text/token co-occurrence, not dynamic execution API call sequences | Supplied comparative concepts for neighborhood feature diffusion and sensitive token weighting. |
| **6** | **A Malware-Detection Method Using Deep Learning to Fully Extract API Sequence Features** | Shuhui Zhang, Mingyu Gao, Lianhai Wang, Shujiang Xu, Wei Shao, Ruixue Kuang | 2025 | Grayscale API sequence image transformation; fusion of visual and semantic API features | CNN, TextCNN, Bi-LSTM | Reported Accuracy ~99.0% on experimental benchmarks | Pure sequential and image-based deep learning; does not construct explicit topological graphs | Served as a sequence-based baseline comparison point for API sequence representation. |
| **7** | **Malware Detection in Virtualized Environments Through API Call Graph Analysis** | Nan Lin, Lijin Wu, Yuxin Liu, Lihong Xu, Xusheng Lin, Zhiqin Lin, Gang Liang | 2025 | Directed API call graph construction in virtualized sandboxes; Word2Vec API embeddings; thread tracking | GCN, GAT, GraphSAGE | Reported GAT Accuracy: 97.12%, F1: 96.87% | Focused on virtualization sandboxing; did not address supply chain CI/CD gating or partial trace early warning | Validated GAT superiority over standard GCN on directed runtime API call graphs. |
| **8** | **Malware Detection Framework Based on Graph Variational Autoencoder Extracted Embeddings from API-Call Graphs** | Hakan Gunduz | 2022 | Android API caller-callee graphs using Androguard; Node2Vec; Graph Variational Autoencoder (GVAE) | GVAE + Feature Selection (RFE, Fisher) + LightGBM/SVM | Reported Accuracy up to 96.7% | Focused strictly on Android APK bytecode caller-callee graphs; cannot be directly applied to Windows user-mode ransomware | Grounded the graph representation learning methodology and unsupervised embedding principles. |
| **9** | **Graph-Contrast Ransomware Detection (GCRD) with Advanced Feature Selection and Deep Learning** | Suneeta Satpathy, Pratik Kumar Swain | 2025 | Static PE file feature graphs; graph-based feature selection; contrastive learning | FT-Transformer + MLP | Reported Accuracy: 99.1%, Precision: 98.9%, Recall: 99.3%, FPR: 1.5% | Static PE header and section analysis; blind to runtime evasive behaviors, fileless ransomware, and dynamic API chains | Provided contrastive feature weighting insights and highlighted the necessity of dynamic behavioral analysis. |

---

## The Evidence-Based Research Gap Identified

While the 9 foundational papers individually advance specific aspects of malware analysis:
1. Dynamic API graph representation (Amer et al., Lin et al.)
2. Pre-attack sensitive API early detection (Cen et al.)
3. Supply-chain CI/CD threat modeling (Dhandapani)
4. Static feature contrastive learning (Satpathy & Swain)
5. Graph representation learning taxonomy (Bilot et al.)

**None of the reviewed papers implements a unified, end-to-end framework integrating:**
- Runtime multi-relational API call graphs (temporal, thread-continuity, and resource-dependency edges),
- Graph Attention Networks (GAT) with dual global pooling,
- Pre-Attack Sensitive API Call (PASAC) prefix analysis with measurable early detection lead time,
- GNNExplainer gradient saliency for explainable security decisions, and
- Automated, policy-driven DevSecOps CI/CD release gating (PASS / WARN / BLOCK) with tamper-evident audit logs.

This project directly investigates and demonstrates this synthesized architecture.
