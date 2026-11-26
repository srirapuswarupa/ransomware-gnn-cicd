# STRIDE-Based CI/CD Software Supply Chain Threat Model

**Theoretical Foundation:** Sowmiya Dhandapani (2025), *"Enhancing Software Supply Chain Security Through STRIDE-Based Threat Modelling of CI/CD Pipelines."*

---

## 1. Executive Summary

Modern software supply chains rely on continuous integration and continuous delivery (CI/CD) pipelines to compile, package, and deploy software artifacts automatically. However, attackers increasingly target these automated build systems to inject malicious payloads—such as ransomware and backdoors—into trusted distribution channels.

This threat model applies the **STRIDE methodology** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to identify supply chain threat vectors and demonstrates how our **Graph Neural Network (GNN) Behavioral Screening Gate** mitigates these vulnerabilities.

---

## 2. Supply Chain Architecture Decomposition

The typical CI/CD pipeline consists of five critical operational stages:

1. **Source SCM Stage:** Developer commit and repository pull request.
2. **Build & Compilation Stage:** Execution of compilers, scripts, and build runners.
3. **Dependency Resolution Stage:** Third-party package fetching (npm, PyPI, Maven).
4. **Artifact Repository Stage:** Storage of built binaries, container images, and packages.
5. **Deployment & Release Stage:** Automated rollout to production or customer distribution.

---

## 3. STRIDE Threat Analysis Matrix

| STRIDE Category | Threat Description in CI/CD Pipeline | Real-World Attack Scenario | Impact Severity | GNN Behavioral Mitigation Strategy |
|-----------------|--------------------------------------|----------------------------|-----------------|-----------------------------------|
| **Spoofing** | Attacker impersonates an authorized developer or automated CI service account to submit untrusted code. | Stolen personal access token (PAT) used to commit a malicious build script. | **CRITICAL** | Artifact behavioral trace screening verifies actual runtime API invocation graph regardless of commit metadata or spoofed credentials. |
| **Tampering** | Malicious injection or modification of build binaries during compilation or packaging (Trojanized dependency). | Supply chain attack where a benign-looking dependency triggers a malicious PowerShell/Windows API payload during the build step. | **CRITICAL** | GAT multi-head attention detects anomalous process injection (`VirtualAllocEx`, `WriteProcessMemory`) and shadow copy tampering (`vssadmin`). |
| **Repudiation** | An insider or attacker modifies a build artifact or policy configuration without leaving an immutable audit trail. | Build engineer claims an artifact was approved when it contained malicious ransomware code. | **HIGH** | Tamper-evident SQLite/PostgreSQL audit logging records every scan decision, risk score, and policy violation timestamped in real time. |
| **Information Disclosure** | Leakage of API keys, code signing certificates, or cloud infrastructure credentials during pipeline execution. | Ransomware component connects to an external C2 server to exfiltrate master keys (`WSAStartup`, `connect`, `send`). | **HIGH** | Network C2 APIs combined with cryptographic key export (`CryptExportKey`) trigger an immediate risk spike and pipeline BLOCK decision. |
| **Denial of Service (DoS)** | Ransomware payload encrypts files or destroys volume shadow copies on shared CI/CD build runners or target servers. | Malicious artifact executes `vssadmin.exe delete shadows /all /quiet` and `bcdedit` to inhibit disaster recovery. | **CRITICAL** | Explicit heuristic policy rules (RULE-SEC-02) flag recovery inhibition commands and halt pipeline execution before deployment. |
| **Elevation of Privilege** | An unprivileged build step exploits kernel or API vulnerabilities to escape container sandboxes or gain SYSTEM privileges. | Build script executes token privilege adjustment (`AdjustTokenPrivileges`) and injects threads into elevated processes. | **CRITICAL** | PASAC sensitive API modeling flags process manipulation sequences and early warning trajectory detects threats at 10% of execution. |

---

## 4. Policy Gate Enforcement Logic

Our automated CI/CD security gate implements a multi-tiered decision matrix based on GNN behavioral risk scoring:

```
+-----------------------------------------------------------------------------------+
|                            GNN BEHAVIORAL RISK SCORE                              |
|                                                                                   |
|  [ 0.0 ------------- 39.0 ]        [ 40.0 ------------- 69.0 ]        [ 70.0 --- 100.0 ]
|          PASS GATE                         WARN GATE                     BLOCK GATE      |
|  * Artifact verified safe         * Suspicious patterns detected       * Critical ransomware |
|  * Standard build flow            * Deployment halted for review       * Immediate exit(1)   |
|  * Audit logged                   * SecOps sign-off required           * Build failed        |
+-----------------------------------------------------------------------------------+
```

### Policy Rules Implemented:
1. **RULE-SEC-01 (Risk Threshold):** If $\text{RiskScore} \ge 70.0$, release is **BLOCKED** immediately.
2. **RULE-SEC-02 (Defense Evasion):** Any trace invoking shadow copy deletion (`vssadmin delete shadows`) or boot recovery disabling (`bcdedit /set recoveryenabled No`) is **BLOCKED** regardless of confidence.
3. **RULE-SEC-03 (Process Injection):** Inter-process memory writing (`VirtualAllocEx`, `WriteProcessMemory`) without legitimate compiler justification triggers **WARN** or **BLOCK**.
4. **RULE-SEC-04 (Low Risk Clearance):** Traces demonstrating standard library loading, configuration reading, and normal runtime termination are marked **PASS**.

---

## 5. Summary Conclusion

By integrating the GNN Behavioral Screening Gate into the deployment phase of the software supply chain, organizations can enforce zero-trust artifact verification. Even if an attacker successfully compromises upstream credentials or injects obfuscated source code, the artifact's dynamic API call graph reveals malicious behavioral intent prior to release.
