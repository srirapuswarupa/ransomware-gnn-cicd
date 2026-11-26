"""
Comprehensive Evaluation Metrics and Reporting.
Calculates Accuracy, Precision, Recall, F1, Confusion Matrix, FPR, FNR, ROC-AUC, and Latency.
"""
import time
from typing import Dict, List, Any, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, average_precision_score
)
import torch

def compute_detailed_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    latency_ms: float = 0.0,
    class_names: List[str] = ["Benign", "Suspicious", "Ransomware"]
) -> Dict[str, Any]:
    """
    Computes rigorous evaluation metrics strictly on empirical test/validation predictions.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    
    # Per-class FPR and FNR
    per_class_metrics = {}
    total_samples = len(y_true)

    for i, cname in enumerate(class_names):
        tp = cm[i, i]
        fn = np.sum(cm[i, :]) - tp
        fp = np.sum(cm[:, i]) - tp
        tn = total_samples - (tp + fp + fn)

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class_metrics[cname.lower()] = {
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
            "fnr": round(float(fnr), 4)
        }

    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    acc = accuracy_score(y_true, y_pred)

    roc_auc = None
    pr_auc = None
    if y_prob is not None:
        try:
            # Multi-class one-vs-rest
            roc_auc = float(roc_auc_score(y_true, y_prob, multi_class="ovr", average="macro"))
            pr_auc = float(average_precision_score(
                np.eye(len(class_names))[y_true], y_prob, average="macro"
            ))
        except Exception:
            roc_auc = None
            pr_auc = None

    return {
        "accuracy": round(float(acc), 4),
        "macro_precision": round(float(macro_prec), 4),
        "macro_recall": round(float(macro_rec), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "confusion_matrix": cm.tolist(),
        "per_class": per_class_metrics,
        "avg_inference_latency_ms": round(float(latency_ms), 2),
        "test_sample_count": total_samples
    }
