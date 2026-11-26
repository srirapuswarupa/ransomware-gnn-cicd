"""
Baseline Classifiers for Comparative Evaluation.
Implements Random Forest, Multilayer Perceptron (MLP), and Sequence-based models
to benchmark against GNN architectures under an identical train/test split.
"""
from typing import List, Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.data.schema import ApiTrace
from ml.graph.builder import GraphData

def extract_tabular_features(traces: List[ApiTrace]) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extracts fixed-length summary feature vectors for tabular baselines:
    - Category call distribution (9 dims)
    - Total calls
    - Duration (ms)
    - Sensitive API count (PASAC)
    - Sensitive API ratio
    - Unique API count
    - Max call frequency
    """
    X = []
    y = []
    from ml.preprocessing.sensitive_api import CATEGORY_LIST

    for trace in traces:
        cat_counts = {cat: 0 for cat in CATEGORY_LIST}
        sensitive_count = 0
        unique_apis = set()
        
        for ev in trace.events:
            if ev.category in cat_counts:
                cat_counts[ev.category] += 1
            if ev.is_sensitive:
                sensitive_count += 1
            unique_apis.add(ev.api_name)
            
        total = max(1, len(trace.events))
        cat_freqs = [cat_counts[cat] / total for cat in CATEGORY_LIST]
        
        feat = cat_freqs + [
            total,
            trace.metadata.duration_ms,
            sensitive_count,
            sensitive_count / total,
            len(unique_apis)
        ]
        X.append(feat)
        y.append(trace.metadata.label_id)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)

class TabularMLP(nn.Module):
    """Feedforward Multi-Layer Perceptron baseline on aggregated trace features."""
    def __init__(self, in_dim: int = 14, hidden_dim: int = 64, num_classes: int = 3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

class SequenceBiLSTM(nn.Module):
    """
    Sequence-based Deep Learning baseline inspired by Zhang et al. (2025) and RansoGuard.
    Models ordered API calls as a temporal sequence without graph topology.
    """
    def __init__(self, vocab_size: int = 70, emb_dim: int = 32, hidden_dim: int = 64, num_classes: int = 3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, padding_idx=0)
        self.lstm = nn.LSTM(emb_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [Batch, SeqLen]
        emb = self.embedding(x)
        out, (hn, cn) = self.lstm(emb)
        # hn: [2, Batch, hidden_dim] -> concat forward and backward
        feat = torch.cat([hn[0], hn[1]], dim=-1)
        return self.fc(feat)
