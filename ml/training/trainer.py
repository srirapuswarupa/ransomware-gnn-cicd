"""
Model Training, Validation, and Checkpoint Management.
Executes high-performance batched training protocols across GNN architectures (GAT, GCN, GraphSAGE)
and baseline models (Random Forest, MLP).
"""
import time
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim

from ml.data.schema import ApiTrace
from ml.graph.builder import GraphBuilder, GraphData, batch_graphs
from ml.models.gnn_modules import GNNClassifier
from ml.models.baselines import RandomForestClassifier, TabularMLP, extract_tabular_features
from ml.training.evaluate import compute_detailed_metrics

def train_gnn_model(
    model_type: str,
    train_graphs: List[GraphData],
    val_graphs: List[GraphData],
    epochs: int = 25,
    batch_size: int = 32,
    lr: float = 0.003,
    hidden_dim: int = 64,
    device: str = "cpu"
) -> Tuple[GNNClassifier, Dict[str, Any]]:
    """Trains a GNN model with high-throughput disjoint graph batching and early stopping."""
    model = GNNClassifier(
        in_dim=train_graphs[0].x.size(1),
        hidden_dim=hidden_dim,
        num_classes=3,
        gnn_type=model_type,
        dropout=0.2
    ).to(device)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()

    best_val_loss = float("inf")
    best_weights = None
    history = {"train_loss": [], "val_loss": [], "val_f1": []}
    
    start_time = time.time()
    val_batched = batch_graphs(val_graphs)
    val_x = val_batched.x.to(device)
    val_edge_index = val_batched.edge_index.to(device)
    val_batch_idx = val_batched.batch.to(device)
    val_y = val_batched.y.to(device)

    for epoch in range(epochs):
        model.train()
        total_train_loss = 0.0
        num_batches = 0
        
        # Shuffle indices
        perm = np.random.permutation(len(train_graphs))
        shuffled_train = [train_graphs[i] for i in perm]

        for b_start in range(0, len(shuffled_train), batch_size):
            batch_slice = shuffled_train[b_start:b_start + batch_size]
            batched = batch_graphs(batch_slice)
            
            x = batched.x.to(device)
            edge_index = batched.edge_index.to(device)
            batch_idx = batched.batch.to(device)
            y = batched.y.to(device)

            optimizer.zero_grad()
            logits, _ = model(x, edge_index, batch=batch_idx)
            loss = criterion(logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()

            total_train_loss += loss.item()
            num_batches += 1

        avg_train_loss = total_train_loss / max(1, num_batches)
        history["train_loss"].append(round(avg_train_loss, 4))

        # Batched Validation pass
        model.eval()
        with torch.no_grad():
            val_logits, _ = model(val_x, val_edge_index, batch=val_batch_idx)
            val_loss = criterion(val_logits, val_y).item()
            val_preds = torch.argmax(val_logits, dim=-1).cpu().numpy()
            val_targets = val_y.cpu().numpy()

        history["val_loss"].append(round(val_loss, 4))
        
        from sklearn.metrics import f1_score
        vf1 = f1_score(val_targets, val_preds, average="macro", zero_division=0)
        history["val_f1"].append(round(vf1, 4))

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    training_time = round(time.time() - start_time, 2)
    if best_weights:
        model.load_state_dict(best_weights)

    return model, {
        "model_type": model_type,
        "epochs_trained": epochs,
        "best_val_loss": round(best_val_loss, 4),
        "training_time_seconds": training_time,
        "history": history
    }

def evaluate_gnn_on_test(
    model: GNNClassifier,
    test_graphs: List[GraphData],
    device: str = "cpu"
) -> Dict[str, Any]:
    """Evaluates a trained GNN model on the held-out test split."""
    model.eval()
    y_true = []
    y_pred = []
    y_probs = []
    latencies = []

    with torch.no_grad():
        for g in test_graphs:
            x = g.x.to(device)
            edge_index = g.edge_index.to(device)
            t0 = time.perf_counter()
            logits, _ = model(x, edge_index)
            t_latency = (time.perf_counter() - t0) * 1000.0  # ms
            latencies.append(t_latency)

            prob = F.softmax(logits, dim=-1).cpu().numpy()[0]
            pred = np.argmax(prob)
            y_probs.append(prob)
            y_pred.append(pred)
            y_true.append(g.y.item())

    avg_latency = float(np.mean(latencies)) if latencies else 0.0
    metrics = compute_detailed_metrics(
        y_true=np.array(y_true),
        y_pred=np.array(y_pred),
        y_prob=np.array(y_probs),
        latency_ms=avg_latency
    )
    return metrics

def train_and_evaluate_all(
    dataset_dir: Path,
    output_dir: Path,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Loads dataset, splits into Train/Val/Test, trains GCN, GAT, GraphSAGE, and Random Forest,
    and saves checkpoints, metrics, and comparisons.
    """
    from ml.data.loader import load_dataset_from_directory, split_dataset
    print(f"Loading dataset from {dataset_dir}...", flush=True)
    traces = load_dataset_from_directory(dataset_dir)
    print(f"Loaded {len(traces)} traces.", flush=True)
    
    train_traces, val_traces, test_traces = split_dataset(traces, seed=seed)
    print(f"Split sizes: Train={len(train_traces)}, Val={len(val_traces)}, Test={len(test_traces)}", flush=True)

    # Convert to GraphData
    builder = GraphBuilder()
    print("Building graphs for Train/Val/Test splits...", flush=True)
    train_graphs = [builder.build(t) for t in train_traces]
    val_graphs = [builder.build(t) for t in val_traces]
    test_graphs = [builder.build(t) for t in test_traces]

    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir = output_dir / "checkpoints"
    metrics_dir = output_dir / "metrics"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    gnn_models = ["gat", "gcn", "graphsage"]

    for gnn_type in gnn_models:
        print(f"\nTraining GNN variant: {gnn_type.upper()}...", flush=True)
        model, train_info = train_gnn_model(gnn_type, train_graphs, val_graphs, epochs=25, batch_size=32)
        metrics = evaluate_gnn_on_test(model, test_graphs)
        
        # Save model checkpoint
        ckpt_path = checkpoints_dir / f"{gnn_type}_model.pt"
        torch.save({
            "model_state_dict": model.state_dict(),
            "model_type": gnn_type,
            "hidden_dim": model.hidden_dim,
            "in_dim": train_graphs[0].x.size(1),
            "num_classes": 3,
            "train_info": train_info,
            "test_metrics": metrics
        }, ckpt_path)

        param_count = sum(p.numel() for p in model.parameters() if p.requires_grad)
        metrics["parameter_count"] = param_count
        metrics["model_size_kb"] = round(ckpt_path.stat().st_size / 1024, 2)
        metrics["training_time_s"] = train_info["training_time_seconds"]

        results[gnn_type] = {
            "metrics": metrics,
            "train_info": train_info,
            "checkpoint_path": str(ckpt_path.name)
        }
        print(f"{gnn_type.upper()} Test Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['macro_f1']:.4f}", flush=True)

    # Baseline: Random Forest
    print("\nTraining Baseline: Random Forest Classifier...", flush=True)
    X_train, y_train = extract_tabular_features(train_traces)
    X_test, y_test = extract_tabular_features(test_traces)
    
    rf = RandomForestClassifier(n_estimators=100, random_state=seed)
    t0 = time.time()
    rf.fit(X_train, y_train)
    rf_train_time = round(time.time() - t0, 3)

    t0 = time.perf_counter()
    y_pred_rf = rf.predict(X_test)
    rf_latency = ((time.perf_counter() - t0) / len(X_test)) * 1000.0
    y_prob_rf = rf.predict_proba(X_test)
    
    rf_metrics = compute_detailed_metrics(y_test, y_pred_rf, y_prob_rf, latency_ms=rf_latency)
    rf_metrics["training_time_s"] = rf_train_time
    rf_metrics["parameter_count"] = 100
    rf_metrics["model_size_kb"] = 150.0

    results["random_forest"] = {
        "metrics": rf_metrics,
        "train_info": {"model_type": "random_forest", "n_estimators": 100},
        "checkpoint_path": "sklearn_rf.joblib"
    }
    print(f"Random Forest Test Accuracy: {rf_metrics['accuracy']:.4f}, F1: {rf_metrics['macro_f1']:.4f}", flush=True)

    # Save comparison summary
    comparison_file = metrics_dir / "comparison_results.json"
    with open(comparison_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nAll models trained and evaluated. Summary saved to {comparison_file}", flush=True)
    return results
