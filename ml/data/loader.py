"""
Dataset Loader and Stratified Train/Val/Test Splitter.
Guarantees clean data segregation without data leakage.
"""
import json
import csv
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from sklearn.model_selection import train_test_split
from ml.data.schema import ApiTrace, ApiCallEvent, TraceMetadata
from ml.preprocessing.normalizer import normalize_trace, normalize_event

def load_trace_from_json(path: Path) -> ApiTrace:
    """Loads and validates an API call trace from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return normalize_trace(data)

def load_trace_from_csv(path: Path, metadata: Optional[Dict[str, Any]] = None) -> ApiTrace:
    """
    Imports an API call trace from a CSV file.
    Expected columns: call_index, timestamp_ms, thread_id, api_name, category, arguments.
    """
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(dict(row))

    raw_data = {
        "metadata": metadata or {
            "sample_id": path.stem,
            "label": "unknown",
            "is_synthetic": True
        },
        "events": events
    }
    return normalize_trace(raw_data)

def load_dataset_from_directory(dataset_dir: Path) -> List[ApiTrace]:
    """Loads all valid JSON trace files recursively from a dataset directory."""
    traces: List[ApiTrace] = []
    for json_file in dataset_dir.rglob("*.json"):
        if json_file.name in ["dataset_summary.json", "metadata.json"]:
            continue
        try:
            trace = load_trace_from_json(json_file)
            traces.append(trace)
        except Exception as e:
            print(f"Warning: Failed to load {json_file}: {e}")
    return traces

def split_dataset(
    traces: List[ApiTrace],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42
) -> Tuple[List[ApiTrace], List[ApiTrace], List[ApiTrace]]:
    """
    Performs stratified train/validation/test split based on trace labels.
    Prevents data leakage by ensuring samples are strictly partitioned.
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-5, "Ratios must sum to 1.0"
    
    labels = [t.metadata.label_id for t in traces]
    
    # First split: train vs (val + test)
    val_test_ratio = val_ratio + test_ratio
    train_traces, temp_traces, train_labels, temp_labels = train_test_split(
        traces, labels, test_size=val_test_ratio, random_state=seed, stratify=labels
    )
    
    # Second split: val vs test
    relative_test_ratio = test_ratio / val_test_ratio
    val_traces, test_traces = train_test_split(
        temp_traces, test_size=relative_test_ratio, random_state=seed, stratify=temp_labels
    )
    
    return train_traces, val_traces, test_traces

def get_dataset_statistics(traces: List[ApiTrace]) -> Dict[str, Any]:
    """Computes comprehensive statistics for a corpus of traces."""
    total = len(traces)
    counts = {"benign": 0, "suspicious": 0, "ransomware": 0}
    families: Dict[str, int] = {}
    call_counts = []
    durations = []
    api_freq: Dict[str, int] = {}

    for t in traces:
        lbl = t.metadata.label
        counts[lbl] = counts.get(lbl, 0) + 1
        fam = t.metadata.family or "Unknown"
        families[fam] = families.get(fam, 0) + 1
        call_counts.append(t.metadata.total_calls)
        durations.append(t.metadata.duration_ms)
        for ev in t.events:
            api_freq[ev.api_name] = api_freq.get(ev.api_name, 0) + 1

    top_apis = sorted(api_freq.items(), key=lambda x: x[1], reverse=True)[:15]

    return {
        "total_samples": total,
        "class_distribution": counts,
        "family_distribution": families,
        "avg_calls_per_sample": round(sum(call_counts) / max(total, 1), 2),
        "min_calls": min(call_counts) if call_counts else 0,
        "max_calls": max(call_counts) if call_counts else 0,
        "avg_duration_ms": round(sum(durations) / max(total, 1), 2),
        "top_apis": [{"api": k, "count": v} for k, v in top_apis]
    }
