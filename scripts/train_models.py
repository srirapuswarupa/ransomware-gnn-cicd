"""
Dedicated script to train all GNN and baseline models with verbose logging.
"""
import sys
import os
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ml.training.trainer import train_and_evaluate_all

if __name__ == "__main__":
    print(f"Starting training pipeline from {ROOT}...", flush=True)
    dataset_dir = ROOT / "datasets" / "synthetic"
    experiments_dir = ROOT / "ml" / "experiments"
    
    results = train_and_evaluate_all(dataset_dir, experiments_dir)
    print("Training pipeline finished successfully!", flush=True)
