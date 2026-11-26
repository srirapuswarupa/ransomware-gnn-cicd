"""
Trace Ingestion, Validation, and Sample Retrieval Endpoints.
"""
import json
import csv
import io
from pathlib import Path
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Query

from backend.app.core.config import settings
from ml.data.schema import ApiTrace
from ml.preprocessing.normalizer import normalize_trace, normalize_event

router = APIRouter(prefix="/traces", tags=["Traces"])

@router.post("/upload")
async def upload_trace_file(file: UploadFile = File(...)):
    """Uploads and normalizes an API call trace in JSON or CSV format."""
    filename = file.filename.lower()
    content_bytes = await file.read()
    
    # 5MB upload limit for safety
    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Max size is 5MB.")

    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text.")

    if filename.endswith(".json"):
        try:
            raw_data = json.loads(content_str)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Malformed JSON: {e}")
        trace = normalize_trace(raw_data)
        return trace.model_dump()
        
    elif filename.endswith(".csv"):
        try:
            reader = csv.DictReader(io.StringIO(content_str))
            events = [dict(row) for row in reader]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Malformed CSV: {e}")
        raw_data = {
            "metadata": {
                "sample_id": Path(filename).stem,
                "label": "unknown",
                "is_synthetic": True
            },
            "events": events
        }
        trace = normalize_trace(raw_data)
        return trace.model_dump()
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format. Please upload .json or .csv.")

@router.get("/samples")
def list_samples(limit: int = Query(30, ge=1, le=100)):
    """Lists pre-generated samples from the research dataset."""
    summary_path = settings.DATASET_DIR / "synthetic" / "dataset_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            samples = data.get("samples", [])
            return {
                "total": len(samples),
                "counts": data.get("counts", {}),
                "samples": samples[:limit]
            }
    return {"total": 0, "samples": []}

@router.get("/samples/{sample_id}")
def get_sample_trace(sample_id: str):
    """Retrieves full trace JSON for a specific sample ID."""
    dataset_dir = settings.DATASET_DIR / "synthetic"
    matches = list(dataset_dir.rglob(f"{sample_id}.json"))
    if not matches:
        raise HTTPException(status_code=404, detail=f"Sample {sample_id} not found.")
    with open(matches[0], "r", encoding="utf-8") as f:
        data = json.load(f)
    return data
