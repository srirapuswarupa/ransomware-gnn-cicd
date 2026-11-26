"""
API Call Trace Schema and Data Contracts
Aligned with research on dynamic Windows API behavior modeling.
"""
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class ApiCallEvent(BaseModel):
    call_index: int = Field(..., description="Monotonic sequence number of the call in trace")
    timestamp_ms: float = Field(..., description="Relative timestamp in milliseconds from execution start")
    process_id: int = Field(default=1000, description="Process identifier")
    process_name: str = Field(default="sample.exe", description="Process executable name")
    thread_id: int = Field(default=1, description="Thread identifier")
    api_name: str = Field(..., description="Canonical or raw Windows API function name")
    category: str = Field(..., description="Functional category (e.g., Cryptography, File_IO, Process)")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Sanitized argument attributes")
    return_value: Optional[str] = Field(default="SUCCESS", description="Call return status")
    is_sensitive: bool = Field(default=False, description="Flagged under PASAC criteria")

class TraceMetadata(BaseModel):
    sample_id: str
    sha256: str
    platform: str = "windows"
    architecture: str = "x64"
    label: str = Field(..., description="benign, suspicious, or ransomware")
    label_id: int = Field(..., description="0=benign, 1=suspicious, 2=ransomware")
    family: Optional[str] = Field(default="Unknown", description="Ransomware or benign family name")
    is_synthetic: bool = Field(default=True, description="Safety requirement: explicit synthetic indicator")
    collection_source: str = Field(default="Dynamic-Trace-Simulation-Engine", description="Source description")
    total_calls: int = 0
    duration_ms: float = 0.0

class ApiTrace(BaseModel):
    metadata: TraceMetadata
    events: List[ApiCallEvent]
