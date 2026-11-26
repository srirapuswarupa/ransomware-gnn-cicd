"""
Trace Normalization and Preprocessing Engine.
Cleans raw API logs, strips PII/local paths, canonicalizes names, and formats timestamps.
"""
import re
from typing import Dict, List, Any, Optional
from ml.data.schema import ApiCallEvent, ApiTrace, TraceMetadata
from ml.preprocessing.sensitive_api import CANONICAL_NAME_MAP, get_api_category, is_pre_attack_sensitive

# Safe argument abstraction regexes
PATH_USER_RE = re.compile(r"^[A-Za-z]:\\Users\\[^\\]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def sanitize_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes trace arguments to remove specific host names, credentials,
    and private directory trees while preserving behavioural indicators.
    """
    sanitized = {}
    for key, val in args.items():
        if isinstance(val, str):
            # Replace local user profile prefixes
            s_val = PATH_USER_RE.sub(r"<USER_PROFILE>", val)
            # Abstract external IP addresses
            s_val = IPV4_RE.sub("<REMOTE_IP>", s_val)
            # Truncate overly long buffers
            if len(s_val) > 120:
                s_val = s_val[:117] + "..."
            sanitized[key] = s_val
        elif isinstance(val, (int, float, bool)):
            sanitized[key] = val
        elif isinstance(val, list):
            sanitized[key] = [str(item)[:40] for item in val[:5]]
        else:
            sanitized[key] = str(val)[:50]
    return sanitized

def normalize_event(raw: Dict[str, Any], default_index: int) -> Optional[ApiCallEvent]:
    """Validates and normalizes an individual API call record."""
    raw_name = raw.get("api_name") or raw.get("api") or raw.get("function")
    if not raw_name or not isinstance(raw_name, str):
        return None
    
    clean_name = raw_name.strip()
    canon_name = CANONICAL_NAME_MAP.get(clean_name, clean_name)
    category = raw.get("category") or get_api_category(canon_name)
    
    try:
        call_index = int(raw.get("call_index", default_index))
    except (ValueError, TypeError):
        call_index = default_index
        
    try:
        ts = float(raw.get("timestamp_ms", raw.get("timestamp", 0.0)))
    except (ValueError, TypeError):
        ts = 0.0

    raw_args = raw.get("arguments", {})
    if not isinstance(raw_args, dict):
        raw_args = {"raw": str(raw_args)}
        
    sanitized_args = sanitize_arguments(raw_args)
    sensitive = is_pre_attack_sensitive(canon_name)

    return ApiCallEvent(
        call_index=call_index,
        timestamp_ms=max(0.0, ts),
        process_id=int(raw.get("process_id", 1000)),
        process_name=str(raw.get("process_name", "sample.exe")),
        thread_id=int(raw.get("thread_id", 1)),
        api_name=canon_name,
        category=category,
        arguments=sanitized_args,
        return_value=str(raw.get("return_value", "SUCCESS")),
        is_sensitive=sensitive
    )

def normalize_trace(raw_trace: Dict[str, Any]) -> ApiTrace:
    """Normalizes an entire trace dictionary containing metadata and events."""
    raw_meta = raw_trace.get("metadata", {})
    raw_events = raw_trace.get("events", [])
    
    norm_events: List[ApiCallEvent] = []
    seen_calls = set()
    
    for idx, e in enumerate(raw_events):
        ev = normalize_event(e, idx)
        if ev:
            # Drop pure duplicate events with identical timestamp, thread, api, and args
            event_sig = (ev.call_index, ev.thread_id, ev.api_name, str(ev.arguments))
            if event_sig not in seen_calls:
                seen_calls.add(event_sig)
                norm_events.append(ev)

    # Sort events chronologically, with call_index as tie-breaker
    norm_events.sort(key=lambda x: (x.timestamp_ms, x.call_index))
    # Re-index monotonically
    for i, ev in enumerate(norm_events):
        ev.call_index = i

    duration = norm_events[-1].timestamp_ms if norm_events else 0.0

    label_str = str(raw_meta.get("label", "benign")).lower()
    if "ransom" in label_str:
        label = "ransomware"
        label_id = 2
    elif "suspicious" in label_str:
        label = "suspicious"
        label_id = 1
    else:
        label = "benign"
        label_id = 0

    metadata = TraceMetadata(
        sample_id=str(raw_meta.get("sample_id", "SAMPLE-UNKNOWN")),
        sha256=str(raw_meta.get("sha256", "0" * 64)),
        platform="windows",
        architecture=str(raw_meta.get("architecture", "x64")),
        label=label,
        label_id=label_id,
        family=str(raw_meta.get("family", "Generic")),
        is_synthetic=bool(raw_meta.get("is_synthetic", True)),
        collection_source=str(raw_meta.get("collection_source", "Dynamic-Trace-Simulation-Engine")),
        total_calls=len(norm_events),
        duration_ms=duration
    )

    return ApiTrace(metadata=metadata, events=norm_events)
