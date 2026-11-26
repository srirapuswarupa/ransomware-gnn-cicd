"""
Early Ransomware Warning Service.
Implements partial-trace prefix evaluation (inspired by RansoGuard, Cen et al. 2025).
Evaluates early detection triggers, lead time, and predictive trajectories.
"""
from typing import Dict, List, Any, Optional
from copy import deepcopy

from ml.data.schema import ApiTrace
from ml.preprocessing.normalizer import normalize_trace
from backend.app.services.gnn_inference_service import inference_service
from backend.app.schemas.prediction import EarlyWarningResponse, EarlyWarningPrefix

class EarlyWarningService:
    def __init__(self):
        self.inference = inference_service
        self.alert_threshold_risk = 65.0 # Early alert risk score trigger

    def analyze_prefix_trajectory(
        self,
        trace_dict_or_obj: Any,
        model_name: Optional[str] = None,
        cutoffs: List[int] = [10, 25, 40, 55, 70, 85, 100]
    ) -> EarlyWarningResponse:
        """
        Evaluates incremental prefixes of an API trace to simulate streaming detection.
        Calculates the earliest point at which malicious intent is identifiable.
        """
        if isinstance(trace_dict_or_obj, dict):
            full_trace = normalize_trace(trace_dict_or_obj)
        else:
            full_trace = trace_dict_or_obj

        events = full_trace.events
        total_events = len(events)
        
        trajectory: List[EarlyWarningPrefix] = []
        alert_triggered = False
        trigger_cutoff = None
        trigger_timestamp = None
        trigger_call_idx = None

        final_resp, _ = self.inference.predict_trace(full_trace, model_name=model_name)
        final_class = final_resp.predicted_class

        # Check for first destructive mass encryption or ransom note event in the full trace
        destructive_event_idx = None
        destructive_event_ts = None
        for ev in events:
            if "MoveFileEx" in ev.api_name or "CryptEncrypt" in ev.api_name or "README" in str(ev.arguments):
                destructive_event_idx = ev.call_index
                destructive_event_ts = ev.timestamp_ms
                break

        for pct in cutoffs:
            num_calls = max(2, int(total_events * (pct / 100.0)))
            sub_events = events[:num_calls]
            
            sub_trace = deepcopy(full_trace)
            sub_trace.events = sub_events
            sub_trace.metadata.total_calls = len(sub_events)
            sub_trace.metadata.duration_ms = sub_events[-1].timestamp_ms if sub_events else 0.0

            resp, _ = self.inference.predict_trace(sub_trace, model_name=model_name)
            
            cutoff_ts = sub_events[-1].timestamp_ms if sub_events else 0.0
            p_ransom = resp.probabilities["ransomware"]

            prefix_item = EarlyWarningPrefix(
                cutoff_percentage=pct,
                calls_observed=len(sub_events),
                cutoff_timestamp_ms=round(cutoff_ts, 2),
                predicted_class=resp.predicted_class,
                confidence=resp.confidence,
                ransomware_probability=p_ransom,
                risk_score=resp.risk_score
            )
            trajectory.append(prefix_item)

            if not alert_triggered and (resp.risk_score >= self.alert_threshold_risk or p_ransom >= 0.65):
                alert_triggered = True
                trigger_cutoff = pct
                trigger_timestamp = cutoff_ts
                trigger_call_idx = sub_events[-1].call_index

        lead_time_ms = None
        lead_events_count = None

        if alert_triggered and destructive_event_ts is not None:
            # Positive lead time means early warning triggered BEFORE destructive activity
            lead_time_ms = max(0.0, round(destructive_event_ts - trigger_timestamp, 2))
            lead_events_count = max(0, destructive_event_idx - trigger_call_idx) if destructive_event_idx else None
        elif alert_triggered:
            # Compared to trace end
            total_duration = events[-1].timestamp_ms if events else 0.0
            lead_time_ms = max(0.0, round(total_duration - trigger_timestamp, 2))
            lead_events_count = max(0, total_events - trigger_call_idx) if trigger_call_idx else 0

        return EarlyWarningResponse(
            sample_id=full_trace.metadata.sample_id,
            final_class=final_class,
            early_alert_triggered=alert_triggered,
            trigger_cutoff_percentage=trigger_cutoff,
            trigger_timestamp_ms=trigger_timestamp,
            trigger_call_index=trigger_call_idx,
            lead_time_ms=lead_time_ms,
            lead_events_count=lead_events_count,
            trajectory=trajectory
        )

early_warning_service = EarlyWarningService()
