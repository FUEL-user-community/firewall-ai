import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CognitiveTraceLogger:
    """
    Analyzes and persists the Hi-CoT reasoning trace of an investigation.
    Tracks cognitive efficiency (Thinking vs Acting).
    """
    
    def __init__(self, trace_dir: str = None):
        from pathlib import Path
        _base_dir = Path(__file__).resolve().parent.parent.parent
        self.trace_dir = str(trace_dir or (_base_dir / "data" / "traces"))
        os.makedirs(self.trace_dir, exist_ok=True)

    def log_trace(self, trace_id: str, target_mode: str, trace_data: list, total_turns: int):
        """
        Dumps the cognitive trace and calculates efficiency metrics.
        """
        if not trace_data:
            logger.warning(f"[TraceLogger] No trace data for {trace_id}")
            return
            
        # Calculate cognitive metrics
        total_hypothesis_weight = sum(t.get("hypothesis_len", 0) for t in trace_data)
        total_contradiction_weight = sum(t.get("contradiction_len", 0) for t in trace_data)
        
        # A high contradiction weight means the AI is actively debating itself (Deep System 2)
        cognitive_depth = "DEEP" if total_contradiction_weight > 200 else "SHALLOW"
        
        # Calculate Average Drift Score
        drift_scores = [t.get("drift_score") for t in trace_data if t.get("drift_score") is not None and t.get("drift_score") != 1.0]
        avg_drift = sum(drift_scores) / len(drift_scores) if drift_scores else 1.0

        report = {
            "timestamp": datetime.now().isoformat(),
            "trace_id": trace_id,
            "mode": target_mode,
            "total_turns": total_turns,
            "metrics": {
                "cognitive_depth": cognitive_depth,
                "hypothesis_weight": total_hypothesis_weight,
                "contradiction_weight": total_contradiction_weight,
                "avg_semantic_coherence": round(avg_drift, 3)
            },
            "turns": trace_data
        }

        import re
        # Prevent path traversal attacks by stripping directory traversal characters
        safe_trace_id = re.sub(r'[^a-zA-Z0-9_-]', '_', str(trace_id))
        
        file_path = os.path.join(self.trace_dir, f"trace_{safe_trace_id}.json")
        with open(file_path, "w") as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"[TraceLogger] Cognitive trace saved: {file_path} (Depth: {cognitive_depth})")
