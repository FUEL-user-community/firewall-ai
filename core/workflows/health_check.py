"""
Deterministic Health Check Workflow

Executes a fixed sequence of tool calls, applies threshold checks in Python,
and sends only a structured summary to the LLM for final synthesis.
The LLM never orchestrates the tools — it only writes the report.
"""
import re
import logging

logger = logging.getLogger(__name__)


# Thresholds (Python-enforced, not prompt-injected)
THRESHOLDS = {
    "uptime_caution_hours": 24,
    "swap_caution_mb": 0,
    "load_per_vcpu_caution": 0.7,
    "load_per_vcpu_critical": 1.5,
    "disk_caution_pct": 80,
}


def _parse_telemetry(raw_output: str) -> dict:
    """
    Extracts structured metrics from hardware_telemetry CLI output.
    Returns dict with parsed values. Missing fields = None.
    """
    metrics = {}
    
    # Uptime: "up X day(s), HH:MM" or "up HH:MM"
    uptime_days = re.search(r'up\s+(\d+)\s+day', raw_output)
    uptime_hours = re.search(r'up\s+(\d+):(\d+)', raw_output)
    if uptime_days:
        metrics['uptime_hours'] = int(uptime_days.group(1)) * 24
    elif uptime_hours:
        metrics['uptime_hours'] = int(uptime_hours.group(1))
    else:
        metrics['uptime_hours'] = None
    
    # Swap: PAN-OS format is "Swap:  4095996k total,        0k used,  4095996k free"
    # Anchor on "total" then capture the "used" value after it.
    swap_used_match = re.search(
        r'[Ss]wap.*?(\d+)\s*k\s+total[,\s]+(\d+)\s*k\s+used',
        raw_output
    )
    if swap_used_match:
        metrics['swap_mb'] = int(swap_used_match.group(2)) // 1024  # group(2) = used
    else:
        # Fallback: if format doesn't match, try generic (but flag as uncertain)
        swap_fallback = re.search(r'[Ss]wap[^:]*:\s*(\d+)', raw_output)
        metrics['swap_mb'] = int(swap_fallback.group(1)) // 1024 if swap_fallback else 0
        if swap_fallback:
            logger.warning("[PARSE] Swap: used 'total' fallback regex - value may be inaccurate")
    
    # Load average (1-min): "load average: X.XX, Y.YY, Z.ZZ"
    load_match = re.search(r'load averages?:\s*([\d.]+)', raw_output)
    metrics['load_avg'] = float(load_match.group(1)) if load_match else None
    
    # CPU idle: "Cpu(s): X.X%id" or similar
    idle_match = re.search(r'([\d.]+)%?\s*id', raw_output)
    metrics['cpu_idle_pct'] = float(idle_match.group(1)) if idle_match else None
    
    # Memory: various formats
    mem_match = re.search(r'Mem[^:]*:\s*(\d+)', raw_output)
    metrics['mem_total_mb'] = int(mem_match.group(1)) if mem_match else None
    
    # vCPU count (default 2 for PA-VM)
    vcpu_match = re.search(r'(\d+)\s*(?:cpus?|cores?|processors?)', raw_output, re.IGNORECASE)
    metrics['vcpu_count'] = int(vcpu_match.group(1)) if vcpu_match else 2
    
    return metrics


def _apply_thresholds(metrics: dict) -> list:
    """
    Applies Python-enforced thresholds.
    Returns list of (subsystem, verdict, detail) tuples.
    
    NOTE: We apply cross-referencing logic here (e.g., suppressing CPU load alerts 
    if CPU idle is high) deterministically in Python. This prevents the LLM from 
    hallucinating or misinterpreting the complex relationships between these metrics.
    """
    findings = []
    
    # Uptime
    uptime = metrics.get('uptime_hours')
    if uptime is not None:
        if uptime < THRESHOLDS['uptime_caution_hours']:
            findings.append(("Uptime", "CAUTION", f"{uptime}h — recent reboot detected, investigate cause"))
        else:
            findings.append(("Uptime", "NORMAL", f"{uptime}h"))
    
    # Swap
    swap = metrics.get('swap_mb', 0)
    if swap > THRESHOLDS['swap_caution_mb']:
        findings.append(("Swap", "CAUTION", f"{swap}MB active — memory pressure on dedicated appliance"))
    else:
        findings.append(("Swap", "NORMAL", "Inactive"))
    
    # CPU Load (normalized to vCPU count)
    # Cross-reference: suppress load CAUTION if CPU idle > 70% (I/O wait inflates load avg)
    load = metrics.get('load_avg')
    vcpus = metrics.get('vcpu_count', 2)
    idle = metrics.get('cpu_idle_pct')
    if load is not None and vcpus:
        ratio = load / vcpus
        idle_override = idle is not None and idle > 70
        
        if ratio > THRESHOLDS['load_per_vcpu_critical'] and not idle_override:
            findings.append(("CPU Load", "CRITICAL", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus})"))
        elif ratio > THRESHOLDS['load_per_vcpu_caution'] and not idle_override:
            findings.append(("CPU Load", "CAUTION", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus})"))
        elif ratio > THRESHOLDS['load_per_vcpu_caution'] and idle_override:
            findings.append(("CPU Load", "NORMAL", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus}) [suppressed: {idle}% idle]"))
        else:
            findings.append(("CPU Load", "NORMAL", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus})"))
    
    # CPU Idle
    idle = metrics.get('cpu_idle_pct')
    if idle is not None:
        if idle < 20:
            findings.append(("CPU Idle", "CRITICAL", f"{idle}% idle"))
        elif idle < 50:
            findings.append(("CPU Idle", "CAUTION", f"{idle}% idle"))
        else:
            findings.append(("CPU Idle", "NORMAL", f"{idle}% idle"))
    
    return findings


def run_health_check(tool_executor, target_device: str = None) -> str:
    """
    Executes the deterministic health check workflow.
    
    Args:
        tool_executor: Callable that takes (tool_name, args_dict)
                       and returns result string.
        target_device: Device alias from devices.yaml to run against.
                       None = use the pool's configured default.
    
    Returns:
        Structured summary string ready for LLM synthesis.
    """
    device_label = target_device or "default"
    logger.info(f"[WORKFLOW] Health check: executing hardware_telemetry on '{device_label}'")
    
    # Pass target_device only if explicitly specified; otherwise let the pool use its default
    args = {"target_device": target_device} if target_device else {}
    raw_output = tool_executor("hardware_telemetry", args)
    
    if not raw_output or "Error" in str(raw_output)[:50]:
        return f"HEALTH CHECK FAILED: hardware_telemetry returned: {raw_output}"
    
    metrics = _parse_telemetry(str(raw_output))
    findings = _apply_thresholds(metrics)
    
    # Build structured summary for LLM
    lines = ["HEALTH CHECK RESULTS (deterministic workflow):"]
    lines.append("")
    
    has_issues = any(v != "NORMAL" for _, v, _ in findings)
    
    for subsystem, verdict, detail in findings:
        marker = "⚠️" if verdict == "CAUTION" else ("🔴" if verdict == "CRITICAL" else "✅")
        lines.append(f"  {marker} {subsystem}: {verdict} — {detail}")
    
    lines.append("")
    lines.append(f"Parsed metrics: {metrics}")
    
    # Fix 3: Multi-CAUTION escalation directive
    caution_count = sum(1 for _, v, _ in findings if v in ("CAUTION", "CRITICAL"))
    if caution_count >= 2:
        lines.append("")
        lines.append(f"ESCALATION: {caution_count} subsystems degraded. "
                     "Your RECOMMENDATION section MUST include specific investigation steps, "
                     "NOT 'no action required'.")
    
    lines.append("")
    lines.append("Raw hardware_telemetry output (capped at 2000 chars):")
    lines.append(str(raw_output)[:2000])
    
    return "\n".join(lines)
