"""
Deterministic Health Check Workflow

Executes a fixed sequence of tool calls, applies threshold checks in Python
loaded from config/health_rules.yaml, and sends a structured summary to the LLM
for final synthesis. The LLM never orchestrates the tools — it only writes the report.
"""
import re
import logging
from pathlib import Path
import yaml

logger = logging.getLogger(__name__)

_RULES_FILE = Path(__file__).resolve().parent.parent.parent / "config" / "health_rules.yaml"

# Built-in fallback defaults in case config file is missing or invalid
_FALLBACK_RULES = {
    "uptime": {"warn_if_under_hours": 12, "rationale": "Recent reboot detected"},
    "memory": {"swap_warn_above_mb": 0},
    "cpu": {
        "load_per_core_caution": 0.75,
        "load_per_core_critical": 1.50,
        "idle_caution_under_pct": 50.0,
        "idle_critical_under_pct": 20.0,
        "suppress_load_alert_if_idle_above_pct": 70.0,
    },
    "storage": {
        "system_partitions": {"caution_pct": 85, "critical_pct": 95},
        "log_partitions": {"caution_pct": 92, "critical_pct": 97},
    },
}


def load_health_rules(target_device: str = None) -> dict:
    """
    Loads health check threshold rules from config/health_rules.yaml.
    Applies device-specific overrides if configured.
    Falls back gracefully to safe defaults if the file is missing or invalid.
    """
    rules = {k: dict(v) for k, v in _FALLBACK_RULES.items()}
    if _RULES_FILE.exists():
        try:
            with open(_RULES_FILE, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
                if isinstance(loaded, dict):
                    # Merge base sections
                    for section in ("uptime", "memory", "cpu", "storage"):
                        if section in loaded and isinstance(loaded[section], dict):
                            rules[section] = {**rules.get(section, {}), **loaded[section]}

                    # Apply optional device-specific overrides
                    dev_overrides = loaded.get("device_overrides", {})
                    if target_device and isinstance(dev_overrides, dict) and target_device in dev_overrides:
                        dev_rule = dev_overrides[target_device]
                        for section, section_rules in dev_rule.items():
                            if section in rules and isinstance(section_rules, dict):
                                rules[section].update(section_rules)
        except Exception as e:
            logger.warning(f"[HealthCheck] Error reading health_rules.yaml: {e}. Using safe fallbacks.")

    return rules


# Backward-compatibility alias
THRESHOLDS = load_health_rules()


def _parse_telemetry(raw_output: str) -> dict:
    """
    Extracts structured metrics from hardware_telemetry CLI output.
    Returns dict with parsed values. Missing fields = None.
    """
    metrics = {}
    
    # Uptime: "up X day(s), HH:MM" or "up HH:MM" or "uptime: X day(s)"
    uptime_days = re.search(r'(?:uptime[:\s]+|up\s+)(\d+)\s+day', raw_output, re.IGNORECASE)
    uptime_hours = re.search(r'(?:uptime[:\s]+|up\s+)(\d+):(\d+)', raw_output, re.IGNORECASE)
    if uptime_days:
        metrics['uptime_hours'] = int(uptime_days.group(1)) * 24
    elif uptime_hours:
        metrics['uptime_hours'] = int(uptime_hours.group(1))
    else:
        metrics['uptime_hours'] = None
    
    # Swap: PAN-OS format is "Swap:  4095996k total,        0k used" or "KiB Swap:  2048000 total,        0 used"
    swap_used_match = re.search(
        r'[Ss]wap.*?(\d+)\s*k?\s+used',
        raw_output
    )
    if swap_used_match:
        metrics['swap_mb'] = int(swap_used_match.group(1)) // 1024  # group(1) = used in KB
    else:
        metrics['swap_mb'] = 0
    
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
    vcpu_match = re.search(r'(?:num(?:ber)?-?(?:of-)?cpus?|cores?)\s*[:=]?\s*(\d+)', raw_output, re.IGNORECASE)
    if not vcpu_match:
        vcpu_match = re.search(r'(?<![\.\d])\b(\d+)\s+[^\S\r\n]*(?:cpus?|cores?|processors?)\b', raw_output, re.IGNORECASE)
    metrics['vcpu_count'] = int(vcpu_match.group(1)) if vcpu_match else 2

    # Disk partitions: parses both standard df output and YAML filesystem dumps
    disks = []
    # Match standard CLI df table: /dev/sda3 3.8G 1.5G 2.1G 43% /opt/pancfg
    for match in re.finditer(r'^\s*(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(\S+)', raw_output, re.MULTILINE):
        disks.append({"filesystem": match.group(1), "pct": int(match.group(2)), "mount": match.group(3)})
    # Fallback to YAML key extraction if already converted by ToxicXmlSanitizer
    if not disks:
        for match in re.finditer(r'usage_pct:\s*[\'"]?(\d+)[\'"]?.*?mounted_on:\s*[\'"]?(\S+)[\'"]?', raw_output, re.DOTALL):
            disks.append({"filesystem": match.group(2).strip('\'"'), "pct": int(match.group(1)), "mount": match.group(2).strip('\'"')})
    metrics['disks'] = disks
    
    return metrics


def _apply_thresholds(metrics: dict, target_device: str = None, rules: dict = None) -> list:
    """
    Applies declarative rules loaded from config/health_rules.yaml.
    Returns list of (subsystem, verdict, detail) tuples.
    """
    findings = []
    r = rules or load_health_rules(target_device)
    
    # 1. Uptime
    uptime = metrics.get('uptime_hours')
    warn_uptime = r.get("uptime", {}).get("warn_if_under_hours", 12)
    if uptime is not None:
        if uptime < warn_uptime:
            rationale = r.get("uptime", {}).get("rationale", "Recent reboot detected")
            findings.append(("Uptime", "CAUTION", f"{uptime}h (Threshold: <{warn_uptime}h) — {rationale}"))
        else:
            findings.append(("Uptime", "NORMAL", f"{uptime}h"))
    
    # 2. Swap
    swap = metrics.get('swap_mb', 0)
    warn_swap = r.get("memory", {}).get("swap_warn_above_mb", 0)
    if swap > warn_swap:
        findings.append(("Swap", "CAUTION", f"{swap}MB active (Threshold: >{warn_swap}MB) — memory pressure detected"))
    else:
        findings.append(("Swap", "NORMAL", "Inactive"))
    
    # 3. CPU Load (Normalized to vCPU count)
    load = metrics.get('load_avg')
    vcpus = metrics.get('vcpu_count', 2)
    idle = metrics.get('cpu_idle_pct')
    cpu_r = r.get("cpu", {})
    if load is not None and vcpus and vcpus > 0:
        ratio = load / vcpus
        suppress_threshold = cpu_r.get("suppress_load_alert_if_idle_above_pct", 70.0)
        idle_override = idle is not None and idle > suppress_threshold
        
        crit_load = cpu_r.get("load_per_core_critical", 1.50)
        caut_load = cpu_r.get("load_per_core_caution", 0.75)

        if ratio > crit_load and not idle_override:
            findings.append(("CPU Load", "CRITICAL", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus}) [Limit: {crit_load}]"))
        elif ratio > caut_load and not idle_override:
            findings.append(("CPU Load", "CAUTION", f"Load/vCPU={ratio:.2f} (load={load}, cores={vcpus}) [Limit: {caut_load}]"))
        elif ratio > caut_load and idle_override:
            findings.append(("CPU Load", "NORMAL", f"Load/vCPU={ratio:.2f} (cores={vcpus}) [Suppressed: {idle}% CPU idle]"))
        else:
            findings.append(("CPU Load", "NORMAL", f"Load/vCPU={ratio:.2f} (cores={vcpus})"))
    
    # 4. CPU Idle
    if idle is not None:
        caut_idle = cpu_r.get("idle_caution_under_pct", 50.0)
        crit_idle = cpu_r.get("idle_critical_under_pct", 20.0)
        if idle < crit_idle:
            findings.append(("CPU Idle", "CRITICAL", f"{idle}% idle (Critical limit: <{crit_idle}%)"))
        elif idle < caut_idle:
            findings.append(("CPU Idle", "CAUTION", f"{idle}% idle (Caution limit: <{caut_idle}%)"))
        else:
            findings.append(("CPU Idle", "NORMAL", f"{idle}% idle"))

    # 5. Storage (Partition-Smart: Log Storage vs System Storage)
    disks = metrics.get('disks', [])
    if disks:
        storage_r = r.get("storage", {})
        sys_cfg = storage_r.get("system_partitions", {"caution_pct": 85, "critical_pct": 95})
        log_cfg = storage_r.get("log_partitions", {"caution_pct": 92, "critical_pct": 97})

        issues = []
        max_disk = max(disks, key=lambda d: d['pct'])
        for d in disks:
            mount, pct = d['mount'], d['pct']
            is_log = "log" in mount.lower()
            cfg = log_cfg if is_log else sys_cfg

            if pct >= cfg["critical_pct"]:
                issues.append(("CRITICAL", f"{mount} at {pct}% capacity (Critical limit: {cfg['critical_pct']}%)"))
            elif pct >= cfg["caution_pct"]:
                issues.append(("CAUTION", f"{mount} at {pct}% capacity (Caution limit: {cfg['caution_pct']}%)"))

        if issues:
            issues.sort(key=lambda x: 0 if x[0] == "CRITICAL" else 1)
            for verdict, detail in issues:
                findings.append(("Disk", verdict, detail))
        else:
            findings.append(("Disk", "NORMAL", f"Max partition usage {max_disk['pct']}% ({max_disk['mount']})"))
    
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
    findings = _apply_thresholds(metrics, target_device=target_device)
    
    # Build structured summary for LLM
    lines = ["HEALTH CHECK RESULTS (deterministic workflow):"]
    lines.append("")
    
    for subsystem, verdict, detail in findings:
        lines.append(f"  [{verdict}] {subsystem}: {verdict} — {detail}")
    
    lines.append("")
    lines.append(f"Parsed metrics: {metrics}")
    
    # Multi-CAUTION escalation directive
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

