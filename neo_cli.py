#!/usr/bin/env python3
"""
NEO — In-Process PAN-OS Cybersec Resident & Symbiotic SSH Shell (`neo_cli.py`).

Zero listening network ports. Keys are consumed once into sealed RAM and purged
from `os.environ` before Turn 1.

Execution Modes:
  1. Single-Prompt Symbiotic SSH (Recommended on Linux/macOS):
       python3 neo_cli.py --ssh fw-hq
       python3 neo_cli.py --ssh admin@192.168.1.254
     Wraps real OpenSSH in a local PTY: native Tab/?/completion at 0ms latency,
     column-0 `@` resident & `$0.00` repo commands (`@walk`, `@macro`, `@stage`),
     rolling 8 KB scrubbed SSH output context, and Pre-Commit Sanctuary lockout gate.
  2. Standalone Resident REPL (Linux/macOS/Windows, optional tmux side-pane):
       python3 neo_cli.py
  3. One-Shot / Pre-Flight Check:
       python3 neo_cli.py -q "check mgt permitted-ip"
       python3 neo_cli.py --check
"""

import argparse
from contextlib import contextmanager
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent

# Standard stdout ANSI palette (never alternate-screen so native mouse copy-paste stays intact)
C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_GREEN = "\033[32m"
C_CYAN = "\033[36m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"

_STAGE_ALLOWED_PREFIX_RE = re.compile(r"^(set|move|rename|delete)\s+", re.IGNORECASE)
_STAGE_FORBIDDEN_RE = re.compile(
    r"(?:^|\s|;|\|)(commit|request|debug|exit|quit|scp|tftp|load|save|revert)\b",
    re.IGNORECASE,
)
_SSH_SECRET_LINE_RE = re.compile(
    r"\b(password|phash|pre-shared-key|private-key|secret|passphrase|bind-password|lufrpt|aizasy)\b",
    re.IGNORECASE,
)
_PANOS_CLI_ERROR_RE = re.compile(
    r"(Invalid syntax|Unknown command|Server error\s*:|Validation Error)",
    re.IGNORECASE,
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")
_COMMIT_CMD_RE = re.compile(r"^commit(?:\s+.*)?$", re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", text or "")


def normalize_panos_set_line(line: str) -> str:
    """Normalize PAN-OS 10.0.x list brackets (`[a b]` -> `[ a b ]`) and strip outer whitespace."""
    cleaned = line.strip()
    return re.sub(r"\[\s*([^\[\]]+?)\s*\]", lambda m: f"[ {m.group(1).strip()} ]", cleaned)


def extract_stageable_panos_lines(markdown_text: str) -> List[str]:
    """
    Extract ONLY safe candidate-config lines (`set|move|rename|delete`) from fenced blocks
    or standalone lines in NEO's last response, hard-dropping `commit`, `request`, `exit`, etc.
    """
    if not markdown_text:
        return []

    blocks = re.findall(r"```(?:panos|cli|text|bash|sh)?\s*\n([\s\S]*?)```", markdown_text, flags=re.IGNORECASE)
    candidate_pool = "\n".join(blocks) if blocks else markdown_text

    safe_lines: List[str] = []
    for raw in candidate_pool.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        ln = re.sub(r"^[a-zA-Z0-9_.@-]+(?:\([^)]+\))?[>#]\s*", "", ln).strip()
        if not _STAGE_ALLOWED_PREFIX_RE.match(ln):
            continue
        if _STAGE_FORBIDDEN_RE.search(ln):
            continue
        safe_lines.append(normalize_panos_set_line(ln))
    return safe_lines


def sanitize_ssh_capture(raw_pane_text: str) -> str:
    """Scrub secrets and drop credential-bearing lines from SSH output captures."""
    from core.safety.scrubber import scrub, scrub_registered_secrets

    if not raw_pane_text:
        return ""
    kept: List[str] = []
    for line in strip_ansi(raw_pane_text).replace("\r", "").splitlines():
        if _SSH_SECRET_LINE_RE.search(line):
            kept.append("[REDACTED_CREDENTIAL_LINE]")
        else:
            kept.append(line)
    joined = "\n".join(kept)
    return scrub_registered_secrets(scrub(joined)).strip()


def resolve_ssh_target(ssh_spec: str, explicit_device: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Resolve `--ssh <spec>` against `config/devices.yaml`:
      - 'fw-hq'            -> ('admin@192.168.1.254', 'fw-hq')
      - 'netops@fw-hq'     -> ('netops@192.168.1.254', 'fw-hq')
      - 'admin@10.0.0.1'   -> ('admin@10.0.0.1', matching_alias_or_explicit)
      - '192.168.1.254'    -> ('admin@192.168.1.254', matching_alias_or_explicit)
    """
    from core.pipeline.prompt_assembler import load_devices_config

    spec = (ssh_spec or "").strip()
    default_user = os.getenv("PANOS_SSH_USER", "admin").strip() or "admin"
    if "@" in spec:
        ssh_user, host_part = spec.split("@", 1)
    else:
        ssh_user, host_part = default_user, spec

    firewalls = (load_devices_config() or {}).get("firewalls", {}) or {}
    if host_part in firewalls and isinstance(firewalls[host_part], dict):
        ip_val = str(firewalls[host_part].get("ip") or host_part).strip()
        return f"{ssh_user}@{ip_val}", (explicit_device or host_part)

    matched_alias = explicit_device
    if not matched_alias:
        for alias, info in firewalls.items():
            if isinstance(info, dict) and str(info.get("ip") or "").strip() == host_part:
                matched_alias = alias
                break
    return f"{ssh_user}@{host_part}", matched_alias


def find_adjacent_tmux_pane() -> Optional[str]:
    """Locate the sibling tmux pane in the current window when running inside `$TMUX`."""
    if not os.getenv("TMUX"):
        return None
    current_pane = os.getenv("TMUX_PANE", "").strip()
    try:
        cp = subprocess.run(
            ["tmux", "list-panes", "-F", "#{pane_id}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if cp.returncode != 0:
            return None
        panes = [p.strip() for p in cp.stdout.splitlines() if p.strip()]
        others = [p for p in panes if p != current_pane]
        return others[0] if others else None
    except Exception:
        return None


def capture_tmux_pane(pane_id: str, lines: int = 50) -> Tuple[bool, str]:
    """Read the last `lines` of `pane_id` via `tmux capture-pane`."""
    try:
        cp = subprocess.run(
            ["tmux", "capture-pane", "-p", "-t", pane_id, "-S", f"-{max(5, int(lines))}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if cp.returncode != 0:
            return False, (cp.stderr or "tmux capture-pane failed").strip()
        return True, cp.stdout
    except Exception as exc:
        return False, str(exc)


def detect_panos_prompt_mode(pane_tail: str) -> Optional[str]:
    """
    Inspect the last non-empty line of SSH output:
    Returns `'config'` if at `user@host#`, `'op'` if at `user@host>`, or `None` if not at PAN-OS CLI.
    """
    clean = strip_ansi(pane_tail).replace("\r", "")
    non_empty = [ln.rstrip() for ln in clean.splitlines() if ln.strip()]
    if not non_empty:
        return None
    last = non_empty[-1]
    low = last.lower()
    if "--more--" in low or "password:" in low:
        return None
    if re.search(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(\([^)]+\))?#\s*$", last):
        return "config"
    if re.search(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(\([^)]+\))?>\s*$", last):
        return "op"
    return None


def extract_echoed_command_after_prompt(line_buf: str) -> Tuple[Optional[str], str]:
    """
    Parse the active PAN-OS prompt line (e.g. `admin@firewall-a# commit force`) into
    `('config'|'op'|None, 'commit force')`. Handles Tab-completed and history-recalled commands.
    """
    clean = strip_ansi(line_buf).replace("\r", "").split("\n")[-1]
    m = re.match(r"^\s*[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?:\([^)]+\))?([>#])\s*(.*)$", clean)
    if not m:
        return None, ""
    mode = "config" if m.group(1) == "#" else "op"
    return mode, m.group(2).strip()


def stage_lines_to_tmux_ssh(pane_id: str, commands: List[str], step_delay: float = 0.35) -> Tuple[bool, str]:
    """Safely stage validated `set|move|rename|delete` lines into an adjacent tmux PAN-OS SSH pane."""
    ok, snap = capture_tmux_pane(pane_id, lines=8)
    if not ok:
        return False, f"Cannot inspect tmux pane {pane_id}: {snap}"

    mode = detect_panos_prompt_mode(snap)
    if mode is None:
        return (
            False,
            f"Pane {pane_id} is not sitting at an idle PAN-OS '>' or '#' prompt "
            "(verify SSH login, exit '--more--' pager, or wait for active command to finish).",
        )

    prep_cmd = "configure" if mode == "op" else "top"
    subprocess.run(["tmux", "send-keys", "-t", pane_id, prep_cmd, "Enter"], check=False, timeout=3)
    time.sleep(step_delay)

    sent_count = 0
    for idx, cmd in enumerate(commands, 1):
        _, before_snap = capture_tmux_pane(pane_id, lines=6)
        subprocess.run(["tmux", "send-keys", "-l", "-t", pane_id, cmd], check=False, timeout=3)
        subprocess.run(["tmux", "send-keys", "-t", pane_id, "Enter"], check=False, timeout=3)
        time.sleep(step_delay)

        ok_after, after_snap = capture_tmux_pane(pane_id, lines=8)
        if not ok_after:
            return False, f"Lost tmux capture after line {idx}: {after_snap}"

        delta_tail = (
            after_snap[len(before_snap) :]
            if before_snap and after_snap.startswith(before_snap[: min(40, len(before_snap))])
            else "\n".join(after_snap.splitlines()[-5:])
        )
        err_match = _PANOS_CLI_ERROR_RE.search(delta_tail)
        if err_match:
            return (
                False,
                f"ABORTED at line {idx}/{len(commands)} ('{err_match.group(1)}' returned by PAN-OS CLI). "
                f"Stopped before sending remaining {len(commands) - idx} line(s).",
            )
        sent_count += 1

    return (
        True,
        f"Staged {sent_count} line(s) into {pane_id} [edit] (NO commit sent — inspect with 'run show config diff' in SSH).",
    )


def stage_lines_to_pty_master(
    master_fd: int,
    commands: List[str],
    current_mode: str = "config",
    timeout_per_cmd: float = 2.0,
) -> Tuple[bool, str]:
    """
    Directly write validated `set|move|rename|delete` lines into the live SSH PTY `master_fd`,
    reading PAN-OS's echoed response bytes in real time and aborting immediately on CLI errors.
    """
    import select

    def _send_and_collect(line_str: str) -> str:
        os.write(master_fd, (line_str + "\r").encode("utf-8"))
        collected = bytearray()
        deadline = time.time() + timeout_per_cmd
        while time.time() < deadline:
            rlist, _, _ = select.select([master_fd], [], [], 0.08)
            if not rlist:
                if detect_panos_prompt_mode(collected.decode("utf-8", errors="replace")) == "config":
                    break
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            collected.extend(chunk)
            if detect_panos_prompt_mode(collected.decode("utf-8", errors="replace")) == "config":
                break
        return strip_ansi(collected.decode("utf-8", errors="replace"))

    prep = "configure" if current_mode == "op" else "top"
    prep_out = _send_and_collect(prep)
    if _PANOS_CLI_ERROR_RE.search(prep_out):
        return False, f"Failed to enter top [edit] hierarchy: {prep_out.strip()[-120:]}"

    sent = 0
    for idx, cmd in enumerate(commands, 1):
        echo_out = _send_and_collect(cmd)
        err_m = _PANOS_CLI_ERROR_RE.search(echo_out)
        if err_m:
            return (
                False,
                f"ABORTED at line {idx}/{len(commands)} ('{err_m.group(1)}' returned by PAN-OS CLI). "
                f"Stopped before sending remaining {len(commands) - idx} line(s).",
            )
        sent += 1

    return True, f"Injected {sent} candidate line(s) into [edit] (0 syntax errors, NO commit sent)."


def read_coalesced_input(prompt_str: str) -> str:
    """Read operator prompt and coalesce pasted multi-line bursts on POSIX within 50ms."""
    first = input(prompt_str)
    if os.name != "posix" or not sys.stdin.isatty():
        return first
    import select

    lines = [first]
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], 0.05)
        if not ready:
            break
        nxt = sys.stdin.readline()
        if not nxt:
            break
        lines.append(nxt.rstrip("\r\n"))
    return "\n".join(lines)


def bootstrap_secure_runtime(
    quiet: bool = False,
    tty_guard_factory: Optional[Callable[[], Any]] = None,
):
    """Load .env, tighten permissions, warm clients, and purge secrets from os.environ."""
    env_file = REPO_ROOT / ".env"
    load_dotenv(dotenv_path=env_file, override=True)
    os.environ["HITL_MODE"] = "terminal"

    from core.brain import CoreBrain
    from core.forge.slot_mutator import register_forge_approval_hook
    from core.integrations.gdrive_client import GoogleDriveClient
    from core.integrations.secrets import enforce_secret_file_permissions, seal_runtime_secrets
    from core.panos.client import PanOSClientPool
    from core.safety.hitl import ApprovalRequest, TerminalHITLProvider

    perm_notes = enforce_secret_file_permissions(env_file)
    for note in perm_notes:
        if not quiet:
            print(f"{C_YELLOW}[security] {note}{C_RESET}")

    if os.getenv("KNOWLEDGE_BASE_FOLDER_ID") or os.getenv("GOOGLE_DRIVE_FOLDER_ID"):
        try:
            GoogleDriveClient.get_instance("readonly").get_service()
        except Exception:
            pass

    fw_label = "unconfigured"
    try:
        pool = PanOSClientPool.get_instance()
        default_client = pool.get_client()
        fw_label = f"{default_client.device_name} ({default_client.hostname})"
    except Exception as exc:
        fw_label = f"offline ({exc})"

    brain = CoreBrain()
    purged_count = seal_runtime_secrets()

    @contextmanager
    def _noop_ctx():
        yield

    guard_ctx = tty_guard_factory or _noop_ctx

    def _hitl_prompt(req: ApprovalRequest) -> bool:
        if not sys.stdin.isatty():
            return False
        with guard_ctx():
            ans = input(f"\n{C_YELLOW}[HITL] Approve WRITE tool '{req.summary}'? [y/N]: {C_RESET}").strip().lower()
            return ans in ("y", "yes")

    brain.hitl = TerminalHITLProvider(prompt_fn=_hitl_prompt)
    if getattr(brain, "tool_executor", None) is not None:
        brain.tool_executor.hitl = brain.hitl

    def _confirm_forge_patch(touched_paths: List[str], diff_preview: str) -> bool:
        if not sys.stdin.isatty():
            return False
        with guard_ctx():
            print(f"\n{C_YELLOW}{C_BOLD}── SLOT_FORGE SELF-PATCH APPROVAL REQUIRED ──{C_RESET}")
            print(f"Touched files: {', '.join(touched_paths)}")
            if diff_preview:
                for dline in diff_preview.splitlines()[:80]:
                    col = C_GREEN if dline.startswith("+") else (C_RED if dline.startswith("-") else C_DIM)
                    print(f"{col}{dline}{C_RESET}")
            ans = input(f"{C_YELLOW}Run pytest & promote this patch live? [y/N]: {C_RESET}").strip().lower()
            return ans in ("y", "yes")

    register_forge_approval_hook(_confirm_forge_patch)
    return brain, fw_label, purged_count


def _extract_compact_self_trap(reasoning_list: List[Dict[str, Any]]) -> str:
    """Pull the most informative SELF_TRAP or INITIATIVE one-liner for compact inline display."""
    for item in reasoning_list or []:
        raw = str(item.get("raw_reasoning", ""))
        m = re.search(r"SELF_TRAP\s*:\s*([^\n]+)", raw, re.IGNORECASE)
        if m and m.group(1).strip():
            return f"self_trap : {m.group(1).strip()[:120]}"
        m_init = re.search(r"INITIATIVE\s*:\s*([^\n]+)", raw, re.IGNORECASE)
        if m_init and m_init.group(1).strip():
            return f"initiative: {m_init.group(1).strip()[:120]}"
    return ""


def _render_turn_output(result: Dict[str, Any], brain=None) -> None:
    """Print compact reasoning + tool receipt tree + NEO's prose response + BudgetGuard footer."""
    reasoning = result.get("reasoning") or []
    receipts = result.get("receipts") or []
    verdict = str(result.get("verdict") or "").strip()
    trace_id = str(result.get("trace_id") or "")

    trap_line = _extract_compact_self_trap(reasoning)
    if trap_line or receipts:
        if trap_line:
            print(f"{C_DIM}┌─ reasoning{C_RESET}")
            print(f"{C_DIM}│ {trap_line}{C_RESET}")
        for idx, rec in enumerate(receipts, 1):
            branch = "└─" if idx == len(receipts) else "├─"
            tname = rec.get("tool", "unknown")
            dur = float(rec.get("duration_ms") or 0.0)
            status = str(rec.get("status") or "ok").lower()
            s_col = C_GREEN if status == "success" else (C_YELLOW if status == "blocked" else C_RED)
            s_lbl = "ok" if status == "success" else status
            pad = "." * max(2, 38 - len(tname))
            print(f"{C_DIM}{branch} #{idx} {C_RESET}{tname} {C_DIM}{pad} {dur:.1f}ms{C_RESET}  {s_col}{s_lbl}{C_RESET}")
        print()

    print(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {verdict}")
    bg = getattr(brain, "budget_guard", None) if brain is not None else None
    if bg is not None and trace_id:
        print(f"{C_DIM}      [{bg.get_status(trace_id)}]{C_RESET}")
    print()


def _run_zero_token_walk(arg_str: str, target_device: Optional[str]) -> None:
    """Execute deterministic `$0.00` SP3 `test_packet_walk` directly without spending LLM tokens."""
    from core.panos.ops import test_packet_walk

    tokens = arg_str.split()
    if len(tokens) < 2:
        print(f"{C_YELLOW}Usage: walk <src_ip> <dst_ip> [port=443] [proto=tcp|udp|icmp]{C_RESET}\n")
        return
    src, dst = tokens[0], tokens[1]
    port = tokens[2] if len(tokens) >= 3 else "443"
    proto = tokens[3] if len(tokens) >= 4 else "tcp"
    t0 = time.perf_counter()
    out = test_packet_walk(source=src, destination=dst, port=port, protocol=proto, target_device=target_device)
    ms = (time.perf_counter() - t0) * 1000
    print(f"{C_BOLD}── SP3 PACKET WALK ({ms:.1f}ms · $0.00) ──{C_RESET}\n{out}")


def _run_zero_token_macro(arg_str: str, brain, target_device: Optional[str]) -> None:
    """Execute any read-only `commands.yaml` macro or tool directly at `$0.00`."""
    all_tools = {t.__name__: t for t in brain.keeper.get_all_tools()}
    name = arg_str.strip()
    if not name or name == "list":
        macros = sorted(
            k for k, cfg in (brain.keeper.commands or {}).items()
            if isinstance(cfg, dict) and cfg.get("type") == "macro"
        )
        print(f"{C_BOLD}Available $0.00 Macros:{C_RESET} {', '.join(macros)}\n")
        return
    fn = all_tools.get(name)
    if not fn:
        print(f"{C_YELLOW}Unknown tool/macro '{name}'. Run 'macro list' to see macros.{C_RESET}\n")
        return
    if getattr(brain, "policy", None) and brain.policy.is_write_tool(name) and brain.policy.mode == "READ_ONLY":
        print(f"{C_RED}[blocked] '{name}' is a WRITE tool and policy is READ_ONLY.{C_RESET}\n")
        return
    t0 = time.perf_counter()
    kwargs = {"target_device": target_device} if target_device else {}
    try:
        out = fn(**kwargs)
    except TypeError:
        out = fn()
    ms = (time.perf_counter() - t0) * 1000
    print(f"{C_BOLD}── {name} ({ms:.1f}ms · $0.00) ──{C_RESET}\n{out}\n")


def _print_help(symbiotic: bool = False) -> None:
    pfx = "@" if symbiotic else "/"
    extra = (
        f"  {C_CYAN}@ <question>{C_RESET}     Ask NEO inline (auto-attaches recent scrubbed SSH output)\n"
        if symbiotic
        else f"  {C_CYAN}/grab [lines]{C_RESET}    Capture & scrub last N lines from adjacent tmux SSH pane\n"
    )
    print(
        f"\n{C_BOLD}NEO Commands ({'Symbiotic Single-Prompt SSH' if symbiotic else 'Resident REPL'}):{C_RESET}\n"
        f"{extra}"
        f"  {C_CYAN}{pfx}walk <s> <d> [p] [pr]{C_RESET} Run $0.00 deterministic SP3 packet walk (FIB->PBF->NAT->Policy)\n"
        f"  {C_CYAN}{pfx}macro [name|list]{C_RESET}     Run $0.00 commands.yaml composite macro (e.g. ha_deep_audit)\n"
        f"  {C_CYAN}{pfx}stage{C_RESET}                 Validate & inject last 'set/move/delete' lines into [edit] (no commit)\n"
        f"  {C_CYAN}{pfx}why{C_RESET}                   Show full <REASONING> trace for the last exchange\n"
        f"  {C_CYAN}{pfx}raw <N>{C_RESET}               Show exact raw PAN-OS XML/YAML/CLI output for [Step N]\n"
        f"  {C_CYAN}{pfx}mem{C_RESET}                   Inspect rolling <resident_session_memory> (max 10 turns)\n"
        f"  {C_CYAN}{pfx}board{C_RESET}                 Sync & view Stigmergic Board notes / Drive workorders\n"
        f"  {C_CYAN}{pfx}forge{C_RESET}                 Inspect active #core tool count & staged zero-disk patches\n"
        f"  {C_CYAN}{pfx}audit <query>{C_RESET}         Run strict forensic audit mode (Device Facts + claim referee)\n"
        f"  {C_CYAN}{pfx}export [file.md]{C_RESET}      Compile CAB Markdown report (evidence.py + google_export.py)\n"
        f"  {C_CYAN}{pfx}reset{C_RESET}                 Clear rolling resident session memory\n"
    )


def _execute_brain_turn(
    brain,
    query: str,
    mode: str,
    target_device: Optional[str],
    ssh_context: str = "",
) -> Dict[str, Any]:
    effective_query = query
    if ssh_context:
        effective_query = f"{effective_query}\n\n<ssh_pane_capture>\n{ssh_context}\n</ssh_pane_capture>"

    abort_event = threading.Event()
    prev_sigint = signal.getsignal(signal.SIGINT)

    def _handle_turn_sigint(_sig, _frame):
        abort_event.set()
        sys.stdout.write(f"\r\033[K{C_YELLOW}[aborting turn...]{C_RESET}\n")
        sys.stdout.flush()

    def _on_status(msg: str) -> None:
        clean = str(msg or "").replace("\n", " ").strip()[:110]
        sys.stdout.write(f"\r\033[K{C_DIM}  ⟳ {clean}{C_RESET}")
        sys.stdout.flush()

    signal.signal(signal.SIGINT, _handle_turn_sigint)
    try:
        res = brain.investigate(
            effective_query,
            user_id="ssh-operator",
            status_callback=_on_status,
            target_device=target_device,
            target_mode=mode,
            abort_event=abort_event,
            return_details=True,
        )
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    if isinstance(res, dict):
        _render_turn_output(res, brain=brain)
        return res
    print(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {res}\n")
    return {"verdict": str(res), "receipts": [], "reasoning": [], "trace_id": ""}


def _dispatch_shared_meta_command(
    cmd_body: str,
    brain,
    state_box: Dict[str, Any],
    target_device: Optional[str],
    symbiotic: bool = False,
    pty_master_fd: Optional[int] = None,
    pty_prompt_mode: str = "config",
    ssh_ring_getter: Optional[Callable[[], str]] = None,
) -> bool:
    """
    Shared handler for both `/cmd` (standalone REPL) and `@cmd` (symbiotic SSH).
    Returns True if handled; False if `cmd_body` should be sent as a resident query to NEO.
    """
    q = cmd_body.strip()
    low = q.lower()
    last_result = state_box.get("last_result") or {}

    if low == "help":
        _print_help(symbiotic=symbiotic)
        return True
    if low == "reset":
        brain.reset_resident_session()
        state_box["last_result"] = {}
        print(f"{C_GREEN}[ok] Resident session memory cleared.{C_RESET}\n")
        return True
    if low == "mem":
        snap = brain.get_resident_memory_snapshot()
        if not snap:
            print(f"{C_DIM}[mem] Session memory is empty (0/10 turns).{C_RESET}\n")
        else:
            print(f"{C_BOLD}── SESSION MEMORY ({len(snap)}/10) ──{C_RESET}")
            for idx, item in enumerate(snap, 1):
                tools_str = ", ".join(item.get("tools") or []) or "none"
                print(f"  {C_CYAN}#{idx:02d}{C_RESET} op   : {item.get('operator', '')[:100]}")
                print(f"      tools: {C_DIM}{tools_str}{C_RESET}")
                print(f"      neo  : {item.get('reply', '')[:140]}\n")
        return True
    if low == "board":
        from core.integrations.board_sync import board_ops

        print(f"{C_DIM}{board_ops(action='sync')}{C_RESET}\n")
        return True
    if low == "forge":
        from core.forge.slot_mutator import get_zero_disk_forge_status

        st = get_zero_disk_forge_status()
        cur_tools = len(getattr(brain, "tools", []) or [])
        print(
            f"{C_BOLD}── FORGE STATUS ──{C_RESET}\n"
            f"  Active #core tools : {cur_tools}\n"
            f"  Staged RAM files   : {st['staged_files'] or 'none'}\n"
            f"  Staged RAM diffs   : {st['staged_diff_count']} ({st['staged_diff_paths'] or 'none'})\n"
        )
        return True
    if low == "why":
        r_list = last_result.get("reasoning") or []
        if not r_list:
            print(f"{C_DIM}[why] No <REASONING> trace recorded on the previous turn.{C_RESET}\n")
        else:
            for item in r_list:
                t_num = int(item.get("turn", 0)) + 1
                print(f"{C_BOLD}── REASONING (Turn {t_num}) ──{C_RESET}")
                print(f"{item.get('raw_reasoning', '').strip()}\n")
        return True
    if low.startswith("raw"):
        parts = q.split()
        receipts = last_result.get("receipts") or []
        if len(parts) < 2 or not parts[1].isdigit():
            print(f"{C_YELLOW}Usage: raw <step_number> (1..{len(receipts)}){C_RESET}\n")
            return True
        step_idx = int(parts[1]) - 1
        if step_idx < 0 or step_idx >= len(receipts):
            print(f"{C_YELLOW}Step #{parts[1]} out of range (1..{len(receipts)}).{C_RESET}\n")
            return True
        rec = receipts[step_idx]
        print(
            f"{C_BOLD}── RAW RECEIPT #{step_idx + 1}: {rec.get('tool')} "
            f"({rec.get('status')}, {rec.get('duration_ms')}ms) ──{C_RESET}\n"
            f"Args: {rec.get('args')}\n\n{rec.get('raw_output', '')}\n"
        )
        return True
    if low.startswith("walk"):
        _run_zero_token_walk(q[4:].strip(), target_device)
        return True
    if low.startswith("macro"):
        _run_zero_token_macro(q[5:].strip(), brain, target_device)
        return True
    if low.startswith("export"):
        if not last_result:
            print(f"{C_YELLOW}[export] No completed turn to export yet.{C_RESET}\n")
            return True
        from core.integrations.google_export import generate_incident_markdown

        parts = q.split(maxsplit=1)
        out_path = Path(parts[1]).expanduser() if len(parts) > 1 else (REPO_ROOT / f"neo_report_{last_result.get('trace_id', 'latest')}.md")
        md_doc = generate_incident_markdown(
            query=str(state_box.get("last_query", "")),
            verdict=str(last_result.get("verdict", "")),
            receipts=last_result.get("receipts") or [],
            trace_id=str(last_result.get("trace_id", "cli")),
        )
        out_path.write_text(md_doc, encoding="utf-8")
        print(f"{C_GREEN}[export] Saved CAB report to {out_path}{C_RESET}\n")
        return True
    if low == "stage":
        verdict_txt = str(last_result.get("verdict") or "")
        cand_lines = extract_stageable_panos_lines(verdict_txt)
        if not cand_lines:
            print(f"{C_YELLOW}[stage] No stageable 'set/move/rename/delete' lines found in NEO's last reply.{C_RESET}\n")
            return True
        print(f"{C_BOLD}── CANDIDATE PAN-OS CLI LINES (commit stripped) ──{C_RESET}")
        for i, cl in enumerate(cand_lines, 1):
            print(f"  {C_GREEN}{i:02d}{C_RESET}  {cl}")

        if symbiotic and pty_master_fd is not None:
            confirm = input(f"\n{C_YELLOW}Inject these {len(cand_lines)} line(s) directly into active SSH [edit]? [y/N]: {C_RESET}").strip().lower()
            if confirm not in ("y", "yes"):
                print(f"{C_DIM}[stage] Cancelled.{C_RESET}\n")
                return True
            ok, msg = stage_lines_to_pty_master(pty_master_fd, cand_lines, current_mode=pty_prompt_mode)
            print(f"{C_GREEN if ok else C_RED}[stage] {msg}{C_RESET}\n")
            if ok:
                brain.record_operator_event(f"Injected {len(cand_lines)} candidate CLI line(s) into SSH [edit]: {cand_lines[0][:80]}")
            return True

        pane = find_adjacent_tmux_pane()
        if not pane:
            print(f"\n{C_YELLOW}[standalone] Copy the validated block above into your PAN-OS SSH window.{C_RESET}\n")
            return True
        confirm = input(f"\n{C_YELLOW}Stage these {len(cand_lines)} line(s) into tmux pane {pane} [edit]? [y/N]: {C_RESET}").strip().lower()
        if confirm not in ("y", "yes"):
            print(f"{C_DIM}[stage] Cancelled.{C_RESET}\n")
            return True
        ok, msg = stage_lines_to_tmux_ssh(pane, cand_lines)
        print(f"{C_GREEN if ok else C_RED}[stage] {msg}{C_RESET}\n")
        if ok:
            brain.record_operator_event(f"Staged {len(cand_lines)} candidate CLI line(s) into SSH [edit]: {cand_lines[0][:80]}")
        return True
    if low.startswith("audit "):
        audit_q = q[6:].strip()
        if not audit_q:
            print(f"{C_YELLOW}Usage: audit <question>{C_RESET}\n")
            return True
        ssh_ctx = ssh_ring_getter() if callable(ssh_ring_getter) else ""
        state_box["last_query"] = audit_q
        state_box["last_result"] = _execute_brain_turn(brain, audit_q, "investigate", target_device, ssh_context=ssh_ctx)
        return True

    return False


def run_symbiotic_ssh(ssh_spec: str, explicit_device: Optional[str] = None, verbose: bool = False) -> int:
    """
    Single-Prompt PTY Symbiotic SSH Shell (`--ssh <alias_or_user@ip>`):
    - Spawns real OpenSSH inside a POSIX PTY (`0ms` native Tab/?/arrow/history passthrough).
    - Intercepts `@` typed at column 0 of an empty PAN-OS prompt for inline NEO queries & $0.00 tools.
    - Intercepts `commit` in `#` config mode to run `evaluate_precommit_sanctuary()` ($0.00) BEFORE
      forwarding `Enter` to `mgmtsrvr`.
    """
    if os.name != "posix":
        print(f"{C_RED}Error: '--ssh' PTY symbiosis requires Linux/macOS POSIX pty. Run standalone 'python neo_cli.py' on Windows.{C_RESET}")
        return 1

    import fcntl
    import pty
    import select
    import struct
    import termios
    import tty

    ssh_target, resolved_dev = resolve_ssh_target(ssh_spec, explicit_device=explicit_device)
    stdin_fd = sys.stdin.fileno()
    is_tty = os.isatty(stdin_fd)
    orig_termios = termios.tcgetattr(stdin_fd) if is_tty else None
    raw_active = [False]

    def _enter_raw() -> None:
        if is_tty and orig_termios is not None and not raw_active[0]:
            tty.setraw(stdin_fd)
            raw_active[0] = True

    def _leave_raw() -> None:
        if is_tty and orig_termios is not None and raw_active[0]:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, orig_termios)
            raw_active[0] = False

    @contextmanager
    def _cooked_guard():
        was_raw = raw_active[0]
        if was_raw:
            _leave_raw()
        try:
            yield
        finally:
            if was_raw:
                _enter_raw()

    brain, fw_label, purged_count = bootstrap_secure_runtime(quiet=False, tty_guard_factory=_cooked_guard)
    policy_mode = brain.policy.mode if getattr(brain, "policy", None) else "READ_ONLY"
    tool_count = len(getattr(brain, "tools", []) or [])

    print(
        f"{C_BOLD}{C_GREEN}NEO // SYMBIOTIC SSH{C_RESET}  {C_DIM}│{C_RESET}  "
        f"{ssh_target} ({fw_label})  {C_DIM}│{C_RESET}  #core({tool_count})  {C_DIM}│{C_RESET}  "
        f"{C_YELLOW}{policy_mode}{C_RESET}  {C_DIM}│{C_RESET}  keys-purged:{purged_count}  {C_DIM}│{C_RESET}  "
        f"{C_GREEN}Sanctuary Gate ARMED{C_RESET}"
    )
    print(f"{C_DIM}At any PAN-OS '>' or '#' prompt, type '@' as the first char to invoke NEO ('@help' for commands).{C_RESET}\n")

    master_fd, slave_fd = pty.openpty()

    def _sync_winsize() -> None:
        if not is_tty:
            return
        try:
            packed = fcntl.ioctl(stdin_fd, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, packed)
        except Exception:
            pass

    _sync_winsize()
    proc = subprocess.Popen(
        ["ssh", ssh_target],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)

    prev_winch = signal.getsignal(signal.SIGWINCH)
    signal.signal(signal.SIGWINCH, lambda _s, _f: _sync_winsize())

    authenticated = False
    ssh_ring = ""
    tail_buf = ""
    state_box: Dict[str, Any] = {"last_result": {}, "last_query": ""}

    def _get_scrubbed_ring() -> str:
        return sanitize_ssh_capture(ssh_ring[-8192:]) if authenticated and ssh_ring else ""

    def _intercept_commit_gate() -> bool:
        """Return True if safe/approved to send Enter on `commit`, False to cancel with Ctrl+C."""
        from core.panos.sanctuary import evaluate_precommit_sanctuary

        t0 = time.perf_counter()
        verdict = evaluate_precommit_sanctuary(target_device=resolved_dev)
        ms = (time.perf_counter() - t0) * 1000
        if verdict.get("safe", True):
            return True

        with _cooked_guard():
            print(f"\n\n{C_RED}{C_BOLD}╔══ SANCTUARY PRE-COMMIT INTERCEPT ({ms:.0f}ms · $0.00) ══╗{C_RESET}")
            for w in verdict.get("warnings") or []:
                print(f"{C_YELLOW}  ! {w}{C_RESET}")
            print(f"{C_RED}{C_BOLD}╚════════════════════════════════════════════════════════╝{C_RESET}")
            ans = input(f"{C_YELLOW}Cancel this commit to prevent lockout/outage? [Y/n]: {C_RESET}").strip().lower()
            return ans in ("n", "no")

    try:
        _enter_raw()
        while proc.poll() is None:
            rlist, _, _ = select.select([master_fd, stdin_fd], [], [], 0.1)

            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
                decoded = data.decode("utf-8", errors="replace")
                tail_buf = (tail_buf + decoded)[-512:]
                p_mode = detect_panos_prompt_mode(tail_buf)
                if p_mode is not None:
                    authenticated = True
                if authenticated:
                    ssh_ring = (ssh_ring + decoded)[-12288:]
                    if "configuration committed successfully" in decoded.lower():
                        brain.record_operator_event("Configuration committed in symbiotic SSH session.")

            if stdin_fd in rlist:
                try:
                    in_bytes = os.read(stdin_fd, 1024)
                except OSError:
                    break
                if not in_bytes:
                    break

                echo_mode, echoed_after_prompt = extract_echoed_command_after_prompt(tail_buf)

                # 1. Column-0 '@' Escape at an idle PAN-OS '>' or '#' prompt
                if authenticated and echo_mode is not None and echoed_after_prompt == "" and in_bytes.startswith(b"@"):
                    prefill = in_bytes[1:].decode("utf-8", errors="replace").strip("\r\n")
                    with _cooked_guard():
                        sys.stdout.write(f"{C_CYAN}@{C_RESET} ")
                        sys.stdout.flush()
                        try:
                            rest = read_coalesced_input("") if not prefill or not in_bytes.endswith((b"\r", b"\n")) else ""
                            inline_cmd = (prefill + rest).strip()
                        except (EOFError, KeyboardInterrupt):
                            inline_cmd = ""
                            print()

                        if inline_cmd:
                            handled = _dispatch_shared_meta_command(
                                inline_cmd,
                                brain=brain,
                                state_box=state_box,
                                target_device=resolved_dev,
                                symbiotic=True,
                                pty_master_fd=master_fd,
                                pty_prompt_mode=echo_mode,
                                ssh_ring_getter=_get_scrubbed_ring,
                            )
                            if not handled:
                                state_box["last_query"] = inline_cmd
                                state_box["last_result"] = _execute_brain_turn(
                                    brain,
                                    inline_cmd,
                                    mode="diagnostic",
                                    target_device=resolved_dev,
                                    ssh_context=_get_scrubbed_ring(),
                                )
                    # Ask PAN-OS to reprint its clean prompt line
                    os.write(master_fd, b"\r")
                    continue

                # 2. Pre-Commit Sanctuary Intercept on Enter after `commit` (typed, Tab-expanded, or pasted)
                in_text = in_bytes.decode("utf-8", errors="replace")
                is_enter_on_echoed_commit = (
                    authenticated
                    and echo_mode == "config"
                    and in_bytes in (b"\r", b"\n", b"\r\n")
                    and bool(_COMMIT_CMD_RE.match(echoed_after_prompt))
                )
                pasted_commit_match = (
                    re.search(r"(?:^|[\r\n])\s*commit(?:\s+[^\r\n]*)?[\r\n]", in_text, re.IGNORECASE)
                    if authenticated and len(in_bytes) > 6
                    else None
                )

                if is_enter_on_echoed_commit:
                    if _intercept_commit_gate():
                        os.write(master_fd, b"\r")
                    else:
                        with _cooked_guard():
                            print(f"{C_GREEN}[sanctuary] Cancelled commit (sent Ctrl+C to CLI; candidate config preserved).{C_RESET}")
                        os.write(master_fd, b"\x03")
                    continue

                if pasted_commit_match:
                    # Flush any preceding `set` lines before the `commit` line first, then run Sanctuary gate
                    split_pos = pasted_commit_match.end() - 1
                    prefix_str = in_text[:split_pos]
                    os.write(master_fd, prefix_str.encode("utf-8"))
                    time.sleep(0.35)
                    if _intercept_commit_gate():
                        os.write(master_fd, in_text[split_pos:].encode("utf-8"))
                    else:
                        with _cooked_guard():
                            print(f"{C_GREEN}[sanctuary] Cancelled pasted commit (sent Ctrl+C to CLI).{C_RESET}")
                        os.write(master_fd, b"\x03")
                    continue

                # 3. Default zero-latency passthrough to OpenSSH
                os.write(master_fd, in_bytes)
    finally:
        _leave_raw()
        signal.signal(signal.SIGWINCH, prev_winch)
        try:
            os.close(master_fd)
        except OSError:
            pass
        if proc.poll() is None:
            proc.terminate()

    return proc.returncode or 0


def run_repl(brain, fw_label: str, purged_count: int, target_device: Optional[str] = None) -> int:
    policy_mode = brain.policy.mode if getattr(brain, "policy", None) else "READ_ONLY"
    tool_count = len(getattr(brain, "tools", []) or [])
    tmux_pane = find_adjacent_tmux_pane()
    tmux_status = f"ssh-pane:{tmux_pane}" if tmux_pane else "standalone"

    print(
        f"{C_BOLD}{C_GREEN}NEO // CYBERSEC RESIDENT{C_RESET}  {C_DIM}│{C_RESET}  "
        f"{fw_label}  {C_DIM}│{C_RESET}  #core({tool_count})  {C_DIM}│{C_RESET}  "
        f"{C_YELLOW}{policy_mode}{C_RESET}  {C_DIM}│{C_RESET}  "
        f"keys-purged:{purged_count}  {C_DIM}│{C_RESET}  {tmux_status}"
    )
    print(f"{C_DIM}Type '/help' for commands ('/walk', '/macro', '/stage', '/why', '/raw N', '/exit') or run '--ssh fw-hq'.{C_RESET}\n")

    state_box: Dict[str, Any] = {"last_result": {}, "last_query": ""}
    pending_grab: str = ""

    while True:
        mem_len = len(brain.get_resident_memory_snapshot())
        try:
            raw_in = read_coalesced_input(f"{C_CYAN}neo [{mem_len}/10]{C_RESET} > ")
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        q = raw_in.strip()
        if not q:
            continue

        low = q.lower()
        if low in ("/exit", "/quit", "exit", "quit"):
            break

        if low.startswith("/grab"):
            parts = q.split()
            n_lines = int(parts[1]) if (len(parts) > 1 and parts[1].isdigit()) else 50
            pane = find_adjacent_tmux_pane()
            if not pane:
                print(f"{C_YELLOW}[grab] Not inside a split tmux window ($TMUX unset or single pane).{C_RESET}\n")
                continue
            ok, raw_cap = capture_tmux_pane(pane, lines=n_lines)
            if not ok:
                print(f"{C_RED}[grab] {raw_cap}{C_RESET}\n")
                continue
            pending_grab = sanitize_ssh_capture(raw_cap)
            if "configuration committed successfully" in raw_cap.lower():
                brain.record_operator_event("Configuration committed in adjacent SSH pane.")
            print(
                f"{C_GREEN}[ok] Captured & scrubbed {len(pending_grab.splitlines())} lines from {pane} "
                f"(attached automatically to your next prompt).{C_RESET}\n"
            )
            continue

        if q.startswith("/"):
            handled = _dispatch_shared_meta_command(
                q[1:],
                brain=brain,
                state_box=state_box,
                target_device=target_device,
                symbiotic=False,
            )
            if handled:
                continue

        effective_query = q
        ssh_context = ""
        if "@ssh" in effective_query:
            pane = find_adjacent_tmux_pane()
            if pane:
                ok, raw_cap = capture_tmux_pane(pane, lines=50)
                if ok:
                    if "configuration committed successfully" in raw_cap.lower():
                        brain.record_operator_event("Configuration committed in adjacent SSH pane.")
                    ssh_context = sanitize_ssh_capture(raw_cap)
            effective_query = effective_query.replace("@ssh", "(see attached <ssh_pane_capture>)").strip()
        elif pending_grab:
            ssh_context = pending_grab
            pending_grab = ""

        state_box["last_query"] = q
        state_box["last_result"] = _execute_brain_turn(
            brain,
            effective_query,
            mode="diagnostic",
            target_device=target_device,
            ssh_context=ssh_context,
        )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NEO — PAN-OS Cybersec Resident & Symbiotic SSH Shell")
    parser.add_argument(
        "--ssh",
        type=str,
        default=None,
        metavar="ALIAS_OR_HOST",
        help="Wrap OpenSSH in a single symbiotic prompt (e.g. '--ssh fw-hq' or '--ssh admin@192.168.1.254')",
    )
    parser.add_argument("--device", type=str, default=None, help="Target firewall alias from config/devices.yaml")
    parser.add_argument("--check", action="store_true", help="Run pre-flight startup check and exit")
    parser.add_argument("-q", "--query", type=str, default=None, help="Execute a single query and exit")
    parser.add_argument("--verbose", action="store_true", help="Show INFO-level internal pipeline logs")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.check:
        load_dotenv(dotenv_path=REPO_ROOT / ".env", override=True)
        from core.utils.startup_validator import run_preflight_check

        ok, _ = run_preflight_check(quiet=False)
        return 0 if ok else 1

    if args.ssh:
        return run_symbiotic_ssh(args.ssh, explicit_device=args.device, verbose=args.verbose)

    brain, fw_label, purged_count = bootstrap_secure_runtime(quiet=bool(args.query))
    if args.query:
        res = brain.investigate(
            args.query,
            user_id="ssh-operator",
            target_device=args.device,
            target_mode="diagnostic",
            return_details=True,
        )
        _render_turn_output(res, brain=brain)
        return 0

    return run_repl(brain, fw_label, purged_count, target_device=args.device)


if __name__ == "__main__":
    sys.exit(main())
