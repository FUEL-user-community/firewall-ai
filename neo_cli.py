#!/usr/bin/env python3
"""
NEO — In-Process PAN-OS Cybersec Resident CLI (`neo_cli.py`).

Zero listening network ports. Keys are consumed once into sealed RAM and purged
from `os.environ` before Turn 1. Runs standalone in any terminal or inside `tmux`
right beside `ssh admin@<firewall-ip>`.
"""

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent

# Standard stdout ANSI codes (never alternate-screen, preserving native mouse copy-paste into SSH)
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
    """Scrub secrets and drop credential-bearing lines from `@ssh` / `/grab` pane captures."""
    from core.safety.scrubber import scrub, scrub_registered_secrets

    if not raw_pane_text:
        return ""
    kept: List[str] = []
    for line in raw_pane_text.splitlines():
        if _SSH_SECRET_LINE_RE.search(line):
            kept.append("[REDACTED_CREDENTIAL_LINE]")
        else:
            kept.append(line)
    joined = "\n".join(kept)
    return scrub_registered_secrets(scrub(joined)).strip()


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
    Inspect the last non-empty line of the SSH pane:
    Returns `'config'` if at `user@host#`, `'op'` if at `user@host>`, or `None` if not at PAN-OS CLI.
    """
    non_empty = [ln.rstrip() for ln in (pane_tail or "").splitlines() if ln.strip()]
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


def stage_lines_to_tmux_ssh(pane_id: str, commands: List[str], step_delay: float = 0.35) -> Tuple[bool, str]:
    """
    Safely stage validated `set|move|rename|delete` lines into an adjacent PAN-OS SSH pane:
    1. Verify prompt is idle at PAN-OS `>` or `#` (never Linux bash `$` or `--more--`).
    2. Enter `configure` (if at `>`) or `top` (if already at `#`, escaping sub-hierarchies).
    3. Inject one line at a time using literal `send-keys -l`, polling `capture-pane` after
       each line and aborting immediately on `Invalid syntax` / `Unknown command` / `Server error`.
    4. NEVER sends `commit`.
    """
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


def bootstrap_secure_runtime(quiet: bool = False):
    """Load .env, tighten file permissions, warm clients, and purge secrets from os.environ."""
    env_file = REPO_ROOT / ".env"
    load_dotenv(dotenv_path=env_file, override=True)
    os.environ["HITL_MODE"] = "terminal"

    from core.brain import CoreBrain
    from core.forge.slot_mutator import register_forge_approval_hook
    from core.integrations.gdrive_client import GoogleDriveClient
    from core.integrations.secrets import enforce_secret_file_permissions, seal_runtime_secrets
    from core.panos.client import PanOSClientPool

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

    def _confirm_forge_patch(touched_paths: List[str], diff_preview: str) -> bool:
        if not sys.stdin.isatty():
            return False
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


def _render_turn_output(result: Dict[str, Any]) -> None:
    """Print compact reasoning + tool receipt tree + NEO's prose response."""
    reasoning = result.get("reasoning") or []
    receipts = result.get("receipts") or []
    verdict = str(result.get("verdict") or "").strip()

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

    print(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {verdict}\n")


def _print_help() -> None:
    print(
        f"\n{C_BOLD}NEO SSH/tmux Commands:{C_RESET}\n"
        f"  {C_CYAN}/why{C_RESET}            Show full <REASONING> trace for the last exchange\n"
        f"  {C_CYAN}/raw <N>{C_RESET}        Show exact raw PAN-OS XML/YAML/CLI output for [Step N]\n"
        f"  {C_CYAN}/stage{C_RESET}          Validate & stage last 'set/move/delete' lines into tmux SSH [edit] (never commits)\n"
        f"  {C_CYAN}/grab [lines]{C_RESET}   Capture & scrub last N lines (default 50) from adjacent tmux SSH pane\n"
        f"  {C_CYAN}@ssh{C_RESET}            Include '@ssh' anywhere in a question to attach scrubbed SSH pane output\n"
        f"  {C_CYAN}/mem{C_RESET}            Inspect rolling <resident_session_memory> (max 10 turns)\n"
        f"  {C_CYAN}/board{C_RESET}          Sync & view Stigmergic Board notes / Drive workorders\n"
        f"  {C_CYAN}/forge{C_RESET}          Inspect active #core tool count & staged zero-disk patches\n"
        f"  {C_CYAN}/audit <query>{C_RESET}  Run strict forensic audit mode (Device Facts + claim referee)\n"
        f"  {C_CYAN}/export [file]{C_RESET}  Save last exchange + raw receipts to Markdown report\n"
        f"  {C_CYAN}/reset{C_RESET}          Clear rolling resident session memory\n"
        f"  {C_CYAN}/exit{C_RESET}           Quit NEO and release all in-RAM state\n"
    )


def run_repl(brain, fw_label: str, purged_count: int, target_device: Optional[str] = None) -> int:
    policy_mode = brain.policy_engine.mode if getattr(brain, "policy_engine", None) else "READ_ONLY"
    tool_count = len(getattr(brain, "tools", []) or [])
    tmux_pane = find_adjacent_tmux_pane()
    tmux_status = f"ssh-pane:{tmux_pane}" if tmux_pane else "standalone"

    print(
        f"{C_BOLD}{C_GREEN}NEO // CYBERSEC RESIDENT{C_RESET}  {C_DIM}│{C_RESET}  "
        f"{fw_label}  {C_DIM}│{C_RESET}  #core({tool_count})  {C_DIM}│{C_RESET}  "
        f"{C_YELLOW}{policy_mode}{C_RESET}  {C_DIM}│{C_RESET}  "
        f"env-keys-purged:{purged_count}  {C_DIM}│{C_RESET}  {tmux_status}"
    )
    print(f"{C_DIM}Type '/help' for SSH commands ('/why', '/raw N', '/stage', '@ssh', '/reset', '/exit').{C_RESET}\n")

    last_result: Dict[str, Any] = {}
    last_query: str = ""
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
        if low == "/help":
            _print_help()
            continue
        if low == "/reset":
            brain.reset_resident_session()
            last_result = {}
            pending_grab = ""
            print(f"{C_GREEN}[ok] Resident session memory cleared.{C_RESET}\n")
            continue
        if low == "/mem":
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
            continue
        if low == "/board":
            from core.integrations.board_sync import board_ops

            print(f"{C_DIM}{board_ops(action='sync')}{C_RESET}\n")
            continue
        if low == "/forge":
            from core.forge.slot_mutator import get_zero_disk_forge_status

            st = get_zero_disk_forge_status()
            cur_tools = len(getattr(brain, "tools", []) or [])
            print(
                f"{C_BOLD}── FORGE STATUS ──{C_RESET}\n"
                f"  Active #core tools : {cur_tools}\n"
                f"  Staged RAM files   : {st['staged_files'] or 'none'}\n"
                f"  Staged RAM diffs   : {st['staged_diff_count']} ({st['staged_diff_paths'] or 'none'})\n"
            )
            continue
        if low == "/why":
            r_list = last_result.get("reasoning") or []
            if not r_list:
                print(f"{C_DIM}[why] No <REASONING> trace recorded on the previous turn.{C_RESET}\n")
            else:
                for item in r_list:
                    t_num = int(item.get("turn", 0)) + 1
                    print(f"{C_BOLD}── REASONING (Turn {t_num}) ──{C_RESET}")
                    print(f"{item.get('raw_reasoning', '').strip()}\n")
            continue
        if low.startswith("/raw"):
            parts = q.split()
            receipts = last_result.get("receipts") or []
            if len(parts) < 2 or not parts[1].isdigit():
                print(f"{C_YELLOW}Usage: /raw <step_number> (1..{len(receipts)}){C_RESET}\n")
                continue
            step_idx = int(parts[1]) - 1
            if step_idx < 0 or step_idx >= len(receipts):
                print(f"{C_YELLOW}Step #{parts[1]} out of range (1..{len(receipts)}).{C_RESET}\n")
                continue
            rec = receipts[step_idx]
            print(
                f"{C_BOLD}── RAW RECEIPT #{step_idx + 1}: {rec.get('tool')} "
                f"({rec.get('status')}, {rec.get('duration_ms')}ms) ──{C_RESET}\n"
                f"Args: {rec.get('args')}\n\n{rec.get('raw_output', '')}\n"
            )
            continue
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
        if low == "/stage":
            verdict_txt = str(last_result.get("verdict") or "")
            cand_lines = extract_stageable_panos_lines(verdict_txt)
            if not cand_lines:
                print(f"{C_YELLOW}[stage] No stageable 'set/move/rename/delete' lines found in NEO's last reply.{C_RESET}\n")
                continue
            print(f"{C_BOLD}── CANDIDATE PAN-OS CLI LINES (commit stripped) ──{C_RESET}")
            for i, cl in enumerate(cand_lines, 1):
                print(f"  {C_GREEN}{i:02d}{C_RESET}  {cl}")
            pane = find_adjacent_tmux_pane()
            if not pane:
                print(f"\n{C_YELLOW}[standalone] No adjacent tmux SSH pane detected — copy the validated block above.{C_RESET}\n")
                continue
            confirm = input(f"\n{C_YELLOW}Stage these {len(cand_lines)} line(s) into tmux pane {pane} [edit]? [y/N]: {C_RESET}").strip().lower()
            if confirm not in ("y", "yes"):
                print(f"{C_DIM}[stage] Cancelled.{C_RESET}\n")
                continue
            ok, msg = stage_lines_to_tmux_ssh(pane, cand_lines)
            col = C_GREEN if ok else C_RED
            print(f"{col}[stage] {msg}{C_RESET}\n")
            if ok:
                brain.record_operator_event(f"Staged {len(cand_lines)} candidate CLI line(s) into SSH [edit]: {cand_lines[0][:80]}")
            continue
        if low.startswith("/export"):
            if not last_result:
                print(f"{C_YELLOW}[export] No completed turn to export yet.{C_RESET}\n")
                continue
            from core.integrations.google_export import generate_incident_markdown

            parts = q.split(maxsplit=1)
            out_path = Path(parts[1]).expanduser() if len(parts) > 1 else (REPO_ROOT / f"neo_report_{last_result.get('trace_id', 'latest')}.md")
            md_doc = generate_incident_markdown(
                query=last_query,
                verdict=str(last_result.get("verdict", "")),
                receipts=last_result.get("receipts") or [],
                trace_id=str(last_result.get("trace_id", "cli")),
            )
            out_path.write_text(md_doc, encoding="utf-8")
            print(f"{C_GREEN}[export] Saved report to {out_path}{C_RESET}\n")
            continue

        # Mode selection ('diagnostic' resident default, or '/audit <query>' for strict forensic report)
        mode = "diagnostic"
        effective_query = q
        if low.startswith("/audit "):
            mode = "investigate"
            effective_query = q[7:].strip()
            if not effective_query:
                print(f"{C_YELLOW}Usage: /audit <question>{C_RESET}\n")
                continue

        # Expand inline '@ssh' or attach pending '/grab' capture
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

        if ssh_context:
            effective_query = (
                f"{effective_query}\n\n"
                f"<ssh_pane_capture>\n{ssh_context}\n</ssh_pane_capture>"
            )

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
            last_result = res
            last_query = q
            _render_turn_output(res)
        else:
            print(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {res}\n")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NEO — In-Process PAN-OS Cybersec Resident CLI")
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

    brain, fw_label, purged_count = bootstrap_secure_runtime(quiet=bool(args.query))
    if args.query:
        res = brain.investigate(
            args.query,
            user_id="ssh-operator",
            target_device=args.device,
            target_mode="diagnostic",
            return_details=True,
        )
        _render_turn_output(res)
        return 0

    return run_repl(brain, fw_label, purged_count, target_device=args.device)


if __name__ == "__main__":
    sys.exit(main())
