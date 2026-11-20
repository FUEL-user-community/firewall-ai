#!/usr/bin/env python3
"""
NEO - PAN-OS CLI assistant (`neo_cli.py`).

No listening network ports. API keys are loaded once into an in-process store and removed
from `os.environ` before the first SSH session or model call.

Modes:
  1. SSH wrapper (Linux / macOS / WSL):
       python3 neo_cli.py --ssh fw-hq
       python3 neo_cli.py --ssh admin@192.168.1.254
     Runs your real OpenSSH session in a local PTY (native Tab / ? / history), adds `@` commands
     at an idle prompt, keeps a scrubbed 8 KB window of recent output for context, and runs a
     local pre-commit safety check before `commit` reaches the firewall.
  2. Standalone REPL (any OS, optional tmux side pane):
       python3 neo_cli.py
  3. One-shot / preflight:
       python3 neo_cli.py -q "check mgt permitted-ip"
       python3 neo_cli.py --check
"""

import warnings

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse
from contextlib import contextmanager
import logging
import os
import re
import shutil
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


_VT100_TOKEN_RE = re.compile(r"\x1b\][^\x07]*\x07|\x1b\[([0-9;?]*)([a-zA-Z])")


def fold_vt100_line_edits(raw_text: str) -> str:
    """
    Replay VT100 in-line cursor edits (`\\x08`/`\\x7f` backspaces, `\\r` carriage overwrites,
    and `\\x1b[K` / `\\x1b[2K` / `\\x1b[P` erases) per line so `tail_buf` matches exact visual prompt text.
    """
    if not raw_text:
        return ""
    normalized = raw_text.replace("\r\n", "\n")
    folded_lines: List[str] = []
    for raw_line in normalized.split("\n"):
        buf: List[str] = []
        pos = 0
        idx = 0
        n_len = len(raw_line)
        while idx < n_len:
            ch = raw_line[idx]
            if ch == "\x1b":
                m = _VT100_TOKEN_RE.match(raw_line, idx)
                if m:
                    params, code = m.group(1), m.group(2)
                    if code == "K":
                        if params == "2":
                            buf.clear()
                            pos = 0
                        elif params in ("", "0"):
                            del buf[pos:]
                    elif code == "D":
                        step = int(params) if params and params.isdigit() else 1
                        pos = max(0, pos - step)
                    elif code == "C":
                        step = int(params) if params and params.isdigit() else 1
                        pos = min(len(buf), pos + step)
                    elif code == "P":
                        cnt = int(params) if params and params.isdigit() else 1
                        del buf[pos : pos + cnt]
                    idx = m.end()
                    continue
                idx += 1
                continue
            if ch == "\r":
                pos = 0
            elif ch in ("\x08", "\x7f"):
                if pos > 0:
                    pos -= 1
                    del buf[pos : pos + 1]
            elif ch >= " " or ch == "\t":
                if pos < len(buf):
                    buf[pos] = ch
                else:
                    buf.append(ch)
                pos += 1
            idx += 1
        folded_lines.append("".join(buf))
    return "\n".join(folded_lines)


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
    clean = strip_ansi(fold_vt100_line_edits(pane_tail))
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
    `('config'|'op'|None, 'commit force')`. Handles Tab-completed, history-recalled, and backspaced commands.
    """
    clean = strip_ansi(fold_vt100_line_edits(line_buf)).split("\n")[-1]
    m = re.match(r"^\s*[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?:\([^)]+\))?([>#])\s*(.*)$", clean)
    if not m:
        return None, ""
    mode = "config" if m.group(1) == "#" else "op"
    return mode, m.group(2).strip()


def extract_raw_after_prompt(line_buf: str) -> Tuple[Optional[str], str]:
    """Like extract_echoed_command_after_prompt, but preserves trailing spaces after '+' or '|'."""
    clean = strip_ansi(fold_vt100_line_edits(line_buf)).split("\n")[-1]
    m = re.match(r"^\s*[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?:\([^)]+\))?([>#])(.*)$", clean)
    if not m:
        return None, ""
    mode = "config" if m.group(1) == "#" else "op"
    after = m.group(2)
    if after.startswith(" "):
        after = after[1:]
    return mode, after


def normalize_dual_neo_query(raw_query: str) -> str:
    """Normalize inline NEO query text (stripping optional '@question ' or '@ask ' lead-in)."""
    q = (raw_query or "").strip()
    q = re.sub(r"^(?:question|ask)\s+", "", q, flags=re.IGNORECASE).strip()
    return q


def parse_dual_plane_split(raw_after_prompt: str, in_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Detect `<ssh_cmd> + @ <neo_query>` (parallel t=0ms) or `<ssh_cmd> | @ <neo_query>` (pipe SSH -> NEO):
      1. Interactive keystroke: user typed `<ssh_cmd> + ` (already in `raw_after_prompt`) and just hit `@`.
      2. Full-line paste: user pasted `<ssh_cmd> + @ <neo_query>` at an empty prompt (`raw_after_prompt == ""`).
    Ignores `+`/`|` inside quotes and email addresses without whitespace before `+` (e.g. `ops+tag@corp.com`).
    """
    if not in_bytes:
        return None

    # Case 1: Interactive '@' typed right after `<ssh_cmd> +` or `<ssh_cmd> |`
    if in_bytes.startswith(b"@") and raw_after_prompt.strip():
        if raw_after_prompt.count('"') % 2 == 0 and raw_after_prompt.count("'") % 2 == 0:
            m = re.match(r"^(.*\S)(\s+)([+|])(\s*)$", raw_after_prompt)
            if m:
                ssh_cmd, ws_pre, op_char, ws_post = m.group(1), m.group(2), m.group(3), m.group(4)
                erase_count = len(ws_pre) + 1 + len(ws_post)
                prefill = in_bytes[1:].decode("utf-8", errors="replace").strip("\r\n")
                return {
                    "kind": "interactive",
                    "ssh_cmd": ssh_cmd,
                    "op": op_char,
                    "erase_count": erase_count,
                    "prefill": prefill,
                    "has_newline": in_bytes.endswith((b"\r", b"\n")),
                }

    # Case 2: Full-line paste `<ssh_cmd> + @ <neo_query>` at an idle prompt
    if not raw_after_prompt.strip() and len(in_bytes) > 4:
        in_text = in_bytes.decode("utf-8", errors="replace")
        single = in_text.strip("\r\n")
        if "\n" not in single and "\r" not in single:
            m = re.match(r"^(.+?\S)\s+([+|])\s*@(.*)$", single)
            if m and m.group(1).count('"') % 2 == 0 and m.group(1).count("'") % 2 == 0:
                return {
                    "kind": "pasted",
                    "ssh_cmd": m.group(1).strip(),
                    "op": m.group(2),
                    "neo_query": normalize_dual_neo_query(m.group(3)),
                    "has_newline": in_bytes.endswith((b"\r", b"\n")),
                }

    return None


def drain_pty_ssh_command(
    master_fd: int,
    max_wait: float = 12.0,
    max_pages: int = 25,
    echo_stdout: bool = True,
) -> str:
    """
    Execute the currently staged SSH CLI line on `master_fd`, auto-advancing PAN-OS `--more--`
    pages up to `max_pages` and streaming clean output until the `>` or `#` prompt returns.
    """
    import select

    os.write(master_fd, b"\r")
    collected: List[str] = []
    pages_seen = 0
    deadline = time.time() + max_wait

    while time.time() < deadline:
        rlist, _, _ = select.select([master_fd], [], [], 0.08)
        if not rlist:
            tail_check = "".join(collected)[-512:]
            if tail_check and detect_panos_prompt_mode(tail_check) is not None:
                break
            continue
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            break
        if not chunk:
            break

        dec = chunk.decode("utf-8", errors="replace")
        if "--more--" in strip_ansi(dec).lower():
            dec = re.sub(r"(?:lines\s+\d+-\d+\s*)?--more--\s*", "", dec, flags=re.IGNORECASE)
            pages_seen += 1
            os.write(master_fd, b" " if pages_seen <= max_pages else b"q")

        collected.append(dec)
        if echo_stdout and dec:
            os.write(sys.stdout.fileno(), dec.encode("utf-8", errors="replace"))

        if detect_panos_prompt_mode("".join(collected)[-512:]) is not None:
            break

    return "".join(collected)


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


def parse_pty_help_completions(help_text: str) -> List[str]:
    """
    Extract clean valid keyword/object completions from PAN-OS CLI `?` output
    (e.g. `  action         Specify action` -> `action`), ignoring prompts and `--more--`.
    """
    if not help_text:
        return []
    seen: List[str] = []
    for raw_ln in strip_ansi(fold_vt100_line_edits(help_text)).splitlines():
        ln = raw_ln.strip()
        if not ln or ln.startswith("^") or _PANOS_CLI_ERROR_RE.search(ln):
            continue
        if re.match(r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?:\([^)]+\))?[>#]", ln):
            continue
        m = re.match(r"^(<cr>|[a-zA-Z0-9_./:-]+|\[\s*\S*)\s{2,}.*$", ln)
        if not m:
            m = re.match(r"^(<cr>|[a-zA-Z0-9_./:-]+)$", ln)
        if m:
            tok = m.group(1).strip()
            if tok and tok not in seen:
                seen.append(tok)
    return seen[:25]


def probe_pty_cli_grammar(
    master_fd: int,
    commands: List[str],
    current_mode: str = "config",
    timeout_per_probe: float = 1.8,
) -> Dict[str, Any]:
    """
    Non-destructive `local` PAN-OS SSH PTY `?` Grammar Oracle:
    - Enters `configure` / `top` on `master_fd`.
    - Probes each candidate `set|move|rename|delete` line with `?` (NO `\\r` execution!),
      auto-quits `--more--` if completions paginate, and immediately sends `Ctrl+C` (`\\x03`)
      to clear `mgmtsrvr`'s readline buffer so ZERO partial mutations occur on syntax failure.
    - If any line fails live `?` grammar, walks prefixes (`<prefix> ?`) to pinpoint the exact
      diverging token and return the live valid completions for this exact PAN-OS build.
    """
    import select

    def _drain_until_config_prompt(max_wait: float, allow_echoed: bool = False) -> str:
        collected = bytearray()
        deadline = time.time() + max_wait
        while time.time() < deadline:
            rlist, _, _ = select.select([master_fd], [], [], 0.06)
            if not rlist:
                dec_now = collected.decode("utf-8", errors="replace")
                if detect_panos_prompt_mode(dec_now) == "config":
                    break
                if allow_echoed and extract_echoed_command_after_prompt(dec_now)[0] == "config":
                    break
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            dec_chunk = chunk.decode("utf-8", errors="replace")
            if "--more--" in strip_ansi(dec_chunk).lower():
                os.write(master_fd, b"q")
            collected.extend(chunk)
            dec_all = collected.decode("utf-8", errors="replace")
            if detect_panos_prompt_mode(dec_all) == "config":
                break
            if allow_echoed and extract_echoed_command_after_prompt(dec_all)[0] == "config":
                break
        return strip_ansi(fold_vt100_line_edits(collected.decode("utf-8", errors="replace")))

    def _probe_single_expr(expr: str) -> str:
        os.write(master_fd, (expr + "?").encode("utf-8"))
        help_out = _drain_until_config_prompt(timeout_per_probe, allow_echoed=True)
        # Clear unexecuted input buffer with Ctrl+C so mgmtsrvr returns to an empty '#' prompt
        os.write(master_fd, b"\x03")
        _drain_until_config_prompt(0.8, allow_echoed=False)
        return help_out

    prep = "configure" if current_mode == "op" else "top"
    os.write(master_fd, (prep + "\r").encode("utf-8"))
    prep_out = _drain_until_config_prompt(timeout_per_probe, allow_echoed=False)
    if _PANOS_CLI_ERROR_RE.search(prep_out):
        return {
            "passed": False,
            "prep_failed": True,
            "error": f"Failed to enter top [edit] hierarchy: {prep_out.strip()[-120:]}",
        }

    for idx, cmd in enumerate(commands, 1):
        probe_out = _probe_single_expr(cmd)
        err_m = _PANOS_CLI_ERROR_RE.search(probe_out)
        if not err_m:
            continue

        # Pinpoint exact invalid token & harvest live PAN-OS '?' completions at the valid prefix
        tokens = cmd.split()
        valid_prefix = ""
        invalid_tok = tokens[-1] if tokens else cmd
        valid_completions: List[str] = []
        probe_steps = 0
        for k in range(len(tokens) - 1, 0, -1):
            if probe_steps >= 6:
                break
            probe_steps += 1
            pfx_candidate = " ".join(tokens[:k])
            pfx_out = _probe_single_expr(pfx_candidate + " ")
            if not _PANOS_CLI_ERROR_RE.search(pfx_out):
                valid_prefix = pfx_candidate
                invalid_tok = tokens[k]
                valid_completions = parse_pty_help_completions(pfx_out)
                break

        return {
            "passed": False,
            "prep_failed": False,
            "failed_index": idx,
            "failed_line": cmd,
            "error": err_m.group(1),
            "valid_prefix": valid_prefix,
            "invalid_token": invalid_tok,
            "valid_completions": valid_completions,
        }

    return {
        "passed": True,
        "verified_count": len(commands),
    }


def parse_panos_counter_deltas(counter_output: str) -> List[Dict[str, str]]:
    """Extract hardware `show counter global filter packet-filter yes delta yes` rows."""
    if not counter_output:
        return []
    rows: List[Dict[str, str]] = []
    for raw_ln in strip_ansi(counter_output).splitlines():
        ln = raw_ln.strip()
        if not ln or ln.startswith(("-", "Global", "name", "Elapsed", "Total")):
            continue
        m = re.match(
            r"^([a-z0-9_]+)\s+(\d+)\s+(\d+)\s+(drop|warn|info|error)\s+(\S+)\s+(\S+)\s+(.*)$",
            ln,
            re.IGNORECASE,
        )
        if m:
            rows.append(
                {
                    "name": m.group(1),
                    "value": m.group(2),
                    "rate": m.group(3),
                    "severity": m.group(4).lower(),
                    "category": m.group(5),
                    "aspect": m.group(6),
                    "description": m.group(7).strip(),
                }
            )
    return rows


def run_pty_tac_packet_diag(
    master_fd: int,
    arg_str: str,
    current_mode: str = "op",
    confirm_fn: Optional[Callable[[str], bool]] = None,
) -> Tuple[bool, str, str]:
    """
    Bounded `local` TAC L3 `packet-diag` & Hardware ASIC Counter Delta Bracket:
    - Validates `<src_ip> <dst_ip> [port] [seconds=3.5]` strictly via `ipaddress`.
    - Prefixes `run ` automatically if operator is currently inside `#` (`[edit]`).
    - Checks `debug dataplane packet-diag show setting` first so pre-existing filters aren't clobbered silently.
    - Arms bidirectional (`src->dst` + `dst->src`) packet filters, primes `delta yes`, holds capture window,
      collects `delta yes` + `show session all`, and ALWAYS disarms `filter off` + `capture off` in `finally:`.
    Returns `(ok, formatted_summary, raw_scrubbed_trace)`.
    """
    import ipaddress

    parts = [p for p in (arg_str or "").split() if p.strip()]
    if len(parts) < 2:
        return (
            False,
            "Usage: @diag <src_ip> <dst_ip> [dst_port] [window_sec=3.5]",
            "",
        )

    try:
        src_ip = str(ipaddress.ip_address(parts[0].strip()))
        dst_ip = str(ipaddress.ip_address(parts[1].strip()))
    except ValueError as ve:
        return False, f"Invalid IP address for @diag: {ve}", ""

    dst_port: Optional[int] = None
    window_sec: float = 3.5
    for extra_tok in parts[2:4]:
        if "." in extra_tok:
            try:
                window_sec = max(1.0, min(10.0, float(extra_tok)))
            except ValueError:
                return False, f"Invalid capture window '{extra_tok}' (expected 1.0..10.0s).", ""
        elif extra_tok.isdigit():
            val = int(extra_tok)
            if 1 <= val <= 10 and dst_port is not None:
                window_sec = float(val)
            elif 1 <= val <= 65535:
                dst_port = val
            else:
                return False, f"Port '{extra_tok}' out of range (1..65535).", ""

    run_pfx = "run " if current_mode == "config" else ""

    def _exec_cli(cli_line: str, echo: bool = False, max_wait: float = 6.0) -> str:
        os.write(master_fd, cli_line.encode("utf-8"))
        return drain_pty_ssh_command(master_fd, max_wait=max_wait, max_pages=10, echo_stdout=echo)

    # 1. Pre-check if another admin already left packet-diag filter enabled
    pre_setting = _exec_cli(f"{run_pfx}debug dataplane packet-diag show setting", echo=False, max_wait=4.0)
    already_enabled = bool(
        re.search(r"Packet filter[\s\S]{0,120}?Enabled\s*:\s*yes", strip_ansi(pre_setting), re.IGNORECASE)
    )
    if already_enabled and callable(confirm_fn):
        if not confirm_fn("packet-diag filter is already enabled on dp0. Override and disarm after capture? [y/N]: "):
            return False, "[diag] Cancelled (existing packet-diag filter left untouched).", ""

    raw_chunks: List[str] = []
    delta_out = ""
    sess_out = ""
    interrupted = False
    port_clause = f" destination-port {dst_port}" if dst_port else ""

    try:
        _exec_cli(f"{run_pfx}debug dataplane packet-diag clear filter", echo=False)
        _exec_cli(
            f"{run_pfx}debug dataplane packet-diag set filter match source {src_ip} destination {dst_ip}{port_clause}",
            echo=False,
        )
        _exec_cli(
            f"{run_pfx}debug dataplane packet-diag set filter match source {dst_ip} destination {src_ip}",
            echo=False,
        )
        _exec_cli(f"{run_pfx}debug dataplane packet-diag set filter on", echo=False)

        # Prime baseline hardware delta counters at t=0
        _exec_cli(f"{run_pfx}show counter global filter packet-filter yes delta yes", echo=False)

        sys.stdout.write(
            f"{C_CYAN}[diag] Armed dp0 bidirectional filter ({src_ip} <-> {dst_ip}"
            f"{f':{dst_port}' if dst_port else ''}) — sampling {window_sec:.1f}s (Ctrl+C to finish early)...{C_RESET}"
        )
        sys.stdout.flush()
        try:
            deadline = time.time() + window_sec
            while time.time() < deadline:
                time.sleep(min(0.2, max(0.01, deadline - time.time())))
        except KeyboardInterrupt:
            interrupted = True

        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

        delta_cmd = f"{run_pfx}show counter global filter packet-filter yes delta yes"
        sess_cmd = f"{run_pfx}show session all filter source {src_ip} destination {dst_ip}"
        delta_out = _exec_cli(delta_cmd, echo=False)
        sess_out = _exec_cli(sess_cmd, echo=False)
        raw_chunks.append(f"$ {delta_cmd}\n{strip_ansi(delta_out)}")
        raw_chunks.append(f"$ {sess_cmd}\n{strip_ansi(sess_out)}")
    finally:
        # HARD SAFETY INVARIANT: Always disarm packet-diag on dp0 even on Ctrl+C or PTY error
        for disarm_cmd in (
            f"{run_pfx}debug dataplane packet-diag set filter off",
            f"{run_pfx}debug dataplane packet-diag set capture off",
            f"{run_pfx}debug dataplane packet-diag clear filter",
        ):
            try:
                _exec_cli(disarm_cmd, echo=False, max_wait=3.0)
            except Exception:
                pass

    rows = parse_panos_counter_deltas(delta_out)
    drops_warns = [r for r in rows if r["severity"] in ("drop", "warn", "error")]
    info_rows = [r for r in rows if r["severity"] not in ("drop", "warn", "error")]

    lines: List[str] = [
        f"{C_BOLD}── PACKET-DIAG COUNTER DELTA ({src_ip} <-> {dst_ip}{f':{dst_port}' if dst_port else ''}, local) ──{C_RESET}",
        f"{C_GREEN}[disarmed]{C_RESET} dp0 packet-diag filter=off, capture=off, filter=cleared (0 residual load)"
        + (" [stopped early]" if interrupted else ""),
    ]
    if drops_warns:
        lines.append(f"\n{C_RED}{C_BOLD}ASIC Drop / Warn Counters Triggered ({len(drops_warns)}):{C_RESET}")
        for r in drops_warns[:12]:
            col = C_RED if r["severity"] in ("drop", "error") else C_YELLOW
            lines.append(
                f"  {col}[{r['severity'].upper()}]{C_RESET} {C_BOLD}{r['name']}{C_RESET} "
                f"(+{r['value']} pkts, {r['rate']}/s) — {r['description']}"
            )
    elif info_rows:
        lines.append(f"\n{C_GREEN}Zero ASIC drop/warn counters during window ({len(info_rows)} info counter(s) incremented):{C_RESET}")
        for r in info_rows[:8]:
            lines.append(f"  [INFO] {r['name']} (+{r['value']}) — {r['description']}")
    else:
        lines.append(
            f"\n{C_YELLOW}Zero matching packets hit dp0 during the {window_sec:.1f}s window "
            f"(verify traffic generator or upstream L2/routing before this firewall).{C_RESET}"
        )

    clean_sess = "\n".join(
        ln
        for ln in strip_ansi(sess_out).splitlines()
        if ln.strip() and not re.match(r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?:\([^)]+\))?[>#]", ln.strip())
    ).strip()
    if clean_sess:
        lines.append(f"\n{C_BOLD}Matching Live Session Table:{C_RESET}\n{clean_sess}")

    lines.append(f"\n{C_DIM}Captured into SSH context — type '@ explain drops' to correlate against SP3 config.{C_RESET}")
    scrubbed_trace = sanitize_ssh_capture("\n\n".join(raw_chunks)[-8192:])
    return True, "\n".join(lines), scrubbed_trace


def extract_panos_test_match_tuple(cmd_text: str) -> Optional[Dict[str, str]]:
    """
    Detect single-table PAN-OS CLI `test security-policy-match ...` or `test nat-policy-match ...`
    commands and extract `(source, destination, port, protocol)` so NEO can automatically check
    whether Post-DNAT zone shifts, PBF, or `[edit]` candidate rules contradict the CLI `test` output.
    """
    clean = re.sub(r"^run\s+", "", (cmd_text or "").strip(), flags=re.IGNORECASE)
    if not re.match(r"^test\s+(?:security-policy-match|nat-policy-match)\b", clean, re.IGNORECASE):
        return None
    src_m = re.search(r"\bsource\s+([0-9a-fA-F.:]+)", clean, re.IGNORECASE)
    dst_m = re.search(r"\bdestination\s+([0-9a-fA-F.:]+)", clean, re.IGNORECASE)
    if not src_m or not dst_m:
        return None
    port_m = re.search(r"\bdestination-port\s+(\d+)", clean, re.IGNORECASE)
    proto_m = re.search(r"\bprotocol\s+(\d+|tcp|udp|icmp)\b", clean, re.IGNORECASE)
    app_m = re.search(r"\bapplication\s+([a-zA-Z0-9_.-]+)", clean, re.IGNORECASE)
    return {
        "source": src_m.group(1),
        "destination": dst_m.group(1),
        "port": port_m.group(1) if port_m else "443",
        "protocol": proto_m.group(1) if proto_m else "6",
        "application": app_m.group(1) if app_m else "",
    }


def stage_lines_to_pty_master(
    master_fd: int,
    commands: List[str],
    current_mode: str = "config",
    timeout_per_cmd: float = 2.0,
    skip_prep: bool = False,
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

    if not skip_prep:
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


def render_markdown_ansi(text: str) -> str:
    """Convert Markdown bold, inline code, headings, and fenced blocks into crisp ANSI terminal text."""
    if not text:
        return ""
    norm = re.sub(r"\n{3,}", "\n\n", text.replace("\r\n", "\n")).strip()
    lines_out: List[str] = []
    in_fence = False
    for raw_line in norm.split("\n"):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            if not in_fence:
                in_fence = True
                hdr = f"── {lang} ──" if lang else "──────"
                lines_out.append(f"{C_DIM}{hdr}{C_RESET}")
            else:
                in_fence = False
                lines_out.append(f"{C_DIM}──────{C_RESET}")
            continue
        if in_fence:
            lines_out.append(f"  {C_CYAN}{raw_line}{C_RESET}")
            continue

        heading_m = re.match(r"^(#{1,4})\s+(.*)$", raw_line)
        if heading_m:
            lines_out.append(f"{C_BOLD}{C_CYAN}{heading_m.group(2).strip()}{C_RESET}")
            continue

        fmt_line = re.sub(r"\*\*([^*\n]+)\*\*", rf"{C_BOLD}\1{C_RESET}", raw_line)
        fmt_line = re.sub(r"`([^`\n]+)`", rf"{C_CYAN}\1{C_RESET}", fmt_line)
        lines_out.append(fmt_line)
    return "\n".join(lines_out)


def _emit_or_page(block_text: str) -> None:
    """Print inline when short; automatically pipe tall outputs through `less -RFX` for native scrolling."""
    if not block_text:
        return
    text_out = block_text if block_text.endswith("\n") else block_text + "\n"
    try:
        term_rows = shutil.get_terminal_size((100, 28)).lines
    except Exception:
        term_rows = 28

    use_pager = (
        os.getenv("NEO_PAGER", "1").strip() != "0"
        and sys.stdout.isatty()
        and sys.stdin.isatty()
        and text_out.count("\n") >= max(16, term_rows - 4)
        and bool(shutil.which("less"))
    )
    if use_pager:
        try:
            subprocess.run(["less", "-RFX"], input=text_out, text=True, check=False)
            return
        except Exception:
            pass
    sys.stdout.write(text_out)
    sys.stdout.flush()


def _render_turn_output(result: Dict[str, Any], brain=None) -> None:
    """Format compact reasoning + tool receipt tree + ANSI-rendered prose + BudgetGuard footer."""
    reasoning = result.get("reasoning") or []
    receipts = result.get("receipts") or []
    verdict = str(result.get("verdict") or "").strip()
    trace_id = str(result.get("trace_id") or "")

    buf_lines: List[str] = []
    trap_line = _extract_compact_self_trap(reasoning)
    if trap_line or receipts:
        if trap_line:
            buf_lines.append(f"{C_DIM}┌─ reasoning{C_RESET}")
            buf_lines.append(f"{C_DIM}│ {trap_line}{C_RESET}")
        total = len(receipts)
        for idx, rec in enumerate(receipts, 1):
            if trap_line:
                branch = "└─" if idx == total else "├─"
            elif total == 1:
                branch = "──"
            elif idx == 1:
                branch = "┌─"
            elif idx == total:
                branch = "└─"
            else:
                branch = "├─"
            tname = rec.get("tool", "unknown")
            dur = float(rec.get("duration_ms") or 0.0)
            status = str(rec.get("status") or "ok").lower()
            s_col = C_GREEN if status == "success" else (C_YELLOW if status == "blocked" else C_RED)
            s_lbl = "ok" if status == "success" else status
            pad = "." * max(2, 38 - len(tname))
            buf_lines.append(
                f"{C_DIM}{branch} #{idx} {C_RESET}{tname} {C_DIM}{pad} {dur:.1f}ms{C_RESET}  {s_col}{s_lbl}{C_RESET}"
            )
        buf_lines.append("")

    rendered_verdict = render_markdown_ansi(verdict)
    buf_lines.append(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {rendered_verdict}")
    bg = getattr(brain, "budget_guard", None) if brain is not None else None
    if bg is not None and trace_id:
        buf_lines.append(f"{C_DIM}      [{bg.get_status(trace_id)}]{C_RESET}")
    buf_lines.append("")
    _emit_or_page("\n".join(buf_lines))


def _run_zero_token_walk(arg_str: str, target_device: Optional[str]) -> None:
    """Execute deterministic `local` SP3 `test_packet_walk` (+ Candidate `[edit]` walk when dirty or `--candidate`)."""
    import yaml as _yaml
    from core.panos.ops import test_packet_walk
    from core.panos.sanctuary import get_pending_candidate_changes

    raw_tokens = [t for t in arg_str.split() if t.strip()]
    force_cand = False
    tokens: List[str] = []
    for tok in raw_tokens:
        if tok.lower() in ("--candidate", "-c", "candidate"):
            force_cand = True
        else:
            tokens.append(tok)

    if len(tokens) < 2:
        print(f"{C_YELLOW}Usage: walk <src_ip> <dst_ip> [port=443] [proto=tcp|udp|icmp] [--candidate]{C_RESET}\n")
        return
    src, dst = tokens[0], tokens[1]
    port = tokens[2] if len(tokens) >= 3 else "443"
    proto = tokens[3] if len(tokens) >= 4 else "tcp"
    t0 = time.perf_counter()
    pending = get_pending_candidate_changes(target_device=target_device)
    want_cand = bool(pending or force_cand)
    try:
        out = test_packet_walk(
            source=src,
            destination=dst,
            port=port,
            protocol=proto,
            target_device=target_device,
            include_candidate=want_cand,
        )
    except TypeError:
        out = test_packet_walk(source=src, destination=dst, port=port, protocol=proto, target_device=target_device)
    ms = (time.perf_counter() - t0) * 1000

    cand_banner = ""
    try:
        parsed = _yaml.safe_load(out) if isinstance(out, str) and not out.startswith("ERROR:") else None
    except Exception:
        parsed = None

    if isinstance(parsed, dict) and isinstance(parsed.get("running_vs_candidate_delta"), dict):
        delta = parsed["running_vs_candidate_delta"]
        c_walk = parsed.get("candidate_edit_walk") or {}
        if delta.get("verdict_changed") == "indeterminate":
            changed_tag = f"{C_YELLOW}INDETERMINATE (unresolved objects){C_RESET}"
        elif delta.get("verdict_changed"):
            changed_tag = f"{C_YELLOW}VERDICT SHIFT IN [edit]{C_RESET}"
        else:
            changed_tag = f"{C_GREEN}MATCHES RUNNING{C_RESET}"
        banner_lines = [
            f"{C_BOLD}┌─ PRE-COMMIT [edit] vs. COMMITTED SP3 COMPARISON ({delta.get('pending_edit_count', 0)} uncommitted edit(s)) · {changed_tag}{C_RESET}",
            f"│ {C_DIM}COMMITTED RUNNING :{C_RESET} {delta.get('running_verdict')}",
            f"└ {C_CYAN}CANDIDATE [edit]  :{C_RESET} {C_BOLD}{delta.get('candidate_verdict')}{C_RESET}"
            + (
                f"  {C_YELLOW}[DNAT -> {c_walk.get('translated_destination')}]{C_RESET}"
                if c_walk.get("translated_destination")
                else ""
            ),
        ]
        for reason in c_walk.get("indeterminate_reasons") or []:
            banner_lines.append(f"  {C_YELLOW}? {reason}{C_RESET}")
        if c_walk.get("indeterminate_reasons"):
            banner_lines.append(
                f"  {C_DIM}Best-effort if unresolved objects do NOT match: "
                f"'{c_walk.get('best_effort_rule_if_unresolved_objects_do_not_match')}'. "
                f"Commit + live 'test security-policy-match' is authoritative.{C_RESET}"
            )
        for sh in c_walk.get("shadowed_later_rules") or []:
            banner_lines.append(
                f"  {C_RED}! SHADOW WARNING:{C_RESET} Later candidate rule {sh} also matches this flow "
                f"but is shadowed by #{c_walk.get('rule_index')} '{c_walk.get('security_rule')}'."
            )
        cand_banner = "\n".join(banner_lines) + "\n\n"
    elif pending:
        cand_banner = (
            f"{C_YELLOW}[NOTE: {len(pending)} uncommitted candidate edit(s) exist in [edit] — "
            f"run '@diff' to audit candidate changes.]{C_RESET}\n"
        )

    _emit_or_page(f"{C_BOLD}── SP3 PACKET WALK ({ms:.1f}ms, local) ──{C_RESET}\n{cand_banner}{out}\n")


def _run_zero_token_macro(arg_str: str, brain, target_device: Optional[str]) -> None:
    """Execute any read-only `commands.yaml` macro or tool directly at `local`."""
    all_tools = {t.__name__: t for t in brain.keeper.get_all_tools()}
    name = arg_str.strip()
    if not name or name == "list":
        macros = sorted(
            k for k, cfg in (brain.keeper.commands or {}).items()
            if isinstance(cfg, dict) and cfg.get("type") == "macro"
        )
        print(f"{C_BOLD}Available local Macros:{C_RESET} {', '.join(macros)}\n")
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
    _emit_or_page(f"{C_BOLD}── {name} ({ms:.1f}ms, local) ──{C_RESET}\n{out}\n")


def _print_help(symbiotic: bool = False) -> None:
    pfx = "@" if symbiotic else "/"
    extra = (
        f"  {C_CYAN}@ <question>{C_RESET}          Ask NEO (recent scrubbed SSH output is attached automatically)\n"
        f"  {C_CYAN}<cmd> + @ <question>{C_RESET}  Run the SSH command and the NEO question at the same time\n"
        f"  {C_CYAN}<cmd> | @ <question>{C_RESET}  Run the SSH command, then hand its output to NEO\n"
        f"  {C_CYAN}@diag <s> <d> [p] [t]{C_RESET} packet-diag + global drop-counter delta; filters always disarmed (needs '@write diag')\n"
        if symbiotic
        else f"  {C_CYAN}/grab [lines]{C_RESET}         Capture & scrub the last N lines from the adjacent tmux SSH pane\n"
    )
    forge_lines = (
        f"  {C_CYAN}{pfx}board{C_RESET}                 [experimental] Drive board sync\n"
        f"  {C_CYAN}{pfx}forge{C_RESET}                 [experimental] Self-patching status\n"
        if _forge_enabled()
        else ""
    )
    print(
        f"\n{C_BOLD}NEO commands ({'SSH wrapper' if symbiotic else 'standalone'}):{C_RESET}\n"
        f"{extra}"
        f"  {C_CYAN}{pfx}walk <s> <d> [p] [pr]{C_RESET} Packet walk: FIB -> PBF -> NAT -> security (committed, plus candidate if edited). Local.\n"
        f"  {C_CYAN}{pfx}diff{C_RESET}                  Pre-commit review of candidate changes. Local.\n"
        f"  {C_CYAN}{pfx}macro [name|list]{C_RESET}     Run a read-only command bundle from config/commands.yaml. Local.\n"
        f"  {C_CYAN}{pfx}stage{C_RESET}                 Syntax-check NEO's last 'set' lines with '?' and inject into [edit] (needs '@write on')\n"
        f"  {C_CYAN}{pfx}write [on|diag|off]{C_RESET}   Write policy for API tools and SSH writes (default READ_ONLY)\n"
        f"  {C_CYAN}{pfx}log [N]{C_RESET}               Show the last N change-provenance entries and verify the hash chain\n"
        f"  {C_CYAN}{pfx}why{C_RESET}                   Show the reasoning trace for the last answer\n"
        f"  {C_CYAN}{pfx}raw <N>{C_RESET}               Show the raw firewall output behind [Step N]\n"
        f"  {C_CYAN}{pfx}mem{C_RESET}                   Show session memory (last 10 turns)\n"
        f"  {C_CYAN}{pfx}audit <question>{C_RESET}      Formal report mode with code-computed facts and citation checks\n"
        f"  {C_CYAN}{pfx}export [file.md]{C_RESET}      Save the last answer as a change-review Markdown report\n"
        f"{forge_lines}"
        f"  {C_CYAN}{pfx}reset{C_RESET}                 Clear session memory\n"
    )


def _build_sp3_cross_plane_overlay(ssh_cmd: str, target_device: Optional[str]) -> str:
    """
    When the operator runs `test security-policy-match ...` or `test nat-policy-match ...` in SSH
    alongside `+ @` or `| @`, run a `local` full 6-stage SP3 walk (+ Candidate `[edit]` check)
    so NEO immediately catches Post-DNAT zone shifts, PBF overrides, or uncommitted `[edit]` deltas.
    """
    tup = extract_panos_test_match_tuple(ssh_cmd)
    if not tup:
        return ""
    try:
        from core.panos.ops import test_packet_walk

        sp3_yaml = test_packet_walk(
            source=tup["source"],
            destination=tup["destination"],
            port=tup["port"],
            protocol=tup["protocol"],
            application=tup["application"] or None,
            target_device=target_device,
        )
        if sp3_yaml and not sp3_yaml.startswith("ERROR:"):
            return (
                f"\n\n<sp3_cross_plane_verification command={ssh_cmd!r}>\n"
                f"{sp3_yaml.strip()}\n"
                f"</sp3_cross_plane_verification>"
            )
    except Exception:
        pass
    return ""


def execute_dual_plane_turn(
    ssh_cmd: str,
    op_char: str,
    neo_raw_cmd: str,
    master_fd: int,
    echo_mode: str,
    brain,
    state_box: Dict[str, Any],
    target_device: Optional[str],
    ssh_ring_snapshot: str,
    ssh_ring_appender: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Execute `<ssh_cmd> + @ <neo_cmd>` (concurrent t=0ms SSH + XML-API) or
    `<ssh_cmd> | @ <neo_cmd>` (pipe fresh SSH command output directly into NEO).
    Returns the raw SSH output captured from `master_fd` so the caller can append to `ssh_ring`.
    """
    neo_cmd = normalize_dual_neo_query(neo_raw_cmd)
    if not neo_cmd:
        return drain_pty_ssh_command(master_fd, echo_stdout=True)

    # Pipe mode (`| @`): drain SSH command first (~150ms), then feed its scrubbed output directly to NEO
    if op_char == "|":
        raw_ssh_out = drain_pty_ssh_command(master_fd, echo_stdout=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
        sp3_overlay = _build_sp3_cross_plane_overlay(ssh_cmd, target_device)
        piped_ctx = sanitize_ssh_capture(f"$ {ssh_cmd}\n{raw_ssh_out}"[-8192:]) + sp3_overlay
        handled = _dispatch_shared_meta_command(
            neo_cmd,
            brain=brain,
            state_box=state_box,
            target_device=target_device,
            symbiotic=True,
            pty_master_fd=master_fd,
            pty_prompt_mode=echo_mode,
            ssh_ring_getter=lambda: piped_ctx,
            ssh_ring_appender=ssh_ring_appender,
        )
        if not handled:
            state_box["last_query"] = neo_cmd
            state_box["last_result"] = _execute_brain_turn(
                brain,
                neo_cmd,
                mode="diagnostic",
                target_device=target_device,
                ssh_context=piped_ctx,
            )
        return raw_ssh_out

    # Parallel mode (`+ @`): check if `neo_cmd` is a shared meta-command vs. concurrent LLM turn
    low = neo_cmd.lower()
    is_llm_audit = low.startswith("audit ") and bool(neo_cmd[6:].strip())
    is_meta_only = not is_llm_audit and (
        low in ("help", "diff", "reset", "mem", "board", "forge", "why", "stage")
        or low.startswith(("write", "raw", "walk", "macro", "export", "diag"))
    )

    if is_meta_only:
        raw_ssh_out = drain_pty_ssh_command(master_fd, echo_stdout=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
        _dispatch_shared_meta_command(
            neo_cmd,
            brain=brain,
            state_box=state_box,
            target_device=target_device,
            symbiotic=True,
            pty_master_fd=master_fd,
            pty_prompt_mode=echo_mode,
            ssh_ring_getter=lambda: ssh_ring_snapshot,
            ssh_ring_appender=ssh_ring_appender,
        )
        return raw_ssh_out

    # True t=0ms Concurrent Dispatch: launch XML-API + Gemini worker thread BEFORE draining SSH PTY
    eff_mode = "investigate" if is_llm_audit else "diagnostic"
    eff_query = neo_cmd[6:].strip() if is_llm_audit else neo_cmd
    full_query = (
        f"{eff_query}\n\n<ssh_pane_capture>\n{ssh_ring_snapshot}\n</ssh_pane_capture>"
        if ssh_ring_snapshot
        else eff_query
    )
    wants_sp3_overlay = extract_panos_test_match_tuple(ssh_cmd) is not None

    abort_event = threading.Event()
    ssh_draining = [True]
    latest_status = [""]
    res_holder: Dict[str, Any] = {}
    err_holder: List[Exception] = []
    prev_sigint = signal.getsignal(signal.SIGINT)

    def _handle_dual_sigint(_sig, _frame):
        abort_event.set()
        if not ssh_draining[0]:
            sys.stdout.write(f"\r\033[K{C_YELLOW}[aborting turn...]{C_RESET}\n")
            sys.stdout.flush()

    def _buffered_status(msg: str) -> None:
        clean = str(msg or "").replace("\n", " ").strip()[:110]
        latest_status[0] = clean
        if not ssh_draining[0]:
            sys.stdout.write(f"\r\033[K{C_DIM}  ⟳ {clean}{C_RESET}")
            sys.stdout.flush()

    def _bg_worker() -> None:
        try:
            # SP3 cross-plane overlay runs INSIDE the worker so the SSH command executes at t=0ms
            worker_query = full_query
            if wants_sp3_overlay and not abort_event.is_set():
                _buffered_status("SP3 cross-plane verification of 'test *-policy-match' tuple (local)...")
                worker_query += _build_sp3_cross_plane_overlay(ssh_cmd, target_device)
            res_holder["res"] = brain.investigate(
                worker_query,
                user_id="ssh-operator",
                status_callback=_buffered_status,
                target_device=target_device,
                target_mode=eff_mode,
                abort_event=abort_event,
                return_details=True,
            )
        except Exception as exc:
            err_holder.append(exc)

    signal.signal(signal.SIGINT, _handle_dual_sigint)
    worker = threading.Thread(target=_bg_worker, name="neo-dual-plane", daemon=True)
    try:
        worker.start()
        raw_ssh_out = drain_pty_ssh_command(master_fd, echo_stdout=True)
        sys.stdout.write("\n")
        sys.stdout.flush()
        ssh_draining[0] = False
        if worker.is_alive() and latest_status[0]:
            sys.stdout.write(f"\r\033[K{C_DIM}  ⟳ {latest_status[0]}{C_RESET}")
            sys.stdout.flush()
        while worker.is_alive():
            worker.join(timeout=0.1)
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    if err_holder:
        print(f"{C_RED}[error] Concurrent query failed: {err_holder[0]}{C_RESET}\n")
        return raw_ssh_out

    res = res_holder.get("res")
    state_box["last_query"] = eff_query
    if isinstance(res, dict):
        state_box["last_result"] = res
        _render_turn_output(res, brain=brain)
    elif res is not None:
        state_box["last_result"] = {"verdict": str(res), "receipts": [], "reasoning": [], "trace_id": ""}
        print(f"{C_GREEN}{C_BOLD}neo >{C_RESET} {res}\n")
    return raw_ssh_out


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


def _policy_mode(brain) -> str:
    pol = getattr(brain, "policy", None)
    mode = getattr(pol, "mode", None) if pol is not None else None
    return mode if isinstance(mode, str) else "READ_ONLY"


def _pty_policy_block(brain, action: str) -> Optional[str]:
    """
    Single policy plane: PTY writes (`@stage`, `@diag`) obey the same PolicyEngine mode as API write tools.
    `@diag` additionally needs an explicit session opt-in because it runs `debug dataplane` commands that the
    API-side CommandFilter forbids.
    """
    mode = _policy_mode(brain)
    if mode != "READ_WRITE":
        return (
            f"[{action}] Blocked: write policy is {mode}. SSH-channel writes follow the same policy as API tools "
            f"— run '@write on' first."
        )
    if action == "diag" and getattr(brain, "_pty_diag_enabled", False) is not True:
        return (
            "[diag] Blocked: packet-diag runs 'debug dataplane' commands, which the API command filter forbids. "
            "Enable explicitly for this session with '@write diag'."
        )
    return None


def _audit(event: str, **fields: Any) -> None:
    """Record a provenance event; never raises."""
    try:
        from core.safety.audit_log import record_audit_event

        record_audit_event(event, **fields)
    except Exception:
        pass


def build_neo_commit_suffix(trace_id: str) -> str:
    """Return the ` description "NEO-assisted <trace>"` suffix appended to a bare `commit` (PAN-OS-safe charset)."""
    clean = re.sub(r"[^A-Za-z0-9_.:-]", "", str(trace_id or "cli"))[:48] or "cli"
    return f' description "NEO-assisted {clean}"'


def _forge_enabled() -> bool:
    return os.getenv("NEO_ENABLE_FORGE", "").strip().lower() in ("1", "true", "yes", "on")


def _dispatch_shared_meta_command(
    cmd_body: str,
    brain,
    state_box: Dict[str, Any],
    target_device: Optional[str],
    symbiotic: bool = False,
    pty_master_fd: Optional[int] = None,
    pty_prompt_mode: str = "config",
    ssh_ring_getter: Optional[Callable[[], str]] = None,
    ssh_ring_appender: Optional[Callable[[str], None]] = None,
) -> bool:
    """
    Ctrl+C containment wrapper: a KeyboardInterrupt raised mid-PTY-probe, mid-`@diag`, or mid-`@stage`
    must cancel ONLY the NEO action (clearing any half-typed CLI line with `\\x03`), never propagate into
    `run_symbiotic_ssh()`'s `finally: proc.terminate()` and kill the operator's live SSH session.
    """
    try:
        return _dispatch_shared_meta_command_impl(
            cmd_body,
            brain=brain,
            state_box=state_box,
            target_device=target_device,
            symbiotic=symbiotic,
            pty_master_fd=pty_master_fd,
            pty_prompt_mode=pty_prompt_mode,
            ssh_ring_getter=ssh_ring_getter,
            ssh_ring_appender=ssh_ring_appender,
        )
    except KeyboardInterrupt:
        if symbiotic and pty_master_fd is not None:
            try:
                os.write(pty_master_fd, b"\x03")
            except OSError:
                pass
        sys.stdout.write(
            f"\r\033[K{C_YELLOW}[neo] Action interrupted (Ctrl+C) — SSH session preserved; "
            f"run 'show config diff' in [edit] if a stage was in progress.{C_RESET}\n"
        )
        sys.stdout.flush()
        try:
            brain.record_operator_event(f"Operator interrupted NEO action '{cmd_body.strip()[:60]}' with Ctrl+C.")
        except Exception:
            pass
        return True


def _dispatch_shared_meta_command_impl(
    cmd_body: str,
    brain,
    state_box: Dict[str, Any],
    target_device: Optional[str],
    symbiotic: bool = False,
    pty_master_fd: Optional[int] = None,
    pty_prompt_mode: str = "config",
    ssh_ring_getter: Optional[Callable[[], str]] = None,
    ssh_ring_appender: Optional[Callable[[str], None]] = None,
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
    if low == "diff":
        from core.panos.sanctuary import summarize_candidate_diff

        t0 = time.perf_counter()
        diff_out = summarize_candidate_diff(target_device=target_device)
        ms = (time.perf_counter() - t0) * 1000
        _emit_or_page(f"{C_BOLD}── CANDIDATE PRE-COMMIT DIFF ({ms:.1f}ms, local) ──{C_RESET}\n{diff_out}\n")
        return True
    if low == "write" or low.startswith("write "):
        sub = q[5:].strip().lower()
        pol = getattr(brain, "policy", None)
        if pol is None:
            print(f"{C_RED}[write] PolicyEngine unavailable.{C_RESET}\n")
            return True
        if sub in ("", "status"):
            diag_state = "enabled" if getattr(brain, "_pty_diag_enabled", False) is True else "disabled"
            print(
                f"{C_BOLD}[write]{C_RESET} Policy {C_YELLOW}{pol.mode}{C_RESET} applies to API tools AND SSH-channel "
                f"writes (@stage). packet-diag (@diag): {diag_state}. Every write still needs your [y/N].\n"
            )
            return True
        if sub == "on":
            pol.mode = "READ_WRITE"
            os.environ["POLICY_MODE"] = "READ_WRITE"
            if getattr(brain, "tool_executor", None) is not None and getattr(brain.tool_executor, "policy", None) is not None:
                brain.tool_executor.policy.mode = "READ_WRITE"
            _audit("policy_change", mode="READ_WRITE")
            print(
                f"{C_YELLOW}[write] READ_WRITE for this session (API tools + @stage). "
                f"Every write still requires your [y/N]; '@write diag' separately enables @diag.{C_RESET}\n"
            )
            return True
        if sub == "diag":
            if pol.mode != "READ_WRITE":
                print(f"{C_YELLOW}[write] Run '@write on' first; @diag is only available in READ_WRITE.{C_RESET}\n")
                return True
            brain._pty_diag_enabled = True
            _audit("policy_change", mode="READ_WRITE", diag_enabled=True)
            print(
                f"{C_YELLOW}[write] @diag enabled for this session (runs 'debug dataplane packet-diag'; "
                f"filters are always disarmed afterwards).{C_RESET}\n"
            )
            return True
        if sub == "off":
            pol.mode = "READ_ONLY"
            os.environ["POLICY_MODE"] = "READ_ONLY"
            if getattr(brain, "tool_executor", None) is not None and getattr(brain.tool_executor, "policy", None) is not None:
                brain.tool_executor.policy.mode = "READ_ONLY"
            brain._pty_diag_enabled = False
            _audit("policy_change", mode="READ_ONLY", diag_enabled=False)
            print(f"{C_GREEN}[write] Back to READ_ONLY (API tools, @stage and @diag all blocked).{C_RESET}\n")
            return True
        print(f"{C_YELLOW}Usage: write [on|diag|off|status]{C_RESET}\n")
        return True
    if low == "log" or low.startswith("log "):
        from core.safety.audit_log import read_recent_audit_events, verify_audit_chain

        n_arg = q[3:].strip()
        limit = int(n_arg) if n_arg.isdigit() else 10
        ok_chain, count, bad_line = verify_audit_chain()
        chain_msg = (
            f"{C_GREEN}chain intact ({count} entries){C_RESET}"
            if ok_chain
            else f"{C_RED}CHAIN BROKEN at line {bad_line} — log was edited or truncated{C_RESET}"
        )
        rows = [f"{C_BOLD}── CHANGE PROVENANCE LOG · {chain_msg} ──{C_RESET}"]
        for ev in read_recent_audit_events(limit):
            detail = ev.get("lines") or ev.get("result") or ev.get("decision") or ev.get("mode") or ""
            if isinstance(detail, list):
                detail = f"{len(detail)} line(s): {detail[0][:70] if detail else ''}"
            rows.append(f"  {ev.get('ts', '')}  {C_CYAN}{ev.get('event', ''):<18}{C_RESET} {str(detail)[:100]}")
        _emit_or_page("\n".join(rows) + "\n")
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
    if low in ("board", "forge") and not _forge_enabled():
        print(f"{C_DIM}[{low}] Experimental self-patching / Drive board is disabled (set NEO_ENABLE_FORGE=1 to enable).{C_RESET}\n")
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
            why_blocks = []
            for item in r_list:
                t_num = int(item.get("turn", 0)) + 1
                why_blocks.append(
                    f"{C_BOLD}── REASONING (Turn {t_num}) ──{C_RESET}\n{item.get('raw_reasoning', '').strip()}\n"
                )
            _emit_or_page("\n".join(why_blocks))
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
        _emit_or_page(
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
    if low == "diag" or low.startswith("diag "):
        if not symbiotic or pty_master_fd is None:
            print(
                f"{C_YELLOW}[diag] packet-diag needs the SSH wrapper "
                f"(run 'python3 neo_cli.py --ssh fw-hq').{C_RESET}\n"
            )
            return True
        blocked = _pty_policy_block(brain, "diag")
        if blocked:
            print(f"{C_YELLOW}{blocked}{C_RESET}\n")
            _audit("diag_blocked", args=q[4:].strip(), reason=blocked)
            return True
        ok_d, summary_d, trace_d = run_pty_tac_packet_diag(
            pty_master_fd,
            q[4:].strip(),
            current_mode=pty_prompt_mode,
            confirm_fn=lambda prompt_msg: input(f"{C_YELLOW}{prompt_msg}{C_RESET}").strip().lower() in ("y", "yes"),
        )
        _emit_or_page(summary_d + "\n")
        _audit("diag_executed", args=q[4:].strip(), result="ok" if ok_d else "failed")
        if ok_d and trace_d:
            if callable(ssh_ring_appender):
                ssh_ring_appender(f"\n[TAC_PACKET_DIAG]\n{trace_d}\n")
            brain.record_operator_event(f"Executed bounded packet-diag ({q[4:].strip()}); filters disarmed.")
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
        stage_trace = str(last_result.get("trace_id") or "cli")
        _audit("stage_proposed", trace_id=stage_trace, lines=list(cand_lines))

        if symbiotic and pty_master_fd is not None:
            blocked = _pty_policy_block(brain, "stage")
            if blocked:
                print(f"\n{C_YELLOW}{blocked}{C_RESET}\n{C_DIM}(Or copy the lines above by hand.){C_RESET}\n")
                _audit("stage_blocked", trace_id=stage_trace, reason=blocked)
                return True
            pano = state_box.get("panorama") or {}
            if pano.get("managed"):
                print(
                    f"\n{C_YELLOW}[panorama] This firewall is Panorama-managed ({pano.get('detail')}). Local candidate "
                    f"edits can be overwritten by the next template / device-group push.{C_RESET}"
                )
            confirm = input(f"\n{C_YELLOW}Check syntax with '?' & inject {len(cand_lines)} line(s) into SSH [edit]? [y/N]: {C_RESET}").strip().lower()
            if confirm not in ("y", "yes"):
                print(f"{C_DIM}[stage] Cancelled.{C_RESET}\n")
                _audit("stage_decision", trace_id=stage_trace, decision="rejected")
                return True
            _audit("stage_decision", trace_id=stage_trace, decision="approved", lines=list(cand_lines))

            t_gram = time.perf_counter()
            gram = probe_pty_cli_grammar(pty_master_fd, cand_lines, current_mode=pty_prompt_mode)
            g_ms = (time.perf_counter() - t_gram) * 1000

            if not gram.get("passed"):
                if gram.get("prep_failed"):
                    print(f"{C_RED}[grammar] {gram.get('error')}{C_RESET}\n")
                    return True
                valid_opts = ", ".join(gram.get("valid_completions") or []) or "none returned"
                print(
                    f"\n{C_RED}{C_BOLD}[syntax] BLOCKED BEFORE INJECTION ({g_ms:.0f}ms, local, 0 lines mutated in [edit]):{C_RESET}\n"
                    f"  Line #{gram.get('failed_index')}: {C_YELLOW}{gram.get('failed_line')}{C_RESET}\n"
                    f"  Invalid token : {C_RED}{gram.get('invalid_token')}{C_RESET} ({gram.get('error')})\n"
                    f"  Valid prefix  : {C_CYAN}{gram.get('valid_prefix') or '<root>'}{C_RESET}\n"
                    f"  Valid tokens from the firewall's '?' at that point: {C_GREEN}{valid_opts}{C_RESET}"
                )
                fix_ans = input(
                    f"\n{C_YELLOW}Ask NEO to fix the line using those tokens? [Y/n]: {C_RESET}"
                ).strip().lower()
                if fix_ans in ("n", "no"):
                    print(f"{C_DIM}[stage] Left [edit] untouched.{C_RESET}\n")
                    return True

                repair_prompt = (
                    "Your previous PAN-OS CLI block failed live SSH PTY '?' grammar pre-validation on this exact "
                    f"firewall build BEFORE execution.\n"
                    f"- Failing line #{gram.get('failed_index')}: `{gram.get('failed_line')}`\n"
                    f"- Rejected token: `{gram.get('invalid_token')}` ({gram.get('error')})\n"
                    f"- Last valid prefix: `{gram.get('valid_prefix')}`\n"
                    f"- Exact valid child tokens returned by live `mgmtsrvr` `?` at that cursor: [{valid_opts}]\n"
                    f"- Full original candidate block:\n```panos\n" + "\n".join(cand_lines) + "\n```\n"
                    "Output ONLY the corrected `panos` fenced `set`/`move` block strictly obeying those live `?` tokens."
                )
                state_box["last_query"] = "stage-grammar-repair"
                repaired_res = _execute_brain_turn(
                    brain,
                    repair_prompt,
                    mode="diagnostic",
                    target_device=target_device,
                    ssh_context=ssh_ring_getter() if callable(ssh_ring_getter) else "",
                )
                state_box["last_result"] = repaired_res
                repaired_lines = extract_stageable_panos_lines(str(repaired_res.get("verdict") or ""))
                if not repaired_lines:
                    print(f"{C_RED}[stage] Repair turn produced no valid stageable lines.{C_RESET}\n")
                    return True

                re_gram = probe_pty_cli_grammar(pty_master_fd, repaired_lines, current_mode="config")
                if not re_gram.get("passed"):
                    print(
                        f"{C_RED}[syntax] Repaired block still rejected at token "
                        f"'{re_gram.get('invalid_token')}' — [edit] left untouched.{C_RESET}\n"
                    )
                    return True
                # HITL invariant: the operator must see and approve the EXACT lines being injected.
                print(f"\n{C_BOLD}── REPAIRED CANDIDATE LINES (syntax re-verified, NOT yet injected) ──{C_RESET}")
                for i, rl in enumerate(repaired_lines, 1):
                    print(f"  {C_GREEN}{i:02d}{C_RESET}  {rl}")
                re_confirm = input(
                    f"\n{C_YELLOW}Inject these {len(repaired_lines)} REPAIRED line(s) into SSH [edit]? [y/N]: {C_RESET}"
                ).strip().lower()
                if re_confirm not in ("y", "yes"):
                    print(f"{C_DIM}[stage] Repaired block rejected — [edit] left untouched.{C_RESET}\n")
                    _audit("stage_repair_decision", trace_id=stage_trace, decision="rejected", lines=list(repaired_lines))
                    return True
                _audit("stage_repair_decision", trace_id=stage_trace, decision="approved", lines=list(repaired_lines))
                cand_lines = repaired_lines
                print(
                    f"{C_GREEN}[syntax] PASS — repaired {len(cand_lines)}/{len(cand_lines)} line(s) "
                    f"accepted by the firewall's '?' parser (object/zone references are validated at commit).{C_RESET}"
                )
            else:
                print(
                    f"{C_GREEN}[syntax] PASS — {len(cand_lines)}/{len(cand_lines)} line(s) accepted by the firewall's "
                    f"'?' parser ({g_ms:.0f}ms, local; object/zone references are validated at commit).{C_RESET}"
                )

            ok, msg = stage_lines_to_pty_master(
                pty_master_fd,
                cand_lines,
                current_mode="config",
                skip_prep=True,
            )
            print(f"{C_GREEN if ok else C_RED}[stage] {msg}{C_RESET}\n")
            _audit("stage_injected", trace_id=stage_trace, lines=list(cand_lines), result="ok" if ok else msg)
            if pty_prompt_mode == "op":
                brain.record_operator_event("SSH session moved from operational '>' into 'configure' mode by @stage.")
            if ok:
                state_box["neo_staged_trace"] = stage_trace
                brain.record_operator_event(f"Injected {len(cand_lines)} syntax-checked CLI line(s) into SSH [edit]: {cand_lines[0][:80]}")
            return True

        pane = find_adjacent_tmux_pane()
        if not pane:
            print(f"\n{C_YELLOW}[standalone] Copy the validated block above into your PAN-OS SSH window.{C_RESET}\n")
            return True
        blocked = _pty_policy_block(brain, "stage")
        if blocked:
            print(f"\n{C_YELLOW}{blocked}{C_RESET}\n")
            _audit("stage_blocked", trace_id=stage_trace, reason=blocked)
            return True
        confirm = input(f"\n{C_YELLOW}Stage these {len(cand_lines)} line(s) into tmux pane {pane} [edit]? [y/N]: {C_RESET}").strip().lower()
        if confirm not in ("y", "yes"):
            print(f"{C_DIM}[stage] Cancelled.{C_RESET}\n")
            _audit("stage_decision", trace_id=stage_trace, decision="rejected")
            return True
        ok, msg = stage_lines_to_tmux_ssh(pane, cand_lines)
        print(f"{C_GREEN if ok else C_RED}[stage] {msg}{C_RESET}\n")
        _audit("stage_injected", trace_id=stage_trace, lines=list(cand_lines), result="ok" if ok else msg, channel="tmux")
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
    SSH wrapper (`--ssh <alias_or_user@ip>`):
    - Spawns real OpenSSH inside a POSIX PTY (`0ms` native Tab/?/arrow/history passthrough).
    - Intercepts `@` typed at column 0 of an empty PAN-OS prompt for inline NEO questions and local tools.
    - Intercepts `commit` in `#` config mode to run `evaluate_precommit_sanctuary()` (local) BEFORE
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
    alias_badge = f" [{resolved_dev}]" if resolved_dev else (f" [{fw_label}]" if fw_label.startswith("offline") else "")
    tls_unverified = os.getenv("PANOS_VERIFY_SSL", "true").strip().lower() in ("false", "0", "no")
    tls_badge = f"  {C_DIM}│{C_RESET}  {C_YELLOW}tls:unverified{C_RESET}" if tls_unverified else ""

    print(
        f"{C_BOLD}{C_GREEN}NEO · PAN-OS SSH assistant{C_RESET}  {C_DIM}│{C_RESET}  "
        f"{ssh_target}{alias_badge}  {C_DIM}│{C_RESET}  tools:{tool_count}  {C_DIM}│{C_RESET}  "
        f"policy:{C_YELLOW}{policy_mode}{C_RESET} (api+ssh)  {C_DIM}│{C_RESET}  keys-purged:{purged_count}{tls_badge}  {C_DIM}│{C_RESET}  "
        f"{C_GREEN}commit-check:on{C_RESET}"
    )
    panorama_state: Dict[str, Any] = {"managed": None, "detail": ""}
    try:
        from core.panos.sanctuary import detect_panorama_management

        panorama_state = detect_panorama_management(target_device=resolved_dev)
    except Exception:
        pass
    if panorama_state.get("managed"):
        print(
            f"{C_YELLOW}[panorama] Panorama-managed firewall ({panorama_state.get('detail')}). Local edits may be "
            f"overwritten by the next push — prefer changing config in Panorama.{C_RESET}"
        )
    print(f"{C_DIM}At any PAN-OS '>' or '#' prompt, type '@' as the first character to ask NEO ('@help' for commands).{C_RESET}\n")

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
    state_box: Dict[str, Any] = {"last_result": {}, "last_query": "", "panorama": panorama_state}
    commit_fail_re = re.compile(
        r"(Configuration is invalid|Validation Error\s*:|Commit job\s+\d+\s+failed|Result\s*:\s*FAIL)",
        re.IGNORECASE,
    )

    def _get_scrubbed_ring() -> str:
        return sanitize_ssh_capture(ssh_ring[-8192:]) if authenticated and ssh_ring else ""

    def _append_to_ring(extra_text: str) -> None:
        nonlocal ssh_ring
        if extra_text:
            ssh_ring = (ssh_ring + extra_text)[-12288:]

    def _note_commit_outcome(chunk: str) -> None:
        low_chunk = chunk.lower()
        if "configuration committed successfully" in low_chunk:
            brain.record_operator_event("Configuration committed in SSH session.")
            _audit("commit_observed", result="success", neo_trace=state_box.get("neo_staged_trace"))
            state_box["neo_staged_trace"] = None
        elif commit_fail_re.search(chunk):
            brain.record_operator_event(
                "PAN-OS CLI commit/validation failure observed in SSH output — inspect <ssh_pane_capture> against candidate XML."
            )
            _audit("commit_observed", result="failed", neo_trace=state_box.get("neo_staged_trace"))

    def _intercept_commit_gate(commit_cmd: str = "commit") -> bool:
        """Return True if safe/approved to send Enter on `commit`, False to cancel with Ctrl+C."""
        from core.panos.sanctuary import evaluate_precommit_sanctuary

        t0 = time.perf_counter()
        verdict = evaluate_precommit_sanctuary(target_device=resolved_dev, commit_cmd=commit_cmd)
        ms = (time.perf_counter() - t0) * 1000
        scope = verdict.get("scope") or {}
        if verdict.get("safe", True):
            _audit("commit_check", command=commit_cmd, scope=scope, decision="pass", neo_trace=state_box.get("neo_staged_trace"))
            return True

        with _cooked_guard():
            print(f"\n\n{C_RED}{C_BOLD}╔══ PRE-COMMIT SAFETY CHECK ({ms:.0f}ms, local) ══╗{C_RESET}")
            if verdict.get("scope_note"):
                print(f"{C_DIM}  scope: {verdict['scope_note']}{C_RESET}")
            for w in verdict.get("warnings") or []:
                print(f"{C_YELLOW}  ! {w}{C_RESET}")
            print(f"{C_RED}{C_BOLD}╚══════════════════════════════════════════════╝{C_RESET}")
            try:
                ans = input(f"{C_YELLOW}Cancel this commit to prevent lockout/outage? [Y/n]: {C_RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                ans = "y"
            proceed = ans in ("n", "no")
            _audit(
                "commit_check",
                command=commit_cmd,
                scope=scope,
                warnings=verdict.get("warnings") or [],
                decision="operator_override" if proceed else "cancelled",
                neo_trace=state_box.get("neo_staged_trace"),
            )
            return proceed

    def _maybe_tag_neo_commit(echoed_cmd: str, has_trailing_space: bool = False) -> Optional[bytes]:
        """
        If NEO staged lines since the last commit and the operator typed a bare `commit`, offer to tag it.
        Returns `bytes` to append (may be `b""` if declined), or `None` if interrupted with Ctrl+C.
        """
        trace = state_box.get("neo_staged_trace")
        if not trace or echoed_cmd.strip().lower() != "commit":
            return b""
        suffix = build_neo_commit_suffix(trace)
        with _cooked_guard():
            try:
                ans = input(
                    f"\n{C_YELLOW}NEO staged lines in this commit. Add{C_RESET}{suffix}{C_YELLOW} for the PAN-OS audit trail? [Y/n]: {C_RESET}"
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
        if ans in ("n", "no"):
            return b""
        _audit("commit_tagged", neo_trace=trace, suffix=suffix.strip())
        out_bytes = suffix.encode("utf-8")
        return out_bytes.lstrip(b" ") if has_trailing_space else out_bytes

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
                    _note_commit_outcome(decoded)

            if stdin_fd in rlist:
                try:
                    in_bytes = os.read(stdin_fd, 1024)
                except OSError:
                    break
                if not in_bytes:
                    break

                echo_mode, echoed_after_prompt = extract_echoed_command_after_prompt(tail_buf)
                _, raw_after_prompt = extract_raw_after_prompt(tail_buf)

                # 0. Dual-Plane Split (`<ssh_cmd> + @ <query>` parallel OR `<ssh_cmd> | @ <query>` piped)
                dual_split = (
                    parse_dual_plane_split(raw_after_prompt, in_bytes)
                    if authenticated and echo_mode is not None
                    else None
                )
                if dual_split is not None:
                    ssh_cmd = dual_split["ssh_cmd"]
                    op_char = dual_split["op"]
                    cancelled = False
                    neo_part = ""

                    if dual_split["kind"] == "interactive":
                        # Erase trailing ` +` / ` | ` from mgmtsrvr's remote buffer so only `ssh_cmd` stays staged
                        os.write(master_fd, b"\x7f" * int(dual_split["erase_count"]))
                        erase_deadline = time.time() + 0.08
                        while time.time() < erase_deadline:
                            er_ready, _, _ = select.select([master_fd], [], [], 0.02)
                            if not er_ready:
                                break
                            try:
                                er_chunk = os.read(master_fd, 1024)
                            except OSError:
                                break
                            if not er_chunk:
                                break
                            os.write(sys.stdout.fileno(), er_chunk)
                            tail_buf = (tail_buf + er_chunk.decode("utf-8", errors="replace"))[-512:]

                        prefill = dual_split["prefill"]
                        with _cooked_guard():
                            sys.stdout.write(f" {C_CYAN}{op_char} @{C_RESET} ")
                            sys.stdout.flush()
                            try:
                                rest = read_coalesced_input("") if not prefill or not dual_split["has_newline"] else ""
                                neo_part = (prefill + rest).strip()
                            except (EOFError, KeyboardInterrupt):
                                cancelled = True
                                print(f"\n{C_DIM}[dual-plane cancelled]{C_RESET}")
                    else:
                        # Pasted full line `<ssh_cmd> + @ <neo_query>` at an empty prompt
                        os.write(master_fd, ssh_cmd.encode("utf-8"))
                        paste_deadline = time.time() + 0.08
                        while time.time() < paste_deadline:
                            pr_ready, _, _ = select.select([master_fd], [], [], 0.02)
                            if not pr_ready:
                                break
                            try:
                                pr_chunk = os.read(master_fd, 1024)
                            except OSError:
                                break
                            if not pr_chunk:
                                break
                            os.write(sys.stdout.fileno(), pr_chunk)
                            tail_buf = (tail_buf + pr_chunk.decode("utf-8", errors="replace"))[-512:]

                        with _cooked_guard():
                            pre_q = dual_split["neo_query"]
                            sys.stdout.write(f" {C_CYAN}{op_char} @{C_RESET} {pre_q}")
                            sys.stdout.flush()
                            if dual_split["has_newline"]:
                                sys.stdout.write("\n")
                                sys.stdout.flush()
                                neo_part = pre_q
                            else:
                                try:
                                    neo_part = (pre_q + read_coalesced_input("")).strip()
                                except (EOFError, KeyboardInterrupt):
                                    cancelled = True
                                    print(f"\n{C_DIM}[dual-plane cancelled]{C_RESET}")

                    if cancelled:
                        os.write(master_fd, b"\x03")
                        continue

                    if echo_mode == "config" and _COMMIT_CMD_RE.match(ssh_cmd.strip()):
                        if not _intercept_commit_gate(ssh_cmd.strip()):
                            with _cooked_guard():
                                print(f"{C_GREEN}[commit-check] Cancelled commit (candidate config preserved).{C_RESET}")
                            os.write(master_fd, b"\x03")
                            continue

                    with _cooked_guard():
                        ring_before = _get_scrubbed_ring()
                        try:
                            captured_ssh = execute_dual_plane_turn(
                                ssh_cmd=ssh_cmd,
                                op_char=op_char,
                                neo_raw_cmd=neo_part,
                                master_fd=master_fd,
                                echo_mode=echo_mode,
                                brain=brain,
                                state_box=state_box,
                                target_device=resolved_dev,
                                ssh_ring_snapshot=ring_before,
                                ssh_ring_appender=_append_to_ring,
                            )
                        except KeyboardInterrupt:
                            # Contain Ctrl+C mid-drain so it never reaches `finally: proc.terminate()`
                            os.write(master_fd, b"\x03")
                            print(f"\n{C_YELLOW}[neo] Dual-plane turn interrupted — SSH session preserved.{C_RESET}")
                            captured_ssh = ""
                        if captured_ssh:
                            ssh_ring = (ssh_ring + captured_ssh)[-12288:]
                            tail_buf = (tail_buf + captured_ssh)[-512:]
                            _note_commit_outcome(captured_ssh)
                    os.write(master_fd, b"\r")
                    continue

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
                                ssh_ring_appender=_append_to_ring,
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
                    if _intercept_commit_gate(echoed_after_prompt):
                        tag_bytes = _maybe_tag_neo_commit(
                            echoed_after_prompt,
                            has_trailing_space=raw_after_prompt.endswith(" "),
                        )
                        if tag_bytes is None:
                            with _cooked_guard():
                                print(f"{C_GREEN}[commit-check] Cancelled commit (sent Ctrl+C to CLI; candidate config preserved).{C_RESET}")
                            os.write(master_fd, b"\x03")
                            continue
                        if tag_bytes:
                            os.write(master_fd, tag_bytes)
                        os.write(master_fd, b"\r")
                    else:
                        with _cooked_guard():
                            print(f"{C_GREEN}[commit-check] Cancelled commit (sent Ctrl+C to CLI; candidate config preserved).{C_RESET}")
                        os.write(master_fd, b"\x03")
                    continue

                if pasted_commit_match:
                    # Flush any preceding `set` lines before the `commit` line first, then run Sanctuary gate
                    split_pos = pasted_commit_match.end() - 1
                    prefix_str = in_text[:split_pos]
                    os.write(master_fd, prefix_str.encode("utf-8"))
                    time.sleep(0.35)
                    pasted_cmd_line = in_text[pasted_commit_match.start():pasted_commit_match.end()].strip()
                    if _intercept_commit_gate(pasted_cmd_line):
                        os.write(master_fd, in_text[split_pos:].encode("utf-8"))
                    else:
                        with _cooked_guard():
                            print(f"{C_GREEN}[commit-check] Cancelled pasted commit (sent Ctrl+C to CLI).{C_RESET}")
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
        level=logging.INFO if args.verbose else logging.ERROR,
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
