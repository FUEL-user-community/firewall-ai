"""
Candidate Slot Crucible (`core/forge/crucible.py`).

Executes deterministic pre-cutover verification on an inactive candidate slot:
1. Constitutional Law & AST/YAML verification on mutated paths.
2. Automatic `PROMPTS_YAML_SHA` sealing in the candidate slot's local `.env` if `config/prompts.yaml` changed.
3. Subprocess `pytest -q` test bench execution under `NEO_PROBATION_SHADOW=1`.
4. Live/Emulated startup & PAN-OS canary verification (`classify_outcome == "success"`).
"""

import hashlib
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from dotenv import set_key

from core.forge.laws import (
    ConstitutionalError,
    validate_mutation_paths,
    validate_python_ast,
    validate_yaml_content,
)

logger = logging.getLogger(__name__)


@dataclass
class CrucibleReport:
    passed: bool
    stage_failed: str
    slot_dir: str
    commit_sha: str
    test_summary: str
    canary_status: str
    details: str = ""


def compute_file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def seal_slot_prompts_sha(slot_dir: Path) -> Optional[str]:
    """Recompute `PROMPTS_YAML_SHA` and write it into the candidate slot's local `.env`."""
    prompts_file = slot_dir / "config" / "prompts.yaml"
    if not prompts_file.is_file():
        return None
    sha = compute_file_sha256(prompts_file)
    slot_env = slot_dir / ".env"
    if not slot_env.exists():
        slot_env.touch(exist_ok=True)
    set_key(str(slot_env), "PROMPTS_YAML_SHA", sha, quote_mode="never")
    return sha


def verify_candidate_slot(
    slot_dir: Path,
    touched_paths: Iterable[str],
    run_pytest: bool = True,
    pytest_targets: Optional[list[str]] = None,
    pytest_timeout: int = 120,
    run_canary: bool = True,
) -> CrucibleReport:
    """Run the 4-stage Crucible against `slot_dir` before permitting handover."""
    slot_dir = Path(slot_dir).resolve()
    commit_sha = _resolve_git_sha(slot_dir)

    # Stage 1: Constitutional & Static Verification
    try:
        clean_paths = validate_mutation_paths(touched_paths)
        for rel in clean_paths:
            fpath = slot_dir / rel
            if not fpath.is_file():
                continue
            text = fpath.read_text(encoding="utf-8")
            if fpath.suffix.lower() == ".py":
                validate_python_ast(text, filename=rel)
            elif fpath.suffix.lower() in (".yaml", ".yml"):
                validate_yaml_content(text, rel_path=rel)
    except ConstitutionalError as ce:
        return CrucibleReport(
            passed=False,
            stage_failed="constitutional_gate",
            slot_dir=str(slot_dir),
            commit_sha=commit_sha,
            test_summary="skipped",
            canary_status="skipped",
            details=str(ce),
        )
    except Exception as e:
        return CrucibleReport(
            passed=False,
            stage_failed="static_analysis",
            slot_dir=str(slot_dir),
            commit_sha=commit_sha,
            test_summary="skipped",
            canary_status="skipped",
            details=str(e),
        )

    # Stage 2: Prompt SHA Auto-Seal in Candidate Slot
    if "config/prompts.yaml" in clean_paths:
        try:
            seal_slot_prompts_sha(slot_dir)
        except Exception as se:
            return CrucibleReport(
                passed=False,
                stage_failed="prompt_sha_seal",
                slot_dir=str(slot_dir),
                commit_sha=commit_sha,
                test_summary="skipped",
                canary_status="skipped",
                details=str(se),
            )

    # Stage 3: Isolated Subprocess Pytest Suite (PROBATION_SHADOW=1)
    test_summary = "skipped"
    if run_pytest:
        env = os.environ.copy()
        env["NEO_PROBATION_SHADOW"] = "1"
        env["PYTHONPATH"] = str(slot_dir)
        slot_env_file = slot_dir / ".env"
        if slot_env_file.is_file():
            # Ensure updated PROMPTS_YAML_SHA from slot .env overrides parent env
            for line in slot_env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("PROMPTS_YAML_SHA="):
                    env["PROMPTS_YAML_SHA"] = line.split("=", 1)[1].strip().strip("'\"")

        cmd = [sys.executable, "-m", "pytest", "-q"]
        if pytest_targets:
            cmd.extend(pytest_targets)

        try:
            cp = subprocess.run(
                cmd,
                cwd=str(slot_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=pytest_timeout,
            )
            out_tail = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()[-1200:]
            last_line = out_tail.splitlines()[-1] if out_tail else f"rc={cp.returncode}"
            test_summary = last_line
            if cp.returncode != 0:
                return CrucibleReport(
                    passed=False,
                    stage_failed="pytest_suite",
                    slot_dir=str(slot_dir),
                    commit_sha=commit_sha,
                    test_summary=test_summary,
                    canary_status="skipped",
                    details=out_tail,
                )
        except subprocess.TimeoutExpired:
            return CrucibleReport(
                passed=False,
                stage_failed="pytest_timeout",
                slot_dir=str(slot_dir),
                commit_sha=commit_sha,
                test_summary=f"timed out after {pytest_timeout}s",
                canary_status="skipped",
                details="Candidate mutation introduced an infinite loop or deadlock in test suite.",
            )

    # Stage 4: Subprocess Boot & Live/Emulated Canary Probe
    canary_status = "skipped"
    if run_canary:
        ok, canary_msg = _execute_slot_canary_subprocess(slot_dir)
        canary_status = "passed" if ok else "failed"
        if not ok:
            return CrucibleReport(
                passed=False,
                stage_failed="canary_probe",
                slot_dir=str(slot_dir),
                commit_sha=commit_sha,
                test_summary=test_summary,
                canary_status=canary_status,
                details=canary_msg,
            )

    return CrucibleReport(
        passed=True,
        stage_failed="",
        slot_dir=str(slot_dir),
        commit_sha=_resolve_git_sha(slot_dir),
        test_summary=test_summary,
        canary_status=canary_status,
        details="All constitutional, AST, pytest, and canary gates passed.",
    )


def _execute_slot_canary_subprocess(slot_dir: Path) -> tuple[bool, str]:
    """
    Boot the candidate slot's core pipeline in a clean Python subprocess:
    1. Verify prompt integrity + ToolKeeper tool loading.
    2. If a live firewall is reachable (`any_online`), run a read-only `system_info` probe
       and verify `classify_outcome(raw_output) == "success"`.
    """
    probe_code = (
        "import os, sys\n"
        "from dotenv import load_dotenv\n"
        "load_dotenv('.env', override=True)\n"
        "from core.pipeline.prompt_assembler import SYSTEM_PROMPT\n"
        "from core.pipeline.tool_keeper import ToolKeeper\n"
        "from core.pipeline.outcomes import classify_outcome\n"
        "from core.utils.startup_validator import get_diagnostic_matrix\n"
        "assert len(str(SYSTEM_PROMPT)) > 100, 'Empty SYSTEM_PROMPT'\n"
        "tk = ToolKeeper()\n"
        "tools = {t.__name__: t for t in tk.get_all_tools()}\n"
        "assert 'test_packet_walk' in tools and 'system_info' in tools, 'Missing core tools'\n"
        "diag = get_diagnostic_matrix()\n"
        "if diag.get('any_online') and os.getenv('NEO_LIVE_CANARY', '1') == '1':\n"
        "    out = tools['system_info']()\n"
        "    if classify_outcome(out) != 'success':\n"
        "        raise RuntimeError(f'Live PA-VM canary failed: {out[:200]}')\n"
        "    print('CANARY_OK:LIVE_CONNECTED')\n"
        "else:\n"
        "    print('CANARY_OK:EMULATION_VERIFIED')\n"
    )
    env = os.environ.copy()
    env["NEO_PROBATION_SHADOW"] = "1"
    env["PYTHONPATH"] = str(slot_dir)
    try:
        cp = subprocess.run(
            [sys.executable, "-c", probe_code],
            cwd=str(slot_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=25,
        )
        combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        if cp.returncode == 0 and "CANARY_OK:" in combined:
            return True, combined
        return False, combined[-800:]
    except Exception as e:
        return False, str(e)


def _resolve_git_sha(directory: Path) -> str:
    try:
        cp = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=str(directory),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return cp.stdout.strip()[:8]
    except Exception:
        pass
    return "00000000"
