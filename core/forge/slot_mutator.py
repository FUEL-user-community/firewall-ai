"""
Dual-Slot Worktree & Reincarnation Mutator (`core/forge/slot_mutator.py`).

Manages `.slots/a` and `.slots/b` candidate staging:
- Seeds isolated slot workspaces cleanly (via `git worktree` when root is a clean git repo,
  plus deterministic working-tree overlay so uncommitted baseline edits or bare `tmp_path`
  test directories never lose files and never push to remotes).
- Stages full-file writes or unified diffs ONLY inside the inactive slot, guarded by `laws.py`.
- Runs `crucible.py` verification and either rolls back on failure or posts a verified
  cutover request to `SharedStateStore` for `stem.py` zero-drop promotion.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.forge.crucible import CrucibleReport, seal_slot_prompts_sha, verify_candidate_slot
from core.forge.laws import (
    ConstitutionalError,
    extract_diff_paths,
    validate_mutation_paths,
)
from core.forge.state_store import SharedStateStore, get_shared_store

logger = logging.getLogger(__name__)

_SYNC_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".slots",
        ".state",
        "__pycache__",
        ".pytest_cache",
        "venv",
        "env",
        ".venv",
        "node_modules",
        "_legacy",
        "landing_site",
    }
)


def resolve_nucleus_root() -> Path:
    """Resolve the outer nucleus root whether running from root or `.slots/<a|b>`."""
    env_root = os.getenv("NEO_NUCLEUS_ROOT", "").strip()
    if env_root:
        return Path(env_root).resolve()
    here = Path(__file__).resolve().parent.parent.parent
    if here.parent.name == ".slots":
        return here.parent.parent.resolve()
    return here.resolve()


class SlotMutator:
    """Orchestrates safe staging, verification, rollback, and promotion between Slot A and Slot B."""

    def __init__(
        self,
        nucleus_root: Optional[Path] = None,
        store: Optional[SharedStateStore] = None,
    ):
        self.nucleus_root = Path(nucleus_root).resolve() if nucleus_root else resolve_nucleus_root()
        self.slots_root = self.nucleus_root / ".slots"
        self.store = store or get_shared_store()

    def get_active_slot(self) -> str:
        """Return `'a'` or `'b'` based on supervisor state or current slot env."""
        kv_slot = self.store.get_kv("active_slot")
        if kv_slot in ("a", "b"):
            return kv_slot
        env_slot = os.getenv("NEO_SLOT_ID", "NEO_A").strip().upper()
        if env_slot.endswith("B"):
            return "b"
        return "a"

    def get_inactive_slot(self) -> str:
        return "b" if self.get_active_slot() == "a" else "a"

    def slot_path(self, slot: str) -> Path:
        s = slot.lower().strip()
        if s not in ("a", "b"):
            raise ValueError(f"Slot must be 'a' or 'b', got '{slot}'")
        return self.slots_root / s

    def ensure_slots_initialized(self, force_resync_inactive: bool = False) -> Dict[str, str]:
        """Ensure `.slots/a` and `.slots/b` exist and have isolated `.env` files."""
        self.slots_root.mkdir(parents=True, exist_ok=True)
        active = self.get_active_slot()
        inactive = self.get_inactive_slot()

        for s in ("a", "b"):
            sp = self.slot_path(s)
            if not (sp / "server.py").is_file() or (force_resync_inactive and s == inactive):
                self._seed_slot_directory(s, sp)

        if not self.store.get_kv("active_slot"):
            self.store.set_kv("active_slot", active)

        return {
            "active_slot": active,
            "inactive_slot": inactive,
            "slot_a": str(self.slot_path("a")),
            "slot_b": str(self.slot_path("b")),
        }

    def _seed_slot_directory(self, slot: str, target_dir: Path) -> None:
        """
        Seed `target_dir` from `self.nucleus_root`:
        1. Attempt `git worktree add -B neo/slot-<s>` if `.git` exists, then overlay current
           working-tree tracked/untracked files so uncommitted baseline fixes are preserved!
        2. Fallback to clean directory sync if `.git` is unavailable (e.g. unit test `tmp_path`).
        """
        source_dir = self.nucleus_root
        used_worktree = False

        if (source_dir / ".git").exists() and not target_dir.exists():
            branch_name = f"neo/slot-{slot}"
            try:
                subprocess.run(
                    ["git", "worktree", "prune"],
                    cwd=str(source_dir),
                    capture_output=True,
                    timeout=10,
                )
                cp = subprocess.run(
                    ["git", "worktree", "add", "-B", branch_name, str(target_dir), "HEAD"],
                    cwd=str(source_dir),
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if cp.returncode == 0 and target_dir.is_dir():
                    used_worktree = True
            except Exception as e:
                logger.debug(f"[FORGE] git worktree fallback to file sync for slot {slot}: {e}")

        # Overlay current working tree from source_dir -> target_dir so dirty/uncommitted
        # baseline improvements are 100% present in the slot.
        self._overlay_workspace_files(source_dir, target_dir)

        # Configure slot-local .env
        root_env = source_dir / ".env"
        slot_env = target_dir / ".env"
        if root_env.is_file():
            shutil.copy2(root_env, slot_env)
        else:
            slot_env.touch(exist_ok=True)

        seal_slot_prompts_sha(target_dir)
        logger.info(
            f"[FORGE] Seeded Slot '{slot.upper()}' at {target_dir} (worktree={used_worktree})"
        )

    @staticmethod
    def _overlay_workspace_files(src: Path, dst: Path) -> None:
        dst.mkdir(parents=True, exist_ok=True)
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in _SYNC_EXCLUDE_DIRS]
            rel_root = Path(root).relative_to(src)
            target_root = dst / rel_root
            target_root.mkdir(parents=True, exist_ok=True)
            for fname in files:
                if fname.endswith((".pyc", ".pyo", ".sqlite", ".db-wal", ".db-shm")):
                    continue
                if fname.startswith(".env"):
                    continue
                s_file = Path(root) / fname
                d_file = target_root / fname
                shutil.copy2(s_file, d_file)

    def reset_inactive_slot(self) -> str:
        """Reset the inactive slot back to match the active slot's verified codebase."""
        active_dir = self.slot_path(self.get_active_slot())
        inactive = self.get_inactive_slot()
        inactive_dir = self.slot_path(inactive)
        source = active_dir if (active_dir / "server.py").is_file() else self.nucleus_root
        self._overlay_workspace_files(source, inactive_dir)
        seal_slot_prompts_sha(inactive_dir)
        return str(inactive_dir)

    def stage_file_mutation(self, rel_path: str, new_content: str) -> Dict[str, Any]:
        """Write `new_content` to `rel_path` strictly inside the inactive candidate slot."""
        clean_rel = validate_mutation_paths([rel_path])[0]
        self.ensure_slots_initialized()
        inactive = self.get_inactive_slot()
        slot_dir = self.slot_path(inactive)
        dest = (slot_dir / clean_rel).resolve()
        if not dest.is_relative_to(slot_dir):
            raise ConstitutionalError(f"Path escape blocked: {rel_path}")

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(new_content, encoding="utf-8")

        staged = list(self.store.get_kv(f"staged_paths_{inactive}", default=[]))
        if clean_rel not in staged:
            staged.append(clean_rel)
            self.store.set_kv(f"staged_paths_{inactive}", staged)

        return {
            "slot": inactive,
            "slot_dir": str(slot_dir),
            "path": clean_rel,
            "bytes_written": len(new_content.encode("utf-8")),
            "staged_paths": staged,
        }

    def stage_unified_diff(self, unified_diff: str) -> Dict[str, Any]:
        """Validate and apply a unified diff strictly inside the inactive candidate slot."""
        touched = extract_diff_paths(unified_diff)
        self.ensure_slots_initialized()
        inactive = self.get_inactive_slot()
        slot_dir = self.slot_path(inactive)

        patch_file = slot_dir / ".candidate_patch.diff"
        try:
            patch_file.write_text(unified_diff, encoding="utf-8")
            cp_check = subprocess.run(
                ["git", "apply", "--check", "--ignore-space-change", str(patch_file)],
                cwd=str(slot_dir),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if cp_check.returncode == 0:
                cp_apply = subprocess.run(
                    ["git", "apply", "--ignore-space-change", str(patch_file)],
                    cwd=str(slot_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if cp_apply.returncode != 0:
                    raise RuntimeError(f"git apply failed: {cp_apply.stderr.strip()}")
            else:
                # Pure-Python unified diff fallback (works even in non-git temp directories)
                self._apply_unified_diff_python(slot_dir, unified_diff)
        finally:
            patch_file.unlink(missing_ok=True)

        staged = list(self.store.get_kv(f"staged_paths_{inactive}", default=[]))
        for p in touched:
            if p not in staged:
                staged.append(p)
        self.store.set_kv(f"staged_paths_{inactive}", staged)

        return {
            "slot": inactive,
            "slot_dir": str(slot_dir),
            "touched_paths": touched,
            "staged_paths": staged,
        }

    @staticmethod
    def _apply_unified_diff_python(slot_dir: Path, unified_diff: str) -> None:
        """Minimal deterministic unified-diff applier for bare directories without `.git`."""
        import re

        current_rel: Optional[str] = None
        hunks: Dict[str, List[List[str]]] = {}
        cur_hunk: Optional[List[str]] = None

        for line in unified_diff.splitlines():
            if line.startswith("--- "):
                continue
            if line.startswith("+++ "):
                tok = line[4:].strip().split("\t", 1)[0].strip()
                if tok.startswith("b/"):
                    tok = tok[2:]
                current_rel = validate_mutation_paths([tok])[0]
                hunks.setdefault(current_rel, [])
                cur_hunk = None
            elif line.startswith("@@ ") and current_rel is not None:
                cur_hunk = [line]
                hunks[current_rel].append(cur_hunk)
            elif cur_hunk is not None and (line.startswith((" ", "+", "-")) or line == ""):
                cur_hunk.append(line)

        if not hunks:
            raise ValueError("Unified diff contained no applicable hunks.")

        for rel, file_hunks in hunks.items():
            fpath = slot_dir / rel
            orig_lines = fpath.read_text(encoding="utf-8").splitlines() if fpath.is_file() else []
            out_lines: List[str] = []
            src_idx = 0
            for hunk in file_hunks:
                hdr = hunk[0]
                m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", hdr)
                if not m:
                    raise ValueError(f"Invalid hunk header: {hdr}")
                start_old = max(0, int(m.group(1)) - 1)
                if start_old < src_idx or start_old > len(orig_lines):
                    raise ValueError(f"Hunk offset out of bounds in {rel}: {hdr}")
                out_lines.extend(orig_lines[src_idx:start_old])
                src_idx = start_old
                for hline in hunk[1:]:
                    if not hline:
                        continue
                    prefix, content = hline[0], hline[1:]
                    if prefix == " ":
                        if src_idx >= len(orig_lines) or orig_lines[src_idx].rstrip("\r") != content.rstrip("\r"):
                            raise ValueError(f"Context mismatch in {rel} at line {src_idx + 1}")
                        out_lines.append(orig_lines[src_idx])
                        src_idx += 1
                    elif prefix == "-":
                        if src_idx >= len(orig_lines) or orig_lines[src_idx].rstrip("\r") != content.rstrip("\r"):
                            raise ValueError(f"Removal mismatch in {rel} at line {src_idx + 1}")
                        src_idx += 1
                    elif prefix == "+":
                        out_lines.append(content)
            out_lines.extend(orig_lines[src_idx:])
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    def verify_and_queue_cutover(
        self,
        reason: str = "Autonomous self-hardening promotion",
        run_pytest: bool = True,
        pytest_targets: Optional[List[str]] = None,
        run_canary: bool = True,
    ) -> CrucibleReport:
        """
        Execute the Crucible on the inactive slot.
        - On failure: automatically roll back the inactive slot to clean baseline and record failure.
        - On pass: commit locally in the slot branch (if git present) and queue `pending_cutover` for `stem.py`.
        """
        self.ensure_slots_initialized()
        active = self.get_active_slot()
        inactive = self.get_inactive_slot()
        inactive_dir = self.slot_path(inactive)
        staged: List[str] = list(self.store.get_kv(f"staged_paths_{inactive}", default=[]))

        if not staged:
            return CrucibleReport(
                passed=False,
                stage_failed="no_staged_changes",
                slot_dir=str(inactive_dir),
                commit_sha="00000000",
                test_summary="skipped",
                canary_status="skipped",
                details=f"Inactive slot '{inactive.upper()}' has no staged mutations.",
            )

        report = verify_candidate_slot(
            slot_dir=inactive_dir,
            touched_paths=staged,
            run_pytest=run_pytest,
            pytest_targets=pytest_targets,
            run_canary=run_canary,
        )

        if not report.passed:
            logger.warning(
                f"[FORGE] Crucible FAILED for Slot '{inactive.upper()}' at {report.stage_failed}: {report.details}"
            )
            self.reset_inactive_slot()
            self.store.set_kv(f"staged_paths_{inactive}", [])
            self.store.record_generation(
                slot=inactive,
                commit_sha=report.commit_sha,
                parent_sha="rollback",
                status=f"rejected:{report.stage_failed}",
                reason=f"{reason} | {report.details[:300]}",
            )
            return report

        # Optional local commit inside the candidate slot worktree (NEVER pushes to remote)
        commit_sha = self._commit_slot_worktree(inactive_dir, staged, reason) or report.commit_sha
        report.commit_sha = commit_sha

        cutover_ticket = {
            "from_slot": active,
            "to_slot": inactive,
            "to_slot_dir": str(inactive_dir),
            "commit_sha": commit_sha,
            "touched_paths": staged,
            "reason": reason,
            "test_summary": report.test_summary,
            "canary_status": report.canary_status,
        }
        self.store.set_kv("pending_cutover", cutover_ticket)
        self.store.set_kv(f"staged_paths_{inactive}", [])
        self.store.record_generation(
            slot=inactive,
            commit_sha=commit_sha,
            parent_sha=active,
            status="crucible_verified_pending_cutover",
            reason=reason,
        )
        return report

    @staticmethod
    def _commit_slot_worktree(slot_dir: Path, staged_paths: List[str], reason: str) -> Optional[str]:
        if not (slot_dir / ".git").exists():
            return None
        try:
            subprocess.run(
                ["git", "add", "--", *staged_paths],
                cwd=str(slot_dir),
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["git", "commit", "-m", f"[NEO-FORGE] {reason[:72]}"],
                cwd=str(slot_dir),
                capture_output=True,
                timeout=10,
            )
            cp = subprocess.run(
                ["git", "rev-parse", "--short=8", "HEAD"],
                cwd=str(slot_dir),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if cp.returncode == 0 and cp.stdout.strip():
                return cp.stdout.strip()[:8]
        except Exception:
            pass
        return None


def slot_forge(
    action: str,
    target_path: str = "",
    content: str = "",
    unified_diff: str = "",
    reason: str = "Autonomous slot hardening",
    target_device: Optional[str] = None,
) -> str:
    """
    Dual-Slot Self-Reincarnation Forge (`Slot A` <-> `Slot B`).

    Args:
        action (str): 'status' (view active/inactive slots & lineage),
                      'init' (seed .slots/a and .slots/b),
                      'stage_diff' (apply unified diff to inactive slot),
                      'stage_file' (write full file in inactive slot),
                      'verify_and_promote' (run AST + pytest + PA-VM canary and queue zero-drop cutover),
                      or 'reset_inactive' (discard staged edits in inactive slot).
        target_path (str): Relative mutable path for 'stage_file' (e.g. 'core/panos/ops.py').
        content (str): Full replacement file text for 'stage_file'.
        unified_diff (str): Unified git diff for 'stage_diff'.
        reason (str): Engineering justification recorded in generation lineage.
    """
    if os.getenv("NEO_PROBATION_SHADOW", "0").strip() in ("1", "true", "yes") and action != "status":
        return "ERROR: Security Policy Block - Candidate slot in PROBATION_SHADOW cannot self-mutate until promoted."

    mutator = SlotMutator()
    act = (action or "").strip().lower()

    try:
        if act == "status":
            active = mutator.get_active_slot()
            inactive = mutator.get_inactive_slot()
            staged = mutator.store.get_kv(f"staged_paths_{inactive}", default=[])
            pending = mutator.store.get_kv("pending_cutover")
            gens = mutator.store.list_generations(limit=5)
            lines = [
                "--- DUAL-SLOT REINCARNATION STATUS ---",
                f"Active Slot:   {active.upper()} ({mutator.slot_path(active)})",
                f"Inactive Slot: {inactive.upper()} ({mutator.slot_path(inactive)})",
                f"Staged Paths:  {staged}",
                f"Pending Cutover: {bool(pending)}",
            ]
            if gens:
                lines.append("Recent Lineage:")
                for g in gens:
                    lines.append(
                        f"  - Gen #{g['gen_id']} [Slot {str(g['slot']).upper()} @ {g['commit_sha']}]: "
                        f"{g['status']} ({g['reason'][:80]})"
                    )
            return "\n".join(lines)

        if act == "init":
            info = mutator.ensure_slots_initialized()
            return (
                f"SLOTS INITIALIZED: Active={info['active_slot'].upper()}, "
                f"Inactive={info['inactive_slot'].upper()}"
            )

        if act == "reset_inactive":
            path = mutator.reset_inactive_slot()
            mutator.store.set_kv(f"staged_paths_{mutator.get_inactive_slot()}", [])
            return f"INACTIVE SLOT RESET to verified baseline: {path}"

        if act == "stage_file":
            if not target_path or not content:
                return "Error: 'stage_file' requires both 'target_path' and 'content'."
            res = mutator.stage_file_mutation(target_path, content)
            return (
                f"STAGED FILE IN SLOT {res['slot'].upper()}: {res['path']} "
                f"({res['bytes_written']}B). Staged set: {res['staged_paths']}"
            )

        if act == "stage_diff":
            if not unified_diff:
                return "Error: 'stage_diff' requires 'unified_diff'."
            res = mutator.stage_unified_diff(unified_diff)
            return (
                f"STAGED DIFF IN SLOT {res['slot'].upper()}: touched={res['touched_paths']}. "
                f"Staged set: {res['staged_paths']}"
            )

        if act == "verify_and_promote":
            rep = mutator.verify_and_queue_cutover(reason=reason)
            if not rep.passed:
                return (
                    f"Error: Crucible REJECTED candidate slot at stage '{rep.stage_failed}' "
                    f"(inactive slot rolled back cleanly). Details: {rep.details}"
                )
            return (
                f"CRUCIBLE PASSED & CUTOVER QUEUED -> Slot @ {rep.commit_sha} | "
                f"pytest={rep.test_summary} | canary={rep.canary_status}"
            )

        return (
            f"Error: Unknown slot_forge action '{action}'. "
            "Use 'status', 'init', 'stage_diff', 'stage_file', 'verify_and_promote', or 'reset_inactive'."
        )
    except ConstitutionalError as ce:
        return f"ERROR: Security Policy Block - {ce}"
    except Exception as e:
        return f"Error: slot_forge failed: {e}"
