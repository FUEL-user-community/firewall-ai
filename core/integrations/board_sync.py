"""
Path-Encoded Immutable Stigmergic Board (`NEO <-> Google Drive <-> Gemini Spark`).

Architecture (Plane 3 — Option 3D):
- Defeats Google Drive API v3 Last-Write-Wins (`files.update` lacks `If-Match`) by writing
  strictly append-only immutable files whose coordination metadata is encoded in the filename:
      <UTC_TS>__<ACTOR>__<MOVE>__<THREAD_ID>__<BASE_SHA8>__<SLUG>.md
- Dual-backend parity: syncs against Google Drive (`DRIVE_BOARD_FOLDER_ID`) when configured,
  and mirrors/falls back to `<shared_state>/board_spool/` for deterministic local/air-gapped execution.
- Enforces `NEO_PROBATION_SHADOW=1` write-fence so unverified candidate slots can read the board
  without polluting Spark or sibling slots.
- Parses external `.md` artifacts into typed `BoardArtifact` records while neutralizing
  control-header smuggling (`[SYSTEM:`, `[Step `, `GEMINI_FILE_URI:`).
"""

import hashlib
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.forge.state_store import SharedStateStore, get_shared_store, is_sqlite_persistence_enabled
from core.integrations.gdrive_client import GoogleDriveClient
from core.safety.scrubber import scrub

logger = logging.getLogger(__name__)

# Ephemeral RAM spool used when local disk/SQLite persistence is disabled
_MEMORY_SPOOL: Dict[str, str] = {}
_MEMORY_SPOOL_LOCK = threading.Lock()

VALID_MOVES = frozenset({"ANOMALY", "WORKORDER", "PATCH", "SABOTAGE", "VERDICT", "AUTOPSY"})

_FILENAME_RE = re.compile(
    r"^(?P<ts>\d{8}T\d{6}Z)__"
    r"(?P<actor>[A-Z0-9_-]{2,24})__"
    r"(?P<move>ANOMALY|WORKORDER|PATCH|SABOTAGE|VERDICT|AUTOPSY)__"
    r"(?P<thread>[A-Za-z0-9_-]{2,32})__"
    r"(?P<sha>[0-9a-fA-F]{7,12})__"
    r"(?P<slug>[A-Za-z0-9_-]{1,48})(?:\.md)?$"
)

# Control-sentinel patterns stripped from untrusted board prose before LLM exposure
_INJECTION_PATTERNS = (
    (re.compile(r"\[SYSTEM\s*:", re.IGNORECASE), "[BOARD-QUOTED-SYSTEM:"),
    (re.compile(r"\[Step\s+\d+", re.IGNORECASE), "[BOARD-QUOTED-STEP"),
    (re.compile(r"GEMINI_FILE_URI\s*:", re.IGNORECASE), "BOARD_QUOTED_URI:"),
)


class ProbationWriteFenceError(PermissionError):
    """Raised when a slot in `PROBATION_SHADOW` mode attempts to write to the shared board."""


@dataclass(frozen=True)
class BoardArtifact:
    artifact_id: str
    filename: str
    created_ts: str
    actor: str
    move_type: str
    thread_id: str
    base_sha: str
    slug: str
    parent_id: str = ""
    target_files: List[str] = field(default_factory=list)
    fitness_score: Optional[float] = None
    summary: str = ""
    unified_diff: str = ""
    raw_size: int = 0


def _clean_token(value: str, fallback: str, max_len: int, upper: bool = False) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", (value or "").strip()).strip("-")
    if not cleaned:
        cleaned = fallback
    if upper:
        cleaned = cleaned.upper()
    return cleaned[:max_len]


def neutralize_board_prose(text: str) -> str:
    """Neutralize prompt-injection sentinels in external board prose without corrupting diffs."""
    out = text or ""
    for pat, repl in _INJECTION_PATTERNS:
        out = pat.sub(repl, out)
    return out


def format_board_filename(
    actor: str,
    move_type: str,
    thread_id: str,
    base_sha: str,
    slug: str,
    ts: Optional[datetime] = None,
) -> str:
    move_up = (move_type or "").strip().upper()
    if move_up not in VALID_MOVES:
        raise ValueError(f"Invalid move_type '{move_type}'. Expected one of {sorted(VALID_MOVES)}")
    dt = (ts or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ts_str = dt.strftime("%Y%m%dT%H%M%SZ")
    actor_tok = _clean_token(actor, "NEO", 24, upper=True).replace("-", "_")
    thread_tok = _clean_token(thread_id, "MAIN", 32, upper=False)
    sha_clean = re.sub(r"[^0-9a-fA-F]", "", base_sha or "")[:8].lower()
    if len(sha_clean) < 7:
        sha_clean = sha_clean.ljust(8, "0")
    slug_tok = _clean_token(slug, move_up.lower(), 48, upper=False).lower()
    return f"{ts_str}__{actor_tok}__{move_up}__{thread_tok}__{sha_clean}__{slug_tok}.md"


def render_board_markdown(
    *,
    actor: str,
    move_type: str,
    thread_id: str,
    base_sha: str,
    summary: str,
    parent_id: str = "",
    target_files: Optional[List[str]] = None,
    fitness_score: Optional[float] = None,
    unified_diff: str = "",
    extra_sections: str = "",
) -> str:
    frontmatter = {
        "schema": "neo-stigmergy/v1",
        "actor": actor,
        "move_type": move_type.upper(),
        "thread_id": thread_id,
        "base_sha": base_sha,
        "parent_id": parent_id or "",
        "target_files": list(target_files or []),
        "fitness_score": fitness_score,
    }
    fm_yaml = yaml.safe_dump(frontmatter, sort_keys=False).strip()
    # Scrub outbound telemetry/prose for secrets before posting to cloud Drive,
    # while keeping unified code diffs intact (checked separately for LUFRPT/PEM keys).
    safe_summary = scrub(summary or "").strip()
    parts = [
        "---",
        fm_yaml,
        "---",
        "",
        "## Summary",
        safe_summary,
    ]
    if unified_diff and unified_diff.strip():
        # Redact accidental private keys or PAN-OS LUFRPT tokens inside diffs without prose mangling
        clean_diff = re.sub(r"\bLUFRPT[a-zA-Z0-9+/=]{16,}", "[REDACTED_API_KEY]", unified_diff.strip())
        parts.extend(["", "## Unified Diff", "```diff", clean_diff, "```"])
    if extra_sections and extra_sections.strip():
        parts.extend(["", extra_sections.strip()])
    return "\n".join(parts) + "\n"


def parse_board_markdown(filename: str, raw_markdown: str, artifact_id: str = "") -> Optional[BoardArtifact]:
    """Parse a path-encoded `.md` file into a typed `BoardArtifact`."""
    m = _FILENAME_RE.match((filename or "").strip())
    if not m:
        return None

    text = raw_markdown or ""
    fm_data: Dict[str, Any] = {}
    body = text

    if text.startswith("---"):
        end_idx = text.find("\n---", 3)
        if end_idx != -1:
            raw_fm = text[3:end_idx].strip()
            body = text[end_idx + 4 :].lstrip("\n")
            try:
                loaded = yaml.safe_load(raw_fm)
                if isinstance(loaded, dict):
                    fm_data = loaded
            except Exception as e:
                logger.warning(f"[BOARD] Malformed YAML frontmatter in {filename}: {e}")

    # Extract ```diff ... ``` block if present
    diff_match = re.search(r"```diff\s*\n([\s\S]*?)\n```", body)
    unified_diff = diff_match.group(1) if diff_match else ""

    # Remove diff block from prose summary and neutralize control-header smuggling
    prose = body
    if diff_match:
        prose = (body[: diff_match.start()] + body[diff_match.end() :]).strip()
    prose = re.sub(r"^##\s+Summary\s*", "", prose, flags=re.IGNORECASE).strip()
    prose = re.sub(r"\n##\s+Unified Diff\s*$", "", prose, flags=re.IGNORECASE).strip()
    safe_prose = neutralize_board_prose(prose)

    t_files = fm_data.get("target_files") or []
    if isinstance(t_files, str):
        t_files = [p.strip() for p in t_files.split(",") if p.strip()]
    elif not isinstance(t_files, list):
        t_files = []

    f_score = fm_data.get("fitness_score")
    try:
        f_score = float(f_score) if f_score is not None else None
    except (ValueError, TypeError):
        f_score = None

    eff_id = artifact_id or hashlib.sha256(f"{filename}:{len(text)}".encode("utf-8")).hexdigest()[:16]
    return BoardArtifact(
        artifact_id=eff_id,
        filename=filename,
        created_ts=m.group("ts"),
        actor=m.group("actor"),
        move_type=m.group("move"),
        thread_id=m.group("thread"),
        base_sha=str(fm_data.get("base_sha") or m.group("sha")),
        slug=m.group("slug"),
        parent_id=str(fm_data.get("parent_id") or ""),
        target_files=[str(x) for x in t_files],
        fitness_score=f_score,
        summary=safe_prose[:8000],
        unified_diff=unified_diff,
        raw_size=len(text.encode("utf-8")),
    )


class StigmergicBoard:
    """
    Append-only stigmergic coordination board bridging embodied local NEO slots
    with asynchronous cloud Gemini Spark synthesis workers.
    """

    def __init__(
        self,
        store: Optional[SharedStateStore] = None,
        spool_dir: Optional[Path] = None,
        folder_id: Optional[str] = None,
        drive_client: Optional[GoogleDriveClient] = None,
    ):
        self.store = store or get_shared_store()
        if spool_dir is not None:
            self.spool_dir: Optional[Path] = Path(spool_dir)
            self.spool_dir.mkdir(parents=True, exist_ok=True)
        elif store is not None or is_sqlite_persistence_enabled():
            self.spool_dir = self.store.state_dir / "board_spool"
            self.spool_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.spool_dir = None

        self.folder_id = (
            folder_id
            if folder_id is not None
            else (
                os.getenv("DRIVE_BOARD_FOLDER_ID")
                or os.getenv("KNOWLEDGE_BASE_FOLDER_ID")
                or os.getenv("GOOGLE_DRIVE_FOLDER_ID")
                or ""
            ).strip()
        )
        self._drive_client = drive_client

    @property
    def in_probation_shadow(self) -> bool:
        return os.getenv("NEO_PROBATION_SHADOW", "0").strip() in ("1", "true", "yes")

    def _assert_write_permitted(self) -> None:
        if self.in_probation_shadow:
            raise ProbationWriteFenceError(
                "PROBATION_SHADOW write-fence active: candidate slot cannot publish to the shared board until promoted."
            )

    def post_artifact(
        self,
        *,
        actor: str,
        move_type: str,
        thread_id: str,
        base_sha: str,
        slug: str,
        summary: str,
        parent_id: str = "",
        target_files: Optional[List[str]] = None,
        fitness_score: Optional[float] = None,
        unified_diff: str = "",
        extra_sections: str = "",
    ) -> Dict[str, Any]:
        """Publish an immutable `.md` artifact to local spool and Google Drive (if configured)."""
        self._assert_write_permitted()
        filename = format_board_filename(
            actor=actor,
            move_type=move_type,
            thread_id=thread_id,
            base_sha=base_sha,
            slug=slug,
        )
        content = render_board_markdown(
            actor=actor,
            move_type=move_type,
            thread_id=thread_id,
            base_sha=base_sha,
            summary=summary,
            parent_id=parent_id,
            target_files=target_files,
            fitness_score=fitness_score,
            unified_diff=unified_diff,
            extra_sections=extra_sections,
        )

        # Store locally on disk only when spool_dir is enabled; otherwise keep in zero-disk RAM spool
        if self.spool_dir is not None:
            spool_file = self.spool_dir / filename
            if spool_file.exists():
                digest4 = hashlib.sha256(content.encode("utf-8")).hexdigest()[:4]
                filename = filename[:-3] + f"-{digest4}.md"
                spool_file = self.spool_dir / filename
            spool_file.write_text(content, encoding="utf-8")
            transport = "local_spool"
        else:
            with _MEMORY_SPOOL_LOCK:
                if filename in _MEMORY_SPOOL:
                    digest4 = hashlib.sha256(content.encode("utf-8")).hexdigest()[:4]
                    filename = filename[:-3] + f"-{digest4}.md"
                _MEMORY_SPOOL[filename] = content
                # Bound RAM spool to 100 entries
                if len(_MEMORY_SPOOL) > 100:
                    oldest_key = next(iter(_MEMORY_SPOOL))
                    _MEMORY_SPOOL.pop(oldest_key, None)
            transport = "memory_spool"

        drive_id = None
        drive_url = None
        if self.folder_id:
            try:
                client = self._drive_client or GoogleDriveClient.get_instance(mode="readwrite")
                created = client.upload_markdown_immutable(
                    filename=filename,
                    content=content,
                    folder_id=self.folder_id,
                    strict_parent=True,
                )
                drive_id = created.get("id")
                drive_url = created.get("webViewLink")
                transport = f"google_drive+{transport}"
            except Exception as drive_err:
                logger.warning(f"[BOARD] Drive upload unavailable (readonly/quota fallback to {transport}): {drive_err}")
                transport = f"{transport} (drive_readonly_fallback)"

        artifact_id = drive_id or f"local:{filename}"
        parsed = parse_board_markdown(filename, content, artifact_id=artifact_id)
        if parsed:
            self.store.mark_artifact_seen(
                artifact_id=parsed.artifact_id,
                filename=parsed.filename,
                move_type=parsed.move_type,
                actor=parsed.actor,
                thread_id=parsed.thread_id,
                base_sha=parsed.base_sha,
                created_ts=parsed.created_ts,
            )

        return {
            "artifact_id": artifact_id,
            "filename": filename,
            "transport": transport,
            "drive_url": drive_url,
        }

    def sync_artifacts(
        self,
        *,
        thread_id: Optional[str] = None,
        move_type: Optional[str] = None,
        only_unseen: bool = False,
        limit: int = 25,
    ) -> List[BoardArtifact]:
        """Read immutable `.md` artifacts from Drive (if configured) + spool."""
        raw_entries: List[tuple[str, str, str]] = []  # (artifact_id, filename, content)
        seen_filenames = set()

        # 1. Pull from Google Drive if folder_id is configured
        if self.folder_id:
            try:
                client = self._drive_client or GoogleDriveClient.get_instance(mode="readonly")
                files = client.list_folder_files(self.folder_id, page_size=200)
                for f in files:
                    fname = f.get("name", "")
                    fid = f.get("id", "")
                    fmime = f.get("mimeType", "")
                    if not _FILENAME_RE.match(fname):
                        continue
                    if only_unseen and self.store.is_artifact_seen(fid):
                        continue
                    norm_fname = fname if fname.endswith(".md") else f"{fname}.md"
                    if self.spool_dir is not None:
                        cache_copy = self.spool_dir / norm_fname
                        if cache_copy.is_file():
                            text = cache_copy.read_text(encoding="utf-8", errors="replace")
                        else:
                            raw_bytes = client.download_bytes(fid, mime_type=fmime)
                            text = raw_bytes.decode("utf-8", errors="replace")
                            cache_copy.write_text(text, encoding="utf-8")
                    else:
                        with _MEMORY_SPOOL_LOCK:
                            cached_text = _MEMORY_SPOOL.get(norm_fname)
                        if cached_text is not None:
                            text = cached_text
                        else:
                            raw_bytes = client.download_bytes(fid, mime_type=fmime)
                            text = raw_bytes.decode("utf-8", errors="replace")
                            with _MEMORY_SPOOL_LOCK:
                                _MEMORY_SPOOL[norm_fname] = text
                    raw_entries.append((fid, norm_fname, text))
                    seen_filenames.add(norm_fname)
            except Exception as e:
                logger.warning(f"[BOARD] Drive sync fallback to spool: {e}")

        # 2. Scan disk spool or zero-disk RAM spool
        if self.spool_dir is not None:
            for p in sorted(self.spool_dir.glob("*.md")):
                if p.name in seen_filenames or not _FILENAME_RE.match(p.name):
                    continue
                aid = f"local:{p.name}"
                if only_unseen and self.store.is_artifact_seen(aid):
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
                raw_entries.append((aid, p.name, text))
        else:
            with _MEMORY_SPOOL_LOCK:
                mem_items = sorted(_MEMORY_SPOOL.items(), key=lambda kv: kv[0])
            for fname, text in mem_items:
                if fname in seen_filenames or not _FILENAME_RE.match(fname):
                    continue
                aid = f"local:{fname}"
                if only_unseen and self.store.is_artifact_seen(aid):
                    continue
                raw_entries.append((aid, fname, text))

        artifacts: List[BoardArtifact] = []
        for aid, fname, text in raw_entries:
            art = parse_board_markdown(fname, text, artifact_id=aid)
            if not art:
                continue
            if thread_id and art.thread_id.lower() != thread_id.strip().lower():
                continue
            if move_type and art.move_type != move_type.strip().upper():
                continue
            self.store.mark_artifact_seen(
                artifact_id=art.artifact_id,
                filename=art.filename,
                move_type=art.move_type,
                actor=art.actor,
                thread_id=art.thread_id,
                base_sha=art.base_sha,
                created_ts=art.created_ts,
            )
            artifacts.append(art)

        # Deterministic ordering: timestamp asc, filename asc
        artifacts.sort(key=lambda a: (a.created_ts, a.filename))
        if limit and limit > 0:
            artifacts = artifacts[-int(limit) :]
        return artifacts

    def dispatch_spark_tournament(
        self,
        *,
        thread_id: str,
        base_sha: str,
        problem_statement: str,
        target_files: List[str],
        repo_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Publish a 20-way Gemini Spark Tournament Work-Order (`15 MAP-Elites Builders + 5 Saboteurs`)
        containing exact harness slices and constitutional constraints.
        """
        self._assert_write_permitted()
        from core.forge.laws import PROTECTED_EXACT_PATHS, PROTECTED_PREFIXES

        root = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parent.parent.parent
        slices: List[str] = []
        clean_targets: List[str] = []

        for rel in target_files[:4]:
            cand = (root / rel).resolve()
            if not cand.is_relative_to(root) or not cand.is_file():
                continue
            rel_posix = cand.relative_to(root).as_posix()
            if rel_posix in PROTECTED_EXACT_PATHS or any(rel_posix.startswith(p) for p in PROTECTED_PREFIXES):
                raise ValueError(f"Cannot target protected constitutional file '{rel_posix}' in Spark workorder.")
            clean_targets.append(rel_posix)
            snippet = cand.read_text(encoding="utf-8", errors="replace")[:12000]
            slices.append(f"### Target File: `{rel_posix}`\n```python\n{snippet}\n```")

        tournament_spec = "\n".join(
            [
                "## Gemini Spark 20-Way Tournament Specification",
                "- **Builders (Candidates 01–15 — MAP-Elites Behavioral Grid):**",
                "  - `01–03`: Minimal-diff surgical fix (lowest cyclomatic complexity).",
                "  - `04–06`: Concurrency & lock-contention resilience (`RLock` / bounded queues).",
                "  - `07–09`: Strict memory & latency bounds (zero unbounded buffers).",
                "  - `10–12`: PAN-OS SP3 / XML edge-case completeness (malformed tags, empty nodes, VR overrides).",
                "  - `13–15`: Composable clean-architecture refactor with explicit type contracts.",
                "- **Saboteurs (Candidates 16–20 — Counter-Logic Falsifiers):**",
                "  - Construct adversarial PAN-OS XML payloads, race schedules, or boundary inputs that break Builders `01–15`.",
                "- **Submission Contract:** Upload immutable `.md` replies named:",
                f"  `<UTC_TS>__SPARK_<NN>__PATCH__{_clean_token(thread_id, 'MAIN', 32)}__{base_sha[:8]}__<slug>.md`",
                "  containing YAML frontmatter (`target_files`, `base_sha`) and a clean `diff` code fence.",
                "- **Constitutional Off-Limits (Immutable Referee):**",
                f"  Protected files: `{sorted(PROTECTED_EXACT_PATHS)}` and prefixes `{list(PROTECTED_PREFIXES)}`.",
                "",
                *slices,
            ]
        )

        actor = os.getenv("NEO_SLOT_ID", "NEO_A").upper()
        return self.post_artifact(
            actor=actor,
            move_type="WORKORDER",
            thread_id=thread_id,
            base_sha=base_sha,
            slug="spark-20way-tournament",
            summary=problem_statement,
            target_files=clean_targets,
            extra_sections=tournament_spec,
        )


def board_ops(
    action: str,
    thread_id: str = "",
    move_type: str = "",
    slug: str = "note",
    summary: str = "",
    target_files: str = "",
    unified_diff: str = "",
    limit: int = 15,
    target_device: Optional[str] = None,
) -> str:
    """
    Interact with the path-encoded immutable Stigmergic Board (Google Drive + local spool).

    Args:
        action (str): 'sync' (read board artifacts), 'post' (publish immutable .md artifact),
                      or 'dispatch_spark' (publish 20-way Spark tournament workorder).
        thread_id (str): Thread identifier (e.g. 'T-SP3-NAT').
        move_type (str): Move filter or post type ('ANOMALY', 'WORKORDER', 'PATCH', 'SABOTAGE', 'VERDICT', 'AUTOPSY').
        slug (str): Short kebab-case descriptor for filename encoding.
        summary (str): Problem statement, hypothesis, or falsification verdict.
        target_files (str): Optional comma-separated relative paths (e.g. 'core/panos/ops.py').
        unified_diff (str): Optional unified git diff when publishing a PATCH.
        limit (int): Max artifacts to return during 'sync'.
    """
    board = StigmergicBoard()
    act = (action or "").strip().lower()

    # Resolve current git HEAD short SHA if available
    base_sha = "00000000"
    try:
        import subprocess
        repo_root = Path(__file__).resolve().parent.parent.parent
        cp = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            base_sha = cp.stdout.strip()[:8]
    except Exception:
        pass

    try:
        if act == "sync":
            filt_thread = None if thread_id in ("", "ALL", "*") else thread_id
            filt_move = None if move_type in ("", "ALL", "*") else move_type
            items = board.sync_artifacts(thread_id=filt_thread, move_type=filt_move, limit=limit)
            if not items:
                return "--- STIGMERGIC BOARD (0 matching artifacts) ---"
            lines = [f"--- STIGMERGIC BOARD ({len(items)} artifacts) ---"]
            for it in items:
                diff_flag = f" | diff={len(it.unified_diff)}B" if it.unified_diff else ""
                lines.append(
                    f"[{it.created_ts}] {it.actor} :: {it.move_type} :: thread={it.thread_id} "
                    f":: sha={it.base_sha}{diff_flag} :: file={it.filename}\n"
                    f"  Summary: {it.summary[:300]}"
                )
            return "\n".join(lines)

        t_list = [p.strip() for p in (target_files or "").split(",") if p.strip()]
        actor = os.getenv("NEO_SLOT_ID", "NEO_A").upper()
        eff_thread = (thread_id or "").strip() or "MAIN"
        eff_move = (move_type or "").strip() or "ANOMALY"

        if act == "dispatch_spark":
            if not summary.strip() or not t_list:
                return "Error: 'dispatch_spark' requires non-empty 'summary' and 'target_files'."
            res = board.dispatch_spark_tournament(
                thread_id=eff_thread,
                base_sha=base_sha,
                problem_statement=summary,
                target_files=t_list,
            )
            return f"SPARK WORKORDER PUBLISHED: {res['filename']} (transport={res['transport']})"

        if act == "post":
            if not summary.strip():
                return "Error: 'post' requires non-empty 'summary'."
            res = board.post_artifact(
                actor=actor,
                move_type=eff_move,
                thread_id=eff_thread,
                base_sha=base_sha,
                slug=slug,
                summary=summary,
                target_files=t_list,
                unified_diff=unified_diff,
            )
            return f"BOARD ARTIFACT PUBLISHED: {res['filename']} (transport={res['transport']})"

        return f"Error: Unknown board_ops action '{action}'. Use 'sync', 'post', or 'dispatch_spark'."
    except ProbationWriteFenceError as pfe:
        return f"ERROR: Security Policy Block - {pfe}"
    except Exception as e:
        return f"Error: board_ops failed: {e}"
