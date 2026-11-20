"""
Constitutional Law Ring (`core/forge/laws.py`).

Enforces strict self-modification boundaries so candidate slots (`Slot A` / `Slot B`)
and cloud Spark patches can evolve operational capabilities, prompts, and workflows
WITHOUT ever modifying the supervisor, safety perimeter, epistemic referee, secrets, or test bench.
"""

import ast
import posixpath
import re
from pathlib import Path
from typing import Iterable, List, Set

import yaml

# Files that no autonomous slot mutation or Spark patch may ever create, modify, or delete.
PROTECTED_EXACT_PATHS: Set[str] = {
    "neo_cli.py",
    "neo_tmux.sh",
    "server.py",
    "stem.py",
    ".env",
    ".env.example",
    ".gitignore",
    "AGENTS.md",
    "requirements.txt",
    "core/forge/__init__.py",
    "core/forge/laws.py",
    "core/forge/crucible.py",
    "core/forge/state_store.py",
    "core/forge/slot_mutator.py",
    "core/pipeline/outcomes.py",
    "core/pipeline/evidence.py",
    "core/pipeline/tool_executor.py",
    "core/safety/policy_engine.py",
    "core/safety/auth.py",
    "core/safety/hitl.py",
    "core/safety/budget_guard.py",
    "core/safety/scrubber.py",
    "core/safety/command_filter.py",
    "core/panos/client.py",
    "core/panos/research.py",
    "core/integrations/gdrive_client.py",
    "core/integrations/secrets.py",
    "core/utils/startup_validator.py",
}

PROTECTED_PREFIXES = (
    "tests/",
    ".git/",
    ".slots/",
    ".state/",
    "_legacy/",
    "web/",
)

ALLOWED_MUTATION_ROOTS = (
    "core/",
    "config/",
)

ALLOWED_EXTENSIONS = frozenset({".py", ".yaml", ".yml"})

FORBIDDEN_AST_CALLS = frozenset({"eval", "exec", "compile", "__import__", "getattr"})
FORBIDDEN_AST_MODULES = frozenset({
    "ctypes",
    "dotenv",
    "pty",
    "winreg",
    "subprocess",
    "socket",
    "http",
    "urllib",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "ftplib",
    "smtplib",
    "telnetlib",
    "paramiko",
})

_ALLOWED_SECRETS_IMPORTERS = frozenset({
    "core/brain.py",
    "core/panos/client.py",
    "core/utils/startup_validator.py",
})

_FORBIDDEN_VAULT_IDENTIFIERS = frozenset({
    "_SEALED_VAULT",
    "_REGISTERED_SECRET_VARIANTS",
    "_SCRUB_KEY",
    "_HITL_SECRET",
})

_SENSITIVE_TARGET_SUBSTRINGS = (
    ".env",
    "/proc/",
    "service-account",
    "service_account",
    "api_key",
    "secret",
    "token",
    "password",
    "phash",
    "private_key",
    "credential",
)

# Narrow grandfathered stdlib imports for non-egress internal utilities
PER_FILE_ALLOWED_AST_MODULES = {
    "core/integrations/board_sync.py": frozenset({"subprocess"}),
    "core/utils/startup_validator.py": frozenset({"socket"}),
}


class ConstitutionalError(PermissionError):
    """Raised when a proposed slot mutation violates an immutable constitutional law."""


def normalize_rel_path(raw_path: str) -> str:
    """Normalize a relative repository path and reject traversal or absolute paths."""
    if not raw_path or not isinstance(raw_path, str):
        raise ConstitutionalError("Target path must be a non-empty string.")
    cleaned = raw_path.strip().replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise ConstitutionalError(f"Absolute path '{raw_path}' is forbidden.")
    norm = posixpath.normpath(cleaned)
    if norm in ("", ".") or norm.startswith("../") or "/../" in f"/{norm}/":
        raise ConstitutionalError(f"Path traversal in '{raw_path}' is forbidden.")
    return norm


def validate_mutation_paths(paths: Iterable[str]) -> List[str]:
    """Validate every target path against the Constitutional Ring and allowed roots."""
    normalized: List[str] = []
    for raw in paths:
        rel = normalize_rel_path(raw)
        low = rel.lower()

        if rel in PROTECTED_EXACT_PATHS or low in {p.lower() for p in PROTECTED_EXACT_PATHS}:
            raise ConstitutionalError(
                f"Constitutional violation: '{rel}' is an immutable referee/safety file."
            )

        for prefix in PROTECTED_PREFIXES:
            if low.startswith(prefix.lower()) or low == prefix.rstrip("/").lower():
                raise ConstitutionalError(
                    f"Constitutional violation: '{rel}' lies inside protected zone '{prefix}'."
                )

        if (
            "service_account" in low
            or "service-account" in low
            or "running_config" in low
            or Path(rel).name.startswith(".env")
        ):
            raise ConstitutionalError(
                f"Constitutional violation: '{rel}' is a protected credential/config artifact."
            )

        if not any(rel.startswith(root) for root in ALLOWED_MUTATION_ROOTS):
            raise ConstitutionalError(
                f"Scope violation: '{rel}' outside mutable roots {ALLOWED_MUTATION_ROOTS}."
            )

        ext = Path(rel).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ConstitutionalError(
                f"Extension violation: '{rel}' ({ext}) not in {sorted(ALLOWED_EXTENSIONS)}."
            )

        normalized.append(rel)

    if not normalized:
        raise ConstitutionalError("Mutation contains zero target paths.")
    return normalized


def extract_diff_paths(unified_diff: str) -> List[str]:
    """Extract all touched relative file paths (`--- a/...`, `+++ b/...`) from a unified diff."""
    if not unified_diff or not isinstance(unified_diff, str):
        raise ConstitutionalError("Unified diff cannot be empty.")

    paths: List[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            token = line[4:].strip().split("\t", 1)[0].strip()
            if token == "/dev/null":
                continue
            if token.startswith("a/") or token.startswith("b/"):
                token = token[2:]
            if token and token not in paths:
                paths.append(token)

    if not paths:
        raise ConstitutionalError("No valid file headers ('--- a/...', '+++ b/...') found in unified diff.")
    return validate_mutation_paths(paths)


def validate_python_ast(source_code: str, filename: str = "<candidate>") -> None:
    """
    Parse Python source and reject syntax errors, dangerous dynamic execution primitives,
    or `shell=True` subprocess escapes.
    """
    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as se:
        raise ConstitutionalError(f"Syntax error in '{filename}' line {se.lineno}: {se.msg}") from se

    norm_file = filename.strip().replace("\\", "/") if filename else ""
    allowed_for_file = PER_FILE_ALLOWED_AST_MODULES.get(norm_file, frozenset())

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_VAULT_IDENTIFIERS:
            raise ConstitutionalError(
                f"Forbidden internal vault/key identifier '{node.id}' in '{filename}'."
            )
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_VAULT_IDENTIFIERS:
            raise ConstitutionalError(
                f"Forbidden internal vault/key attribute '{node.attr}' in '{filename}'."
            )
        # Block bulk os.environ dumping (os.environ.items/values/copy, dict(os.environ))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"
                and node.attr in ("items", "values", "copy", "keys")
            ):
                raise ConstitutionalError(
                    f"Forbidden bulk environment inspection 'os.environ.{node.attr}' in '{filename}'."
                )
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            if isinstance(node.value.value, ast.Name) and node.value.value.id == "os" and node.value.attr == "environ":
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    low_k = node.slice.value.lower()
                    if any(s in low_k for s in _SENSITIVE_TARGET_SUBSTRINGS):
                        raise ConstitutionalError(
                            f"Forbidden secret environment subscript 'os.environ[{node.slice.value!r}]' in '{filename}'."
                        )

        if isinstance(node, ast.Import):
            for alias in node.names:
                top_mod = alias.name.split(".")[0]
                if top_mod in FORBIDDEN_AST_MODULES and top_mod not in allowed_for_file:
                    raise ConstitutionalError(
                        f"Forbidden module import '{alias.name}' in '{filename}'."
                    )
                if alias.name == "core.integrations.secrets" and norm_file not in _ALLOWED_SECRETS_IMPORTERS:
                    raise ConstitutionalError(
                        f"Forbidden credential module import '{alias.name}' in '{filename}'."
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_mod = node.module.split(".")[0]
            if top_mod in FORBIDDEN_AST_MODULES and top_mod not in allowed_for_file:
                raise ConstitutionalError(
                    f"Forbidden module import '{node.module}' in '{filename}'."
                )
            if node.module.startswith("core.integrations.secrets") and norm_file not in _ALLOWED_SECRETS_IMPORTERS:
                raise ConstitutionalError(
                    f"Forbidden credential module import '{node.module}' in '{filename}'."
                )
        elif isinstance(node, ast.Call):
            # Note: core/brain.py legitimately uses getattr; forbid getattr in newly mutated tool/config modules
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_AST_CALLS:
                if not (node.func.id == "getattr" and norm_file in ("core/brain.py", "core/pipeline/synthesizer.py", "core/pipeline/tool_keeper.py")):
                    raise ConstitutionalError(
                        f"Forbidden dynamic execution call '{node.func.id}()' in '{filename}'."
                    )
            # Block os.system / os.popen
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr in ("system", "popen", "execl", "execvp"):
                    raise ConstitutionalError(
                        f"Forbidden shell call 'os.{node.func.attr}()' in '{filename}'."
                    )
            # Block open/Path/getenv/environ.get targeting .env, /proc/, or secret key names
            is_file_or_env_read = False
            if isinstance(node.func, ast.Name) and node.func.id in ("open", "Path"):
                is_file_or_env_read = True
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in ("getenv", "read_text", "read_bytes", "open"):
                    is_file_or_env_read = True
                elif (
                    node.func.attr == "get"
                    and isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "os"
                    and node.func.value.attr == "environ"
                ):
                    is_file_or_env_read = True
            if is_file_or_env_read and norm_file not in _ALLOWED_SECRETS_IMPORTERS:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        low_arg = arg.value.lower()
                        if any(s in low_arg for s in _SENSITIVE_TARGET_SUBSTRINGS):
                            raise ConstitutionalError(
                                f"Forbidden credential/secret read target '{arg.value}' in '{filename}'."
                            )
            # Block shell=True in subprocess calls
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    raise ConstitutionalError(
                        f"Forbidden 'shell=True' subprocess execution in '{filename}'."
                    )


def validate_yaml_content(yaml_text: str, rel_path: str) -> None:
    """Validate YAML syntax and enforce required schema keys on `config/prompts.yaml`."""
    try:
        loaded = yaml.safe_load(yaml_text)
    except Exception as ye:
        raise ConstitutionalError(f"Invalid YAML in '{rel_path}': {ye}") from ye

    if rel_path == "config/prompts.yaml":
        if not isinstance(loaded, dict):
            raise ConstitutionalError("config/prompts.yaml must parse to a YAML mapping.")
        from core.pipeline.prompt_assembler import PROMPT_ASSEMBLY_ORDER

        persona_block = loaded.get("neo") if isinstance(loaded.get("neo"), dict) else loaded
        missing = [k for k in PROMPT_ASSEMBLY_ORDER if not str(persona_block.get(k, "")).strip()]
        if missing:
            raise ConstitutionalError(
                f"config/prompts.yaml mutation missing required PROMPT_ASSEMBLY_ORDER keys: {missing}"
            )
