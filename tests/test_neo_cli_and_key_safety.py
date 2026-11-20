"""
Counter-Logic Regression Suite for `neo_cli.py` (SSH/tmux Resident CLI) & Runtime Key Safety:
1. Consume-once `seal_runtime_secrets()` moves keys out of `os.environ` into private `_SEALED_VAULT`.
2. `register_runtime_secret()` + `scrub_registered_secrets()` redact raw, Base64, hex, URL-encoded,
   and reversed (`[::-1]`) forms of loaded secrets across ALL tools (including `_RAW_CODE_TOOLS`) and receipts.
3. Constitutional Ring (`laws.py`) + `inspect_own_harness` block `secrets.py` access, `dotenv` imports,
   `os.environ` scraping, and `.env` / `/proc/` file reads while preserving valid `tool_keeper.py` edits.
4. `slot_forge(action="verify_and_promote")` respects terminal diff approval hooks (`[y/N]`).
5. `neo_cli.py` `/stage` strips `commit`, normalizes `[ a b ]` PAN-OS 10.0 brackets, sends `top`,
   uses literal `tmux send-keys -l`, and aborts mid-batch on `Invalid syntax` before sending subsequent rules.
6. `@ssh` / `/grab` `sanitize_ssh_capture()` redacts passwords, pre-shared keys, `LUFRPT`, and `AIza` tokens.
"""

import base64
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import neo_cli
from core.forge.laws import ConstitutionalError, validate_mutation_paths, validate_python_ast
from core.forge.slot_mutator import register_forge_approval_hook, slot_forge
from core.forge.state_store import SharedStateStore
from core.integrations.secrets import (
    DotenvSecretsProvider,
    clear_sealed_secrets,
    reset_provider,
    seal_runtime_secrets,
)
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.tool_keeper import inspect_own_harness
from core.safety.scrubber import clear_registered_secrets, register_runtime_secret, scrub


@pytest.fixture(autouse=True)
def _clean_secret_state():
    clear_sealed_secrets()
    clear_registered_secrets()
    register_forge_approval_hook(None)
    reset_provider()
    yield
    clear_sealed_secrets()
    clear_registered_secrets()
    register_forge_approval_hook(None)
    reset_provider()


def test_seal_runtime_secrets_purges_os_environ_and_serves_from_sealed_vault(monkeypatch):
    fake_panos = "LUFRPT14aSuperSecretPanosToken987654321"
    fake_gemini = "AIzaSyD9876543210abcdefGHIJKLMNopqrstuv"
    monkeypatch.setenv("PANOS_API_KEY_FW_HQ", fake_panos)
    monkeypatch.setenv("GEMINI_API_KEY", fake_gemini)
    monkeypatch.setenv("PROMPTS_YAML_SHA", "deadbeef" * 8)

    purged = seal_runtime_secrets()
    assert purged >= 2

    # Keys are completely gone from os.environ
    assert "PANOS_API_KEY_FW_HQ" not in os.environ
    assert "GEMINI_API_KEY" not in os.environ
    # Public non-secret config stays intact
    assert os.environ.get("PROMPTS_YAML_SHA") == "deadbeef" * 8

    # DotenvSecretsProvider still resolves both keys from _SEALED_VAULT
    provider = DotenvSecretsProvider()
    assert provider.get("panos_api_key_fw_hq") == fake_panos
    assert provider.get("gemini_api_key") == fake_gemini


def test_registered_secrets_redacted_in_raw_base64_hex_reversed_and_raw_code_tools():
    secret = "MyUltraSensitiveVaultSecret2026!"
    register_runtime_secret(secret)

    b64_val = base64.b64encode(secret.encode()).decode("ascii")
    rev_val = secret[::-1]
    hex_val = secret.encode().hex()

    for payload in (
        f"raw={secret}",
        f"b64={b64_val}",
        f"rev={rev_val}",
        f"hex={hex_val}",
        "bare_gemini=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    ):
        cleaned = scrub(payload)
        assert secret not in cleaned
        assert b64_val not in cleaned
        assert rev_val not in cleaned
        assert hex_val not in cleaned
        assert "AIzaSyA1B2" not in cleaned

    # Even _RAW_CODE_TOOLS (board_ops / inspect_own_harness / slot_forge) must strip registered secrets
    # while preserving git commit SHAs untouched!
    def board_ops(**kwargs):
        return f"commit a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 leaked={rev_val}"

    executor = ToolExecutor(policy=None, hitl=None, circuit_breaker=MagicMock(), tools=[board_ops])
    part = MagicMock()
    part.function_call.name = "board_ops"
    part.function_call.args = {"action": "sync"}

    res = executor.execute_function_call(
        part=part,
        manifest_str="board_ops",
        trace_id="t-sec-1",
        user_id="ssh-op",
        drive_call_history={},
        turn=0,
        thought_signatures=[],
        step_number=1,
    )
    assert rev_val not in res.raw_output
    assert "[REDACTED_RUNTIME_SECRET]" in res.raw_output
    assert "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678" in res.raw_output


@pytest.mark.parametrize(
    "protected_path",
    [
        "neo_cli.py",
        "neo_tmux.sh",
        "core/integrations/secrets.py",
        "core/pipeline/tool_executor.py",
        "web/app.js",
    ],
)
def test_laws_block_protected_cli_and_secret_paths(protected_path):
    with pytest.raises(ConstitutionalError):
        validate_mutation_paths([protected_path])


@pytest.mark.parametrize(
    "malicious_source",
    [
        "import dotenv\ndotenv.dotenv_values('.env')\n",
        "from core.integrations.secrets import get_secret\nx = get_secret('gemini_api_key')\n",
        "from core.integrations import secrets\nx = secrets._SEALED_VAULT\n",
        "x = open('.env').read()\n",
        "from pathlib import Path\nx = Path('/proc/self/environ').read_text()\n",
        "import os\nx = os.getenv('PANOS_API_KEY_FW_HQ')\n",
        "import os\nx = os.environ['GEMINI_API_KEY']\n",
        "import os\nx = dict(os.environ.items())\n",
    ],
)
def test_laws_ast_blocks_credential_exfiltration_primitives(malicious_source):
    with pytest.raises(ConstitutionalError):
        validate_python_ast(malicious_source, filename="core/panos/ops.py")


def test_laws_ast_still_permits_live_tool_keeper_source():
    """Ensuring legitimate open(self.registry_path) in tool_keeper.py remains valid for slot_forge."""
    tk_src = Path("core/pipeline/tool_keeper.py").read_text(encoding="utf-8")
    validate_python_ast(tk_src, filename="core/pipeline/tool_keeper.py")
    assert "forbidden" in inspect_own_harness("core/integrations/secrets.py").lower()


def test_slot_forge_verify_and_promote_honors_terminal_rejection_hook(monkeypatch):
    monkeypatch.delenv("NEO_SHARED_STATE_DIR", raising=False)
    monkeypatch.setenv("NEO_SLOT_ID", "STANDALONE")
    SharedStateStore.reset_instance()
    slot_forge(action="reset_inactive")

    target_rel = "config/commands.yaml"
    orig_text = Path(target_rel).read_text(encoding="utf-8")
    slot_forge(action="stage_file", target_path=target_rel, content=orig_text + "\n# test comment\n")

    seen_diffs = []
    register_forge_approval_hook(lambda paths, diff: (seen_diffs.append((paths, diff)) or False))

    out = slot_forge(action="verify_and_promote")
    assert "REJECTED BY OPERATOR" in out
    assert seen_diffs and target_rel in seen_diffs[0][0]
    assert "+# test comment" in seen_diffs[0][1]
    assert Path(target_rel).read_text(encoding="utf-8") == orig_text
    slot_forge(action="reset_inactive")


def test_neo_cli_extract_stageable_lines_strips_commit_and_normalizes_brackets():
    reply = (
        "Stage these rules:\n"
        "```panos\n"
        "admin@firewall-a# set deviceconfig system permitted-ip 192.168.1.20/32\n"
        "set rulebase security rules allow-dns from inside to dmz application [dns-base ssl] action allow\n"
        "move rulebase security rules allow-dns top\n"
        "commit\n"
        "request restart system\n"
        "```\n"
    )
    lines = neo_cli.extract_stageable_panos_lines(reply)
    assert lines == [
        "set deviceconfig system permitted-ip 192.168.1.20/32",
        "set rulebase security rules allow-dns from inside to dmz application [ dns-base ssl ] action allow",
        "move rulebase security rules allow-dns top",
    ]


def test_neo_cli_stage_aborts_immediately_on_mid_batch_syntax_error():
    commands = [
        "set rulebase security rules bad-rule from inside to bogus-zone action allow",
        "set rulebase default-security-rules rules interzone-default action deny",
    ]
    sent_keys = []
    captures = [
        (True, "admin@firewall-a# "),
        (True, "admin@firewall-a# "),
        (True, "admin@firewall-a# set rulebase...\nInvalid syntax.\nadmin@firewall-a# "),
    ]

    def fake_run(argv, **kwargs):
        sent_keys.append(argv)
        cp = MagicMock()
        cp.returncode = 0
        return cp

    with patch("neo_cli.capture_tmux_pane", side_effect=captures), patch("neo_cli.subprocess.run", side_effect=fake_run):
        ok, msg = neo_cli.stage_lines_to_tmux_ssh("%1", commands, step_delay=0.0)

    assert ok is False
    assert "ABORTED at line 1/2" in msg
    assert "Invalid syntax" in msg
    # Crucially, line 2 ('interzone-default action deny') was NEVER sent!
    flattened = " ".join(" ".join(cmd) for cmd in sent_keys)
    assert "top" in flattened
    assert "bad-rule" in flattened
    assert "interzone-default" not in flattened


def test_neo_cli_sanitize_ssh_capture_redacts_credentials():
    raw_ssh = (
        "admin@firewall-a> configure\n"
        "admin@firewall-a# set network ike gateway gw1 authentication pre-shared-key key SuperSecretPSK123\n"
        "token LUFRPT1234567890abcdefghij\n"
        "admin@firewall-a# run show session info\n"
        "Number of active sessions: 60\n"
    )
    clean = neo_cli.sanitize_ssh_capture(raw_ssh)
    assert "SuperSecretPSK123" not in clean
    assert "LUFRPT123456" not in clean
    assert "[REDACTED_CREDENTIAL_LINE]" in clean
    assert "Number of active sessions: 60" in clean
