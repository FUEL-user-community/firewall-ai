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
        "core/panos/sanctuary.py",
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


def test_f01_extract_dnat_ip_skips_outbound_snat_but_detects_real_dnat():
    """Verify F-01: outbound SNAT source-translation IP is never misclassified as DNAT."""
    from core.panos.ops import _extract_dnat_ip

    snat_only_yaml = {
        "result": {
            "rules": "Outbound-Internet-SNAT",
            "source-translation": {"ip": "203.0.113.2", "dynamic-ip-and-port": {"ip": "203.0.113.2"}},
        }
    }
    assert _extract_dnat_ip(snat_only_yaml, source_ip="10.1.1.5", dest_ip="8.8.8.8") is None

    real_dnat_yaml = {
        "result": {
            "rules": "Inbound-HTTPS-DNAT",
            "ip": "192.168.50.10:443",
        }
    }
    assert _extract_dnat_ip(real_dnat_yaml, source_ip="198.51.100.9", dest_ip="203.0.113.10") == "192.168.50.10"


def test_f02_drive_knowledge_uses_singleton_gdrive_client_after_secret_seal():
    """Verify F-02: drive_knowledge._init_drive_service delegates to GoogleDriveClient.get_instance('readonly')."""
    from core.integrations import drive_knowledge
    from core.integrations.gdrive_client import GoogleDriveClient

    fake_service = MagicMock(name="drive_v3_service")
    fake_wrapper = MagicMock()
    fake_wrapper.get_service.return_value = (fake_service, None)

    with patch.object(GoogleDriveClient, "get_instance", return_value=fake_wrapper) as mock_get_inst:
        svc, err = drive_knowledge._init_drive_service()
        assert svc is fake_service
        assert err is None
        mock_get_inst.assert_called_once_with(mode="readonly")


def test_f05_apply_dynamic_tag_blocks_mgt_and_active_admin_ips_under_elevated_policy():
    """Verify F-05: Sanctuary blocks tagging firewall MGT IP and active admin IPs even in READ_WRITE mode."""
    from core.panos.client import PanOSClient
    from core.panos.ops import apply_dynamic_tag
    from core.safety.policy_engine import PolicyEngine

    mock_client = MagicMock(spec=PanOSClient)
    mock_client.hostname = "192.168.1.254"
    mock_client.execute_op.return_value = (
        200,
        "<response status='success'><result><admins><entry><admin>admin</admin><from>192.168.1.20</from></entry></admins></result></response>",
    )
    mock_client.execute_user_id.return_value = (200, "<response status='success'/>")

    mock_pool = MagicMock()
    mock_pool.get_client.return_value = mock_client

    fake_brain = MagicMock()
    fake_brain.policy = PolicyEngine(mode="READ_WRITE")

    with patch("core.panos.ops._get_pool", return_value=mock_pool), patch(
        "core.brain.get_active_brain", return_value=fake_brain
    ):
        # 1. Firewall MGT IP blocked
        res_mgt = apply_dynamic_tag("192.168.1.254", "NEO-Quarantine")
        assert "Sanctuary Law forbids tagging firewall management IP" in res_mgt

        # 2. Active SSH/WebUI admin IP blocked
        res_adm = apply_dynamic_tag("192.168.1.20", "NEO-Quarantine")
        assert "Sanctuary Law forbids tagging active admin session IP" in res_adm

        # 3. Normal host IP succeeds when active brain policy is READ_WRITE
        res_ok = apply_dynamic_tag("10.50.1.99", "NEO-Quarantine")
        assert "SUCCESS" in res_ok
        assert mock_client.execute_user_id.called


def test_precommit_sanctuary_catches_lockout_and_active_flow_severance():
    """Verify Pre-Commit Sanctuary fast-passes clean configs and flags MGT lockout + interzone-default severance."""
    from core.panos.sanctuary import evaluate_precommit_sanctuary

    mock_client = MagicMock()
    mock_pool = MagicMock()
    mock_pool.get_client.return_value = mock_client

    # Case 1: Empty candidate changes -> immediate safe fast-path
    mock_client.execute_op.return_value = (200, "<response status='success'><result></result></response>")
    with patch("core.panos.sanctuary.PanOSClientPool.get_instance", return_value=mock_pool):
        clean_res = evaluate_precommit_sanctuary(target_device="fw-hq")
    assert clean_res["safe"] is True
    assert clean_res["changed"] is False

    # Case 2: Candidate permitted-ip excludes active admin 192.168.1.20 + interzone-default flipped to deny
    def fake_op(cmd):
        if "<changes" in cmd:
            return (
                200,
                "<response status='success'><result><entry>deviceconfig system permitted-ip</entry>"
                "<entry>rulebase default-security-rules interzone-default</entry></result></response>",
            )
        if "<admins" in cmd:
            return (
                200,
                "<response status='success'><result><admins><entry><admin>admin</admin>"
                "<from>192.168.1.20</from><type>SSH</type></entry></admins></result></response>",
            )
        if "<system><info" in cmd:
            return (
                200,
                "<response status='success'><result><system><ip-address>192.168.1.254</ip-address>"
                "<netmask>255.255.255.0</netmask><default-gateway>192.168.1.1</default-gateway></system></result></response>",
            )
        return (200, "<response status='success'><result/></response>")

    def fake_get(xpath):
        if xpath.endswith("/deviceconfig/system"):
            return (
                200,
                "<response status='success'><result><system><ip-address>192.168.1.254</ip-address>"
                "<permitted-ip><entry name='10.99.99.0/24'/></permitted-ip></system></result></response>",
            )
        if xpath.endswith("/default-security-rules"):
            return (
                200,
                "<response status='success'><result><default-security-rules><rules>"
                "<entry name='interzone-default'><action>deny</action></entry>"
                "</rules></default-security-rules></result></response>",
            )
        if xpath.endswith("/rulebase/security"):
            return (200, "<response status='success'><result><security><rules/></security></result></response>")
        return (200, "<response status='success'><result/></response>")

    mock_client.execute_op.side_effect = fake_op
    mock_client.execute_get.side_effect = fake_get
    mock_client.execute_log.return_value = (
        200,
        "<response status='success'><result><log><logs>"
        "<entry><from>inside</from><to>dmz</to><src>10.1.1.5</src><dst>10.2.2.10</dst><app>dns-base</app></entry>"
        "</logs></log></result></response>",
    )

    with patch("core.panos.sanctuary.PanOSClientPool.get_instance", return_value=mock_pool):
        risk_res = evaluate_precommit_sanctuary(target_device="fw-hq")

    assert risk_res["safe"] is False
    assert any("MGT SELF-LOCKOUT" in w and "192.168.1.20" in w for w in risk_res["warnings"])
    assert any("ACTIVE FLOW SEVERANCE" in w and "inside->dmz" in w for w in risk_res["warnings"])


def test_neo_cli_symbiotic_ssh_helpers_and_pty_stage_abort():
    """Verify resolve_ssh_target, extract_echoed_command_after_prompt, and stage_lines_to_pty_master abort."""
    target_str, alias = neo_cli.resolve_ssh_target("fw-hq")
    assert target_str == "admin@192.168.1.254"
    assert alias == "fw-hq"

    custom_str, custom_alias = neo_cli.resolve_ssh_target("netops@fw-hq")
    assert custom_str == "netops@192.168.1.254"
    assert custom_alias == "fw-hq"

    mode, echoed = neo_cli.extract_echoed_command_after_prompt("\x1b[0madmin@firewall-a# commit force")
    assert mode == "config"
    assert echoed == "commit force"

    written_cmds = []
    read_chunks = [
        b"[edit]\r\nadmin@firewall-a# ",
        b"set rulebase security rules bad-rule\r\nInvalid syntax.\r\nadmin@firewall-a# ",
    ]

    with patch("neo_cli.os.write", side_effect=lambda fd, data: written_cmds.append(data.decode("utf-8"))), patch(
        "neo_cli.os.read", side_effect=read_chunks
    ), patch("select.select", return_value=([99], [], [])):
        ok, msg = neo_cli.stage_lines_to_pty_master(
            99,
            [
                "set rulebase security rules bad-rule from inside to bogus action allow",
                "set rulebase default-security-rules rules interzone-default action deny",
            ],
            current_mode="config",
            timeout_per_cmd=0.2,
        )

    assert ok is False
    assert "ABORTED at line 1/2" in msg
    joined_writes = "".join(written_cmds)
    assert "top\r" in joined_writes
    assert "bad-rule" in joined_writes
    assert "interzone-default" not in joined_writes


def test_neo_cli_ansi_markdown_tree_and_auto_pager():
    """Verify **bold** -> ANSI, top receipt uses '┌─ #1' without dangling '├─', and tall outputs pipe to less -RFX."""
    rendered = neo_cli.render_markdown_ansi("**Vitals:**\n\n\n- **System:** `PA-VM`")
    assert "**" not in rendered
    assert "`PA-VM`" not in rendered
    assert "\n\n\n" not in rendered
    assert neo_cli.C_BOLD in rendered

    captured_blocks = []
    with patch("neo_cli._emit_or_page", side_effect=lambda txt: captured_blocks.append(txt)):
        neo_cli._render_turn_output(
            {
                "reasoning": [],
                "receipts": [
                    {"tool": "map_home_topology", "duration_ms": 210.0, "status": "SUCCESS"},
                    {"tool": "get_telemetry_snapshot", "duration_ms": 340.0, "status": "SUCCESS"},
                ],
                "verdict": "**Posture:** Clean.",
                "trace_id": "t-1",
            }
        )
    out_txt = neo_cli.strip_ansi(captured_blocks[0])
    assert out_txt.startswith("┌─ #1 map_home_topology")
    assert "└─ #2 get_telemetry_snapshot" in out_txt
    assert "**Posture:**" not in out_txt

    # Tall output triggers `less -RFX` when stdout & stdin are TTYs
    tall_text = "\n".join(f"line {i}" for i in range(40)) + "\n"
    with patch("neo_cli.sys.stdout.isatty", return_value=True), patch(
        "neo_cli.sys.stdin.isatty", return_value=True
    ), patch("neo_cli.shutil.which", return_value="/usr/bin/less"), patch(
        "neo_cli.subprocess.run"
    ) as mock_less:
        neo_cli._emit_or_page(tall_text)
        mock_less.assert_called_once()
        assert mock_less.call_args[0][0] == ["less", "-RFX"]


def test_validate_model_id_rejects_double_dot_typo_in_startup_and_brain(monkeypatch):
    """Verify 'gemini-3.1-pro-p..review' fails validate_model_id and validate_startup immediately."""
    from core.pipeline.model_config import validate_model_id
    from core.utils.startup_validator import validate_startup

    ok_bad, msg_bad = validate_model_id("gemini-3.1-pro-p..review")
    assert ok_bad is False
    assert ".." in msg_bad

    ok_good, cleaned = validate_model_id("gemini-3.1-pro-preview")
    assert ok_good is True
    assert cleaned == "gemini-3.1-pro-preview"

    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.1-pro-p..review")
    monkeypatch.setenv("PANOS_HOSTNAME", "192.168.1.254")
    with pytest.raises(RuntimeError, match="GEMINI_MODEL invalid"):
        validate_startup()


def test_vt100_backspace_and_cr_folding_preserves_commit_and_empty_prompt():
    """Verify Change A: mistyped+backspaced 'commit' still triggers Sanctuary and backspaced line unlocks '@'."""
    # 1. 'commti' + BS*2 + 'it' -> 'commit'
    mode1, cmd1 = neo_cli.extract_echoed_command_after_prompt("admin@firewall-a# commti\x08\x08it")
    assert mode1 == "config"
    assert cmd1 == "commit"

    # 2. 'show' + BS + CSI-erase * 4 -> empty prompt '' (unlocks column-0 '@')
    erased = "admin@firewall-a# show\x08\x1b[K\x08\x1b[K\x08\x1b[K\x08\x1b[K"
    mode2, cmd2 = neo_cli.extract_echoed_command_after_prompt(erased)
    assert mode2 == "config"
    assert cmd2 == ""
    assert neo_cli.detect_panos_prompt_mode(erased) == "config"

    # 3. In-line carriage overwrite (\r without \n)
    overwritten = "admin@firewall-a# badcmd\radmin@firewall-a# commit force\x1b[K"
    mode3, cmd3 = neo_cli.extract_echoed_command_after_prompt(overwritten)
    assert mode3 == "config"
    assert cmd3 == "commit force"


def test_candidate_diff_and_walk_warning_and_live_write_toggle(monkeypatch):
    """Verify Change B (@diff + @walk uncommitted warning) and Change C (@write on/off toggle)."""
    from core.panos.sanctuary import summarize_candidate_diff
    from core.safety.policy_engine import PolicyEngine

    mock_client = MagicMock()
    mock_pool = MagicMock()
    mock_pool.get_client.return_value = mock_client

    mock_client.execute_op.return_value = (
        200,
        "<response status='success'><result><entry><xpath>/config/devices/entry/vsys/entry/rulebase/security</xpath>"
        "<cmd>set</cmd><admin>admin</admin></entry></result></response>",
    )
    mock_client.execute_get.return_value = (
        200,
        "<response status='success'><result><security><rules>"
        "<entry name='temp-wide-open'><action>allow</action>"
        "<application><member>any</member></application><service><member>any</member></service></entry>"
        "</rules></security></result></response>",
    )

    with patch("core.panos.sanctuary.PanOSClientPool.get_instance", return_value=mock_pool):
        diff_txt = summarize_candidate_diff(target_device="fw-hq")

    assert "Pending Candidate Edits: 1" in diff_txt
    assert "temp-wide-open" in diff_txt
    assert "application:any" in diff_txt
    assert "no-security-profile" in diff_txt

    # Verify @walk emits uncommitted candidate warning banner
    walk_blocks = []
    with patch("core.panos.sanctuary.get_pending_candidate_changes", return_value=["edit-1"]), patch(
        "core.panos.ops.test_packet_walk", return_value="sp3_packet_walk:\n  action: allow"
    ), patch("neo_cli._emit_or_page", side_effect=lambda t: walk_blocks.append(t)):
        neo_cli._run_zero_token_walk("10.1.1.5 8.8.8.8 443 tcp", target_device="fw-hq")
    assert "uncommitted candidate edit(s) exist in [edit]" in walk_blocks[0]

    # Verify @write on / off toggles PolicyEngine in-session
    monkeypatch.setenv("POLICY_MODE", "READ_ONLY")
    fake_brain = MagicMock()
    fake_brain.policy = PolicyEngine(mode="READ_ONLY")
    fake_brain.tool_executor.policy = PolicyEngine(mode="READ_ONLY")
    state_box = {"last_result": {}}

    assert neo_cli._dispatch_shared_meta_command("write on", fake_brain, state_box, "fw-hq", symbiotic=True) is True
    assert fake_brain.policy.mode == "READ_WRITE"
    assert fake_brain.tool_executor.policy.mode == "READ_WRITE"

    assert neo_cli._dispatch_shared_meta_command("write off", fake_brain, state_box, "fw-hq", symbiotic=True) is True
    assert fake_brain.policy.mode == "READ_ONLY"
    assert fake_brain.tool_executor.policy.mode == "READ_ONLY"


def test_dual_plane_split_parser_and_more_pager_drain():
    """Verify '<cmd> + @ <query>' and '<cmd> | @ <query>' parsing, quote/email safety, and '--more--' auto-advance."""
    # 1. Interactive '+' with trailing space
    sp1 = neo_cli.parse_dual_plane_split("show system info + ", b"@")
    assert sp1 is not None
    assert sp1["kind"] == "interactive"
    assert sp1["ssh_cmd"] == "show system info"
    assert sp1["op"] == "+"
    assert sp1["erase_count"] == 3

    # 2. Interactive '|' without trailing space
    sp2 = neo_cli.parse_dual_plane_split("show routing route |", b"@")
    assert sp2 is not None
    assert sp2["ssh_cmd"] == "show routing route"
    assert sp2["op"] == "|"
    assert sp2["erase_count"] == 2

    # 3. Full-line paste with '@question ' prefix stripped
    sp3 = neo_cli.parse_dual_plane_split("", b"show system info + @question check logs\r")
    assert sp3 is not None
    assert sp3["kind"] == "pasted"
    assert sp3["ssh_cmd"] == "show system info"
    assert sp3["op"] == "+"
    assert sp3["neo_query"] == "check logs"

    # 4. Counter-logic: email address with '+' (no space) and open quotes must NOT hijack
    assert neo_cli.parse_dual_plane_split("set mgt-config users admin email ops+alert", b"@corp.com") is None
    assert neo_cli.parse_dual_plane_split('set rulebase security rules r1 description "a + ', b"@") is None

    # 5. Multi-page '--more--' auto-advance in drain_pty_ssh_command
    pty_writes = []
    pty_reads = [
        b"hostname: firewall-a\r\nlines 1-23 --more-- ",
        b"sw-version: 10.0.12-h3\r\nadmin@firewall-a> ",
    ]
    with patch("neo_cli.os.write", side_effect=lambda fd, b: pty_writes.append((fd, b))), patch(
        "neo_cli.os.read", side_effect=pty_reads
    ), patch("select.select", return_value=([77], [], [])):
        out = neo_cli.drain_pty_ssh_command(77, echo_stdout=False)

    assert "sw-version: 10.0.12-h3" in out
    assert "--more--" not in out
    assert (77, b"\r") in pty_writes
    assert (77, b" ") in pty_writes


def test_dual_plane_true_concurrent_execution_and_pipe_forwarding():
    """Prove '+ @' dispatches SSH and brain.investigate simultaneously (via Barrier) and '| @' pipes SSH output."""
    import threading

    barrier = threading.Barrier(2, timeout=2.0)
    rendered = []

    def fake_drain(master_fd, echo_stdout=True):
        barrier.wait()  # Proves brain.investigate thread is ALREADY running concurrently!
        return "hostname: firewall-a\nsys-uptime: 6 hours\nadmin@firewall-a> "

    fake_brain = MagicMock()

    def fake_investigate(query, **kwargs):
        barrier.wait()  # Meets fake_drain at t=0ms!
        return {
            "verdict": "Traffic logs checked concurrently.",
            "receipts": [{"tool": "execute_log_query", "duration_ms": 180.0, "status": "SUCCESS"}],
            "reasoning": [],
            "trace_id": "dual-1",
        }

    fake_brain.investigate.side_effect = fake_investigate
    state_box = {"last_result": {}, "last_query": ""}

    with patch("neo_cli.drain_pty_ssh_command", side_effect=fake_drain), patch(
        "neo_cli._render_turn_output", side_effect=lambda r, brain=None: rendered.append(r)
    ):
        ssh_out = neo_cli.execute_dual_plane_turn(
            ssh_cmd="show system info",
            op_char="+",
            neo_raw_cmd="question check logs",
            master_fd=88,
            echo_mode="op",
            brain=fake_brain,
            state_box=state_box,
            target_device="fw-hq",
            ssh_ring_snapshot="prior-ring",
        )

    assert "hostname: firewall-a" in ssh_out
    assert state_box["last_query"] == "check logs"
    assert rendered and "Traffic logs checked concurrently" in rendered[0]["verdict"]

    # Pipe mode ('| @') feeds fresh SSH command output directly into <ssh_pane_capture>
    seen_queries = []
    fake_brain.investigate.side_effect = lambda q, **kw: (
        seen_queries.append(q)
        or {"verdict": "No blackhole routes.", "receipts": [], "reasoning": [], "trace_id": "pipe-1"}
    )
    with patch(
        "neo_cli.drain_pty_ssh_command",
        return_value="0.0.0.0/0 via 192.168.1.1 ethernet1/1\nadmin@firewall-a> ",
    ), patch("neo_cli._render_turn_output"):
        neo_cli.execute_dual_plane_turn(
            ssh_cmd="show routing route",
            op_char="|",
            neo_raw_cmd="any blackholes?",
            master_fd=88,
            echo_mode="op",
            brain=fake_brain,
            state_box=state_box,
            target_device="fw-hq",
            ssh_ring_snapshot="",
        )

    assert seen_queries
    assert "0.0.0.0/0 via 192.168.1.1" in seen_queries[0]
    assert "<ssh_pane_capture>" in seen_queries[0]


def test_spark_google_doc_export_and_extensionless_board_ingest():
    """Verify Gemini Ultra Spark native Google Docs (without .md suffix) export via files().export and ingest cleanly."""
    from core.integrations.board_sync import StigmergicBoard
    from core.integrations.gdrive_client import GoogleDriveClient

    client = GoogleDriveClient(mode="readonly")
    fake_svc = MagicMock()
    fake_svc.files.return_value.export.return_value.execute.return_value = (
        b"---\nactor: SPARK_01\nmove_type: PATCH\nthread_id: T-SPARK\nbase_sha: deadbeef\n---\n\n"
        b"## Summary\nSpark native Google Doc artifact.\n"
    )
    client._service = fake_svc

    exported_bytes = client.download_bytes("doc-id-123", mime_type="application/vnd.google-apps.document")
    assert b"Spark native Google Doc artifact" in exported_bytes
    fake_svc.files.return_value.export.assert_called_once_with(fileId="doc-id-123", mimeType="text/markdown")

    mock_drive = MagicMock()
    mock_drive.list_folder_files.return_value = [
        {
            "id": "doc-id-123",
            "name": "20261120T060000Z__SPARK_01__PATCH__T-SPARK__deadbeef__cadence-sensor",  # No .md suffix!
            "mimeType": "application/vnd.google-apps.document",
        }
    ]
    mock_drive.download_bytes.return_value = exported_bytes

    board = StigmergicBoard(folder_id="folder-ultra-1", drive_client=mock_drive)
    arts = board.sync_artifacts(thread_id="T-SPARK")
    assert len(arts) == 1
    assert arts[0].actor == "SPARK_01"
    assert arts[0].move_type == "PATCH"
    assert "Spark native Google Doc artifact" in arts[0].summary
    mock_drive.download_bytes.assert_called_once_with(
        "doc-id-123", mime_type="application/vnd.google-apps.document"
    )
