# NEO — Symbiotic SSH + XML-API Cybersec Resident for PAN-OS

NEO fuses an interactive **OpenSSH PTY (`TCP/22`)** and a persistent **PAN-OS XML-API channel (`TCP/443`)** into a single zero-port terminal session (`neo_cli.py`), powered by Google Gemini and deterministic Single-Pass Parallel Processing (SP3) path math.

Instead of bouncing between a live firewall SSH window and a separate API script, MCP chat client, or cloud dashboard, you work inside one native `admin@firewall>` / `#` prompt. Both channels terminate inside PAN-OS's `mgmtsrvr` daemon—giving you `0ms` native CLI `Tab`/`?` completion on the front channel while NEO queries FIB/PBF/NAT/Security Policy, inspects uncommitted candidate XML, scrubs credentials, stages `set` rules into `[edit]`, and gates `commit` against self-lockout on the back channel.

---

## Architecture: Dual-Plane Convergence on `mgmtsrvr`

```text
  [Operator Terminal: tmux / Remmina / WSL / Linux / macOS]
                 │  stdin / stdout (tty.setraw <-> _cooked_guard + less -RFX)
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ neo_cli.py (In-Process Resident) — ZERO listening network ports         │
  │  • _SEALED_VAULT: consumes API keys once & purges os.environ pre-SSH    │
  │  • Multi-encoding secret scrubber (raw, Base64, hex, URL, reversed)     │
  │  • VT100 cursor/backspace folder + 8 KB scrubbed SSH output ring        │
  ├─────────────────────────────────┬───────────────────────────────────────┤
  │ Front Plane: POSIX PTY master   │ Back Plane: PanOSClient (RLock)       │
  │ Child /usr/bin/ssh (clean env)  │ Persistent HTTPS pan.xapi + Cert Pin  │
  └────────────────┬────────────────┴───────────────────┬───────────────────┘
                   │ TCP/22 (sshd -> cli)               │ TCP/443 (/api/)
                   └───────────────► mgmtsrvr ◄─────────┘
                        (Shared Candidate XML DOM + Running SP3 State)
```

---

## Core Capabilities

- **Single-Prompt Symbiotic SSH (`--ssh`):** Wraps `/usr/bin/ssh` in a local POSIX PTY (`0ms` keystroke passthrough for `Tab`, `?`, `↑`/`↓` history, and pipes). Typing `@` at column `0` of any idle `>` or `#` prompt invokes NEO inline with the last 8 KB of credential-scrubbed SSH output automatically attached.
- **Simultaneous Dual-Plane Dispatch (`+ @`) & Live Output Piping (`| @`):**
  - `show system info + @ check traffic logs` — fires the SSH CLI command (auto-advancing `--more--` pages) and a background XML-API Gemini investigation simultaneously at `t = 0ms`, rendering clean non-interleaved output.
  - `show routing route | @ any blackhole or asymmetric routes?` — drains the SSH command first and pipes its scrubbed output directly into NEO's turn context.
- **`$0.00` Deterministic SP3 & Candidate Audits (Zero LLM Tokens):**
  - `@walk <src> <dst> [port] [proto]` — executes full PAN-OS SP3 path math (`Ingress FIB -> PBF -> Pre-NAT FIB -> NAT -> Post-DNAT FIB -> Security Policy`), filtering outbound SNAT false positives and warning whenever uncommitted `[edit]` edits exist.
  - `@diff` — audits uncommitted `[edit]` candidate XML at `$0.00` for management self-lockout, MGT IP/gateway drift, `interzone-default: deny` active-flow severance, and `application:any` / `service:any` / uninspected `allow` rules.
  - `@macro [list|<name>]` — runs composite multi-command sweeps from `config/commands.yaml` at `$0.00`.
- **Direct `[edit]` Candidate Injection (`@stage`):** Extracts only `set`/`move`/`rename`/`delete` lines (stripping `commit`, `request`, `debug`, `exit`), normalizes PAN-OS 10.0 `[ a b ]` list brackets, writes lines directly into your active SSH `[edit]` session via `master_fd` (avoiding `config-lock` conflicts across admin sessions), and aborts mid-batch immediately if PAN-OS echoes `Invalid syntax` or `Unknown command`.
- **`$0.00` Pre-Commit Sanctuary Gate (`commit`):** Intercepts typed, `Tab`-completed, history-recalled, backspaced, or pasted `commit` commands in `#` mode and evaluates `core/panos/sanctuary.py` over XML-API *before* `\r` reaches `mgmtsrvr`.
- **90 Verified PAN-OS Tools & Entitlement Awareness:** Dynamic tray mounting (`#core` plus `#sys`, `#net`, `#sec`, `#vpn`, `#ops`, `#troubleshoot`, `#ha`, `#routing`, `#l2`, `#user-id`), `Cartographer` (`map_home_topology`), End-of-Life OS (`<= 10.1`) detection, and explicit separation of expired Threat/WildFire/URL subscriptions from working base-OS controls (`App-ID`, `Zone Protection`, `File Blocking`, `DAG`, `MGT permitted-ip`).
- **Receipt Referee & Constitutional Self-Forging (`slot_forge`):** `core/pipeline/evidence.py` validates `[Step N]` citations against real tool receipts in forensic/CAB export modes, while `core/forge/slot_mutator.py` + `core/forge/laws.py` allow in-memory tool/macro evolution gated by AST constitutional checks, `pytest`, and terminal `[y/N]` diff approval.

---

## Quick Start

### 1. Requirements & Installation
- Python `3.11+`
- PAN-OS firewall (`10.0.x`, `10.1.x`, `10.2.x`, `11.x`) reachable via HTTPS XML-API (and SSH for `--ssh` mode)
- Google Gemini API key

```bash
git clone https://github.com/FUEL-user-community/firewall-ai.git
cd firewall-ai

python3 -m venv venv
# Linux / macOS / WSL:
source venv/bin/activate
# Windows PowerShell:
venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
```

### 2. Configure `.env` (and Optional `config/devices.yaml`)

```env
GEMINI_API_KEY=your-gemini-api-key
PANOS_HOSTNAME=192.168.1.254
PANOS_API_KEY=your-panos-api-key
# Lab self-signed cert toggle (prefer ssl_fingerprint pinning in config/devices.yaml):
PANOS_VERIFY_SSL=false
```

For multi-firewall fleets or alias binding (`fw-hq`), edit `config/devices.yaml` with per-device IPs, labels, optional virtual routers (auto-discovered if omitted), and optional SHA-256 `ssl_fingerprint` pins.

### 3. Verify & Launch

```bash
# 1. Pre-flight check (vault seal, model ID validation, fleet reachability, 90-tool registry)
python3 neo_cli.py --check

# 2. Persistent tmux Symbiotic SSH session (Linux / WSL / macOS — mouse scroll enabled)
./neo_tmux.sh

# 3. Direct Single-Prompt Symbiotic SSH without tmux (alias from devices.yaml or user@ip)
python3 neo_cli.py --ssh fw-hq
python3 neo_cli.py --ssh admin@192.168.1.254

# 4. Standalone Resident REPL (Windows / Linux / macOS — commands use '/' prefix)
python neo_cli.py

# 5. Headless one-shot execution
python neo_cli.py -q "map my home topology and audit uninspected allow rules"
```

---

## Operator Command Reference

Inside `--ssh` mode, type `@` at column `0` of an idle `>` or `#` prompt (in standalone REPL mode, use `/` instead of `@`):

| Command | Cost | Description |
| :--- | :--- | :--- |
| `<panos_cli>` | `$0.00` | Native `0ms` OpenSSH passthrough (`Tab`, `?`, `↑`/`↓` history, pipes). |
| `@ <question>` | Gemini | Inline Resident turn (10-turn memory + scrubbed 8 KB SSH output ring). |
| `<cmd> + @ <question>` | Gemini / `$0.00` | Run SSH `<cmd>` and NEO query simultaneously at `t = 0ms`. |
| `<cmd> \| @ <question>` | Gemini | Run SSH `<cmd>` first and pipe its scrubbed output directly into NEO. |
| `@walk <s> <d> [p] [pr]` | `$0.00` | Deterministic SP3 packet walk (`FIB -> PBF -> NAT -> Security Policy`). |
| `@diff` | `$0.00` | Pre-commit candidate XML audit (lockout, severance, permissive rules). |
| `@macro [list\|<name>]` | `$0.00` | Execute any composite macro or read-only tool from `config/commands.yaml`. |
| `@stage` | `$0.00` | Validate & inject candidate `set`/`move`/`rename`/`delete` lines into `[edit]`. |
| `commit` (in `#` mode) | `$0.00` | Automatic Pre-Commit Sanctuary check before `\r` reaches `mgmtsrvr`. |
| `@write [on\|off\|status]` | `$0.00` | Toggle `PolicyEngine` `READ_WRITE` / `READ_ONLY` in-session (`[y/N]` HITL active). |
| `@audit <question>` | Gemini | Strict forensic mode with code-computed `Device Facts` & `[Step N]` referee. |
| `@why` / `@raw <N>` / `@mem` | `$0.00` | View `<REASONING>` trace, raw XML/YAML receipt `#N`, or session memory. |
| `@board` / `@forge` / `@export` | `$0.00` | Sync Stigmergic Board, inspect `#core` / RAM patches, or save CAB `.md` report. |
| `@reset` / `@help` | `$0.00` | Clear rolling resident session memory or show command help. |

Outputs taller than the terminal viewport automatically open in `less -RFX` (`↑`/`↓`/`PgUp`/`PgDn`/mouse wheel to scroll, `q` to return to the firewall prompt; set `NEO_PAGER=0` to disable).

---

## Security & Key Isolation

1. **Zero Open Network Ports:** Runs strictly in-process inside your local terminal—no HTTP/WebSocket listener is ever bound.
2. **Consume-Once `_SEALED_VAULT` (`core/integrations/secrets.py`):** Secrets are loaded once at startup, `chmod 600` is enforced on `.env` / `devices.yaml`, and `PANOS_API_KEY*`, `GEMINI_API_KEY`, and Vault/cloud tokens are deleted from `os.environ` before `/usr/bin/ssh` or Turn 1 spawns.
3. **Multi-Encoding Output & SSH Scrubbing (`core/safety/scrubber.py`):** Runtime secrets are fingerprinted and redacted across raw, Base64, hex, URL-encoded, and reversed (`[::-1]`) forms across all tool receipts and SSH ring captures (`pre-shared-key`, `phash`, `password`, `LUFRPT`, `AIza` lines dropped before LLM egress).
4. **Layered Write & Sanctuary Governance:** Defaults to `READ_ONLY`. Write-capable API tools (`apply_dynamic_tag`, `capture_pcap`, elevated `clear session id`) require both `READ_WRITE` elevation (`@write on`) and interactive `[y/N]` terminal HITL approval, while Sanctuary blocks tagging firewall MGT or active admin session IPs.
5. **Constitutional Self-Patch Ring (`core/forge/laws.py`):** Blocks autonomous `slot_forge` mutations from touching `neo_cli.py`, `sanctuary.py`, `secrets.py`, `scrubber.py`, `policy_engine.py`, `hitl.py`, `client.py`, `evidence.py`, or `tests/`, and rejects credential/network exfiltration AST primitives.

---

## Repository Structure

| Path | Role |
| :--- | :--- |
| `neo_cli.py`, `neo_tmux.sh` | Symbiotic SSH PTY multiplexer, standalone REPL, pager, and staging engine. |
| `core/brain.py` | Multi-turn Gemini cognitive loop, rolling resident memory, and quota/budget guards. |
| `core/panos/` | `client.py` (TLS/fingerprint `xapi` pool), `ops.py` (SP3 math & ops), `sanctuary.py` (pre-commit gate), `cartographer.py` (topology/EoL graph), `logs.py`, `config.py`, `research.py`. |
| `core/pipeline/` | `tool_keeper.py`, `tool_executor.py`, `tool_schemas.py`, `evidence.py`, `outcomes.py`, `prompt_assembler.py`, `model_config.py`, `context_manager.py`, `synthesizer.py`. |
| `core/safety/` | `policy_engine.py`, `hitl.py`, `command_filter.py`, `scrubber.py`, `budget_guard.py`, `circuit_breaker.py`. |
| `core/forge/` | `laws.py` (constitutional AST/path ring), `slot_mutator.py` (zero-disk live patching), `crucible.py`, `state_store.py`. |
| `core/integrations/` | `secrets.py` (sealed vault / Vault / GCP / AWS / Azure), `gdrive_client.py`, `drive_knowledge.py`, `board_sync.py`, `google_export.py`, `telemetry.py`. |
| `config/` | `prompts.yaml` (SHA-256 pinned resident kernel), `commands.yaml` (operational tool & macro catalog), `devices.yaml` (fleet inventory; API keys stored in vault/env). |
| `tests/` | `388`-test suite covering key sealing, PTY staging/folding, Sanctuary gates, dual-plane concurrency, SP3 math, and constitutional boundaries. |

---

## Running Tests

```bash
python -m pytest -q
```

---

## License

MIT License. See [LICENSE](LICENSE).
