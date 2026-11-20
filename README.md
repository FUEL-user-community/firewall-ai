# NEO — PAN-OS SSH & XML-API CLI Assistant

[![CI](https://github.com/FUEL-user-community/firewall-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/FUEL-user-community/firewall-ai/actions/workflows/ci.yml)

NEO wraps a native **OpenSSH PTY (`TCP/22`)** and a persistent **PAN-OS XML-API client (`TCP/443`)** into a single local terminal process (`neo_cli.py`), combining deterministic PAN-OS Single-Pass Parallel Processing (SP3) checks with Google Gemini.

You stay inside one `admin@firewall>` / `#` prompt with native `Tab`, `?`, and CLI history. Typing `@` at an idle prompt queries NEO with a credential-scrubbed window of recent SSH output, runs local XML-API diagnostics without LLM calls, checks candidate `set` syntax against the firewall's own `?` parser before staging, and evaluates candidate changes for self-lockout before `commit` executes.

---

## Architecture

```text
  [Operator Terminal: Linux / macOS / WSL / tmux]
                 │  stdin / stdout (raw PTY <-> cooked prompts + less -RFX)
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ neo_cli.py — local process, zero listening network ports                │
  │  • Sealed credentials: loads .env/Vault once & purges os.environ        │
  │  • Secret scrubber: redacts raw, Base64, hex, URL, and reversed forms   │
  │  • Unified policy gate across API tools AND SSH-channel writes          │
  │  • Hash-chained change provenance log (~/.neo/audit/neo_audit.jsonl)    │
  ├─────────────────────────────────┬───────────────────────────────────────┤
  │ SSH Channel: POSIX PTY master   │ API Channel: PanOSClient (RLock)      │
  │ Child /usr/bin/ssh (clean env)  │ HTTPS pan.xapi + optional cert pin    │
  └────────────────┬────────────────┴───────────────────┬───────────────────┘
                   │ TCP/22 (sshd -> cli)               │ TCP/443 (/api/)
                   └───────────────► mgmtsrvr ◄─────────┘
                        (Shared Candidate XML + Running SP3 State)
```

---

## What It Does

- **Inline SSH Wrapper (`--ssh`):** Runs real OpenSSH inside a local POSIX PTY (`0ms` passthrough for `Tab`, `?`, history, and pipes). Typing `@` at column `0` of an idle `>` or `#` prompt invokes NEO with the last 8 KB of scrubbed SSH output attached.
- **Concurrent (`+ @`) & Piped (`| @`) Execution:**
  - `test security-policy-match ... + @ why is this flow still failing?` — runs the SSH command immediately while querying the XML-API (including a 6-stage SP3 cross-check for Post-DNAT zone shifts and PBF overrides) in a background thread.
  - `show routing route | @ check for asymmetric or blackhole paths` — runs the SSH command first and pipes its scrubbed output into NEO.
- **Syntax-Checked Candidate Staging (`@stage`):** Strips `commit`/`request`/`debug`/`exit`, normalizes PAN-OS `[ a b ]` list brackets, probes each candidate line against the firewall's live `?` CLI parser (`Ctrl+C` line-clear, zero partial mutations on syntax error), requires explicit `[y/N]` re-approval if NEO repairs a rejected line, and warns on Panorama-managed firewalls.
- **Scope-Aware Pre-Commit Safety Check (`commit`):** Intercepts `commit`, `commit force`, and `commit partial admin <name>` in `#` mode to check candidate XML for management `permitted-ip` self-lockout, MGT IP/gateway drift, and uncovered `interzone-default: deny` severance before `\r` reaches `mgmtsrvr`. Offers `commit description "NEO-assisted <trace>"` when committing NEO-staged lines.
- **Bounded `packet-diag` Counter Delta (`@diag`):** Runs a bidirectional (`src <-> dst`) packet-filtered `show counter global filter packet-filter yes delta yes` + session sample from either `>` or `#` mode (requires `@write diag`), disarming `filter off`, `capture off`, and `clear filter` inside `finally:` even on `Ctrl+C`.
- **Local SP3 Packet Walk & Candidate Review (`@walk`, `@diff`, `@macro`):** Evaluates `Ingress FIB -> PBF -> Pre-NAT FIB -> NAT -> Post-DNAT FIB -> Security Policy` with zero LLM calls, plus a best-effort pre-commit candidate `[edit]` comparison when uncommitted changes exist.

## What It Does Not Do

- **Never commits autonomously:** `commit` is never injected by `@stage` or any API tool.
- **Never mutates SSH or API state in `READ_ONLY`:** Both XML-API write tools and SSH-channel writes (`@stage`, `@diag`) are blocked until elevated with `@write on` (and `@write diag` for `packet-diag`), with `[y/N]` confirmation on every action.
- **No background network listener:** Binds zero TCP/HTTP/WebSocket ports.
- **Self-patching disabled by default:** Experimental runtime tool/macro self-patching (`slot_forge`) and Drive board sync (`board_ops`) are off unless `NEO_ENABLE_FORGE=1` is explicitly set.

---

## Quick Start

### 1. Install

Requires Python `3.10+`, a PAN-OS firewall (`10.0.x`–`11.x`) reachable over HTTPS (and SSH for `--ssh`), and a Google Gemini API key.

```bash
git clone https://github.com/FUEL-user-community/firewall-ai.git
cd firewall-ai

python3 -m venv venv
source venv/bin/activate        # Windows PowerShell: venv\Scripts\Activate.ps1
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

For named device aliases (`fw-hq`), multiple firewalls, or SHA-256 `ssl_fingerprint` certificate pinning, edit `config/devices.yaml`. For HashiCorp Vault AppRole setup, see [VAULT_GUIDE.md](VAULT_GUIDE.md).

### 3. Verify & Run

```bash
# Pre-flight check (credential seal, model ID, firewall reachability, tool catalog)
python3 neo_cli.py --check

# Persistent tmux SSH session (Linux / macOS / WSL — mouse scroll enabled)
./neo_tmux.sh

# Direct SSH wrapper without tmux
python3 neo_cli.py --ssh fw-hq
python3 neo_cli.py --ssh admin@192.168.1.254

# Standalone REPL (Windows / Linux / macOS — commands use '/' prefix)
python neo_cli.py

# Single headless query
python neo_cli.py -q "check management permitted-ip and expired licenses"
```

---

## Command Reference

Inside `--ssh` mode, type `@` at column `0` of an idle `>` or `#` prompt (in standalone mode, use `/` instead of `@`):

| Command | Execution | Description |
| :--- | :--- | :--- |
| `<panos_cli>` | Local | Native `0ms` OpenSSH passthrough (`Tab`, `?`, history, pipes). |
| `@ <question>` | Gemini | Ask NEO inline (attaches scrubbed 8 KB SSH output window). |
| `<cmd> + @ <question>` | Gemini | Run SSH `<cmd>` immediately while NEO queries the XML-API in parallel. |
| `<cmd> \| @ <question>` | Gemini | Run SSH `<cmd>` first, then pass its scrubbed output to NEO. |
| `@walk <s> <d> [p] [pr]` | Local | SP3 packet walk across committed state (+ candidate `[edit]` approximation if edited). |
| `@diff` | Local | Pre-commit review of uncommitted candidate XML changes. |
| `@macro [list\|<name>]` | Local | Run a read-only multi-command bundle from `config/commands.yaml`. |
| `@stage` | Local | Syntax-check candidate `set`/`move`/`rename`/`delete` lines via `?` and inject into `[edit]` (needs `@write on`). |
| `@diag <s> <d> [p] [t]` | Local | Bounded `packet-diag` + hardware drop-counter delta; always disarms filters (needs `@write diag`). |
| `commit` (in `#` mode) | Local | Scope-aware pre-commit safety check before `\r` reaches `mgmtsrvr`. |
| `@write [on\|diag\|off\|status]` | Local | Control session write policy across API tools, `@stage`, and `@diag`. |
| `@log [N]` | Local | Show recent change-provenance entries and verify the SHA-256 hash chain. |
| `@audit <question>` | Gemini | Formal report mode with code-computed `Device Facts` and `[Step N]` citation checks. |
| `@why` / `@raw <N>` / `@mem` | Local | View `<REASONING>` trace, raw XML/YAML receipt `#N`, or 10-turn session memory. |
| `@export [file.md]` | Local | Save the last turn as a change-review Markdown report. |
| `@reset` / `@help` | Local | Clear session memory or print command help. |

Outputs taller than the terminal automatically open in `less -RFX` (`q` to return to the prompt; set `NEO_PAGER=0` to disable).

---

## Safety & Change Provenance

1. **Unified Write Policy (`PolicyEngine`):** Defaults to `READ_ONLY` across both the XML-API and SSH channels. `@stage` requires `@write on` + `[y/N]` approval; `@diag` additionally requires `@write diag`.
2. **Hash-Chained Provenance Log (`core/safety/audit_log.py`):** Because PAN-OS attributes `@stage` lines to the logged-in SSH admin, NEO records proposals, operator approvals/rejections, injected lines, `@diag` runs, and commit checks in `~/.neo/audit/neo_audit.jsonl` (`chmod 600`, scrubbed, SHA-256 hash-chained, verifiable via `@log`) and offers `commit description "NEO-assisted <trace>"` on bare commits.
3. **Consume-Once Credential Seal (`core/integrations/secrets.py`):** Loads secrets once into an in-process store, enforces `0600` permissions on `.env` / `devices.yaml`, and deletes secret env vars from `os.environ` before spawning `ssh`.
4. **Multi-Encoding Scrubbing (`core/safety/scrubber.py`):** Redacts registered secrets across raw, Base64, hex, URL-encoded, and reversed forms across tool outputs, SSH captures, and audit logs.

---

## Known Limitations

- **Candidate `[edit]` walk is an approximation:** PAN-OS has no native CLI/API command to test uncommitted candidate rules. `evaluate_candidate_packet_walk()` models `/config/shared` and `vsys` XML in Python and returns `INDETERMINATE` whenever a rule above the match depends on runtime state (FQDNs, Dynamic Address Groups, EDLs, regions, or unmapped App-ID default ports). Commit + live `test security-policy-match` remains authoritative.
- **`?` checks syntax, not object references:** Live `?` probing catches invalid CLI grammar/keywords for the exact PAN-OS version before lines enter `[edit]`, while nonexistent zone or address-object names are validated by PAN-OS at `validate` / `commit` time.
- **Shared-candidate race window:** On multi-admin or Panorama-managed firewalls, another admin or push can modify the shared candidate configuration between the pre-commit check and `commit` execution.
- **Single-device POSIX PTY:** `--ssh` wraps one SSH session per process and requires Linux, macOS, or Windows WSL (`pty` stdlib). Native Windows PowerShell supports standalone REPL (`python neo_cli.py`) and `-q` modes.

---

## Repository Layout

| Path | Role |
| :--- | :--- |
| `neo_cli.py`, `neo_tmux.sh` | SSH PTY wrapper, standalone REPL, syntax prober, `packet-diag` runner, and pager. |
| `core/brain.py` | Multi-turn Gemini loop, 10-turn session memory, and budget/circuit-breaker integration. |
| `core/panos/` | `client.py` (TLS/pinning `xapi` pool), `ops.py` (SP3 walks & ops), `sanctuary.py` (pre-commit & candidate checks, Panorama detection), `cartographer.py` (topology & EoL), `logs.py`, `config.py`, `research.py`. |
| `core/pipeline/` | `tool_keeper.py`, `tool_executor.py`, `tool_schemas.py`, `evidence.py`, `outcomes.py`, `prompt_assembler.py`, `model_config.py`, `context_manager.py`, `synthesizer.py`. |
| `core/safety/` | `policy_engine.py`, `hitl.py`, `command_filter.py`, `scrubber.py`, `audit_log.py` (hash-chained provenance), `budget_guard.py`, `circuit_breaker.py`. |
| `core/integrations/` | `secrets.py` (dotenv / Vault / GCP / AWS / Azure), `gdrive_client.py`, `drive_knowledge.py`, `board_sync.py`, `google_export.py`, `telemetry.py`. |
| `core/forge/` | Opt-in (`NEO_ENABLE_FORGE=1`) sandboxed tool staging (`laws.py`, `slot_mutator.py`, `crucible.py`, `state_store.py`). |
| `config/` | `prompts.yaml` (SHA-256 pinned system prompt), `commands.yaml` (88-tool catalog), `devices.yaml` (device inventory). |
| `tests/` | `406`-test suite covering credential sealing, unified write policy, PTY `?` syntax probing, provenance hash chains, candidate SP3 tri-state logic, and safety gates. |

---

## Testing & Linting

```bash
ruff check .
python -m pytest -q
```

---

## License

MIT License. See [LICENSE](LICENSE).
