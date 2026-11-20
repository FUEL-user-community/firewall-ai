# HashiCorp Vault Setup (Optional)

By default NEO reads credentials from `.env`, loads them once into an in-process sealed store, and
removes them from `os.environ` before the first SSH session or LLM call. For teams that want
credentials to live outside the workstation, NEO can read them from HashiCorp Vault via AppRole.

## Prerequisites

- Docker
- Port `8200` free on your machine (local test only)

## 1. Start a local test Vault

```bash
# Linux / macOS / WSL
chmod +x scripts/setup_vault.sh
./scripts/setup_vault.sh
```

```powershell
# Windows PowerShell
.\scripts\setup_vault.ps1
```

The script:

1. Starts a dev-mode Vault container named `neo-vault` (`hashicorp/vault`, root token `root`).
2. Enables AppRole authentication.
3. Creates a read-only policy scoped to `secret/data/core-defense`.
4. Creates the `core-defense` AppRole and prints its Role ID and Secret ID.

Dev mode keeps everything in memory and uses a fixed root token. It is for local testing only.

## 2. Store your keys in Vault

Open http://127.0.0.1:8200, log in with token `root`, and add your keys under
**Secrets Engines → secret → core-defense** (for example `gemini_api_key`, `panos_api_key_fw_hq`).

## 3. Point NEO at Vault

Add these lines to `.env`:

```env
SECRETS_BACKEND=vault
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<role id printed by the script>
VAULT_SECRET_ID=<secret id printed by the script>
VAULT_SECRET_PATH=core-defense
```

Then verify:

```bash
python3 neo_cli.py --check
```

## Production

Point `VAULT_ADDR` at your organization's Vault cluster with TLS, use a narrowly scoped AppRole,
and issue short-lived Secret IDs. Do not run dev-mode Vault outside a lab.
