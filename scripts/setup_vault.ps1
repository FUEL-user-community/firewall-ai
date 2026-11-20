# NEO - local dev-mode HashiCorp Vault for testing the SECRETS_BACKEND=vault path.
# Dev mode is in-memory with a fixed root token. Never use it outside a lab.
$ErrorActionPreference = "Stop"

$Container = "neo-vault"
$Image = "hashicorp/vault:latest"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[error] docker CLI not found." -ForegroundColor Red
    exit 1
}
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[error] Docker daemon is not running." -ForegroundColor Red
    exit 1
}

function VExec { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root $Container vault @args }

$running = docker ps --format "{{.Names}}" | Where-Object { $_ -eq $Container }
if (-not $running) {
    docker rm -f $Container *> $null
    Write-Host "Starting $Container..."
    docker run -d --name $Container --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 `
        -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 $Image | Out-Null
}

Write-Host "Waiting for Vault..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    VExec status *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    Write-Host "[error] Vault did not become ready within 30s." -ForegroundColor Red
    exit 1
}

VExec auth enable approle *> $null
"path `"secret/data/core-defense`" {`n  capabilities = [`"read`"]`n}`n" | VExec policy write core-defense-policy - | Out-Null
VExec write auth/approle/role/core-defense policies=core-defense-policy token_ttl=1h token_max_ttl=4h | Out-Null
VExec kv put -mount=secret core-defense placeholder="replace-me" | Out-Null

$roleId = (VExec read -field=role_id auth/approle/role/core-defense/role-id).Trim()
$secretId = (VExec write -f -field=secret_id auth/approle/role/core-defense/secret-id).Trim()

Write-Host ""
Write-Host "Vault dev server: http://127.0.0.1:8200  (UI token: root)"
Write-Host ""
Write-Host "Add to .env:"
Write-Host "  SECRETS_BACKEND=vault"
Write-Host "  VAULT_ADDR=http://127.0.0.1:8200"
Write-Host "  VAULT_ROLE_ID=$roleId"
Write-Host "  VAULT_SECRET_ID=$secretId"
Write-Host "  VAULT_SECRET_PATH=core-defense"
Write-Host ""
Write-Host "Then store your keys under secret/core-defense in the UI and run: python neo_cli.py --check"
