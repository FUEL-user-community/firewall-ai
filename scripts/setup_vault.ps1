# ══════════════════════════════════════════════════════════════
# CORE DEFENSE — Local Vault Setup Wizard (Windows)
# ══════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " CORE DEFENSE — Local Vault Setup Wizard" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Starting Vault via Docker Compose..." -ForegroundColor Yellow
docker compose up -d vault
Start-Sleep -Seconds 4

Write-Host "Configuring AppRole authentication..." -ForegroundColor Yellow
docker compose exec -T -e VAULT_TOKEN=root vault vault auth enable approle 2>$null

Write-Host "Creating CORE DEFENSE read-only policy..." -ForegroundColor Yellow
$policy = @"
path `"secret/data/core-defense`" {
  capabilities = [`"read`"]
}
"@
$policy | docker compose exec -T -e VAULT_TOKEN=root vault vault policy write core-defense-policy - 2>$null

Write-Host "Creating CORE DEFENSE AppRole..." -ForegroundColor Yellow
docker compose exec -T -e VAULT_TOKEN=root vault vault write auth/approle/role/core-defense policies=core-defense-policy token_ttl=1h token_max_ttl=4h 2>$null

Write-Host "Seeding dummy secret..." -ForegroundColor Yellow
docker compose exec -T -e VAULT_TOKEN=root vault vault kv put -mount=secret core-defense dummy="Replace me in Vault UI" 2>$null

Write-Host "Retrieving Role ID and Secret ID..." -ForegroundColor Yellow
$roleId = (docker compose exec -T -e VAULT_TOKEN=root vault vault read -field=role_id auth/approle/role/core-defense/role-id).Trim()
$secretId = (docker compose exec -T -e VAULT_TOKEN=root vault vault write -f -field=secret_id auth/approle/role/core-defense/secret-id).Trim()

Clear-Host
Write-Host "======================================================" -ForegroundColor Green
Write-Host "✓ CORE DEFENSE LOCAL VAULT PROVISIONED SUCCESSFULLY" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host "Your local Vault is running at: http://127.0.0.1:8200"
Write-Host "You can log into the Vault UI using the token: root"
Write-Host ""
Write-Host "Copy and paste these exact values into the CORE DEFENSE Setup Wizard:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Vault URL:         http://127.0.0.1:8200" -ForegroundColor Cyan
Write-Host "  Vault AppRole ID:  $roleId" -ForegroundColor Cyan
Write-Host "  Vault Secret ID:   $secretId" -ForegroundColor Cyan
Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
