#!/bin/bash
# ══════════════════════════════════════════════════════════════
# CORE DEFENSE — Local Vault Setup Wizard (Mac/Linux)
# ══════════════════════════════════════════════════════════════

set -e

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN} CORE DEFENSE — Local Vault Setup Wizard${NC}"
echo -e "${CYAN}======================================================${NC}\n"

echo -e "${YELLOW}Starting Vault via Docker Compose...${NC}"
docker compose up -d vault
sleep 4

echo -e "${YELLOW}Configuring AppRole authentication...${NC}"
docker compose exec -T -e VAULT_TOKEN=root vault vault auth enable approle 2>/dev/null || true

echo -e "${YELLOW}Creating CORE DEFENSE read-only policy...${NC}"
cat <<EOF | docker compose exec -T -e VAULT_TOKEN=root vault vault policy write core-defense-policy - 2>/dev/null
path "secret/data/core-defense" {
  capabilities = ["read"]
}
EOF

echo -e "${YELLOW}Creating CORE DEFENSE AppRole...${NC}"
docker compose exec -T -e VAULT_TOKEN=root vault vault write auth/approle/role/core-defense policies=core-defense-policy token_ttl=1h token_max_ttl=4h 2>/dev/null

echo -e "${YELLOW}Seeding dummy secret...${NC}"
docker compose exec -T -e VAULT_TOKEN=root vault vault kv put -mount=secret core-defense dummy="Replace me in Vault UI" 2>/dev/null

echo -e "${YELLOW}Retrieving Role ID and Secret ID...${NC}"
ROLE_ID=$(docker compose exec -T -e VAULT_TOKEN=root vault vault read -field=role_id auth/approle/role/core-defense/role-id | tr -d '\r')
SECRET_ID=$(docker compose exec -T -e VAULT_TOKEN=root vault vault write -f -field=secret_id auth/approle/role/core-defense/secret-id | tr -d '\r')

clear
echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}✓ CORE DEFENSE LOCAL VAULT PROVISIONED SUCCESSFULLY${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Your local Vault is running at: http://127.0.0.1:8200"
echo -e "You can log into the Vault UI using the token: root\n"
echo -e "${YELLOW}Copy and paste these exact values into the CORE DEFENSE Setup Wizard:${NC}\n"
echo -e "${CYAN}  Vault URL:         http://127.0.0.1:8200${NC}"
echo -e "${CYAN}  Vault AppRole ID:  $ROLE_ID${NC}"
echo -e "${CYAN}  Vault Secret ID:   $SECRET_ID${NC}\n"
echo -e "${GREEN}======================================================${NC}"
