#!/usr/bin/env bash
# NEO - local dev-mode HashiCorp Vault for testing the `SECRETS_BACKEND=vault` path.
# Dev mode is in-memory with a fixed root token. Never use it outside a lab.
set -euo pipefail

CONTAINER="neo-vault"
IMAGE="hashicorp/vault:latest"

if ! command -v docker >/dev/null 2>&1; then
    echo "[error] docker CLI not found." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "[error] Docker daemon is not running." >&2
    exit 1
fi

vexec() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root "$CONTAINER" vault "$@"; }

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo "Starting $CONTAINER..."
    docker run -d --name "$CONTAINER" --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 \
        -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
        "$IMAGE" >/dev/null
fi

echo "Waiting for Vault..."
for _ in $(seq 1 30); do
    if vexec status >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
done
if [ "${READY:-0}" != "1" ]; then
    echo "[error] Vault did not become ready within 30s." >&2
    exit 1
fi

vexec auth enable approle >/dev/null 2>&1 || true
printf 'path "secret/data/core-defense" {\n  capabilities = ["read"]\n}\n' | vexec policy write core-defense-policy - >/dev/null
vexec write auth/approle/role/core-defense policies=core-defense-policy token_ttl=1h token_max_ttl=4h >/dev/null
vexec kv put -mount=secret core-defense placeholder="replace-me" >/dev/null

ROLE_ID=$(vexec read -field=role_id auth/approle/role/core-defense/role-id | tr -d '\r')
SECRET_ID=$(vexec write -f -field=secret_id auth/approle/role/core-defense/secret-id | tr -d '\r')

cat <<EOF

Vault dev server: http://127.0.0.1:8200  (UI token: root)

Add to .env:
  SECRETS_BACKEND=vault
  VAULT_ADDR=http://127.0.0.1:8200
  VAULT_ROLE_ID=$ROLE_ID
  VAULT_SECRET_ID=$SECRET_ID
  VAULT_SECRET_PATH=core-defense

Then store your keys under secret/core-defense in the UI and run: python3 neo_cli.py --check
EOF
