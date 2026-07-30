# Enterprise Vault Setup Guide

CORE DEFENSE natively supports HashiCorp Vault for secure API key management. For teams testing the Enterprise deployment flow locally, we've provided an automated script that spins up and provisions a Vault server for you.

## Prerequisites
- Docker and Docker Compose installed
- Port `8200` available on your local machine

## 1. Run the Auto-Provisioning Script

Open your terminal in the project root and run the script for your operating system:

**Windows (PowerShell):**
```powershell
.\scripts\setup_vault.ps1
```

**Mac/Linux (Bash):**
```bash
chmod +x scripts/setup_vault.sh
./scripts/setup_vault.sh
```

## 2. What the Script Does

Behind the scenes, this script executes Vault configuration:
1. Starts the `vault` container in `docker-compose.yml`.
2. Enables the `approle` authentication method.
3. Creates a read-only policy strictly scoped to the `secret/data/core-defense` path.
4. Creates the `core-defense` AppRole and attaches the policy.
5. Generates the required AppRole credentials.

## 3. Enter the Credentials

Once the script finishes, it will print a color-coded summary containing three pieces of information:
- **Vault URL**
- **Vault AppRole ID**
- **Vault Secret ID**

Simply open the CORE DEFENSE web interface (`http://127.0.0.1:8888`), select **Enterprise (HashiCorp Vault)** in the Setup Wizard, and paste those exact values in. 

## 4. Viewing the Vault UI

You can view and modify your secrets directly in the Vault UI:
1. Navigate to http://127.0.0.1:8200
2. Enter the token: `root`
3. Navigate to **Secrets Engines -> secret -> core-defense**

*Note: In a production environment, you would point CORE DEFENSE to your company's existing Vault infrastructure instead of running the local container.*
