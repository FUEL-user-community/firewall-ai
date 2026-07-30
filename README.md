# Core Defense — Autonomous Cyber Defense Orchestrator for PAN-OS

**An open-source AI security operations and diagnostic engine for Palo Alto Networks Next-Generation Firewalls (NGFW).**

Core Defense connects AI models to your live Palo Alto Networks firewalls. It allows security engineers and network administrators to perform health checks, simulate security policies, and map network topologies using natural language instead of manual CLI commands.

---

## Key Capabilities

*   **Investigation Engine**: Powered by Google Gemini (tested with Gemini 3.1 Pro and 3.6 Flash), the agent breaks down complex network troubleshooting step-by-step.
*   **Multi-Layered Safety Pipeline**:
    *   **Policy Engine**: Enforces strict `READ_ONLY` mode by default.
    *   **Circuit Breaker**: Prevents runaway execution loops (max 30 steps).
    *   **Budget Guard**: Enforces configurable API spending caps per investigation (default: $2.00) and per day (default: $20.00) to prevent cost runaways when processing large custom firewall XML configurations.
    *   **Semantic Drift Gate**: Monitors the AI's internal reasoning and stops execution if it begins hallucinating or going off-topic.
    *   **Command Filter & Toxic XML Sanitizer**: Strips destructive commands (`reboot`, `wipe`, `commit`) before API dispatch.
*   **Topology Cartographer**: Automatically parses your firewall's XML configurations to generate live Mermaid diagrams of your network architecture.
*   **Defense Deck (Cards)**: Automated, on-demand threat hunting scripts (e.g., checking operational resilience or IPS blind spots) that the AI runs and verifies for you.
*   **Enterprise Secrets Provider**: Pluggable support for HashiCorp Vault (AppRole), GCP Secret Manager, AWS Secrets Manager, and local `.env`.
*   **Multi-Firewall Fleet Support**: Single interface to query and audit multiple firewalls declared in `config/devices.yaml`.

---

## System Architecture



---

## Quick Start

### Prerequisites
*   Python 3.11 or higher
*   A Palo Alto Networks Firewall running PAN-OS 10.x or 11.x
*   A Google Gemini API key ([Get one free at AI Studio](https://aistudio.google.com/apikey))

---

### Option 1: Native Python

```bash
# 1. Clone the repository
git clone https://github.com/FUEL-UG/neo-framework-pan-os.git
cd neo-framework-pan-os

# 2. Create and activate a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
```

Edit `.env` with your firewall IP and API keys:
```env
PANOS_HOSTNAME=192.168.1.254
PANOS_API_KEY=your-panos-api-key
GEMINI_API_KEY=your-gemini-api-key
```

```bash
# 5. Launch the application
python server.py
```

Open **`http://localhost:8888`** in your browser.

---

### Option 2: Docker & Docker Compose

```bash
# Edit environment variables in docker-compose.yml, then launch:
docker compose up -d
```

Or run via Docker single container:
```bash
docker run -d -p 8888:8888 \
  -e GEMINI_API_KEY="your-gemini-api-key" \
  -e PANOS_API_KEY="your-panos-api-key" \
  -e PANOS_HOSTNAME="192.168.1.254" \
  --name core-defense \
  coredefense/agent
```

---

## Example Queries

| Category | Query |
| :--- | :--- |
| **Health & Telemetry** | `"Give me a proactive morning briefing based on firewall health."` |
| **Policy Simulation** | `"Can 10.0.0.5 reach 8.8.8.8 on port 443?"` |
| **Routing Lookups** | `"Which interface and next-hop is used to reach 172.16.50.1?"` |
| **Threat & Log Audits** | `"Are there any critical threat logs in the last hour?"` |
| **VPN & User-ID** | `"Audit all active GlobalProtect VPN sessions and User-ID mappings."` |
| **Range Simulation** | Launch Range Simulator tab to generate dynamic Mermaid attack graphs. |

---

## Configuration Files

All configuration lives in the `config/` directory:

```
config/
├── devices.yaml        # Firewall fleet registry (IPs, labels, default target)
├── prompts.yaml        # System prompts and persona definitions (NEO / GHOST)
├── commands.yaml       # Allowed PAN-OS commands and macro chains
├── cards.yaml          # Autonomous Defense Deck card definitions
├── card_prompts.yaml   # Card execution prompt templates
└── range_prompts.yaml  # Range simulation Mermaid instructions
```

### Multi-Firewall Configuration (`config/devices.yaml`)
To manage multiple firewalls from a single instance:

```yaml
firewalls:
  fw-hq:
    ip: 192.168.1.254
    label: "HQ Perimeter Firewall"
    default: true

  fw-dmz:
    ip: 10.0.0.1
    label: "DMZ Edge Firewall"
```

Set secret keys in `.env` or Vault following the convention: `PANOS_API_KEY_<DEVICE_NAME>` (e.g. `PANOS_API_KEY_FW_HQ`, `PANOS_API_KEY_FW_DMZ`).

---

## Enterprise Security & Governance

1.  **Read-Only Safeguard**: All tool calls default to `READ_ONLY`. Modifying tools (`apply_dynamic_tag`, `clear_session_id`) require setting `POLICY_MODE=READ_WRITE` and passing through human approval gates when configured.
2.  **Secrets Provider Abstraction**: API keys are isolated via `core/integrations/secrets.py`. Supports:
    *   `dotenv` (Local development)
    *   `vault` (HashiCorp Vault AppRole)
    *   `gcp` (Google Cloud Secret Manager)
    *   `aws` (AWS Secrets Manager)
3.  **Command Allowlist**: Raw CLI commands executed via `execute_operational_command` pass through `CommandFilter` to prevent unauthorized or destructive operations.

---

## Optional Knowledge Base & Obsidian Vault Sync

Core Defense includes built-in optional integrations for document RAG and personal knowledge management:

* **Google Drive RAG (`query_knowledge_base`)**: Place official PAN-OS documentation or incident response PDFs in a Google Drive folder to allow the agent to search Table of Contents and read page slices during investigations.
* **Obsidian Vault Sync (`GoogleDriveObsidianMapper`)**: Automatically converts live firewall telemetry and tool outputs into formatted Obsidian Markdown notes (tagged with `#security/policy`, `#network/interface`, `#threat/audit`) and syncs them to Google Drive.

> **Note**: Both features are completely **optional and fail-soft**. If `GCP_SERVICE_ACCOUNT_FILE` or `OBSIDIAN_DRIVE_FOLDER_ID` are not configured in `.env`, these features remain dormant without impacting core firewall operations.



## Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open issues on the Palo Alto Networks FUEL User Group GitHub repository.

1.  Fork the Repository
2.  Create a Feature Branch (`git checkout -b feature/amazing-feature`)
3.  Commit your Changes (`git commit -m 'Add amazing feature'`)
4.  Push to the Branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.
