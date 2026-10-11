# Core Defense

A diagnostic and troubleshooting toolkit for Palo Alto Networks (PAN-OS) firewalls, powered by Google Gemini.

Core Defense connects to your PAN-OS firewalls to troubleshoot traffic drops, inspect telemetry, and verify configurations. Instead of manually hopping across multiple CLI commands or web UI tabs to diagnose a network issue, the agent dynamically queries the firewall, inspects live outputs, and provides verifiable CLI command receipts for every finding.

---

## Key Features

- **Interactive Diagnostic Console:** Ask natural language questions to diagnose why traffic is allowed or blocked, inspect BGP/OSPF states, check VPN tunnels, or audit system health.
- **Dynamic Tool Execution:** The agent autonomously selects and chains tools from the 85-operation PAN-OS manifest based on live firewall responses.
- **Raw Command Receipts:** Every answer includes an expandable drawer showing the exact PAN-OS CLI commands and XML queries executed, along with the raw device output.
- **Topology Mapping (Cartographer):** Parses running configuration XML directly into a structured network graph of interfaces, zones, and subnets.
- **Multi-Device Fleet Support:** Query, compare, and audit multiple firewalls from a single console using `config/devices.yaml`.
- **1-Click Incident Export:** Export any diagnostic session, findings, and receipts directly to a Google Doc or local Markdown report.
- **Read-Only Safety:** Operates in `READ_ONLY` mode by default. Destructive operations (`commit`, `reboot`, configuration edits) are blocked by the safety engine.

---

## Diagnostic Investigation

When troubleshooting traffic drops, reachability, or network anomalies, Core Defense gives Gemini access to live PAN-OS telemetry tools. The agent investigates dynamically based on observed evidence:

- **Routing & Path (FIB):** Evaluates virtual router FIB lookup, egress interface, and next-hop resolution (`test routing fib-lookup`).
- **NAT Policy Matching:** Verifies source and destination NAT matching and translation rules (`test nat-policy-match`).
- **Security Policy Evaluation:** Pinpoints matching rule name, rule index, and action (`test security-policy-match`).
- **Active Sessions & Counters:** Queries active session state, metering, and global drop counters (`show counter global`).
- **Network Subsystems:** Inspects BGP/OSPF peer states, IPsec tunnels, IKE phase 1/2 associations, and hardware telemetry.

Responses pinpoint the exact failure point (e.g. valid route and NAT, but denied by Security Rule #14) and provide copy-pasteable PAN-OS CLI syntax for remediation.

---

## Command Coverage

Supported operational checks across PAN-OS subsystems:

| Subsystem | Key Operations |
| :--- | :--- |
| **Flow & Policy** | `test routing fib-lookup`, `test nat-policy-match`, `test security-policy-match`, running config XML |
| **Sessions & Counters** | Active sessions, session metering, flow filters, global drop counters |
| **Routing & Interfaces** | BGP peers, OSPF neighbors, route tables, ARP, MAC, interface hardware stats |
| **VPN & Remote Access** | IPsec tunnels, IKE Phase 1/2 associations, GlobalProtect active users & history |
| **Identity & User-ID** | IP-to-User mapping cache, Active Directory server monitoring |
| **High Availability** | HA cluster state, sync status, link and path monitoring |
| **System & Health** | Hardware telemetry, resource utilization, partition quotas |

---

## Quick Start

### 1. Requirements & Setup
- Python 3.11+
- PAN-OS firewall with API access (PAN-OS 10.1, 10.2, 11.x)
- Gemini API key

```bash
git clone https://github.com/FUEL-user-community/firewall-ai.git
cd firewall-ai

python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

### 2. Configure Environment (`.env`)

```env
PANOS_HOSTNAME=192.168.1.254
PANOS_API_KEY=your-panos-api-key
GEMINI_API_KEY=your-gemini-api-key
```

### 3. Verify & Start

```bash
# Pre-flight check (verifies credentials, inventory, and schemas)
python server.py --check

# Start the web console
python server.py
```

Open **`http://localhost:8888`** in your browser.

---

## Example Queries

Once the web console is open, you can ask direct diagnostic questions:

- **Flow & Policy:** *"Why is 10.0.1.5 blocked when reaching 172.16.20.10 on port 443?"*
- **Routing:** *"Which interface and next hop are used to reach 192.168.50.1?"*
- **VPN:** *"Are any IPsec tunnels or IKE Phase 2 associations currently down?"*
- **Identity:** *"Show active User-ID mappings for IP 10.20.4.15."*
- **Health:** *"Check system load, swap usage, and partition storage across all firewalls."*

Every response displays the direct answer, followed by the **CLI Receipts Drawer** with the exact commands executed.

---

## Configuration Files

All configuration lives in the `config/` directory:

| File | Purpose |
| :--- | :--- |
| `config/devices.yaml` | List of firewalls (IPs, labels, virtual routers, default target). |
| `config/health_rules.yaml` | Alert thresholds for CPU, uptime, memory, and partitions with per-device overrides. |
| `config/commands.yaml` | Registry of allowed PAN-OS operational commands and parameters. |
| `config/prompts.yaml` | LLM reasoning prompts and output formatting rules. |

---

## Running Tests

Core Defense includes a regression test suite verifying tool schemas, client connection pooling, safety policy enforcement, and API endpoints:

```bash
python -m pytest
```

*133 passing tests.*

---

## License

MIT License. See [LICENSE](LICENSE).
