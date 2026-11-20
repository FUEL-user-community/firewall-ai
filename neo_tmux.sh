#!/usr/bin/env bash
# Launch or re-attach NEO Cybersec Resident beside a live PAN-OS SSH session.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="${NEO_TMUX_SESSION:-neo}"
PANOS_USER="${PANOS_SSH_USER:-admin}"

FW_IP="$(python3 -c '
import yaml
from pathlib import Path
p = Path("config/devices.yaml")
ip = ""
if p.is_file():
    d = (yaml.safe_load(p.read_text()) or {}).get("firewalls", {})
    for _, v in d.items():
        if isinstance(v, dict) and v.get("default") and v.get("ip"):
            ip = str(v["ip"]).strip()
            break
    if not ip and d:
        first = next(iter(d.values()))
        ip = str(first.get("ip", "")).strip() if isinstance(first, dict) else ""
print(ip or "192.168.1.254")
')"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    exec tmux attach-session -t "$SESSION_NAME"
fi

tmux new-session -d -s "$SESSION_NAME" -c "$REPO_DIR" "python3 neo_cli.py"
tmux split-window -h -p 38 -t "${SESSION_NAME}:0.0" "ssh ${PANOS_USER}@${FW_IP}"
tmux select-pane -t "${SESSION_NAME}:0.0"
exec tmux attach-session -t "$SESSION_NAME"
