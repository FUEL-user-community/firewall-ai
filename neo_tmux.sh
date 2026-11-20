#!/usr/bin/env bash
# Launch NEO Symbiotic Single-Prompt SSH inside a persistent tmux session
# (Pass '--split' if you ever want legacy 2-pane side-by-side mode instead).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="${NEO_TMUX_SESSION:-neo}"
PANOS_Target="${NEO_TARGET_DEVICE:-fw-hq}"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    exec tmux attach-session -t "$SESSION_NAME"
fi

if [[ "${1:-}" == "--split" ]]; then
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
            ip = str(v["ip"]).strip(); break
print(ip or "192.168.1.254")
')"
    tmux new-session -d -s "$SESSION_NAME" -c "$REPO_DIR" "python3 neo_cli.py"
    tmux set-option -t "$SESSION_NAME" mouse on >/dev/null 2>&1 || true
    tmux set-option -t "$SESSION_NAME" history-limit 50000 >/dev/null 2>&1 || true
    tmux split-window -h -p 38 -t "${SESSION_NAME}:0.0" "ssh ${PANOS_USER}@${FW_IP}"
    tmux select-pane -t "${SESSION_NAME}:0.0"
else
    tmux new-session -d -s "$SESSION_NAME" -c "$REPO_DIR" "python3 neo_cli.py --ssh ${PANOS_Target}"
    tmux set-option -t "$SESSION_NAME" mouse on >/dev/null 2>&1 || true
    tmux set-option -t "$SESSION_NAME" history-limit 50000 >/dev/null 2>&1 || true
fi

exec tmux attach-session -t "$SESSION_NAME"
