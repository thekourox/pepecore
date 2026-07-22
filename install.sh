#!/bin/bash
# ============================================================
# PepeCore v2 installer
# ============================================================
set -e

[ "$EUID" -ne 0 ] && { echo "Run as root."; exit 1; }

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/venv"
PORT="${PEPECORE_PORT:-8088}"

echo "[1/6] System packages"
apt-get update -y -qq
apt-get install -y -qq python3 python3-pip python3-venv curl >/dev/null

echo "[2/6] Virtualenv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q fastapi "uvicorn[standard]" pydantic jinja2 httpx PySocks

echo "[3/6] Kernel tuning for many concurrent tunnels"
SYSCTL=/etc/sysctl.d/99-pepecore.conf
cat > "$SYSCTL" <<'SEOF'
# 140 WireGuard tunnels keep a lot of UDP flows alive at once.
net.netfilter.nf_conntrack_max = 262144
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000
fs.file-max = 2097152
SEOF
sysctl -p "$SYSCTL" >/dev/null 2>&1 || echo "  (some sysctls unavailable in this environment)"

echo "[4/6] Directories"
mkdir -p "$APP_DIR/data/wg" "$APP_DIR/bin"
chmod 700 "$APP_DIR/data/wg"     # private keys live here

echo "[5/6] Fetching wireproxy"
"$VENV/bin/python" -c "
import sys; sys.path.insert(0,'$APP_DIR')
from core import engine
engine.ensure_binary()
print('  wireproxy ready')
" || echo "  (will retry on first start)"

echo "[6/6] systemd service"
cat > /etc/systemd/system/pepecore.service <<EOF
[Unit]
Description=PepeCore - decoupled WireGuard engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$VENV/bin/python -m uvicorn app:app --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5
# Each tunnel holds several descriptors and is its own process. These are
# sized for ~140 concurrent tunnels with plenty of headroom.
LimitNOFILE=1048576
LimitNPROC=1048576
TasksMax=8192

[Install]
WantedBy=multi-user.target
EOF

chmod +x "$APP_DIR/pepectl.py"
ln -sf "$APP_DIR/pepectl.py" /usr/local/bin/pepectl

systemctl daemon-reload
systemctl enable -q pepecore
systemctl restart pepecore

cat <<EOF

============================================================
 PepeCore installed.

 Panel : http://<server-ip>:$PORT
 CLI   : pepectl status
 Logs  : journalctl -u pepecore -f

 First-time setup:
   1. pepectl capacity --slots <N>        check this machine first
   2. pepectl key import keys.txt         (or: key add --key <KEY>)
   3. pepectl slots ensure <N>
   4. pepectl slots fill
   5. pepectl bind --host https://panel.tld --token <TOKEN> \\
                   --core-id <ID> --slot-count <N>
      (run once)

 For large deployments (100+ locations) set the slot ceiling first:
   export PEPECORE_MAX_SLOTS=200

 From then on, rotating a key is just:
   pepectl key rotate <id> --key <NEW_KEY>
 No re-inject. No panel call. No user disruption.
============================================================
EOF
