cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Web Admin (auto-auth.sync fixed)
set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

echo "==> Updating system"
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip curl jq openssl ufw >/dev/null

echo "==> Installing ZIVPN UDP"
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"
mkdir -p "${ZIVPN_DIR}"

echo "==> Creating config"
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode":"passwords","config":["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generating cert files"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

sysctl -w net.core.rmem_max=16777216 >/dev/null
sysctl -w net.core.wmem_max=16777216 >/dev/null

cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 6000:19999/udp || true

# ===== Web Admin Panel =====
echo "==> Installing Web Admin Panel"
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet flask waitress

read -rp "Set Web Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Set Web Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, subprocess, tempfile, socket
from datetime import datetime, date
from pathlib import Path
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template_string, flash, session

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
Path("/var/lib/zivpn-admin").mkdir(parents=True, exist_ok=True)

ZIVPN_CONFIG = os.environ.get("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SERVICE = os.environ.get("ZIVPN_SERVICE","zivpn.service")
ADMIN_USER = os.environ.get("ADMIN_USER","admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD","admin")

app = Flask(__name__)
app.secret_key = os.urandom(32)

def db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, expires DATE
    )""")

def active_pw():
    today = date.today().isoformat()
    with db() as con:
        return [r[0] for r in con.execute("SELECT password FROM users WHERE DATE(expires)>=DATE(?)",(today,))] or ["zi"]

def write_cfg():
    pw = sorted(set(active_pw()))
    cfg = {}
    try:
        with open(ZIVPN_CONFIG,"r") as f: cfg=json.load(f)
    except: pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw
    cfg["config"]=pw
    text=json.dumps(cfg,indent=2)
    with tempfile.NamedTemporaryFile("w",delete=False,dir="/etc/zivpn",encoding="utf-8") as t:
        t.write(text); tmp=t.name
    os.replace(tmp,ZIVPN_CONFIG)
    subprocess.run(["systemctl","restart",ZIVPN_SERVICE],check=False)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect("/login")
        return f(*a,**kw)
    return w

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASSWORD:
            session["ok"]=True; return redirect("/")
        flash("Invalid login")
    return "<form method=post><input name=u><input name=p type=password><button>Login</button></form>"

@app.route("/",methods=["GET"])
@login_required
def index():
    with db() as con:
        users = con.execute("SELECT * FROM users").fetchall()
    return str(users)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"]; p=request.form["password"]; e=request.form["expires"]
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
            VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=?,expires=?""",(u,p,e,p,e))
    flash("Saved"); return redirect("/")

@app.route("/sync",methods=["POST"])
@login_required
def sync():
    write_cfg(); flash("Synced + Restarted"); return redirect("/")

if __name__=="__main__":
    from waitress import serve; serve(app,host="0.0.0.0",port=8088)
PY

cat > "${SYNC_PY}" <<'PY'
import os,json,sqlite3,tempfile,subprocess
from datetime import date
cfg="/etc/zivpn/config.json"; db="/var/lib/zivpn-admin/zivpn.db"
svc="zivpn.service"
with sqlite3.connect(db) as c:
    pw=[r[0] for r in c.execute("SELECT password FROM users WHERE DATE(expires)>=DATE(?)",(date.today().isoformat(),))] or ["zi"]
try:
    with open(cfg,"r") as f: data=json.load(f)
except: data={}
data.setdefault("auth",{})["mode"]="passwords"
data["auth"]["config"]=pw
data["config"]=pw
text=json.dumps(data,indent=2)
with tempfile.NamedTemporaryFile("w",delete=False,dir="/etc/zivpn") as t:
    t.write(text); tmp=t.name
os.replace(tmp,cfg)
subprocess.run(["systemctl","restart",svc])
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Admin Panel
After=network.target
[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN daily sync
[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${SYNC_PY}
EOF

cat >/etc/systemd/system/${SYNC_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN sync daily
[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${SYNC_TIMER}
ufw allow 8088/tcp || true

IP=$(hostname -I | awk '{print $1}')
echo
echo "=== INSTALL COMPLETE ==="
echo "Panel: http://${IP}:8088/login"
echo "ZIVPN Password default: zi"
echo "========================="
BASH

chmod +x zi.sh
sudo ./zi.sh
