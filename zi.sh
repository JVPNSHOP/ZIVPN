cat > zi.sh <<'BASH'
#!/bin/bash
# All-in-one installer: ZIVPN + Web Admin Panel (fixed)
set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"

echo "==> Updating packages"
apt-get update -y && apt-get upgrade -y

echo "==> Install ZIVPN"
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"
mkdir -p "${ZIVPN_DIR}"
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O "${ZIVPN_CFG}"

echo "==> Generate certs"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=zivpn VPN Server
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

echo "==> ZIVPN UDP Passwords"
read -rp "Enter passwords (comma separated) [default: zi]: " input_config
[[ -z "${input_config}" ]] && input_config="zi"

python3 - "$ZIVPN_CFG" "$input_config" <<'PY'
import sys, json
cfg_path, csv = sys.argv[1], sys.argv[2]
pw = [x.strip() for x in csv.split(",") if x.strip()] or ["zi"]
try:
    with open(cfg_path, "r", encoding="utf-8") as f: cfg = json.load(f)
except Exception: cfg = {}
cfg["config"] = pw
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False); f.write("\n")
PY

systemctl daemon-reload
systemctl enable --now "${ZIVPN_SVC}"

# NAT/Firewall (one-time)
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

echo "==> Install Web Admin Panel"
apt-get install -y python3-venv python3-pip >/dev/null
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask >/dev/null

read -rp "Set Web Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Set Web Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

# Bind 0.0.0.0 so phone browser can open directly
cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# --- FIXED Flask app (no decorator syntax errors) ---
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
# ZIVPN Web Admin Panel (single-file, fixed)
import os, json, sqlite3, subprocess, tempfile
from datetime import datetime, date
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template_string, flash, Response
from functools import wraps

APP_TITLE = "ZIVPN User Panel"
DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
Path("/var/lib/zivpn-admin").mkdir(parents=True, exist_ok=True)

ZIVPN_CONFIG_PATH = os.environ.get("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SERVICE = os.environ.get("ZIVPN_SERVICE","zivpn.service")
BIND_HOST = os.environ.get("BIND_HOST","0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT","8088"))
ADMIN_USER = os.environ.get("ADMIN_USER","admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD","admin")

app = Flask(__name__)
app.secret_key = os.urandom(16)

def require_auth(f):
    @wraps(f)
    def w(*a, **kw):
        auth = request.authorization
        if not auth or not (auth.username==ADMIN_USER and auth.password==ADMIN_PASSWORD):
            return Response("Auth required",401,{"WWW-Authenticate":'Basic realm="ZIVPN Admin"'})
        return f(*a, **kw)
    return w

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        expires DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

HTML = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<link href="https://cdn.jsdelivr.net/npm/modern-normalize@2/modern-normalize.min.css" rel="stylesheet">
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#f6f7fb}
.container{max-width:1100px;margin:2rem auto;padding:0 1rem}
.card{background:#fff;border-radius:14px;box-shadow:0 6px 18px rgba(0,0,0,.06);padding:1rem}
.grid{display:grid;grid-template-columns:320px 1fr;gap:1rem}
input{width:100%;padding:.6rem;border:1px solid #e3e3ea;border-radius:10px;margin:.25rem 0 1rem}
.btn{padding:.6rem .9rem;border:0;border-radius:10px;background:#14a44d;color:#fff;font-weight:700;cursor:pointer}
.btn.danger{background:#dc3545}
table{width:100%;border-collapse:separate;border-spacing:0 8px}
th,td{background:#fff;padding:.6rem .75rem;text-align:left}
.flash{background:#fff3cd;border:1px solid #ffeeba;color:#856404;padding:.5rem;border-radius:10px;margin-bottom:1rem}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}
</style>
</head><body><div class="container">
<header><h2>🛡️ {{title}}</h2>
<form method="post" action="{{url_for('sync')}}"><button class="btn" type="submit">Save + Sync</button></form>
</header>
{% for m in get_flashed_messages() %}<div class="flash">{{m}}</div>{% endfor %}
<div class="grid">
  <div class="card">
    <form method="post" action="{{url_for('save')}}">
      <label>User</label><input name="username" required>
      <label>Password</label><input name="password" required>
      <label>Expires</label><input type="date" name="expires" value="{{default_expiry}}" required>
      <button class="btn" type="submit">Save</button>
    </form>
  </div>
  <div>
    <table>
      <thead><tr><th>User</th><th>Password</th><th>Expires</th><th></th></tr></thead>
      <tbody>
      {% for r in rows %}
        <tr>
          <td>{{r.username}}</td><td>{{r.password}}</td><td>{{r.expires}}</td>
          <td>
            <form method="post" action="{{url_for('delete', user_id=r.id)}}">
              <button class="btn danger" type="submit">Delete</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</div></body></html>
"""

def list_users():
    with db() as con:
        return con.execute("SELECT id,username,password,expires FROM users ORDER BY username").fetchall()

def upsert(u,p,e):
    datetime.strptime(e,"%Y-%m-%d")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires) VALUES(?,?,?)
        ON CONFLICT(username) DO UPDATE SET password=excluded.password, expires=excluded.expires""",(u,p,e))

def delete_user(i):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(i,))

def active_passwords():
    today = date.today().isoformat()
    with db() as con:
        rows = con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE(?)",(today,)).fetchall()
    return [r[0] for r in rows]

def sync_config_and_restart():
    try:
        with open(ZIVPN_CONFIG_PATH,"r",encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    pw = active_passwords()
    cfg["config"] = sorted(set(pw)) if pw else ["zi"]
    text = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    try:
        with tempfile.NamedTemporaryFile("w",delete=False,dir=os.path.dirname(ZIVPN_CONFIG_PATH),encoding="utf-8") as t:
            t.write(text); t.flush(); os.fsync(t.fileno()); tmp=t.name
        os.replace(tmp, ZIVPN_CONFIG_PATH)
    except PermissionError:
        subprocess.run(["sudo","tee",ZIVPN_CONFIG_PATH], input=text.encode(), stdout=subprocess.DEVNULL)
    subprocess.run(["sudo","systemctl","restart",ZIVPN_SERVICE], check=False)

@app.route("/", methods=["GET"])
@require_auth
def index():
    default_expiry = date(date.today().year+1, date.today().month, date.today().day).isoformat()
    return render_template_string(HTML, title=APP_TITLE, rows=list_users(), default_expiry=default_expiry)

@app.route("/save", methods=["POST"])
@require_auth
def save():
    u = request.form.get("username","").strip()
    p = request.form.get("password","").strip()
    e = request.form.get("expires","").strip()
    if not (u and p and e):
        flash("All fields required"); return redirect(url_for("index"))
    try:
        upsert(u,p,e); flash(f"Saved {u}")
    except Exception as ex:
        flash(f"Error: {ex}")
    return redirect(url_for("index"))

@app.route("/delete/<int:user_id>", methods=["POST"])
@require_auth
def delete(user_id):
    delete_user(user_id); flash("Deleted"); return redirect(url_for("index"))

@app.route("/sync", methods=["POST"])
@require_auth
def sync():
    try:
        sync_config_and_restart(); flash("Synced to config.json + restarted service")
    except Exception as ex:
        flash(f"Sync failed: {ex}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
PY

chmod +x "${APP_PY}"

cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Admin Panel
After=network.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${PANEL_SVC}"

ufw allow 8088/tcp || true

IP=$(hostname -I | awk '{print $1}')
echo
echo "================ DONE ================"
echo "ZIVPN        : ${ZIVPN_SVC}  (systemctl status ${ZIVPN_SVC})"
echo "Admin Panel  : ${PANEL_SVC}  (systemctl status ${PANEL_SVC})"
echo "Open in your browser:  http://${IP}:8088/"
echo "Login with the admin credentials you set."
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
