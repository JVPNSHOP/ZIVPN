cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Stylish Web Admin (Flask+Waitress, login, IP badge, Save+Sync, auto-expiry)
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

echo "==> Updating server & installing deps"
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip curl jq openssl ufw > /dev/null

echo "==> Install ZIVPN UDP"
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"
mkdir -p "${ZIVPN_DIR}"

# solid default config (auth.config & config both present)
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": { "mode": "passwords", "config": ["zi"] },
  "config": ["zi"]
}
JSON

echo "==> Generate TLS cert"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=Admin/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" > /dev/null 2>&1

# kernel tune (best effort)
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# systemd unit for UDP daemon
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
systemctl enable --now "${ZIVPN_SVC}"

# DNAT + firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 6000:19999/udp || true

# ========= Web Admin =========
echo "==> Install Web Admin (Flask + Waitress)"
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet flask waitress

read -rp "Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# -------- Stylish Flask App (Tailwind UI) --------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, subprocess, tempfile, socket
from datetime import datetime, date
from pathlib import Path
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template_string, flash, session

APP_TITLE = "ZIVPN User Panel"
DB_DIR = Path("/var/lib/zivpn-admin"); DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DB_DIR / "zivpn.db")

ZIVPN_CONFIG = os.environ.get("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SERVICE = os.environ.get("ZIVPN_SERVICE","zivpn.service")
BIND_HOST = os.environ.get("BIND_HOST","0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT","8088"))
ADMIN_USER = os.environ.get("ADMIN_USER","admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD","admin")

app = Flask(__name__)
app.secret_key = os.urandom(32)

# ---------- DB ----------
def db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        expires  DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

# ---------- Helpers ----------
def server_ip():
    try:
        ip = os.popen("hostname -I").read().strip().split()[0]
        return ip or socket.gethostbyname(socket.gethostname())
    except Exception:
        return "unknown"

def active_passwords():
    today = date.today().isoformat()
    with db() as con:
        rows = con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE(?)",(today,)).fetchall()
    return [r[0] for r in rows] or ["zi"]

def write_config_and_restart():
    cfg = {}
    try:
        with open(ZIVPN_CONFIG,"r",encoding="utf-8") as f: cfg=json.load(f)
    except: cfg={}
    pw = sorted(set(active_passwords()))
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw   # <-- UDP checks this
    cfg["config"]=pw           # <-- some builds also read this; keep identical
    text=json.dumps(cfg,indent=2,ensure_ascii=False)+"\n"
    # atomic write
    with tempfile.NamedTemporaryFile("w",delete=False,dir=os.path.dirname(ZIVPN_CONFIG),encoding="utf-8") as t:
        t.write(text); tmp=t.name
    os.replace(tmp, ZIVPN_CONFIG)
    subprocess.run(["systemctl","restart",ZIVPN_SERVICE], check=False)

# ---------- Auth ----------
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a, **kw)
    return w

# ---------- UI (Tailwind CDN) ----------
LOGIN_HTML = """
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script>
<title>Login • ZIVPN</title>
</head><body class="min-h-screen bg-slate-900 text-slate-100 grid place-items-center">
  <div class="w-[380px] max-w-[94vw] bg-slate-800/70 rounded-2xl p-6 shadow-2xl">
    <h2 class="text-xl font-bold mb-4">🛡️ ZIVPN Admin</h2>
    {% for m in get_flashed_messages() %}
      <div class="mb-3 rounded-lg bg-yellow-100 text-yellow-900 px-3 py-2">{{m}}</div>
    {% endfor %}
    <form method="post" class="space-y-3">
      <input name="u" class="w-full px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-700" placeholder="Username" required>
      <input name="p" type="password" class="w-full px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-700" placeholder="Password" required>
      <button class="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 font-semibold">Login</button>
    </form>
    <div class="mt-3 text-slate-400 text-sm">Server: {{server_ip}}</div>
  </div>
</body></html>
"""

BASE_HTML = """
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script>
<title>{{title}}</title>
</head><body class="bg-slate-100">
<div class="max-w-6xl mx-auto p-4">
  <div class="flex items-center justify-between mb-4">
    <div class="flex items-center gap-3">
      <div class="text-2xl font-bold">🛡️ {{title}}</div>
      <span class="px-3 py-1 rounded-full bg-indigo-100 text-indigo-700 text-sm">Server: {{server_ip}}</span>
    </div>
    <div class="flex gap-2">
      <form method="post" action="{{url_for('sync')}}">
        <button class="px-3 py-2 rounded-lg bg-emerald-600 text-white font-semibold hover:bg-emerald-500">Save + Sync</button>
      </form>
      <a href="{{url_for('logout')}}" class="px-3 py-2 rounded-lg bg-sky-600 text-white font-semibold hover:bg-sky-500">Logout</a>
    </div>
  </div>

  {% for m in get_flashed_messages() %}
    <div class="mb-4 rounded-xl bg-yellow-50 text-yellow-800 px-4 py-2">{{m}}</div>
  {% endfor %}

  <div class="grid md:grid-cols-[340px_1fr] gap-4">
    <div class="bg-white rounded-2xl shadow p-4">
      <form method="post" action="{{url_for('save')}}" class="space-y-2">
        <label class="text-sm text-slate-600">User</label>
        <input name="username" class="w-full px-3 py-2 rounded-lg border border-slate-300" required>
        <label class="text-sm text-slate-600">Password</label>
        <input name="password" class="w-full px-3 py-2 rounded-lg border border-slate-300" required>
        <label class="text-sm text-slate-600">Expires</label>
        <input type="date" name="expires" value="{{default_expiry}}" class="w-full px-3 py-2 rounded-lg border border-slate-300" required>
        <button class="w-full py-2 rounded-lg bg-emerald-600 text-white font-semibold hover:bg-emerald-500">Save</button>
      </form>
    </div>

    <div class="bg-white rounded-2xl shadow p-4 overflow-x-auto">
      <table class="w-full text-left">
        <thead class="text-slate-600 text-sm">
          <tr><th class="py-2">User</th><th class="py-2">Password</th><th class="py-2">Expires</th><th class="py-2"></th></tr>
        </thead>
        <tbody class="text-slate-800">
          {% for r in rows %}
          <tr class="border-b last:border-b-0">
            <td class="py-2">{{r.username}}</td>
            <td class="py-2">{{r.password}}</td>
            <td class="py-2">{{r.expires}}</td>
            <td class="py-2">
              <form method="post" action="{{url_for('delete', user_id=r.id)}}" onsubmit="return confirm('Delete {{r.username}}?')">
                <button class="px-3 py-1 rounded-lg bg-rose-600 text-white hover:bg-rose-500">Delete</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body></html>
"""

# ---------- Routes ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASSWORD:
            session["ok"]=True; return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template_string(LOGIN_HTML, server_ip=server_ip())

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

def require_login(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**k)
    return w

@app.route("/", methods=["GET"])
@require_login
def index():
    d = date(date.today().year+1, date.today().month, date.today().day).isoformat()
    with db() as con:
        rows = con.execute("SELECT id,username,password,expires FROM users ORDER BY username").fetchall()
    return render_template_string(BASE_HTML, title=APP_TITLE, rows=rows, default_expiry=d, server_ip=server_ip())

@app.route("/save", methods=["POST"])
@require_login
def save():
    u=request.form.get("username","").strip()
    p=request.form.get("password","").strip()
    e=request.form.get("expires","").strip()
    if not (u and p and e): flash("All fields required"); return redirect(url_for("index"))
    try:
        datetime.strptime(e,"%Y-%m-%d")
        with db() as con:
            con.execute("""INSERT INTO users(username,password,expires) VALUES(?,?,?)
              ON CONFLICT(username) DO UPDATE SET password=excluded.password, expires=excluded.expires""",(u,p,e))
        flash(f"Saved {u}")
    except Exception as ex:
        flash(f"Error: {ex}")
    return redirect(url_for("index"))

@app.route("/delete/<int:user_id>", methods=["POST"])
@require_login
def delete(user_id):
    with db() as con: con.execute("DELETE FROM users WHERE id=?",(user_id,))
    flash("Deleted")
    return redirect(url_for("index"))

@app.route("/sync", methods=["POST"])
@require_login
def sync():
    try: write_config_and_restart(); flash("Synced to config + restarted ZIVPN")
    except Exception as ex: flash(f"Sync failed: {ex}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    from waitress import serve
    serve(app, host=BIND_HOST, port=BIND_PORT)
PY

# -------- Daily sync (auto-expire) --------
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
from datetime import date
CFG=os.environ.get("ZIVPN_CONFIG","/etc/zivpn/config.json")
SVC=os.environ.get("ZIVPN_SERVICE","zivpn.service")
DB="/var/lib/zivpn-admin/zivpn.db"
def active():
    with sqlite3.connect(DB) as con:
        return [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE(?)",(date.today().isoformat(),))] or ["zi"]
cfg={}
try:
    with open(CFG,"r",encoding="utf-8") as f: cfg=json.load(f)
except: cfg={}
pw=sorted(set(active()))
cfg.setdefault("auth",{})["mode"]="passwords"
cfg["auth"]["config"]=pw
cfg["config"]=pw
txt=json.dumps(cfg,indent=2,ensure_ascii=False)+"\n"
with tempfile.NamedTemporaryFile("w",delete=False,dir=os.path.dirname(CFG),encoding="utf-8") as t:
    t.write(txt); tmp=t.name
os.replace(tmp, CFG)
subprocess.run(["systemctl","restart",SVC],check=False)
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

# systemd units for panel + daily sync
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

cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN daily sync
[Service]
Type=oneshot
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${SYNC_PY}
EOF

cat >/etc/systemd/system/${SYNC_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN daily sync
[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "${PANEL_SVC}"
systemctl enable --now "${SYNC_TIMER}"

ufw allow 8088/tcp || true

IP=$(hostname -I | awk '{print $1}')
echo
echo "======== DONE ========"
echo "Admin Panel : http://${IP}:8088/login"
echo "Service     : systemctl status ${ZIVPN_SVC}"
echo "Panel svc   : systemctl status ${PANEL_SVC}"
echo "======================"
BASH

chmod +x zi.sh
sudo ./zi.sh
