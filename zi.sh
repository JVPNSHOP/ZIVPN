cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Web Admin (nice UI + login + IP badge + edit/date + Save+Sync + auto-expiry)
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

echo "==> Updating server"
apt-get update -y && apt-get upgrade -y

echo "==> Installing dependencies"
apt-get install -y python3-venv python3-pip curl jq openssl ufw >/dev/null

echo "==> Installing ZIVPN UDP"
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"
mkdir -p "${ZIVPN_DIR}"
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O "${ZIVPN_CFG}"

echo "==> Generating cert files"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

# Kernel tuning (best-effort)
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# ===== systemd for zivpn =====
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

echo "==> Initial UDP passwords"
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

# ===== DNAT + UFW =====
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

# ===== Web Admin Panel =====
echo "==> Installing Web Admin Panel (Flask + Waitress)"
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

# ---------- app.py (login UI, server IP badge, CRUD, Save+Sync, only non-expired passwords) ----------
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

def server_ip():
    try:
        ip = os.popen("hostname -I").read().strip().split()[0]
        return ip or socket.gethostbyname(socket.gethostname())
    except Exception:
        return "unknown"

# ---------- auth (login form + session) ----------
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a, **kw)
    return w

# ---------- db ----------
def db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        expires DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

# ---------- UI ----------
BASE = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<link href="https://cdn.jsdelivr.net/npm/modern-normalize@2/modern-normalize.min.css" rel="stylesheet">
<style>
:root{--bg:#f6f7fb;--card:#fff;--pri:#16a34a;--danger:#dc3545;--text:#111827}
body{background:var(--bg);font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial}
.container{max-width:1100px;margin:2rem auto;padding:0 1rem}
.card{background:var(--card);border-radius:16px;box-shadow:0 6px 20px rgba(0,0,0,.06);padding:1rem}
.btn{border:0;border-radius:10px;padding:.65rem .9rem;font-weight:700;color:#fff;background:var(--pri);cursor:pointer}
.btn.alt{background:#0ea5e9}.btn.danger{background:var(--danger)}
.input{width:100%;padding:.6rem;border:1px solid #e5e7eb;border-radius:10px;margin:.35rem 0 1rem}
.grid{display:grid;grid-template-columns:320px 1fr;gap:1rem}
table{width:100%;border-collapse:separate;border-spacing:0 8px}
th,td{background:#fff;padding:.65rem .75rem;text-align:left}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}
.badge{font-size:.8rem;background:#eef2ff;color:#3730a3;border-radius:999px;padding:.25rem .6rem}
.flash{background:#fff3cd;border:1px solid #ffeeba;color:#856404;padding:.5rem;border-radius:10px;margin:1rem 0}
</style></head><body>
<div class="container">
<header>
  <div><strong style="font-size:1.25rem">🛡️ {{title}}</strong>
  <span class="badge">Server: {{server_ip}}</span></div>
  <div>
    <a class="btn alt" href="{{url_for('logout')}}">Logout</a>
    <form style="display:inline" method="post" action="{{url_for('sync')}}"><button class="btn" type="submit">Save + Sync</button></form>
  </div>
</header>
{% for m in get_flashed_messages() %}<div class="flash">{{m}}</div>{% endfor %}
<div class="grid">
  <div class="card">
    <form method="post" action="{{url_for('save')}}">
      <label>User</label><input class="input" name="username" required>
      <label>Password</label><input class="input" name="password" required>
      <label>Expires</label><input class="input" type="date" name="expires" value="{{default_expiry}}" required>
      <button class="btn" type="submit">Save</button>
    </form>
  </div>
  <div>
    <table>
      <thead><tr><th>User</th><th>Password</th><th>Expires</th><th></th></tr></thead>
      <tbody>
      {% for r in rows %}
        <tr>
          <td>{{r.username}}</td>
          <td>{{r.password}}</td>
          <td>{{r.expires}}</td>
          <td>
            <form method="post" action="{{url_for('delete', user_id=r.id)}}" style="display:inline">
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

LOGIN = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login • ZIVPN</title>
<link href="https://cdn.jsdelivr.net/npm/modern-normalize@2/modern-normalize.min.css" rel="stylesheet">
<style>
body{min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#fff;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial}
.card{width:380px;max-width:96vw;background:#111827;border-radius:16px;padding:1.25rem;box-shadow:0 15px 40px rgba(0,0,0,.4)}
h2{margin:.3rem 0 1rem}
.input{width:100%;padding:.65rem;border-radius:10px;border:1px solid #334155;background:#0b1220;color:#fff;margin:.35rem 0 1rem}
.btn{width:100%;padding:.75rem;border:0;border-radius:10px;background:#16a34a;color:#fff;font-weight:700;cursor:pointer}
.muted{color:#9ca3af;font-size:.9rem}
</style></head><body>
<div class="card">
  <h2>🛡️ ZIVPN Admin</h2>
  <form method="post">
    <input class="input" name="u" placeholder="Username" required>
    <input class="input" type="password" name="p" placeholder="Password" required>
    <button class="btn" type="submit">Login</button>
  </form>
  <div class="muted">Server: {{server_ip}}</div>
</div>
</body></html>
"""

# ---------- helpers ----------
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
    return [r[0] for r in rows] or ["zi"]

def write_config_and_restart():
    cfg={}
    try:
        with open(ZIVPN_CONFIG,"r",encoding="utf-8") as f: cfg=json.load(f)
    except Exception: cfg={}
    cfg["config"]=sorted(set(active_passwords()))
    text=json.dumps(cfg,indent=2,ensure_ascii=False)+"\n"
    try:
        with tempfile.NamedTemporaryFile("w",delete=False,dir=os.path.dirname(ZIVPN_CONFIG),encoding="utf-8") as t:
            t.write(text); t.flush(); os.fsync(t.fileno()); tmp=t.name
        os.replace(tmp, ZIVPN_CONFIG)
    except PermissionError:
        subprocess.run(["tee",ZIVPN_CONFIG], input=text.encode(), check=False)
    subprocess.run(["systemctl","restart",os.environ.get("ZIVPN_SERVICE","zivpn.service")], check=False)

# ---------- routes ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASSWORD:
            session["ok"]=True; return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template_string(LOGIN, server_ip=server_ip())

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/", methods=["GET"])
@login_required
def index():
    d = date(date.today().year+1, date.today().month, date.today().day).isoformat()
    return render_template_string(BASE, title=APP_TITLE, rows=list_users(), default_expiry=d, server_ip=server_ip())

@app.route("/save", methods=["POST"])
@login_required
def save():
    u = request.form.get("username","").strip()
    p = request.form.get("password","").strip()
    e = request.form.get("expires","").strip()
    if not (u and p and e):
        flash("All fields required"); return redirect(url_for("index"))
    try: upsert(u,p,e); flash(f"Saved {u}")
    except Exception as ex: flash(f"Error: {ex}")
    return redirect(url_for("index"))

@app.route("/delete/<int:user_id>", methods=["POST"])
@login_required
def delete(user_id):
    delete_user(user_id); flash("Deleted"); return redirect(url_for("index"))

@app.route("/sync", methods=["POST"])
@login_required
def sync():
    try: write_config_and_restart(); flash("Synced to config + restarted ZIVPN")
    except Exception as ex: flash(f"Sync failed: {ex}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    from waitress import serve
    serve(app, host=BIND_HOST, port=BIND_PORT)
PY
chmod +x "${APP_PY}"

# ---------- sync.py (daily auto apply non-expired passwords) ----------
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
from datetime import date
ZIVPN_CONFIG=os.environ.get("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SERVICE=os.environ.get("ZIVPN_SERVICE","zivpn.service")
DB="/var/lib/zivpn-admin/zivpn.db"

def active_pw():
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE(?)",(date.today().isoformat(),)).fetchall()
    return [r[0] for r in rows] or ["zi"]

def run():
    cfg={}
    try:
        with open(ZIVPN_CONFIG,"r",encoding="utf-8") as f: cfg=json.load(f)
    except Exception: cfg={}
    cfg["config"]=sorted(set(active_pw()))
    text=json.dumps(cfg,indent=2,ensure_ascii=False)+"\n"
    try:
        with tempfile.NamedTemporaryFile("w",delete=False,dir=os.path.dirname(ZIVPN_CONFIG),encoding="utf-8") as t:
            t.write(text); t.flush(); os.fsync(t.fileno()); tmp=t.name
        os.replace(tmp, ZIVPN_CONFIG)
    except PermissionError:
        subprocess.run(["tee",ZIVPN_CONFIG], input=text.encode(), check=False)
    subprocess.run(["systemctl","restart",ZIVPN_SERVICE], check=False)

if __name__=="__main__": run()
PY

# ===== systemd: admin panel =====
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

# ===== systemd: daily sync timer (00:10) =====
cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN daily sync (apply non-expired passwords)

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
echo "=============== DONE ==============="
echo "ZIVPN service : ${ZIVPN_SVC}     (systemctl status ${ZIVPN_SVC})"
echo "Admin Panel   : ${PANEL_SVC}     (systemctl status ${PANEL_SVC})"
echo "Daily Sync    : ${SYNC_TIMER}    (systemctl list-timers | grep zivpn-sync)"
echo "Open Panel    : http://${IP}:8088/login"
echo "===================================="
BASH

chmod +x zi.sh
sudo ./zi.sh
