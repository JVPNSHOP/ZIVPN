cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel (with icons, copy button, floating logout)
# Author: GPT-5 Edition for ZIVPN Admin Panel

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

echo "==> Updating packages..."
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip openssl ufw curl jq > /dev/null

echo "==> Installing ZIVPN binary..."
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generating TLS certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" > /dev/null 2>&1

cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

echo "==> Setting up Web Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress > /dev/null

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

# ---- Flask app ----
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess
from datetime import date, datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","change-me")
app=Flask(__name__)
app.secret_key=os.urandom(24)

def db(): c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
with db() as con:
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,expires DATE)")

def logs():
    try:
        out=subprocess.check_output(["journalctl","-u",ZIVPN_SVC,"--since","-5min","-o","cat"]).decode().lower()
    except: out=""
    return out

def active_rows():
    log=logs(); today=date.today(); rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=False
            if not expired and r["password"].lower() in log:
                online=True
            rows.append({
                "id":r["id"],
                "username":r["username"],
                "password":r["password"],
                "expires":r["expires"],
                "expired":expired,
                "online":online
            })
    return rows

def sync():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    cfg={}
    try: cfg=json.load(open(ZIVPN_CFG))
    except: pass
    cfg.setdefault("auth",{})["mode"]="passwords";cfg["auth"]["config"]=pw;cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f: json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)
    subprocess.run(["systemctl","restart",ZIVPN_SVC])

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form["u"]==ADMIN_USER and request.form["p"]==ADMIN_PASS:
            session["ok"]=True;return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<html><head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-900 text-white grid place-items-center min-h-screen">
<div class="bg-slate-800 p-6 rounded-2xl w-[360px]">
<h2 class="text-xl font-bold mb-3">🛡️ ZIVPN Login</h2>
<form method=post><input name=u class="w-full mb-2 p-2 rounded bg-slate-700" placeholder=Username>
<input name=p type=password class="w-full mb-3 p-2 rounded bg-slate-700" placeholder=Password>
<button class="w-full bg-emerald-600 py-2 rounded">Login</button></form></div></body></html>''')

@app.route("/")
@login_required
def index():
    rows=active_rows()
    d=(date.today().replace(year=date.today().year+1)).isoformat()
    return render_template_string('''<html><head><script src="https://cdn.tailwindcss.com"></script>
<script>function copy(t,b){navigator.clipboard.writeText(t);b.innerText='✓';setTimeout(()=>b.innerText='Copy',700)}</script>
</head><body class="bg-slate-100">
<a href="/logout" class="fixed bottom-4 right-4 bg-sky-600 text-white px-4 py-3 rounded-full shadow-lg">Logout</a>
<div class="max-w-6xl mx-auto p-4"><h2 class="text-2xl font-bold mb-4">🛡️ ZIVPN Admin Panel</h2>
<div class="grid md:grid-cols-[320px_1fr] gap-4">
<div class="bg-white p-4 rounded-xl shadow">
<form method=post action="/save" class="space-y-2">
<input name=username placeholder="Username" class="w-full border rounded p-2">
<input name=password placeholder="Password" class="w-full border rounded p-2">
<input type=date name=expires value="'''+d+'''" class="w-full border rounded p-2">
<button class="w-full bg-emerald-600 text-white py-2 rounded">💾 Save & Sync</button></form></div>
<div class="bg-white p-4 rounded-xl shadow overflow-x-auto">
<table class="w-full text-left"><tr class="text-slate-600"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr>'''+
"".join([
f"<tr><td>{r['username']}</td>"
f"<td>{r['password']} <button onclick=\"copy('{r['password']}',this)\" class='ml-2 bg-slate-800 text-white px-2 py-1 rounded'>Copy</button></td>"
f"<td>{r['expires']}</td>"
f"<td>{'🟢 Online' if r['online'] else ('⚠️ Expired' if r['expired'] else '🔴 Offline')}</td>"
f"<td><form method=post action='/del/{r['id']}'><button class='bg-rose-600 text-white px-3 py-1 rounded'>🗑️</button></form></td></tr>"
for r in rows
])+
"</table></div></div></div></body></html>")

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"];p=request.form["password"];e=request.form["expires"]
    with db() as con:
        con.execute("INSERT INTO users(username,password,expires) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=?,expires=?",(u,p,e,p,e))
    sync();return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con: con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync();return redirect("/")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve; serve(app,host="0.0.0.0",port=8088)
PY

# --- Auto Sync Script ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
from datetime import date
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"
def actives():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
cfg={}
try: cfg=json.load(open(CFG))
except: pass
pw=actives()
cfg.setdefault("auth",{})["mode"]="passwords";cfg["auth"]["config"]=pw;cfg["config"]=pw
with tempfile.NamedTemporaryFile("w",delete=False) as f: json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
subprocess.run(["systemctl","restart",SVC])
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel
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
Description=ZIVPN Daily Sync
[Service]
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
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${SYNC_TIMER}

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "Open Panel: http://${IP}:8088/login"
echo "======================================"
BASH
chmod +x zi.sh
sudo ./zi.sh
