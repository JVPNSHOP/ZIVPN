cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP Server + Tailwind Web Panel
# Stable GPT-5 Edition — Fixed Initramfs freeze
# Script By: JueHtet

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

echo "==> Installing dependencies..."
DEBIAN_FRONTEND=noninteractive apt-get update -yq
DEBIAN_FRONTEND=noninteractive apt-get install -yq python3-venv python3-pip openssl ufw curl jq conntrack iptables-persistent

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
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

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
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

echo "==> Setting up Web Panel..."
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

# --- Flask Admin Panel ---
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, re
from datetime import date, datetime, timedelta
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs(os.path.dirname(DB), exist_ok=True)
ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","change-me")
app=Flask(__name__)
app.secret_key=os.urandom(24)

def db(): c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
with db() as con:
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,expires DATE)")

def days_left(exp):
    try:
        return (datetime.strptime(exp,"%Y-%m-%d").date()-date.today()).days
    except: return 0

def active_rows():
    out=subprocess.getoutput(f"journalctl -u {ZIVPN_SVC} --since -15min -o cat").lower()
    today=date.today(); rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=(not expired) and (r["password"].lower() in out)
            rows.append(dict(id=r["id"],username=r["username"],password=r["password"],expires=r["expires"],
                             expired=expired,online=online,days=days_left(r["expires"])))
    return rows

def sync():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    cfg=json.load(open(ZIVPN_CFG))
    cfg["auth"]["config"]=pw; cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f: json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)
    subprocess.run(["systemctl","restart",ZIVPN_SVC])

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST" and request.form["u"]==ADMIN_USER and request.form["p"]==ADMIN_PASS:
        session["ok"]=True; return redirect("/")
    return render_template_string('''<html><head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-900 grid place-items-center h-screen text-white">
<div class="bg-slate-800 p-6 rounded-2xl w-[350px]"><h2 class="text-xl font-bold mb-3">🛡️ ZIVPN Login</h2>
<form method=post><input name=u placeholder=Username class="w-full mb-2 p-2 rounded bg-slate-700">
<input name=p type=password placeholder=Password class="w-full mb-3 p-2 rounded bg-slate-700">
<button class="bg-emerald-600 w-full py-2 rounded">Login</button></form></div></body></html>''')

def login_required(f):
    @wraps(f)
    def w(*a,**kw): return redirect("/login") if not session.get("ok") else f(*a,**kw)
    return w

@app.route("/")
@login_required
def home():
    rows=active_rows()
    tot=len(rows); on=sum(r["online"] for r in rows); off=sum((not r["online"]) and (not r["expired"]) for r in rows)
    default=(date.today()+timedelta(days=365)).isoformat()
    html='''<html><head><script src="https://cdn.tailwindcss.com"></script>
<script>function copy(t,b){navigator.clipboard.writeText(t);b.innerText='✓';setTimeout(()=>b.innerText='Copy',800)}</script>
</head><body class="bg-slate-100">
<a href="/logout" class="fixed bottom-4 right-4 bg-sky-600 text-white px-4 py-2 rounded-full">Logout</a>
<div class="max-w-6xl mx-auto p-4"><h2 class="text-2xl font-bold mb-4">🛡️ ZIVPN Admin Panel</h2>
<div class="grid sm:grid-cols-3 gap-3 mb-4">
<div class="bg-white p-3 rounded-xl shadow"><p>Total Users</p><h3 class="text-2xl font-bold">{{tot}}</h3></div>
<div class="bg-white p-3 rounded-xl shadow"><p>Total Online</p><h3 class="text-2xl font-bold text-emerald-600">{{on}}</h3></div>
<div class="bg-white p-3 rounded-xl shadow"><p>Total Offline</p><h3 class="text-2xl font-bold text-rose-600">{{off}}</h3></div>
</div>
<div class="grid md:grid-cols-[320px_1fr] gap-4">
<div class="bg-white p-4 rounded-xl shadow">
<form method=post action="/save" class="space-y-2"><input name=username placeholder="Username" class="w-full border p-2 rounded">
<input name=password placeholder="Password" class="w-full border p-2 rounded">
<input type=date name=expires value="{{default}}" class="w-full border p-2 rounded">
<button class="bg-emerald-600 text-white w-full py-2 rounded">💾 Save & Sync</button></form>
<p class="text-xs mt-2 text-slate-500">Script By: <b>JueHtet</b></p></div>
<div class="bg-white p-3 rounded-xl shadow overflow-x-auto"><table class="w-full text-sm">
<tr class="text-slate-600"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr>
{% for r in rows %}
<tr><td>{{r.username}}</td>
<td>{{r.password}} <button onclick="copy('{{r.password}}',this)" class="bg-slate-800 text-white px-2 rounded">Copy</button>
<span class="ml-2 text-xs px-2 py-0.5 rounded-full {% if r.days>=0 %}bg-emerald-100 text-emerald-700{% else %}bg-rose-100 text-rose-700{% endif %}">
သက်တော် {{r.days}} days</span></td>
<td>{{r.expires}}</td>
<td>{% if r.online %}🟢 Online{% elif r.expired %}⚠️ Expired{% else %}🔴 Offline{% endif %}</td>
<td><form method=post action="/del/{{r.id}}"><button class="bg-rose-600 text-white px-2 rounded">🗑️</button></form></td></tr>
{% endfor %}</table></div></div></div></body></html>'''
    return render_template_string(html,rows=rows,tot=tot,on=on,off=off,default=default)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"];p=request.form["password"];e=request.form["expires"]
    with db() as con:
        con.execute("INSERT INTO users(username,password,expires) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=?,expires=?",(u,p,e,p,e))
    sync();return redirect("/")

@app.route("/del/<int:id>",methods=["POST"])
@login_required
def delete(id):
    with db() as con: con.execute("DELETE FROM users WHERE id=?",(id,))
    sync();return redirect("/")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve; serve(app,host="0.0.0.0",port=8088)
PY

# --- Sync Script ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"

def actives():
    with sqlite3.connect(DB) as con:
        return [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")] or ["zi"]

cfg=json.load(open(CFG))
pw=actives(); cfg["auth"]["config"]=pw; cfg["config"]=pw
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
