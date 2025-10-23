#!/bin/bash
# ZIVPN UDP + Tailwind Panel + Multi-Login Auto-Expire (1min IP block)
# - Fixes "wrong password" by reloading service on Save & Sync (no restart)
# - Multi-login: expire only that password + ipset block 60s, no reload/restart
# Script By: JueHtet (tuned)

set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
GUARD_PY="${ADMIN_DIR}/ml_guard.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"

PANEL_SVC="zivpn-admin.service"
GUARD_SVC="zivpn-ml-guard.service"
GUARD_TIMER="zivpn-ml-guard.timer"

echo "==> Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -o Acquire::Retries=3 -o Acquire::http::Timeout=10 >/dev/null
apt-get install -y --no-install-recommends python3-venv python3-pip openssl ufw curl jq ipset wget >/dev/null

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

# NAT helper & firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

echo "==> Setting up Web Admin Panel..."
mkdir -p "${ADMIN_DIR}" /var/lib/zivpn-admin
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress >/dev/null

# Default admin env (you can edit later at ${ENV_FILE})
cat > "${ENV_FILE}" <<EOF
ADMIN_USER=admin
ADMIN_PASSWORD=change-me
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# ---------------- app.py ----------------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time, re
from subprocess import DEVNULL
from datetime import date, datetime, timedelta
from flask import Flask, request, redirect, url_for, session, render_template_string, flash, jsonify
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","change-me")
app=Flask(__name__)
app.secret_key=os.urandom(24)

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        expires DATE
    )""")

def write_cfg_and_reload():
    # write active passwords to config and RELOAD (no restart) to fix "wrong password"
    with db() as con:
        today = date.today().isoformat()
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires >= ?", (today,))]
    if not pw: pw=["zi"]
    try: cfg=json.load(open(ZIVPN_CFG))
    except Exception: cfg={}
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw
    cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)
    # reload only (seamless)
    try:
        subprocess.run(["systemctl","reload",ZIVPN_SVC], check=False, stdout=DEVNULL, stderr=DEVNULL)
    except Exception:
        pass

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True;return redirect("/")
        flash("Invalid credentials")
    return render_template_string('<form method=post><input name=u placeholder=Username autofocus><input name=p type=password placeholder=Password><button>Login</button></form>')

@app.route("/")
@login_required
def index():
    with db() as con:
        rows=con.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return render_template_string('''<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
    <h2>ZIVPN Panel</h2>
    <form method=post action="/save">
      <input name=username placeholder=Username required>
      <input name=password placeholder=Password required>
      <input type=date name=expires value="{{today}}" required>
      <button>💾 Save & Sync</button>
    </form>
    <hr>
    <table border=1 cellpadding=6><tr><th>User</th><th>Password</th><th>Expires</th><th>Actions</th></tr>
    {% for r in rows %}
      <tr><td>{{r['username']}}</td><td>{{r['password']}}</td><td>{{r['expires']}}</td>
      <td><form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete?')"><button>🗑️</button></form>
      <button onclick="fetch('/expire-multi-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:'{{r['password']}}'})}).then(()=>location.reload())">Expire</button></td></tr>
    {% endfor %}</table>''', today=date.today().isoformat(), rows=rows)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"].strip()
    p=request.form["password"].strip()
    e=request.form["expires"].strip()
    if not u or not p or not e:
        flash("Please fill all fields"); return redirect("/")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
                       VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",(u,p,e,p,e))
    write_cfg_and_reload()  # apply immediately without restart
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    write_cfg_and_reload()
    return redirect("/")

@app.route("/expire-multi-login", methods=["POST"])
@login_required
def expire_multi_login():
    data = request.get_json(force=True)
    password = (data.get('password') or "").strip()
    if not password:
        return jsonify({'success': False, 'error': 'No password provided'})
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    with db() as con:
        con.execute("UPDATE users SET expires=? WHERE password=?", (yesterday, password))
    # do NOT reload/restart here; ml_guard handles blocking
    return jsonify({'success': True})
PY

# ---------------- sync.py (supports --reload/--restart) ----------------
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess, sys
from subprocess import DEVNULL
from datetime import date

DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")

mode="--reload"
if "--restart" in sys.argv: mode="--restart"

with sqlite3.connect(DB) as con:
    today=date.today().isoformat()
    pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires >= ?", (today,))]
if not pw: pw=["zi"]

try: cfg=json.load(open(CFG))
except Exception: cfg={}
cfg["auth"]={"mode":"passwords","config":pw}
cfg["config"]=pw

with tempfile.NamedTemporaryFile("w",delete=False) as f:
    json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
print("Config updated.")

try:
    if mode=="--restart":
        subprocess.run(["systemctl","restart",SVC], check=True, stdout=DEVNULL, stderr=DEVNULL)
        print("Service restarted (initial only).")
    else:
        subprocess.run(["systemctl","reload",SVC], check=False, stdout=DEVNULL, stderr=DEVNULL)
        print("Service reloaded.")
except Exception as e:
    print("Apply warning:", e)
PY

# ---------------- ml_guard.py (0-day + 60s IP block, no reload) ----------------
cat > "${GUARD_PY}" <<'PY'
import os, re, sqlite3, subprocess
from datetime import date, timedelta
from subprocess import DEVNULL

DB="/var/lib/zivpn-admin/zivpn.db"
SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")

def sh(cmd): subprocess.run(cmd, check=False, stdout=DEVNULL, stderr=DEVNULL)

def ensure_ipset():
    sh(["ipset","create","zivpn_block","hash:ip","timeout","60","-exist"])
    chk=subprocess.run(["iptables","-C","INPUT","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"], stdout=DEVNULL, stderr=DEVNULL)
    if chk.returncode!=0:
        sh(["iptables","-I","INPUT","1","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"])

def recent_logs():
    try:
        return subprocess.check_output(["journalctl","-u",SVC,"--since","-2min","-o","cat"]).decode(errors="ignore").lower()
    except Exception:
        return ""

PW=re.compile(r'password[=\s:]+([a-z0-9]+)')
IP=re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

def parse_pairs(txt):
    pairs=[]
    for ln in txt.splitlines():
        pw=PW.search(ln); ip=IP.search(ln)
        if pw and ip: pairs.append((pw.group(1), ip.group(1)))
    return pairs

def expire_pw(pw):
    with sqlite3.connect(DB) as con:
        today=date.today().isoformat()
        if not con.execute("SELECT 1 FROM users WHERE password=? AND expires>=?",(pw,today)).fetchone():
            return False
        y=(date.today()-timedelta(days=1)).isoformat()
        con.execute("UPDATE users SET expires=? WHERE password=?", (y,pw))
    return True

def main():
    ensure_ipset()
    pairs=parse_pairs(recent_logs())
    if not pairs: return
    from collections import defaultdict
    bypw=defaultdict(set)
    for pw,ip in pairs: bypw[pw].add(ip)
    for pw,ips in bypw.items():
        if len(ips)<=1: continue  # not multi-login
        changed=expire_pw(pw)    # only that password -> 0-day
        for ip in ips:           # and block those IPs 60s
            sh(["ipset","add","zivpn_block", ip, "timeout","60","-exist"])
        if changed:
            print(f"ml-guard: expired {pw}; blocked {', '.join(ips)} for 60s")

if __name__=="__main__":
    main()
PY

# ---------------- systemd units ----------------
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

cat >/etc/systemd/system/${GUARD_SVC} <<EOF
[Unit]
Description=ZIVPN Multi-Login Guard (0-day + 60s IP block)
After=network.target
[Service]
Environment=ZIVPN_SERVICE=${ZIVPN_SVC}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${GUARD_PY}
EOF

cat >/etc/systemd/system/${GUARD_TIMER} <<'EOF'
[Unit]
Description=Run Multi-Login guard every 1 minute
[Timer]
OnUnitActiveSec=60
OnBootSec=30
Persistent=true
[Install]
WantedBy=timers.target
EOF

# ---------------- enable ----------------
systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${GUARD_TIMER}

# initial sync: ensure first passwords load (safe to restart once now)
echo "==> Initial sync..."
${VENV}/bin/python ${SYNC_PY} --restart

# ensure ipset rule exists now
ipset create zivpn_block hash:ip timeout 60 -exist
iptables -C INPUT -m set --match-set zivpn_block src -p udp --dport 5667 -j DROP 2>/dev/null || \
iptables -I INPUT 1 -m set --match-set zivpn_block src -p udp --dport 5667 -j DROP

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "Panel: http://${IP}:8088/login (admin / change-me)"
echo "— Save & Sync => reload only (no disconnect), fixes wrong-password."
echo "— Multi-Login => only that password 0-day + IPs blocked 60s (no reload)."
echo "Check blocks: ipset list zivpn_block | Unblock all: ipset flush zivpn_block"
