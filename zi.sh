#!/bin/bash
# ------------------------------------------------------------
# ZIVPN UDP + Tailwind Web Panel + Multi-Login Auto-Expire
# Behavior:
#   • Multi-Login ဖြစ်တဲ့ password "တစ်ခုတည်း" ကို auto 0-day (expire)
#   • အဲဒီ password နဲ့ လာနေတဲ့ IP တွေကို 1 မိနစ်ပဲ block (ipset)
#   • ZIVPN service ကို reload/restart မလုပ်ပါ → တခြား users မထိ
#   • Admin Save & Sync ကလည်း service မrestart/reload (zero downtime)
# Author: JueHtet (tuned as requested)
# ------------------------------------------------------------

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

# -------------------- Packages --------------------
echo "==> Installing dependencies..."
apt-get update -y >/dev/null
apt-get install -y python3-venv python3-pip openssl ufw curl jq ipset wget >/dev/null

# -------------------- ZIVPN binary --------------------
echo "==> Installing ZIVPN binary..."
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

# -------------------- ZIVPN config --------------------
mkdir -p "${ZIVPN_DIR}"
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

# TLS cert
echo "==> Generating TLS certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

# -------------------- ZIVPN systemd --------------------
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

# -------------------- Networking helpers --------------------
echo "==> Setting NAT/Firewall..."
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667

ufw allow 5667/udp || true
ufw allow 8088/tcp || true

# -------------------- Admin Panel --------------------
echo "==> Setting up Web Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress >/dev/null

# Admin creds (can be edited later in ${ENV_FILE})
cat > "${ENV_FILE}" <<EOF
ADMIN_USER=admin
ADMIN_PASSWORD=change-me
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# app.py — minimal panel (Save & Sync does NOT restart/reload the service)
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile
from datetime import date
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)

ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
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

def write_cfg():
    # update config's password list from DB (no service reload/restart here)
    with db() as con:
        today = date.today().isoformat()
        pw = [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires >= ?", (today,))]
    if not pw: pw=["zi"]
    try:
        cfg=json.load(open(ZIVPN_CFG))
    except Exception:
        cfg={"listen":":5667","cert":"/etc/zivpn/zivpn.crt","key":"/etc/zivpn/zivpn.key","obfs":"zivpn"}
    cfg["auth"]={"mode":"passwords","config":pw}
    cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True; return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<!doctype html><form method=post>
      <input name=u placeholder=Username autofocus>
      <input name=p type=password placeholder=Password>
      <button>Login</button></form>''')

@app.route("/")
@login_required
def index():
    with db() as con:
        rows=con.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    t=date.today().isoformat()
    return render_template_string('''<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
    <h2>ZIVPN Panel</h2>
    <form method=post action="/save">
      <input name=username placeholder=Username required>
      <input name=password placeholder=Password required>
      <input type=date name=expires value="{{t}}" required>
      <button>💾 Save & Sync (no restart)</button>
    </form>
    <hr>
    <table border=1 cellpadding=6><tr><th>User</th><th>Password</th><th>Expires</th><th></th></tr>
    {% for r in rows %}
      <tr><td>{{r['username']}}</td><td>{{r['password']}}</td><td>{{r['expires']}}</td>
      <td><form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')"><button>🗑️</button></form></td></tr>
    {% endfor %}</table>''', t=t, rows=rows)

@app.route("/save", methods=["POST"])
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
    write_cfg()  # apply to config file only — NO restart/reload
    return redirect("/")

@app.route("/del/<int:uid>", methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    write_cfg()
    return redirect("/")

if __name__=="__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST","0.0.0.0"), port=int(os.getenv("BIND_PORT","8088")))
PY

# sync.py — only writes to config (never restarts/reloads)
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile
from datetime import date
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"

with sqlite3.connect(DB) as con:
    today=date.today().isoformat()
    pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires >= ?", (today,))]
if not pw: pw=["zi"]

try:
    cfg=json.load(open(CFG))
except Exception:
    cfg={"listen":":5667","cert":"/etc/zivpn/zivpn.crt","key":"/etc/zivpn/zivpn.key","obfs":"zivpn"}

cfg["auth"]={"mode":"passwords","config":pw}
cfg["config"]=pw

with tempfile.NamedTemporaryFile("w",delete=False) as f:
    json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
print("Config updated (no restart).")
PY

# ml_guard.py — Multi-Login → expire that password + 1-minute IP block, NO reload/restart
cat > "${GUARD_PY}" <<'PY'
import os, re, sqlite3, subprocess
from datetime import date, timedelta
from subprocess import DEVNULL

DB="/var/lib/zivpn-admin/zivpn.db"
SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")  # service name for logs

def sh(cmd): subprocess.run(cmd, check=False, stdout=DEVNULL, stderr=DEVNULL)

def ensure_ipset():
    # create 1-minute timeout block set and attach to INPUT udp/5667
    sh(["ipset","create","zivpn_block","hash:ip","timeout","60","-exist"])
    chk=subprocess.run(
        ["iptables","-C","INPUT","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"],
        stdout=DEVNULL, stderr=DEVNULL
    )
    if chk.returncode!=0:
        sh(["iptables","-I","INPUT","1","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"])

def recent_log():
    try:
        return subprocess.check_output(["journalctl","-u",SVC,"--since","-2min","-o","cat"]).decode(errors="ignore").lower()
    except Exception:
        return ""

PW_RE = re.compile(r'password[=\s:]+([a-z0-9]+)')
IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

def extract_pairs(text):
    pairs=[]
    for line in text.splitlines():
        pw = PW_RE.search(line); ip = IP_RE.search(line)
        if pw and ip:
            pairs.append((pw.group(1), ip.group(1)))
    return pairs

def expire_only(password):
    # set yesterday (0-day) only if currently active
    with sqlite3.connect(DB) as con:
        today=date.today().isoformat()
        ok=con.execute("SELECT 1 FROM users WHERE password=? AND expires>=?",(password,today)).fetchone()
        if not ok: return False
        y=(date.today()-timedelta(days=1)).isoformat()
        con.execute("UPDATE users SET expires=? WHERE password=?", (y,password))
    return True

def main():
    ensure_ipset()
    pairs = extract_pairs(recent_log())
    if not pairs: 
        print("guard: no activity"); return
    from collections import defaultdict
    bypw=defaultdict(set)
    for pw,ip in pairs: bypw[pw].add(ip)

    acted=False
    for pw,ips in bypw.items():
        if len(ips) <= 1:
            continue  # not multi-login
        changed = expire_only(pw)  # mark only this password as 0-day
        for ip in ips:
            sh(["ipset","add","zivpn_block", ip, "timeout", "60", "-exist"])
        if changed or ips:
            acted=True
            print(f"guard: expired PW={pw}, blocked IPs={','.join(ips)} 60s")

    if not acted:
        print("guard: nothing to do")

if __name__=="__main__":
    main()
PY

# -------------------- systemd units --------------------
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel (no-restart sync)
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
Description=ZIVPN Multi-Login Guard (expire 0-day + 1min IP block, no reload)
After=network.target

[Service]
Environment=ZIVPN_SERVICE=${ZIVPN_SVC}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${GUARD_PY}
EOF

cat >/etc/systemd/system/${GUARD_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN Multi-Login Guard every 1 minute

[Timer]
OnUnitActiveSec=60
OnBootSec=30
AccuracySec=15s
Persistent=true

[Install]
WantedBy=timers.target
EOF

# -------------------- finalize --------------------
systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${GUARD_TIMER}

# initial ipset hook (ensure chain exists now)
python3 - <<'PY'
import subprocess,sys
subprocess.run(["ipset","create","zivpn_block","hash:ip","timeout","60","-exist"], check=False)
probe=subprocess.run(["iptables","-C","INPUT","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"])
if probe.returncode!=0:
    subprocess.run(["iptables","-I","INPUT","1","-m","set","--match-set","zivpn_block","src","-p","udp","--dport","5667","-j","DROP"], check=False)
PY

# Show info
IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "Panel: http://${IP}:8088  (login: admin / change-me)"
echo "Multi-Login: offending password => auto 0-day; its IPs blocked 60s; NO service restart/reload."
echo "Check blocks: ipset list zivpn_block   | Unblock all: ipset flush zivpn_block"
