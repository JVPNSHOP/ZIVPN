cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Admin Panel (Multi-Instance + LB = many devices per password, no drops)
# - Same password => many devices OK (sharded across instances)
# - One public port (5667) -> iptables random DNAT to backend ports
# - Rolling restarts; panel low-latency; hash-compare on auth list
# By: JueHtet (tuned)

set -euo pipefail

INSTANCES="${INSTANCES:-4}"         # << increase if needed
BASE_PORT="${BASE_PORT:-5667}"      # public port clients use
START_PORT="${START_PORT:-5667}"    # first backend port for instance 1

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_BASE_CFG="${ZIVPN_DIR}/config.base.json"
ZIVPN_SVC_TMPL="zivpn@.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"

STATE_DIR="/var/lib/zivpn-admin"
mkdir -p "$STATE_DIR" "$ZIVPN_DIR"

echo "==> Update & deps"
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip openssl ufw curl jq > /dev/null

echo "==> ZIVPN binary"
systemctl stop "zivpn.service" 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

echo "==> TLS cert"
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

echo "==> Base config"
cat > "${ZIVPN_BASE_CFG}" <<JSON
{
  "listen": ":${START_PORT}",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Systemd template (multi-instance)"
cat >/etc/systemd/system/${ZIVPN_SVC_TMPL} <<'EOF'
[Unit]
Description=ZIVPN UDP Server Instance %i
After=network.target

[Service]
# Instance-specific config path: /etc/zivpn/config-%i.json
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config-%i.json
Restart=always
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "==> Prepare per-instance configs"
for i in $(seq 1 "${INSTANCES}"); do
  PORT=$((START_PORT + i - 1))
  CFG="${ZIVPN_DIR}/config-${i}.json"
  jq ".listen=\":${PORT}\"" "${ZIVPN_BASE_CFG}" > "${CFG}"
done

echo "==> Enable instances"
for i in $(seq 1 "${INSTANCES}"); do
  systemctl enable --now "zivpn@${i}.service"
done

echo "==> Firewall & UDP Load Balancing"
# flush our old rules (safe best-effort)
iptables -t nat -D PREROUTING -p udp --dport ${BASE_PORT} -j DNAT --to-destination :${START_PORT} 2>/dev/null || true
# Randomly spread incoming :BASE_PORT to backend :START_PORT..START_PORT+INSTANCES-1
# Chain for manageability
iptables -t nat -N ZIVPN_LB 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp --dport ${BASE_PORT} -j ZIVPN_LB 2>/dev/null || true
iptables -t nat -A PREROUTING -p udp --dport ${BASE_PORT} -j ZIVPN_LB

# wipe previous content
iptables -t nat -F ZIVPN_LB
for i in $(seq 1 "${INSTANCES}"); do
  PORT=$((START_PORT + i - 1))
  # cascade random matching; last rule is catch-all
  if [ "$i" -lt "${INSTANCES}" ]; then
    iptables -t nat -A ZIVPN_LB -m statistic --mode random --probability "$(awk -v n=${INSTANCES} 'BEGIN{printf("%.6f",1.0/(n+0))}')" -j DNAT --to-destination :${PORT}
  else
    iptables -t nat -A ZIVPN_LB -j DNAT --to-destination :${PORT}
  fi
done

ufw allow ${BASE_PORT}/udp || true
ufw allow 8088/tcp || true

echo "==> Admin panel"
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
STATE_DIR=${STATE_DIR}
ZIVPN_DIR=${ZIVPN_DIR}
INSTANCES=${INSTANCES}
START_PORT=${START_PORT}
BASE_PORT=${BASE_PORT}
EOF

# ---- Flask app (low-latency + rolling restart + unique passwords) ----
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time, hashlib
from subprocess import DEVNULL
from datetime import date, datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps

STATE_DIR=os.getenv("STATE_DIR","/var/lib/zivpn-admin")
DB=os.path.join(STATE_DIR,"zivpn.db")
ZIVPN_DIR=os.getenv("ZIVPN_DIR","/etc/zivpn")
INSTANCES=int(os.getenv("INSTANCES","4"))
START_PORT=int(os.getenv("START_PORT","5667"))
BASE_PORT=int(os.getenv("BASE_PORT","5667"))
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

def days_left(expires_str):
    try:
        exp=datetime.strptime(expires_str,"%Y-%m-%d").date()
        return (exp - date.today()).days
    except Exception:
        return None

def active_rows():
    today=date.today()
    rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            rows.append({
                "id":r["id"],"username":r["username"],"password":r["password"],
                "expires":r["expires"],"expired":exp<today,"online": exp>=today,
                "days_left": days_left(r["expires"])
            })
    return rows

def uniq_passwords():
    with db() as con:
        # keep config clean (multi-device still OK)
        pws=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pws or ["zi"]

def write_cfgs(pws):
    # write identical config to all instances, only listen port differs
    for i in range(1, INSTANCES+1):
        port = START_PORT + i - 1
        cfg_path=os.path.join(ZIVPN_DIR, f"config-{i}.json")
        cfg={"listen": f":{port}",
             "cert": f"{ZIVPN_DIR}/zivpn.crt",
             "key": f"{ZIVPN_DIR}/zivpn.key",
             "obfs": "zivpn",
             "auth": {"mode":"passwords","config": pws},
             "config": pws}
        with tempfile.NamedTemporaryFile("w",delete=False) as f:
            json.dump(cfg,f,indent=2); tmp=f.name
        os.replace(tmp,cfg_path)

def set_hash(pws):
    h=hashlib.sha256("\n".join(pws).encode()).hexdigest()
    open(os.path.join(STATE_DIR,"auth.sha256"),"w").write(h)
    return h

def need_change(pws):
    h=hashlib.sha256("\n".join(pws).encode()).hexdigest()
    p=os.path.join(STATE_DIR,"auth.sha256")
    if os.path.exists(p) and open(p).read().strip()==h:
        return False
    return True

def rolling_bounce():
    # try reload, then restart instance by instance (reduce drops)
    for i in range(1, INSTANCES+1):
        # reload (best-effort)
        subprocess.Popen(["systemctl","reload",f"zivpn@{i}.service"], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(1)
    for i in range(1, INSTANCES+1):
        subprocess.Popen(["systemctl","restart",f"zivpn@{i}.service"], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(0.5)

def sync():
    pws=uniq_passwords()
    write_cfgs(pws)
    if need_change(pws):
        set_hash(pws)
        rolling_bounce()

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
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen grid place-items-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
<div class="w-[360px] bg-slate-800/70 backdrop-blur p-6 rounded-2xl shadow-2xl ring-1 ring-white/10">
  <h2 class="text-xl font-bold mb-3">ZIVPN Login</h2>
  <form method=post class="space-y-3">
    <input name=u class="w-full p-2 rounded bg-slate-700/80 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Username">
    <input name=p type=password class="w-full p-2 rounded bg-slate-700/80 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Password">
    <button class="w-full bg-emerald-600 hover:bg-emerald-500 transition py-2 rounded-xl shadow">Login</button>
  </form>
</div></body></html>''')

@app.route("/")
@login_required
def index():
    rows=active_rows()
    total_users=len(rows)
    total_online=sum(1 for r in rows if not r["expired"])
    total_offline=sum(1 for r in rows if r["expired"])
    default_exp=date.today().isoformat()
    try:
        vps_ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        vps_ip=request.host.split(":")[0]
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-50">
<header class="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
    <h1 class="text-2xl font-extrabold">ZIVPN</h1>
    <div class="text-sm">Public Port: <b>{{ base_port }}</b></div>
  </div>
</header>
<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">
  <section class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200 text-sm">
    VPS IP: <b>{{ vps_ip }}</b> • Instances: <b>{{ instances }}</b> ({{ start_port }}..{{ start_port+instances-1 }})
  </section>
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    {% for cat, msg in msgs %}
      <div class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-2xl p-3 text-sm whitespace-pre-wrap">{{ msg }}</div>
    {% endfor %}
  {% endif %}
  {% endwith %}
  <section class="grid grid-cols-1 sm:grid-cols-3 gap-3">
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Users</div><div class="mt-1 text-2xl font-bold text-slate-900">{{total_users}}</div></div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Online</div><div class="mt-1 text-2xl font-bold text-emerald-600">{{total_online}}</div></div>
    {% if total_offline > 0 %}
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Offline</div><div class="mt-1 text-2xl font-bold text-rose-600">{{total_offline}}</div></div>
    {% endif %}
  </section>
  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm">Add / Update User</h3>
      <form method=post action="/save" class="space-y-2">
        <input name=username placeholder="Username" class="w-full border rounded-lg p-2 text-sm">
        <input name=password placeholder="Password" class="w-full border rounded-lg p-2 text-sm">
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save & Sync</button>
      </form>
    </div>
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200 overflow-x-auto">
      <table class="w-full text-left align-middle">
        <thead><tr class="text-slate-600 text-[12px]"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr></thead>
        <tbody class="text-[12px]">
          {% for r in rows %}
          <tr class="border-t">
            <td class="py-1">{{r['username']}}</td>
            <td class="py-1"><code class="px-1.5 py-0.5 bg-slate-100 rounded">{{r['password']}}</code></td>
            <td class="py-1 text-slate-600">{{r['expires']}}</td>
            <td class="py-1">{% if not r['expired'] %}<span class="text-emerald-700">Online</span>{% else %}<span class="text-slate-600">Offline</span>{% endif %}</td>
            <td class="py-1">
              <form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
                <button class="px-2 py-0.5 bg-rose-600 text-white rounded text-[11px]">🗑️</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </section>
</main>
</body></html>''',
        rows=rows, total_users=total_users, total_online=total_online, total_offline=total_offline,
        default_exp=default_exp, vps_ip=vps_ip, instances=INSTANCES, start_port=START_PORT, base_port=BASE_PORT)

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
    sync()
    flash(f"VIP OK • Public Port: {BASE_PORT}\nUser: {u}\nPassword: {p}\nExpire: {e}")
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync();return redirect("/")

def main():
    from waitress import serve
    serve(app,host="0.0.0.0",port=int(os.getenv("BIND_PORT","8088")), threads=16)

if __name__=="__main__":
    main()
PY

# --- Sync helper (rebuild configs + rolling restart) ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess, hashlib, time
from subprocess import DEVNULL

STATE=os.getenv("STATE_DIR","/var/lib/zivpn-admin")
DB=os.path.join(STATE,"zivpn.db")
ZIVPN_DIR=os.getenv("ZIVPN_DIR","/etc/zivpn")
INSTANCES=int(os.getenv("INSTANCES","4"))
START_PORT=int(os.getenv("START_PORT","5667"))

LAST_HASH=os.path.join(STATE,"auth.sha256")

def uniq_passwords():
    with sqlite3.connect(DB) as con:
        pws=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pws or ["zi"]

def write_cfgs(pws):
    for i in range(1, INSTANCES+1):
        port = START_PORT + i - 1
        path=os.path.join(ZIVPN_DIR, f"config-{i}.json")
        cfg={"listen": f":{port}",
             "cert": f"{ZIVPN_DIR}/zivpn.crt",
             "key": f"{ZIVPN_DIR}/zivpn.key",
             "obfs": "zivpn",
             "auth": {"mode":"passwords","config": pws},
             "config": pws}
        with tempfile.NamedTemporaryFile("w",delete=False) as f:
            json.dump(cfg,f,indent=2); tmp=f.name
        os.replace(tmp,path)

def need_change(pws):
    h=hashlib.sha256("\n".join(pws).encode()).hexdigest()
    if os.path.exists(LAST_HASH) and open(LAST_HASH).read().strip()==h:
        return False
    open(LAST_HASH,"w").write(h)
    return True

pws=uniq_passwords()
write_cfgs(pws)
if need_change(pws):
    # rolling reload + restart
    for i in range(1, INSTANCES+1):
        subprocess.Popen(["systemctl","reload",f"zivpn@{i}.service"], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(1)
    for i in range(1, INSTANCES+1):
        subprocess.Popen(["systemctl","restart",f"zivpn@{i}.service"], stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(0.5)
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

# Panel service
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel
After=network.target

[Service]
EnvironmentFile=${ENV_FILE}
Environment=STATE_DIR=${STATE_DIR}
Environment=ZIVPN_DIR=${ZIVPN_DIR}
Environment=INSTANCES=${INSTANCES}
Environment=START_PORT=${START_PORT}
Environment=BASE_PORT=${BASE_PORT}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "Public Port (clients use): ${BASE_PORT}/udp"
echo "Open Panel: http://${IP}:8088/login"
echo "Instances running: ${INSTANCES} (ports ${START_PORT}..$((START_PORT+INSTANCES-1)))"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
