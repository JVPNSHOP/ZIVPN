cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel (Reload-only + Smooth)
# - Save = config write only
# - Apply = reload only (no restart)
# - UDP stability tuned
# Script By: JueHtet | Patch by helper

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

echo "==> Update & deps..."
apt-get update -y && apt-get install -y python3-venv python3-pip openssl ufw curl jq conntrack irqbalance > /dev/null

echo "==> Install ZIVPN..."
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

echo "==> TLS cert..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

# systemd (reload-capable)
cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
User=root
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

# NAT/Firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
# remove old DNAT if any
iptables -t nat -S PREROUTING | awk '/--dport 6000:19999/ {print $0}' | sed 's/^-A /-D /' | while read -r r; do iptables -t nat $r || true; done
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

# Smooth sysctl
cat >/etc/sysctl.d/98-zivpn-smooth.conf <<'SYS'
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.ipv4.udp_rmem_min=131072
net.ipv4.udp_wmem_min=131072
net.core.netdev_max_backlog=250000
net.core.default_qdisc=fq
net.netfilter.nf_conntrack_max=524288
net.netfilter.nf_conntrack_udp_timeout=300
net.netfilter.nf_conntrack_udp_timeout_stream=1800
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.ip_local_port_range=10000 65000
SYS
sysctl --system >/dev/null

# irqbalance + RPS
systemctl enable --now irqbalance
for f in /sys/class/net/*/queues/rx-*/rps_cpus; do echo ffffffff > "$f" 2>/dev/null || true; done

echo "==> Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress > /dev/null

read -rp "Admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Admin password [change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# ---------------- app.py (Save=write only, Apply=reload only) ----------------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time
from subprocess import DEVNULL
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

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        expires DATE
    )""")

def logs():
    try: return subprocess.check_output(["journalctl","-u",ZIVPN_SVC,"--since","-15min","-o","cat"]).decode().lower()
    except Exception: return ""

def days_left(s):
    try: return (datetime.strptime(s,"%Y-%m-%d").date()-date.today()).days
    except: return None

def rows_now():
    log=logs(); today=date.today(); out=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            out.append({"id":r["id"],"username":r["username"],"password":r["password"],
                        "expires":r["expires"],"expired":exp<today,
                        "online": (exp>=today and r["password"].lower() in log),
                        "days_left": days_left(r["expires"])})
    return out

def write_cfg(pw):
    cfg={}
    try: cfg=json.load(open(ZIVPN_CFG))
    except Exception: pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw; cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)

def sync_only():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    write_cfg(pw or ["zi"])

def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**k)
    return w

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True; return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen grid place-items-center bg-slate-900 text-white">
<div class="w-[360px] bg-slate-800/70 p-6 rounded-2xl">
  <div class="flex items-center gap-2 mb-3">
    <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" class="h-8 w-8"><h2 class="text-xl font-bold">ZIVPN Login</h2>
  </div>
  <form method=post class="space-y-3">
    <input name=u class="w-full p-2 rounded bg-slate-700/80" placeholder="👤 Username">
    <input name=p type=password class="w-full p-2 rounded bg-slate-700/80" placeholder="🔒 Password">
    <button class="w-full bg-emerald-600 py-2 rounded-xl">Login</button>
  </form>
</div></body></html>''')

@app.route("/")
@login_required
def index():
    data=rows_now()
    total=len(data); online=sum(1 for r in data if not r["expired"]); offline=sum(1 for r in data if r["expired"])
    try: vps_ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception: vps_ip=request.host.split(":")[0]
    server_ts=int(time.time())
    return render_template_string('''<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script>
<script>
const S={{server_ts}}*1000;let st=Date.now();
function z(n){return n.toString().padStart(2,'0')}
function tick(){const d=new Date(S+(Date.now()-st));
document.getElementById('server-time').textContent=d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate())+" "+z(d.getHours())+":"+z(d.getMinutes())+":"+z(d.getSeconds());}
setInterval(tick,1000);window.addEventListener('load',tick);
function copyText(t,b){function ok(){if(b){b.innerText='✓';b.disabled=true;setTimeout(()=>{b.innerText='Copy';b.disabled=false;},800)}}; if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok);}else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();ok();}}
function fillForm(u,p,e){const f=document.querySelector('form[action="/save"]');f.username.value=u;f.password.value=p;f.expires.value=e;f.scrollIntoView({behavior:'smooth'});}
function closeNotice(id){const el=document.getElementById(id); if(el) el.remove();}
</script>
<style>.tiny{font-size:12px;line-height:1.1}.code{font-family:ui-monospace,Menlo,monospace}</style>
</head><body class="bg-slate-50">

<div class="fixed top-3 right-3 flex gap-2">
  <a href="https://t.me/Pussy1990" target="_blank" class="bg-sky-600 text-white rounded-full w-9 h-9 grid place-items-center">TG</a>
  <a href="/logout" class="bg-slate-700 text-white rounded-full w-9 h-9 grid place-items-center">⎋</a>
</div>

<header class="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center gap-2">
    <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" class="h-8 w-8"><h1 class="text-2xl font-extrabold">ZIVPN</h1>
  </div>
</header>

<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">
  <section class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
    <div class="grid sm:grid-cols-2 gap-2 text-sm">
      <div>VPS IP: <b>{{vps_ip}}</b></div>
      <div>Server Time: <b id="server-time">--</b></div>
    </div>
  </section>

  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}{% for cat, msg in msgs %}
  <div id="notice-{{loop.index}}" class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-2xl p-3">
    <div class="flex items-start justify-between">
      <div class="text-sm font-medium whitespace-pre-wrap">Create Account Done ✅
{{ msg }}</div>
      <button class="px-2 py-0.5 bg-emerald-600 text-white rounded text-[11px]" onclick="closeNotice('notice-{{loop.index}}')">OK</button>
    </div>
    <div class="mt-1 text-[11px] text-emerald-800/80">1 User For 1 Device</div>
  </div>
  {% endfor %}{% endif %}{% endwith %}

  <section class="grid grid-cols-1 sm:grid-cols-3 gap-3">
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Users</div><div class="mt-1 text-2xl font-bold">{{total}}</div></div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Online</div><div class="mt-1 text-2xl font-bold text-emerald-600">{{online}}</div></div>
    {% if offline>0 %}<div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Offline</div><div class="mt-1 text-2xl font-bold text-rose-600">{{offline}}</div></div>{% endif %}
  </section>

  <section class="flex gap-2">
    <form method="post" action="/apply"><button class="bg-slate-800 hover:bg-slate-700 text-white rounded-xl px-3 py-2 text-sm">⚙️ Apply Config (Reload only)</button></form>
  </section>

  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm">Add / Update User</h3>
      <form method=post action="/save" class="space-y-2">
        <input name=username placeholder="👤 Username" class="w-full border rounded-lg p-2 text-sm">
        <input name=password placeholder="🔒 Password" class="w-full border rounded-lg p-2 text-sm">
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{date.today().isoformat()}}" class="w-full border rounded-lg p-2 text-sm">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save & Sync</button>
      </form>
      <p class="mt-2 text-[11px] text-slate-500">Script By: <b>JueHtet</b></p>
    </div>

    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200 overflow-x-auto">
      <table class="w-full text-left align-middle">
        <thead><tr class="text-slate-600 text-[12px]"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr></thead>
        <tbody class="tiny">
        {% for r in data %}
          <tr class="border-t">
            <td>{{r['username']}}</td>
            <td><span class="code px-1.5 py-0.5 bg-slate-100 rounded">{{r['password']}}</span> <button onclick="copyText('{{r['password']}}',this)" class="px-2 py-0.5 bg-slate-800 text-white rounded text-[11px]">Copy</button> {% if r['days_left'] is not none %}{% if r['days_left']>=0 %}<span class="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-[11px]">{{r['days_left']}} days</span>{% else %}<span class="px-2 py-0.5 bg-rose-100 text-rose-700 rounded-full text-[11px]">Expired {{-r['days_left']}} days</span>{% endif %}{% endif %}</td>
            <td class="text-slate-600">{{r['expires']}}</td>
            <td>{% if not r['expired'] %}<span class="text-emerald-700">● Online</span>{% else %}<span class="text-slate-600">● Offline</span>{% endif %}</td>
            <td><div class="flex gap-1.5"><button type="button" onclick="fillForm('{{r['username']}}','{{r['password']}}','{{r['expires']}}')" class="px-2 py-0.5 bg-amber-500 text-white rounded text-[11px]">Edit</button><form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')"><button class="px-2 py-0.5 bg-rose-600 text-white rounded text-[11px]">🗑️</button></form></div></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </section>
</main>
</body></html>''', data=data, total=total, online=online, offline=offline, vps_ip=vps_ip, server_ts=server_ts)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"].strip(); p=request.form["password"].strip(); e=request.form["expires"].strip()
    if not u or not p or not e: flash("Please fill all fields"); return redirect("/")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
                       VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",(u,p,e,p,e))
    try: ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception: ip=request.host.split(":")[0]
    flash(f"IP : {ip}\nUsers : {u}\nPassword : {p}\nExpired Date : {e}\n1 User For 1 Device","ok")
    # write-only (no reload here)
    with db() as con:
        pass
    # keep config synced (write only)
    sync_only()
    return redirect("/")

@app.route("/apply",methods=["POST"])
@login_required
def apply():
    # RELOAD ONLY (never restart)
    try:
        subprocess.call(["systemctl","reload",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)
        flash("Applied with RELOAD only (no restart). If daemon ignores HUP, changes apply after next manual restart.","ok")
    except Exception:
        flash("Reload attempt failed (no restart).","err")
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync_only(); return redirect("/")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app,host=os.getenv("BIND_HOST","0.0.0.0"),port=int(os.getenv("BIND_PORT","8088")))
PY

chmod +x "${APP_PY}"

# service
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

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE (Reload-only + Smooth)"
echo "======================================"
echo "📊 Web Panel: http://${IP}:8088/login"
echo "👤 Admin Username: ${ADMIN_USER}"
echo "🔑 Admin Password: ${ADMIN_PASSWORD}"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
