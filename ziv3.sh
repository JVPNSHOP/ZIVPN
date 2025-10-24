cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel (Hardened Smooth Edition)
# - Save = config.json write only (no reload/restart)
# - Apply = reload only (never restart)
# - UDP stability: conntrack timeouts ++, DNAT->REDIRECT, DSCP mark, fq qdisc, irqbalance/RPS, keepalive cron
# Script By: JueHtet | Smooth Pack by: helper

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
apt-get install -y python3-venv python3-pip openssl ufw curl jq conntrack irqbalance tcpdump > /dev/null

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

# --- systemd unit (reload-capable; never auto-restart from panel) ---
cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
ExecReload=/bin/kill -HUP $MAINPID
# Smooth Pack: scheduling/limits
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=2
LimitNOFILE=1048576
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

# --- UDP stability: conntrack timeouts & buffers ---
echo "==> Tuning sysctl for UDP/NAT..."
cat > /etc/sysctl.d/98-zivpn-smooth.conf <<'SYS'
# buffers
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.ipv4.udp_rmem_min=131072
net.ipv4.udp_wmem_min=131072
# backlog & qdisc
net.core.netdev_max_backlog=250000
net.core.default_qdisc=fq
# conntrack capacity + UDP timeouts
net.netfilter.nf_conntrack_max=524288
net.netfilter.nf_conntrack_udp_timeout=300
net.netfilter.nf_conntrack_udp_timeout_stream=1800
# routing sanity
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
# ephemeral ports
net.ipv4.ip_local_port_range=10000 65000
SYS
sysctl --system > /dev/null

# --- NAT: REDIRECT local 5667 (more stable than DNAT for local daemon) ---
echo "==> Applying iptables REDIRECT rule..."
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
# remove any previous 6000:19999 rules then add idempotently
iptables -t nat -S PREROUTING | awk '/--dport 6000:19999/ {print $0}' | sed 's/^-A /-D /' | while read -r r; do iptables -t nat $r || true; done
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null \
  || iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667

# --- QoS: DSCP EF for UDP/5667 (if routers respect) ---
echo "==> Marking DSCP EF on UDP/5667..."
iptables -t mangle -C PREROUTING -p udp --dport 5667 -j DSCP --set-dscp 46 2>/dev/null \
  || iptables -t mangle -A PREROUTING -p udp --dport 5667 -j DSCP --set-dscp 46

# --- firewall ---
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

# --- irqbalance & RPS (multi-core packet steering) ---
echo "==> Enabling irqbalance & RPS..."
systemctl enable --now irqbalance
for f in /sys/class/net/*/queues/rx-*/rps_cpus; do echo ffffffff > "$f" 2>/dev/null || true; done

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

# ------------------- app.py (Save=write only, Apply=reload only) -------------------
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
    try:
        return subprocess.check_output(["journalctl","-u",ZIVPN_SVC,"--since","-15min","-o","cat"]).decode().lower()
    except Exception:
        return ""

def days_left(expires_str):
    try:
        exp=datetime.strptime(expires_str,"%Y-%m-%d").date()
        return (exp - date.today()).days
    except Exception:
        return None

def active_rows():
    log=logs()
    today=date.today()
    rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=(not expired) and (r["password"].lower() in log)
            rows.append({
                "id":r["id"], "username":r["username"], "password":r["password"],
                "expires":r["expires"], "expired":expired, "online":online,
                "days_left": days_left(r["expires"])
            })
    return rows

def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(ZIVPN_CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)

def sync():
    # Save-time: only write config (no reload/restart)
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    write_cfg(pw)

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

# ---------- Login ----------
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
  <div class="flex items-center gap-2 mb-3">
    <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" alt="Logo" class="h-8 w-8">
    <h2 class="text-xl font-bold">ZIVPN Login</h2>
  </div>
  <form method=post class="space-y-3">
    <div class="relative">
      <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
        </svg>
      </div>
      <input name=u class="w-full pl-10 p-2 rounded bg-slate-700/80 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="👤 Enter Username">
    </div>
    <div class="relative">
      <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <input name=p type=password class="w-full pl-10 p-2 rounded bg-slate-700/80 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="🔒 Enter Password">
    </div>
    <button class="w-full bg-emerald-600 hover:bg-emerald-500 transition py-2 rounded-xl shadow">Login</button>
  </form>
</div></body></html>''')

# ---------- Dashboard ----------
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
    server_ts=int(time.time())
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script>
<script>
const SERVER_TS={{server_ts}}*1000; let start=Date.now();
function z(n){return n.toString().padStart(2,'0')}
function tick(){const now=SERVER_TS+(Date.now()-start);const d=new Date(now);
const el=document.getElementById('server-time'); if(el) el.textContent=d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate())+" "+z(d.getHours())+":"+z(d.getMinutes())+":"+z(d.getSeconds());}
setInterval(tick,1000);window.addEventListener('load',tick);
function copyText(t,btn){function ok(){if(btn){btn.innerText='✓';btn.disabled=true;setTimeout(()=>{btn.innerText='Copy';btn.disabled=false;},800)}};if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok);}else{const ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);ok();}}
function fillForm(u,p,e){const f=document.querySelector('form[action="/save"]');if(!f)return;f.querySelector('input[name="username"]').value=u;f.querySelector('input[name="password"]').value=p;const ie=f.querySelector('input[name="expires"]');ie.value=e;f.scrollIntoView({behavior:'smooth',block:'start'});setTimeout(()=>{if(ie.showPicker) ie.showPicker();},150);}
function closeNotice(id){const el=document.getElementById(id); if(el) el.remove();}
</script>
<style>
.table-tight td,.table-tight th{padding-top:.15rem;padding-bottom:.15rem}
.tiny{font-size:12px;line-height:1.1}
.code-chip{font-family:ui-monospace,Menlo,monospace}
.badge{font-size:11px;padding:.2rem .5rem;border-radius:9999px}
.fab{position:fixed;top:.75rem;right:.75rem;display:flex;gap:.5rem;z-index:50}
.fab a{width:36px;height:36px;display:grid;place-items:center;border-radius:9999px;box-shadow:0 4px 14px rgba(0,0,0,.15)}
</style>
</head>
<body class="bg-slate-50">

<!-- Floating buttons (Telegram / Logout) -->
<div class="fab">
  <a href="https://t.me/Pussy1990" target="_blank" rel="noopener" class="bg-sky-600 hover:bg-sky-500 text-white" title="Telegram">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M9.04 15.47l-.39 5.49c.56 0 .8-.24 1.09-.53l2.62-2.52 5.43 3.97c1 .55 1.71.26 1.98-.93l3.6-16.85c.32-1.5-.54-2.09-1.52-1.73L1.16 9.64c-1.46.57-1.44 1.39-.25 1.76l5.34 1.66L19.36 6.1c.62-.41 1.18-.18.72.23"/></svg>
  </a>
  <a href="/logout" class="bg-slate-700 hover:bg-slate-600 text-white" title="Logout">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M10 17v2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5v2H5v10h5zm4.293-1.293 2.293-2.293H9v-2h7.586l-2.293-2.293 1.414-1.414L21.414 12l-4.707 4.707-1.414-1.414z"/></svg>
  </a>
</div>

<header class="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-2">
      <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" alt="Logo" class="h-8 w-8">
      <h1 class="text-2xl font-extrabold tracking-tight">ZIVPN</h1>
    </div>
    <div></div>
  </div>
</header>

<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">

  <!-- Server info -->
  <section class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
    <div class="grid sm:grid-cols-2 gap-2 text-sm">
      <div>VPS IP: <span class="font-semibold text-slate-900">{{ vps_ip }}</span></div>
      <div>Server Time: <span id="server-time" class="font-semibold text-slate-900">--:--:--</span></div>
    </div>
  </section>

  <!-- Flash messages (Create Account Successfully ✅) -->
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    {% for cat, msg in msgs %}
    <div id="notice-{{ loop.index }}" class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-2xl p-3">
      <div class="flex items-start justify-between gap-2">
        <div class="text-sm whitespace-pre-wrap font-medium">
Create Account Successfully ✅
{{ msg }}
        </div>
        <button class="px-2 py-0.5 bg-emerald-600 text-white rounded text-[11px]" onclick="closeNotice('notice-{{ loop.index }}')">OK</button>
      </div>
      <div class="mt-1 text-[11px] text-emerald-800/80">1 User For 1 Device</div>
    </div>
    {% endfor %}
  {% endif %}
  {% endwith %}

  <!-- Stats -->
  <section class="grid grid-cols-1 sm:grid-cols-3 gap-3">
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Users</div>
      <div class="mt-1 text-2xl font-bold text-slate-900">{{total_users}}</div>
    </div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Online</div>
      <div class="mt-1 text-2xl font-bold text-emerald-600">{{total_online}}</div>
    </div>
    {% if total_offline > 0 %}
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Offline</div>
      <div class="mt-1 text-2xl font-bold text-rose-600">{{total_offline}}</div>
    </div>
    {% endif %}
  </section>

  <!-- Controls -->
  <section class="flex gap-2">
    <form method="post" action="/apply">
      <button class="bg-slate-800 hover:bg-slate-700 text-white rounded-xl px-3 py-2 text-sm">⚙️ Apply Config (Reload only)</button>
    </form>
  </section>

  <!-- Form + Table -->
  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-500">
          <path d="M12 12c2.761 0 5-2.686 5-6s-2.239-6-5-6-5 2.686-5 6 5 6zm0 2c-4.418 0-8 2.239-8 5v3h16v-3c0-2.761-3.582-5-8-5z"/>
        </svg>
        Add / Update User
      </h3>
      <form method=post action="/save" class="space-y-2">
        <div><input name=username placeholder="👤 Username" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none"></div>
        <div><input name=password placeholder="🔒 Password" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none"></div>
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save & Sync</button>
      </form>
      <p class="mt-2 text-[11px] text-slate-500">Script By: <b>JueHtet</b></p>
    </div>

    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200 overflow-x-auto">
      <table class="w-full text-left align-middle table-tight">
        <thead>
          <tr class="text-slate-600 text-[12px]">
            <th class="py-1">User</th>
            <th class="py-1">Password</th>
            <th class="py-1">Expires</th>
            <th class="py-1">Status</th>
            <th class="py-1"></th>
          </tr>
        </thead>
        <tbody class="tiny">
          {% for r in rows %}
          <tr class="border-t">
            <td class="py-1"><span class="font-medium" title="{{r['username']}}">{{r['username']}}</span></td>
            <td class="py-1">
              <div class="flex items-center gap-1.5 flex-wrap">
                <code class="code-chip px-1.5 py-0.5 bg-slate-100 rounded" title="{{r['password']}}">{{r['password']}}</code>
                <button onclick="copyText('{{r['password']}}',this)" class="px-2 py-0.5 bg-slate-800 text-white rounded text-[11px]">Copy</button>
                {% if r['days_left'] is not none %}
                  {% if r['days_left'] >= 0 %}
                    <span class="badge bg-emerald-100 text-emerald-700">{{r['days_left']}} days</span>
                  {% else %}
                    <span class="badge bg-rose-100 text-rose-700">Expired {{-r['days_left']}} days</span>
                  {% endif %}
                {% endif %}
              </div>
            </td>
            <td class="py-1 text-slate-600">{{r['expires']}}</td>
            <td class="py-1">
              {% if not r['expired'] %}
                <span class="inline-flex items-center gap-1 text-emerald-700"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>Online</span>
              {% else %}
                <span class="inline-flex items-center gap-1 text-slate-600"><span class="w-2 h-2 rounded-full bg-slate-400"></span>Offline</span>
              {% endif %}
            </td>
            <td class="py-1">
              <div class="flex items-center gap-1.5">
                <button type="button" onclick="fillForm('{{r['username']}}','{{r['password']}}','{{r['expires']}}')" class="px-2 py-0.5 bg-amber-500 hover:bg-amber-400 text-white rounded text-[11px]">Edit</button>
                <form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
                  <button class="px-2 py-0.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px]">🗑️</button>
                </form>
              </div>
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
        default_exp=default_exp, vps_ip=vps_ip, server_ts=server_ts)

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
    try:
        ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        ip=request.host.split(":")[0]
    msg=f"IP : {ip}\nUsers : {u}\nPassword : {p}\nExpired Date : {e}\n1 User For 1 Device"
    flash(msg, "ok")
    sync();return redirect("/")

# Apply = RELOAD ONLY (never restart)
@app.route("/apply", methods=["POST"])
@login_required
def apply():
    try:
        subprocess.call(["systemctl","reload",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)
        flash("Applied with RELOAD only (no restart). If daemon ignores HUP, changes take effect after next manual restart.", "ok")
    except Exception:
        flash("Reload attempt failed (no restart done).", "err")
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync();return redirect("/")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app,host=os.getenv("BIND_HOST","0.0.0.0"),port=int(os.getenv("BIND_PORT","8088")))
PY

# --- Auto Sync Script (never restarts) ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
def actives():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,CFG)
if __name__=="__main__":
    write_cfg(actives())
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

# --- Panel service & timer ---
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

# --- OPTIONAL: Server-side keepalive every minute (helps strict NATs) ---
cat >/usr/local/sbin/zivpn-udp-keepalive.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
PORT=5667
command -v conntrack >/dev/null 2>&1 || exit 0
conntrack -L -p udp 2>/dev/null | awk -v p="dport="PORT '$0 ~ p {print}' | \
  sed -n 's/.*src=\([0-9\.]\+\).*sport=\([0-9]\+\).*/\1 \2/p' | \
  while read SRC SPORT; do printf '.' >/dev/udp/${SRC}/${SPORT} || true; done
SH
chmod +x /usr/local/sbin/zivpn-udp-keepalive.sh
echo '* * * * * root /usr/local/sbin/zivpn-udp-keepalive.sh >/dev/null 2>&1' > /etc/cron.d/zivpn-keepalive
systemctl restart cron

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE (Smooth Edition)"
echo "======================================"
echo "📊 Web Panel: http://${IP}:8088/login"
echo "👤 Admin Username: ${ADMIN_USER}"
echo "🔑 Admin Password: ${ADMIN_PASSWORD}"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
