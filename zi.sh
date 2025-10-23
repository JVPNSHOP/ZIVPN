cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel (with icons, copy button, floating logout)
# Author: GPT-5 Edition for ZIVPN Admin Panel (UI revamp + stats)
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

# ---- Flask app (revamped UI) ----
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess
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
        return subprocess.check_output(
            ["journalctl","-u",ZIVPN_SVC,"--since","-15min","-o","cat"]
        ).decode().lower()
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
                "id":r["id"],
                "username":r["username"],
                "password":r["password"],
                "expires":r["expires"],
                "expired":expired,
                "online":online,
                "days_left": days_left(r["expires"])
            })
    return rows

def sync():
    # write config and restart zivpn without blocking the request
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    cfg={}
    try: cfg=json.load(open(ZIVPN_CFG))
    except Exception: pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw
    cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)
    # restart in background to avoid UI lag
    subprocess.Popen(["systemctl","restart",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)

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
  <div class="flex items-center gap-2 mb-3">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-400">
      <path d="M12 12c2.761 0 5-2.686 5-6s-2.239-6-5-6-5 2.686-5 6 2.239 6 5 6zm0 2c-4.418 0-8 2.239-8 5v3h16v-3c0-2.761-3.582-5-8-5z"/>
    </svg>
    <h2 class="text-xl font-bold">ZIVPN Login</h2>
  </div>
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
    # Counters based on date only (expired => Offline)
    total_users=len(rows)
    total_active=sum(1 for r in rows if not r["expired"])
    total_expired=sum(1 for r in rows if r["expired"])
    default_exp=date.today().isoformat()
    # VPS IP for header and flashes
    try:
        vps_ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        vps_ip=request.host.split(":")[0]
    
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script>
<script>
function copyText(t, btn){
  function ok(){ if(btn){ btn.innerText='✓'; btn.disabled=true; setTimeout(()=>{btn.innerText='Copy'; btn.disabled=false;},800);} }
  if (navigator.clipboard && window.isSecureContext){ navigator.clipboard.writeText(t).then(ok); }
  else { const ta=document.createElement('textarea'); ta.value=t; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); ok(); }
}
function fillForm(u,p,e){
  const f=document.querySelector('form[action="/save"]'); if(!f) return;
  f.querySelector('input[name="username"]').value=u;
  f.querySelector('input[name="password"]').value=p;
  const ie=f.querySelector('input[name="expires"]'); ie.value=e;
  f.scrollIntoView({behavior:'smooth', block:'start'});
}
function closeNotice(id){ const el=document.getElementById(id); if(el) el.remove(); }
</script>
<style>
.table-tight td, .table-tight th { padding-top:.15rem; padding-bottom:.15rem; }
.table-tight .tiny { font-size: 12px; line-height: 1.1; }
.code-chip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.truncate-soft { max-width: 180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.btn-slim { padding:.25rem .6rem; }
.badge { font-size:11px; padding:.2rem .5rem; border-radius:9999px; }
</style>
</head>
<body class="bg-slate-50">

<header class="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-2">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-400">
        <path d="M12 12c2.761 0 5-2.686 5-6s-2.239-6-5-6-5 2.686-5 6 2.239 6 5 6zm0 2c-4.418 0-8 2.239-8 5v3h16v-3c0-2.761-3.582-5-8-5z"/>
      </svg>
      <h1 class="text-2xl font-extrabold tracking-tight">ZIVPN</h1>
    </div>
    <a href="/logout" class="bg-slate-700 hover:bg-slate-600 text-white px-3 py-1 rounded text-sm">Logout</a>
  </div>
</header>

<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">

  <!-- VPS IP -->
  <section class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
    <div class="text-sm">
      VPS IP: <span class="font-semibold text-slate-900">{{ vps_ip }}</span>
    </div>
  </section>

  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    {% for cat, msg in msgs %}
    <div id="notice-{{ loop.index }}" class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-2xl p-3">
      <div class="flex items-start justify-between gap-2">
        <div class="text-sm whitespace-pre-wrap font-medium">
Create Account Done ✅
{{ msg }}
        </div>
        <button class="btn-slim bg-emerald-600 text-white rounded text-[11px]" onclick="closeNotice('notice-{{ loop.index }}')">OK</button>
      </div>
      <div class="mt-1 text-[11px] text-emerald-800/80">Multi-Login Allowed - Manual Restart Required</div>
    </div>
    {% endfor %}
  {% endif %}
  {% endwith %}

  <!-- Stats Cards -->
  <section class="grid grid-cols-1 sm:grid-cols-3 gap-3">
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Users</div>
      <div class="mt-1 text-2xl font-bold text-slate-900">{{total_users}}</div>
    </div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Active</div>
      <div class="mt-1 text-2xl font-bold text-emerald-600">{{total_active}}</div>
    </div>
    {% if total_expired > 0 %}
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200">
      <div class="text-slate-500 text-xs">Total Expired</div>
      <div class="mt-1 text-2xl font-bold text-rose-600">{{total_expired}}</div>
    </div>
    {% endif %}
  </section>

  <!-- Manual Restart Button -->
  <section class="bg-amber-50 ring-1 ring-amber-200 rounded-2xl p-4">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="font-semibold text-amber-800">Manual Restart Required</h3>
        <p class="text-sm text-amber-700">After adding users, run this command to apply changes:</p>
        <code class="text-xs bg-amber-100 px-2 py-1 rounded mt-1 inline-block">systemctl restart zivpn.service</code>
      </div>
      <button onclick="copyText('systemctl restart zivpn.service', this)" class="btn-slim bg-amber-600 hover:bg-amber-500 text-white rounded">Copy Command</button>
    </div>
  </section>

  <!-- Form + Table -->
  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-500">
          <path d="M12 12c2.761 0 5-2.686 5-6s-2.239-6-5-6-5 2.686-5 6 2.239 6 5 6zm0 2c-4.418 0-8 2.239-8 5v3h16v-3c0-2.761-3.582-5-8-5z"/>
        </svg>
        Add / Update User
      </h3>
      <form method=post action="/save" class="space-y-2">
        <input name=username placeholder="Username" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <input name=password placeholder="Password" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save User</button>
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
            <td class="py-1"><span class="font-medium truncate-soft" title="{{r['username']}}">{{r['username']}}</span></td>
            <td class="py-1">
              <div class="flex items-center gap-1.5 flex-wrap">
                <code class="code-chip px-1.5 py-0.5 bg-slate-100 rounded truncate-soft" title="{{r['password']}}">{{r['password']}}</code>
                <button onclick="copyText('{{r['password']}}',this)" class="btn-slim bg-slate-800 text-white rounded text-[11px]">Copy</button>
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
                <span class="inline-flex items-center gap-1 text-emerald-700"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>Active</span>
              {% else %}
                <span class="inline-flex items-center gap-1 text-slate-600"><span class="w-2 h-2 rounded-full bg-slate-400"></span>Expired</span>
              {% endif %}
            </td>
            <td class="py-1">
              <div class="flex items-center gap-1.5">
                <button type="button" onclick="fillForm('{{r['username']}}','{{r['password']}}','{{r['expires']}}')" class="btn-slim bg-amber-500 hover:bg-amber-400 text-white rounded text-[11px]">Edit</button>
                <form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
                  <button class="btn-slim bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px]">🗑️</button>
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
        rows=rows, total_users=total_users, total_active=total_active, total_expired=total_expired,
        default_exp=default_exp, vps_ip=vps_ip)

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
    msg=f"IP : {ip}\nUsers : {u}\nPassword : {p}\nExpired Date : {e}\nRemember to restart ZIVPN service!"
    flash(msg, "ok")
    sync()  # Only updates config file, no auto restart
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync()  # Only updates config file, no auto restart
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app,host=os.getenv("BIND_HOST","0.0.0.0"),port=int(os.getenv("BIND_PORT","8088")))
PY

# --- Auto Sync Script ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
from subprocess import DEVNULL
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"
def actives():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
cfg={}
try:
    cfg=json.load(open(CFG))
except Exception:
    pass
pw=actives()
cfg.setdefault("auth",{})["mode"]="passwords";cfg["auth"]["config"]=pw;cfg["config"]=pw
with tempfile.NamedTemporaryFile("w",delete=False) as f:
    import json; json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
# restart in background (faster cron/timer run)
subprocess.Popen(["systemctl","restart",SVC], stdout=DEVNULL, stderr=DEVNULL)
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
