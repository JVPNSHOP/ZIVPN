cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel
# Stable one-device policy: expire on multi-IP without killing Admin Panel
# Script By: JueHtet (tuned)

set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
GUARD_PY="${ADMIN_DIR}/guard.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"
GUARD_SVC="zivpn-guard.service"

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

# ---- Flask app (your current UI kept; trimmed here for brevity) ----
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time
from subprocess import DEVNULL
from datetime import date
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
    c=sqlite3.connect(DB, timeout=5); c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA busy_timeout=3000"); c.row_factory=sqlite3.Row; return c

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
        from datetime import datetime, date as d
        exp=datetime.strptime(expires_str,"%Y-%m-%d").date()
        return (exp - d.today()).days
    except Exception:
        return None

def active_rows():
    log=logs()
    from datetime import date as d, datetime
    today=d.today()
    rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=(not expired) and (r["password"].lower() in log)
            rows.append({
                "id":r["id"],"username":r["username"],"password":r["password"],
                "expires":r["expires"],"expired":expired,"online":online,
                "days_left": days_left(r["expires"])
            })
    return rows

def sync():
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
    return render_template_string('<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen grid place-items-center bg-slate-900 text-white"><div class="w-[360px] bg-slate-800 p-6 rounded-2xl shadow-2xl ring-1 ring-white/10"><h2 class="text-xl font-bold mb-3">ZIVPN Login</h2><form method=post class="space-y-3"><input name=u class="w-full p-2 rounded bg-slate-700 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Username"><input name=p type=password class="w-full p-2 rounded bg-slate-700 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Password"><button class="w-full bg-emerald-600 hover:bg-emerald-500 transition py-2 rounded-xl shadow">Login</button></form></div></body></html>')

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
function copyImpl(text, btn){
  function ok(){ if(btn){ const o=btn.innerText; btn.innerText='✓ Copied'; btn.disabled=true; setTimeout(()=>{btn.innerText=o; btn.disabled=false;},900);} }
  function fallback(){ const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');ok();}catch(e){} document.body.removeChild(ta); }
  if(navigator.clipboard&&isSecureContext){ navigator.clipboard.writeText(text).then(ok).catch(fallback);} else { fallback(); }
}
function bindBtns(){
  document.querySelectorAll('[data-copy]').forEach(b=>{ const h=e=>{e.stopPropagation();e.preventDefault();copyImpl(b.dataset.copy,b);}; b.addEventListener('click',h,{passive:false}); b.addEventListener('touchend',h,{passive:false}); });
  document.querySelectorAll('[data-edit]').forEach(b=>{ const h=e=>{e.stopPropagation();e.preventDefault(); const f=document.querySelector('form[action="/save"]'); f.username.value=b.dataset.user; f.password.value=b.dataset.pass; f.expires.value=b.dataset.exp; f.scrollIntoView({behavior:'smooth',block:'start'}); setTimeout(()=>{if(f.expires.showPicker) f.expires.showPicker();},120);}; b.addEventListener('click',h,{passive:false}); b.addEventListener('touchend',h,{passive:false}); });
}
const SERVER_TS={{server_ts}}*1000; let start=Date.now();
function fmt(n){return n.toString().padStart(2,'0')}
function tick(){ const d=new Date(SERVER_TS+(Date.now()-start)); const s=d.getFullYear()+"-"+fmt(d.getMonth()+1)+"-"+fmt(d.getDate())+" "+fmt(d.getHours())+":"+fmt(d.getMinutes())+":"+fmt(d.getSeconds()); const el=document.getElementById('server-time'); if(el) el.textContent=s; }
window.addEventListener('DOMContentLoaded',()=>{bindBtns();tick();}); setInterval(tick,1000);
</script>
<style>
.table-tight td,.table-tight th{padding-top:.15rem;padding-bottom:.15rem}
.tiny{font-size:12px;line-height:1.1}
.btn-slim{padding:.25rem .6rem;touch-action:manipulation;cursor:pointer;position:relative;z-index:1}
</style></head>
<body class="bg-slate-50">
<header class="bg-slate-900 text-white"><div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between"><h1 class="text-2xl font-extrabold">ZIVPN</h1><a href="/logout" class="text-white/80 hover:text-white text-sm">Logout</a></div></header>
<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">
<section class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="grid sm:grid-cols-2 gap-2 text-sm"><div>VPS IP: <span class="font-semibold text-slate-900">{{vps_ip}}</span></div><div>Server Time: <span id="server-time" class="font-semibold text-slate-900">--:--:--</span></div></div></section>
<section class="grid grid-cols-1 sm:grid-cols-3 gap-3"><div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Users</div><div class="mt-1 text-2xl font-bold text-slate-900">{{total_users}}</div></div><div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Online</div><div class="mt-1 text-2xl font-bold text-emerald-600">{{total_online}}</div></div>{% if total_offline>0 %}<div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Offline</div><div class="mt-1 text-2xl font-bold text-rose-600">{{total_offline}}</div></div>{% endif %}</section>
<section class="grid md:grid-cols-[320px_1fr] gap-3">
  <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
    <h3 class="font-semibold mb-2 text-sm">Add / Update User</h3>
    <form method=post action="/save" class="space-y-2">
      <input name=username placeholder="Username" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
      <input name=password placeholder="Password" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
      <label class="text-[11px] text-slate-600">Expires</label>
      <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
      <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save & Sync</button>
    </form>
  </div>
  <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200 overflow-x-auto">
    <table class="w-full text-left align-middle table-tight">
      <thead><tr class="text-slate-600 text-[12px]"><th class="py-1">User</th><th class="py-1">Password</th><th class="py-1">Expires</th><th class="py-1">Status</th><th class="py-1"></th></tr></thead>
      <tbody class="tiny">
      {% for r in rows %}
        <tr class="border-t">
          <td class="py-1"><span class="font-medium">{{r['username']}}</span></td>
          <td class="py-1">
            <div class="flex items-center gap-1.5 flex-wrap">
              <code class="px-1.5 py-0.5 bg-slate-100 rounded">{{r['password']}}</code>
              <button type="button" class="btn-slim bg-slate-800 text-white rounded text-[11px]" data-copy="{{ r['password'] }}">Copy</button>
              {% if r['days_left'] is not none %}
                {% if r['days_left'] >= 0 %}
                  <span class="text-emerald-700 text-[11px] px-2 py-0.5 bg-emerald-100 rounded-full">{{r['days_left']}} days</span>
                {% else %}
                  <span class="text-rose-700 text-[11px] px-2 py-0.5 bg-rose-100 rounded-full">Expired {{-r['days_left']}} days</span>
                {% endif %}
              {% endif %}
            </div>
          </td>
          <td class="py-1 text-slate-600">{{r['expires']}}</td>
          <td class="py-1">{% if not r['expired'] %}<span class="inline-flex items-center gap-1 text-emerald-700"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>Online</span>{% else %}<span class="inline-flex items-center gap-1 text-slate-600"><span class="w-2 h-2 rounded-full bg-slate-400"></span>Offline</span>{% endif %}</td>
          <td class="py-1"><div class="flex items-center gap-1.5"><button type="button" class="btn-slim bg-amber-500 hover:bg-amber-400 text-white rounded text-[11px]" data-edit data-user="{{ r['username'] }}" data-pass="{{ r['password'] }}" data-exp="{{ r['expires'] }}">Edit</button><form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')"><button class="btn-slim bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px]">🗑️</button></form></div></td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</section>
</main></body></html>''',
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

# --- Auto Sync Script ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
from subprocess import DEVNULL
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"
def actives():
    with sqlite3.connect(DB, timeout=5) as con:
        con.execute("PRAGMA busy_timeout=3000")
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
cfg={}
try: cfg=json.load(open(CFG))
except Exception: cfg={}
pw=actives()
cfg.setdefault("auth",{})["mode"]="passwords";cfg["auth"]["config"]=pw;cfg["config"]=pw
with tempfile.NamedTemporaryFile("w",delete=False) as f:
    json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
subprocess.Popen(["systemctl","restart",SVC], stdout=DEVNULL, stderr=DEVNULL)
PY

# --- One-Device Guard (robust, debounced) ---
cat > "${GUARD_PY}" <<'PY'
import os, re, sqlite3, subprocess, time, json, tempfile
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"
STATE="/var/lib/zivpn-admin/guard.state.json"   # { "cooldown": {uid: ts}, "last_restart": ts }
os.makedirs(os.path.dirname(STATE), exist_ok=True)

IP_RE=re.compile(r'(?:(?:\d{1,3}\.){3}\d{1,3})')

COOLDOWN_SEC=300        # once expired, ignore same user for 5 min
RESTART_DEBOUNCE=30     # do not restart zivpn faster than every 30s

def load_state():
    try: return json.load(open(STATE))
    except Exception: return {"cooldown": {}, "last_restart": 0}

def save_state(st):
    with open(STATE,"w") as f: json.dump(st,f)

def now(): return int(time.time())

def users():
    with sqlite3.connect(DB, timeout=5) as con:
        con.execute("PRAGMA busy_timeout=3000")
        return list(con.execute("SELECT id,username,password FROM users WHERE DATE(expires)>=DATE('now')"))

def scan_log(minutes=2):
    try:
        out=subprocess.check_output(["journalctl","-u",SVC,"--since",f"-{minutes}min","-o","cat"], text=True)
    except Exception:
        out=""
    return out.splitlines()

def ips_seen_for_pw(lines, pw):
    s=set()
    key=pw.lower()
    for ln in lines:
        if key in ln.lower():
            m=IP_RE.search(ln)
            if m: s.add(m.group(0))
    return s

def resync_and_maybe_restart(st):
    # write config with active passwords
    with sqlite3.connect(DB, timeout=5) as con:
        con.execute("PRAGMA busy_timeout=3000")
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    cfg={}
    try: cfg=json.load(open(CFG))
    except Exception: cfg={}
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw or ["zi"]
    cfg["config"]=pw or ["zi"]
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,CFG)
    # debounce restart
    t=now()
    if t - st.get("last_restart",0) >= RESTART_DEBOUNCE:
        subprocess.Popen(["systemctl","restart",SVC], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st["last_restart"]=t

def main():
    st=load_state()
    while True:
        lines=scan_log(2)
        changed=False
        t=now()
        with sqlite3.connect(DB, timeout=5) as con:
            con.execute("PRAGMA busy_timeout=3000")
            for uid,uname,pw in users():
                # cooldown skip
                cd=int(st.get("cooldown",{}).get(str(uid),0))
                if t - cd < COOLDOWN_SEC: 
                    continue
                ips=ips_seen_for_pw(lines, pw)
                if len(ips) >= 2:
                    # expire immediately (admin must re-enable)
                    con.execute("UPDATE users SET expires=date('now','-1 day') WHERE id=?", (uid,))
                    st["cooldown"][str(uid)]=t
                    changed=True
        if changed:
            resync_and_maybe_restart(st)
            save_state(st)
        time.sleep(15)

if __name__=="__main__":
    main()
PY

# systemd units
cat >/etc/systemd/system/${GUARD_SVC} <<EOF
[Unit]
Description=ZIVPN 1-device guard (expire user on multi-IP)
After=network.target
[Service]
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${GUARD_PY}
Restart=always
User=root
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=6
[Install]
WantedBy=multi-user.target
EOF

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
systemctl enable --now ${GUARD_SVC}

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "Open Panel: http://${IP}:8088/login"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
