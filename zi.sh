cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP Server + Web Panel (Renew + Copy Fix + Solid Internet NAT)
# Script By: JueHtet — Internet Fix Edition

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

SYNC_PY="${ADMIN_DIR}/sync.py"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

echo "==> Install deps..."
DEBIAN_FRONTEND=noninteractive apt-get update -yq
DEBIAN_FRONTEND=noninteractive apt-get install -yq python3-venv python3-pip openssl ufw curl jq conntrack iptables-persistent

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
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1 || true

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

echo "==> Detect outbound interface..."
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
[ -n "${IFC}" ] || { echo "Cannot detect outbound interface"; exit 1; }

echo "==> Enable IPv4 forwarding (runtime + persist)..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/90-zivpn.conf
sysctl --system >/dev/null

echo "==> iptables NAT + FORWARD rules..."
# DNAT: Map public UDP 6000-19999 -> 5667 (zivpn)
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667

# MASQUERADE for all egress via outbound IFC
iptables -t nat -C POSTROUTING -o "$IFC" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$IFC" -j MASQUERADE

# Forwarding rules (stateful + general allow)
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT

# Persist
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
fi

echo "==> UFW adjustments (if UFW is active)..."
if ufw status | grep -q "Status: active"; then
  # Allow panel + udp port
  ufw allow 8088/tcp || true
  ufw allow 5667/udp || true
  # Allow forwarding via UFW
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
  # Ensure NAT in before.rules
  if ! grep -q "ZIVPN NAT" /etc/ufw/before.rules 2>/dev/null; then
    cat >> /etc/ufw/before.rules <<EOFUFW

# ZIVPN NAT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i ${IFC} -p udp --dport 6000:19999 -j DNAT --to-destination :5667
-A POSTROUTING -o ${IFC} -j MASQUERADE
COMMIT
EOFUFW
  fi
  # Enable kernel forward via UFW sysctl
  sed -i 's/^#\?net\/ipv4\/ip_forward=.*/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
  ufw reload
fi

echo "==> Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress >/dev/null

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

# -------- Panel app (Online = not expired) --------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess
from datetime import date, datetime
from flask import Flask, request, redirect, session, render_template_string
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs(os.path.dirname(DB), exist_ok=True)
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
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, expires DATE
    )""")

def sync():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    cfg={}
    try: cfg=json.load(open(ZIVPN_CFG))
    except: cfg={"listen":":5667","auth":{}}
    cfg["auth"]={"mode":"passwords","config":pw}; cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)
    subprocess.run(["systemctl","restart",ZIVPN_SVC])

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect("/login")
        return f(*a,**kw)
    return w

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST" and request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
        session["ok"]=True; return redirect("/")
    return render_template_string('''<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="grid place-items-center h-screen bg-slate-900 text-white">
<div class="bg-slate-800 p-6 rounded-xl w-[360px]">
<h2 class="text-lg font-bold mb-3">🛡️ ZIVPN Login</h2>
<form method=post class="space-y-3">
<input name=u placeholder="Username" class="w-full p-2 rounded bg-slate-700">
<input name=p type=password placeholder="Password" class="w-full p-2 rounded bg-slate-700">
<button class="w-full bg-emerald-600 py-2 rounded">Login</button>
</form></div></body></html>''')

@app.route("/")
@login_required
def index():
    with db() as con:
        rows=[dict(r) for r in con.execute("SELECT * FROM users ORDER BY id DESC")]
    today=date.today()
    for r in rows:
        exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
        r["days"]=(exp-today).days
        r["online"]=r["days"]>=0
    ip=subprocess.getoutput("hostname -I | awk '{print $1}'").strip()
    return render_template_string('''<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script>
<script>
function copyText(t,btn){
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(()=>{btn.innerText='✓';setTimeout(()=>btn.innerText='Copy',800);})
    .catch(()=>fallback(t,btn));
  } else { fallback(t,btn); }
}
function fallback(t,btn){
  const el=document.createElement('textarea');el.value=t;el.setAttribute('readonly','');
  el.style.position='absolute';el.style.left='-9999px';document.body.appendChild(el);
  el.select();try{document.execCommand('copy');}catch(e){};document.body.removeChild(el);
  btn.innerText='✓';setTimeout(()=>btn.innerText='Copy',800);
}
</script></head>
<body class="bg-slate-50">
<a href="/logout" class="fixed bottom-4 right-4 bg-sky-600 text-white px-4 py-2 rounded-full shadow">Logout</a>
<div class="max-w-6xl mx-auto p-4">
<h2 class="text-2xl font-bold mb-2">🛡️ ZIVPN Admin Panel</h2>
<p class="text-sm text-slate-600 mb-4">Server: <span class="font-mono">{{ip}}</span> • UDP:5667</p>

<div class="grid md:grid-cols-[320px_1fr] gap-4">
  <div class="bg-white p-4 rounded-xl shadow">
    <h3 class="font-semibold mb-3">Add / Update</h3>
    <form method=post action="/save" class="space-y-2">
      <input name=username placeholder="Username" class="w-full border rounded p-2">
      <input name=password placeholder="Password" class="w-full border rounded p-2">
      <input type=date name=expires value="{{date.today().isoformat()}}" class="w-full border rounded p-2">
      <button class="w-full bg-emerald-600 text-white py-2 rounded">💾 Save</button>
    </form>
  </div>

  <div class="bg-white p-4 rounded-xl shadow overflow-x-auto">
    <table class="w-full text-left align-middle">
      <thead><tr class="text-slate-600"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr></thead>
      <tbody>
      {% for r in rows %}
        <tr class="border-t">
          <td class="py-2 font-medium">{{r['username']}}</td>
          <td class="py-2">
            <code class="px-2 py-1 bg-slate-100 rounded">{{r['password']}}</code>
            <button type="button" onclick="copyText('{{r['password']}}',this)" class="ml-2 bg-slate-800 text-white px-2 py-1 rounded">Copy</button>
            <span class="ml-2 text-xs px-2 py-0.5 rounded-full {{ 'bg-emerald-100 text-emerald-700' if r['days']>=0 else 'bg-rose-100 text-rose-700' }}">{{r['days']}} days</span>
          </td>
          <td class="py-2">{{r['expires']}}</td>
          <td class="py-2">
            {% if r['online'] %}<span class="text-emerald-700">Online</span>
            {% else %}<span class="text-rose-700">Offline</span>{% endif %}
          </td>
          <td class="py-2">
            <form method=post action="/edit/{{r['id']}}" style="display:inline">
              <button class="bg-sky-600 text-white px-3 py-1 rounded">✏️ Edit</button>
            </form>
            <form method=post action="/del/{{r['id']}}" style="display:inline">
              <button class="bg-rose-600 text-white px-3 py-1 rounded ml-1">🗑️</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</div>
</body></html>''', rows=rows, ip=ip, date=date)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"].strip(); p=request.form["password"].strip(); e=request.form["expires"].strip()
    if not u or not p or not e: return redirect("/")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
                       VALUES(?,?,?) ON CONFLICT(username)
                       DO UPDATE SET password=excluded.password, expires=excluded.expires""",(u,p,e))
    sync(); return redirect("/")

@app.route("/edit/<int:uid>",methods=["POST"])
@login_required
def edit(uid):
    with db() as con:
        row=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not row: return redirect("/")
    return render_template_string('''<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="grid place-items-center h-screen bg-slate-900 text-white">
<div class="bg-slate-800 p-6 rounded-xl w-[360px]">
<h2 class="text-lg font-bold mb-3">✏️ Edit / Renew</h2>
<form method=post action="/update/{{row['id']}}" class="space-y-2">
  <input name=username value="{{row['username']}}" class="w-full p-2 rounded bg-slate-700">
  <input name=password value="{{row['password']}}" class="w-full p-2 rounded bg-slate-700">
  <input type=date name=expires value="{{row['expires']}}" class="w-full p-2 rounded bg-slate-700">
  <div class="flex gap-2">
    <a href="/" class="flex-1 bg-slate-600 text-white py-2 rounded text-center">Cancel</a>
    <button class="flex-1 bg-emerald-600 py-2 rounded">Save</button>
  </div>
</form></div></body></html>''', row=row)

@app.route("/update/<int:uid>",methods=["POST"])
@login_required
def update(uid):
    u=request.form["username"].strip(); p=request.form["password"].strip(); e=request.form["expires"].strip()
    with db() as con:
        con.execute("UPDATE users SET username=?, password=?, expires=? WHERE id=?",(u,p,e,uid))
    sync(); return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con: con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync(); return redirect("/")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve; serve(app,host="0.0.0.0",port=8088)
PY

# -------- Daily sync (keeps only active passwords) --------
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile, subprocess
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"
def active_passwords():
    with sqlite3.connect(DB) as con:
        return [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")] or ["zi"]
cfg={"listen":":5667","auth":{"mode":"passwords","config":active_passwords()},"config":active_passwords()}
with tempfile.NamedTemporaryFile("w",delete=False) as f: json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
subprocess.run(["systemctl","restart",SVC])
PY
chmod +x "${SYNC_PY}"

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
echo "Panel : http://${IP}:8088/login"
echo "UDP   : 5667  (6000-19999 → 5667 mapped)"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
