cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Web Panel (DB-only panel: no reload/restart, no timers)
# — Multi-login allowed, no “Save/Apply” tips, custom logo —
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

echo "==> Packages"
apt-get update -y && apt-get install -y python3-venv python3-pip openssl ufw curl jq > /dev/null

echo "==> ZIVPN binary"
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"
# If config already exists, keep it. Else write minimal default (single 'zi' pass)
if [ ! -f "${ZIVPN_CFG}" ]; then
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
fi

# TLS (only if absent)
[ -f "${ZIVPN_DIR}/zivpn.key" ] || openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" > /dev/null 2>&1

# systemd unit (panel will NEVER call reload/restart)
cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=1
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

# NAT + firewall (idempotent)
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

echo "==> Panel"
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
EOF

# ---------------- Flask (no journalctl, no apply, no sync) ----------------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, sqlite3
from datetime import date, datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, flash

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","change-me")

app=Flask(__name__)
app.secret_key=os.urandom(24)

def db():
    c=sqlite3.connect(DB, timeout=3, check_same_thread=False)
    c.row_factory=sqlite3.Row
    return c

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

def login_required(fn):
    def w(*a,**k):
        if not session.get("ok"): return redirect(url_for("login"))
        return fn(*a,**k)
    w.__name__=fn.__name__
    return w

# --- Login ---
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True; return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen grid place-items-center bg-slate-100">
  <div class="w-[360px] bg-white p-6 rounded-2xl shadow ring-1 ring-slate-200">
    <div class="flex items-center gap-2 mb-3">
      <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" class="h-8 w-8 rounded" alt="ZIVPN">
      <h2 class="text-xl font-bold text-slate-900">ZIVPN Login</h2>
    </div>
    <form method=post class="space-y-3">
      <input name=u class="w-full p-2 rounded border border-slate-300 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Username">
      <input name=p type=password class="w-full p-2 rounded border border-slate-300 outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Password">
      <button class="w-full bg-emerald-600 hover:bg-emerald-500 transition py-2 rounded-xl shadow text-white">Login</button>
    </form>
  </div>
</body></html>''')

# --- Dashboard ---
@app.route("/")
@login_required
def index():
    with db() as con:
        rows=[dict(r) for r in con.execute("SELECT * FROM users ORDER BY username")]
    for r in rows:
        dl=days_left(r["expires"]); r["days_left"]=dl
        r["expired"] = (dl is not None and dl<0)
    total_users=len(rows)
    total_active=sum(1 for r in rows if not r["expired"])
    total_expired=total_users-total_active
    default_exp=date.today().isoformat()
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><script src="https://cdn.tailwindcss.com"></script>
<style>
.table-tight td,.table-tight th{padding-top:.15rem;padding-bottom:.15rem}
.table-tight .tiny{font-size:12px;line-height:1.1}
.code-chip{font-family:ui-monospace,Menlo,monospace}
.truncate-soft{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn-slim{padding:.25rem .6rem}
.badge{font-size:11px;padding:.2rem .5rem;border-radius:9999px}
</style></head>
<body class="bg-slate-50">
<header class="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-2">
      <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" class="h-7 w-7 rounded" alt="ZIVPN">
      <h1 class="text-2xl font-extrabold tracking-tight">ZIVPN</h1>
    </div>
    <a href="/logout" class="text-sm opacity-80 hover:opacity-100">Logout</a>
  </div>
</header>

<main class="max-w-6xl mx-auto px-4 py-4 space-y-4">
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    {% for cat,msg in msgs %}
    <div class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-2xl p-3">
      <div class="text-sm whitespace-pre-wrap font-medium">Done ✅
{{ msg }}</div>
    </div>
    {% endfor %}
  {% endif %}
  {% endwith %}

  <section class="grid grid-cols-1 sm:grid-cols-3 gap-3">
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Total Users</div><div class="mt-1 text-2xl font-bold text-slate-900">{{total_users}}</div></div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Active</div><div class="mt-1 text-2xl font-bold text-emerald-600">{{total_active}}</div></div>
    <div class="bg-white rounded-2xl shadow p-4 ring-1 ring-slate-200"><div class="text-slate-500 text-xs">Expired</div><div class="mt-1 text-2xl font-bold text-rose-600">{{total_expired}}</div></div>
  </section>

  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm flex items-center gap-2">
        <img src="https://raw.githubusercontent.com/JVPNSHOP/ZIVPN/main/1761213901286.png" class="h-4 w-4 rounded"> Add / Update User
      </h3>
      <form method=post action="/save" class="space-y-2">
        <input name=username placeholder="Username" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <input name=password placeholder="Password" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-emerald-500 outline-none">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-xl shadow text-sm">💾 Save</button>
      </form>
      <!-- No Apply button, no tips -->
    </div>

    <div class="bg-white p-3 rounded-2xl shadow ring-1 ring-slate-200 overflow-x-auto">
      <table class="w-full text-left align-middle table-tight">
        <thead><tr class="text-slate-600 text-[12px]"><th>User</th><th>Password</th><th>Expires</th><th>Status</th><th></th></tr></thead>
        <tbody class="tiny">
          {% for r in rows %}
          <tr class="border-t">
            <td class="py-1"><span class="font-medium truncate-soft" title="{{r['username']}}">{{r['username']}}</span></td>
            <td class="py-1">
              <div class="flex items-center gap-1.5 flex-wrap">
                <code class="code-chip px-1.5 py-0.5 bg-slate-100 rounded truncate-soft" title="{{r['password']}}">{{r['password']}}</code>
                <button onclick="navigator.clipboard.writeText('{{r['password']}}')" class="btn-slim bg-slate-800 text-white rounded text-[11px]">Copy</button>
              </div>
            </td>
            <td class="py-1 text-slate-600">{{r['expires']}}</td>
            <td class="py-1">{% if not r['expired'] %}<span class="badge bg-emerald-100 text-emerald-700">Active{% else %}<span class="badge bg-rose-100 text-rose-700">Expired{% endif %}</span></td>
            <td class="py-1">
              <div class="flex items-center gap-1.5">
                <button type="button" onclick="(function(){const f=document.querySelector('form[action=&quot;/save&quot;]');f.username.value='{{r['username']}}';f.password.value='{{r['password']}}';f.expires.value='{{r['expires']}}';f.scrollIntoView({behavior:'smooth'})})()" class="btn-slim bg-amber-500 hover:bg-amber-400 text-white rounded text-[11px]">Edit</button>
                <form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')"><button class="btn-slim bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px]">🗑️</button></form>
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
        rows=rows, total_users=total_users, total_active=total_active,
        total_expired=total_expired, default_exp=default_exp)

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
                       ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",
                    (u,p,e,p,e))
    flash(f"User: {u}\nPassword: {p}\nExpired: {e}", "ok")
    # IMPORTANT: Do NOT touch service or config here (DB-only).
    return redirect("/")

@app.route("/del/<int:uid>", methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    flash("Deleted.", "ok")
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST","0.0.0.0"), port=int(os.getenv("BIND_PORT","8088")), threads=2)
PY

# panel service
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel (DB-only)
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

echo
echo "✅ INSTALL COMPLETE (DB-only Panel; no service reloads)"
echo "Admin Panel: http://$(hostname -I | awk '{print $1}'):8088/login"
echo "Admin User: ${ADMIN_USER}"
echo "Admin Pass: ${ADMIN_PASSWORD}"
echo "NOTE: Panel never touches zivpn service. Manage zivpn manually if you need to."
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
