sudo tee /root/zi.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# === Vars ===
ZIVPN_VER="1.4.9"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_${ZIVPN_VER}/udp-zivpn-linux-amd64"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
APP_PY="${ADMIN_DIR}/app.py"
PANEL_SVC="zivpn-admin.service"

PANEL_PORT=81        # HTTPS
APP_PORT=8088        # Flask (waitress) backend
LOCAL_PORT=5667
PORT_MIN=6000
PORT_MAX=19999

# === Packages ===
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-venv python3-pip openssl ufw curl jq nginx acl iptables iproute2 > /dev/null

# === ZIVPN install ===
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
curl -fsSL "$ZIVPN_URL" -o "$ZIVPN_BIN"
chmod +x "$ZIVPN_BIN"
mkdir -p "$ZIVPN_DIR"

cat > "$ZIVPN_CFG" <<JSON
{
  "listen": "0.0.0.0:${LOCAL_PORT}",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "config": ["zi"]
}
JSON

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

# NAT + firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
# use REDIRECT (more reliable than DNAT :port)
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT} 2>/dev/null \
  || iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT}
ufw allow ${PORT_MIN}:${PORT_MAX}/udp || true
ufw allow ${LOCAL_PORT}/udp || true
ufw allow ${PANEL_PORT}/tcp || true

# === Web Panel (Flask on :8088) ===
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet flask waitress python-dotenv

# default admin creds (can change later in /opt/zivpn-admin/.env)
ADMIN_USER="admin"
ADMIN_PASSWORD="change-me"

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=${APP_PORT}
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# Flask app
cat > "${APP_PY}" <<'PY'
import os, json, subprocess, datetime, socket
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
load_dotenv()

ADMIN_USER = os.getenv("ADMIN_USER","admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD","change-me")
CFG_PATH   = os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
SERVICE    = os.getenv("ZIVPN_SERVICE","zivpn.service")

app = Flask(__name__, static_folder=None)

def _load_cfg():
    with open(CFG_PATH,'r') as f: return json.load(f)
def _save_cfg(obj):
    with open(CFG_PATH,'w') as f: json.dump(obj,f,indent=2)

def _restart():
    subprocess.run(["/bin/systemctl","restart",SERVICE], check=False)

def _ips():
    ips=[]
    for iface in os.listdir('/sys/class/net'):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ips.append({ "iface": iface, "ip": socket.gethostbyname(socket.gethostname())})
        except: pass
    return ips

def auth(req):
    user=req.headers.get("X-User",""); pw=req.headers.get("X-Pass","")
    return (user==ADMIN_USER and pw==ADMIN_PASS)

@app.get("/api/info")
def info():
    if not auth(request): return ("unauthorized",401)
    now=datetime.datetime.utcnow().isoformat()+"Z"
    st=subprocess.run(["/bin/systemctl","is-active",SERVICE], capture_output=True, text=True)
    return jsonify({"time":now,"service":st.stdout.strip(),"ips":_ips()})

@app.get("/api/accounts")
def accounts():
    if not auth(request): return ("unauthorized",401)
    cfg=_load_cfg()
    # only password list; usernames managed client-side
    rows=[]
    for pw in cfg.get("config",[]):
        rows.append({"username":"-", "password":pw, "expiresAt":"-", "dayLeft":"-", "status":"Active"})
    return jsonify(rows)

@app.post("/api/accounts")
def create():
    if not auth(request): return ("unauthorized",401)
    data=request.get_json(force=True)
    password=data.get("password","").strip()
    if not password: return ("bad request",400)
    cfg=_load_cfg()
    lst=list(dict.fromkeys([*cfg.get("config",[]), password]))
    cfg["config"]=lst
    _save_cfg(cfg); _restart()
    return jsonify({"ok":True})

@app.delete("/api/accounts/<name>")
def delete(name):
    if not auth(request): return ("unauthorized",401)
    data=request.get_json(silent=True) or {}
    password=data.get("password","")
    cfg=_load_cfg()
    if password and password in cfg.get("config",[]):
        cfg["config"]=[p for p in cfg["config"] if p!=password]
        _save_cfg(cfg); _restart()
    return jsonify({"ok":True})

@app.get("/")
def ui():
    return """<!doctype html><html><head>
<meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>ZIVPN Panel</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-50">
<div class="max-w-3xl mx-auto p-6 space-y-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold">ZIVPN Panel</h1>
    <button id="refresh" class="px-3 py-2 rounded-lg bg-black text-white">Refresh</button>
  </div>
  <div class="grid md:grid-cols-3 gap-4" id="cards"></div>
  <div class="bg-white p-4 rounded-xl shadow">
    <div class="font-semibold mb-2">Create Account</div>
    <div class="grid md:grid-cols-3 gap-3">
      <input id="pw" placeholder="Password" class="border rounded-lg px-3 py-2">
      <input id="user" placeholder="Admin user" value="admin" class="border rounded-lg px-3 py-2">
      <input id="pass" placeholder="Admin pass" value="change-me" class="border rounded-lg px-3 py-2">
    </div>
    <button id="save" class="mt-3 px-4 py-2 rounded-lg bg-black text-white">Save</button>
  </div>
  <div class="bg-white p-4 rounded-xl shadow">
    <div class="font-semibold mb-2">Accounts (Password → Day left)</div>
    <table class="min-w-full text-sm"><thead><tr class="text-left text-gray-500">
      <th class="p-2">Username</th><th class="p-2">Password (Day left)</th><th class="p-2">Expired Date</th><th class="p-2">Status</th></tr></thead>
      <tbody id="rows"></tbody></table>
  </div>
</div>
<script>
async function call(path, method='GET', body=null){
  const u=document.getElementById('user').value, p=document.getElementById('pass').value;
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-User':u,'X-Pass':p},body: body?JSON.stringify(body):null});
  if(!r.ok) throw new Error(await r.text()); return r.json();
}
async function refresh(){
  const info=await call('/api/info'); const cards=document.getElementById('cards'); cards.innerHTML='';
  cards.innerHTML+=\`<div class="bg-white p-4 rounded-xl shadow"><div class="text-sm text-gray-500">Server Time</div><div class="mt-2 font-mono">\${new Date(info.time).toLocaleString()}</div></div>\`;
  cards.innerHTML+=\`<div class="bg-white p-4 rounded-xl shadow"><div class="text-sm text-gray-500">Service</div><div class="mt-2 font-semibold">\${info.service}</div></div>\`;
  cards.innerHTML+=\`<div class="bg-white p-4 rounded-xl shadow"><div class="text-sm text-gray-500">Run IP(s)</div><div class="mt-2 font-mono">\${info.ips.map(x=>x.ip).join(', ')}</div></div>\`;
  const rows=await call('/api/accounts'); const tb=document.getElementById('rows'); tb.innerHTML='';
  rows.forEach(r=>{ tb.innerHTML+=\`<tr class="border-t"><td class="p-2">-</td><td class="p-2">1 day left</td><td class="p-2">-</td><td class="p-2"><span class="px-2 py-1 rounded-xl bg-green-100 text-green-700">Active</span></td></tr>\`; });
}
document.getElementById('refresh').onclick=refresh;
document.getElementById('save').onclick=async ()=>{ const pw=document.getElementById('pw').value.trim(); if(!pw) return alert('enter password'); await call('/api/accounts','POST',{password:pw}); document.getElementById('pw').value=''; refresh(); }
refresh();
</script>
</body></html>"""
PY

# systemd for panel
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Admin Web (Flask)
After=network.target
[Service]
WorkingDirectory=${ADMIN_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV}/bin/waitress-serve --host=\${BIND_HOST} --port=\${BIND_PORT} app:app
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}

# Nginx HTTPS :81 reverse proxy → :8088
CERT_KEY="/etc/ssl/private/zivpn-panel.key"
CERT_CRT="/etc/ssl/certs/zivpn-panel.crt"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -subj "/CN=$(hostname -I | awk '{print $1}')" \
  -keyout "$CERT_KEY" -out "$CERT_CRT" >/dev/null 2>&1

cat >/etc/nginx/sites-available/zivpn-panel <<EOF
server {
  listen ${PANEL_PORT} ssl;
  server_name _;
  ssl_certificate $CERT_CRT;
  ssl_certificate_key $CERT_KEY;
  location / {
    proxy_pass http://127.0.0.1:${APP_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
  }
}
EOF
ln -sf /etc/nginx/sites-available/zivpn-panel /etc/nginx/sites-enabled/zivpn-panel
nginx -t && systemctl reload nginx

IP=$(hostname -I | awk '{print $1}')
echo "=================================="
echo "PANEL:   https://${IP}:${PANEL_PORT}"
echo "LOGIN:   admin / change-me  (edit ${ENV_FILE})"
echo "ZIVPN:   $(systemctl is-active ${ZIVPN_SVC} || true)"
echo "PANEL:   $(systemctl is-active ${PANEL_SVC} || true)"
echo "=================================="
BASH
