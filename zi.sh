# write a single go script that fixes apt & installs everything end-to-end
sudo tee /root/go.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# ---------- harden apt so it won't hang ----------
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none
export UCF_FORCE_CONFOLD=1
export TZ=UTC

# unlock / fix partial installs (safe if nothing is locked)
dpkg --configure -a || true
apt-get -f install -y || true

# kill any stray apt/apt-get if running
pids=$(pgrep -f "apt|apt-get|unattended"); if [ -n "${pids:-}" ]; then kill -9 $pids 2>/dev/null || true; fi

apt-get update -y
apt-get install -y curl jq openssl iptables iproute2 ufw nginx python3-venv python3-pip > /dev/null

# ---------- config (override via env when running this script) ----------
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-StrongP@ss123}"
ZIVPN_PASSWORDS="${ZIVPN_PASSWORDS:-zi}"
PANEL_PORT="${PANEL_PORT:-81}"   # HTTPS
APP_PORT=8088                    # Flask backend
LOCAL_PORT=5667
PORT_MIN=6000; PORT_MAX=19999
ZIVPN_VER=1.4.9

# ---------- paths ----------
BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_${ZIVPN_VER}/udp-zivpn-linux-amd64"
BIN="/usr/local/bin/zivpn"
CONF_DIR="/etc/zivpn"; CFG="$CONF_DIR/config.json"; KEY="$CONF_DIR/zivpn.key"; CRT="$CONF_DIR/zivpn.crt"
UNIT="/etc/systemd/system/zivpn.service"

APP_DIR="/opt/zivpn-admin"; VENV="$APP_DIR/venv"; ENVF="$APP_DIR/.env"; APP="$APP_DIR/app.py"
PUNIT="/etc/systemd/system/zivpn-admin.service"
SITE="/etc/nginx/sites-available/zivpn-panel"
CK="/etc/ssl/private/zivpn-panel.key"; CC="/etc/ssl/certs/zivpn-panel.crt"

# ---------- install ZIVPN ----------
mkdir -p "$CONF_DIR"
curl -fsSL "$BIN_URL" -o "$BIN"; chmod +x "$BIN"

# base config
if [ ! -f "$CFG" ]; then
  cat >"$CFG"<<JSON
{"listen":"0.0.0.0:${LOCAL_PORT}","cert":"$CRT","key":"$KEY","config":["zi"]}
JSON
fi
# set passwords
IFS=',' read -r -a arr <<<"$ZIVPN_PASSWORDS"
mapfile -t clean < <(printf '%s\n' "${arr[@]}" | sed 's/^ *//;s/ *$//' | awk 'length($0)>0 && !s[$0]++')
cfg=$(jq -r --argjson a "$(printf '%s\n' "${clean[@]}"|jq -R .|jq -s .)" '.config=$a' "$CFG"); echo "$cfg" > "$CFG"

# certs
[ -f "$KEY" ] && [ -f "$CRT" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=zivpn" -keyout "$KEY" -out "$CRT" >/dev/null 2>&1

# service
cat >"$UNIT"<<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart=$BIN server -c $CFG
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now zivpn.service

# NAT + firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT} 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT}
ufw allow ${PORT_MIN}:${PORT_MAX}/udp || true
ufw allow ${LOCAL_PORT}/udp || true
ufw allow ${PANEL_PORT}/tcp || true

# ---------- Panel (Flask on :8088) ----------
mkdir -p "$APP_DIR"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q flask waitress python-dotenv

cat >"$ENVF"<<EOF
ADMIN_USER=$ADMIN_USER
ADMIN_PASSWORD=$ADMIN_PASS
BIND_HOST=0.0.0.0
BIND_PORT=$APP_PORT
ZIVPN_CONFIG=$CFG
ZIVPN_SERVICE=zivpn.service
EOF

cat >"$APP"<<'PY'
import os,json,subprocess,datetime,socket
from flask import Flask,request,jsonify
from dotenv import load_dotenv; load_dotenv()
U=os.getenv("ADMIN_USER","admin"); P=os.getenv("ADMIN_PASSWORD","pass")
CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json"); SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
app=Flask(__name__)
def ok(req): return req.headers.get("X-User")==U and req.headers.get("X-Pass")==P
@app.get("/api/info")
def info():
  if not ok(request): return ("unauthorized",401)
  s=subprocess.run(["/bin/systemctl","is-active",SVC],capture_output=True,text=True).stdout.strip()
  ip=socket.gethostbyname(socket.gethostname())
  return jsonify({"time":datetime.datetime.utcnow().isoformat()+"Z","service":s,"ips":[{"iface":"default","ip":ip}]})
@app.get("/api/accounts")
def acc():
  if not ok(request): return ("unauthorized",401)
  cfg=json.load(open(CFG))
  return jsonify([{"username":"-","password":pw,"expiresAt":"-","dayLeft":"-","status":"Active"} for pw in cfg.get("config",[])])
@app.post("/api/accounts")
def add():
  if not ok(request): return ("unauthorized",401)
  pw=(request.get_json() or {}).get("password","").strip()
  if not pw: return ("bad request",400)
  cfg=json.load(open(CFG))
  if pw not in cfg.get("config",[]): cfg["config"].append(pw); json.dump(cfg,open(CFG,"w"),indent=2)
  subprocess.run(["/bin/systemctl","restart",SVC])
  return jsonify({"ok":True})
@app.get("/")
def ui():
  return """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
  <title>ZIVPN Panel</title><link href='https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.violet.min.css' rel='stylesheet'></head>
  <body><main class=container><h3>ZIVPN Panel</h3>
  <article><header>Login headers (X-User / X-Pass)</header>
  <label>Admin User <input id=u value='""" + U + """'></label>
  <label>Admin Pass <input id=p value='""" + P + """'></label></article>
  <article><header>Server</header><pre id=info></pre></article>
  <article><header>Create</header><input id=pw placeholder='password'><button id=add>Add</button></article>
  <article><header>Accounts</header><table><thead><tr><th>User</th><th>Password (Day left)</th><th>Expired</th><th>Status</th></tr></thead><tbody id=rows></tbody></table></article>
  <script>
  async function call(path,method='GET',body=null){const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-User':u.value,'X-Pass':p.value},body:body?JSON.stringify(body):null});if(!r.ok)throw new Error(await r.text());return r.json();}
  async function refresh(){const i=await call('/api/info'); info.textContent=JSON.stringify(i,null,2); const a=await call('/api/accounts'); rows.innerHTML=a.map(r=>'<tr><td>-</td><td>1 day left</td><td>-</td><td>Active</td></tr>').join('');}
  add.onclick=async()=>{if(!pw.value.trim())return alert('enter pw'); await call('/api/accounts','POST',{password:pw.value.trim()}); pw.value=''; refresh();}; refresh();
  </script></main></body></html>"""
PY

cat >"$PUNIT"<<EOF
[Unit]
Description=ZIVPN Admin Panel (Flask)
After=network.target
[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENVF
ExecStart=$VENV/bin/waitress-serve --host=0.0.0.0 --port=$APP_PORT app:app
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now zivpn-admin.service

# ---------- Nginx TLS :81 (→ :8088) ----------
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$(hostname -I | awk '{print $1}')" -keyout "$CK" -out "$CC" >/dev/null 2>&1
cat >"$SITE"<<EOF
server {
  listen ${PANEL_PORT} ssl;
  server_name _;
  ssl_certificate $CC;
  ssl_certificate_key $CK;
  location / {
    proxy_pass http://127.0.0.1:${APP_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
  }
}
EOF
ln -sf "$SITE" /etc/nginx/sites-enabled/zivpn-panel
nginx -t
systemctl reload nginx

IP=$(hostname -I | awk '{print $1}')
echo "================================================="
echo "PANEL: https://${IP}:${PANEL_PORT}"
echo "LOGIN headers: X-User=${ADMIN_USER}  X-Pass=${ADMIN_PASS}"
echo "ZIVPN status: $(systemctl is-active zivpn || true)"
echo "PANEL status: $(systemctl is-active zivpn-admin || true)"
echo "================================================="
BASH
sudo chmod +x /root/go.sh
