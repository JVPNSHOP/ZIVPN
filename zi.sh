sudo tee /root/zi.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# =========================
# ZIVPN Full Installer (Server + Web Panel HTTPS:81)
# Tested: Ubuntu 20.04/22.04
# =========================

# ----- Vars -----
ZIVPN_VER="1.4.9"
ZIVPN_BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_${ZIVPN_VER}/udp-zivpn-linux-amd64"

APP_USER="zivpnadmin"
APP_DIR="/opt/zivpn-admin"
DATA_DIR="/var/lib/zivpn-admin"

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_KEY="${ZIVPN_DIR}/zivpn.key"
ZIVPN_CRT="${ZIVPN_DIR}/zivpn.crt"
ZIVPN_UNIT="/etc/systemd/system/zivpn.service"

PANEL_UNIT="/etc/systemd/system/zivpn-panel.service"
NGINX_SITE="/etc/nginx/sites-available/zivpn-panel"
CERT_KEY="/etc/ssl/private/zivpn-panel.key"
CERT_CRT="/etc/ssl/certs/zivpn-panel.crt"

# Ports
PORT_MIN=6000
PORT_MAX=19999
LOCAL_PORT=5667
PANEL_HTTP_PORT=81    # HTTPS

msg(){ echo -e "\033[1;32m>>> $*\033[0m"; }
err(){ echo -e "\033[1;31m!! $*\033[0m" >&2; }
need_root(){ [[ $EUID -eq 0 ]] || { err "Run as root: sudo bash $0"; exit 1; } }

# ----- Packages -----
install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl wget ca-certificates openssl ufw iptables iproute2 systemd jq \
                      nginx acl nodejs npm
}

# ----- ZIVPN server -----
install_zivpn(){
  mkdir -p "$ZIVPN_DIR"
  if [[ ! -f "$ZIVPN_BIN" ]]; then
    msg "Downloading ZIVPN ${ZIVPN_VER}"
    curl -fsSL "$ZIVPN_BIN_URL" -o "$ZIVPN_BIN"
    chmod +x "$ZIVPN_BIN"
  else
    msg "ZIVPN binary exists"
  fi

  if [[ ! -f "$ZIVPN_CFG" ]]; then
    msg "Creating default /etc/zivpn/config.json"
    cat >"$ZIVPN_CFG" <<JSON
{"config":["zi"],"listen":"0.0.0.0:${LOCAL_PORT}","loglevel":"info"}
JSON
  fi

  if [[ ! -f "$ZIVPN_KEY" || ! -f "$ZIVPN_CRT" ]]; then
    msg "Generating ZIVPN TLS cert"
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
      -subj "/C=US/ST=CA/L=LA/O=ZIVPN/OU=IT/CN=zivpn" \
      -keyout "$ZIVPN_KEY" -out "$ZIVPN_CRT"
    chmod 600 "$ZIVPN_KEY"
  fi

  msg "Socket buffer tuning"
  sysctl -w net.core.rmem_max=16777216 >/dev/null
  sysctl -w net.core.wmem_max=16777216 >/dev/null

  msg "Writing systemd unit for ZIVPN"
  cat >"$ZIVPN_UNIT" <<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${ZIVPN_DIR}
ExecStart=${ZIVPN_BIN} server -c ${ZIVPN_CFG}
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
}

set_passwords(){
  echo
  echo "ZIVPN Password list"
  read -rp "Enter passwords (comma separated). Press Enter for default 'zi': " input || true
  if [[ -n "${input:-}" ]]; then
    IFS=',' read -r -a arr <<<"$input"
  else
    arr=("zi")
  fi
  mapfile -t cleaned < <(printf '%s\n' "${arr[@]}" | sed 's/^ *//;s/ *$//' | awk 'length($0)>0 && !seen[$0]++')
  local cfg; cfg=$(jq -r --argjson a "$(printf '%s\n' "${cleaned[@]}" | jq -R . | jq -s .)" \
    '.config=$a' "$ZIVPN_CFG")
  echo "$cfg" > "$ZIVPN_CFG"
  msg "Updated ${ZIVPN_CFG} (passwords: ${#cleaned[@]})"
}

nat_firewall(){
  msg "UFW allow UDP ${PORT_MIN}-${PORT_MAX} and ${LOCAL_PORT}"
  ufw allow ${PORT_MIN}:${PORT_MAX}/udp || true
  ufw allow ${LOCAL_PORT}/udp || true

  msg "iptables REDIRECT PREROUTING → ${LOCAL_PORT}"
  local IFACE
  IFACE=$(ip -4 route ls default | awk '/default/ {print $5; exit}')
  if [[ -n "${IFACE:-}" ]]; then
    if ! iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT} 2>/dev/null; then
      iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT}
    fi
  else
    err "Default interface not found; NAT rule skipped."
  fi
}

start_zivpn(){
  systemctl enable --now zivpn.service
  sleep 1
  systemctl --no-pager --full status zivpn.service | sed -n '1,15p' || true
}

# ----- Panel -----
setup_user(){
  id -u "$APP_USER" &>/dev/null || useradd --system --shell /usr/sbin/nologin "$APP_USER"
  mkdir -p "$APP_DIR" "$DATA_DIR" "$APP_DIR/public"
  chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$DATA_DIR"
  setfacl -m u:$APP_USER:rw "$ZIVPN_CFG" || true
}

write_panel_server(){
  cat >"$APP_DIR/server.js" <<'JS'
const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const APP_PORT = 8080;
const DATA_DIR = '/var/lib/zivpn-admin';
const ACCOUNTS = path.join(DATA_DIR, 'accounts.json');
const ZIVPN_CFG = '/etc/zivpn/config.json';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_HASH = process.env.ADMIN_HASH || '';

if (!fs.existsSync(ACCOUNTS)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNTS, JSON.stringify({ accounts: [] }, null, 2));
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readJSON(p, fb){ try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch { return fb; } }
function writeJSON(p, o){ fs.writeFileSync(p, JSON.stringify(o,null,2)); }
function sudo(cmd,args){ return new Promise((res,rej)=>{
  execFile('/usr/bin/sudo',[cmd,...args],{timeout:15000},(e,so,se)=> e?rej(new Error(se||e.message)):res(so.trim()));
});}
function nics(){ const out=[]; Object.entries(os.networkInterfaces()).forEach(([n,ifs])=>{ (ifs||[]).forEach(i=>{ if(i.family==='IPv4'&&!i.internal) out.push({iface:n, ip:i.address});});}); return out; }
function daysLeft(iso){ const end=new Date(iso+'T23:59:59Z'); return Math.ceil((end-new Date())/86400000); }
function active(iso){ const t=new Date(); t.setHours(0,0,0,0); return new Date(iso)>=t; }
function rebuild(){
  const db=readJSON(ACCOUNTS,{accounts:[]});
  const pw=[...new Set(db.accounts.filter(a=>active(a.expiresAt)).map(a=>a.password.trim()).filter(Boolean))];
  const cur=readJSON(ZIVPN_CFG,{}); const next={...cur, config: pw}; writeJSON(ZIVPN_CFG,next);
}

function auth(req,res,next){
  const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):'';
  try{ req.user=jwt.verify(t,JWT_SECRET); next(); }catch{ return res.status(401).json({error:'unauthorized'});}
}

app.post('/api/auth/login', async (req,res)=>{
  const {username,password}=req.body||{};
  if(username!==ADMIN_USER) return res.status(401).json({error:'bad creds'});
  const ok=await bcrypt.compare(password||'', ADMIN_HASH);
  if(!ok) return res.status(401).json({error:'bad creds'});
  const token=jwt.sign({sub:username},JWT_SECRET,{expiresIn:'8h'});
  res.json({token});
});

app.get('/api/info', auth, async (req,res)=>{
  let svc='unknown'; try{ svc=await sudo('/bin/systemctl',['is-active','zivpn.service']); }catch{}
  res.json({ips:nics(), time:new Date().toISOString(), service:svc});
});

app.get('/api/accounts', auth, (req,res)=>{
  const db=readJSON(ACCOUNTS,{accounts:[]});
  res.json(db.accounts.map(a=>({username:a.username, password:a.password, expiresAt:a.expiresAt, dayLeft:daysLeft(a.expiresAt), status:active(a.expiresAt)?'Active':'Expired'})));
});

app.post('/api/accounts', auth, (req,res)=>{
  const {username,password,expiresAt}=req.body||{};
  if(!username||!password||!expiresAt) return res.status(400).json({error:'username, password, expiresAt required'});
  const db=readJSON(ACCOUNTS,{accounts:[]});
  if (db.accounts.find(x=>x.username===username)) return res.status(409).json({error:'username exists'});
  db.accounts.push({username,password,expiresAt});
  writeJSON(ACCOUNTS,db); rebuild(); sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});
  res.json({ok:true});
});

app.delete('/api/accounts/:username', auth, (req,res)=>{
  const {username}=req.params;
  const db=readJSON(ACCOUNTS,{accounts:[]}); db.accounts=db.accounts.filter(x=>x.username!==username);
  writeJSON(ACCOUNTS,db); rebuild(); sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});
  res.json({ok:true});
});

app.listen(APP_PORT, ()=>console.log('ZIVPN panel API :'+APP_PORT));
JS
}

write_panel_ui(){
  cat >"$APP_DIR/public/index.html" <<'HTML'
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZIVPN Panel</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.violet.min.css">
<script src="https://unpkg.com/lucide@latest"></script>
<style>.tag{padding:.2rem .5rem;border-radius:999px;font-size:.8rem}.ok{background:#e6ffed;color:#137333}.bad{background:#ffe6e6;color:#b00020}.mono{font-family:ui-monospace,Menlo,monospace}</style>
</head><body>
<main class="container">
  <h3>ZIVPN Panel</h3>
  <article id="login">
    <header>Login</header>
    <label>Username <input id="u" value="admin"></label>
    <label>Password <input id="p" type="password"></label>
    <button id="btnLogin">Sign in</button>
  </article>

  <article id="dash" style="display:none">
    <header>Server</header>
    <div class="grid">
      <div><small>Run IP(s)</small><div id="ips" class="mono"></div></div>
      <div><small>Server Time</small><div id="time" class="mono"></div></div>
      <div><small>Service</small><div id="svc" class="mono"></div></div>
    </div>
  </article>

  <article id="create" style="display:none">
    <header>Create Account</header>
    <div class="grid">
      <label><span>Username</span><input id="cu" placeholder="user1"></label>
      <label><span>Password</span><input id="cp" placeholder="secret"></label>
      <label><span>Expire Date</span><input id="ce" type="date"></label>
    </div>
    <button id="btnCreate">Save</button>
    <small>Save ပြီးတာနဲ့ zivpn ကို auto-restart လုပ်ပြီး ချိတ်သုံးနိုင်ပါမယ်</small>
  </article>

  <article id="list" style="display:none">
    <header>Accounts</header>
    <table>
      <thead><tr><th>Username</th><th>Password (Day left)</th><th>Expired Date</th><th>Status</th><th></th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </article>
</main>
<script>
let T='';
async function call(p, m='GET', b=null){
  const r = await fetch(p,{method:m,headers:{'Content-Type':'application/json', ...(T?{'Authorization':'Bearer '+T}:{})}, body:b?JSON.stringify(b):null});
  if(!r.ok) throw new Error(await r.text());
  const ct=r.headers.get('content-type')||''; return ct.includes('json')?r.json():r.text();
}
function show(id,on=true){ document.getElementById(id).style.display=on?'block':'none'; }
async function login(){
  const u=document.getElementById('u').value, p=document.getElementById('p').value;
  const r=await call('/api/auth/login','POST',{username:u,password:p}); T=r.token;
  show('login',false); ['dash','create','list'].forEach(x=>show(x,true)); refresh();
}
async function refresh(){
  const info=await call('/api/info'); document.getElementById('ips').innerText=info.ips.map(x=>x.ip).join(', ');
  document.getElementById('time').innerText=new Date(info.time).toLocaleString();
  document.getElementById('svc').innerText=info.service;
  const rows=await call('/api/accounts'); const tb=document.getElementById('rows'); tb.innerHTML='';
  rows.forEach(r=>{
    const tr=document.createElement('tr');
    tr.innerHTML=\`<td>\${r.username}</td><td>\${r.dayLeft} days left</td><td>\${r.expiresAt}</td>
      <td><span class="tag \${r.status==='Active'?'ok':'bad'}">\${r.status}</span></td>
      <td><button data-u="\${r.username}" class="del">Delete</button></td>\`;
    tb.appendChild(tr);
  });
  document.querySelectorAll('button.del').forEach(b=>b.onclick=async e=>{
    const u=e.target.getAttribute('data-u'); if(!confirm('Delete '+u+' ?')) return;
    await call('/api/accounts/'+encodeURIComponent(u),'DELETE'); refresh();
  });
}
async function create(){
  const u=document.getElementById('cu').value, p=document.getElementById('cp').value, e=document.getElementById('ce').value;
  if(!u||!p||!e) return alert('fill all');
  await call('/api/accounts','POST',{username:u,password:p,expiresAt:e});
  document.getElementById('cu').value=''; document.getElementById('cp').value=''; document.getElementById('ce').value='';
  refresh();
}
document.getElementById('btnLogin').onclick=login;
document.getElementById('btnCreate').onclick=create;
</script>
</body></html>
HTML
}

npm_deps(){
  cd "$APP_DIR"
  npm init -y >/dev/null
  npm i express jsonwebtoken bcryptjs >/dev/null
  chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
}

panel_service(){
  # prompt admin
  echo
  read -p "Admin username [admin]: " AU; AU=${AU:-admin}
  read -s -p "Admin password: " AP; echo
  local HASH
  HASH=$(node -e "console.log(require('bcryptjs').hashSync(process.argv[1],10))" "$AP")

  cat >"$PANEL_UNIT" <<EOF
[Unit]
Description=ZIVPN Panel API
After=network.target

[Service]
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=NODE_ENV=production
Environment=JWT_SECRET=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 24)
Environment=ADMIN_USER=$AU
Environment=ADMIN_HASH=$HASH
ExecStart=/usr/bin/node $APP_DIR/server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now zivpn-panel.service
}

nginx_https81(){
  # self-signed cert
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -subj "/CN=$(hostname -I | awk '{print $1}')" \
    -keyout "$CERT_KEY" -out "$CERT_CRT" >/dev/null 2>&1

  cat >"$NGINX_SITE" <<EOF
server {
    listen ${PANEL_HTTP_PORT} ssl;
    server_name _;

    ssl_certificate     $CERT_CRT;
    ssl_certificate_key $CERT_KEY;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF

  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/zivpn-panel
  nginx -t
  systemctl reload nginx
  ufw allow ${PANEL_HTTP_PORT}/tcp || true
}

show_finish(){
  local IP; IP=$(hostname -I | awk '{print $1}')
  echo
  echo "================= DONE ================="
  echo "ZIVPN:   $(systemctl is-active zivpn.service 2>/dev/null || echo unknown)"
  echo "PANEL:   https://${IP}:${PANEL_HTTP_PORT}"
  echo "Note: Browser will warn (self-signed TLS)."
  echo "Logs:   journalctl -u zivpn -n 50 --no-pager"
  echo "        journalctl -u zivpn-panel -n 50 --no-pager"
  echo "========================================"
}

main(){
  need_root
  msg "Installing packages"; install_pkgs
  msg "Installing ZIVPN server"; install_zivpn
  msg "Set passwords into config"; set_passwords
  msg "NAT & firewall"; nat_firewall
  msg "Start ZIVPN"; start_zivpn

  msg "Create panel user & files"; setup_user
  msg "Write panel backend"; write_panel_server
  msg "Write panel UI"; write_panel_ui
  msg "Install NPM deps"; npm_deps
  msg "Create systemd for panel"; panel_service
  msg "Configure Nginx HTTPS :${PANEL_HTTP_PORT}"; nginx_https81

  show_finish
}

main "$@"
BASH
