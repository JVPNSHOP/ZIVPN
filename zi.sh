sudo tee /root/zi-auto.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# ======= Config via ENV (change if you like) =======
ADMIN_USER="${ADMIN_USER:-admin}"          # Panel login username
ADMIN_PASS="${ADMIN_PASS:-ChangeMeNow!}"   # Panel login password
ZIVPN_PASSWORDS="${ZIVPN_PASSWORDS:-zi}"   # comma-separated: eg "pass1,pass2"
PANEL_PORT="${PANEL_PORT:-81}"             # HTTPS port for panel

# ======= Vars =======
ZIVPN_VER="1.4.9"
BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_${ZIVPN_VER}/udp-zivpn-linux-amd64"
BIN_PATH="/usr/local/bin/zivpn"
CONF_DIR="/etc/zivpn"
CONF_PATH="${CONF_DIR}/config.json"
KEY_PATH="${CONF_DIR}/zivpn.key"
CRT_PATH="${CONF_DIR}/zivpn.crt"
UNIT="/etc/systemd/system/zivpn.service"
PORT_MIN=6000; PORT_MAX=19999; LOCAL_PORT=5667

APP_USER="zivpnadmin"
APP_DIR="/opt/zivpn-admin"; DATA_DIR="/var/lib/zivpn-admin"
PANEL_UNIT="/etc/systemd/system/zivpn-panel.service"
NGINX_SITE="/etc/nginx/sites-available/zivpn-panel"
CERT_KEY="/etc/ssl/private/zivpn-panel.key"
CERT_CRT="/etc/ssl/certs/zivpn-panel.crt"

msg(){ echo -e "\033[1;32m>>> $*\033[0m"; }
err(){ echo -e "\033[1;31m!! $*\033[0m" >&2; }
[[ $EUID -eq 0 ]] || { err "Run as root: sudo bash /root/zi-auto.sh"; exit 1; }

# ======= Packages =======
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget ca-certificates openssl ufw iptables iproute2 systemd jq nginx acl nodejs npm

# ======= ZIVPN server =======
mkdir -p "$CONF_DIR"
curl -fsSL "$BIN_URL" -o "$BIN_PATH"; chmod +x "$BIN_PATH"

# config.json
if [[ ! -f "$CONF_PATH" ]]; then
  echo "{\"config\":[\"zi\"],\"listen\":\"0.0.0.0:${LOCAL_PORT}\",\"loglevel\":\"info\"}" > "$CONF_PATH"
fi
# overwrite config "config" array from ZIVPN_PASSWORDS
IFS=',' read -r -a arr <<<"$ZIVPN_PASSWORDS"
mapfile -t cleaned < <(printf '%s\n' "${arr[@]}" | sed 's/^ *//;s/ *$//' | awk 'length($0)>0 && !seen[$0]++')
cfg=$(jq -r --argjson a "$(printf '%s\n' "${cleaned[@]}" | jq -R . | jq -s .)" '.config=$a' "$CONF_PATH")
echo "$cfg" > "$CONF_PATH"

# certs
if [[ ! -f "$KEY_PATH" || ! -f "$CRT_PATH" ]]; then
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/CN=zivpn" -keyout "$KEY_PATH" -out "$CRT_PATH"
  chmod 600 "$KEY_PATH"
fi

# kernel tune
sysctl -w net.core.rmem_max=16777216 >/dev/null
sysctl -w net.core.wmem_max=16777216 >/dev/null

# systemd unit
cat >"$UNIT" <<EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=${CONF_DIR}
ExecStart=${BIN_PATH} server -c ${CONF_PATH}
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

# firewall + NAT
ufw allow ${PORT_MIN}:${PORT_MAX}/udp || true
ufw allow ${LOCAL_PORT}/udp || true
IFACE=$(ip -4 route ls default | awk '/default/ {print $5; exit}')
if ! iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT} 2>/dev/null; then
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport ${PORT_MIN}:${PORT_MAX} -j REDIRECT --to-ports ${LOCAL_PORT}
fi
systemctl enable --now zivpn.service

# ======= Panel (backend + ui) =======
id -u "$APP_USER" &>/dev/null || useradd --system --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" "$DATA_DIR" "$APP_DIR/public"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$DATA_DIR"
setfacl -m u:$APP_USER:rw "$CONF_PATH" || true

# backend
cat >"$APP_DIR/server.js" <<'JS'
const express=require('express'),fs=require('fs'),os=require('os'),path=require('path'),{execFile}=require('child_process');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
const APP_PORT=8080,DATA_DIR='/var/lib/zivpn-admin',ACCOUNTS=path.join(DATA_DIR,'accounts.json'),ZIVPN_CFG='/etc/zivpn/config.json';
const JWT_SECRET=process.env.JWT_SECRET||'change-me',ADMIN_USER=process.env.ADMIN_USER||'admin',ADMIN_HASH=process.env.ADMIN_HASH||'';
if(!fs.existsSync(ACCOUNTS)){fs.mkdirSync(DATA_DIR,{recursive:true});fs.writeFileSync(ACCOUNTS,JSON.stringify({accounts:[]},null,2));}
const app=express();app.use(express.json());app.use(express.static(path.join(__dirname,'public')));
const R=p=>JSON.parse(fs.readFileSync(p,'utf8')); const W=(p,o)=>fs.writeFileSync(p,JSON.stringify(o,null,2));
const sudo=(c,a)=>new Promise((res,rej)=>execFile('/usr/bin/sudo',[c,...a],{timeout:15000},(e,so,se)=>e?rej(new Error(se||e.message)):res(so.trim())));
const nics=()=>{const out=[];Object.entries(os.networkInterfaces()).forEach(([n,ifs])=>(ifs||[]).forEach(i=>{if(i.family==='IPv4'&&!i.internal)out.push({iface:n,ip:i.address});}));return out;}
const dleft=i=>Math.ceil((new Date(i+'T23:59:59Z')-new Date())/86400000);
const active=i=>{const t=new Date();t.setHours(0,0,0,0);return new Date(i)>=t;}
function rebuild(){const db=R(ACCOUNTS);const pw=[...new Set(db.accounts.filter(a=>active(a.expiresAt)).map(a=>a.password.trim()).filter(Boolean))];const cur=R(ZIVPN_CFG);W(ZIVPN_CFG,{...cur,config:pw});}
function auth(req,res,next){const h=req.headers.authorization||'';const t=h.startsWith('Bearer ')?h.slice(7):'';try{req.user=jwt.verify(t,JWT_SECRET);next();}catch{return res.status(401).json({error:'unauthorized'});}}
app.post('/api/auth/login',async (req,res)=>{const{username,password}=req.body||{};if(username!==ADMIN_USER)return res.status(401).json({error:'bad creds'});const ok=await bcrypt.compare(password||'',ADMIN_HASH);if(!ok)return res.status(401).json({error:'bad creds'});res.json({token:jwt.sign({sub:username},JWT_SECRET,{expiresIn:'8h'})});});
app.get('/api/info',auth,async (req,res)=>{let s='unknown';try{s=await sudo('/bin/systemctl',['is-active','zivpn.service']);}catch{}res.json({ips:nics(),time:new Date().toISOString(),service:s});});
app.get('/api/accounts',auth,(req,res)=>{const db=R(ACCOUNTS);res.json(db.accounts.map(a=>({username:a.username,password:a.password,expiresAt:a.expiresAt,dayLeft:dleft(a.expiresAt),status:active(a.expiresAt)?'Active':'Expired'})));});
app.post('/api/accounts',auth,(req,res)=>{const{username,password,expiresAt}=req.body||{};if(!username||!password||!expiresAt)return res.status(400).json({error:'username, password, expiresAt required'});const db=R(ACCOUNTS);if(db.accounts.find(x=>x.username===username))return res.status(409).json({error:'username exists'});db.accounts.push({username,password,expiresAt});W(ACCOUNTS,db);rebuild();sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});res.json({ok:true});});
app.delete('/api/accounts/:username',auth,(req,res)=>{const u=req.params.username;const db=R(ACCOUNTS);db.accounts=db.accounts.filter(x=>x.username!==u);W(ACCOUNTS,db);rebuild();sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});res.json({ok:true});});
app.listen(8080,()=>console.log('ZIVPN panel API :8080'));
JS

# ui
cat >"$APP_DIR/public/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZIVPN Panel</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.violet.min.css">
<style>.tag{padding:.2rem .5rem;border-radius:999px;font-size:.8rem}.ok{background:#e6ffed;color:#137333}.bad{background:#ffe6e6;color:#b00020}.mono{font-family:ui-monospace,Menlo,monospace}</style></head>
<body><main class="container">
<h3>ZIVPN Panel</h3>
<article id="login"><header>Login</header><label>Username <input id="u" value="admin"></label><label>Password <input id="p" type="password"></label><button id="btnLogin">Sign in</button></article>
<article id="dash" style="display:none"><header>Server</header><div class="grid"><div><small>Run IP(s)</small><div id="ips" class="mono"></div></div><div><small>Server Time</small><div id="time" class="mono"></div></div><div><small>Service</small><div id="svc" class="mono"></div></div></div></article>
<article id="create" style="display:none"><header>Create Account</header><div class="grid"><label>Username<input id="cu"></label><label>Password<input id="cp"></label><label>Expire Date<input id="ce" type="date"></label></div><button id="btnCreate">Save</button></article>
<article id="list" style="display:none"><header>Accounts</header><table><thead><tr><th>Username</th><th>Password (Day left)</th><th>Expired Date</th><th>Status</th><th></th></tr></thead><tbody id="rows"></tbody></table></article>
</main><script>
let T='';async function call(p,m='GET',b=null){const r=await fetch(p,{method:m,headers:{'Content-Type':'application/json',...(T?{'Authorization':'Bearer '+T}:{})},body:b?JSON.stringify(b):null});if(!r.ok)throw new Error(await r.text());const ct=r.headers.get('content-type')||'';return ct.includes('json')?r.json():r.text();}
function sh(id,on=true){document.getElementById(id).style.display=on?'block':'none';}
async function login(){const u=document.getElementById('u').value,p=document.getElementById('p').value;const r=await call('/api/auth/login','POST',{username:u,password:p});T=r.token;sh('login',false);['dash','create','list'].forEach(x=>sh(x,true));refresh();}
async function refresh(){const i=await call('/api/info');document.getElementById('ips').innerText=i.ips.map(x=>x.ip).join(', ');document.getElementById('time').innerText=new Date(i.time).toLocaleString();document.getElementById('svc').innerText=i.service;const rows=await call('/api/accounts');const tb=document.getElementById('rows');tb.innerHTML='';rows.forEach(r=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${r.username}</td><td>${r.dayLeft} days left</td><td>${r.expiresAt}</td><td><span class="tag ${r.status==='Active'?'ok':'bad'}">${r.status}</span></td><td><button data-u="${r.username}" class="del">Delete</button></td>`;tb.appendChild(tr);});document.querySelectorAll('button.del').forEach(b=>b.onclick=async e=>{const u=e.target.getAttribute('data-u');if(!confirm('Delete '+u+' ?')) return;await call('/api/accounts/'+encodeURIComponent(u),'DELETE');refresh();});}
async function create(){const u=document.getElementById('cu').value,p=document.getElementById('cp').value,e=document.getElementById('ce').value;if(!u||!p||!e)return alert('fill all');await call('/api/accounts','POST',{username:u,password:p,expiresAt:e});document.getElementById('cu').value='';document.getElementById('cp').value='';document.getElementById('ce').value='';refresh();}
document.getElementById('btnLogin').onclick=login;document.getElementById('btnCreate').onclick=create;
</script></body></html>
HTML

# deps
cd "$APP_DIR"; npm init -y >/dev/null; npm i express jsonwebtoken bcryptjs >/dev/null
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

# systemd for panel
HASH=$(node -e "console.log(require('bcryptjs').hashSync(process.argv[1],10))" "$ADMIN_PASS")
cat >"$PANEL_UNIT" <<EOF
[Unit]
Description=ZIVPN Panel API
After=network.target
[Service]
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=NODE_ENV=production
Environment=JWT_SECRET=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 24)
Environment=ADMIN_USER=$ADMIN_USER
Environment=ADMIN_HASH=$HASH
ExecStart=/usr/bin/node $APP_DIR/server.js
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now zivpn-panel.service

# nginx https :81 (default)
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$(hostname -I | awk '{print $1}')" -keyout "$CERT_KEY" -out "$CERT_CRT" >/dev/null 2>&1
cat >"$NGINX_SITE" <<EOF
server {
  listen ${PANEL_PORT} ssl;
  server_name _;
  ssl_certificate $CERT_CRT;
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
nginx -t && systemctl reload nginx
ufw allow ${PANEL_PORT}/tcp || true

IP=$(hostname -I | awk '{print $1}')
echo -e "\n=========== READY ==========="
echo "PANEL:   https://${IP}:${PANEL_PORT} (self-signed TLS)"
echo "LOGIN:   ${ADMIN_USER} / ${ADMIN_PASS}"
echo "ZIVPN:   $(systemctl is-active zivpn.service || true)"
echo "PANEL:   $(systemctl is-active zivpn-panel.service || true)"
echo "Logs:    journalctl -u zivpn-panel -n 50 --no-pager"
echo "============================="
BASH
