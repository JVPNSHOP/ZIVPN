sudo tee /root/install-zivpn-panel.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

APP_USER="zivpnadmin"
APP_DIR="/opt/zivpn-admin"
DATA_DIR="/var/lib/zivpn-admin"
UNIT="/etc/systemd/system/zivpn-panel.service"
NGINX_SITE="/etc/nginx/sites-available/zivpn-panel"
CERT_KEY="/etc/ssl/private/zivpn-panel.key"
CERT_CRT="/etc/ssl/certs/zivpn-panel.crt"

echo ">>> 1) Packages"
apt-get update -y
apt-get install -y nodejs npm nginx acl

echo ">>> 2) App user & dirs"
id -u $APP_USER &>/dev/null || useradd --system --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" "$DATA_DIR" "$APP_DIR/public"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$DATA_DIR"

echo ">>> 3) Sudoers for limited systemctl/journalctl"
cat >/etc/sudoers.d/zivpn-admin <<'EOF'
Defaults:zivpnadmin !requiretty
Cmnd_Alias ZIVPN_CMDS = /bin/systemctl start zivpn.service, \
  /bin/systemctl stop zivpn.service, \
  /bin/systemctl restart zivpn.service, \
  /bin/systemctl is-active zivpn.service, \
  /bin/journalctl -u zivpn -n 200 --no-pager
zivpnadmin ALL=(root) NOPASSWD: ZIVPN_CMDS
EOF
chmod 440 /etc/sudoers.d/zivpn-admin

echo ">>> 4) Allow app to read/write /etc/zivpn/config.json"
setfacl -m u:$APP_USER:rw /etc/zivpn/config.json || true

echo ">>> 5) Backend code"
cat >"$APP_DIR/server.js" <<'JS'
const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const bcrypt = require('bcryptjs'); // pure JS
const jwt = require('jsonwebtoken');

const APP_PORT = 8080;
const DATA_DIR = '/var/lib/zivpn-admin';
const ACCOUNTS_PATH = path.join(DATA_DIR, 'accounts.json');
const ZIVPN_CONFIG = '/etc/zivpn/config.json';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_HASH = process.env.ADMIN_HASH || '';

if (!fs.existsSync(ACCOUNTS_PATH)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNTS_PATH, JSON.stringify({ accounts: [] }, null, 2));
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function readJSON(p, fb) { try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch { return fb; } }
function writeJSON(p, o) { fs.writeFileSync(p, JSON.stringify(o,null,2)); }
function sudo(cmd,args){ return new Promise((res,rej)=>{
  execFile('/usr/bin/sudo',[cmd,...args],{timeout:15000},(e,so,se)=> e?rej(new Error(se||e.message)):res(so.trim()));
});}
function getIPs(){
  const out=[]; const nics=os.networkInterfaces();
  Object.entries(nics).forEach(([name,ifs])=>{
    (ifs||[]).forEach(i=>{ if(i.family==='IPv4' && !i.internal) out.push({iface:name, ip:i.address}); });
  });
  return out;
}
function daysLeft(iso){ const end=new Date(iso+'T23:59:59Z'); const now=new Date(); return Math.ceil((end-now)/86400000); }
function isActive(iso){ const today=new Date(); today.setHours(0,0,0,0); return new Date(iso)>=today; }
function rebuildConfig(){
  const db=readJSON(ACCOUNTS_PATH,{accounts:[]});
  const activePw=[...new Set(db.accounts.filter(a=>isActive(a.expiresAt)).map(a=>a.password.trim()).filter(Boolean))];
  const cur=readJSON(ZIVPN_CONFIG, {});
  const next={...cur, config: activePw};
  writeJSON(ZIVPN_CONFIG, next);
}

function auth(req,res,next){
  const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):'';
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'unauthorized'}); }
}

app.post('/api/auth/login', async (req,res)=>{
  const {username,password}=req.body||{};
  if (username!==ADMIN_USER) return res.status(401).json({error:'bad creds'});
  const ok = await bcrypt.compare(password||'', ADMIN_HASH);
  if (!ok) return res.status(401).json({error:'bad creds'});
  const token = jwt.sign({sub:username}, JWT_SECRET, {expiresIn:'8h'});
  res.json({token});
});

app.get('/api/info', auth, async (req,res)=>{
  let svc='unknown'; try { svc=await sudo('/bin/systemctl',['is-active','zivpn.service']); } catch {}
  res.json({ips:getIPs(), time:new Date().toISOString(), service:svc});
});

app.get('/api/accounts', auth, (req,res)=>{
  const db=readJSON(ACCOUNTS_PATH,{accounts:[]});
  res.json(db.accounts.map(a=>({username:a.username, password:a.password, expiresAt:a.expiresAt, dayLeft:daysLeft(a.expiresAt), status:isActive(a.expiresAt)?'Active':'Expired'})));
});

app.post('/api/accounts', auth, (req,res)=>{
  const {username,password,expiresAt}=req.body||{};
  if(!username||!password||!expiresAt) return res.status(400).json({error:'username, password, expiresAt required'});
  const db=readJSON(ACCOUNTS_PATH,{accounts:[]});
  if (db.accounts.find(x=>x.username===username)) return res.status(409).json({error:'username exists'});
  db.accounts.push({username,password,expiresAt});
  writeJSON(ACCOUNTS_PATH,db); rebuildConfig(); sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});
  res.json({ok:true});
});

app.put('/api/accounts/:username', auth, (req,res)=>{
  const {username}=req.params; const {password,expiresAt}=req.body||{};
  const db=readJSON(ACCOUNTS_PATH,{accounts:[]}); const i=db.accounts.findIndex(x=>x.username===username);
  if(i<0) return res.status(404).json({error:'not found'});
  if(password) db.accounts[i].password=password;
  if(expiresAt) db.accounts[i].expiresAt=expiresAt;
  writeJSON(ACCOUNTS_PATH,db); rebuildConfig(); sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});
  res.json({ok:true});
});

app.delete('/api/accounts/:username', auth, (req,res)=>{
  const {username}=req.params;
  const db=readJSON(ACCOUNTS_PATH,{accounts:[]}); db.accounts=db.accounts.filter(x=>x.username!==username);
  writeJSON(ACCOUNTS_PATH,db); rebuildConfig(); sudo('/bin/systemctl',['restart','zivpn.service']).catch(()=>{});
  res.json({ok:true});
});

app.get('/api/logs', auth, async (req,res)=>{
  try { const out=await sudo('/bin/journalctl',['-u','zivpn','-n','200','--no-pager']); res.type('text/plain').send(out); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.listen(APP_PORT, ()=>console.log('ZIVPN panel API :'+APP_PORT));
JS

echo ">>> 6) Minimal Web UI"
cat >"$APP_DIR/public/index.html" <<'HTML'
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZIVPN Panel</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.violet.min.css">
<script src="https://unpkg.com/lucide@latest"></script>
<style>
  .tag{padding:.2rem .5rem;border-radius:999px;font-size:.8rem}
  .ok{background:#e6ffed;color:#137333}.bad{background:#ffe6e6;color:#b00020}
  .mono{font-family:ui-monospace,Menlo,monospace}
</style>
</head><body>
<main class="container">
  <h3>ZIVPN Panel</h3>
  <article id="loginCard">
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
function show(id, on=true){ document.getElementById(id).style.display=on?'block':'none'; }

async function login(){
  const u=document.getElementById('u').value; const p=document.getElementById('p').value;
  const r=await call('/api/auth/login','POST',{username:u,password:p}); T=r.token;
  show('loginCard',false); show('dash',true); show('create',true); show('list',true); refresh();
}
async function refresh(){
  const info=await call('/api/info'); document.getElementById('ips').innerText=info.ips.map(x=>x.ip).join(', ');
  document.getElementById('time').innerText=new Date(info.time).toLocaleString(); document.getElementById('svc').innerText=info.service;
  const rows=await call('/api/accounts'); const tb=document.getElementById('rows'); tb.innerHTML='';
  rows.forEach(r=>{
    const tr=document.createElement('tr');
    tr.innerHTML=\`
      <td>\${r.username}</td>
      <td>\${r.dayLeft} days left</td>
      <td>\${r.expiresAt}</td>
      <td><span class="tag \${r.status==='Active'?'ok':'bad'}">\${r.status}</span></td>
      <td><button data-user="\${r.username}" class="del">Delete</button></td>\`;
    tb.appendChild(tr);
  });
  document.querySelectorAll('button.del').forEach(b=>b.onclick=async e=>{
    const u=e.target.getAttribute('data-user'); if(!confirm('Delete '+u+' ?')) return;
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

echo ">>> 7) NPM deps"
cd "$APP_DIR"
npm init -y >/dev/null
npm i express jsonwebtoken bcryptjs >/dev/null

echo ">>> 8) Admin credential (prompt)"
read -p "Admin username [admin]: " AU; AU=${AU:-admin}
read -s -p "Admin password: " AP; echo
HASH=$(node -e "console.log(require('bcryptjs').hashSync(process.argv[1], 10))" "$AP")

echo ">>> 9) systemd unit"
cat >"$UNIT" <<EOF
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

echo ">>> 10) TLS cert (self-signed) & Nginx on :81"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -subj "/CN=$(hostname -I | awk '{print $1}')" \
  -keyout "$CERT_KEY" -out "$CERT_CRT" >/dev/null 2>&1

cat >"$NGINX_SITE" <<EOF
server {
    listen 81 ssl;
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
ufw allow 81/tcp || true

echo ">>> 11) Enable panel service"
systemctl daemon-reload
systemctl enable --now zivpn-panel.service

IP=$(hostname -I | awk '{print $1}')
echo "=============================================="
echo " ZIVPN PANEL is up!"
echo " URL: https://$IP:81"
echo " Login: $AU  (your password as entered)"
echo "----------------------------------------------"
echo " Note: Browser may warn about self-signed TLS."
echo "=============================================="
BASH
