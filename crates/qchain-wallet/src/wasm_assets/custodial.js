const $ = id => document.getElementById(id);
let WALLETS = [];
let active = localStorage.getItem("qchain_active") || null;
let lastListSig = "";

function toast(t){ const e=$("toast"); e.textContent=t; e.classList.add("show"); setTimeout(()=>e.classList.remove("show"),1300); }
// HTML-escape before folding node/user data into innerHTML. A no-op for base58
// addresses and [A-Za-z0-9_-] server-sanitised wallet names (they contain none
// of these chars), so display is unchanged for all real data — defense-in-depth.
function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function short(s){ return (s&&s.length>18)? s.slice(0,10)+"…"+s.slice(-6) : (s||""); }
function copy(t){ navigator.clipboard.writeText(t).then(()=>toast("copiado")); }
function initials(n){ return (n||"?").slice(0,2).toUpperCase(); }

// dinero exacto (BigInt), 1 QCH = 1e9 unidades
function qchToUnits(s){ s=(s||"").trim().replace(",","."); if(!/^\d+(\.\d+)?$/.test(s)) throw new Error("monto inválido");
  let [i,f=""]=s.split("."); f=(f+"000000000").slice(0,9); return (BigInt(i)*1000000000n+BigInt(f)).toString(); }
function unitsToQch(u){ u=BigInt(u); const i=u/1000000000n; let f=(u%1000000000n).toString().padStart(9,"0").replace(/0+$/,""); return f?`${i}.${f}`:i.toString(); }
function fmt(s){ return s.replace(/\B(?=(\d{3})+(?!\d))/g,"."); }
function qchDisp(u){ const q=unitsToQch(u); const [i,f]=q.split("."); return fmt(i)+(f?","+f:"")+" QCH"; }

async function api(path, opts){ const r=await fetch(path,opts); const b=await r.json().catch(()=>({})); if(!r.ok) throw new Error(b.error||("error "+r.status)); return b; }

function showView(name){
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  $("v-"+name).classList.add("active");
  window.scrollTo(0,0);
  if(name==="home") renderHome();
  if(name==="receive") renderReceive();
  if(name==="send") renderSend();
  if(name==="settings") renderSettings();
}
document.querySelectorAll(".nav").forEach(el=>el.addEventListener("click",()=>showView(el.dataset.to)));

// --- tema claro / oscuro / auto ---
function resolveTheme(setting){ return setting==="auto" ? (window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark") : setting; }
function applyTheme(setting){
  localStorage.setItem("qchain_theme", setting);
  document.documentElement.dataset.theme = resolveTheme(setting);
  document.querySelectorAll("#theme-seg button").forEach(b=>b.classList.toggle("on", b.dataset.themeSet===setting));
}
// seguir el sistema en vivo cuando está en "auto"
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change",()=>{
  if((localStorage.getItem("qchain_theme")||"dark")==="auto") applyTheme("auto");
});
document.querySelectorAll("#theme-seg button").forEach(b=>b.addEventListener("click",()=>applyTheme(b.dataset.themeSet)));

// --- descarga de respaldo (compartida por crear y configuración) ---
async function downloadBackup(name, pass, msgEl){
  msgEl.className="msg"; msgEl.textContent="";
  if(pass.length<6){ msgEl.className="msg err"; msgEl.textContent="la contraseña debe tener al menos 6 caracteres"; return; }
  try{
    const r=await fetch("/api/export-encrypted",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name,password:pass})});
    if(!r.ok){ const b=await r.json().catch(()=>({})); throw new Error(b.error||"error"); }
    const blob=await r.blob(), url=URL.createObjectURL(blob), a=document.createElement("a");
    a.href=url; a.download=name+".qchain-keystore.json"; a.click(); URL.revokeObjectURL(url);
    msgEl.className="msg ok"; msgEl.textContent="✓ respaldo descargado. Guardalo junto con su contraseña.";
  }catch(e){ msgEl.className="msg err"; msgEl.textContent=e.message; }
}

async function renderSettings(){
  const w=activeWallet(); if(!w){ showView("welcome"); return; }
  applyTheme(localStorage.getItem("qchain_theme")||"dark");
  $("set-wallet-name").textContent=w.name;
  $("set-wallet-addr").textContent=w.address;
  try{ const cfg=await api("/api/config"); $("set-rpc").textContent=cfg.rpc.replace(/^https?:\/\//,""); }catch(e){}
  try{ const st=await api("/api/node"); const on=st.online!==false;
    $("set-ver").textContent=on?("v"+st.version):"—"; $("set-appver").textContent=on?("v"+st.version):"—";
    $("set-status").innerHTML=on?'<span style="color:var(--good)">en vivo</span>':'<span style="color:var(--bad)">sin conexión</span>';
  }catch(e){}
}
$("set-download").onclick=()=>{ const w=activeWallet(); if(w) downloadBackup(w.name, $("set-pass").value, $("set-msg")); };
$("set-plain").onclick=e=>{ e.preventDefault(); const w=activeWallet(); if(w) window.location.href="/api/export/"+encodeURIComponent(w.name); };
$("set-logout").onclick=()=>{
  localStorage.removeItem("qchain_active"); active=null; lastListSig=""; lastActivitySig="";
  toast("sesión cerrada"); showView("welcome");
};

function activeWallet(){ return WALLETS.find(w=>w.name===active) || WALLETS[0] || null; }

async function loadWallets(){
  try{ WALLETS = await api("/api/wallets"); }catch(e){ WALLETS=[]; }
  if(WALLETS.length && !WALLETS.some(w=>w.name===active)){ active = WALLETS[0].name; localStorage.setItem("qchain_active",active); }
}

async function loadNode(){
  try{
    const st=await api("/api/node");
    if(st.online===false) throw 0;
    $("dot").className="dot ok"; $("node-text").textContent=`en vivo · v${st.version}`;
  }catch(e){ $("dot").className="dot bad"; $("node-text").textContent="sin conexión"; }
}

function renderHome(){
  const w=activeWallet();
  if(!w){ showView("welcome"); return; }
  $("h-name").textContent=w.name;
  $("h-balance").textContent=qchDisp(w.balance);
  $("h-addr").textContent=short(w.address);
  $("h-copy").onclick=()=>copy(w.address);

  const box=$("wallets-list");
  // Igual que la actividad: redibujar la lista de wallets solo si cambió
  // (nombres, saldos o cuál está activa), para no parpadear en cada refresco.
  const listSig=active+"|"+WALLETS.map(x=>x.name+":"+x.balance).join(",");
  if(listSig!==lastListSig){
    lastListSig=listSig;
    box.innerHTML = WALLETS.map(x=>`
      <div class="wallet-item" data-name="${esc(x.name)}">
        <div class="wi-ic">${esc(initials(x.name))}</div>
        <div class="wi-main"><div class="wi-name">${esc(x.name)}</div><div class="wi-addr">${esc(short(x.address))}</div></div>
        <div class="wi-bal">${qchDisp(x.balance)} ${x.name===active?'<span class="wi-check">✓</span>':''}</div>
      </div>`).join("");
    box.querySelectorAll(".wallet-item").forEach(el=>el.onclick=()=>{
      active=el.dataset.name; localStorage.setItem("qchain_active",active); renderHome();
    });
  }
  renderActivity(w.address);
}

let lastActivitySig="";
async function renderActivity(addr){
  const box=$("activity");
  let txs;
  try{ txs=await api("/api/transfers"); }catch(e){ return; } // ante un error de red no borramos lo que ya se ve
  const mine=txs.filter(t=>t.from===addr||t.to===addr).slice(0,15);
  // Solo tocamos el DOM si la actividad cambió de verdad; si no, evitamos el
  // "apagón"/parpadeo de reescribir la lista idéntica cada pocos segundos.
  const sig=addr+"|"+mine.map(t=>t.tx_hash).join(",");
  if(sig===lastActivitySig) return;
  lastActivitySig=sig;
  if(!mine.length){ box.innerHTML='<div class="empty">sin movimientos todavía</div>'; return; }
  box.innerHTML=mine.map(t=>{
    const inc=t.to===addr;
    return `<div class="tx">
      <div class="tx-ic ${inc?'tx-in':'tx-out'}">${inc?'↓':'↑'}</div>
      <div class="tx-main"><div class="tx-t">${inc?'Recibido':'Enviado'}</div>
        <div class="tx-s">${inc?'de '+esc(short(t.from)):'a '+esc(short(t.to))}</div></div>
      <div class="tx-amt ${inc?'in':'out'}">${inc?'+':'−'}${qchDisp(t.amount)}</div>
    </div>`;
  }).join("");
}

function renderReceive(){
  const w=activeWallet(); if(!w) return;
  $("qr-img").src="/api/qr/"+encodeURIComponent(w.address);
  $("r-addr").textContent=w.address;
  $("r-copy").onclick=()=>copy(w.address);
}

function renderSend(){
  const w=activeWallet(); if(!w) return;
  $("s-from-name").textContent=w.name;
  $("s-from-addr").textContent=w.address;
  $("s-fee").textContent="El fee de red se calcula solo al enviar.";
  $("s-amount").value=""; $("s-to").value="";
  const pick=$("s-to-pick");
  pick.innerHTML=`<option value="">— o elegí una de mis wallets —</option>`+WALLETS.filter(x=>x.name!==w.name).map(x=>`<option value="${esc(x.address)}">${esc(x.name)} — ${esc(short(x.address))}</option>`).join("");
  const msg=$("s-msg"); msg.className="msg"; msg.textContent="";
}
$("s-to-pick").onchange=e=>{ if(e.target.value) $("s-to").value=e.target.value; };

// crear
$("c-btn").onclick=async()=>{
  const name=$("c-name").value.trim(); const msg=$("c-msg"); msg.className="msg"; msg.textContent="";
  if(!name){ msg.className="msg err"; msg.textContent="poné un nombre"; return; }
  $("c-btn").disabled=true;
  try{
    const w=await api("/api/wallets",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name})});
    await loadWallets(); active=w.name; localStorage.setItem("qchain_active",active);
    $("cd-addr").textContent=w.address;
    $("cd-copy").onclick=()=>copy(w.address);
    $("create-form").style.display="none"; $("create-done").style.display="block";
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("c-btn").disabled=false;
};

// descargar respaldo protegido con contraseña (keystore cifrado)
$("cd-download").onclick=async()=>{
  const w=activeWallet(); if(!w) return;
  const pass=$("cd-pass").value; const msg=$("cd-msg"); msg.className="msg"; msg.textContent="";
  if(pass.length<6){ msg.className="msg err"; msg.textContent="la contraseña debe tener al menos 6 caracteres"; return; }
  $("cd-download").disabled=true;
  try{
    const r=await fetch("/api/export-encrypted",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:w.name,password:pass})});
    if(!r.ok){ const b=await r.json().catch(()=>({})); throw new Error(b.error||"error"); }
    const blob=await r.blob(), url=URL.createObjectURL(blob), a=document.createElement("a");
    a.href=url; a.download=w.name+".qchain-keystore.json"; a.click(); URL.revokeObjectURL(url);
    msg.className="msg ok"; msg.textContent="✓ respaldo descargado. Guardalo bien junto con su contraseña.";
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("cd-download").disabled=false;
};
$("cd-plain").onclick=e=>{ e.preventDefault(); const w=activeWallet(); if(w) window.location.href="/api/export/"+encodeURIComponent(w.name); };

// importar
$("i-file").onchange=async e=>{ const f=e.target.files[0]; if(f) $("i-key").value=await f.text(); };
$("i-btn").onclick=async()=>{
  const name=$("i-name").value.trim(), keypair=$("i-key").value.trim(), password=$("i-pass").value; const msg=$("i-msg"); msg.className="msg"; msg.textContent="";
  if(!name){ msg.className="msg err"; msg.textContent="poné un nombre"; return; }
  if(!keypair){ msg.className="msg err"; msg.textContent="subí o pegá tu archivo de respaldo"; return; }
  $("i-btn").disabled=true;
  try{
    const w=await api("/api/import",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name,keypair,password})});
    await loadWallets(); active=w.name; localStorage.setItem("qchain_active",active);
    toast("wallet importada"); showView("home");
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("i-btn").disabled=false;
};

// máximo
$("s-max").onclick=async()=>{
  const w=activeWallet(); if(!w) return;
  $("s-max").disabled=true;
  try{
    const r=await api("/api/max/"+encodeURIComponent(w.name));
    if(BigInt(r.max)<=0n){ $("s-fee").textContent="saldo insuficiente incluso para el fee"; }
    else{ $("s-amount").value=unitsToQch(r.max); $("s-fee").textContent=`máximo: ${qchDisp(r.max)} · fee: ${qchDisp(r.fee)}`; }
  }catch(e){ $("s-fee").textContent=e.message; }
  $("s-max").disabled=false;
};

// enviar
$("s-btn").onclick=async()=>{
  const w=activeWallet(); const to=$("s-to").value.trim(), amt=$("s-amount").value.trim();
  const msg=$("s-msg"); msg.className="msg"; msg.textContent="";
  if(!w) return;
  if(!to){ msg.className="msg err"; msg.textContent="poné la dirección de destino"; return; }
  let amount; try{ amount=qchToUnits(amt); }catch(e){ msg.className="msg err"; msg.textContent="monto inválido (ej: 1,5)"; return; }
  $("s-btn").disabled=true; msg.className="msg"; msg.style.display="block"; msg.textContent="enviando…";
  try{
    const r=await api("/api/transfer",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({from:w.name,to,amount})});
    msg.className="msg ok"; msg.innerHTML=`✓ Enviaste ${esc(amt)} QCH`;
    $("s-amount").value=""; $("s-to").value="";
    setTimeout(async()=>{ await loadWallets(); }, 1500);
    setTimeout(()=>showView("home"), 1800);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("s-btn").disabled=false;
};

$("w-create").onclick=()=>{ $("create-form").style.display="block"; $("create-done").style.display="none"; $("c-name").value=""; $("c-msg").textContent=""; showView("create"); };
$("w-import").onclick=()=>showView("import");

// arranque
(async function(){
  applyTheme(localStorage.getItem("qchain_theme")||"dark");
  await loadWallets(); await loadNode();
  showView(WALLETS.length ? "home" : "welcome");
  setInterval(async()=>{ await loadWallets(); if($("v-home").classList.contains("active")) renderHome(); }, 5000);
  setInterval(loadNode, 5000);
})();
