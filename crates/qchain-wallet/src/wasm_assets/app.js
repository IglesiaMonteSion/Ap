import init, { addressFromSeed, signTransfer, addressFromBytes, signDelegate, signUndelegate, signClaimReward, signVote, signFinalize, signExecute, stakeAddressFromSeed, deriveAccountSeed, signV7Stake, signV7BeginUnstake, signV7WithdrawUnbonded, programAddressFromSeed, signDeployProgram, signCallProgram } from '/wasm/qchain_wasm.js';

const $ = id => document.getElementById(id);
const LS_KEY = "qchain_wasm_wallet_v1";
const BIO_KEY = "qchain_bio_v1";   // semilla cifrada con una clave del enclave seguro (WebAuthn PRF)
const ACCOUNTS_KEY = "qchain_accounts_v1"; // cuentas HD por-wallet (cuántas, nombres, cuál está activa) - NO secreto (las direcciones son públicas)
const TX_BYTES = 5571n; // tamaño real de una transferencia híbrida firmada (documentado)
// MASTER es la semilla maestra (lo único que se respalda). SEED es la semilla de
// la cuenta ACTIVA, derivada de MASTER con deriveAccountSeed(MASTER, ACCT). La
// cuenta 0 == MASTER exactamente (la dirección de siempre no cambia); las cuentas
// 1,2,3… son direcciones nuevas, TODAS recuperables desde la misma semilla maestra.
let MASTER = null;      // Uint8Array(32), semilla maestra, solo en memoria mientras está desbloqueada
let ACCT = 0;           // índice de la cuenta activa
let SEED = null;        // Uint8Array(32) de la cuenta activa = deriveAccountSeed(MASTER, ACCT)
let PW = null;          // contraseña en memoria (solo para cifrar el respaldo sin re-preguntar); nunca se persiste ni se muestra
let lastActivitySig = "";
let activityExpanded = false;   // el historial muestra 5 filas; "Ver más" lo expande
let nodeTimer = null, balTimer = null;

// ---- helpers ----
function toast(t){ const e=$("toast"); e.textContent=t; e.classList.add("show"); setTimeout(()=>e.classList.remove("show"),1300); }
function short(s){ return (s&&s.length>18)? s.slice(0,10)+"…"+s.slice(-6) : (s||""); }
// Escapa texto que va a innerHTML. CRÍTICO para cualquier campo de texto libre
// que venga del nodo (ej. el NOMBRE de un validador): sin esto, un validador con
// un nombre como `</option><img src=x onerror=...>` inyectaría JS en el origen de
// la wallet y podría robar la semilla (que está en memoria al estar desbloqueada).
function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function copy(t){ navigator.clipboard.writeText(t).then(()=>toast("copiado")); }
function b64(b){ return btoa(String.fromCharCode(...b)); }
function ub64(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }

// ---- Desbloqueo biométrico (Face ID / Touch ID / huella) vía WebAuthn PRF ----
// La semilla se cifra con una clave que SOLO sale del enclave seguro del
// teléfono (Secure Enclave / StrongBox) tras un biométrico exitoso — nunca
// vive en el navegador. La contraseña sigue como respaldo (nunca se elimina).
// Requiere un autenticador de plataforma con la extensión PRF (iOS/Safari
// recientes, Android/Chrome). Si no está soportado, la opción no se ofrece.
function bioEnabled(){ return !!localStorage.getItem(BIO_KEY); }
async function bioAvailable(){
  try{
    if(!(window.PublicKeyCredential && window.isSecureContext)) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }catch(e){ return false; }
}
// Obtiene la clave AES derivada del PRF del enclave (pide biométrico). Devuelve
// null si el navegador/teléfono no soporta PRF (no se puede cifrar con esto).
async function bioKeyFromAssertion(credId, salt){
  const assertion = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),   // local-only, no se verifica en servidor: solo nos importa el PRF
    allowCredentials: credId ? [{ type:"public-key", id: credId }] : [],
    userVerification: "required",
    timeout: 60000,
    extensions: { prf: { eval: { first: salt } } },
  }});
  const ext = assertion.getClientExtensionResults();
  const prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
  if(!prf) return null;   // el autenticador no soporta PRF
  return crypto.subtle.importKey('raw', new Uint8Array(prf), {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
// Activa el biométrico: crea una credencial de plataforma, obtiene su PRF y
// cifra la semilla con esa clave. Requiere la wallet desbloqueada (SEED).
async function enrollBiometric(){
  if(!MASTER) throw new Error("desbloqueá la wallet primero");
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    // rp.id se OMITE a propósito: el navegador usa el dominio del origen actual
    // (correcto en un dominio real o localhost). Una IP cruda no es un rp.id
    // válido por spec, así que ahí el biométrico no se ofrece — un despliegue
    // real usa un dominio (tu túnel de Cloudflare o dominio propio).
    rp: { name: "QCHAIN Wallet" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "qchain-wallet", displayName: "QCHAIN Wallet" },
    pubKeyCredParams: [{type:"public-key", alg:-7},{type:"public-key", alg:-257}],
    authenticatorSelection: { authenticatorAttachment:"platform", userVerification:"required", residentKey:"required" },
    timeout: 60000,
    extensions: { prf: {} },
  }});
  const credId = new Uint8Array(cred.rawId);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const key = await bioKeyFromAssertion(credId, salt);
  if(!key) throw new Error("tu teléfono/navegador no soporta el cifrado por biométrico (WebAuthn PRF) todavía. Seguí usando la contraseña.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, MASTER)); // cifra la MAESTRA, no la cuenta activa (recupera TODAS las cuentas)
  localStorage.setItem(BIO_KEY, JSON.stringify({ v:1, credId:b64(credId), salt:b64(salt), iv:b64(iv), ct:b64(ct) }));
}
// Desbloquea con el biométrico: pide el PRF y descifra la semilla.
async function unlockWithBiometric(){
  const store = JSON.parse(localStorage.getItem(BIO_KEY));
  const key = await bioKeyFromAssertion(ub64(store.credId), ub64(store.salt));
  if(!key) throw new Error("no se pudo obtener la clave del biométrico");
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:ub64(store.iv)}, key, ub64(store.ct));
  return new Uint8Array(pt);
}
function disableBiometric(){ localStorage.removeItem(BIO_KEY); }
function hex(b){ return [...b].map(x=>x.toString(16).padStart(2,'0')).join(''); }
function fromHex(s){ const a=new Uint8Array(s.length/2); for(let i=0;i<a.length;i++)a[i]=parseInt(s.substr(i*2,2),16); return a; }

// dinero exacto (BigInt), 1 QCH = 1e9 unidades
function qchToUnits(s){ s=(s||"").trim().replace(",","."); if(!/^\d+(\.\d+)?$/.test(s)) throw new Error("monto inválido");
  let [i,f=""]=s.split(".");
  // Reject more than 9 decimals instead of silently truncating: 1 QCH = 1e9
  // units, so a 10th decimal is a sub-unit the chain can't represent.
  // Truncating would quietly send a different amount than the user typed.
  if(f.length>9) throw new Error("máximo 9 decimales (1 QCH = 1e9 unidades)");
  f=(f+"000000000").slice(0,9); return BigInt(i)*1000000000n+BigInt(f); }
function unitsToQch(u){ u=BigInt(u); const i=u/1000000000n; let f=(u%1000000000n).toString().padStart(9,"0").replace(/0+$/,""); return f?`${i}.${f}`:i.toString(); }
function fmt(s){ return s.replace(/\B(?=(\d{3})+(?!\d))/g,"."); }
function qchDisp(u){ const q=unitsToQch(u); const [i,f]=q.split("."); return fmt(i)+(f?","+f:"")+" QCH"; }

async function api(path, opts){ const r=await fetch(path,opts); const b=await r.json().catch(()=>({})); if(!r.ok) throw new Error(b.error||("error "+r.status)); return b; }

// ---- WebCrypto: cifrar/descifrar la semilla con la contraseña ----
// PBKDF2-HMAC-SHA256 iteration count. Raised to OWASP's 2023 recommendation
// (600k) from the original 250k - a brute-forcer now pays ~2.4x more per guess.
// The count is stored IN each blob (`iter`) so blobs written at the old 250k
// still decrypt (fallback below), and a future raise stays backward-compatible.
const PBKDF2_ITERS = 600000;
async function deriveKey(password, salt, iters){
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:iters, hash:'SHA-256'}, base,
    {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encryptSeed(seed, password){
  const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(password, salt, PBKDF2_ITERS);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, seed));
  return { v:1, iter:PBKDF2_ITERS, salt:b64(salt), iv:b64(iv), ct:b64(ct) };
}
async function decryptSeed(store, password){
  // Old blobs (v1, pre-hardening) carry no `iter`: they were derived at 250k.
  const iters=Number(store.iter)||250000;
  const key=await deriveKey(password, ub64(store.salt), iters);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM', iv:ub64(store.iv)}, key, ub64(store.ct));
  return new Uint8Array(pt);
}

// --- Endurecimiento de la wallet (tarea #197) ---
// Cifra la semilla Y re-descifra para CONFIRMAR el round-trip antes de entregar
// el respaldo — así un archivo corrupto/mal cifrado nunca se le da al usuario
// (si esto no round-trippea, el respaldo sería irrecuperable). AES-GCM ya
// autentica, pero esta re-decodificación explícita atrapa cualquier bug de
// codificación/serialización del blob.
async function encryptSeedConfirmed(seed, password){
  const store=await encryptSeed(seed, password);
  const back=await decryptSeed(store, password);
  if(back.length!==seed.length || !back.every((b,i)=>b===seed[i]))
    throw new Error("el respaldo cifrado no se pudo re-descifrar — abortado por seguridad");
  return store;
}

// Rechaza semillas OBVIAMENTE débiles al RESTAURAR una semilla provista por el
// usuario (una creada con getRandomValues nunca es débil). No pretende medir
// entropía real (cualquier 32 bytes es una clave válida), solo atrapar los
// errores catastróficos: todo ceros, todo el mismo byte, o 0,1,2,…,31.
function isWeakSeed(seed){
  if(!seed || seed.length!==32) return true;
  if(seed.every(b=>b===seed[0])) return true;          // todo el mismo byte (incl. todo 0)
  if(seed.every((b,i)=>b===(i&0xff))) return true;     // 0,1,2,…,31
  if(seed.every((b,i)=>b===((31-i)&0xff))) return true;// 31,30,…,0
  return false;
}

// Lockout anti fuerza-bruta del desbloqueo local: tras varios intentos fallidos
// de contraseña se impone una espera creciente antes del próximo intento. El
// atacante que ya tiene el blob cifrado igual paga el PBKDF2 de 600k por cada
// intento, pero esto frena además un ataque interactivo en el propio navegador.
const LOCK_KEY="qchain_unlock_lock_v1", LOCK_FREE=4; // 4 intentos libres, luego backoff
function unlockLockState(){ try{ return JSON.parse(localStorage.getItem(LOCK_KEY))||{fails:0,until:0}; }catch(e){ return {fails:0,until:0}; } }
function unlockLockedMs(){ const s=unlockLockState(); return Math.max(0, (s.until||0)-Date.now()); }
function noteUnlockFail(){
  const s=unlockLockState(); s.fails=(s.fails||0)+1;
  if(s.fails>LOCK_FREE){
    const over=s.fails-LOCK_FREE;
    const wait=Math.min(5*60*1000, 5000*Math.pow(2, Math.min(over-1,6))); // 5s,10s,20s…máx 5min
    s.until=Date.now()+wait;
  }
  localStorage.setItem(LOCK_KEY, JSON.stringify(s));
}
function clearUnlockFails(){ localStorage.removeItem(LOCK_KEY); }

// ---- Shamir Secret Sharing sobre GF(256) ----
// Parte la semilla en N fragmentos donde K reconstruyen y K-1 no revelan NADA.
// Todo pasa en el navegador; la semilla nunca sale de acá. Formato de fragmento:
// "QS1-" + hex([K, N, x, chk0, chk1, y0..y31]) = 37 bytes. Los 2 bytes de
// checksum (primeros de SHA-256 de la semilla) solo sirven para avisar si los
// fragmentos no encajan; no revelan la semilla (256 bits de entropía).
const GF_EXP=new Uint8Array(512), GF_LOG=new Uint8Array(256);
// tablas exp/log con generador 3 (x·3 = xtime(x) XOR x). Ojo: 2 NO es
// generador de GF(256) bajo 0x11b (cicla antes de 255); 3 sí lo es.
(function(){ let x=1; for(let i=0;i<255;i++){ GF_EXP[i]=x; GF_LOG[x]=i; const t=((x<<1)^((x&0x80)?0x11b:0))&0xff; x=t^x; } for(let i=255;i<512;i++) GF_EXP[i]=GF_EXP[i-255]; })();
function gmul(a,b){ return (a===0||b===0)?0:GF_EXP[GF_LOG[a]+GF_LOG[b]]; }
function gdiv(a,b){ return a===0?0:GF_EXP[GF_LOG[a]-GF_LOG[b]+255]; }
function gpoly(coeffs,x){ let r=0; for(let i=coeffs.length-1;i>=0;i--) r=gmul(r,x)^coeffs[i]; return r; }

// Lista de palabras oficial de SLIP-39 (1024 = 2^10, 10 bits por palabra).
const SLIP39=["academic","acid","acne","acquire","acrobat","activity","actress","adapt","adequate","adjust","admit","adorn","adult","advance","advocate","afraid","again","agency","agree","aide","aircraft","airline","airport","ajar","alarm","album","alcohol","alien","alive","alpha","already","alto","aluminum","always","amazing","ambition","amount","amuse","analysis","anatomy","ancestor","ancient","angel","angry","animal","answer","antenna","anxiety","apart","aquatic","arcade","arena","argue","armed","artist","artwork","aspect","auction","august","aunt","average","aviation","avoid","award","away","axis","axle","beam","beard","beaver","become","bedroom","behavior","being","believe","belong","benefit","best","beyond","bike","biology","birthday","bishop","black","blanket","blessing","blimp","blind","blue","body","bolt","boring","born","both","boundary","bracelet","branch","brave","breathe","briefing","broken","brother","browser","bucket","budget","building","bulb","bulge","bumpy","bundle","burden","burning","busy","buyer","cage","calcium","camera","campus","canyon","capacity","capital","capture","carbon","cards","careful","cargo","carpet","carve","category","cause","ceiling","center","ceramic","champion","change","charity","check","chemical","chest","chew","chubby","cinema","civil","class","clay","cleanup","client","climate","clinic","clock","clogs","closet","clothes","club","cluster","coal","coastal","coding","column","company","corner","costume","counter","course","cover","cowboy","cradle","craft","crazy","credit","cricket","criminal","crisis","critical","crowd","crucial","crunch","crush","crystal","cubic","cultural","curious","curly","custody","cylinder","daisy","damage","dance","darkness","database","daughter","deadline","deal","debris","debut","decent","decision","declare","decorate","decrease","deliver","demand","density","deny","depart","depend","depict","deploy","describe","desert","desire","desktop","destroy","detailed","detect","device","devote","diagnose","dictate","diet","dilemma","diminish","dining","diploma","disaster","discuss","disease","dish","dismiss","display","distance","dive","divorce","document","domain","domestic","dominant","dough","downtown","dragon","dramatic","dream","dress","drift","drink","drove","drug","dryer","duckling","duke","duration","dwarf","dynamic","early","earth","easel","easy","echo","eclipse","ecology","edge","editor","educate","either","elbow","elder","election","elegant","element","elephant","elevator","elite","else","email","emerald","emission","emperor","emphasis","employer","empty","ending","endless","endorse","enemy","energy","enforce","engage","enjoy","enlarge","entrance","envelope","envy","epidemic","episode","equation","equip","eraser","erode","escape","estate","estimate","evaluate","evening","evidence","evil","evoke","exact","example","exceed","exchange","exclude","excuse","execute","exercise","exhaust","exotic","expand","expect","explain","express","extend","extra","eyebrow","facility","fact","failure","faint","fake","false","family","famous","fancy","fangs","fantasy","fatal","fatigue","favorite","fawn","fiber","fiction","filter","finance","findings","finger","firefly","firm","fiscal","fishing","fitness","flame","flash","flavor","flea","flexible","flip","float","floral","fluff","focus","forbid","force","forecast","forget","formal","fortune","forward","founder","fraction","fragment","frequent","freshman","friar","fridge","friendly","frost","froth","frozen","fumes","funding","furl","fused","galaxy","game","garbage","garden","garlic","gasoline","gather","general","genius","genre","genuine","geology","gesture","glad","glance","glasses","glen","glimpse","goat","golden","graduate","grant","grasp","gravity","gray","greatest","grief","grill","grin","grocery","gross","group","grownup","grumpy","guard","guest","guilt","guitar","gums","hairy","hamster","hand","hanger","harvest","have","havoc","hawk","hazard","headset","health","hearing","heat","helpful","herald","herd","hesitate","hobo","holiday","holy","home","hormone","hospital","hour","huge","human","humidity","hunting","husband","hush","husky","hybrid","idea","identify","idle","image","impact","imply","improve","impulse","include","income","increase","index","indicate","industry","infant","inform","inherit","injury","inmate","insect","inside","install","intend","intimate","invasion","involve","iris","island","isolate","item","ivory","jacket","jerky","jewelry","join","judicial","juice","jump","junction","junior","junk","jury","justice","kernel","keyboard","kidney","kind","kitchen","knife","knit","laden","ladle","ladybug","lair","lamp","language","large","laser","laundry","lawsuit","leader","leaf","learn","leaves","lecture","legal","legend","legs","lend","length","level","liberty","library","license","lift","likely","lilac","lily","lips","liquid","listen","literary","living","lizard","loan","lobe","location","losing","loud","loyalty","luck","lunar","lunch","lungs","luxury","lying","lyrics","machine","magazine","maiden","mailman","main","makeup","making","mama","manager","mandate","mansion","manual","marathon","march","market","marvel","mason","material","math","maximum","mayor","meaning","medal","medical","member","memory","mental","merchant","merit","method","metric","midst","mild","military","mineral","minister","miracle","mixed","mixture","mobile","modern","modify","moisture","moment","morning","mortgage","mother","mountain","mouse","move","much","mule","multiple","muscle","museum","music","mustang","nail","national","necklace","negative","nervous","network","news","nuclear","numb","numerous","nylon","oasis","obesity","object","observe","obtain","ocean","often","olympic","omit","oral","orange","orbit","order","ordinary","organize","ounce","oven","overall","owner","paces","pacific","package","paid","painting","pajamas","pancake","pants","papa","paper","parcel","parking","party","patent","patrol","payment","payroll","peaceful","peanut","peasant","pecan","penalty","pencil","percent","perfect","permit","petition","phantom","pharmacy","photo","phrase","physics","pickup","picture","piece","pile","pink","pipeline","pistol","pitch","plains","plan","plastic","platform","playoff","pleasure","plot","plunge","practice","prayer","preach","predator","pregnant","premium","prepare","presence","prevent","priest","primary","priority","prisoner","privacy","prize","problem","process","profile","program","promise","prospect","provide","prune","public","pulse","pumps","punish","puny","pupal","purchase","purple","python","quantity","quarter","quick","quiet","race","racism","radar","railroad","rainbow","raisin","random","ranked","rapids","raspy","reaction","realize","rebound","rebuild","recall","receiver","recover","regret","regular","reject","relate","remember","remind","remove","render","repair","repeat","replace","require","rescue","research","resident","response","result","retailer","retreat","reunion","revenue","review","reward","rhyme","rhythm","rich","rival","river","robin","rocky","romantic","romp","roster","round","royal","ruin","ruler","rumor","sack","safari","salary","salon","salt","satisfy","satoshi","saver","says","scandal","scared","scatter","scene","scholar","science","scout","scramble","screw","script","scroll","seafood","season","secret","security","segment","senior","shadow","shaft","shame","shaped","sharp","shelter","sheriff","short","should","shrimp","sidewalk","silent","silver","similar","simple","single","sister","skin","skunk","slap","slavery","sled","slice","slim","slow","slush","smart","smear","smell","smirk","smith","smoking","smug","snake","snapshot","sniff","society","software","soldier","solution","soul","source","space","spark","speak","species","spelling","spend","spew","spider","spill","spine","spirit","spit","spray","sprinkle","square","squeeze","stadium","staff","standard","starting","station","stay","steady","step","stick","stilt","story","strategy","strike","style","subject","submit","sugar","suitable","sunlight","superior","surface","surprise","survive","sweater","swimming","swing","switch","symbolic","sympathy","syndrome","system","tackle","tactics","tadpole","talent","task","taste","taught","taxi","teacher","teammate","teaspoon","temple","tenant","tendency","tension","terminal","testify","texture","thank","that","theater","theory","therapy","thorn","threaten","thumb","thunder","ticket","tidy","timber","timely","ting","tofu","together","tolerate","total","toxic","tracks","traffic","training","transfer","trash","traveler","treat","trend","trial","tricycle","trip","triumph","trouble","true","trust","twice","twin","type","typical","ugly","ultimate","umbrella","uncover","undergo","unfair","unfold","unhappy","union","universe","unkind","unknown","unusual","unwrap","upgrade","upstairs","username","usher","usual","valid","valuable","vampire","vanish","various","vegan","velvet","venture","verdict","verify","very","veteran","vexed","victim","video","view","vintage","violence","viral","visitor","visual","vitamins","vocal","voice","volume","voter","voting","walnut","warmth","warn","watch","wavy","wealthy","weapon","webcam","welcome","welfare","western","width","wildlife","window","wine","wireless","wisdom","withdraw","wits","wolf","woman","work","worthy","wrap","wrist","writing","wrote","year","yelp","yield","yoga","zero"];
const WIDX=new Map(SLIP39.map((w,i)=>[w,i]));

// Un fragmento son 37 bytes [K,N,x,chk0,chk1,y0..y31]. Para mostrarlo como
// PALABRAS estilo SLIP-39 se le agregan 3 bytes de checksum (SHA-256 del
// fragmento) -> 40 bytes = 320 bits = 32 palabras de 10 bits. El checksum
// detecta un error de tipeo antes de intentar reconstruir.
async function shareToWords(payload){
  const chk=new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  const full=new Uint8Array(40); full.set(payload,0); full.set(chk.slice(0,3),37);
  let acc=0,bits=0,out=[];
  for(const b of full){ acc=(acc<<8)|b; bits+=8; while(bits>=10){ bits-=10; out.push(SLIP39[(acc>>bits)&0x3ff]); } }
  return out.join(' ');
}
async function wordsToShare(mnemonic){
  const idx=mnemonic.trim().split(/\s+/).map(w=>{ const i=WIDX.get(w.toLowerCase()); if(i===undefined) throw new Error('palabra desconocida: "'+w+'"'); return i; });
  if(idx.length!==32) throw new Error('cada fragmento son 32 palabras (este tiene '+idx.length+')');
  let acc=0,bits=0,out=[];
  for(const i of idx){ acc=(acc<<10)|i; bits+=10; while(bits>=8){ bits-=8; out.push((acc>>bits)&0xff); } }
  const full=Uint8Array.from(out), payload=full.slice(0,37), chk=full.slice(37,40);
  const d=new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  if(d[0]!==chk[0]||d[1]!==chk[1]||d[2]!==chk[2]) throw new Error('un fragmento tiene un error de tipeo (checksum)');
  return payload;
}

async function shamirSplit(seed, k, n){
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256', seed));
  const shares=[]; for(let x=1;x<=n;x++) shares.push({x, ys:new Uint8Array(32)});
  for(let pos=0;pos<32;pos++){
    const coeffs=new Uint8Array(k); coeffs[0]=seed[pos];
    if(k>1) crypto.getRandomValues(coeffs.subarray(1));   // K-1 coeficientes al azar
    for(const sh of shares) sh.ys[pos]=gpoly(coeffs, sh.x);
  }
  const out=[];
  for(const sh of shares){
    const buf=new Uint8Array(37);
    buf[0]=k; buf[1]=n; buf[2]=sh.x; buf[3]=digest[0]; buf[4]=digest[1]; buf.set(sh.ys,5);
    out.push(await shareToWords(buf));   // cada fragmento = 32 palabras
  }
  return out;
}
async function shamirCombine(mnemonics){
  if(!mnemonics.length) throw new Error('pegá tus fragmentos');
  const parsed=[];
  for(const m of mnemonics){ const b=await wordsToShare(m); parsed.push({k:b[0], n:b[1], x:b[2], chk:[b[3],b[4]], ys:b.slice(5)}); }
  const k=parsed[0].k;
  const seen=new Set(), use=[];
  for(const p of parsed){ if(!seen.has(p.x)){ seen.add(p.x); use.push(p); } }
  if(use.length<k) throw new Error(`necesit\u00e1s al menos ${k} fragmentos distintos (ten\u00e9s ${use.length})`);
  const sel=use.slice(0,k);
  const seed=new Uint8Array(32);
  for(let pos=0;pos<32;pos++){
    let acc=0;
    for(let i=0;i<k;i++){
      let num=1, den=1;
      for(let j=0;j<k;j++){ if(j===i) continue; num=gmul(num, sel[j].x); den=gmul(den, sel[i].x ^ sel[j].x); }
      acc ^= gmul(sel[i].ys[pos], gdiv(num,den));
    }
    seed[pos]=acc;
  }
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256', seed));
  if(digest[0]!==sel[0].chk[0]||digest[1]!==sel[0].chk[1]) throw new Error('los fragmentos no coinciden o faltan algunos');
  return seed;
}

// ---- libreta de contactos ----
// Direcciones de destino con un nombre amigable. Se guardan SOLO en este
// dispositivo (localStorage) — nunca salen del navegador ni tocan la cadena;
// son públicas (direcciones de pago), no un secreto, así que no van en el
// respaldo de la semilla. Clave global (un contacto es un destinatario, igual
// desde cualquiera de tus cuentas). Forma: { address: name }.
const CONTACTS_KEY = "qchain_contacts_v1";
function contactsStore(){ try{ return JSON.parse(localStorage.getItem(CONTACTS_KEY)||"{}"); }catch(e){ return {}; } }
function saveContact(addr,name){ const c=contactsStore(); c[addr]=String(name||"").slice(0,40); localStorage.setItem(CONTACTS_KEY, JSON.stringify(c)); }
function deleteContact(addr){ const c=contactsStore(); delete c[addr]; localStorage.setItem(CONTACTS_KEY, JSON.stringify(c)); }
function contactName(addr){ const n=contactsStore()[addr]; return (n&&n.trim())?n:null; }
// Etiqueta amigable para un peer en la actividad/confirmación: nombre de
// contacto si lo hay, si no la dirección abreviada. Ambos escapados por el
// caller donde se inyecta a innerHTML.
function peerLabel(addr){ return contactName(addr) || short(addr); }

function renderContacts(){
  const box=$("c-list"); const c=contactsStore();
  const entries=Object.entries(c).filter(([a,n])=>a&&n);
  if(!entries.length){ box.innerHTML='<div class="empty">todavía no guardaste ninguno</div>'; return; }
  box.innerHTML=entries.map(([a,n])=>{
    const ini=esc((n.trim()[0]||"?").toUpperCase());
    return `<div class="contact">
      <div class="cav">${ini}</div>
      <div class="cmain"><div class="cn">${esc(n)}</div><div class="ca mono">${esc(a)}</div></div>
      <div class="cbtns">
        <button class="btn-sec c-send" data-a="${esc(a)}">Enviar</button>
        <button class="danger c-del" data-a="${esc(a)}">🗑</button>
      </div>
    </div>`;
  }).join("");
  box.querySelectorAll(".c-del").forEach(b=>b.onclick=()=>{
    const a=b.dataset.a;
    if(confirm(`¿Borrar el contacto «${contactName(a)||short(a)}»?\n\n(No afecta ningún fondo — solo quita el nombre guardado en este dispositivo.)`)){ deleteContact(a); renderContacts(); }
  });
  box.querySelectorAll(".c-send").forEach(b=>b.onclick=()=>{ showView("send"); $("s-to").value=b.dataset.a; onSendToChanged(); });
}

// ---- valor en USD (precio de REFERENCIA, no un oráculo de mercado) ----
// QCHAIN no tiene todavía un precio de mercado real; se muestra un estimado con
// un precio de referencia configurable (default 1 QCH = 1 USD, el mismo ancla
// documentado para la calibración de fees). NO es asesoría ni un precio real.
function refUsd(){ const v=parseFloat(localStorage.getItem("qchain_ref_usd")||"1"); return (isFinite(v)&&v>0)?v:1; }
function usdOf(units){
  const q=Number(BigInt(units||0))/1e9;      // unidades → QCH
  const usd=q*refUsd();
  return "≈ $"+usd.toLocaleString("es",{minimumFractionDigits:2,maximumFractionDigits:2})+" USD";
}
// ---- ocultar/mostrar saldo (👁) ----
function balanceHidden(){ return localStorage.getItem("qchain_hide_bal")==="1"; }
function setBalanceHidden(v){ localStorage.setItem("qchain_hide_bal", v?"1":"0"); }

// Las vistas que forman parte de la barra inferior (muestran la tabbar).
const TAB_VIEWS = new Set(["home","accounts","swap","staking","settings"]);
// Qué pestaña se resalta para una vista dada (sub-vistas mapean a su raíz).
function tabFor(name){
  if(name==="home"||name==="send"||name==="receive"||name==="buy"||name==="contacts"||name==="activity-all") return "home";
  if(name==="accounts") return "accounts";
  if(name==="swap") return "swap";
  if(name==="staking") return "staking";
  if(name==="settings") return "settings";
  return "";
}

// ---- navegación entre vistas ----
function showView(name){
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  $("v-"+name).classList.add("active");
  window.scrollTo(0,0);
  // Barra inferior: visible en las vistas principales (y sub-vistas de home),
  // oculta en welcome/unlock/create/import/backup/shamir.
  const rooted = TAB_VIEWS.has(name) || tabFor(name)!=="";
  const loggedIn = !!MASTER;
  const tb=$("tabbar");
  if(tb){
    tb.style.display = (loggedIn && rooted) ? "grid" : "none";
    const t=tabFor(name);
    tb.querySelectorAll(".tab").forEach(b=>b.classList.toggle("on", b.dataset.tab===t));
  }
  // Barra lateral de escritorio: resalta el ítem activo + refresca el nombre de
  // cuenta. `body.authed` habilita el layout de escritorio (sidebar + contenido
  // centrado) SOLO con sesión iniciada; sin sesión, welcome/unlock quedan
  // centrados como en móvil. La sidebar solo aparece en pantallas anchas (CSS).
  document.body.classList.toggle("authed", loggedIn && rooted);
  document.querySelectorAll(".dnav").forEach(b=>b.classList.toggle("on", b.dataset.view===name));
  try{ const dna=$("dn-acct-name"); if(dna && typeof accountName==="function") dna.textContent=accountName(ACCT); }catch(e){}
  if(name==="home"){ renderHome(); }
  if(name==="accounts") renderAccounts();
  if(name==="receive") renderReceive();
  if(name==="send") renderSend();
  if(name==="contacts") renderContacts();
  if(name==="staking") renderStaking();
  if(name==="settings") renderSettings();
  if(name==="activity-all") renderActivityFull();
  if(name==="buy") renderBuy();
  if(name==="unlock") refreshBioUnlockBtn();
}
document.querySelectorAll(".nav").forEach(el=>el.addEventListener("click",()=>showView(el.dataset.to)));
document.querySelectorAll(".tab").forEach(el=>el.addEventListener("click",()=>showView(el.dataset.to)));
// Pie de la barra lateral de escritorio: tema claro/oscuro y bloquear.
(function(){
  const t=document.getElementById("dn-theme");
  if(t) t.onclick=()=>{ const cur=localStorage.getItem("qchain_theme")||"dark"; const nx=cur==="dark"?"light":"dark"; localStorage.setItem("qchain_theme",nx); applyTheme(nx); };
  const l=document.getElementById("dn-lock");
  if(l) l.onclick=()=>{ const sl=$("set-lock"); if(sl) sl.click(); };  // reusa el bloqueo real de Ajustes
})();
// Campana de notificaciones: resume el estado del nodo / aviso de actualización.
$("h-bell").onclick=async()=>{
  let txt="Todo en orden. Tu wallet está conectada al nodo.";
  try{ const st=await api("/api/node");
    if(st.online===false) txt="⚠️ Sin conexión con el nodo. Revisá que esté corriendo.";
    else if(st.update_available) txt="⬆️ Hay una actualización disponible del nodo (v"+st.update_available+"). Pedile al operador que actualice.";
    else txt="✓ Nodo en vivo · v"+st.version+". No hay novedades.";
  }catch(e){ txt="⚠️ No pude contactar el nodo."; }
  toast(txt);
};
// Ojo: alternar ocultar/mostrar el saldo.
$("h-eye").onclick=()=>{ setBalanceHidden(!balanceHidden()); renderHome(); };

// ---- tema claro / oscuro / auto ----
function resolveTheme(s){ return s==="auto" ? (window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark") : s; }
function applyTheme(s){
  localStorage.setItem("qchain_theme", s);
  document.documentElement.dataset.theme = resolveTheme(s);
  document.querySelectorAll("#theme-seg button").forEach(b=>b.classList.toggle("on", b.dataset.themeSet===s));
}
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change",()=>{
  if((localStorage.getItem("qchain_theme")||"dark")==="auto") applyTheme("auto");
});
document.querySelectorAll("#theme-seg button").forEach(b=>b.addEventListener("click",()=>applyTheme(b.dataset.themeSet)));

// ---- estado del nodo ----
async function loadNode(){
  // El punto rojo de la campana avisa: nodo caído o actualización disponible.
  const dot=$("bell-dot"); const show=(v)=>{ if(dot) dot.style.display = v ? "block" : "none"; };
  // Estado de red en la barra lateral de escritorio (verde/rojo).
  const setNet=(on)=>{ const n=$("dn-net"); if(!n) return; n.classList.toggle("off",!on);
    const s=n.querySelector("span"); if(s) s.textContent = on ? "nodo conectado" : "sin conexión"; };
  try{
    const st=await api("/api/node");
    if(st.online===false){ show(true); setNet(false); return; }
    show(!!st.update_available); setNet(true);
  }catch(e){ show(true); setNet(false); }
}

// ---- cuentas HD (múltiples direcciones desde una semilla) ----
// La dirección de la cuenta 0 identifica a esta wallet; la lista de cuentas se
// guarda por-wallet (localStorage) solo como caché de conveniencia (cuántas hay,
// sus nombres, cuál está activa). Como cada cuenta es determinista por índice,
// nada de esto es secreto ni imprescindible: se puede re-derivar desde la semilla.
function master0Addr(){ return MASTER ? addressFromSeed(MASTER) : null; }
function acctSeed(i){ return new Uint8Array(deriveAccountSeed(MASTER, i)); }
function acctAddr(i){ return addressFromSeed(acctSeed(i)); }
function accountsStore(){ try{ return JSON.parse(localStorage.getItem(ACCOUNTS_KEY)||"{}"); }catch(e){ return {}; } }
function myAccounts(){ const s=accountsStore()[master0Addr()]; return s&&s.count>=1 ? s : {count:1, names:{}, active:0}; }
function saveAccounts(o){ const all=accountsStore(); all[master0Addr()]=o; localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(all)); }
function accountName(i, o){ o=o||myAccounts(); return (o.names&&o.names[i]) || (i===0?"Cuenta principal":"Cuenta "+(i+1)); }
// Borrar una cuenta = ocultarla de la lista (las cuentas se DERIVAN de la semilla,
// así que "borrar" no destruye la clave: oculta el índice y quema el saldo residual
// antes, para que no quede QCH accesible en una cuenta que ya no querés ver). El
// índice sigue existiendo en la derivación; `hidden` es la lista de índices ocultos.
function acctHidden(o){ o=o||myAccounts(); return Array.isArray(o.hidden)?o.hidden:[]; }
function isHidden(i,o){ return acctHidden(o).includes(i); }
function visibleAccounts(o){ o=o||myAccounts(); const h=acctHidden(o); const v=[]; for(let i=0;i<o.count;i++) if(!h.includes(i)) v.push(i); return v; }
// Cambia la cuenta activa: re-deriva SEED, persiste la elección y refresca la vista.
function setAccount(i){
  ACCT=i; SEED=acctSeed(i);
  const o=myAccounts(); o.active=i; if(i+1>o.count) o.count=i+1; saveAccounts(o);
  lastActivitySig=""; activityExpanded=false;  // re-render de la actividad (colapsada) para la cuenta nueva
}
// Al desbloquear/crear/restaurar: fijá MASTER y activá la última cuenta usada.
let acctDiscoveryRan=false;   // el auto-descubrimiento corre una vez por sesión desbloqueada
function bootAccounts(){ acctDiscoveryRan=false; const o=myAccounts(); setAccount(Math.min(o.active||0, o.count-1)); }
// Crea la siguiente cuenta (índice determinista libre) y la activa.
function createAccount(){ const o=myAccounts(); const i=o.count; o.count=i+1; o.active=i; saveAccounts(o); setAccount(i); return i; }

// Descubrir cuentas HD financiadas/usadas al restaurar en otro dispositivo: la
// lista de cuentas (cuántas hay) vive SOLO en localStorage, no en el respaldo,
// así que en un equipo nuevo `myAccounts()` cae a `{count:1}` y solo se vería la
// cuenta 0. Como cada cuenta es determinista por índice (deriveAccountSeed), se
// re-deriva 1,2,3… y se le pregunta a la cadena por cada dirección: una cuenta
// "existe" si tiene saldo > 0 o ya firmó algo (nonce > 0). Se extiende el
// contador para incluir la de índice más alto en uso. Corta tras GAP índices
// seguidos sin uso (gap limit, como toda HD wallet). Mismo patrón que
// recoverStakes. No toca la cuenta 0 (siempre existe = la maestra).
async function recoverAccounts(){
  acctDiscoveryRan=true;
  const GAP=10; let highestUsed=0, gap=0, i=1;
  while(gap<GAP){
    const a=await api("/api/account/"+encodeURIComponent(acctAddr(i))).catch(()=>null);
    let used=false;
    try{ used = a && ((BigInt(a.balance||0) > 0n) || (Number(a.nonce||0) > 0)); }catch(e){}
    if(used){ highestUsed=i; gap=0; if(isHidden(i)){ const o=myAccounts(); o.hidden=acctHidden(o).filter(x=>x!==i); saveAccounts(o); } } else { gap++; }
    i++;
  }
  if(highestUsed>0){
    const o=myAccounts();
    if(highestUsed+1 > o.count){ o.count=highestUsed+1; saveAccounts(o); }
  }
  return highestUsed;
}

// ---- home / saldo / actividad ----
function myAddress(){ return SEED ? addressFromSeed(SEED) : null; }

// Suma best-effort del stake vivo de la cuenta activa (sobre las posiciones
// conocidas en localStorage). No bloquea el home si el nodo no responde.
async function walletStakedTotal(addr){
  const list=(allStakes()[addr]||[]);
  if(!list.length) return 0n;
  const live=await Promise.all(list.map(s=>api("/api/stake/"+encodeURIComponent(s.stakeAccount)).catch(()=>null)));
  let t=0n; for(const d of live){ if(d&&d.amount) t+=BigInt(d.amount); }
  return t;
}

async function renderHome(){
  const addr = myAddress(); if(!addr){ showView("unlock"); return; }
  const nm=$("h-acct-name"); if(nm) nm.textContent=accountName(ACCT);
  $("h-addr").textContent = short(addr);
  $("h-copy").onclick = ()=>copy(addr);
  const hidden=balanceHidden();
  $("h-eye").textContent = hidden ? "🙈" : "👁";
  if(hidden){
    $("h-balance").textContent="••••••"; $("h-usd").textContent="≈ $•••• USD";
    $("as-bal").textContent="••••"; $("as-usd").textContent="≈ $•••• USD";
    $("as-stake").textContent="••••"; $("as-stake-usd").textContent="≈ $•••• USD";
  }
  try{
    const acct = await api("/api/account/"+encodeURIComponent(addr));
    if(!balanceHidden()){
      $("h-balance").textContent = qchDisp(acct.balance);
      $("h-usd").textContent = usdOf(acct.balance);
      $("as-bal").textContent = qchDisp(acct.balance);
      $("as-usd").textContent = usdOf(acct.balance);
    }
  }
  catch(e){ /* no borramos lo que ya se ve ante un error de red */ }
  // Total en staking (best-effort, no bloquea).
  walletStakedTotal(addr).then(st=>{
    if(balanceHidden()) return;
    $("as-stake").textContent = unitsToQch(st)+" QCH";
    $("as-stake-usd").textContent = usdOf(st);
  }).catch(()=>{});
  renderActivity(addr);
}

// ---- vista de cuentas (múltiples direcciones desde una semilla) ----
async function renderAccounts(){
  if(!MASTER){ showView("unlock"); return; }
  const box=$("acct-list");
  let o=myAccounts();
  // En un equipo recién restaurado la lista local está vacía (solo la cuenta 0).
  // Descubrí las cuentas usadas desde la semilla la primera vez, una sola vez.
  if(o.count<=1 && !acctDiscoveryRan){
    box.innerHTML='<div class="empty">buscando tus cuentas…</div>';
    try{ await recoverAccounts(); }catch(e){}
    o=myAccounts();
  }
  const vis=visibleAccounts(o);
  const rows=[];
  for(const i of vis){
    const addr=acctAddr(i), name=accountName(i,o), activo=(i===ACCT);
    // La cuenta principal (0) no se puede borrar: es la identidad de la wallet.
    const delBtn = i===0 ? '' : `<button class="btn-ghost acct-del" data-i="${i}" title="borrar" style="padding:2px 6px;color:var(--bad)">🗑</button>`;
    rows.push(`<div class="acct-row" data-i="${i}" style="display:flex;align-items:center;gap:8px;padding:12px 4px;cursor:pointer;border-bottom:1px solid var(--line)">
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;display:flex;align-items:center;gap:8px">${esc(name)} ${activo?'<span style="font-size:11px;color:var(--good);border:1px solid var(--good);border-radius:6px;padding:0 6px">activa</span>':''}</div>
        <div class="mono" style="font-size:12px;opacity:.7">${esc(short(addr))}</div>
      </div>
      <div class="acct-bal" data-addr="${esc(addr)}" style="font-weight:700;white-space:nowrap">…</div>
      <button class="btn-ghost acct-rename" data-i="${i}" title="renombrar" style="padding:2px 6px">✎</button>
      ${delBtn}
    </div>`);
  }
  box.innerHTML=rows.join("");
  // switch al tocar una fila
  box.querySelectorAll(".acct-row").forEach(r=>r.addEventListener("click",e=>{
    if(e.target.closest(".acct-rename")||e.target.closest(".acct-del")) return;   // lápiz/papelera no cambian de cuenta
    setAccount(+r.dataset.i); toast("cuenta "+accountName(+r.dataset.i)); showView("home");
  }));
  // renombrar
  box.querySelectorAll(".acct-rename").forEach(b=>b.addEventListener("click",e=>{
    e.stopPropagation();
    const i=+b.dataset.i, cur=accountName(i), nn=(prompt("Nombre de la cuenta:", cur)||"").trim();
    if(nn){ const oo=myAccounts(); oo.names=oo.names||{}; oo.names[i]=nn.slice(0,40); saveAccounts(oo); renderAccounts(); }
  }));
  // borrar (quema el saldo residual y oculta la cuenta)
  box.querySelectorAll(".acct-del").forEach(b=>b.addEventListener("click",e=>{ e.stopPropagation(); deleteAccount(+b.dataset.i); }));
  // saldos (best-effort, en paralelo) + saldo total sumado de todas las cuentas
  let total=0n;
  const totalEl=$("acct-total"); if(totalEl) totalEl.textContent="…";
  box.querySelectorAll(".acct-bal").forEach(async el=>{
    try{ const a=await api("/api/account/"+encodeURIComponent(el.dataset.addr)); el.textContent=qchDisp(a.balance); total+=BigInt(a.balance||0); }
    catch(e){ el.textContent="—"; }   // 404 = cuenta sin usar = 0, no suma nada
    if(totalEl) totalEl.textContent=qchDisp(total);   // se actualiza a medida que llegan
  });
}
$("acct-new").onclick=()=>{ const i=createAccount(); toast("cuenta creada"); renderAccounts(); };

// Saldo por encima del cual borrar una cuenta pide confirmación (0,1 QCH); por
// debajo se quema en silencio, como pidió el usuario. 1 QCH = 1e9 unidades.
const BURN_WARN_UNITS = 100000000n;

// Borra una cuenta: quema su saldo residual (transferencia a la dirección de quema
// inquemable) y la oculta de la lista. La clave se DERIVA de la semilla, así que no
// se destruye nada irrecuperable salvo el saldo, que es justamente lo que se quema.
async function deleteAccount(i){
  if(i===0){ toast("la cuenta principal no se puede borrar"); return; }
  if(visibleAccounts().length<=1){ toast("no podés borrar tu única cuenta"); return; }
  const seed=acctSeed(i), addr=addressFromSeed(seed), name=accountName(i);
  let bal=0n;
  try{ const a=await api("/api/account/"+encodeURIComponent(addr)); bal=BigInt(a.balance||0); }catch(e){ bal=0n; }
  // Con saldo, hay que quemarlo. Aviso solo si supera 0,1 QCH.
  if(bal>0n){
    let fee=0n, burnAddr=null, dustThr=1000000n;
    try{ const node=await api("/api/node"); fee=BigInt(node.base_fee_per_byte||180)*TX_BYTES; dustThr=BigInt(node.dust_threshold||1000000); }catch(e){ fee=BigInt(180)*TX_BYTES; }
    try{ const cfg=await api("/api/config"); burnAddr=cfg.burn_address; }catch(e){}
    // Se manda TODO menos el fee y un margen de "polvo" (medio umbral). El margen
    // cumple dos cosas: (1) absorbe cualquier diferencia entre el fee estimado y
    // el real (si no, un fee real un pelo mayor haría fallar la transferencia por
    // fondos insuficientes, dejando el saldo intacto), y (2) el remanente que
    // queda en la cuenta es sub-umbral, así que la red lo BARRE y QUEMA en la
    // misma tx — no queda nada accesible.
    const margin=fee+dustThr/2n;
    if(bal<=margin || !burnAddr){
      // Saldo demasiado chico para quemarlo a la dirección (o no hay dirección):
      // se oculta; el residuo (sub-polvo) queda inaccesible/insignificante.
      hideAccount(i); toast("cuenta borrada"); return;
    }
    if(bal>BURN_WARN_UNITS){
      if(!confirm(`«${name}» tiene ${qchDisp(bal)}.\n\nBorrarla QUEMARÁ ese saldo de forma permanente e irrecuperable (contribuye a la deflación de la red).\n\n¿Borrar y quemar?`)) return;
    }
    try{
      toast("quemando saldo…");
      const a=await api("/api/account/"+encodeURIComponent(addr));
      const cid=await api("/api/chain_id"); const chainId=fromHex(cid.chain_id);
      const amount=bal-margin;   // el grueso se quema en la dirección; el resto lo barre la red
      const validUntil=await txValidUntil();
      const txJson=signTransfer(seed, burnAddr, amount, BigInt(a.nonce), chainId, 10000000n, validUntil);
      const r=await fetch("/api/relay-tx",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
      const body=await r.json().catch(()=>({}));
      if(!r.ok) throw new Error(body.error||("error "+r.status));
      toast("✓ saldo quemado · cuenta borrada");
    }catch(e){ toast("no se pudo quemar: "+e.message); return; }
  } else {
    toast("cuenta borrada");
  }
  hideAccount(i);
}
// Oculta el índice y, si era la cuenta activa, vuelve a la principal.
function hideAccount(i){
  const o=myAccounts(); o.hidden=acctHidden(o).slice(); if(!o.hidden.includes(i)) o.hidden.push(i);
  saveAccounts(o);
  if(ACCT===i){ setAccount(0); }
  renderAccounts();
}
$("acct-recover").onclick=async()=>{
  const box=$("acct-list"); box.innerHTML='<div class="empty">buscando cuentas desde tu semilla…</div>';
  try{ const n=await recoverAccounts(); toast(n>0 ? `✓ Cuentas encontradas hasta la #${n+1}` : "no se encontraron cuentas nuevas con saldo"); }catch(e){}
  renderAccounts();
};

// Tiempo relativo aproximado desde el número de ronda (no hay timestamp real
// por-tx; se estima con `(ronda_actual − ronda_tx) × intervalo_de_ronda`). Es un
// aproximado honesto — si no hay datos de ronda, cae a "ronda N".
function relTime(round, cur, intervalMs){
  if(!cur||!intervalMs||round<=0||round>cur) return null;
  let s=Math.round((cur-round)*intervalMs/1000);
  if(s<45) return "hace un momento";
  if(s<3600) return "hace "+Math.max(1,Math.round(s/60))+" min";
  if(s<86400) return "hace "+Math.round(s/3600)+" h";
  return "hace "+Math.round(s/86400)+" d";
}

// Construye las filas de movimientos (transferencias + staking) para una cuenta,
// ordenadas por ronda desc. Comparte lógica entre el home y la vista completa.
async function buildActivityRows(addr){
  let txs=[], stk=[], cur=0, iv=0;
  try{ txs=await api("/api/transfers"); }catch(e){}
  try{ stk=await api("/api/staking_activity/"+encodeURIComponent(addr)); }catch(e){}
  try{ const n=await api("/api/node"); if(n.online!==false){ cur=Number(n.next_round)||0; iv=Number(n.round_interval_ms)||0; } }catch(e){}
  const rows=[];
  const when=(rnd)=>{ const r=relTime(rnd,cur,iv); return r?esc(r):("ronda "+esc(fmt(String(rnd)))); };
  for(const s of (stk||[])){
    let title, sub, cls, ic, sign;
    if(s.kind==="delegate"){ title="Delegación a staking"; sub="validador "+esc(peerLabel(s.validator)); cls="out"; ic="🔒"; sign="−"; }
    else if(s.kind==="undelegate"){ title="Retiro de staking"; sub="validador "+esc(peerLabel(s.validator)); cls="in"; ic="🔓"; sign="+"; }
    else if(s.kind==="unbonding_started"){ title="Unbonding iniciado (self-stake)"; sub="los fondos SIGUEN en staking · retirá de nuevo tras 100 rondas"; cls="neutral"; ic="⏳"; sign=""; }
    else { title="Recompensa de staking"; sub="reclamada"; cls="in"; ic="★"; sign="+"; }
    const rnd=Number(s.round)||0, amt=esc(qchDisp(s.amount));
    rows.push({round:rnd, key:"s"+s.tx_hash, html:`<div class="tx">
      <div class="tx-ic ${cls==='in'?'tx-in':'tx-out'}">${ic}</div>
      <div class="tx-main"><div class="tx-t">${title}</div><div class="tx-s">${sub} · ${when(rnd)}</div></div>
      <div class="tx-amt ${cls}">${sign}${amt}</div>
    </div>`});
  }
  const mine=(txs||[]).filter(t=>t.from===addr||t.to===addr);
  for(const t of mine){
    const inc=t.to===addr;
    // Escape every node-supplied value folded into innerHTML (defense-in-depth).
    const peer=esc(peerLabel(inc?t.from:t.to)), amt=esc(qchDisp(t.amount)), rnd=Number(t.round)||0;
    rows.push({round:rnd, key:"t"+t.tx_hash, html:`<div class="tx">
      <div class="tx-ic ${inc?'tx-in':'tx-out'}">${inc?'↓':'↑'}</div>
      <div class="tx-main"><div class="tx-t">${inc?'Recibido':'Enviado'}</div>
        <div class="tx-s">${inc?'de ':'a '}${peer} · ${when(rnd)}</div></div>
      <div class="tx-amt ${inc?'in':'out'}">${inc?'+':'−'}${amt}</div>
    </div>`});
  }
  rows.sort((a,b)=>b.round-a.round);
  return rows;
}

async function renderActivity(addr){
  const box=$("activity");
  const rows=await buildActivityRows(addr);
  // Historial: 5 filas por defecto (se ve más limpio), "Ver todo" abre la lista completa.
  const LIMIT=5;
  const shown = rows.slice(0,LIMIT);
  const sig=addr+"|c|"+shown.map(r=>r.key).join(",");
  if(sig===lastActivitySig) return;
  lastActivitySig=sig;
  if(!rows.length){ box.innerHTML='<div class="empty">sin movimientos todavía</div>'; return; }
  let html=shown.map(r=>r.html).join("");
  if(rows.length>LIMIT){
    html += `<button class="btn-block btn-sec nav" data-to="activity-all" style="margin-top:10px">Ver todo (${rows.length})</button>`;
  }
  box.innerHTML=html;
  const mb=box.querySelector('[data-to="activity-all"]');
  if(mb) mb.onclick=()=>showView("activity-all");
}

async function renderActivityFull(){
  const addr=myAddress(); if(!addr) return;
  const box=$("activity-full");
  const rows=await buildActivityRows(addr);
  box.innerHTML = rows.length ? rows.map(r=>r.html).join("") : '<div class="empty">sin movimientos todavía</div>';
}

function renderReceive(){
  const addr=myAddress(); if(!addr) return;
  $("qr-img").src="/api/qr/"+encodeURIComponent(addr);
  $("r-addr").textContent=addr;
  $("r-copy").onclick=()=>copy(addr);
}

// Pantalla Comprar: el bloque del faucet solo aparece si el operador configuró
// un faucet en la wallet (`/api/config` → faucet_enabled). El pedido va por el
// proxy `/api/faucet` (el navegador no puede llamar al faucet directo).
async function renderBuy(){
  const card=$("faucet-card"), m=$("faucet-msg"); m.className="msg"; m.style.display="none"; m.textContent="";
  let enabled=false;
  try{ const cfg=await api("/api/config"); enabled=!!cfg.faucet_enabled; }catch(e){}
  card.style.display = enabled ? "block" : "none";
}
$("faucet-btn").onclick=async()=>{
  const addr=myAddress(); if(!addr) return;
  const m=$("faucet-msg"), btn=$("faucet-btn");
  btn.disabled=true; m.className="msg"; m.style.display="block"; m.textContent="pidiendo al faucet…";
  try{
    const r=await fetch("/api/faucet",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({address:addr})});
    const text=await r.text();
    let body={}; try{ body=JSON.parse(text); }catch(e){}
    if(!r.ok) throw new Error(body.error||text||("error "+r.status));
    const amt = body.amount!=null ? qchDisp(body.amount) : "";
    m.className="msg ok"; m.textContent = amt ? `✓ El faucet te envió ${amt}` : "✓ Fondos solicitados al faucet";
    // Refrescar el saldo del home tras un momento (la tx tarda en asentar).
    setTimeout(()=>{ lastActivitySig=""; }, 500);
  }catch(e){ m.className="msg err"; m.textContent=String(e.message||e); }
  btn.disabled=false;
};

// Semilla/dirección de la cuenta ORIGEN elegida en el envío (por defecto la
// activa). Deriva de la misma semilla — enviar desde otra cuenta no cambia la
// cuenta activa del home.
function sendFromSeed(){ const s=$("s-from"); const i=(s&&s.value!=="")?+s.value:ACCT; return acctSeed(i); }
function sendFromAddr(){ return addressFromSeed(sendFromSeed()); }
function renderSend(){
  if(!MASTER) return;
  const o=myAccounts(), sel=$("s-from");
  // Poblá el selector de origen con todas las cuentas (default = la activa).
  // textContent (no innerHTML) → sin riesgo de inyección por el nombre.
  sel.innerHTML="";
  const vis=visibleAccounts(o);
  for(const i of vis){
    const op=document.createElement("option");
    op.value=i; op.textContent=accountName(i,o)+" · "+short(acctAddr(i));
    sel.appendChild(op);
  }
  sel.value=String(ACCT);
  sel.style.display = vis.length>1 ? "block" : "none";   // el selector solo aparece si hay >1 cuenta visible
  const upd=()=>{ $("s-from-addr").textContent=sendFromAddr(); };
  sel.onchange=upd; upd();
  // Selector de contactos: elegir uno rellena la dirección de destino.
  const cs=$("s-contact"), cts=Object.entries(contactsStore()).filter(([a,n])=>a&&n);
  cs.innerHTML="";
  if(cts.length){
    const ph=document.createElement("option"); ph.value=""; ph.textContent="📇 Elegir un contacto…"; cs.appendChild(ph);
    for(const [a,n] of cts){ const op=document.createElement("option"); op.value=a; op.textContent=n+" · "+short(a); cs.appendChild(op); }
    cs.style.display="block";
    cs.onchange=()=>{ if(cs.value){ $("s-to").value=cs.value; onSendToChanged(); } };
  } else { cs.style.display="none"; }
  $("s-amount").value=""; $("s-to").value="";
  $("s-save-contact").style.display="none";
  $("s-fee").textContent="El fee de red se calcula solo al enviar.";
  const msg=$("s-msg"); msg.className="msg"; msg.textContent="";
}

// Cuando cambia la dirección de destino: si es una dirección nueva (no guardada
// como contacto y con pinta de dirección real) ofrecé guardarla con un nombre.
function onSendToChanged(){
  const to=$("s-to").value.trim();
  const known=!!contactName(to);
  const looksAddr=to.length>=32 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(to); // base58, sin 0OIl
  $("s-save-contact").style.display = (looksAddr && !known) ? "block" : "none";
  if(!looksAddr||known) $("s-cname").value="";
}

async function renderSettings(){
  applyTheme(localStorage.getItem("qchain_theme")||"dark");
  refreshBioSettings();
  try{ const cfg=await api("/api/config"); $("set-rpc").textContent=cfg.rpc.replace(/^https?:\/\//,""); }catch(e){}
  try{ const st=await api("/api/node"); const on=st.online!==false;
    $("set-ver").textContent=on?("v"+st.version):"—"; $("set-appver").textContent=on?("v"+st.version):"—";
    $("set-status").innerHTML=on?'<span style="color:var(--good)">en vivo</span>':'<span style="color:var(--bad)">sin conexión</span>';
  }catch(e){}
}

// ---- descargar semilla como archivo ----
// Respaldo CIFRADO: la semilla nunca se guarda ni descarga en claro. El .json
// lleva solo el ciphertext (PBKDF2-SHA256 + AES-256-GCM, mismo esquema que ya
// usa la wallet para guardar la semilla en el navegador). Un archivo robado no
// sirve sin la contraseña. Se restaura en la wallet tipeando esa contraseña.
async function downloadEncryptedBackup(){
  if(!MASTER){ toast("desbloqueá la wallet primero"); return; }
  let pw=PW;
  if(!pw){ pw=prompt("Contraseña para cifrar el respaldo (mínimo 8):")||""; if(pw.length<8){ toast("contraseña muy corta"); return; } }
  const addr=master0Addr();   // identidad de la wallet (cuenta 0)
  const store=await encryptSeedConfirmed(MASTER, pw);   // re-descifra para confirmar el round-trip (#197) — nunca entrega un respaldo irrecuperable
  const data=JSON.stringify({ type:"qchain-wallet-encrypted-backup", version:2, address:addr,
    kdf:"PBKDF2-SHA256", cipher:"AES-256-GCM", ...store,
    note:"Respaldo CIFRADO de una wallet QCHAIN no-custodial. Restauralo en la wallet (Restaurar) tipeando tu contraseña. Sin la contraseña, este archivo no revela nada." }, null, 2);
  const blob=new Blob([data],{type:"application/json"}), url=URL.createObjectURL(blob), a=document.createElement("a");
  a.href=url; a.download="qchain-wallet-backup.json"; a.click(); URL.revokeObjectURL(url);
  toast("respaldo cifrado descargado");
}

// ==================== flujos ====================

// crear
$("w-create").onclick=()=>{ $("c-pass").value=""; $("c-pass2").value=""; $("c-msg").className="msg"; $("c-msg").textContent=""; showView("create"); };
$("w-import").onclick=()=>{ $("i-seed").value=""; $("i-pass").value=""; $("i-msg").className="msg"; $("i-msg").textContent=""; showView("import"); };

$("c-btn").onclick=async()=>{
  const p=$("c-pass").value, p2=$("c-pass2").value, msg=$("c-msg"); msg.className="msg"; msg.textContent="";
  if(p.length<8){ msg.className="msg err"; msg.textContent="la contraseña debe tener al menos 8 caracteres"; return; }
  if(p!==p2){ msg.className="msg err"; msg.textContent="las contraseñas no coinciden"; return; }
  $("c-btn").disabled=true;
  try{
    const seed=crypto.getRandomValues(new Uint8Array(32));       // entropía real del navegador
    const store=await encryptSeedConfirmed(seed, p);             // re-descifra para confirmar el round-trip (#197)
    localStorage.setItem(LS_KEY, JSON.stringify(store));
    clearUnlockFails();
    MASTER=seed; PW=p; disableBiometric(); bootAccounts();
    showView("backup");
  }catch(e){ msg.className="msg err"; msg.textContent="no se pudo crear: "+e.message; }
  $("c-btn").disabled=false;
};
$("b-download").onclick=()=>downloadEncryptedBackup();
$("b-done").onclick=()=>showView("home");

// restaurar — dos modos: semilla directa o fragmentos Shamir
let importMode="seed";
$("i-file").onchange=async e=>{ const f=e.target.files[0]; if(f) $("i-seed").value=(await f.text()).trim(); };
document.querySelectorAll("#import-mode button").forEach(b=>b.onclick=()=>{
  importMode=b.dataset.mode;
  document.querySelectorAll("#import-mode button").forEach(x=>x.classList.toggle("on", x===b));
  $("imp-seed-box").style.display   = importMode==="seed"   ? "block":"none";
  $("imp-shamir-box").style.display = importMode==="shamir" ? "block":"none";
  const msg=$("i-msg"); msg.className="msg"; msg.textContent="";
});

async function seedFromSeedMode(msg, password){
  let raw=$("i-seed").value.trim(), seedHex=raw;
  if(raw.startsWith("{")){
    let obj; try{ obj=JSON.parse(raw); }catch(e){ throw new Error("el archivo no es válido"); }
    // Respaldo CIFRADO nuevo (v2): tiene salt/iv/ct. Se descifra con la misma
    // contraseña que se pone abajo (tu contraseña de wallet).
    if(obj.type==="qchain-wallet-encrypted-backup" || (obj.salt && obj.iv && obj.ct && !obj.seed)){
      if(!password || password.length<8) throw new Error("poné la contraseña de tu respaldo abajo para descifrarlo");
      let seed;
      try{ seed=await decryptSeed(obj, password); }
      catch(e){ throw new Error("contraseña incorrecta para este respaldo cifrado"); }
      if(seed.length!==32) throw new Error("el respaldo cifrado no contiene una semilla válida");
      return seed;
    }
    // Respaldo de la wallet CUSTODIAL (otro formato) → redirigir.
    if(!obj.seed && (obj.ciphertext||obj.kdf||obj.public||obj.secret||obj.keypair)){
      msg.className="msg err";
      msg.innerHTML='Este respaldo es de la wallet <b>custodial</b> (otro formato). Restauralo en '+
        '<a href="/custodial" style="color:#c9c2ff">/custodial</a>, no acá. Esta wallet usa una semilla de 64 caracteres.';
      throw new Error("__handled__");
    }
    // Respaldo viejo en texto plano (v1, obj.seed) o hex pegado → compatibilidad.
    seedHex=(obj.seed||"").trim();
  }
  seedHex=seedHex.replace(/^0x/,"").toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error("pegá tu respaldo (.json cifrado o semilla de 64 hex) o subí el archivo");
  return fromHex(seedHex);
}

$("i-btn").onclick=async()=>{
  const p=$("i-pass").value, msg=$("i-msg"); msg.className="msg"; msg.textContent="";
  $("i-btn").disabled=true;
  try{
    let seed;
    if(importMode==="shamir"){
      const text=$("i-shares").value.trim();
      if(!text) throw new Error("pegá tus fragmentos");
      let blocks=text.split(/\n\s*\n/).map(s=>s.trim()).filter(Boolean);
      let mnemonics;
      if(blocks.length>1){ mnemonics=blocks; }             // un fragmento por bloque
      else { const all=text.split(/\s+/).filter(Boolean);   // o todo seguido, en grupos de 32
        if(all.length%32!==0) throw new Error("revisá: cada fragmento son 32 palabras");
        mnemonics=[]; for(let i=0;i<all.length;i+=32) mnemonics.push(all.slice(i,i+32).join(" ")); }
      seed=await shamirCombine(mnemonics);
    }else{
      seed=await seedFromSeedMode(msg, p);
    }
    if(p.length<8) throw new Error("la contraseña debe tener al menos 8 caracteres");
    // Rechazo de semillas obviamente débiles (#197) — solo al RESTAURAR (una
    // creada por getRandomValues nunca lo es).
    if(isWeakSeed(seed)) throw new Error("esa semilla es insegura (todo ceros / repetida / secuencial) — no se restaura");
    const store=await encryptSeedConfirmed(seed, p);   // re-descifra para confirmar el round-trip
    localStorage.setItem(LS_KEY, JSON.stringify(store));
    clearUnlockFails();
    MASTER=seed; PW=p; disableBiometric(); bootAccounts();
    toast("wallet restaurada"); showView("home");
  }catch(e){ if(e.message!=="__handled__"){ msg.className="msg err"; msg.textContent="no se pudo restaurar: "+e.message; } }
  $("i-btn").disabled=false;
};

// respaldo Shamir (generar)
let shamirK=2, shamirN=3, shamirShares=[];
document.querySelectorAll("#shamir-preset button").forEach(b=>b.onclick=()=>{
  shamirK=+b.dataset.k; shamirN=+b.dataset.n;
  document.querySelectorAll("#shamir-preset button").forEach(x=>x.classList.toggle("on", x===b));
  $("shamir-desc").textContent=`"${shamirK} de ${shamirN}": ${shamirN} fragmentos, juntás ${shamirK} para recuperar. Aguantás perder ${shamirN-shamirK}.`;
  $("shamir-out").style.display="none";
});
$("shamir-gen").onclick=async()=>{
  const msg=$("shamir-msg"); msg.className="msg"; msg.textContent="";
  if(!MASTER){ msg.className="msg err"; msg.textContent="desbloqueá la wallet primero"; return; }
  $("shamir-gen").disabled=true;
  try{
    shamirShares=await shamirSplit(MASTER, shamirK, shamirN);   // divide la MAESTRA (recupera todas las cuentas)
    $("shamir-list").innerHTML=shamirShares.map((s,i)=>`
      <div class="row-item" style="align-items:flex-start">
        <div style="min-width:0;flex:1">
          <div style="font-weight:700;margin-bottom:4px">Fragmento ${i+1} de ${shamirN}</div>
          <div class="mono" style="font-size:11px;word-break:break-all;color:var(--muted)">${s}</div>
        </div>
        <button class="btn-sec" data-share="${i}" style="flex:0 0 auto;padding:8px 12px;font-size:13px">copiar</button>
      </div>`).join("");
    $("shamir-list").querySelectorAll("button[data-share]").forEach(btn=>btn.onclick=()=>copy(shamirShares[+btn.dataset.share]));
    $("shamir-out").style.display="block";
  }catch(e){ msg.className="msg err"; msg.textContent="no se pudo generar: "+e.message; }
  $("shamir-gen").disabled=false;
};
$("shamir-dl").onclick=()=>{
  const addr=myAddress();
  const txt=`QCHAIN Wallet — respaldo Shamir (${shamirK} de ${shamirN})\n`+
    `dirección: ${addr}\n`+
    `Necesitás juntar ${shamirK} de estos ${shamirN} fragmentos para recuperar la wallet.\n`+
    `Restaurar: wallet -> Restaurar -> Fragmentos -> pegá ${shamirK} de ellos.\n\n`+
    shamirShares.map((s,i)=>`Fragmento ${i+1}:\n${s}`).join("\n\n")+"\n";
  const blob=new Blob([txt],{type:"text/plain"}), url=URL.createObjectURL(blob), a=document.createElement("a");
  a.href=url; a.download="qchain-shamir-backup.txt"; a.click(); URL.revokeObjectURL(url);
  toast("fragmentos descargados");
};

// desbloquear
$("u-btn").onclick=async()=>{
  const p=$("u-pass").value, msg=$("u-msg"); msg.className="msg"; msg.style.display="block"; msg.textContent="";
  // Lockout anti fuerza-bruta (#197): si hay una espera activa, no intentar.
  const lockedMs=unlockLockedMs();
  if(lockedMs>0){ msg.className="msg err"; msg.textContent="demasiados intentos — esperá "+Math.ceil(lockedMs/1000)+" s"; return; }
  $("u-btn").disabled=true;
  try{
    const store=JSON.parse(localStorage.getItem(LS_KEY));
    MASTER=await decryptSeed(store, p);
    PW=p;
    clearUnlockFails();
    bootAccounts();
    $("u-pass").value="";
    showView("home");
  }catch(e){
    noteUnlockFail();
    const w=unlockLockedMs();
    msg.className="msg err";
    msg.textContent = w>0 ? ("contraseña incorrecta — demasiados intentos, esperá "+Math.ceil(w/1000)+" s") : "contraseña incorrecta";
  }
  $("u-btn").disabled=false;
};
// Muestra el botón de biométrico en la pantalla de bloqueo solo si está activado.
async function refreshBioUnlockBtn(){
  const btn=$("u-bio"); if(!btn) return;
  btn.style.display = bioEnabled() ? "block" : "none";
}
$("u-bio").onclick=async()=>{
  const msg=$("u-msg"); msg.className="msg"; msg.style.display="block"; msg.textContent="esperando Face ID / huella…";
  $("u-bio").disabled=true;
  try{
    MASTER=await unlockWithBiometric();
    bootAccounts();
    msg.textContent=""; $("u-pass").value="";
    showView("home");
  }catch(e){ msg.className="msg err"; msg.textContent="no se pudo con biométrico — usá tu contraseña"; }
  $("u-bio").disabled=false;
};
$("u-reset").onclick=()=>{
  if(confirm("Esto borra la wallet cifrada de ESTE navegador. Solo vas a poder recuperarla con tu respaldo. ¿Seguir?")){
    localStorage.removeItem(LS_KEY); localStorage.removeItem(BIO_KEY); location.reload();
  }
};

// máximo (saldo menos fee estimado)
$("s-max").onclick=async()=>{
  const addr=sendFromAddr(); if(!addr) return;
  $("s-max").disabled=true;
  try{
    const acct=await api("/api/account/"+encodeURIComponent(addr));
    const node=await api("/api/node");
    const fee=BigInt(node.base_fee_per_byte||180)*TX_BYTES;
    const bal=BigInt(acct.balance);
    // Enviar máximo deja a propósito un "polvo" por DEBAJO del umbral de polvo:
    // la red barre y QUEMA cualquier saldo sub-umbral que quede en la cuenta al
    // participar en una tx (esta misma), así que ese remanente se destruye y
    // contribuye a la deflación en vez de quedar en cero. Se deja la mitad del
    // umbral (holgura ante variaciones del fee dinámico, para que siga siendo
    // sub-umbral y se queme seguro).
    const dustThr=BigInt(node.dust_threshold||1000000);
    const dustLeave=dustThr/2n;
    let max=bal-fee-dustLeave;
    if(max<=0n){
      // Saldo demasiado chico para dejar polvo: mandá todo lo que se pueda.
      max=bal-fee;
      if(max<=0n){ $("s-fee").textContent="saldo insuficiente incluso para el fee"; }
      else{ $("s-amount").value=unitsToQch(max); $("s-fee").textContent=`máximo: ${qchDisp(max)} · fee aprox: ${qchDisp(fee)}`; }
    } else {
      $("s-amount").value=unitsToQch(max);
      $("s-fee").textContent=`máximo: ${qchDisp(max)} · fee aprox: ${qchDisp(fee)} · deja ${qchDisp(dustLeave)} de polvo que la red quema 🔥`;
    }
  }catch(e){ $("s-fee").textContent="no pude calcular el máximo"; }
  $("s-max").disabled=false;
};

// enviar (firma en el navegador)
// Estado del envío pendiente de confirmación (llenado por s-btn, usado por cf-ok).
let pendingSend=null;
function closeConfirm(){ $("confirm-bg").classList.remove("show"); }

// Paso 1: validar → FIRMAR en el navegador → SIMULAR en el nodo (dry-run, sin
// comprometer nada) → mostrar la confirmación con el resultado REAL (fee exacto,
// saldo después, y si fallaría). QCH-WALLET-001: el usuario ve exactamente qué
// va a pasar ANTES de autorizar el envío, en vez de firmar/enviar a ciegas.
// Enviar es IRREVERSIBLE.
$("s-btn").onclick=async()=>{
  const to=$("s-to").value.trim(), amt=$("s-amount").value.trim(), msg=$("s-msg"); msg.className="msg"; msg.textContent="";
  if(!to){ msg.className="msg err"; msg.style.display="block"; msg.textContent="poné la dirección de destino"; return; }
  let amount; try{ amount=qchToUnits(amt); }catch(e){ msg.className="msg err"; msg.style.display="block"; msg.textContent="monto inválido (ej: 1,5)"; return; }
  if(amount<=0n){ msg.className="msg err"; msg.style.display="block"; msg.textContent="el monto debe ser mayor a 0"; return; }
  $("s-btn").disabled=true;
  msg.className="msg"; msg.style.display="block"; msg.textContent="preparando y simulando…";
  try{
    const seed=sendFromSeed();          // cuenta origen elegida (default = activa)
    const addr=addressFromSeed(seed);
    const acct=await api("/api/account/"+encodeURIComponent(addr));
    const cid=await api("/api/chain_id");
    const chainId=fromHex(cid.chain_id);
    // Firmar en el navegador (la semilla nunca sale). Nada se difunde todavía.
    const validUntil=await txValidUntil();
    const txJson=signTransfer(seed, to, amount, BigInt(acct.nonce), chainId, 10000000n, validUntil);
    // DRY-RUN contra el nodo (no compromete nada): trae fee exacto + resultado.
    let sim=null;
    try{ const r=await fetch("/api/simulate",{method:"POST",headers:{"content-type":"application/json"},body:txJson}); if(r.ok) sim=await r.json(); }catch(e){}
    // Fee: el exacto de la simulación; si el nodo no soporta /simulate, se cae al estimado.
    const fee = (sim && sim.fee!=null) ? BigInt(sim.fee) : (BigInt((await api("/api/node").catch(()=>({}))).base_fee_per_byte||180)*TX_BYTES);
    const nm=contactName(to);
    $("cf-to").innerHTML = nm ? `${esc(nm)}<small class="mono">${esc(short(to))}</small>` : `<span class="mono">${esc(short(to))}</span>`;
    $("cf-amt").textContent=qchDisp(amount);
    $("cf-fee").textContent=qchDisp(fee);
    $("cf-total").textContent=qchDisp(amount+fee);
    const simNote=$("cf-sim"); const okBtn=$("cf-ok");
    if(sim && sim.ok===false){
      // La simulación dice que FALLARÍA — mostrar el motivo real y bloquear el envío.
      $("cf-after").textContent="—";
      simNote.style.display="block"; simNote.className="msg err"; simNote.style.display="block";
      simNote.textContent="⚠ Esta transferencia FALLARÍA: "+esc(sim.error||"motivo desconocido")+". No se enviará.";
      okBtn.disabled=true;
    } else {
      if(sim && sim.payer_after!=null){ $("cf-after").textContent=qchDisp(BigInt(sim.payer_after)); }
      else { $("cf-after").textContent="—"; }
      simNote.style.display = sim ? "block" : "none";
      if(sim){ simNote.className="hint"; simNote.textContent="✓ Simulado contra el nodo: se ejecutaría correctamente."; }
      okBtn.disabled=false;
    }
    pendingSend={txJson, to, amt};
    $("confirm-bg").classList.add("show");
  }catch(e){ msg.className="msg err"; msg.textContent=e.message||"no se pudo preparar la transferencia"; }
  $("s-btn").disabled=false;
};
$("cf-cancel").onclick=closeConfirm;
$("confirm-bg").onclick=(e)=>{ if(e.target===$("confirm-bg")) closeConfirm(); };

// Paso 2: difundir la tx YA firmada+simulada al nodo (tras confirmar).
$("cf-ok").onclick=async()=>{
  if(!pendingSend||!pendingSend.txJson) return closeConfirm();
  const {txJson, to, amt}=pendingSend; const msg=$("s-msg");
  closeConfirm();
  $("s-btn").disabled=true; $("cf-ok").disabled=true;
  msg.className="msg"; msg.style.display="block"; msg.textContent="enviando al nodo…";
  try{
    const r=await fetch("/api/relay-tx",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
    const body=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(body.error||("error "+r.status));
    // Guardar como contacto si el usuario tipeó un nombre para una dirección nueva.
    const cname=$("s-cname").value.trim();
    if(cname && !contactName(to)){ saveContact(to,cname); }
    msg.className="msg ok"; msg.innerHTML=`✓ Enviaste ${esc(amt)} QCH`;
    $("s-amount").value=""; $("s-to").value=""; $("s-cname").value=""; $("s-save-contact").style.display="none";
    setTimeout(()=>showView("home"), 1600);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("s-btn").disabled=false; $("cf-ok").disabled=false; pendingSend=null;
};

// Detectar dirección nueva mientras se escribe/pega → ofrecer guardarla.
$("s-to").addEventListener("input", onSendToChanged);

// ---- escáner de QR con la cámara ----
// Usa jsQR (vendorizado, MIT) en el navegador — funciona en cualquier equipo,
// incluido iOS Safari (que NO tiene BarcodeDetector). La cámara se decodifica
// localmente; ningún frame sale del dispositivo. Requiere HTTPS (getUserMedia),
// que ya está por el túnel de Cloudflare.
let _jsqrPromise=null;
function loadJsQR(){
  if(window.jsQR) return Promise.resolve(window.jsQR);
  if(_jsqrPromise) return _jsqrPromise;
  _jsqrPromise=new Promise((res,rej)=>{
    const s=document.createElement("script");
    s.src="/vendor/jsQR.min.js"; s.onload=()=>res(window.jsQR); s.onerror=()=>rej(new Error("no pude cargar el decodificador"));
    document.head.appendChild(s);
  });
  return _jsqrPromise;
}
// Extrae una dirección base58 de lo que sea que traiga el QR: dirección cruda,
// un URI `qchain:<addr>` / `qch:<addr>`, o una URL con la dirección en el path/query.
function extractAddress(text){
  if(!text) return null;
  let t=String(text).trim();
  const m=t.match(/(?:qchain|qch):\/*([1-9A-HJ-NP-Za-km-z]{32,})/i) || t.match(/[?&](?:to|address|addr)=([1-9A-HJ-NP-Za-km-z]{32,})/i);
  if(m) t=m[1];
  else { const parts=t.split(/[\/?#=:\s]+/).filter(Boolean); const cand=parts.reverse().find(p=>/^[1-9A-HJ-NP-Za-km-z]{32,}$/.test(p)); if(cand) t=cand; }
  return /^[1-9A-HJ-NP-Za-km-z]{32,}$/.test(t) ? t : null;
}
let _scanStream=null, _scanRAF=null, _scanOnResult=null;
async function openScanner(onResult){
  _scanOnResult=onResult;
  const bg=$("scan-bg"), video=$("scan-video"), msg=$("scan-msg");
  msg.style.display="none";
  bg.classList.add("show");
  let jsQR;
  try{ jsQR=await loadJsQR(); }catch(e){ msg.textContent="No pude cargar el escáner."; msg.style.display="block"; return; }
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia){
    msg.textContent="Este navegador no permite usar la cámara. Pegá la dirección a mano."; msg.style.display="block"; return;
  }
  try{
    _scanStream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:"environment"}}, audio:false});
  }catch(e){
    msg.textContent = (e&&e.name==="NotAllowedError")
      ? "Permiso de cámara denegado. Habilitalo en el navegador y probá de nuevo."
      : "No pude abrir la cámara. Pegá la dirección a mano.";
    msg.style.display="block"; return;
  }
  video.srcObject=_scanStream; await video.play().catch(()=>{});
  const canvas=document.createElement("canvas"); const ctx=canvas.getContext("2d",{willReadFrequently:true});
  const tick=()=>{
    if(!_scanStream){ return; }
    if(video.readyState===video.HAVE_ENOUGH_DATA && video.videoWidth){
      const w=canvas.width=video.videoWidth, h=canvas.height=video.videoHeight;
      ctx.drawImage(video,0,0,w,h);
      let img; try{ img=ctx.getImageData(0,0,w,h); }catch(e){ img=null; }
      if(img){
        const code=jsQR(img.data,w,h,{inversionAttempts:"dontInvert"});
        if(code&&code.data){
          const addr=extractAddress(code.data);
          if(addr){ const cb=_scanOnResult; closeScanner(); if(cb) cb(addr); return; }
          else { msg.textContent="Ese QR no es una dirección de QCHAIN."; msg.style.display="block"; }
        }
      }
    }
    _scanRAF=requestAnimationFrame(tick);
  };
  _scanRAF=requestAnimationFrame(tick);
}
function closeScanner(){
  const bg=$("scan-bg"), video=$("scan-video");
  if(_scanRAF){ cancelAnimationFrame(_scanRAF); _scanRAF=null; }
  if(_scanStream){ _scanStream.getTracks().forEach(t=>t.stop()); _scanStream=null; }
  if(video){ video.pause(); video.srcObject=null; }
  bg.classList.remove("show");
}
$("scan-close").onclick=closeScanner;
// Escanear desde la pantalla de envío → rellena el destino.
$("s-scan").onclick=()=>openScanner(a=>{ showView("send"); $("s-to").value=a; onSendToChanged(); toast("dirección escaneada"); });
// Ícono de escaneo del header (escanear para pagar) → abre el envío ya rellenado.
if($("h-scan")) $("h-scan").onclick=()=>openScanner(a=>{ showView("send"); $("s-to").value=a; onSendToChanged(); toast("dirección escaneada"); });

// Guardar un contacto desde la libreta.
$("c-add").onclick=()=>{
  const name=$("c-name").value.trim(), addr=$("c-addr").value.trim(), m=$("c-msg");
  m.className="msg"; m.style.display="block";
  if(!name){ m.className="msg err"; m.textContent="poné un nombre"; return; }
  if(!(addr.length>=32 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(addr))){ m.className="msg err"; m.textContent="dirección inválida"; return; }
  saveContact(addr,name);
  $("c-name").value=""; $("c-addr").value="";
  m.className="msg ok"; m.textContent="✓ contacto guardado";
  renderContacts();
  setTimeout(()=>{ m.style.display="none"; }, 1400);
};

// ---- staking ----
// Las delegaciones se guardan por-dirección en localStorage como caché, PERO la
// cuenta de stake ya NO es una dirección random: se DERIVA de la semilla
// (`stakeAddressFromSeed(SEED, index)`), así una posición de staking es
// RECUPERABLE con solo la semilla (Shamir incluido) — re-derivás index 0,1,2…
// y preguntás a la cadena, sin depender del localStorage del navegador. Las
// posiciones viejas (dirección random, sin campo `index`) siguen funcionando
// para reclamar/retirar; simplemente no son recuperables desde la semilla (eso
// era el estado anterior, no se puede retrofittear una dirección random).
const STAKES_KEY="qchain_stakes_v1";
function allStakes(){ try{ return JSON.parse(localStorage.getItem(STAKES_KEY)||"{}"); }catch(e){ return {}; } }
function myStakes(){ const a=myAddress(); return (allStakes()[a]||[]); }
function saveStake(pos){ const a=myAddress(), all=allStakes(); (all[a]=all[a]||[]).push(pos); localStorage.setItem(STAKES_KEY, JSON.stringify(all)); }
function dropStake(stakeAccount){ const a=myAddress(), all=allStakes(); all[a]=(all[a]||[]).filter(p=>p.stakeAccount!==stakeAccount); localStorage.setItem(STAKES_KEY, JSON.stringify(all)); }
// Importar una posición por su dirección de cuenta de stake. Para posiciones de
// dirección ALEATORIA (creadas antes de la derivación determinista v2.0.5, o en
// otro dispositivo) que "Recuperar" no puede re-derivar de la semilla. Solo
// agrega la posición a la lista local si la cuenta on-chain es REALMENTE tuya
// (owner == tu dirección); el Retirar posterior lo firma tu semilla, como siempre.
async function importStakeByAddress(){
  const m=$("st-import-msg"), raw=($("st-import").value||"").trim();
  m.className="msg"; m.textContent="";
  if(!raw){ m.className="msg err"; m.textContent="Pegá la dirección de una cuenta de stake."; return; }
  let d; try{ d=await api("/api/stake/"+encodeURIComponent(raw)); }catch(e){ m.className="msg err"; m.textContent="No se pudo consultar esa dirección."; return; }
  if(!(d&&d.exists)){ m.className="msg err"; m.textContent="No existe una cuenta de stake en esa dirección."; return; }
  if(d.owner!==myAddress()){ m.className="msg err"; m.textContent="Esa cuenta de stake no es tuya (el dueño es otra dirección)."; return; }
  if(myStakes().some(p=>p.stakeAccount===raw)){ m.className="msg ok"; m.textContent="Esa posición ya estaba en tu lista."; renderStaking(); return; }
  saveStake({ stakeAccount: raw, validator: d.validator, amount: String(d.amount) });
  m.className="msg ok"; m.textContent="✓ Posición importada. Aparece abajo — tocá Retirar para recuperar tus fondos.";
  $("st-import").value=""; renderStaking();
}
// El próximo índice determinista libre = 1 + el mayor índice ya usado. Nunca se
// reutiliza un índice (una cuenta de stake ya creada — aunque esté en 0 tras un
// retiro — haría fallar un Delegate nuevo, que rechaza sobrescribir).
function nextStakeIndex(){ let mx=-1; for(const p of myStakes()){ if(typeof p.index==="number" && p.index>mx) mx=p.index; } return mx+1; }
function stakeKnown(sa){ return myStakes().some(p=>p.stakeAccount===sa); }

// Recuperar posiciones desde la semilla: re-deriva index 0,1,2… y pregunta a la
// cadena por cada dirección. Reconstruye la lista sin ningún estado local — el
// caso exacto de restaurar la wallet en otro navegador/dispositivo. Corta tras
// varias direcciones vacías consecutivas (las posiciones son contiguas porque
// los índices siempre incrementan). Solo suma una posición si la cadena
// confirma que su `owner` es esta wallet.
async function recoverStakes(){
  const addr=myAddress(); if(!addr) return 0;
  const all=allStakes(); const list=all[addr]||[];
  let idx=0, misses=0, found=0; const MAX_IDX=256, MAX_MISS=10;
  while(idx<MAX_IDX && misses<MAX_MISS){
    const sa=stakeAddressFromSeed(SEED, idx);
    const d=await api("/api/stake/"+encodeURIComponent(sa)).catch(()=>null);
    if(d && d.exists && d.owner===addr && Number(d.amount)>0){
      if(!list.some(p=>p.stakeAccount===sa)){ list.push({ stakeAccount:sa, index:idx, validator:d.validator, amount:String(d.amount) }); found++; }
      misses=0;
    }else{ misses++; }
    idx++;
  }
  all[addr]=list; localStorage.setItem(STAKES_KEY, JSON.stringify(all));
  return found;
}

async function relaySigned(txJson){
  const r=await fetch("/api/relay-tx",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
  const body=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(body.error||("error "+r.status));
  return body;
}

// Puebla el selector de validadores desde /api/validators (nombre + stake +
// dirección) para que el usuario elija de una lista en vez de pegar la
// dirección. Al elegir uno, se rellena el campo de dirección real.
let validatorListLoaded=false;
// ---- staking profesional: economía viva (APY/comisión) + mapa de validadores ----
let STK_ECON=null, STK_VALMAP={}, STK_AVAIL=0n;
const BONDING_ROUNDS=100;
function apyPct(){ return STK_ECON ? (STK_ECON.emission_apr_bps||0)/100 : null; }        // % anual de emisión
function commissionPct(){ return STK_ECON ? (STK_ECON.staking_commission_bps||0)/100 : null; }
function valName(addr){ const v=STK_VALMAP[addr]; return v&&v.name ? v.name : short(addr); }

async function loadStakingMeta(){
  try{ STK_ECON=await api("/api/economics"); }catch(e){ STK_ECON=null; }
  const apy=apyPct(), com=commissionPct();
  $("stk-apy").textContent = apy!=null ? ("~"+ (Number.isInteger(apy)?apy:apy.toFixed(1)) +"%") : "—";
  $("stk-commission").textContent = com!=null ? (Number.isInteger(com)?com:com.toFixed(1))+"%" : "—";
}
async function loadValidatorList(){
  const sel=$("st-valselect");
  try{
    const vals=await api("/api/validators");
    STK_VALMAP={}; (Array.isArray(vals)?vals:[]).forEach(v=>{ STK_VALMAP[v.address]={name:v.name,stake:v.stake}; });
    if(!Array.isArray(vals)||!vals.length){ sel.innerHTML='<option value="">— sin validadores —</option>'; return; }
    vals.sort((a,b)=>{ const an=a.name||"", bn=b.name||""; if(an&&!bn) return -1; if(!an&&bn) return 1; if(an&&bn) return an.localeCompare(bn); return (b.stake||0)-(a.stake||0); });
    const com=commissionPct();
    const opts=['<option value="">— elegí un validador —</option>'];
    for(const v of vals){
      const suffix = com!=null ? (" · comisión "+ (Number.isInteger(com)?com:com.toFixed(1)) +"%") : "";
      const label=(v.name?esc(v.name):esc(short(v.address)))+" · "+esc(qchDisp(v.stake))+" stake"+esc(suffix);
      opts.push(`<option value="${esc(v.address)}">${label}</option>`);
    }
    sel.innerHTML=opts.join("");
    validatorListLoaded=true;
    const cur=$("st-validator").value.trim(); if(cur) sel.value=cur;
  }catch(e){ sel.innerHTML='<option value="">— no se pudo cargar la lista —</option>'; }
}
$("st-valselect").addEventListener("change",e=>{
  const v=e.target.value;
  if(v){ $("st-validator").value=v; const n=valName(v); $("st-valhint").textContent="Validador: "+n+" (podés editar la dirección)."; }
});
// MÁX y estimación de ganancia anual
function stakeEstimate(){
  const apy=apyPct(); const est=$("st-est");
  let amt; try{ amt=qchToUnits($("st-amount").value.trim()); }catch(e){ amt=0n; }
  if(apy==null || amt<=0n){ est.hidden=true; return; }
  const yearly = (amt * BigInt(Math.round(apy*100))) / 10000n;   // amt * apy%
  $("st-est-val").textContent = qchDisp(yearly);
  est.hidden=false;
}
$("st-amount").addEventListener("input", stakeEstimate);
$("st-max").onclick=()=>{
  // deja un pequeño margen para el fee de la tx de staking
  const margin=3000000n; const max = STK_AVAIL>margin ? STK_AVAIL-margin : 0n;
  $("st-amount").value=unitsToQch(max); stakeEstimate();
};

function stakeBadge(d){
  if(!(d&&d.exists)) return {cls:'ready', txt:'Pendiente'};
  const cur=d.current_round||0;
  const selfStake=d.owner===d.validator, req=selfStake?d.unbonding_requested_at_round:null;
  if(selfStake && req!=null && cur<req+BONDING_ROUNDS) return {cls:'cool', txt:'Desactivando'};
  if(cur < (d.bonding_until_round||0)) return {cls:'warm', txt:'Activando'};
  const until=Math.max(d.bonding_until_round||0, d.locked_until_round||0);
  if(cur < until) return {cls:'warm', txt:'Bloqueado (voto)'};
  return {cls:'active', txt:'Activo'};
}

// Directorio / mercado de validadores: lista rankeada por stake con % de red,
// comisión (global hoy) y "Delegar" por fila. Reusa /api/validators + STK_ECON.
async function renderValidatorDirectory(){
  const box=$("vd-list");
  let vals; try{ vals=await api("/api/validators"); }catch(e){ box.innerHTML='<div class="empty">no se pudo cargar el directorio</div>'; return; }
  if(!Array.isArray(vals)||!vals.length){ box.innerHTML='<div class="empty">sin validadores</div>'; $("vd-count").textContent=""; return; }
  vals.sort((a,b)=>(b.stake||0)-(a.stake||0));
  const total=vals.reduce((s,v)=>s+(v.stake||0),0)||1;
  const com=commissionPct();
  $("vd-count").textContent=vals.length+(vals.length===1?" validador":" validadores");
  box.innerHTML=vals.map((v,i)=>{
    const share=(v.stake||0)/total*100;
    const comTxt = com!=null ? ` · comisión ${Number.isInteger(com)?com:com.toFixed(1)}%` : "";
    return `<div class="vd-row">
      <div class="vd-rank">${i+1}</div>
      <div class="vd-main">
        <div class="vd-name">${esc(v.name||short(v.address))}</div>
        <div class="vd-sub">${esc(short(v.address))}${esc(comTxt)}</div>
        <div class="vd-bar"><i style="width:${share.toFixed(1)}%"></i></div>
      </div>
      <div class="vd-share"><b>${share.toFixed(1)}%</b><small>${esc(qchDisp(v.stake))}</small></div>
      <button class="vd-pick" data-val="${esc(v.address)}">Delegar</button>
    </div>`;
  }).join("");
  box.querySelectorAll("button[data-val]").forEach(b=>b.onclick=()=>{
    const a=b.dataset.val; $("st-validator").value=a;
    const sel=$("st-valselect"); if(sel) sel.value=a;
    $("st-valhint").textContent="Validador elegido del directorio: "+valName(a);
    $("st-amount").focus(); $("st-delegate").scrollIntoView({behavior:"smooth",block:"center"});
  });
}
// Historial de recompensas reclamadas (eventos ClaimReward on-chain de esta cuenta).
async function renderRewardHistory(){
  const box=$("rh-list"), addr=myAddress(); if(!addr) return;
  let evs; try{ evs=await api("/api/staking_activity/"+encodeURIComponent(addr)); }catch(e){ box.innerHTML='<div class="empty">no se pudo cargar el historial</div>'; return; }
  const list=Array.isArray(evs)?evs:(evs&&evs.events)||[];
  const claims=list.filter(e=>e.kind==="claim_reward").sort((a,b)=>(Number(b.round)||0)-(Number(a.round)||0));
  if(!claims.length){ box.innerHTML='<div class="empty">todavía no reclamaste recompensas</div>'; $("rh-total").textContent=""; return; }
  let tot=0n; for(const c of claims) tot+=BigInt(c.amount||0);
  $("rh-total").textContent="total: "+qchDisp(tot);
  box.innerHTML=claims.slice(0,20).map(c=>`<div class="rh-row">
    <div class="rh-l"><b>★ Recompensa reclamada</b><div>validador ${esc(peerLabel(c.validator))} · ronda ${esc(fmt(String(Number(c.round)||0)))}</div></div>
    <div class="rh-amt">+${esc(qchDisp(c.amount))}</div>
  </div>`).join("");
}

// ¿La red corre la economía v7? (staking shares+índice, sin validador destino).
// Detectado del flag economics_v7 que el nodo expone en /status (proxied a
// /api/node). En una red v6 (el default) NODE_V7 queda false y todo el path de
// staking de abajo es byte-idéntico al de siempre.
let NODE_V7=false;
function setV7Ui(v7){
  NODE_V7=v7;
  const show=(id,on)=>{ const e=$(id); if(e) e.style.display= on?"":"none"; };
  show("st-v6val", !v7);            // selector de validador (v6)
  show("st-v7hint", v7);           // explicación v7
  show("st-import-sec", !v7);      // importar posición (v6)
  show("st-dir-sec", !v7);         // directorio de validadores (v6)
  show("st-rh-sec", !v7);          // historial de recompensas reclamadas (v6)
  const t=$("st-deleg-title"); if(t) t.textContent = v7 ? "Hacer staking" : "Delegar QCH";
  const b=$("st-delegate"); if(b) b.textContent = v7 ? "Hacer staking" : "Delegar";
}

async function renderStaking(){
  const addr=myAddress(); if(!addr) return;
  $("st-msg").className="msg"; $("st-msg").textContent=""; $("st-amount").value=""; $("st-est").hidden=true;
  // Detectar la economía de la red y adaptar la UI. En v7 el flujo es distinto
  // (posiciones shares+índice, sin validador), así que se delega a renderStakingV7.
  try{ const st=await api("/api/node"); setV7Ui(st&&st.economics_v7===true); }catch(e){ setV7Ui(false); }
  if(NODE_V7){ await renderStakingV7(addr); return; }
  await Promise.all([loadStakingMeta(), loadValidatorList()]);
  renderValidatorDirectory(); renderRewardHistory();   // tras cargar economía (comisión); pueblan su propio DOM
  // saldo disponible para la tarjeta de delegar
  try{ const acct=await api("/api/account/"+encodeURIComponent(addr)); STK_AVAIL=BigInt(acct.balance||0); $("st-avail").textContent="disponible: "+qchDisp(STK_AVAIL); }catch(e){ $("st-avail").textContent="disponible: —"; }
  if(!$("st-validator").value){
    try{ const st=await api("/api/node"); if(st.validator){ $("st-validator").value=st.validator; $("st-valhint").textContent="Sugerido: "+valName(st.validator)+" (el validador del nodo conectado)."; } }catch(e){}
  }
  let stakes=myStakes();
  const list=$("st-list");
  if(!stakes.length){ list.innerHTML='<div class="empty">buscando posiciones…</div>'; try{ await recoverStakes(); }catch(e){} stakes=myStakes(); }
  if(!stakes.length){ list.innerHTML='<div class="empty">todavía no tenés posiciones de staking</div>'; $("stk-total").textContent="0 QCH"; $("stk-rewards").textContent="0 QCH"; return; }
  const live=await Promise.all(stakes.map(s=>api("/api/stake/"+encodeURIComponent(s.stakeAccount)).catch(()=>null)));
  let totStake=0n, totReward=0n;
  list.innerHTML=stakes.map((s,i)=>{
    const d=live[i];
    const amount=(d&&d.exists)?d.amount:s.amount;
    const reward=(d&&d.exists)?d.pending_reward:0;
    totStake+=BigInt(amount||0); totReward+=BigInt(reward||0);
    const b=stakeBadge(d);
    const cur=(d&&d.exists)?(d.current_round||0):0;
    // ¿se puede retirar? (bonding+lock cumplidos y, si es self-stake en unbonding, pasado el período)
    let ready=true;
    if(d&&d.exists){ const until=Math.max(d.bonding_until_round||0,d.locked_until_round||0); ready=cur>=until; if(d.owner===d.validator && d.unbonding_requested_at_round!=null && cur<d.unbonding_requested_at_round+BONDING_ROUNDS) ready=false; }
    // barra de progreso para "Activando" o "Desactivando"
    let prog='';
    if(b.txt==='Activando'){ const end=d.bonding_until_round||0, start=end-BONDING_ROUNDS, pct=Math.max(0,Math.min(100,Math.round((cur-start)/BONDING_ROUNDS*100)));
      prog=`<div class="pos-prog"><i style="width:${pct}%"></i></div><div class="pos-progtxt">activa en ${esc(fmt(String(Math.max(0,end-cur))))} rondas</div>`; }
    else if(b.txt==='Desactivando'){ const end=(d.unbonding_requested_at_round||0)+BONDING_ROUNDS, start=end-BONDING_ROUNDS, pct=Math.max(0,Math.min(100,Math.round((cur-start)/BONDING_ROUNDS*100)));
      prog=`<div class="pos-prog"><i style="width:${pct}%"></i></div><div class="pos-progtxt">fondos disponibles en ${esc(fmt(String(Math.max(0,end-cur))))} rondas</div>`; }
    const rewardTxt = reward>0 ? `<span class="pos-reward">🎁 <b>${esc(qchDisp(reward))}</b></span>` : `<span class="pos-reward">🎁 sin recompensa aún</span>`;
    return `<div class="pos-card">
      <div class="pos-top">
        <div class="pos-val">${esc(valName(s.validator))}<div class="pv-addr">${esc(short(s.validator))}</div></div>
        <div class="pos-amt">${esc(qchDisp(amount))}<small>${esc(usdOf(amount))}</small></div>
      </div>
      <div class="pos-meta"><span class="badge ${b.cls}">${esc(b.txt)}</span>${rewardTxt}</div>
      ${prog}
      <div class="pos-actions">
        <button class="btn-sec" data-claim="${i}" ${reward>0?'':'disabled'}>Reclamar</button>
        <button class="btn-sec" data-undel="${i}" ${ready?'':'disabled'}>Retirar</button>
      </div>
    </div>`;
  }).join("");
  $("stk-total").textContent=qchDisp(totStake);
  $("stk-rewards").textContent=qchDisp(totReward);
  list.querySelectorAll("button[data-claim]:not([disabled])").forEach(b=>b.onclick=()=>stakeAction("claim", stakes[+b.dataset.claim]));
  list.querySelectorAll("button[data-undel]:not([disabled])").forEach(b=>b.onclick=()=>stakeAction("undelegate", stakes[+b.dataset.undel]));
}

async function stakeCtx(){
  const addr=addressFromSeed(SEED);
  const acct=await api("/api/account/"+encodeURIComponent(addr));
  const cid=await api("/api/chain_id");
  return { nonce:BigInt(acct.nonce), chainId:fromHex(cid.chain_id), validUntil:await txValidUntil() };
}

// TTL OBLIGATORIO (endurecimiento): TODA transacción firmada por la wallet lleva
// un `valid_until_round` acotado — nunca 0 (que el nodo interpreta como "sin
// caducidad"). Fail-closed: si no podemos leer la ronda actual del nodo, LANZA
// en vez de firmar una tx que no caduca (una tx sin caducidad capturada por un
// atacante o atascada en una cola podría ejecutarse mucho después). Un solo
// helper para transferencias, staking, gobernanza y contratos.
const TX_TTL_ROUNDS = 300n;   // ventana de validez firmada (~minutos según el intervalo de ronda)
async function txValidUntil(){
  let node=null;
  try{ node=await api("/api/node"); }catch(e){ node=null; }
  const nr = node && node.online!==false ? Number(node.next_round) : NaN;
  if(!Number.isFinite(nr) || nr<0){
    throw new Error("no se pudo leer la ronda actual del nodo — no se firma una transacción sin caducidad; reintentá cuando el nodo responda");
  }
  return BigInt(Math.trunc(nr)) + TX_TTL_ROUNDS;   // siempre > 0 (fail-closed)
}

$("st-recover").onclick=async()=>{
  const msg=$("st-msg"); msg.className="msg"; msg.style.display="block"; msg.textContent="buscando posiciones desde tu semilla…";
  try{
    const n=NODE_V7 ? await recoverStakesV7() : await recoverStakes();
    msg.className="msg ok"; msg.textContent = n>0 ? `✓ Recuperé ${n} delegación${n>1?"es":""}` : "no se encontraron delegaciones nuevas para esta semilla";
    await renderStaking();
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
};
$("st-import-btn").onclick=importStakeByAddress;

// ---- staking v7 (shares+índice, sin validador destino) ----
// Sólo se usa cuando NODE_V7 (la red corre economics_v7). Firma con los signers
// v7 de qchain-wasm (verificados end-to-end contra un nodo v7 real). Las
// posiciones usan la MISMA derivación desde la semilla (stakeAddressFromSeed) →
// recuperables, igual que las v6.
// Formatea una duración (ms) en algo humano: "2d 3h" / "11h 59m" / "45m" / "listo".
function fmtDur(ms){
  if(!(ms>0)) return "listo";
  const s=Math.round(ms/1000), d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  if(d>0) return d+"d "+h+"h";
  if(h>0) return h+"h "+m+"m";
  if(m>0) return m+"m";
  return Math.max(1,s)+"s";
}
async function renderStakingV7(addr){
  await loadStakingMeta();                 // APY de emisión (economics)
  $("stk-commission").textContent="—";     // v7 no expone comisión por-validador acá
  try{ const acct=await api("/api/account/"+encodeURIComponent(addr)); STK_AVAIL=BigInt(acct.balance||0); $("st-avail").textContent="disponible: "+qchDisp(STK_AVAIL); }catch(e){ $("st-avail").textContent="disponible: —"; }
  let stakes=myStakes().filter(s=>s.v7);
  const list=$("st-list");
  if(!stakes.length){ list.innerHTML='<div class="empty">buscando posiciones…</div>'; try{ await recoverStakesV7(); }catch(e){} stakes=myStakes().filter(s=>s.v7); }
  if(!stakes.length){ list.innerHTML='<div class="empty">todavía no tenés posiciones de staking</div>'; $("stk-total").textContent="0 QCH"; $("stk-rewards").textContent="0 QCH"; return; }
  const live=await Promise.all(stakes.map(s=>api("/api/stake_v7/"+encodeURIComponent(s.stakeAccount)).catch(()=>null)));
  let totVal=0n, totDep=0n;
  list.innerHTML=stakes.map((s,i)=>{
    const d=live[i];
    if(!(d&&d.exists)){ return `<div class="pos-card"><div class="pos-top"><div class="pos-val">Posición v7<div class="pv-addr">${esc(short(s.stakeAccount))}</div></div><div class="pos-amt">—</div></div><div class="pos-meta"><span class="badge cool">no encontrada</span></div><div class="hint" style="margin-top:8px">Esta posición ya no existe en la red (o la red se reinició).</div><div class="pos-actions"><button class="btn-sec" data-v7drop="${esc(s.stakeAccount)}">Quitar de la lista</button></div></div>`; }
    const value=BigInt(d.value||0), dep=BigInt(d.net_deposited||0), unb=BigInt(d.unbonding_amount||0);
    totVal+=value; totDep+=dep;
    const gain=value>dep?value-dep:0n;
    // Cadencia real on-chain para las barras de progreso.
    const rpq=Number(d.rounds_per_quanto||0), ri=Number(d.round_interval_ms||0), cr=Number(d.current_round||0);
    const unbQ=Number(d.unbonding_quantos||1);
    let badge, actions='', progHtml='';
    if(unb>0n && d.withdrawable){
      badge={cls:'ready',txt:'Listo para cobrar'};
      actions=`<button class="btn-sec" data-v7withdraw="${i}">Cobrar ${esc(qchDisp(unb))}</button>`;
      progHtml=`<div class="pos-progtxt"><span>🔓 Fondos liberados</span><b>${esc(qchDisp(unb))} listos</b></div><div class="pos-prog"><i class="unb" style="width:100%"></i></div>`;
    } else if(unb>0n){
      badge={cls:'cool',txt:'En unbonding'};
      const readyRound=Number(d.unbonding_ready_quanto||0)*rpq, totalRounds=Math.max(1,unbQ*rpq);
      const leftRounds=Math.max(0,readyRound-cr);
      const pct=Math.max(3,Math.min(100,Math.round((totalRounds-leftRounds)/totalRounds*100)));
      actions=`<button class="btn-sec" disabled>🔒 en espera</button>`;
      progHtml=`<div class="pos-progtxt"><span>⏳ Disponible para cobrar en</span><b>~${esc(fmtDur(leftRounds*ri))}</b></div><div class="pos-prog"><i class="unb" style="width:${pct}%"></i></div>`;
    } else if(d.activating){
      // Depósito recién hecho: en pausa hasta que empiece el próximo cuanto — así
      // no cobra la recompensa del cuanto en que entró (activación alineada).
      badge={cls:'warm',txt:'Activándose'};
      actions=`<button class="btn-sec" data-v7unstake="${i}">Retirar</button>`;
      const into=rpq>0?(((cr%rpq)+rpq)%rpq):0, pct=rpq>0?Math.max(4,Math.min(100,Math.round(into/rpq*100))):4;
      progHtml=`<div class="pos-progtxt"><span>⏳ Empieza a rendir en</span><b>~${esc(fmtDur(rpq>0?(rpq-into)*ri:0))}</b></div><div class="pos-prog"><i class="rw" style="width:${pct}%"></i></div>`;
    } else if(value>0n){
      badge={cls:'active',txt:'Activo · rindiendo'};
      actions=`<button class="btn-sec" data-v7unstake="${i}">Retirar todo</button>`;
      if(rpq>0){
        const into=((cr%rpq)+rpq)%rpq, pct=Math.max(3,Math.min(100,Math.round(into/rpq*100)));
        progHtml=`<div class="pos-progtxt"><span>🎁 Próxima recompensa en</span><b>~${esc(fmtDur((rpq-into)*ri))}</b></div><div class="pos-prog"><i class="rw" style="width:${pct}%"></i></div>`;
      }
    } else { badge={cls:'cool',txt:'Vacía'}; }
    const gainTxt = d.activating ? `<span class="pos-reward">🕒 en pausa · rinde desde el próximo cuanto</span>` : (gain>0n ? `<span class="pos-reward">🎁 <b>${esc(qchDisp(gain))}</b> rendimiento</span>` : `<span class="pos-reward">🎁 acumulando…</span>`);
    const headAmt = value>0n?value:unb;
    return `<div class="pos-card">
      <div class="pos-top">
        <div class="pos-val">Staking v7<div class="pv-addr">${esc(short(s.stakeAccount))}</div></div>
        <div class="pos-amt">${esc(qchDisp(headAmt))}<small>${esc(usdOf(headAmt))}</small></div>
      </div>
      <div class="pos-meta"><span class="badge ${badge.cls}">${esc(badge.txt)}</span>${gainTxt}</div>
      <div class="pos-brk"><span>Capital <b>${esc(qchDisp(dep))}</b></span><span>Rendimiento <b class="g">${esc(qchDisp(gain))}</b></span></div>
      ${progHtml}
      <div class="pos-actions">${actions}</div>
    </div>`;
  }).join("");
  $("stk-total").textContent=qchDisp(totVal);
  $("stk-rewards").textContent=qchDisp(totVal>totDep?totVal-totDep:0n);
  list.querySelectorAll("button[data-v7unstake]").forEach(b=>b.onclick=()=>v7StakeAction("unstake", stakes[+b.dataset.v7unstake], live[+b.dataset.v7unstake]));
  list.querySelectorAll("button[data-v7withdraw]").forEach(b=>b.onclick=()=>v7StakeAction("withdraw", stakes[+b.dataset.v7withdraw], live[+b.dataset.v7withdraw]));
  list.querySelectorAll("button[data-v7drop]").forEach(b=>b.onclick=()=>{ if(confirm("Esta posición no existe en la red. ¿Quitarla de la lista? (no toca ningún fondo)")){ dropStake(b.dataset.v7drop); renderStaking(); } });
}

async function v7Stake(){
  const amt=$("st-amount").value.trim(), msg=$("st-msg"); msg.className="msg"; msg.textContent="";
  let amount; try{ amount=qchToUnits(amt); }catch(e){ msg.className="msg err"; msg.textContent="monto inválido (ej: 1,5)"; return; }
  if(amount<=0n){ msg.className="msg err"; msg.textContent="poné un monto mayor a 0"; return; }
  $("st-delegate").disabled=true; msg.style.display="block"; msg.textContent="firmando en tu navegador…";
  try{
    let index=nextStakeIndex(), position=stakeAddressFromSeed(SEED, index), guard=0;
    while(guard++<300){
      const d=await api("/api/stake_v7/"+encodeURIComponent(position)).catch(()=>null);
      if(!(d && d.exists)) break;            // índice libre → usar este
      index++; position=stakeAddressFromSeed(SEED, index);
    }
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson=signV7Stake(SEED, position, amount, nonce, chainId, 50000000n, validUntil);
    msg.textContent="enviando al nodo…";
    await relaySigned(txJson);
    saveStake({ stakeAccount: position, index, v7:true, amount:amount.toString() });
    msg.className="msg ok"; msg.innerHTML=`✓ Staking de ${esc(amt)} QCH`;
    $("st-amount").value="";
    setTimeout(renderStaking, 1500);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("st-delegate").disabled=false;
}

async function v7StakeAction(kind, pos, d){
  const msg=$("st-msg"); msg.className="msg"; msg.style.display="block";
  try{
    const {nonce,chainId,validUntil}=await stakeCtx();
    let txJson;
    if(kind==="unstake"){
      const value=BigInt((d&&d.value)||0);
      if(value<=0n){ msg.className="msg err"; msg.textContent="no hay valor para retirar"; return; }
      const wMs=Number((d&&d.unbonding_quantos)||1)*Number((d&&d.rounds_per_quanto)||0)*Number((d&&d.round_interval_ms)||0);
      const wTxt=wMs>0?("~"+fmtDur(wMs)):"un período";
      if(!confirm("Al retirar, tu staking entra en un período de espera (unbonding) de "+wTxt+" antes de poder cobrarlo. Durante ese tiempo deja de generar rendimiento. Cuando termine, tocá «Cobrar». ¿Continuar?")){ msg.textContent=""; msg.style.display="none"; return; }
      msg.textContent="retirando (firmando en tu navegador)…";
      txJson=signV7BeginUnstake(SEED, pos.stakeAccount, value, nonce, chainId, 50000000n, validUntil);
    } else {
      msg.textContent="cobrando (firmando en tu navegador)…";
      txJson=signV7WithdrawUnbonded(SEED, pos.stakeAccount, nonce, chainId, 50000000n, validUntil);
    }
    await relaySigned(txJson);
    msg.className="msg ok"; msg.textContent = kind==="unstake" ? "✓ Unbonding iniciado — cobrá cuando termine el período" : "✓ Fondos cobrados";
    setTimeout(renderStaking, 1500);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
}

async function recoverStakesV7(){
  const addr=myAddress(); if(!addr) return 0;
  const all=allStakes(); const listAll=all[addr]||[];
  let idx=0, misses=0, found=0; const MAX_IDX=256, MAX_MISS=10;
  while(idx<MAX_IDX && misses<MAX_MISS){
    const sa=stakeAddressFromSeed(SEED, idx);
    const d=await api("/api/stake_v7/"+encodeURIComponent(sa)).catch(()=>null);
    if(d && d.exists && d.owner===addr){
      if(!listAll.some(p=>p.stakeAccount===sa)){ listAll.push({ stakeAccount:sa, index:idx, v7:true, amount:String(d.value||0) }); found++; }
      misses=0;
    } else { misses++; }
    idx++;
  }
  all[addr]=listAll; localStorage.setItem(STAKES_KEY, JSON.stringify(all));
  return found;
}

// ===================== GOBERNANZA =====================
// Firma Vote/Finalize/Execute en el navegador (signVote/signFinalize/signExecute
// de qchain-wasm) y relaya por /api/relay-tx, igual que staking. El estado de la
// propuesta se lee de /api/proposal/:addr (decodificado por el server, read-only).
let GOV_PROP=null, GOV_CHOICE=0;
document.querySelectorAll('#gov-choice button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#gov-choice button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); GOV_CHOICE=+b.dataset.choice;
});
function govStakeOptions(){
  const sel=$("gov-stake"), list=myStakes();
  if(!list.length){ sel.innerHTML='<option value="">— no tenés posiciones de staking —</option>'; return; }
  sel.innerHTML=list.map(p=>`<option value="${esc(p.stakeAccount)}">${esc(short(p.stakeAccount))} · ${esc(qchDisp(p.amount))}</option>`).join("");
}
async function govLoad(){
  const raw=$("gov-addr").value.trim(), msg=$("gov-msg"); msg.className="msg"; msg.style.display="block"; msg.textContent="";
  if(!raw){ msg.className="msg err"; msg.textContent="pegá la dirección de una propuesta"; return; }
  msg.textContent="consultando…";
  let p; try{ p=await api("/api/proposal/"+encodeURIComponent(raw)); }
  catch(e){ msg.className="msg err"; msg.textContent=e.message||"no se pudo consultar la propuesta"; $("gov-detail").style.display="none"; return; }
  GOV_PROP=p; msg.style.display="none";
  $("gov-action").textContent=p.action||"—";
  $("gov-tier").textContent = (p.tier==="registry"?"Registro de algoritmos (supermayoría + time-lock)":"Parámetro económico (mayoría simple, sin time-lock)");
  const statusMap={Voting:"En votación",Passed:"Aprobada",Rejected:"Rechazada",Executed:"Ejecutada"};
  $("gov-status").textContent=statusMap[p.status]||p.status;
  $("gov-ends").textContent=p.voting_ends_round;
  $("gov-yes").textContent="+"+qchDisp(p.yes_stake);
  $("gov-no").textContent="+"+qchDisp(p.no_stake);
  $("gov-abs").textContent=qchDisp(p.abstain_stake);
  $("gov-votes").textContent=p.votes;
  govStakeOptions();
  $("gov-detail").style.display="block";
}
$("gov-load").onclick=govLoad;
$("gov-vote").onclick=async()=>{
  const msg=$("gov-msg"); msg.className="msg"; msg.style.display="block";
  const proposal=$("gov-addr").value.trim(), stake=$("gov-stake").value;
  if(!proposal){ msg.className="msg err"; msg.textContent="consultá primero una propuesta"; return; }
  if(!stake){ msg.className="msg err"; msg.textContent="necesitás una posición de staking para votar (delegá primero)"; return; }
  msg.textContent="firmando tu voto en el navegador…";
  try{
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson=signVote(SEED, proposal, stake, GOV_CHOICE, nonce, chainId, 10000000n, validUntil);
    await relaySigned(txJson);
    const label=["Sí","No","Abstención"][GOV_CHOICE];
    msg.className="msg ok"; msg.textContent="✓ Voto enviado: "+label;
    setTimeout(govLoad, 1600);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
};
$("gov-finalize").onclick=async()=>{
  const msg=$("gov-msg"); msg.className="msg"; msg.style.display="block";
  const proposal=$("gov-addr").value.trim(); if(!proposal){ msg.className="msg err"; msg.textContent="consultá primero una propuesta"; return; }
  msg.textContent="finalizando (firmando en el navegador)…";
  try{
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson=signFinalize(SEED, proposal, nonce, chainId, 10000000n, validUntil);
    await relaySigned(txJson);
    msg.className="msg ok"; msg.textContent="✓ Finalización enviada — los votos se cuentan al ejecutarse";
    setTimeout(govLoad, 1600);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
};
$("gov-execute").onclick=async()=>{
  const msg=$("gov-msg"); msg.className="msg"; msg.style.display="block";
  const proposal=$("gov-addr").value.trim(); if(!proposal){ msg.className="msg err"; msg.textContent="consultá primero una propuesta"; return; }
  // El tier decide qué cuenta singleton nombra Execute (params vs registro). Lo
  // sabemos por /api/proposal; el nodo igual rechaza el singleton equivocado.
  const registry = !!(GOV_PROP && GOV_PROP.registry);
  msg.textContent="ejecutando (firmando en el navegador)…";
  try{
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson=signExecute(SEED, proposal, registry, nonce, chainId, 10000000n, validUntil);
    await relaySigned(txJson);
    msg.className="msg ok"; msg.textContent="✓ Ejecución enviada — si la propuesta pasó, el cambio se aplica";
    setTimeout(govLoad, 1600);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
};

$("st-delegate").onclick=async()=>{
  if(NODE_V7) return v7Stake();
  const validator=$("st-validator").value.trim(), amt=$("st-amount").value.trim(), msg=$("st-msg"); msg.className="msg"; msg.textContent="";
  if(!validator){ msg.className="msg err"; msg.textContent="poné la dirección del validador"; return; }
  // Bloqueá delegar a tu PROPIA dirección de wallet: eso crea un "self-stake"
  // (owner == validator) cuyo retiro on-chain es un proceso de DOS pasos de 100
  // rondas (protección anti-slash pensada para validadores reales, no para un
  // usuario común) - la trampa exacta que dejaba fondos "atascados" con un
  // "retiro enviado" que no devolvía nada. Elegí un validador de la lista.
  if(validator===myAddress()){ msg.className="msg err"; msg.textContent="no podés delegar a tu propia dirección de wallet — elegí un validador de la lista de abajo."; return; }
  let amount; try{ amount=qchToUnits(amt); }catch(e){ msg.className="msg err"; msg.textContent="monto inválido (ej: 1,5)"; return; }
  $("st-delegate").disabled=true; msg.style.display="block"; msg.textContent="firmando en tu navegador…";
  try{
    // Dirección de la cuenta de stake DERIVADA de la semilla (recuperable),
    // no random. Se salta cualquier índice cuya dirección ya exista on-chain
    // (una posición previa aún abierta), para que Delegate nunca choque con
    // una cuenta ya creada.
    let index=nextStakeIndex(), stakeAccount=stakeAddressFromSeed(SEED, index), guard=0;
    while(guard++<300){
      const d=await api("/api/stake/"+encodeURIComponent(stakeAccount)).catch(()=>null);
      if(!(d && d.exists)) break;             // libre → usar este índice
      index++; stakeAccount=stakeAddressFromSeed(SEED, index);
    }
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson=signDelegate(SEED, validator, amount, stakeAccount, nonce, chainId, 10000000n, validUntil);
    msg.textContent="enviando al nodo…";
    await relaySigned(txJson);
    saveStake({ stakeAccount, index, validator, amount:amount.toString() });
    msg.className="msg ok"; msg.innerHTML=`✓ Delegaste ${esc(amt)} QCH`;
    $("st-amount").value="";
    setTimeout(renderStaking, 1500);
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
  $("st-delegate").disabled=false;
};

async function stakeAction(kind, pos){
  const msg=$("st-msg"); msg.className="msg"; msg.style.display="block";
  try{
    // Estado real ANTES de firmar, para (a) no enviar una tx que la ejecución
    // rechazaría y (b) comparar contra el estado DESPUÉS para reportar lo que de
    // verdad pasó (no solo que se admitió al mempool - el bug que hacía que
    // "retiro enviado" mintiera).
    const d=await api("/api/stake/"+encodeURIComponent(pos.stakeAccount)).catch(()=>null);
    if(kind==="undelegate" && d && d.exists){
      const until=Math.max(d.bonding_until_round||0, d.locked_until_round||0);
      if((d.current_round||0) < until){ msg.className="msg err"; msg.textContent=`todavía no podés retirar — disponible en la ronda ${until} (vas por la ${d.current_round})`; return; }
      const selfStake = d.owner===d.validator;
      if(selfStake){
        const req=d.unbonding_requested_at_round;
        if(req==null){
          if(!confirm("Esta posición es un self-stake (delegaste a tu propia dirección). El retiro es en DOS pasos: este paso inicia un unbonding de 100 rondas y NO devuelve los fondos todavía; pasadas esas rondas tenés que darle a Retirar OTRA vez para recibirlos. ¿Continuar?")){ msg.textContent=""; msg.style.display="none"; return; }
        } else if((d.current_round||0) < req+100){
          msg.className="msg err"; msg.textContent=`self-stake en unbonding — vas a poder retirar los fondos en la ronda ${req+100} (vas por la ${d.current_round})`; return;
        }
      }
    }
    if(kind==="claim" && d && d.exists && Number(d.pending_reward)===0){ msg.className="msg err"; msg.textContent="no hay recompensa pendiente para reclamar todavía"; return; }
    msg.className="msg"; msg.textContent=(kind==="claim"?"reclamando":"retirando")+" (firmando en tu navegador)…";
    const {nonce,chainId,validUntil}=await stakeCtx();
    const txJson = kind==="claim"
      ? signClaimReward(SEED, pos.stakeAccount, nonce, chainId, 10000000n, validUntil)
      : signUndelegate(SEED, pos.stakeAccount, nonce, chainId, 10000000n, validUntil);
    await relaySigned(txJson);
    msg.className="msg"; msg.textContent="confirmando en la cadena…";
    // Confirmación REAL: sondear el estado on-chain unos segundos y reportar el
    // resultado verdadero, en vez de decir "hecho" apenas se admite al mempool.
    const beforeReq = d && d.exists ? d.unbonding_requested_at_round : null;
    const beforePending = d && d.exists ? Number(d.pending_reward||0) : 0;
    let outcome=null;
    for(let i=0;i<12 && !outcome;i++){
      await new Promise(r=>setTimeout(r,700));
      const a=await api("/api/stake/"+encodeURIComponent(pos.stakeAccount)).catch(()=>null);
      if(kind==="undelegate"){
        if(!a || !a.exists || Number(a.amount)===0){ outcome={done:true}; }
        else if(a.unbonding_requested_at_round!=null && beforeReq==null){ outcome={unbonding:a.unbonding_requested_at_round}; }
      } else { // claim: se acreditó si la recompensa pendiente cayó
        if(a && a.exists && Number(a.pending_reward) < beforePending){ outcome={done:true}; }
        else if(!a || !a.exists){ outcome={done:true}; }
      }
    }
    if(kind==="undelegate"){
      if(outcome && outcome.done){ msg.className="msg ok"; msg.textContent="✓ Retiro completado — recibiste tus fondos"; dropStake(pos.stakeAccount); }
      else if(outcome && outcome.unbonding!=null){ msg.className="msg ok"; msg.textContent=`Unbonding iniciado (self-stake). Volvé a darle a Retirar en la ronda ${outcome.unbonding+100} para recibir los fondos.`; }
      else { msg.className="msg err"; msg.textContent="el retiro no se aplicó (probable bonding/lock aún vigente). Revisá el estado y reintentá."; }
    } else {
      if(outcome && outcome.done){ msg.className="msg ok"; msg.textContent="✓ Recompensa reclamada"; }
      else { msg.className="msg err"; msg.textContent="la recompensa no se acreditó todavía — reintentá en unos segundos."; }
    }
    renderStaking();
  }catch(e){ msg.className="msg err"; msg.textContent=e.message; }
}

// configuración
$("set-download").onclick=()=>downloadEncryptedBackup();
$("set-lock").onclick=()=>{ MASTER=null; SEED=null; ACCT=0; PW=null; $("u-pass").value=""; showView("unlock"); };
$("set-remove").onclick=()=>{
  if(confirm("Esto borra la wallet cifrada de ESTE navegador. Solo vas a poder recuperarla con tu respaldo. ¿Seguir?")){
    localStorage.removeItem(LS_KEY); localStorage.removeItem(BIO_KEY); location.reload();
  }
};

// ---- desbloqueo biométrico (Settings) ----
// Muestra la tarjeta solo si el dispositivo tiene autenticador de plataforma
// (Face ID / Touch ID / huella). Alterna Activar/Desactivar según el estado.
async function refreshBioSettings(){
  const avail = await bioAvailable();
  $("bio-section-title").style.display = avail ? "block" : "none";
  $("bio-card").style.display = avail ? "block" : "none";
  if(!avail) return;
  const on = bioEnabled();
  $("bio-enable").style.display = on ? "none" : "block";
  $("bio-disable").style.display = on ? "block" : "none";
  $("bio-msg").className="msg"; $("bio-msg").textContent="";
}
$("bio-enable").onclick=async()=>{
  const msg=$("bio-msg"); msg.className="msg"; msg.style.display="block"; msg.textContent="registrando tu biométrico…";
  $("bio-enable").disabled=true;
  try{
    await enrollBiometric();
    msg.className="msg ok"; msg.textContent="✓ Face ID / huella activado en este dispositivo";
    await refreshBioSettings();
  }catch(e){ msg.className="msg err"; msg.textContent=e.message||"no se pudo activar"; }
  $("bio-enable").disabled=false;
};
$("bio-disable").onclick=async()=>{
  disableBiometric();
  await refreshBioSettings();
  $("bio-msg").className="msg ok"; $("bio-msg").style.display="block"; $("bio-msg").textContent="biométrico desactivado — seguís con tu contraseña";
};

// ==================== campo cuántico (canvas) ====================
// Ondas sinusoidales fluidas + partículas ascendentes, en gradiente violeta.
// Es el fondo "cuántico" del arranque y (más sutil) de toda la app. Ligero:
// DPR limitado a 2, ~30 partículas, se detiene al desmontar.
function quantumWaves(canvas, opts){
  const ctx=canvas.getContext("2d"); if(!ctx) return {stop(){}};
  const cfg=Object.assign({lines:5,amp:20,speed:.013,alpha:.5,particles:26,bright:false},opts||{});
  let W=0,H=0,dpr=1,raf=0,t=0,parts=[];
  function resize(){ dpr=Math.min(window.devicePixelRatio||1,2); W=canvas.clientWidth||canvas.offsetWidth; H=canvas.clientHeight||canvas.offsetHeight;
    canvas.width=Math.max(1,W*dpr); canvas.height=Math.max(1,H*dpr); ctx.setTransform(dpr,0,0,dpr,0,0); }
  function seed(){ parts=[]; for(let i=0;i<cfg.particles;i++) parts.push({x:Math.random()*W,y:Math.random()*H,r:Math.random()*1.4+.4,s:Math.random()*.35+.06,ph:Math.random()*6.28}); }
  function frame(){ t+=cfg.speed; ctx.clearRect(0,0,W,H);
    for(let l=0;l<cfg.lines;l++){
      const yBase=H*(0.32+0.52*(l/Math.max(1,cfg.lines-1)));
      const g=ctx.createLinearGradient(0,0,W,0);
      const a=cfg.alpha*(cfg.bright?.95:.5)*(1-l/(cfg.lines*1.7));
      g.addColorStop(0,"rgba(124,110,255,0)"); g.addColorStop(.5,"rgba(150,130,255,"+a.toFixed(3)+")"); g.addColorStop(1,"rgba(102,144,255,0)");
      ctx.strokeStyle=g; ctx.lineWidth=1; ctx.beginPath();
      for(let x=0;x<=W;x+=7){ const y=yBase+Math.sin(x*0.012+t+l*0.75)*cfg.amp*(1-l/(cfg.lines*1.6))+Math.sin(x*0.031-t*1.35)*4;
        x===0?ctx.moveTo(x,y):ctx.lineTo(x,y); }
      ctx.stroke();
    }
    for(const p of parts){ p.y-=p.s; if(p.y<-4){p.y=H+4;p.x=Math.random()*W;}
      const tw=0.35+0.65*Math.abs(Math.sin(t*2+p.ph));
      ctx.fillStyle="rgba(180,165,255,"+((cfg.bright?.7:.42)*tw).toFixed(3)+")";
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,6.283); ctx.fill();
    }
    raf=requestAnimationFrame(frame);
  }
  resize(); seed(); frame();
  const onR=()=>{resize();seed();}; window.addEventListener("resize",onR);
  return { stop(){ cancelAnimationFrame(raf); window.removeEventListener("resize",onR); } };
}

// ==================== animación de arranque ====================
function runBoot(){
  return new Promise(res=>{
    const boot=$("boot"); if(!boot){ res(); return; }
    const reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
    let w=null; try{ w=quantumWaves($("boot-wave"),{bright:true,lines:6,amp:24,particles:36,alpha:.6,speed:.016}); }catch(e){}
    const finish=()=>{ boot.classList.add("done"); setTimeout(()=>{ try{w&&w.stop();}catch(e){} boot.remove(); res(); }, 680); };
    if(reduce){ setTimeout(finish, 350); return; }
    const st=$("boot-status"), steps=["Inicializando núcleo…","Verificando entorno seguro…","Generando campo cuántico…","Listo"];
    let i=0; if(st){ st.textContent=steps[0]; const iv=setInterval(()=>{ i++; if(i<steps.length){ st.textContent=steps[i]; } else clearInterval(iv); }, 640); }
    setTimeout(finish, 2950);
  });
}

// ==================== puente wallet-connect (firmar contratos desde QScan) ====================
// Modelo de seguridad (ver docs/WALLET-CONNECT.md): esta wallet es el LÍMITE DE
// CONFIANZA. QScan (no confiable) le pide firmas por window.postMessage; la
// semilla NUNCA sale de acá. Invariantes: (1) origin allowlist estricto validado
// en CADA mensaje; (2) aprobación HUMANA explícita por acción, mostrando en claro
// qué se firma; (3) conectar = solo lectura de la dirección; cada firma
// re-pregunta; (4) el bridge está APAGADO salvo que el server pase connect_origin.
let CONNECT_ORIGIN = null;   // origen exacto autorizado (de /api/config), ej. https://scan.qchainhq.com
// Ventana de validez CORTA para una tx de contrato (re-audit #4): expira ~120
// rondas después de firmarla, así una tx firmada-pero-no-transmitida no se puede
// reusar mucho más tarde contra un estado on-chain cambiado.
const CONTRACT_TX_TTL_ROUNDS = 120n;
// Límites de una tx de contrato para el puente (re-audit #5). El nodo y el signer
// también los aplican; acá se rechaza temprano con un mensaje claro.
const MAX_MODULE_BYTES = 256*1024, MAX_CALL_ACCOUNTS = 64, MAX_CALL_ARGS = 32;
// PROCEDENCIA "verificada" (re-audit #6): code_hash SHA3-256 de las plantillas
// OFICIALES del SDK de qchain. Si el contrato que se llama coincide, la wallet
// muestra "✅ verificado: <nombre> oficial"; si no, "⚠ no verificado" (código
// desconocido — no confíes en su identidad). Es el equivalente cliente-side de
// un "verified source" sin registro on-chain de fuente publicada.
const KNOWN_CONTRACTS = {
  "bb30d4027ecd8947781305414778736ae2bae16eabec4baf5388273eaaf329f5":"token (fungible) oficial de qchain",
  "6c0fd056350763b5c200d377a444cc57d386361ecd4db6ae3c27746b7a4eba34":"bóveda (vault) oficial de qchain",
  "28ba3dcd0441ac046fe76fc94e511c62cf4e431365a9263bacdeabd6e681a447":"pagos/tesorería oficial de qchain",
  "de8bb893d5a3e67d0681824b764a805ef718af607f47e7bcf45f13b49546903d":"contador oficial de qchain",
  "fd8e366758ffa994b52fbe7c78fd92ae89f91c3c7dfe16232b84247333cb14f7":"contador compartido oficial de qchain",
};

// Modal de aprobación genérico: devuelve true si el usuario aprueba.
// `opts.blocked` deshabilita el botón Aprobar (p.ej. la simulación dice que
// FALLARÍA); `opts.note` muestra un aviso en rojo (el motivo del fallo o que no
// se pudo simular). Re-audit QCH-WALLET blind-signing: la aprobación se hace con
// el resultado REAL de simular la tx ya firmada, no con datos abreviados.
function bridgeApprove(title, lines, opts){
  opts=opts||{};
  return new Promise((resolve)=>{
    const ov=document.createElement("div");
    ov.style.cssText="position:fixed;inset:0;z-index:9999;background:rgba(4,6,20,.72);display:flex;align-items:center;justify-content:center;padding:18px";
    // Cada fila es [etiqueta, valor, tipo?] — tipo "danger" la pinta en ROJO (un
    // cambio sensible de estado: dueño/datos/código/eliminación) y "signer" la
    // resalta en cian (una cuenta del FIRMANTE). Todo se escapa con esc().
    const rows=lines.map(l=>{
      const kind=l[2]||"";
      const danger=kind==="danger", signer=kind==="signer";
      const bd = danger ? "rgba(255,90,90,.35)" : "rgba(255,255,255,.08)";
      const bg = danger ? "background:rgba(255,90,90,.07);" : "";
      const lc = danger ? "color:#ff9a9a;opacity:1" : (signer ? "color:#7fe3ff;opacity:1" : "opacity:.7");
      const vc = danger ? "color:#ffb0b0;" : (signer ? "color:#7fe3ff;" : "");
      return `<div style="display:flex;justify-content:space-between;gap:12px;padding:7px 8px;border-bottom:1px solid ${bd};${bg}border-radius:6px"><span style="${lc}">${esc(l[0])}</span><span style="font-weight:600;word-break:break-all;text-align:right;${vc}">${esc(l[1])}</span></div>`;
    }).join("");
    const noteHtml=opts.note?`<div style="margin:12px 0;padding:9px 11px;border-radius:9px;background:rgba(255,90,90,.12);border:1px solid rgba(255,90,90,.4);color:#ffb0b0;font-size:12.5px">${esc(opts.note)}</div>`:"";
    // SEGUNDA CONFIRMACIÓN para cambios sensibles (re-audit QCH-SIMULATE): un
    // cambio de dueño/permisos/datos/código o la eliminación de una cuenta exige
    // marcar explícitamente esta casilla ANTES de habilitar "Aprobar" — no basta
    // con un clic distraído.
    const ackHtml=opts.sensitive?`<label style="display:flex;gap:9px;align-items:flex-start;margin:12px 0;padding:10px 11px;border-radius:9px;background:rgba(255,90,90,.10);border:1px solid rgba(255,90,90,.45);cursor:pointer;font-size:12.5px;color:#ffd0d0"><input type="checkbox" id="bg-ack" style="margin-top:2px;flex:0 0 auto"><span>Confirmo que entiendo que esta transacción realiza <b>cambios sensibles de estado</b> (dueño / permisos / datos / código, o elimina una cuenta) y quiero continuar.</span></label>`:"";
    ov.innerHTML=`<div style="max-width:440px;width:100%;background:var(--card,#0f1330);border:1px solid rgba(140,120,255,.25);border-radius:16px;padding:20px;max-height:88vh;overflow:auto">
      <div style="font-weight:800;font-size:17px;margin-bottom:4px">${esc(title)}</div>
      <div style="opacity:.65;font-size:13px;margin-bottom:12px">Pedido desde <span class="mono">${esc(CONNECT_ORIGIN||"")}</span></div>
      ${rows}
      ${noteHtml}
      ${ackHtml}
      <div style="opacity:.6;font-size:12px;margin:12px 0">Tu clave NUNCA sale de esta wallet. Se firma acá, se SIMULA contra el nodo, y recién si aprobás se envía la MISMA transacción ya firmada.</div>
      <div style="display:flex;gap:10px;margin-top:6px">
        <button id="bg-no" class="btn-sec" style="flex:1">Rechazar</button>
        <button id="bg-yes" class="btn-glow" style="flex:1">Aprobar y enviar</button>
      </div></div>`;
    document.body.appendChild(ov);
    ov.querySelector("#bg-no").onclick=()=>{ ov.remove(); resolve(false); };
    const yes=ov.querySelector("#bg-yes");
    const ack=ov.querySelector("#bg-ack");
    // El botón "Aprobar" se habilita SÓLO si la simulación no está bloqueada Y, si
    // hay cambios sensibles, la casilla de segunda confirmación está marcada.
    function refresh(){
      const ok = !opts.blocked && (!opts.sensitive || (ack && ack.checked));
      yes.disabled=!ok;
      yes.style.opacity=ok?"":"0.45";
      yes.style.cursor=ok?"":"not-allowed";
    }
    if(ack) ack.onchange=refresh;
    refresh();
    yes.onclick=()=>{ if(yes.disabled) return; ov.remove(); resolve(true); };
  });
}

// Simula una tx ya firmada contra el nodo (dry-run, no compromete nada) vía el
// proxy read-only de la wallet. Devuelve el resultado {ok,status,fee,changes,...}
// o, si NO se pudo simular, un marcador {unavailable:true, busy:<429?>} — nunca
// null — para que el llamador falle CERRADO (re-audit QCH-WALLET fail-open): sin
// una simulación exitosa NO se habilita "Aprobar y enviar".
async function bridgeSimulate(txJson){
  try{
    const r=await fetch("/api/simulate",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
    if(r.status===429) return { unavailable:true, busy:true };
    if(!r.ok) return { unavailable:true, busy:false };
    return await r.json();
  }catch(e){ return { unavailable:true, busy:false }; }
}
// ¿Se puede aprobar esta acción de contrato? SÓLO si la simulación existió y dio
// ok===true (re-audit QCH-WALLET fail-open, HIGH). Simulación no disponible / 429 /
// fallida ⇒ BLOQUEADO: para un contrato con fondos reales no se firma a ciegas.
function bridgeSimBlocked(sim){ return !(sim && sim.ok===true); }
// Mensaje honesto según por qué está (o no) bloqueado.
function bridgeSimNote(sim){
  if(sim && sim.ok===true) return null;
  if(sim && sim.unavailable && sim.busy) return "El nodo está ocupado (429): no se puede simular ahora. NO se firma a ciegas — reintentá en unos segundos.";
  if(sim && sim.unavailable) return "No se pudo simular la transacción. Por seguridad, para un contrato con fondos NO se firma sin ver el resultado — reintentá.";
  if(sim && sim.ok===false){
    let m="La simulación indica que FALLARÍA: "+esc(sim.error||"motivo desconocido")+".";
    if(sim.status==="execution_failed_after_charge"){
      try{ m+=" ⚠ Aun fallando, PERDERÍAS "+qchDisp(BigInt(sim.fee||"0"))+" QCH (fee + gas ya cobrados)."; }catch(e){}
    }
    return m+" No se enviará.";
  }
  return "No se pudo simular. No se firmará a ciegas.";
}
// Filas de detalle COMPLETAS a partir de una simulación (re-audit QCH-SIMULATE #2:
// "mostrar cambios completos de estado"): fee REAL + por CADA cuenta que la tx
// cambiaría, TODO su estado antes/después — saldo, existencia (creada/eliminada),
// owner, nonce, data_hash y code_hash — no sólo el saldo. Un cambio de owner/data/
// code NO mueve saldo pero es lo MÁS sensible: puede transferir el control de una
// cuenta/contrato (admin, permisos, allowance, dirección de retiro). Cada fila
// sensible lleva un tercer elemento "danger" para pintarla en ROJO en el modal; la
// cuenta del FIRMANTE se marca "signer". Un cambio de owner/data/code sobre una
// cuenta RECIÉN CREADA es la inicialización normal (no un takeover), así que se
// muestra informativo, no en rojo; el rojo se reserva para cambios sobre cuentas
// PREEXISTENTES (donde el control realmente se transfiere) y para eliminaciones.
// ¿Este cambio de cuenta es SENSIBLE (rojo + exige 2ª confirmación)? El veredicto
// AUTORITATIVO lo da el NODO (`c.sensitive`): sabe qué direcciones son singletons
// de PROTOCOLO (su `data` la reescribe el ledger en cada tx = ruido, no un
// takeover) y distingue una cuenta NUEVA benigna (wallet vacía) de un registro de
// AUTORIDAD recién creado (una PDA program-owned con datos = un allowance/operator/
// admin lazily-creado — el vector de approve-phishing). Si el nodo es VIEJO y no
// manda `c.sensitive`, fallamos CERRADO: tratamos como sensible cualquier cambio
// de owner/data/code sobre una cuenta preexistente, una eliminación, o una cuenta
// nueva con datos (posible grant) — más avisos, nunca menos.
function simChangeSensitive(c){
  if(typeof c.sensitive==="boolean") return c.sensitive;
  const created = c.existed_before===false && c.exists_after===true;
  const deleted = c.existed_before===true && c.exists_after===false;
  const grantLike = created && c.data_changed===true; // cuenta nueva con datos
  return deleted || grantLike || (c.existed_before===true && (c.owner_changed===true||c.data_changed===true||c.code_changed===true));
}

// Filas de detalle COMPLETAS a partir de una simulación (re-audit QCH-SIMULATE #2:
// "mostrar cambios completos de estado"): fee REAL + por CADA cuenta que la tx
// cambiaría, TODO su estado antes/después — saldo, existencia (creada/eliminada),
// owner, nonce, data_hash y code_hash — no sólo el saldo. Un cambio de owner/data/
// code NO mueve saldo pero es lo MÁS sensible: puede transferir el control de una
// cuenta/contrato (admin, permisos, allowance, dirección de retiro). Cada fila
// sensible (veredicto del nodo) lleva un tercer elemento "danger" para pintarla en
// ROJO; la cuenta del FIRMANTE se marca "signer"; una cuenta de PROTOCOLO se
// etiqueta como tal (su churn es mecánica del ledger, no un ataque).
function bridgeSimLines(sim){
  const out=[];
  // Only a real, successful simulation produces change detail. A marker
  // ({unavailable:true}) or a failed sim must NOT render a fake "0" fee.
  if(!sim || sim.ok!==true) return out;
  try{ out.push(["Fee real", qchDisp(BigInt(sim.fee||"0"))]); }catch(e){}
  const me = myAddress();
  const bof=(c)=>{ try{ return BigInt(c.balance_before!=null?c.balance_before:(c.before||"0")); }catch(e){ return 0n; } };
  const aof=(c)=>{ try{ return BigInt(c.balance_after!=null?c.balance_after:(c.after||"0")); }catch(e){ return 0n; } };
  (sim.changes||[]).forEach(c=>{
    const isSigner = !!me && c.address===me;
    const proto = c.protocol===true;
    const created = c.existed_before===false && c.exists_after===true;
    const deleted = c.existed_before===true && c.exists_after===false;
    const ownerChg = c.owner_changed===true;
    const dataChg  = c.data_changed===true;
    const codeChg  = c.code_changed===true;
    const balChg   = bof(c)!==aof(c);
    const nonceChg = (c.nonce_before!=null || c.nonce_after!=null) && String(c.nonce_before)!==String(c.nonce_after);
    const sens = simChangeSensitive(c);
    // Encabezado de la cuenta con etiquetas de lo que cambia.
    const tags=[];
    if(isSigner) tags.push("TU CUENTA (firmante)");
    if(proto)    tags.push("cuenta de protocolo");
    if(created && sens) tags.push("⚠ NUEVA cuenta con DATOS/AUTORIDAD");
    else if(created)    tags.push("creada");
    if(deleted)  tags.push("⚠ ELIMINADA");
    if(ownerChg && sens && !created) tags.push("⚠ cambia DUEÑO");
    if(codeChg && sens && !created)  tags.push("⚠ cambia CÓDIGO");
    if(dataChg && sens && !created)  tags.push("⚠ cambia DATOS");
    const kind = sens ? "danger" : (isSigner ? "signer" : null);
    out.push(["Cuenta "+short(c.address), tags.length?tags.join(" · "):"(cambia)", kind]);
    if(balChg) out.push(["↳ saldo", qchDisp(bof(c))+" → "+qchDisp(aof(c)), isSigner?"signer":null]);
    if(created) out.push(["↳ existencia", "cuenta NUEVA (no existía antes)", sens?"danger":null]);
    if(deleted) out.push(["↳ existencia", "cuenta ELIMINADA (existía antes)", "danger"]);
    if(ownerChg) out.push(["↳ dueño (owner)", short(c.owner_before)+" → "+short(c.owner_after), sens?"danger":null]);
    if(nonceChg) out.push(["↳ nonce", String(c.nonce_before)+" → "+String(c.nonce_after), isSigner?"signer":null]);
    if(dataChg) out.push(["↳ data_hash", short(c.data_hash_before)+" → "+short(c.data_hash_after), sens?"danger":null]);
    if(codeChg) out.push(["↳ code_hash", short(c.code_hash_before)+" → "+short(c.code_hash_after), sens?"danger":null]);
  });
  return out;
}

// Detecta CAMBIOS SENSIBLES en la simulación (veredicto del nodo `c.sensitive`,
// con fallback fail-closed) para: (a) armar el aviso rojo y (b) EXIGIR una segunda
// confirmación explícita antes de aprobar. Distingue un GRANT (cuenta de autoridad
// recién creada = approve-phishing) de un takeover de cuenta existente y de una
// eliminación. Para un contrato SIN ABI verificada, explica que un cambio de datos
// puede representar un cambio de ADMINISTRADOR, PERMISOS, ALLOWANCE o DIRECCIÓN DE
// RETIRO — el usuario no puede saber QUÉ campo cambió sin la fuente. Devuelve
// {sensitive, note}.
function bridgeSimAlert(sim, opts){
  opts=opts||{};
  const res={ sensitive:false, note:"" };
  if(!sim || sim.ok!==true) return res;
  const me=myAddress();
  let grant=0, owner=0, data=0, code=0, del=0, signerSensitive=false;
  (sim.changes||[]).forEach(c=>{
    if(!simChangeSensitive(c)) return;
    const created = c.existed_before===false && c.exists_after===true;
    const deleted = c.existed_before===true && c.exists_after===false;
    if(deleted) del++;
    else if(created) grant++;               // registro de autoridad recién creado
    else {
      if(c.owner_changed===true) owner++;
      if(c.code_changed===true) code++;
      if(c.data_changed===true) data++;
    }
    if(!!me && c.address===me) signerSensitive=true;
  });
  if(grant+owner+data+code+del===0) return res;
  res.sensitive=true;
  const parts=[];
  if(grant) parts.push(grant+" cuenta(s) de AUTORIDAD/DATOS recién creada(s) (posible permiso/allowance/admin)");
  if(owner) parts.push(owner+" cambio(s) de DUEÑO (owner)");
  if(code)  parts.push(code+" cambio(s) de CÓDIGO (bytecode)");
  if(data)  parts.push(data+" cambio(s) de DATOS (data_hash)");
  if(del)   parts.push(del+" cuenta(s) ELIMINADA(s)");
  let m="⚠ CAMBIO SENSIBLE DE ESTADO — esta transacción hace: "+parts.join(", ")+". Un cambio de dueño/datos/código (o crear un registro de autoridad) NO mueve saldo pero puede TRANSFERIR EL CONTROL de una cuenta o darle a un tercero permiso para GASTAR tus fondos MÁS TARDE.";
  if(signerSensitive) m+=" Además MODIFICA una de TUS cuentas (la del firmante).";
  if((data||grant) && opts.unverified){
    m+=" Este contrato NO tiene ABI/código verificado: ese cambio de datos puede representar un cambio de ADMINISTRADOR, PERMISOS, ALLOWANCE o DIRECCIÓN DE RETIRO — no hay forma de saber cuál sin la fuente. Aprobá SÓLO si confiás plenamente en quién lo desplegó.";
  }
  m+=" Revisá cada fila ROJA antes de continuar.";
  res.note=m;
  return res;
}

// La primera dirección de programa (derivada de la semilla) que todavía NO tiene
// un contrato desplegado — deploy-once necesita una fresca. Se compara contra la
// lista real de contratos del nodo (/api/programs), no contra /api/account (que
// no distingue un slot vacío de una cuenta program-owned).
// Re-audit #2: the contract address is derived from the PAYER + index (salt).
// Returns {index, addr} for the first index whose derived address has no
// deployed program yet — deploy-once picks the next free slot.
async function freshProgramAddr(){
  let deployed=new Set();
  try{ const r=await api("/api/programs"); (r.programs||[]).forEach(p=>deployed.add(p.address)); }catch(e){}
  for(let i=0;i<64;i++){
    const a=programAddressFromSeed(SEED, i);
    if(!deployed.has(a)) return { index:i, addr:a };
  }
  throw new Error("no encontré un índice de programa libre");
}

async function bridgeSignAndSubmit(tx){
  if(!MASTER || !SEED) throw new Error("desbloqueá la wallet primero");
  const cid=await api("/api/chain_id"); const chainId=fromHex(cid.chain_id);
  const me=myAddress();
  const acct=await api("/api/account/"+encodeURIComponent(me));
  const nonce=BigInt(acct.nonce||0);
  const node=await api("/api/node").catch(()=>null);
  // EXPIRACIÓN OBLIGATORIA, FAIL-CLOSED (re-audit #5): una tx de contrato SIEMPRE
  // lleva una ventana de validez corta. Si no podemos obtener la ronda actual del
  // nodo, NO se firma — nunca una tx de contrato sin expiración. La ronda 0
  // (génesis) igual produce una expiración POSITIVA (0 + 120 = 120), así que
  // valid_until_round nunca queda en 0 (que el nodo interpreta como "sin caducidad").
  if(!node || node.online===false || !Number.isFinite(Number(node.next_round))){
    throw new Error("no se pudo obtener la ronda actual del nodo; no se firma una transacción de contrato sin expiración");
  }
  const bfpb=BigInt(node.base_fee_per_byte||180);
  const curRound=BigInt(Math.trunc(Number(node.next_round)));
  const validUntil = curRound + CONTRACT_TX_TTL_ROUNDS; // siempre > 0 (fail-closed)
  if(tx.kind==="deployProgram"){
    // VALIDAR EL TAMAÑO Y CADA BYTE **ANTES** DE CONVERTIR (re-audit #6): un origen
    // autorizado pero comprometido podría mandar un arreglo enorme o con valores
    // fuera de rango; comprobar tipo → tope de 256 KiB → cada elemento 0..255, y
    // recién ahí construir el Uint8Array (que asigna memoria). El chequeo de tamaño
    // va antes del bucle, así que nunca se itera un arreglo sin cota.
    const mb=tx.moduleBytes;
    if(!Array.isArray(mb) && !(mb instanceof Uint8Array)) throw new Error("el módulo WASM debe ser un arreglo de bytes");
    if(!mb.length) throw new Error("el .wasm está vacío");
    if(mb.length>MAX_MODULE_BYTES) throw new Error("el .wasm supera el máximo de "+(MAX_MODULE_BYTES/1024)+" KB");
    for(let i=0;i<mb.length;i++){ const b=mb[i]; if(!Number.isInteger(b)||b<0||b>255) throw new Error("byte inválido en la posición "+i+" del módulo WASM (se esperaba 0..255)"); }
    const bytes=Uint8Array.from(mb);
    const kb=(bytes.length/1024).toFixed(1);
    // FIRMAR primero (sin transmitir), luego SIMULAR la tx firmada, y recién
    // mostrar la aprobación con el resultado real (fee + cambios de saldo). La
    // dirección se deriva del payer + índice (re-audit #2).
    const fp=await freshProgramAddr();
    const paddr=fp.addr;
    const txJson=signDeployProgram(SEED, fp.index, bytes, tx.entryPoint||"run", nonce, chainId, BigInt(node.fee_limit||10000000), validUntil);
    const sim=await bridgeSimulate(txJson);
    // FAIL-CLOSED (re-audit QCH-WALLET, HIGH): sólo una simulación ok===true
    // habilita aprobar. No disponible / 429 / fallida ⇒ bloqueado.
    const blocked = bridgeSimBlocked(sim);
    let note = bridgeSimNote(sim);
    // Un deploy CREA una cuenta de programa nueva (owner/código iniciales), lo que
    // NO es un cambio sensible sobre una cuenta preexistente. Igual detectamos por
    // si tocara una cuenta ya existente (defensa en profundidad) y exigimos la 2ª
    // confirmación si así fuera.
    const alert = bridgeSimAlert(sim, {unverified:false});
    if(alert.note) note = note ? (note+"  "+alert.note) : alert.note;
    const lines=[
      ["Acción","Desplegar un contrato WASM"],
      ["Tamaño", kb+" KB"],
      ["Entry point", tx.entryPoint||"run"],
      ["Dirección del contrato", paddr],
      ["Firmando como", short(me)],
      ["Expira", validUntil>0n ? ("ronda "+validUntil.toString()+" (~"+CONTRACT_TX_TTL_ROUNDS+" rondas)") : "sin expiración"],
    ].concat(bridgeSimLines(sim));
    const ok=await bridgeApprove("Desplegar contrato", lines, {blocked, note, sensitive:alert.sensitive});
    if(!ok) return { rejected:true };
    const r=await fetch("/api/relay-tx",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
    const body=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(body.error||("error "+r.status));
    return { hash: body.hash||"", programAddress: paddr };
  }
  if(tx.kind==="callProgram"){
    const pid=String(tx.programId||"").trim(); if(!pid) throw new Error("falta la dirección del contrato");
    const accountsCsv=String(tx.accounts||"");
    const argsCsv=String(tx.args||"");
    // Límites (re-audit #5): cuentas/args acotados (el signer/nodo también los aplican).
    const nAcc=accountsCsv.split(',').map(s=>s.trim()).filter(Boolean).length;
    const nArg=argsCsv.split(',').map(s=>s.trim()).filter(Boolean).length;
    if(nAcc>MAX_CALL_ACCOUNTS) throw new Error("demasiadas cuentas (máx "+MAX_CALL_ACCOUNTS+")");
    if(nArg>MAX_CALL_ARGS) throw new Error("demasiados argumentos (máx "+MAX_CALL_ARGS+")");
    // FIRMAR primero, SIMULAR, y mostrar los CAMBIOS DE SALDO reales (qué cuenta
    // se debita y hacia dónde) — cierra la firma ciega (re-audit QCH-WALLET).
    const txJson=signCallProgram(SEED, pid, accountsCsv, argsCsv, nonce, chainId, BigInt(node.fee_limit||10000000), validUntil);
    const sim=await bridgeSimulate(txJson);
    // FAIL-CLOSED (re-audit QCH-WALLET, HIGH): sólo una simulación ok===true habilita aprobar.
    const blocked = bridgeSimBlocked(sim);
    let note = bridgeSimNote(sim);
    // PROCEDENCIA COMPLETA DEL CONTRATO (re-audit #6): code_hash + deployer + si el
    // código está VERIFICADO contra una compilación conocida (las plantillas
    // oficiales del SDK). El code_hash lo FUERZA el nodo contra el bytecode
    // ejecutado (v6.26.2). Si el contrato no existe on-chain, avisar.
    let prog=null;
    try{ prog=await api("/api/program/"+encodeURIComponent(pid)); }catch(e){ prog=null; }
    const ch = prog ? String(prog.code_hash||"").toLowerCase() : "";
    const known = KNOWN_CONTRACTS[ch];
    const verified = known ? ("✅ verificado — "+known) : "⚠ NO verificado — código/ABI desconocido; no confíes en la identidad de este contrato";
    // PROCEDENCIA COMPLETA (re-audit #7): mostrar el code_hash y el deployer
    // COMPLETOS (no abreviados), el entry point, y si hay ABI/código verificado.
    // Un code_hash abreviado puede colisionar visualmente — el usuario debe poder
    // comparar el hash entero contra el que publicó el autor.
    const provenance = prog ? [
      ["Code hash (completo)", String(prog.code_hash||"")],
      ["Verificación", verified],
      ["ABI / código fuente", known ? "plantilla oficial del SDK (interfaz conocida)" : "no disponible / no verificado"],
      ["Desplegado por (completo)", String(prog.deployer||"—")],
      ["Entry point", String(prog.entry_point||"—")],
      ["Tamaño del código", ((Number(prog.size_bytes||0))/1024).toFixed(1)+" KB"],
    ] : [["Contrato","⚠ NO existe un contrato desplegado en esta dirección"]];
    if(!prog && !note) note="No hay un contrato desplegado en esa dirección — la llamada fallaría. Verificá la dirección.";
    else if(prog && !known && !blocked && !note) note="El código de este contrato NO coincide con ninguna compilación conocida y NO tiene ABI verificada. Las cuentas y los argumentos i64 de abajo NO tienen una interpretación humana confiable: no podés saber con certeza qué hará este contrato con ellos. Confirmá que confiás en quién lo desplegó antes de aprobar.";
    // CAMBIOS SENSIBLES (re-audit QCH-SIMULATE): si la simulación muestra un cambio
    // de dueño/datos/código sobre una cuenta preexistente (o elimina una), se pinta
    // en rojo, se explica (para un contrato SIN ABI, qué puede representar un cambio
    // de data_hash), y se exige la 2ª confirmación. Se combina con el aviso previo.
    const alert = bridgeSimAlert(sim, {unverified: !known});
    if(alert.note) note = note ? (note+"  "+alert.note) : alert.note;
    const lines=[
      ["Acción","Llamar un contrato"],
      ["Contrato", pid],
    ].concat(provenance).concat([
      ["Cuentas", accountsCsv||"—"],
      ["Args (i64)", argsCsv||"—"],
      ["Firmando como", short(me)],
      ["Expira", validUntil>0n ? ("ronda "+validUntil.toString()+" (~"+CONTRACT_TX_TTL_ROUNDS+" rondas)") : "sin expiración"],
    ]).concat(bridgeSimLines(sim));
    const ok=await bridgeApprove("Interactuar con contrato", lines, {blocked, note, sensitive:alert.sensitive});
    if(!ok) return { rejected:true };
    const r=await fetch("/api/relay-tx",{method:"POST",headers:{"content-type":"application/json"},body:txJson});
    const body=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(body.error||("error "+r.status));
    return { hash: body.hash||"" };
  }
  throw new Error("tipo de operación desconocido");
}

let BRIDGE_SESSION=null;   // token de sesión aleatorio, emitido al conectar (re-audit #5)
let BRIDGE_BUSY=false;     // sólo una solicitud de firma activa a la vez (re-audit #5)
function randToken(){ const a=new Uint8Array(16); crypto.getRandomValues(a); return Array.from(a).map(b=>b.toString(16).padStart(2,"0")).join(""); }
async function initConnectBridge(){
  try{ const cfg=await api("/api/config"); CONNECT_ORIGIN=cfg.connect_origin||null; }catch(e){ CONNECT_ORIGIN=null; }
  if(!CONNECT_ORIGIN) return;   // bridge OFF salvo que el server lo configure
  // La ÚNICA ventana autorizada a hablarnos es la que nos abrió (el popup lo abre
  // QScan). Fijarla una vez y exigir `ev.source === opener` en cada mensaje cierra
  // que otra ventana/iframe del mismo origen inyecte pedidos (re-audit #5).
  const OPENER = window.opener;
  window.addEventListener("message", async (ev)=>{
    // INVARIANTE 3: allowlist de origen estricto, en CADA mensaje.
    if(ev.origin !== CONNECT_ORIGIN) return;
    // La ventana emisora DEBE ser exactamente la que nos abrió (validación de source).
    if(!OPENER || ev.source !== OPENER) return;
    const msg=ev.data||{};
    if(!msg || msg.v!==1 || !msg.type || !msg.id) return;
    const reply=(obj)=>{ try{ OPENER.postMessage(Object.assign({v:1,id:msg.id},obj), CONNECT_ORIGIN); }catch(e){} };
    try{
      if(msg.type==="connect"){
        if(!MASTER){ reply({type:"error", msg:"la wallet está bloqueada — desbloqueala y reintentá"}); return; }
        const ok=await bridgeApprove("Conectar", [["Sitio", CONNECT_ORIGIN],["Permiso","Ver tu dirección pública (solo lectura)"]]);
        if(!ok){ reply({type:"rejected"}); return; }
        // Nueva sesión: emite un token que las solicitudes siguientes DEBEN traer.
        BRIDGE_SESSION=randToken();
        reply({type:"connected", address: myAddress(), session: BRIDGE_SESSION});
      } else if(msg.type==="signAndSubmit"){
        // Exige una sesión ACTIVA con el token correcto (re-audit #5): sin conectar
        // primero, o con un token que no coincide, no se firma nada.
        if(!BRIDGE_SESSION || msg.session!==BRIDGE_SESSION){ reply({type:"error", msg:"sesión inválida — conectá primero"}); return; }
        // Una sola solicitud de firma a la vez (evita aprobaciones superpuestas).
        if(BRIDGE_BUSY){ reply({type:"error", msg:"ya hay una solicitud de firma en curso"}); return; }
        BRIDGE_BUSY=true;
        try{
          const res=await bridgeSignAndSubmit(msg.tx||{});
          if(res.rejected) reply({type:"rejected"});
          else reply({type:"submitted", hash:res.hash, programAddress:res.programAddress});
        } finally { BRIDGE_BUSY=false; }
      } else if(msg.type==="disconnect"){
        BRIDGE_SESSION=null;   // cierra la sesión: futuros signAndSubmit se rechazan
        reply({type:"disconnected"});
      }
    }catch(e){ reply({type:"error", msg:String(e.message||e)}); }
  });
  // avisar a quien nos abrió que estamos listos
  try{ OPENER?.postMessage({v:1,type:"ready"}, CONNECT_ORIGIN); }catch(e){}
}

// ==================== arranque ====================
// Versión + huellas del código servido (#214/#215). Se muestran en Ajustes para
// que el usuario las compare contra el release FIRMADO publicado fuera de banda
// — la verificación real de que el servidor no sirve una versión alterada.
let VER_INFO=null;
async function loadVersion(){
  const el=$("ver-build"); if(!el) return;
  try{
    const v=await api("/api/version"); VER_INFO=v;
    el.innerHTML =
      `<div><b>versión</b> ${esc(v.version||"?")}</div>`+
      `<div><b>app.js</b> sha256:${esc((v.app_js_sha256||"").slice(0,32))}…</div>`+
      `<div><b>SRI</b> ${esc(v.app_js_sri||"")}</div>`+
      `<div><b>wasm glue</b> sha256:${esc((v.wasm_glue_sha256||"").slice(0,32))}…</div>`+
      `<div><b>wasm bin</b> sha256:${esc((v.wasm_bg_sha256||"").slice(0,32))}…</div>`;
  }catch(e){ el.textContent="no se pudo leer /api/version"; }
}
document.addEventListener("click",e=>{
  if(e.target && e.target.id==="ver-copy" && VER_INFO){
    const t=`qchain-wallet ${VER_INFO.version}\napp.js sha256 ${VER_INFO.app_js_sha256}\napp.js SRI ${VER_INFO.app_js_sri}\nwasm glue sha256 ${VER_INFO.wasm_glue_sha256}\nwasm bin sha256 ${VER_INFO.wasm_bg_sha256}`;
    copy(t); toast("huellas copiadas");
  }
});

(async function(){
  applyTheme(localStorage.getItem("qchain_theme")||"dark");
  const bootDone = runBoot();                 // arranca la animación ya mismo
  try{ quantumWaves($("qwave"),{bright:false,lines:5,amp:16,particles:22,alpha:.42}); }catch(e){}  // fondo ambiente persistente
  showView("loading");
  if(!(window.isSecureContext && window.crypto && crypto.subtle)){
    // `location.href` is attacker-influenceable (path/query), so escape it
    // before folding into innerHTML - both the attribute and the text - or a
    // crafted `http://host/">…` URL would be reflected DOM-XSS. Scheme is
    // always http:->https: here, so no `javascript:` risk; esc() handles the
    // quotes/brackets that would break out of the attribute or inject markup.
    const httpsUrl=esc(location.href.replace(/^http:/, 'https:'));
    $("loading-text").innerHTML = '⚠️ Esta wallet cifra tu clave <b>en tu navegador</b>, lo que requiere <b>HTTPS</b> '+
      '(o acceso local). Estás entrando por HTTP plano.<br><br>Probá <a href="'+httpsUrl+'" style="color:#a78bfa">'+httpsUrl+'</a>.';
    return;
  }
  try{ await init('/wasm/qchain_wasm_bg.wasm'); }
  catch(e){ $("loading-text").textContent='no se pudo cargar el módulo de firma: '+e.message; return; }

  await loadNode();
  loadVersion();                              // versión + huellas del build (verificación de integridad, #214/#215)
  await bootDone;                             // no revelar hasta que la animación termine
  refreshBioUnlockBtn();                      // botón de biométrico en la pantalla de bloqueo si está activado
  showView(localStorage.getItem(LS_KEY) ? "unlock" : "welcome");
  try{ await initConnectBridge(); }catch(e){ console.warn("connect bridge no inicializado:", e); }  // puente wallet-connect (postMessage con allowlist de origen)

  // refrescos en vivo (sin parpadeo: la actividad solo se redibuja si cambió)
  nodeTimer=setInterval(loadNode, 6000);
  balTimer=setInterval(()=>{ if($("v-home").classList.contains("active")) renderHome(); }, 6000);
})();
