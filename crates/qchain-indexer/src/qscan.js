/* QScan — single-page block explorer for a Qchain network.
   Talks only to this indexer's /api/*; renders an Etherscan-style UI. */
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const app = $("#app");
  let STATS = {}; // last /api/stats, used for age fallback

  // ---------- helpers ----------
  const esc = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const UNITS = 1000000000n; // 1 QCH = 1e9 units
  function toBig(v) {
    try { if (typeof v === "string") return BigInt(v); if (typeof v === "number") return BigInt(Math.trunc(v)); if (typeof v === "bigint") return v; } catch (e) {}
    return 0n;
  }
  function fmtQch(v, dp) {
    const n = toBig(v); const dec = dp === undefined ? 4 : dp;
    const whole = n / UNITS; let frac = (n % UNITS).toString().padStart(9, "0");
    frac = frac.slice(0, dec).replace(/0+$/, "");
    const ws = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return frac ? `${ws}.${frac}` : ws;
  }
  const fmtNum = (v) => toBig(v).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const short = (s, a, b) => { s = String(s || ""); a = a || 8; b = b || 6; return s.length > a + b + 2 ? s.slice(0, a) + "…" + s.slice(-b) : s; };

  function age(ts, round) {
    const now = Math.floor(Date.now() / 1000);
    if (ts && ts > 0) return rel(now - ts);
    // fallback: estimate from round distance × round interval
    const h = Number(STATS.height || 0), iv = Number(STATS.round_interval_ms || 500);
    if (h && round != null) { const secs = Math.max(0, (h - Number(round)) * iv / 1000); return "~" + rel(secs); }
    return "ronda " + fmtNum(round);
  }
  function rel(secs) {
    secs = Math.max(0, Math.floor(secs));
    if (secs < 60) return secs + " s";
    const m = Math.floor(secs / 60); if (m < 60) return m + " min";
    const h = Math.floor(m / 60); if (h < 24) return h + " h";
    const d = Math.floor(h / 24); return d + " d";
  }
  function copyBtn(v) { return `<span class="copy" title="Copiar" onclick="QScan.copy('${esc(v)}',event)">⧉</span>`; }
  const addrLink = (a) => a ? `<a class="mono" href="#/address/${esc(a)}">${esc(short(a, 10, 8))}</a>` : "<span class=dim>—</span>";
  const txLink = (h) => `<a class="mono hashlink" href="#/tx/${esc(h)}">${esc(short(h, 12, 8))}</a>`;
  const blockLink = (r) => `<a href="#/block/${esc(r)}">${fmtNum(r)}</a>`;

  const KIND = {
    transfer: ["tf", "Transferencia"], delegate: ["dg", "Delegación"], undelegate: ["ud", "Retiro"],
    unbonding_started: ["ub", "Unbonding"], claim_reward: ["cl", "Recompensa"],
  };
  function kindPill(k) { const m = KIND[k] || ["tf", k]; return `<span class="pill ${m[0]}">${esc(m[1])}</span>`; }

  async function api(path) {
    const r = await fetch("/api" + path);
    if (!r.ok) throw new Error((await r.text().catch(() => "")) || r.status);
    return r.json();
  }
  const loading = () => `<div class="empty"><span class="spin"></span></div>`;
  function setNav(hash) { document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === hash)); }

  // ---------- pages ----------
  function statCells(s) {
    return [
      ["Ronda (altura)", fmtNum(s.height), `${fmtNum(s.executed_transactions)} tx ejecutadas`],
      ["En circulación", fmtQch(s.circulating || 0, 0) + " QCH", `${fmtQch(s.held_in_wallets || 0, 0)} en wallets`],
      ["Quemado", fmtQch(s.total_burned || 0, 0) + " QCH", `${fmtQch(s.total_emitted || 0, 0)} emitido`],
      ["Fee base / byte", fmtNum(s.base_fee_per_byte), `${fmtNum(s.validators)} validadores · ${fmtNum(s.mempool_transactions)} en cola`],
    ];
  }
  function blockRowHome(x) {
    return `<div class="row"><span class="badge">◆</span>
      <div style="flex:1;min-width:0"><div>${blockLink(x.round)}</div><div class="dim tag">${age(x.ts, x.round)}</div></div>
      <div class="right"><div>${fmtNum(x.tx_count)} tx</div><div class="dim tag">${fmtQch(x.fees)} QCH fee</div></div></div>`;
  }
  function txRowHome(x) {
    return `<div class="row"><span class="badge">↔</span>
      <div style="flex:1;min-width:0"><div>${txLink(x.hash)} ${kindPill(x.kind)}</div><div class="dim tag">${addrLink(x.from)} → ${addrLink(x.to)}</div></div>
      <div class="right"><div>${x.kind === "transfer" || x.kind === "delegate" ? fmtQch(x.amount) + " QCH" : ""}</div><div class="dim tag">${age(x.ts, x.round)}</div></div></div>`;
  }
  // Build the home shell ONCE. Data is filled/refreshed in place by loadHomeData()
  // so the periodic refresh never blanks the page to a spinner (no flicker).
  function renderHomeShell() {
    app.innerHTML = `
      <div class="hero">
        <h1>Explorador de la red Qchain</h1>
        <div class="hsub">Blockchain L1 post-cuántica · datos en vivo desde un nodo por RPC</div>
      </div>
      <div class="statpanel" id="statpanel">
        ${[0, 1, 2, 3].map((i) => `<div class="cell"><div class="k" id="k${i}"></div><div class="v" id="v${i}">—</div><div class="s" id="s${i}"></div></div>`).join("")}
      </div>
      <div id="homebanner"></div>
      <div class="grid cols">
        <div class="card"><div class="panel-h"><h3>Últimos bloques (rondas)</h3><a href="#/blocks">Ver todos →</a></div><div id="lb">${loading()}</div></div>
        <div class="card"><div class="panel-h"><h3>Últimas transacciones</h3><a href="#/txs">Ver todas →</a></div><div id="lt">${loading()}</div></div>
      </div>
      <div class="dim center" id="homefoot" style="margin-bottom:24px"></div>`;
  }
  // Fetch and patch only the changed nodes — no full re-render, no spinner blackout.
  async function loadHomeData() {
    let s = {};
    try { s = await api("/stats"); STATS = s; } catch (e) {}
    if (!$("#statpanel")) return; // navigated away mid-fetch
    statCells(s).forEach((c, i) => {
      const k = $("#k" + i), v = $("#v" + i), sub = $("#s" + i);
      if (k) k.textContent = c[0];
      if (v) v.textContent = c[1];
      if (sub) sub.innerHTML = c[2];
    });
    const hb = $("#homebanner");
    if (hb) hb.innerHTML = s.height == null ? `<div class="banner bad">El indexador aún no pudo contactar al nodo (RPC). Verificá <span class="mono">--node</span>.</div>` : "";
    const hf = $("#homefoot");
    if (hf) hf.innerHTML = `<span class="live"><i></i>en vivo</span> · ${fmtNum(s.indexed_txs)} tx / ${fmtNum(s.indexed_blocks)} bloques indexados · ${esc(s.version || "")} · chain ${esc(short(s.chain_id || "—", 8, 6))}`;
    // panels: replace only when the rendered HTML actually changed (avoids reflow/flicker on unchanged data)
    const put = (el, html) => { if (el && el.innerHTML !== html) el.innerHTML = html; };
    try {
      const b = (await api("/blocks?size=8")).blocks || [];
      put($("#lb"), b.length ? b.map(blockRowHome).join("") : `<div class="empty">Sin bloques todavía</div>`);
    } catch (e) { const el = $("#lb"); if (el && el.querySelector(".spin")) el.innerHTML = `<div class="empty">—</div>`; }
    try {
      const t = (await api("/txs?size=8")).txs || [];
      put($("#lt"), t.length ? t.map(txRowHome).join("") : `<div class="empty">Sin transacciones todavía</div>`);
    } catch (e) { const el = $("#lt"); if (el && el.querySelector(".spin")) el.innerHTML = `<div class="empty">—</div>`; }
  }
  async function home() {
    setNav("#/");
    if (!$("#statpanel")) renderHomeShell();
    await loadHomeData();
  }

  function pager(page, hasNext, base) {
    return `<div class="pager">
      <button ${page <= 0 ? "disabled" : ""} onclick="QScan.go('${base}0')">« Primera</button>
      <button ${page <= 0 ? "disabled" : ""} onclick="QScan.go('${base}${page - 1}')">‹</button>
      <span class="dim">Página ${page + 1}</span>
      <button ${!hasNext ? "disabled" : ""} onclick="QScan.go('${base}${page + 1}')">›</button></div>`;
  }

  async function txsPage(page, kind) {
    setNav("#/txs"); page = page || 0; kind = kind || "all";
    app.innerHTML = `<h2 class="title">Transacciones</h2>${loading()}`;
    let d = { txs: [] };
    try { d = await api(`/txs?page=${page}&size=25&kind=${encodeURIComponent(kind)}`); } catch (e) {}
    const filters = ["all", "transfer", "delegate", "undelegate", "claim_reward"];
    const chips = filters.map((f) => `<a href="#/txs/0/${f}" class="pill ${kind === f ? "tf" : ""}" style="padding:6px 12px;margin-right:6px">${f === "all" ? "Todas" : (KIND[f] ? KIND[f][1] : f)}</a>`).join("");
    app.innerHTML = `<h2 class="title">Transacciones</h2>
      <div style="margin-bottom:12px">${chips}</div>
      <div class="card"><table><thead><tr><th>Hash</th><th>Tipo</th><th>Ronda</th><th>Edad</th><th>Desde</th><th>Hacia</th><th class="right">Monto</th><th class="right">Fee</th></tr></thead>
      <tbody>${d.txs.length ? d.txs.map(txRow).join("") : `<tr><td colspan=8 class=empty>Sin resultados</td></tr>`}</tbody></table>
      ${pager(page, d.txs.length >= 25, `#/txs/`).replace(`#/txs/${page + 1}`, `#/txs/${page + 1}/${kind}`).replace(`#/txs/${page - 1}`, `#/txs/${page - 1}/${kind}`).replace(`#/txs/0'`, `#/txs/0/${kind}'`)}</div>`;
  }
  function txRow(x) {
    return `<tr><td>${txLink(x.hash)}${copyBtn(x.hash)}</td><td>${kindPill(x.kind)}</td><td>${blockLink(x.round)}</td>
      <td class="dim nowrap">${age(x.ts, x.round)}</td><td>${addrLink(x.from)}</td><td>${addrLink(x.to)}</td>
      <td class="right">${x.kind === "transfer" || x.kind === "delegate" ? fmtQch(x.amount) + " QCH" : "<span class=dim>—</span>"}</td>
      <td class="right dim">${x.fee ? fmtQch(x.fee) : "—"}</td></tr>`;
  }

  async function blocksPage(page) {
    setNav("#/blocks"); page = page || 0;
    app.innerHTML = `<h2 class="title">Bloques (rondas de consenso)</h2>${loading()}`;
    let d = { blocks: [] };
    try { d = await api(`/blocks?page=${page}&size=25`); } catch (e) {}
    app.innerHTML = `<h2 class="title">Bloques (rondas de consenso)</h2>
      <div class="card"><table><thead><tr><th>Ronda</th><th>Edad</th><th class="right">Txns</th><th class="right">Fees</th><th class="right">Quemado</th><th>Llenado</th></tr></thead>
      <tbody>${d.blocks.length ? d.blocks.map((b) => `<tr>
        <td>${blockLink(b.round)}</td><td class="dim nowrap">${age(b.ts, b.round)}</td>
        <td class="right">${fmtNum(b.tx_count)}</td><td class="right">${fmtQch(b.fees)}</td>
        <td class="right" style="color:var(--burn)">${fmtQch(b.burned)}</td>
        <td><div class="bar"><i style="width:${Math.min(100, b.fill_pct)}%"></i></div><span class="tag dim">${b.fill_pct}%</span></td></tr>`).join("") : `<tr><td colspan=6 class=empty>Sin bloques</td></tr>`}</tbody></table>
      ${pager(page, d.blocks.length >= 25, "#/blocks/")}</div>`;
  }

  async function blockPage(round) {
    setNav("#/blocks");
    app.innerHTML = `<h2 class="title">Bloque · Ronda ${fmtNum(round)}</h2>${loading()}`;
    let d;
    try { d = await api(`/block/${round}`); } catch (e) { app.innerHTML = notFound("Ese bloque (ronda) no está indexado."); return; }
    const b = d.block || {};
    app.innerHTML = `<h2 class="title">Bloque · Ronda ${fmtNum(round)}</h2>
      <div class="card"><div class="kv">
        <div class="kk">Ronda</div><div class="mono">${fmtNum(round)}</div>
        <div class="kk">Edad</div><div>${age(b.ts, round)}</div>
        <div class="kk">Transacciones</div><div>${fmtNum(b.tx_count || d.txs.length)}</div>
        <div class="kk">Bytes comprometidos</div><div>${fmtNum(b.bytes)} <span class="dim">/ ${fmtNum(b.cap_bytes)} (cap) · objetivo ${fmtNum(b.target_bytes)}</span></div>
        <div class="kk">Llenado</div><div><div class="bar" style="max-width:220px"><i style="width:${Math.min(100, b.fill_pct || 0)}%"></i></div> <span class="dim">${b.fill_pct || 0}%</span></div>
        <div class="kk">Fees (transferencias)</div><div>${fmtQch(b.fees)} QCH <span class="dim">· ${fmtQch(b.burned)} quemado</span></div>
      </div></div>
      <h2 class="title" style="font-size:16px">Transacciones del bloque</h2>
      <div class="card"><table><thead><tr><th>Hash</th><th>Tipo</th><th>Desde</th><th>Hacia</th><th class="right">Monto</th></tr></thead>
      <tbody>${d.txs.length ? d.txs.map((x) => `<tr><td>${txLink(x.hash)}</td><td>${kindPill(x.kind)}</td><td>${addrLink(x.from)}</td><td>${addrLink(x.to)}</td><td class="right">${x.kind === "transfer" || x.kind === "delegate" ? fmtQch(x.amount) + " QCH" : "—"}</td></tr>`).join("") : `<tr><td colspan=5 class=empty>Sin transferencias de una instrucción en esta ronda (staking/contratos no generan recibo detallado)</td></tr>`}</tbody></table></div>`;
  }

  async function txPage(hash) {
    setNav("#/txs");
    app.innerHTML = `<h2 class="title">Transacción</h2>${loading()}`;
    let d;
    try { d = await api(`/tx/${hash}`); } catch (e) { app.innerHTML = notFound("No se encontró esa transacción en el índice ni en la ventana del nodo."); return; }
    const t = d.tx, r = d.receipt;
    const base = t || {};
    let rows = `
      <div class="kv">
        <div class="kk">Hash</div><div class="mono" style="word-break:break-all">${esc(base.hash || hash)}${copyBtn(base.hash || hash)}</div>
        <div class="kk">Tipo</div><div>${kindPill(base.kind || "transfer")}</div>
        <div class="kk">Estado</div><div><span class="pill dg">✓ Confirmada</span></div>
        <div class="kk">Ronda</div><div>${base.round != null ? blockLink(base.round) : "—"}</div>
        <div class="kk">Edad</div><div>${age(base.ts, base.round)}</div>
        <div class="kk">Desde</div><div>${addrLink(base.from)}${base.from ? copyBtn(base.from) : ""}</div>
        <div class="kk">${base.kind && base.kind !== "transfer" ? "Validador" : "Hacia"}</div><div>${addrLink(base.to)}${base.to ? copyBtn(base.to) : ""}</div>
        ${base.stake_account ? `<div class="kk">Cuenta de stake</div><div>${addrLink(base.stake_account)}</div>` : ""}
        <div class="kk">Monto</div><div><b>${fmtQch(base.amount)} QCH</b></div>
        <div class="kk">Fee</div><div>${fmtQch(base.fee)} QCH</div>`;
    if (r) {
      const fb = r.from_before, fa = r.from_after, tb = r.to_before, ta = r.to_after;
      const bal = (v) => v == null ? "" : fmtQch(v.balance != null ? v.balance : v) + " QCH";
      rows += `
        <div class="kk">Root antes</div><div class="mono dim" style="word-break:break-all">${esc(toHex(r.root_before))}</div>
        <div class="kk">Root después</div><div class="mono dim" style="word-break:break-all">${esc(toHex(r.root_after))}</div>`;
      if (fb || fa) rows += `<div class="kk">Balance emisor</div><div>${bal(fb)} → <b>${bal(fa)}</b></div>`;
      if (tb || ta) rows += `<div class="kk">Balance receptor</div><div>${bal(tb)} → <b>${bal(ta)}</b></div>`;
    }
    rows += `</div>`;
    app.innerHTML = `<h2 class="title">Transacción</h2><div class="card">${rows}</div>
      ${r ? `<div class="dim center" style="margin:14px 0">Incluye pruebas Merkle verificables (light client). Consultá <span class="mono">GET /transfers/${esc(base.hash || hash)}</span> en el nodo para el recibo STARK completo.</div>` : ""}`;
  }

  async function addressPage(addr, page) {
    setNav(""); page = page || 0;
    app.innerHTML = `<h2 class="title">Dirección</h2>${loading()}`;
    let d;
    try { d = await api(`/address/${addr}?page=${page}&size=25`); } catch (e) { app.innerHTML = notFound("Dirección inválida."); return; }
    const acc = d.account, stake = d.stake;
    let head = `<div class="kv">
        <div class="kk">Dirección</div><div class="mono" style="word-break:break-all">${esc(addr)}${copyBtn(addr)}</div>`;
    if (acc) {
      head += `<div class="kk">Balance</div><div><b style="font-size:18px">${fmtQch(acc.balance)} QCH</b></div>
        <div class="kk">Nonce</div><div>${fmtNum(acc.nonce)}</div>
        <div class="kk">Tipo</div><div>${acc.code_hash && acc.code_hash.some ? "Contrato" : "Cuenta"}${acc.owner ? ` <span class="dim">· owner ${esc(short(String(acc.owner), 8, 6))}</span>` : ""}</div>`;
    } else {
      head += `<div class="kk">Balance</div><div class="dim">Cuenta no encontrada on-chain (0 QCH) — puede tener actividad indexada abajo</div>`;
    }
    if (stake && stake.amount != null) {
      head += `<div class="kk">Posición de staking</div><div>${fmtQch(stake.amount)} QCH <span class="dim">· recompensa pendiente ${fmtQch(stake.pending_reward)} QCH</span></div>`;
    }
    head += `<div class="kk">Transacciones</div><div>${fmtNum(d.tx_total)}</div></div>`;
    const rows = d.txs.length ? d.txs.map(txRow).join("") : `<tr><td colspan=8 class=empty>Sin transacciones indexadas para esta dirección</td></tr>`;
    app.innerHTML = `<h2 class="title">Dirección</h2>
      <div class="card">${head}</div>
      <h2 class="title" style="font-size:16px">Historial de transacciones</h2>
      <div class="card"><table><thead><tr><th>Hash</th><th>Tipo</th><th>Ronda</th><th>Edad</th><th>Desde</th><th>Hacia</th><th class="right">Monto</th><th class="right">Fee</th></tr></thead>
      <tbody>${rows}</tbody></table>${pager(page, d.txs.length >= 25, `#/address/${esc(addr)}/`)}</div>`;
  }

  async function validatorsPage() {
    setNav("#/validators");
    app.innerHTML = `<h2 class="title">Validadores</h2>${loading()}`;
    let d = {};
    try { d = await api("/validators"); } catch (e) {}
    const vs = d.validators || [];
    const totalStake = vs.reduce((a, v) => a + Number(v.stake || 0), 0) || 1;
    const econ = d.economics || {};
    const body = vs.length ? vs.map((v, i) => {
      const share = (Number(v.stake || 0) / totalStake * 100).toFixed(1);
      return `<tr><td>${i + 1}</td><td>${v.name ? `<b>${esc(v.name)}</b>` : "<span class=dim>(sin nombre)</span>"}</td>
        <td>${addrLink(v.address)}</td><td class="right">${fmtQch(v.stake, 0)} QCH</td>
        <td><div class="bar" style="max-width:120px"><i style="width:${share}%"></i></div><span class="tag dim">${share}%</span></td></tr>`;
    }).join("") : `<tr><td colspan=5 class=empty>Sin validadores</td></tr>`;
    app.innerHTML = `<h2 class="title">Validadores</h2>
      <div class="grid stats" style="grid-template-columns:repeat(3,1fr)">
        <div class="card pad stat"><div class="k">Validadores activos</div><div class="v">${vs.length}</div></div>
        <div class="card pad stat"><div class="k">Comisión (global)</div><div class="v">${((Number(econ.staking_commission_bps || 0)) / 100).toFixed(1)}%</div></div>
        <div class="card pad stat"><div class="k">Emisión anual (APR)</div><div class="v">${((Number(econ.emission_apr_bps || 0)) / 100).toFixed(1)}%</div></div>
      </div>
      <div class="card"><table><thead><tr><th>#</th><th>Nombre</th><th>Dirección</th><th class="right">Stake BFT</th><th>Peso</th></tr></thead><tbody>${body}</tbody></table></div>
      <div class="dim center" style="margin:14px 0">La comisión es un parámetro global de la red (todos los validadores cobran igual); se elige por confianza/uptime. El registro on-chain permissionless de validadores está disponible en el nodo (<span class="mono">/validator_registry</span>).</div>`;
  }

  async function holdersPage() {
    setNav("#/holders");
    app.innerHTML = `<h2 class="title">Holders — distribución de QCH</h2>${loading()}`;
    let h = {};
    try { h = await api("/holders"); } catch (e) {}
    const top = h.top || [];
    const walletsPct = h.total_balance && Number(h.total_balance) > 0 ? (Number(h.held_in_wallets) / Number(h.total_balance) * 100) : 0;
    app.innerHTML = `<h2 class="title">Holders — distribución de QCH</h2>
      <div class="grid stats">
        <div class="card pad stat"><div class="k">En circulación</div><div class="v">${fmtQch(h.total_balance || 0, 0)}</div><div class="s">QCH en estado</div></div>
        <div class="card pad stat"><div class="k">Cuentas</div><div class="v">${fmtNum(h.total_accounts)}</div><div class="s">${fmtNum(h.wallet_accounts)} wallets de usuario</div></div>
        <div class="card pad stat"><div class="k">En wallets</div><div class="v">${fmtQch(h.held_in_wallets || 0, 0)}</div><div class="s">líquido</div></div>
        <div class="card pad stat"><div class="k">En staking/programas</div><div class="v">${fmtQch(h.held_in_programs || 0, 0)}</div><div class="s">bloqueado</div></div>
      </div>
      <div class="card pad" style="margin-bottom:16px"><div class="dim" style="margin-bottom:6px">Reparto wallets vs staking/programas</div>
        <div class="bar" style="height:14px"><i style="width:${walletsPct.toFixed(1)}%"></i></div>
        <div class="tag dim" style="margin-top:6px">${walletsPct.toFixed(1)}% en wallets · ${(100 - walletsPct).toFixed(1)}% en staking/programas</div></div>
      <div class="card"><table><thead><tr><th>#</th><th>Dirección</th><th class="right">Balance</th><th class="right">% del circulante</th></tr></thead>
      <tbody>${top.length ? top.map((t, i) => `<tr><td>${i + 1}</td><td>${addrLink(t.address)}</td><td class="right">${fmtQch(t.balance, 4)} QCH</td><td class="right">${Number(t.pct || 0).toFixed(4)}%</td></tr>`).join("") : `<tr><td colspan=4 class=empty>Sin datos de holders todavía</td></tr>`}</tbody></table></div>
      <div class="dim center" style="margin:14px 0">"Circulante" = QCH que vive en cuentas (excluye lo quemado). Foto point-in-time del nodo seguido.</div>`;
  }

  function notFound(msg) { return `<div class="card pad empty">${esc(msg)}<div style="margin-top:12px"><a href="#/">← Volver al inicio</a></div></div>`; }
  function toHex(v) {
    if (v == null) return "";
    if (typeof v === "string") return v;
    if (Array.isArray(v)) return v.map((b) => Number(b).toString(16).padStart(2, "0")).join("");
    return String(v);
  }

  // ---------- search ----------
  async function doSearch(ev) {
    ev.preventDefault();
    const q = $("#q").value.trim();
    if (!q) return false;
    try {
      const r = await api("/search?q=" + encodeURIComponent(q));
      if (r.type === "tx") location.hash = "#/tx/" + r.target;
      else if (r.type === "block") location.hash = "#/block/" + r.target;
      else if (r.type === "address") location.hash = "#/address/" + r.target;
      else app.innerHTML = notFound("No se encontró nada para: " + esc(q));
    } catch (e) { app.innerHTML = notFound("Búsqueda fallida."); }
    $("#q").value = "";
    return false;
  }

  // ---------- router ----------
  function route() {
    const h = location.hash || "#/";
    const p = h.replace(/^#\//, "").split("/");
    const seg = p[0] || "";
    if (seg === "" ) return home();
    if (seg === "txs") return txsPage(parseInt(p[1] || "0", 10) || 0, p[2] || "all");
    if (seg === "blocks") return blocksPage(parseInt(p[1] || "0", 10) || 0);
    if (seg === "block") return blockPage(p[1]);
    if (seg === "tx") return txPage(p[1]);
    if (seg === "address") return addressPage(p[1], parseInt(p[2] || "0", 10) || 0);
    if (seg === "validators") return validatorsPage();
    if (seg === "holders") return holdersPage();
    return home();
  }

  window.QScan = {
    doSearch,
    go: (hash) => { location.hash = hash; },
    copy: (v, ev) => { if (ev) ev.stopPropagation(); navigator.clipboard && navigator.clipboard.writeText(v); },
  };
  window.addEventListener("hashchange", route);
  route();
  // Light auto-refresh of the home page — patches data in place (no page blackout).
  setInterval(() => { if ((location.hash || "#/") === "#/" && $("#statpanel")) loadHomeData(); }, 10000);
})();
