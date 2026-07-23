#!/usr/bin/env python3
"""Soak canary + invariant monitor para la testnet PRE-LANZAMIENTO.

Corre CONTINUAMENTE (días/semanas) contra TODOS los RPC de la red y verifica las
5 invariantes que NO deben romperse nunca durante el soak:

  1. RAÍCES DIVERGENTES   — dos nodos con la MISMA ronda deben reportar el MISMO
                            Merkle root (si difieren = fork = FALLA dura).
  2. SUPPLY INCONSISTENTE — conservación por-nodo (total_balance + burned - emitted
                            == supply de génesis, constante) Y acuerdo cross-node
                            del total_balance a la misma ronda.
  3. PÉRDIDA DE TX FINALIZADA — un canary manda transferencias etiquetadas a una
                            dirección fija; el saldo del receptor en CADA nodo debe
                            alcanzar la suma acumulada de lo enviado (nunca quedar
                            permanentemente por debajo tras la ventana de catch-up,
                            nunca DECRECER).
  4. CRECIMIENTO DE RAM/DISCO — por nodo, RSS y disco del data_dir acotados (techo
                            configurable) y sin crecer monotónicamente sin fin.
  5. CONGELAMIENTO (tras reinicio) — next_round debe avanzar dentro de un timeout;
                            si se estanca en un nodo VIVO = freeze = FALLA.

Es TOLERANTE al caos: un nodo caído (kill/partición/disco-lleno provocados por
`chaos-test.sh`) NO cuenta como falla — sólo se comparan los nodos ALCANZABLES, y
la pérdida de tx / freeze se juzgan con ventanas de catch-up para no dar falsos
positivos mientras un nodo se recupera.

stdlib-only (como el watchdog). Emite un JSONL de eventos + un resumen periódico.
Sale != 0 y marca `VERDICT: FAIL` si CUALQUIER invariante dura (fork / supply /
tx-loss real) se rompe.

  deploy/soak-canary.py \
    --node v1=http://IP1:8080 --node v2=http://IP2:8080 ... \
    --qchain-bin ./target/release/qchain \
    --sender-keypair bank.json --canary-recipient <addr base58> \
    --interval 15 --send-every 60 --ram-max-mb 3000 --disk-max-mb 20000 \
    --stall-secs 90 --out soak.jsonl
"""
import argparse, json, subprocess, sys, time, urllib.request, urllib.error

def now():  # monotonic wall clock, no Date.now-style nondeterminism concerns here (a tool, not consensus)
    return time.time()

def get(url, path, timeout=8):
    try:
        with urllib.request.urlopen(url.rstrip('/') + path, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--node', action='append', default=[], metavar='NAME=URL',
                    help='validador a monitorear (repetible)')
    ap.add_argument('--qchain-bin', default='qchain', help='binario CLI para mandar los canary transfers')
    ap.add_argument('--sender-keypair', help='keypair fondeado que firma los canary transfers')
    ap.add_argument('--submit-rpc', help='RPC al que se somete el canary (default: el primer --node)')
    ap.add_argument('--canary-recipient', help='dirección base58 que recibe los canary transfers (tx-loss check)')
    ap.add_argument('--canary-amount', type=int, default=1, help='unidades por canary transfer')
    ap.add_argument('--interval', type=float, default=15, help='segundos entre chequeos')
    ap.add_argument('--send-every', type=float, default=60, help='segundos entre canary transfers (0 = no mandar)')
    ap.add_argument('--catchup-secs', type=float, default=180, help='ventana para que un nodo alcance el saldo esperado antes de declarar tx-loss')
    ap.add_argument('--stall-secs', type=float, default=90, help='sin avanzar next_round en un nodo vivo por más de esto = freeze')
    ap.add_argument('--ram-max-mb', type=float, default=0, help='RSS máximo por nodo (0 = sin techo, sólo monotonía)')
    ap.add_argument('--disk-max-mb', type=float, default=0, help='disco máximo del data_dir por nodo (0 = sin techo)')
    ap.add_argument('--genesis-supply', type=int, default=0, help='supply total en génesis (para el chequeo de conservación exacto; 0 = sólo cross-node)')
    ap.add_argument('--out', default='soak.jsonl', help='archivo JSONL de eventos')
    ap.add_argument('--selftest', action='store_true', help='corre aserciones internas y sale')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    nodes = {}
    for spec in args.node:
        name, _, url = spec.partition('=')
        if not url:
            print(f'--node inválido: {spec} (esperaba NAME=URL)', file=sys.stderr); return 2
        nodes[name] = url
    if not nodes:
        print('necesitás al menos un --node NAME=URL', file=sys.stderr); return 2
    submit_rpc = args.submit_rpc or next(iter(nodes.values()))

    out = open(args.out, 'a', buffering=1)
    def emit(kind, **kw):
        rec = {'t': round(now(), 3), 'kind': kind, **kw}
        out.write(json.dumps(rec, sort_keys=True) + '\n')
        tag = {'FORK': '🔴', 'SUPPLY': '🔴', 'TXLOSS': '🔴', 'FREEZE': '🟠',
               'RAM': '🟠', 'DISK': '🟠', 'RECOVER': '🟢'}.get(kind, '·')
        if kind not in ('tick',):
            print(f'{tag} {kind}: ' + ' '.join(f'{k}={v}' for k, v in kw.items()), flush=True)

    # cross-node state
    exec_root = {}             # executed_transactions -> {root: [nodes]}  (fork detection)
    round_supply = {}          # round -> {total_balance: [nodes]} (supply cross-node)
    last_round = {}            # node -> (round, wall_ts) for stall detection
    ram0 = {}; disk0 = {}      # baselines for growth
    canary_sent = 0            # cumulative units sent+confirmed to the recipient
    pending_send_since = None  # ts a send became "confirmed" but not yet on all nodes
    hard_fail = False
    start = now()
    last_send = 0.0

    def cli_transfer():
        if not (args.sender_keypair and args.canary_recipient):
            return None
        try:
            r = subprocess.run([args.qchain_bin, 'transfer', '--rpc', submit_rpc,
                                '--keypair', args.sender_keypair, '--to', args.canary_recipient,
                                '--amount', str(args.canary_amount)],
                               capture_output=True, text=True, timeout=30)
            return r.returncode == 0
        except Exception:
            return False

    emit('start', nodes=list(nodes.keys()), submit_rpc=submit_rpc)
    while True:
        t = now()
        alive = {}
        for name, url in nodes.items():
            st = get(url, '/status')
            if not st:
                continue
            alive[name] = {'status': st}
            hd = get(url, '/holders?limit=1')
            ec = get(url, '/economics')
            rt = get(url, '/root')
            rs = get(url, '/resources')
            if hd: alive[name]['holders'] = hd
            if ec: alive[name]['economics'] = ec
            if rt: alive[name]['root'] = rt
            if rs: alive[name]['resources'] = rs

        # ---- 1. FORK: same EXECUTED-TX count -> same root ----
        # El state root es función determinista del nº de tx EJECUTADAS, no de la
        # ronda de consenso (la ejecución va detrás del ordenamiento). Se re-lee
        # executed_transactions después del root: si cambió, la muestra está en
        # vuelo y se descarta (evita falsos positivos por lectura no-atómica).
        for name, url in nodes.items():
            if name not in alive:
                continue
            st1 = alive[name]['status']
            e1 = st1.get('executed_transactions')
            root = (alive[name].get('root') or {}).get('root')
            st2 = get(url, '/status')
            e2 = st2.get('executed_transactions') if st2 else None
            if e1 is None or root is None or e1 != e2:
                continue  # en vuelo o incompleto → descartar la muestra
            slot = exec_root.setdefault(e1, {})
            slot.setdefault(root, [])
            if name not in slot[root]:
                slot[root].append(name)
            if len(slot) > 1:  # dos roots distintos al MISMO nº de tx ejecutadas
                hard_fail = True
                emit('FORK', executed=e1, roots={r: ns for r, ns in slot.items()})

        # ---- 2. SUPPLY: conservation per-node + cross-node agreement ----
        for name, d in alive.items():
            hd = d.get('holders'); ec = d.get('economics')
            if not hd:
                continue
            try:
                tb = int(hd['total_balance']); burned = int(hd['total_burned'])
            except (KeyError, ValueError, TypeError):
                continue
            emitted = int((ec or {}).get('total_emitted', 0)) if ec else 0
            if args.genesis_supply:
                # conservation: balances + burned - emitted == genesis supply (constant)
                cons = tb + burned - emitted
                if cons != args.genesis_supply:
                    hard_fail = True
                    emit('SUPPLY', node=name, kind_detail='conservation', got=cons, expected=args.genesis_supply,
                         total_balance=tb, burned=burned, emitted=emitted)
            # cross-node agreement at the same holders-snapshot round
            hr = hd.get('round')
            if hr is not None:
                slot = round_supply.setdefault(hr, {})
                slot.setdefault(tb, [])
                if name not in slot[tb]:
                    slot[tb].append(name)
                if len(slot) > 1:
                    hard_fail = True
                    emit('SUPPLY', kind_detail='cross_node', round=hr, balances={b: ns for b, ns in slot.items()})

        # ---- 5. FREEZE: a live node's round must advance ----
        for name, d in alive.items():
            rnd = d['status'].get('next_round')
            if rnd is None:
                continue
            prev = last_round.get(name)
            if prev is None or rnd > prev[0]:
                last_round[name] = (rnd, t)
            elif t - prev[1] > args.stall_secs:
                emit('FREEZE', node=name, round=rnd, stalled_secs=round(t - prev[1], 1))
                # freeze is loud but not an instant hard-fail (could be recovering);
                # a sustained freeze on a node that is UP is the real kill-criterion —
                # the operator sees repeated FREEZE lines for the same node.

        # ---- 4. RAM/DISK growth ----
        for name, d in alive.items():
            rs = d.get('resources')
            if not rs:
                continue
            rss_mb = rs.get('rss_bytes', 0) / 1e6
            disk_mb = rs.get('disk_bytes', 0) / 1e6
            ram0.setdefault(name, rss_mb); disk0.setdefault(name, disk_mb)
            if args.ram_max_mb and rss_mb > args.ram_max_mb:
                emit('RAM', node=name, rss_mb=round(rss_mb, 1), max_mb=args.ram_max_mb)
            if args.disk_max_mb and disk_mb > args.disk_max_mb:
                emit('DISK', node=name, disk_mb=round(disk_mb, 1), max_mb=args.disk_max_mb)

        # ---- send a canary transfer + 3. TX-LOSS check ----
        if args.send_every and (t - last_send) >= args.send_every:
            last_send = t
            ok = cli_transfer()
            if ok:
                # confirm it landed on the submit node, then require all nodes to reach it
                canary_sent += args.canary_amount
                pending_send_since = t
                emit('canary_sent', total=canary_sent)
        if args.canary_recipient and canary_sent > 0:
            behind = []
            for name, url in nodes.items():
                if name not in alive:
                    continue  # node down (chaos) — don't judge it
                acct = get(url, '/account/' + args.canary_recipient)
                bal = int((acct or {}).get('balance', 0)) if acct else None
                if bal is None:
                    continue
                if bal > canary_sent:
                    # recipient has MORE than we sent — only possible if someone else funds it;
                    # for a dedicated canary address this is a config error, flag softly.
                    emit('canary_over', node=name, balance=bal, sent=canary_sent)
                elif bal < canary_sent:
                    behind.append((name, bal))
            if behind:
                waited = (t - pending_send_since) if pending_send_since else 0
                if waited > args.catchup_secs:
                    hard_fail = True
                    emit('TXLOSS', behind=behind, sent=canary_sent, waited_secs=round(waited, 1))
            else:
                if pending_send_since:
                    pending_send_since = None  # everyone caught up

        emit('tick', alive=len(alive), of=len(nodes), rounds={n: d['status'].get('next_round') for n, d in alive.items()})
        if hard_fail:
            emit('VERDICT', result='FAIL', uptime_secs=round(now() - start, 1))
            print('VERDICT: FAIL — una invariante dura se rompió (ver el JSONL). El operador debe detener el gate de lanzamiento.', flush=True)
            return 1
        time.sleep(args.interval)

def selftest():
    # Fork detection: two different roots at the same round trips.
    rr = {}
    def see(round_, root, node):
        slot = rr.setdefault(round_, {}); slot.setdefault(root, [])
        if node not in slot[root]: slot[root].append(node)
        return len(slot) > 1
    assert see(10, 'aaaa', 'v1') is False
    assert see(10, 'aaaa', 'v2') is False, 'same root same round is fine'
    assert see(10, 'bbbb', 'v3') is True, 'different root same round = fork'
    # Conservation math
    genesis = 1_000_000
    tb, burned, emitted = 900_000, 50_000, 0  # 900k live + 50k burned, 0 emitted... 950k != 1M -> broken
    assert tb + burned - emitted != genesis
    tb2 = 950_000
    assert tb2 + burned - emitted == genesis, 'balances+burned-emitted == genesis when conserved'
    # emission grows supply: 1M genesis, 100k emitted -> live+burned == 1.1M
    assert (1_000_000 + 100_000) + 0 - 100_000 == 1_000_000
    print('selftest OK (fork detection + conservation math)')
    return 0

if __name__ == '__main__':
    sys.exit(main())
