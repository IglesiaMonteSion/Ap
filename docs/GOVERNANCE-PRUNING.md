# Poda de gobernanza + depósito antispam (roadmap #16)

Dos mecanismos de higiene de gobernanza, **ambos GATED/aditivos** — una red que
no los configura ni los usa es **byte-idéntica** a la de antes de #16 (nada que
aplicar en la red viva; `chain_id` sin cambio). Todo el cambio vive en
`qchain-governance` (tipos puros) + `qchain-execution::governance` (el programa
nativo) + `qchain-cli`. NO toca consenso/wire/estado de las tx normales. Sin
regen de WASM (la wallet nunca crea propuestas; sus firmas Vote/Finalize/Execute
= discriminantes 1/2/3 quedan intactas).

---

## 1. Depósito antispam (refundable)

Crear una propuesta puede costar un **depósito reembolsable**, para que hacer
spam de propuestas sea caro. Modelo estándar (Cosmos): **se reembolsa** si la
propuesta fue genuina, **se quema** si nadie la votó.

- **Gate:** `EconomicParams.governance_proposal_deposit` (átomos). Default **0**
  = SIN depósito → byte-idéntico. Se lee de la MISMA fuente autoritativa que usa
  el ledger (la cuenta `PARAMS`), y es **gobernable** por el mismo camino
  `Economic`-tier que los demás parámetros económicos.
- **Cobro (`CreateProposal`):** con `deposit > 0`, se debita del pagador (que es
  el proponente) y se **RETIENE en el balance de la propia cuenta de la
  propuesta** — no hay singleton de escrow nuevo. `CreateProposal` ahora exige
  `accounts[3] = PARAMS_ACCOUNT_ID` (pinneado, read-only) para leer el depósito;
  con depósito 0 es no-op. **Sólo el CLI construye `CreateProposal`** (la wallet
  no), así que node + CLI se actualizan juntos; una red con depósito 0 no cambia.
- **Liquidación (`CloseProposal`, ver abajo):** al podar la propuesta,
  - **REEMBOLSO** al proponente si la propuesta **alcanzó el piso de
    participación** (`reached_participation_floor()` — hubo quórum de turnout, es
    decir fue una propuesta genuina; incluso si fue **rechazada** en la votación
    se reembolsa, sólo la falta de turnout la pierde);
  - **QUEMA** (al `BURN_ADDRESS` canónico `[0xFF;32]`, inquemable) si quedó por
    debajo del piso (spam que nadie votó).
  - Cualquier balance por ENCIMA del depósito registrado (p.ej. una
    transferencia no solicitada a la dirección de la propuesta) se **quema por
    defensa**. La conservación de suministro se mantiene trivialmente: todo el
    balance se rutea (reembolso + quema == balance), nada se destruye fuera de
    libro.

## 2. Poda de propuestas terminales (`CloseProposal`)

Instrucción nueva `GovernanceInstruction::CloseProposal` (**discriminante 6**,
apéndice → no mueve 1/2/3). **Permissionless:** cualquiera la llama como
"janitor" para reclamar estado.

- `accounts[0]` = la propuesta, `accounts[1]` = el proponente (destino del
  reembolso, pinneado a `proposal.proposer`), `accounts[2]` = `BURN_ADDRESS`.
- **Condición:** `status ∈ {Rejected, Executed}` **Y**
  `current_round >= voting_ends_round + PROPOSAL_RETENTION_ROUNDS` (5000 rondas).
  - Una propuesta **`Voting`** no se cierra (aún abierta).
  - Una propuesta **`Passed`-pero-no-`Executed`** tampoco (todavía tiene un
    efecto pendiente) — se cierra recién cuando se ejecuta (o nunca, si no se
    ejecuta: límite honesto abajo).
- **Efecto:** liquida el depósito (§1) y **limpia la `data` de la cuenta** — el
  término de crecimiento de estado real (el `Vec<voted_stake_accounts>`, que
  crece con el número de votantes) se reclama.

### Límite honesto de la poda

Un programa nativo **no puede borrar una cuenta** por el commit del working-set
(el ledger sólo ESCRIBE las cuentas del working-set, nunca elimina). Así que la
**hoja Merkle de la propuesta permanece** (como una cuenta vacía: balance 0,
`data` vacío), pero el **blob de datos no acotado se reclama** — que es el
término que crecía sin cota. Una segunda `CloseProposal` sobre una cuenta ya
podada falla al decodificar la propuesta (data vacía) → no se puede
doble-liquidar. Una propuesta `Passed`-nunca-`Executed` no se auto-poda (su
depósito queda retenido); es un corner raro (¿por qué aprobar y nunca ejecutar,
si cualquiera puede ejecutar permissionless?), documentado.

`PROPOSAL_RETENTION_ROUNDS = 5000` es generoso — cómodamente mayor que el
período de votación + time-lock de cualquier tier (~200 + ~120 rondas), así que
nunca se poda algo con efecto pendiente. A ~500 ms/ronda son ~42 minutos.

---

## Compatibilidad / migración

- `Proposal` gana un campo `deposit: u64` **al final**; `Proposal::read_or_legacy`
  migra una propuesta pre-#16 (sin el campo) con `deposit = 0`. `read_proposal`
  del programa usa `read_or_legacy` → una propuesta on-chain vieja sigue leyendo.
- `EconomicParams` gana `governance_proposal_deposit: u64` **al final**;
  `EconomicParams::read_or_legacy` migra un blob v4 (28 bytes) o pre-v4 (26
  bytes) con `deposit = 0`. El apply-path (`current_params`), el Execute de
  gobernanza y el CLI ya usan `read_or_legacy` → la red viva no se rompe; la
  cuenta `PARAMS` se re-serializa al formato de 6 campos la próxima vez que un
  Execute la escribe (determinista, sin fork).

## Herramientas

- **Activar el depósito:** una propuesta `Economic`-tier que setee
  `governance_proposal_deposit` (o un génesis nuevo con el valor).
- **Podar:** `qchain close-proposal --proposal <addr>` (permissionless; lee el
  proponente de la propia propuesta para el reembolso y pasa `BURN_ADDRESS`).
