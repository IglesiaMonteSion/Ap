//! Invariantes ESTRUCTURALES formalizadas (roadmap #15).
//!
//! Este módulo formaliza, como funciones puras y checkeables, las invariantes que
//! NO son económicas (esas viven en `invariants_v7`: supply/bonos/shares/fee-split).
//! Cubre las tres dimensiones estructurales del roadmap #15:
//!
//! - **no-duplicados**: en el registro de validadores, entre entradas VIVAS
//!   (no-`Removed`), ninguna dirección (consenso/operador/retiro) ni moniker se
//!   repite; y un conjunto de firmantes (certificado / aprobaciones de tesorería)
//!   no cuenta la misma identidad dos veces.
//! - **nonce**: entre dos estados comprometidos consecutivos, el nonce de ninguna
//!   cuenta puede DECRECER (un apply válido sólo lo incrementa → sin replay de una
//!   tx ya ejecutada).
//! - **expiración**: una tx APLICADA nunca puede haber estado caducada
//!   (`valid_until_round == 0`, o `current_round <= valid_until_round`).
//!
//! Cada función es PURA (sin I/O, sin reloj/RNG) y determinista, para poder correrla
//! en tests diferenciales, en un canary de runtime, o como defensa-en-profundidad.
//! No REEMPLAZA la aplicación de estas reglas en el hot path (el registro las fuerza
//! en `bond_and_register`, el ledger fuerza nonce-exacto + expiración en
//! `apply_transaction`) — las FORMALIZA y las hace testeables por separado.
//!
//! Documento canónico de TODAS las invariantes (estas + las económicas de §13):
//! `docs/INVARIANTS.md`.

use crate::validator_v7::{ValidatorV7Registry, ValidatorV7State};
use qchain_core::Account;
use qchain_crypto::Pubkey;
use std::collections::{HashMap, HashSet};

/// Una invariante estructural rota. Nombra los valores que discreparon (no un
/// assert pelado) para que un fallo sea diagnosticable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralViolation {
    /// no-duplicados: una dirección aparece más de una vez entre validadores vivos
    /// (como consenso/operador/retiro, del mismo o de otro validador).
    DuplicateIdentity { address: Pubkey },
    /// no-duplicados: un moniker repetido entre validadores vivos.
    DuplicateMoniker { moniker: String },
    /// nonce: el nonce de una cuenta retrocedió entre dos estados comprometidos.
    NonceDecreased { account: Pubkey, before: u64, after: u64 },
    /// expiración: se aplicó una tx cuya ventana de validez ya había pasado.
    ExpiredTransactionApplied { valid_until_round: u64, current_round: u64 },
    /// no-duplicados: un firmante contado dos veces en un conjunto de aprobaciones.
    DuplicateSigner { signer: Pubkey },
}

/// **no-duplicados (registro).** Entre validadores VIVOS (no-`Removed`), ninguna de
/// las tres direcciones de rol (consenso `address`, `operator_address`,
/// `withdrawal_address`) ni el `moniker` puede repetirse — ni dentro de un
/// validador ni entre validadores distintos. Formaliza `addresses_in_use` /
/// `moniker_taken` como una invariante de ESTADO checkeable sobre cualquier
/// registro comprometido (el runtime ya rechaza el alta duplicada en
/// `bond_and_register`; esto verifica que el estado resultante lo respeta).
pub fn check_registry_uniqueness(registry: &ValidatorV7Registry) -> Result<(), StructuralViolation> {
    let mut ids: HashSet<Pubkey> = HashSet::new();
    let mut monikers: HashSet<&str> = HashSet::new();
    for v in &registry.validators {
        if v.state == ValidatorV7State::Removed {
            continue;
        }
        for a in [v.address, v.operator_address, v.withdrawal_address] {
            if !ids.insert(a) {
                return Err(StructuralViolation::DuplicateIdentity { address: a });
            }
        }
        if !monikers.insert(v.moniker.as_str()) {
            return Err(StructuralViolation::DuplicateMoniker { moniker: v.moniker.clone() });
        }
    }
    Ok(())
}

/// **nonce (monotonía).** Entre un estado `before` y el `after` inmediatamente
/// siguiente (un batch/ronda comprometido), NINGUNA cuenta presente en ambos puede
/// tener su nonce DECRECIDO. Un `apply_transaction` válido sólo incrementa el nonce
/// (nonce-exacto + bump), nunca lo baja; un nonce que retrocede sería un replay de
/// una tx ya ejecutada o una corrupción de estado. Invariante de TRANSICIÓN.
///
/// Una cuenta nueva en `after` (ausente en `before`) es válida (arranca en 0).
pub fn check_nonce_monotonic(
    before: &HashMap<Pubkey, Account>,
    after: &HashMap<Pubkey, Account>,
) -> Result<(), StructuralViolation> {
    for (pk, a_before) in before {
        if let Some(a_after) = after.get(pk) {
            if a_after.nonce < a_before.nonce {
                return Err(StructuralViolation::NonceDecreased {
                    account: *pk,
                    before: a_before.nonce,
                    after: a_after.nonce,
                });
            }
        }
    }
    Ok(())
}

/// **expiración.** Una tx APLICADA no puede haber estado caducada: `valid_until_round`
/// 0 (sin expiración) o `current_round <= valid_until_round`. Pura; espejo EXACTO de
/// la regla que el ledger fuerza en `apply_transaction` (#191). Invariante POR-TX,
/// para verificar en un test diferencial que ninguna tx del orden comprometido se
/// aplicó fuera de su ventana.
pub fn check_not_expired(valid_until_round: u64, current_round: u64) -> Result<(), StructuralViolation> {
    if valid_until_round != 0 && current_round > valid_until_round {
        return Err(StructuralViolation::ExpiredTransactionApplied { valid_until_round, current_round });
    }
    Ok(())
}

/// **no-duplicados (firmantes).** Un conjunto de identidades firmantes (las firmas
/// de un certificado, las aprobaciones de una op de tesorería, los votos de una
/// propuesta) no puede contar a la misma identidad dos veces — sin re-usar el mismo
/// stake/aprobación. Formaliza el dedup que `verify_certificate` y el multisig de
/// tesorería ya hacen. Invariante de CONTEO.
pub fn check_unique_signers(signers: &[Pubkey]) -> Result<(), StructuralViolation> {
    let mut seen: HashSet<Pubkey> = HashSet::new();
    for s in signers {
        if !seen.insert(*s) {
            return Err(StructuralViolation::DuplicateSigner { signer: *s });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics_v7::VALIDATOR_BOND_ATOMS;
    use crate::validator_v7::ValidatorV7Entry;
    use qchain_crypto::Keypair;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn entry(consensus: Pubkey, operator: Pubkey, withdrawal: Pubkey, moniker: &str, state: ValidatorV7State) -> ValidatorV7Entry {
        // Un bundle real cualquiera (los campos de identidad son lo que se chequea).
        let kp = Keypair::generate().unwrap();
        ValidatorV7Entry {
            address: consensus,
            operator_address: operator,
            withdrawal_address: withdrawal,
            moniker: moniker.to_string(),
            pubkey_bundle: kp.public_key_bundle(),
            p2p_address: "127.0.0.1:9000".to_string(),
            bond: VALIDATOR_BOND_ATOMS,
            state,
            registered_quanto: 0,
            activation_quanto: 1,
            exit_requested_quanto: 0,
            bond_release_quanto: 0,
            participation_credits: 0,
            participation_opportunities: 0,
        }
    }

    fn acct(nonce: u64) -> Account {
        let mut a = Account::new_wallet(Pubkey::system_program_id());
        a.nonce = nonce;
        a
    }

    #[test]
    fn registry_uniqueness_accepts_distinct_and_rejects_dups() {
        // Limpio: tres validadores con las 9 direcciones todas distintas + monikers únicos.
        let clean = ValidatorV7Registry {
            validators: vec![
                entry(pk(1), pk(2), pk(3), "alpha", ValidatorV7State::Active),
                entry(pk(4), pk(5), pk(6), "beta", ValidatorV7State::BondedPending),
            ],
        };
        assert!(check_registry_uniqueness(&clean).is_ok());

        // Dirección compartida entre dos roles/validadores vivos → rechazado.
        let dup_addr = ValidatorV7Registry {
            validators: vec![
                entry(pk(1), pk(2), pk(3), "alpha", ValidatorV7State::Active),
                entry(pk(4), pk(1), pk(6), "beta", ValidatorV7State::Active), // pk(1) reusada como operador
            ],
        };
        assert!(matches!(check_registry_uniqueness(&dup_addr), Err(StructuralViolation::DuplicateIdentity { .. })));

        // Moniker repetido → rechazado.
        let dup_moniker = ValidatorV7Registry {
            validators: vec![
                entry(pk(1), pk(2), pk(3), "same", ValidatorV7State::Active),
                entry(pk(4), pk(5), pk(6), "same", ValidatorV7State::Active),
            ],
        };
        assert!(matches!(check_registry_uniqueness(&dup_moniker), Err(StructuralViolation::DuplicateMoniker { .. })));

        // Una entrada Removed NO cuenta para unicidad — su dirección/moniker se
        // pueden re-usar (re-registro en el mismo slot).
        let with_removed = ValidatorV7Registry {
            validators: vec![
                entry(pk(1), pk(2), pk(3), "alpha", ValidatorV7State::Removed),
                entry(pk(1), pk(2), pk(3), "alpha", ValidatorV7State::Active),
            ],
        };
        assert!(check_registry_uniqueness(&with_removed).is_ok());
    }

    #[test]
    fn nonce_never_decreases() {
        let mut before = HashMap::new();
        before.insert(pk(1), acct(5));
        before.insert(pk(2), acct(0));

        // Igual o mayor → OK; una cuenta nueva en after → OK.
        let mut after_ok = HashMap::new();
        after_ok.insert(pk(1), acct(6));
        after_ok.insert(pk(2), acct(0));
        after_ok.insert(pk(9), acct(0)); // nueva
        assert!(check_nonce_monotonic(&before, &after_ok).is_ok());

        // Un nonce que retrocede → violación diagnosticable.
        let mut after_bad = HashMap::new();
        after_bad.insert(pk(1), acct(4)); // 5 -> 4
        assert!(matches!(
            check_nonce_monotonic(&before, &after_bad),
            Err(StructuralViolation::NonceDecreased { before: 5, after: 4, .. })
        ));
    }

    #[test]
    fn expiration_matches_the_ledger_rule() {
        assert!(check_not_expired(0, 999).is_ok(), "0 = sin expiración");
        assert!(check_not_expired(10, 10).is_ok(), "el borde exacto vale");
        assert!(check_not_expired(10, 9).is_ok());
        assert!(matches!(
            check_not_expired(10, 11),
            Err(StructuralViolation::ExpiredTransactionApplied { valid_until_round: 10, current_round: 11 })
        ));
    }

    #[test]
    fn unique_signers_rejects_a_double_count() {
        assert!(check_unique_signers(&[pk(1), pk(2), pk(3)]).is_ok());
        assert!(matches!(
            check_unique_signers(&[pk(1), pk(2), pk(1)]),
            Err(StructuralViolation::DuplicateSigner { signer })
            if signer == pk(1)
        ));
    }
}
