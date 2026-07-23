//! Native helper that exercises the exact same signing code the WASM wallet
//! uses (the `pure` crypto backend), so it can be tested end-to-end against a
//! real liboqs node without a browser. Not shipped - a verification tool.
//!
//!   qchain-wasm-signer address <seed_hex>
//!   qchain-wasm-signer stake-addr <seed_hex> <index>
//!   qchain-wasm-signer sign <seed_hex> <to_addr> <amount> <nonce> <chain_id_hex> <fee_limit>

use std::env;

fn seed(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes of hex"))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("address") => {
            let s = seed(&args[2])?;
            println!("{}", qchain_wasm::address_from_seed(&s)?);
        }
        Some("stake-addr") => {
            let s = seed(&args[2])?;
            let index: u32 = args[3].parse()?;
            println!("{}", qchain_wasm::stake_address_from_seed(&s, index));
        }
        Some("sign") => {
            let s = seed(&args[2])?;
            let to = &args[3];
            let amount: u64 = args[4].parse()?;
            let nonce: u64 = args[5].parse()?;
            let chain_id = seed(&args[6])?;
            let fee_limit: u64 = args[7].parse()?;
            print!("{}", qchain_wasm::sign_transfer_json(&s, to, amount, nonce, &chain_id, fee_limit, args.get(8).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        // sign-expiring <seed> <to> <amount> <nonce> <chain_id_hex> <fee_limit> <valid_until_round>
        // Signs a transfer with an explicit `valid_until_round` (task #191) — used
        // to verify the node rejects an ALREADY-EXPIRED transaction at admission.
        Some("sign-expiring") => {
            use qchain_core::{Instruction, Transaction};
            use qchain_crypto::{Keypair, Pubkey};
            let s = seed(&args[2])?;
            let to_pk: Pubkey = args[3].trim().parse().map_err(|e| anyhow::anyhow!("bad to: {e}"))?;
            let amount: u64 = args[4].parse()?;
            let nonce: u64 = args[5].parse()?;
            let chain_id = seed(&args[6])?;
            let fee_limit: u64 = args[7].parse()?;
            let valid_until: u64 = args[8].parse()?;
            let payer = Keypair::generate_from_seed(&s)?;
            let mut data = vec![1u8]; // SystemInstruction::Transfer discriminant (CreateAccount=0, Transfer=1)
            data.extend_from_slice(&amount.to_le_bytes());
            let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![payer.pubkey(), to_pk], data };
            let tx = Transaction::new_signed_full(&payer, nonce, chain_id, fee_limit, 0, valid_until, vec![ix])?;
            print!("{}", serde_json::to_string(&tx)?);
        }
        // Governance-path helpers, exercising the exact browser signing code.
        Some("delegate") => {
            // delegate <seed> <validator> <amount> <stake_account> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_delegate_json(&s, &args[3], args[4].parse()?, &args[5], args[6].parse()?, &seed(&args[7])?, args[8].parse()?, args.get(9).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("vote") => {
            // vote <seed> <proposal> <stake_account> <choice 0|1|2> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_vote_json(&s, &args[3], &args[4], args[5].parse()?, args[6].parse()?, &seed(&args[7])?, args[8].parse()?, args.get(9).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("finalize") => {
            // finalize <seed> <proposal> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_finalize_json(&s, &args[3], args[4].parse()?, &seed(&args[5])?, args[6].parse()?, args.get(7).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("execute") => {
            // execute <seed> <proposal> <registry 0|1> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_execute_json(&s, &args[3], args[4] != "0", args[5].parse()?, &seed(&args[6])?, args[7].parse()?, args.get(8).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        // v7 staking-path helpers, exercising the exact browser signing code.
        Some("v7-stake") => {
            // v7-stake <seed> <position> <amount> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_stake_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?, args.get(8).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("v7-increase") => {
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_increase_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?, args.get(8).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("v7-begin-unstake") => {
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_begin_unstake_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?, args.get(8).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("v7-withdraw") => {
            // v7-withdraw <seed> <position> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_withdraw_unbonded_json(&s, &args[3], args[4].parse()?, &seed(&args[5])?, args[6].parse()?, args.get(7).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("program-addr") => {
            // program-addr <seed> <index>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::program_address_from_seed(&s, args[3].parse()?));
        }
        Some("program-pda") => {
            // program-pda <program_id> <seed_string>  — deriva la PDA de un programa
            print!("{}", qchain_wasm::program_pda(&args[2], args[3].as_bytes())?);
        }
        Some("program-pda-hex") => {
            // program-pda-hex <program_id> <seed_hex>  — PDA con seed BINARIO (para
            // seeds que llevan bytes crudos, ej. una dirección). SDK v0.5.
            let seed_bytes = hex::decode(args[3].trim()).map_err(|e| anyhow::anyhow!("seed hex inválido: {e}"))?;
            print!("{}", qchain_wasm::program_pda(&args[2], &seed_bytes)?);
        }
        Some("token-balance-pda") => {
            // token-balance-pda <program_id> <holder_base58>  — la PDA de saldo de
            // un titular en un token del SDK v0.5: seed = 0x01 ‖ holder(32 bytes).
            // MISMA fórmula que `holder_seed(0x01, holder)` on-chain.
            let holder: qchain_crypto::Pubkey =
                args[3].trim().parse().map_err(|e| anyhow::anyhow!("dirección de titular inválida: {e}"))?;
            let mut seed_bytes = [0u8; 33];
            seed_bytes[0] = 0x01;
            seed_bytes[1..].copy_from_slice(&holder.to_bytes());
            print!("{}", qchain_wasm::program_pda(&args[2], &seed_bytes)?);
        }
        Some("deploy-program") => {
            // deploy-program <seed> <index> <wasm_file> <entry_point> <nonce> <chain_id_hex> <fee_limit>
            // (re-audit #2: the address is derived from the payer + index/salt,
            // not passed in — same as programAddressFromSeed(seed, index).)
            let s = seed(&args[2])?;
            let module = std::fs::read(&args[4])?;
            print!("{}", qchain_wasm::sign_deploy_program_json(&s, args[3].parse()?, &module, &args[5], args[6].parse()?, &seed(&args[7])?, args[8].parse()?, args.get(9).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        Some("call-program") => {
            // call-program <seed> <program_id> <accounts_csv> <args_csv> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_call_program_json(&s, &args[3], &args[4], &args[5], args[6].parse()?, &seed(&args[7])?, args[8].parse()?, args.get(9).map(|a| a.parse()).transpose()?.unwrap_or(0))?);
        }
        _ => anyhow::bail!("usage: qchain-wasm-signer address|stake-addr|sign|delegate|vote|finalize|execute|v7-stake|v7-increase|v7-begin-unstake|v7-withdraw|program-addr|deploy-program|call-program ..."),
    }
    Ok(())
}
