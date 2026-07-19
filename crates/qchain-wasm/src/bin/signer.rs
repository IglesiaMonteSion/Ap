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
            print!("{}", qchain_wasm::sign_transfer_json(&s, to, amount, nonce, &chain_id, fee_limit)?);
        }
        // Governance-path helpers, exercising the exact browser signing code.
        Some("delegate") => {
            // delegate <seed> <validator> <amount> <stake_account> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_delegate_json(&s, &args[3], args[4].parse()?, &args[5], args[6].parse()?, &seed(&args[7])?, args[8].parse()?)?);
        }
        Some("vote") => {
            // vote <seed> <proposal> <stake_account> <choice 0|1|2> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_vote_json(&s, &args[3], &args[4], args[5].parse()?, args[6].parse()?, &seed(&args[7])?, args[8].parse()?)?);
        }
        Some("finalize") => {
            // finalize <seed> <proposal> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_finalize_json(&s, &args[3], args[4].parse()?, &seed(&args[5])?, args[6].parse()?)?);
        }
        Some("execute") => {
            // execute <seed> <proposal> <registry 0|1> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_execute_json(&s, &args[3], args[4] != "0", args[5].parse()?, &seed(&args[6])?, args[7].parse()?)?);
        }
        // v7 staking-path helpers, exercising the exact browser signing code.
        Some("v7-stake") => {
            // v7-stake <seed> <position> <amount> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_stake_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?)?);
        }
        Some("v7-increase") => {
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_increase_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?)?);
        }
        Some("v7-begin-unstake") => {
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_begin_unstake_json(&s, &args[3], args[4].parse()?, args[5].parse()?, &seed(&args[6])?, args[7].parse()?)?);
        }
        Some("v7-withdraw") => {
            // v7-withdraw <seed> <position> <nonce> <chain_id_hex> <fee_limit>
            let s = seed(&args[2])?;
            print!("{}", qchain_wasm::sign_v7_withdraw_unbonded_json(&s, &args[3], args[4].parse()?, &seed(&args[5])?, args[6].parse()?)?);
        }
        _ => anyhow::bail!("usage: qchain-wasm-signer address|stake-addr|sign|delegate|vote|finalize|execute|v7-stake|v7-increase|v7-begin-unstake|v7-withdraw ..."),
    }
    Ok(())
}
