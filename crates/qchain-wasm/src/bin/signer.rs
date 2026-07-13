//! Native helper that exercises the exact same signing code the WASM wallet
//! uses (the `pure` crypto backend), so it can be tested end-to-end against a
//! real liboqs node without a browser. Not shipped - a verification tool.
//!
//!   qchain-wasm-signer address <seed_hex>
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
        Some("sign") => {
            let s = seed(&args[2])?;
            let to = &args[3];
            let amount: u64 = args[4].parse()?;
            let nonce: u64 = args[5].parse()?;
            let chain_id = seed(&args[6])?;
            let fee_limit: u64 = args[7].parse()?;
            print!("{}", qchain_wasm::sign_transfer_json(&s, to, amount, nonce, &chain_id, fee_limit)?);
        }
        _ => anyhow::bail!("usage: qchain-wasm-signer address <seed_hex> | sign <seed_hex> <to> <amount> <nonce> <chain_id_hex> <fee_limit>"),
    }
    Ok(())
}
