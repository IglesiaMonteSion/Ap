//! Library surface for `qchain-node` - split out from the `qchain-node`
//! binary so a second binary in this crate (`qchain-genesis-build`, see
//! `src/bin/genesis_build.rs`) can reuse `config::NodeConfig` and friends
//! without duplicating the schema.

pub mod config;
pub mod engine;
pub mod genesis;
pub mod rpc;
