//! What the scenario tests share: a whole Arca server as an operator runs it,
//! on an anchored proof-of-stake regtest chain, and the `arca` binary run as a
//! user runs it.
//!
//! Needs `SEQUENTIAD_EXEC` (a node binary), `ARCA_TEST_POSTGRES` (a PostgreSQL
//! server the test may create databases on) and the `arca-signer` binary,
//! named by `ARCA_SIGNER_EXEC` or built beside `arca`
//! (`cargo build -p arca-server --bin arca-signer`).

#![allow(dead_code)]

pub mod cli;
pub mod db;
pub mod keeper;
pub mod lightning;
pub mod node;
pub mod proxy;
pub mod running;
pub mod signer;
