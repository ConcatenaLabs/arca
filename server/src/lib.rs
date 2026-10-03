//! The Arca operator's server on Sequentia.
//!
//! The server holds the operator's side of Arca: it hands out the operator's
//! half of every leaf's salt, registers and credits boards, co-signs
//! out-of-round transfers and delivers them to their receivers, and keeps its
//! own on-chain wallet and transactions. Its state is in PostgreSQL
//! ([`store`]); what it knows of the chain, and whether anything is final,
//! comes from the finality service ([`chain::finality`]). Its on-chain wallet
//! ([`wallet`]) is built on the Sequentia Wallet Kit, and the nursery
//! ([`nursery`]) keeps the transactions it relies on broadcast until final.
//!
//! The scripts, records and their validation are `arca-covenant`'s; the server
//! uses them and writes none of its own.

pub mod boards;
pub mod chain;
pub mod nursery;
pub mod params;
pub mod store;
pub mod wallet;

pub use store::{Store, StoreError};
