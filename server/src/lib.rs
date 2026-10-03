//! The Arca operator's server on Sequentia.
//!
//! The server holds the operator's side of Arca: it hands out the operator's
//! half of every leaf's salt, registers and credits boards, co-signs
//! out-of-round transfers and delivers them to their receivers, and keeps its
//! own on-chain wallet and transactions. Its state is in PostgreSQL
//! ([`store`]).
//!
//! The scripts, records and their validation are `arca-covenant`'s; the server
//! uses them and writes none of its own.

pub mod store;

pub use store::{Store, StoreError};
