//! The Arca wallet on Sequentia.
//!
//! Arca is a covenant-tree Ark on Sequentia. This module is a wallet for it:
//! the user's side of every flow the Arca server runs, built on
//! [`arca_covenant`] for every script, record and check, so the wallet writes
//! none of its own.
//!
//! - [`chain`]: the chain source, a `sequentiad` over JSON-RPC, and the one
//!   answer to "is this final" (certified, and the Bitcoin anchor buried).
//! - [`store`]: the SQLite store, which keeps every nonce and key the wallet
//!   ever drew, every coin it holds or held with its record, and its
//!   bookkeeping.
//! - [`keys`]: the keys, from one BIP39 mnemonic as the Sequentia Wallet Kit
//!   derives them.
//! - [`client`]: the server's JSON interface over HTTP, with challenge
//!   authentication.
//! - [`registry`]: the operators the Sequentia registry lists, each
//!   record's signature checked by the wallet, and what a server joined from
//!   a record must show before it is pinned.
//! - [`command`]: the commands by name, with JSON arguments and answers, for a
//!   program that embeds the library (a browser worker, a mobile app's core).
//! - [`order`]: an order placed on the chain from the wallet's leaves, by an
//!   offboard into the address SeqDEX's fill covenant makes for its terms;
//!   where it rests and what filled it, read from the chain; its REFUND.
//! - [`claim`]: claim trees: a distribution that pays many holders in one
//!   round, each under a key the payer names, what no holder takes up going
//!   back to the payer; and the claims a wallet finds under its own address
//!   keys and takes up ([`Wallet::distribute`], [`Wallet::claims`],
//!   [`Wallet::claim`]).
//! - [`btc_swap`]: a swap of native BTC in a Bitcoin ark for an asset in the
//!   operator's tree, with another wallet of the operator, under one payment
//!   hash; the Bitcoin side, Bark, is run by the program, which hands in what
//!   Bark says and is told what Bark must run next.
//! - [`Wallet`]: the operations — create, board, receive, send, read the
//!   mailbox, take part in a round, take an on-chain order in a round
//!   ([`Wallet::take`]), place one ([`Wallet::order_place`]), swap, exit,
//!   re-check every coin after a
//!   rollback, and restore from the mnemonic alone ([`Wallet::restore`]:
//!   every leaf the server serves to the wallet's mailbox key, to which the
//!   wallet binds each leaf it makes, checked against the chain, the
//!   published tree and its owner's own signatures).
//!
//! The module builds in two ways. With the `arca` feature, as the command line
//! builds it, the node and the server are reached over `minreq` and the store
//! is a file in the wallet's directory. With `arca-core` alone it has no
//! transport of its own: every request goes through the one a program
//! registers with [`sequentia_ext::platform::set_platform`], and the program
//! opens the store itself ([`Wallet::create_in`], [`Wallet::open_in`]), as the
//! browser build does (`wallet-wasm/`).
//!
//! Every coin is validated with the library's checks under the wallet's own
//! policy before it is stored: a leaf from a round with the five checks on its
//! sweep token and clock and the bounds on its path; a coin received out of
//! round back to the batches and boards it rests on, with its lineage and its
//! boards checked against the chain. A refusal is never silent: it is shown
//! with its reason and recorded.
//!
//! Fees are paid in the asset being moved unless the user names another, and
//! no asset is a default: when the node does not accept that asset for fees,
//! the wallet says so and asks for one, and never falls back to another. An
//! exit is the one exception, since a coin must reach the chain whatever its
//! asset: where the coin's own reserves cannot pay and no asset is named, the
//! wallet pays with an on-chain coin of its own in an asset the node takes,
//! the asset moved first, no other preferred, and says which.
//!
//! `sync` keeps the wallet's coins alive by itself (D57): it asks for the
//! refresh of each coin in the two days before its exit deadline, where the
//! refresh is free, and from a day before takes on the chain every coin whose
//! refresh has not completed, whatever stands in the way. Run it at least
//! once a day while the wallet holds a coin off the chain or waits for a
//! payment (a coin paid to it is read only by `sync`, and may come days from
//! its exit date). [`Wallet::sync_schedule`] says when it must run next, for
//! a client on a timer, never more than a day ahead while a receive request
//! is unpaid, and due at once for a wallet that has never synced, and every
//! coin shows its dates ([`CoinDates`]). `sync` takes every exit step whose
//! date has come (a received leaf's home date, an exit's next step) before it
//! asks the operator anything, so an operator that answers slowly holds back
//! no claim; the schedule names those dates on their own (`next_exit_at`),
//! for [`Wallet::sync_exits`], which takes them and asks the operator
//! nothing. A take of an on-chain order ([`Wallet::take`]) needs the wallet
//! awake until it is released: its round goes out only once every take in
//! it has handed over its forfeits, which are due within the operator's
//! forfeit window (`info.fills.forfeit_window_seconds`, by the chain's median
//! time) of the round being built, and a take whose forfeits do not come is
//! void. The schedule wakes the wallet within the operator's round interval
//! and within half that window for as long as a take waits, so a client that
//! syncs when it is due completes the take; a client whose platform defers
//! its wakes longer than that loses the take, its coins its own again.
//! A leaf received over Lightning comes home, should the operator
//! not co-sign its claim, by a claim that races the operator's refund once
//! the leaf's timeout has passed: its fee rises at every wake as the timeout
//! nears, up to the leaf's whole value, it is paid from a coin of another
//! accepted asset when the node no longer takes the leaf's, and past the
//! timeout it replaces any refund in the mempool by paying more. A stall
//! longer than its margin leaves a fee race the operator can still win by
//! burning the leaf's value.

pub mod btc_swap;
pub mod chain;
pub mod claim;
pub mod client;
pub mod command;
pub mod keys;
pub mod registry;
pub mod store;

mod exit;
pub mod lightning;
pub mod order;
mod pay;
pub mod plan;
mod restore;
mod round;
mod take;
mod wallet;

pub use round::{RefreshQuote, DEFAULT_MAX_FEE_PPM};
pub use wallet::{CoinDates, Config, Spelling, Wallet, HOME_FROM, REFRESH_FROM, REQUEST_HOLDS, SYNC_DAILY, WITNESS_PATIENCE};

pub use arca_covenant;
pub use elements;

/// Why an operation could not be done.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// The wallet refused: the reason is for the user.
	#[error("refused: {0}")]
	Refused(String),
	/// The server refused, with its stable code.
	#[error("the server refused {call} ({status} {code}): {message}")]
	Server { call: String, status: i32, code: String, message: String },
	#[error("cannot reach the server: {0}")]
	Unreachable(String),
	/// What a coin rests on is not on the chain the node holds now, as during
	/// a rollback: it may be again.
	#[error("not on the chain now: {0}")]
	Missing(String),
	#[error("the node: {0}")]
	Node(String),
	#[error("the store: {0}")]
	Store(String),
	#[error("the keys: {0}")]
	Keys(String),
	#[error("cannot parse {0}")]
	Parse(String),
	#[error("{0}")]
	Io(String),
}

impl Error {
	/// A short machine-readable kind, for the command line's JSON.
	pub fn kind(&self) -> &'static str {
		match self {
			Error::Refused(_) => "refused",
			Error::Server { .. } => "server_refused",
			Error::Unreachable(_) => "unreachable",
			Error::Missing(_) => "missing",
			Error::Node(_) => "node",
			Error::Store(_) => "store",
			Error::Keys(_) => "keys",
			Error::Parse(_) => "parse",
			Error::Io(_) => "io",
		}
	}
}

/// 32 random bytes from the system's source: every nonce the wallet draws.
pub fn random32() -> [u8; 32] {
	use bitcoin::secp256k1::rand::RngCore;
	let mut b = [0u8; 32];
	bitcoin::secp256k1::rand::rngs::OsRng.fill_bytes(&mut b);
	b
}
