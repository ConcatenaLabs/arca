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
//! - [`Wallet`]: the operations — create, board, receive, send, read the
//!   mailbox, take part in a round, swap, exit, and re-check every coin after
//!   a rollback.
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
//! is unpaid, and every coin shows its dates ([`CoinDates`]).

pub mod chain;
pub mod client;
pub mod keys;
pub mod store;

mod exit;
mod pay;
mod round;
mod wallet;

pub use round::{RefreshQuote, DEFAULT_MAX_FEE_PPM};
pub use wallet::{CoinDates, Config, Wallet, HOME_FROM, REFRESH_FROM, SYNC_DAILY, WITNESS_PATIENCE};

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
