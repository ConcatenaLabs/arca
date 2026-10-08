//! The wallet: its configuration, its policies, the check of every coin it
//! holds against the chain, the re-check after a rollback, its on-chain coins
//! and the board.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use elements::{AssetId, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use arca_covenant::{BoardRecord, Chain, CoinRecord, MedianTime, RelativeTime, Template, ValidCoin, WalletPolicy};

use super::chain::{hex, unhex, unhex32, ChainSource, Finality};
use super::client::ServerClient;
use super::keys::{p2wpkh, Keys, CHANGE, RECEIVE};
use super::store::{CoinRow, Store};
use super::{random32, Error};

/// The file beside the database that holds the mnemonic.
pub const MNEMONIC_FILE: &str = "mnemonic";
/// The database.
pub const DB_FILE: &str = "arca.sqlite";
/// The file beside the database that holds the node's RPC password, when the
/// node is reached with one: readable by its owner alone, and never in the
/// database.
pub const NODE_PASSWORD_FILE: &str = "node_password";

/// Writes `contents` to `path`, readable and writable by its owner alone.
fn write_private(path: &Path, contents: &str) -> Result<(), Error> {
	std::fs::write(path, contents).map_err(|e| Error::Io(format!("{}: {}", path.display(), e)))?;
	set_private(path)
}

/// Makes `path` readable and writable by its owner alone.
fn set_private(path: &Path) -> Result<(), Error> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| Error::Io(format!("{}: {}", path.display(), e)))?;
	}
	#[cfg(not(unix))]
	let _ = path;
	Ok(())
}
/// What a new wallet pins from its node and its server.
struct Pins {
	genesis: String,
	chain_name: String,
	operator: String,
	keepers: String,
	tip_height: u64,
	tip_hash: String,
}

/// How many unused on-chain scripts past the last one in use the wallet looks at.
const GAP: u32 = 20;

/// How the wallet reaches its node and its server, and what it asks for and
/// accepts.
#[derive(Debug, Clone)]
pub struct Config {
	/// The server's base URL (`https://host/arca`): calls go under `/v1/`.
	pub server: String,
	/// The node's JSON-RPC URL and credentials.
	pub node_url: String,
	pub node_user: Option<String>,
	pub node_password: Option<String>,
	pub node_cookie: Option<String>,
	/// The account of the leaf keys, `m/6'/account'/…`.
	pub account: u32,
	/// The exit delay the wallet asks for its own leaves, in 512-second units.
	pub exit_delay_units: u16,
	/// The bounds on the exit delay of any leaf it accepts, its lineage
	/// included.
	pub min_exit_delay_units: u16,
	pub max_exit_delay_units: u16,
}

impl Config {
	/// The specification's delays: leaves asked for at 36 hours, accepted from
	/// 36 to 48 hours.
	pub fn spec_delays(server: &str, node_url: &str) -> Config {
		let d = RelativeTime::from_seconds_ceil(WalletPolicy::SPEC_DELAY_SECONDS).expect("36 hours").units();
		let max = RelativeTime::from_seconds_ceil(WalletPolicy::DEFAULT_MAX_EXIT_SECONDS).expect("48 hours").units();
		Config {
			server: server.into(), node_url: node_url.into(), node_user: None, node_password: None, node_cookie: None,
			account: 0, exit_delay_units: d, min_exit_delay_units: d, max_exit_delay_units: max,
		}
	}
}

/// The wallet. See the [module documentation](super).
pub struct Wallet {
	pub(crate) datadir: PathBuf,
	pub(crate) store: Store,
	pub(crate) keys: Keys,
	pub(crate) chain: ChainSource,
	pub(crate) server: ServerClient,
	pub(crate) genesis: Chain,
	pub(crate) operator: XOnlyPublicKey,
	pub(crate) cfg: Config,
	pub(crate) secp: Secp256k1<elements::secp256k1_zkp::All>,
	/// What witnessing the operator's signer's record found, and when
	/// ([`Wallet::witness`]): once a command, and again after
	/// [`WITNESS_FOR`] in a process that runs longer.
	pub(crate) witnessed: std::cell::RefCell<Option<(web_time::Instant, Value)>>,
	/// How long `sync` keeps trying to reach the operator, with back-off,
	/// before it takes it for unreachable ([`WITNESS_PATIENCE`] unless set).
	pub witness_patience: std::time::Duration,
	/// The change of every fee coin this process's exits spent, not in a
	/// block yet: a later exit of the same `sync` pays its fees from it, as
	/// the steps of one exit do.
	pub(crate) change_in_flight: std::cell::RefCell<Vec<(OutPoint, TxOut, Keypair)>>,
	/// How what the wallet says names the client's commands, and the
	/// prefixes of the texts it hands out ([`Spelling`]).
	pub(crate) spelling: Spelling,
}

/// How a client spells, in what the wallet says, its own commands and the
/// prefixes of the texts the wallet hands out (a receive request, a swap
/// offer, a swap acceptance). The default names no command: the wallet
/// says the act ("sync", "an exit", "the wallet's address"), and prefixes
/// its texts `request:`, `swap-offer:` and `swap-accept:`. A command line
/// passes its own name ([`Spelling::command_line`]), so that its notes name
/// its commands (`arca sync`) and its texts carry its prefixes (`arca:`).
/// Whatever their prefix, every wallet reads every text: it tells a request
/// from an offer by what the text holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spelling {
	/// The command line's name, as its commands are run (`arca`); `None`
	/// for a client without one.
	pub commands: Option<String>,
	pub request: String,
	pub offer: String,
	pub accept: String,
}

impl Default for Spelling {
	fn default() -> Spelling {
		Spelling { commands: None, request: "request:".into(), offer: "swap-offer:".into(), accept: "swap-accept:".into() }
	}
}

impl Spelling {
	/// A command line named `name`: its commands in every note (`name sync`),
	/// and texts prefixed `name:`, `name-offer:` and `name-accept:`.
	pub fn command_line(name: &str) -> Spelling {
		Spelling { commands: Some(name.to_string()), request: format!("{}:", name), offer: format!("{}-offer:", name),
			accept: format!("{}-accept:", name) }
	}

	/// `note` with its slots filled: `{sync}` and `{exit}`, the command or the
	/// act; `{address}`, where to send the wallet an on-chain coin.
	pub fn say(&self, note: &str) -> String {
		let command = |c: &str| self.commands.as_ref().map(|n| format!("`{} {}`", n, c));
		note.replace("{sync}", &command("sync").unwrap_or_else(|| "sync".into()))
			.replace("{exit}", &command("exit").unwrap_or_else(|| "an exit".into()))
			.replace("{address}", &command("address").map(|c| format!("an address of {}", c))
				.unwrap_or_else(|| "the wallet's address".into()))
	}
}

/// How long a witness of the operator's signer's record stands before the
/// wallet witnesses it again.
pub const WITNESS_FOR: std::time::Duration = std::time::Duration::from_secs(10);

/// The most heads one witness hands the server: the server's bound.
pub const MAX_WITNESS: usize = 32;

/// The most heads without the signer's signature one witness hands the
/// server: the server's bound.
pub const MAX_UNSIGNED_WITNESS: usize = 4;

/// What the wallet says of an operator with no keeper, and of every coin it
/// receives from one out of round.
pub(crate) const NO_KEEPER: &str = "the operator runs no keeper of its signer's record: a coin received out of round rests on the \
	operator's machine alone until it is refreshed, and a restore of that machine can let its sender spend it twice";

/// How long before a coin's exit date `sync` takes it on the chain once the
/// operator's signer is stopped: three days.
pub const HOME_WINDOW: u32 = 3 * 86_400;

/// From how long before a coin's exit date (its exit deadline, `exit_by`)
/// `sync` asks for the coin's refresh by itself: two days, the free window,
/// where the refresh costs nothing ([`super::round::FREE_WINDOW`]).
pub const REFRESH_FROM: u32 = 2 * 86_400;

/// From how long before a coin's exit date `sync` takes it on the chain
/// unless its refresh has completed, whatever stands in the way: a day.
pub const HOME_FROM: u32 = 86_400;

/// How long before a coin's exit date `sync_schedule` wakes the wallet at
/// least once a day: three days. A sync in each of those days finds the
/// coin once in its refresh window and once in its last day.
pub const SYNC_DAILY: u32 = 3 * 86_400;

/// How long after `sync` last asked for a coin's refresh it asks again,
/// once the operator refused, voided or let expire that refresh: six hours,
/// a quarter of the refresh window (from [`REFRESH_FROM`] to [`HOME_FROM`]
/// before the exit date), so that a refusal early in the window is asked
/// again in it, while the refresh is still free, before the coin goes home
/// at a cost of its exit's fees.
pub const REFUSED_AGAIN: u32 = (REFRESH_FROM - HOME_FROM) / 4;

/// Where the wallet keeps when `sync` last asked for each live coin's
/// refresh: `{leaf id: median time}`.
const REFRESH_ASKED: &str = "refresh_asked";

/// Where the wallet keeps when it handed out each receive request still
/// unpaid: `{owner nonce: median time}`.
pub(crate) const RECEIVE_ASKED: &str = "receive_asked";

/// Where the wallet keeps when each receive request still unpaid lapses, as
/// the request itself says (`until`): `{owner nonce: median time}`. A request
/// with no entry was handed out before requests carried their lapse, and
/// holds the schedule until it is paid or forgotten.
pub(crate) const RECEIVE_UNTIL: &str = "receive_until";

/// How long a receive request lasts, from the median time it was handed
/// out: the acceptance horizon, 27 days. The request carries the median time
/// it lapses at (`until`); a sender refuses to pay it from then, and until
/// then, while it is unpaid, it holds `sync`'s schedule at a day.
pub const REQUEST_HOLDS: u32 = WalletPolicy::DEFAULT_HORIZON;

/// How long `sync` keeps trying to reach the operator, with back-off, before
/// it takes it for unreachable: about a minute. One failed witness decides
/// nothing.
pub const WITNESS_PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// What the wallet says of every coin it holds off the chain: how `sync`
/// keeps it alive.
pub(crate) const SYNC_NOTE: &str = "sync keeps the coin alive by itself: from refresh_from (two days before its exit date, the free \
	window) it asks for the coin's refresh, and from home_from (a day before) it takes the coin on the chain unless the wallet holds \
	its new leaf, whatever stands in the way. Run {sync} at least once a day while the wallet holds a coin off the chain or waits \
	for a payment, whatever next_sync_at says; {exit} takes the coin now";

/// Why the wallet's schedule is a day at most while it waits for a payment.
pub(crate) const WAITING_NOTE: &str = "the wallet waits for a payment to a receive request it handed out: a coin paid to it is read \
	only by sync, and its sender may have paid with a coin days from its exit date, so sync runs at least once a day until it \
	comes";

/// What the wallet says of a coin it still holds off the chain once the
/// operator's signer is stopped.
pub(crate) const HOME_NOTE: &str = "the operator's signer is stopped: the coin can no longer be paid on or refreshed, and must be \
	exited by its exit date (exit_by, a median time); sync takes it on the chain when that date is within three days, and {exit} takes \
	it now";

/// What the wallet says of a coin it holds off the chain while the operator
/// cannot be reached: its witness fails, or the server does not answer or
/// refuses the wallet.
pub(crate) const UNREACHABLE_NOTE: &str = "the operator cannot be reached now: nothing is taken on the chain for that before the \
	coin's home_from (a day before its exit date, exit_by, median times); from then sync takes the coin on the chain unless its \
	refresh has completed. Run {sync} at least once a day while the wallet holds a coin off the chain; {exit} takes it now";

/// What the wallet says of a coin whose refresh the operator refused.
pub(crate) const REFUSED_NOTE: &str = "the operator refused the coin's last refresh: sync asks again six hours after it last \
	asked, while the coin is in its refresh window (from refresh_from, two days before its exit date, to home_from, a day before), \
	and from home_from takes the coin on the chain unless a refresh has completed; {exit} takes it now";

/// What the wallet says of a coin whose refresh expired at the server.
pub(crate) const EXPIRED_NOTE: &str = "the coin's last refresh expired at the server: its forfeits were not handed over and \
	co-signed by the later of a day after its round was final and the coin's exit date (the wallet did not sync in that time, or \
	the operator's signer or its keepers were away), so the new leaf was never released; sync asks again six hours after it last \
	asked, while the coin is in its refresh window (from refresh_from, two days before its exit date, to home_from, a day before), \
	and from home_from takes the coin on the chain unless a refresh has completed; {exit} takes it now";

/// What the wallet says of a coin whose last refresh ended as `p` says
/// ([`Wallet::refused_refreshes`]): expired, or refused.
pub(crate) fn refusal_note(spelling: &Spelling, p: &str) -> String {
	format!("{} (participation {})", spelling.say(if p.ends_with(" expired") { EXPIRED_NOTE } else { REFUSED_NOTE }), p)
}

/// What the wallet says of a coin whose exit needs a fee coin it does not
/// hold.
pub(crate) const FEE_COIN_MISSING: &str = "this coin cannot come home until the wallet holds an on-chain coin in an asset the node \
	accepts for fees (send one to {address}): its exit takes a fee coin, which the wallet chooses (the moved asset \
	first, where the node takes it)";

/// An asset the node takes for fees that the wallet holds on the chain: its
/// largest coin there, and the fee of 1,000 vbytes in it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FeeHolding {
	pub asset: AssetId,
	pub largest: u64,
	pub per_kvb: u64,
}

/// Why `sync` takes coins home (D57): it cannot have them refreshed.
pub(crate) enum Home {
	/// The operator's signer is stopped, on its own proof: every held coin
	/// within three days of its exit date.
	Stopped,
	/// The operator cannot be reached now, and why: every held coin whose
	/// refresh has not completed a day before its exit date, as below.
	Unreachable(String),
	/// The operator answers: every held coin whose refresh has not
	/// completed a day before its exit date, for whatever reason.
	Answering,
}

/// The dates of a coin held off the chain, median times: its exit date (its
/// exit deadline, three days before its first expiry, or before the service
/// expiry of a board it rests on), and from when `sync` must run daily, asks
/// for its refresh, and takes it home unless refreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinDates {
	pub sync_daily_from: u32,
	pub refresh_from: u32,
	pub home_from: u32,
	pub exit_by: u32,
}

impl CoinDates {
	/// The dates of a coin of service expiry `expiry`; none for one whose
	/// expiry is not known yet (a board not in a block).
	pub fn of(expiry: u32) -> Option<CoinDates> {
		if expiry == u32::MAX {
			return None;
		}
		let exit_by = expiry.saturating_sub(WalletPolicy::EXIT_DEADLINE);
		Some(CoinDates {
			sync_daily_from: exit_by.saturating_sub(SYNC_DAILY),
			refresh_from: exit_by.saturating_sub(REFRESH_FROM),
			home_from: exit_by.saturating_sub(HOME_FROM),
			exit_by,
		})
	}

	pub fn json(&self) -> Value {
		json!({"sync_daily_from": self.sync_daily_from, "refresh_from": self.refresh_from, "home_from": self.home_from,
			"exit_by": self.exit_by})
	}
}

/// Where the wallet keeps why the operator could not refresh its coins,
/// as `sync` last found it: `{"since": <median time>, "why"}`. The next
/// `sync` that finds the operator answering removes it: the wallet refuses
/// nothing for good on that ground.
const UNREACHABLE: &str = "operator_unreachable";

/// Where the wallet keeps a rollback of the operator's signer's record it
/// found: `{"at": <the highest entry the record still agrees with>, "why"}`.
const ROLLED_BACK: &str = "operator_rolled_back";

/// The states of a coin the wallet holds, or may still hold, off the chain.
const HELD: [&str; 6] = ["live", "pending", "sending", "offered", "given", "forfeited"];

fn parse<T: FromStr>(what: &str, s: &str) -> Result<T, Error> where T::Err: std::fmt::Display {
	s.parse::<T>().map_err(|e| Error::Parse(format!("{} {:?}: {}", what, s, e)))
}

pub(crate) fn amount(v: &Value, what: &str) -> Result<u64, Error> {
	parse(what, v.as_str().ok_or_else(|| Error::Parse(format!("{} is missing", what)))?)
}

/// How many times the node's relay floor every reserve on a new leaf's path
/// holds, when the node accepts the leaf's asset for fees: the
/// specification's cover for a fourfold rise in the floor.
pub const RESERVE_MULTIPLE: u64 = 4;

/// The least reserve the wallet accepts on a new leaf's path, given the
/// node's relay floor in the leaf's asset (`None` when the node does not
/// accept the asset for fees).
pub fn reserve_floor(floor_per_kvb: Option<u64>) -> arca_covenant::ReserveFloor {
	match floor_per_kvb {
		Some(f) => arca_covenant::ReserveFloor::FeeRate { floor_per_kvb: f, multiple: RESERVE_MULTIPLE },
		None => arca_covenant::ReserveFloor::Atoms(1),
	}
}

/// A coin record's kind, as the store names it.
pub(crate) fn kind_of(record: &CoinRecord) -> &'static str {
	match record {
		CoinRecord::Leaf { .. } => "batch",
		CoinRecord::Transfer(_) => "transfer",
		CoinRecord::Board(_) => "board",
	}
}

/// The owner key and nonce a coin record names for its coin.
pub(crate) fn owner_of(record: &CoinRecord) -> (XOnlyPublicKey, [u8; 32]) {
	match record {
		CoinRecord::Leaf { record, .. } => (record.owner, record.owner_nonce),
		CoinRecord::Transfer(t) => (t.leaf.owner, t.leaf.owner_nonce),
		CoinRecord::Board(b) => (b.owner, b.owner_nonce),
	}
}

/// Every output a coin rests on: the batch output of each batch leaf and each
/// board output in its record, from the coin up.
fn base_outputs(record: &CoinRecord, out: &mut Vec<TxOut>) -> Result<(), Error> {
	match record {
		CoinRecord::Leaf { record, .. } => {
			out.push(record.branch().map_err(|e| Error::Refused(e.to_string()))?.batch_output().txout());
		},
		CoinRecord::Board(b) => out.push(b.output().txout()),
		CoinRecord::Transfer(t) => {
			for i in &t.inputs {
				base_outputs(&i.coin, out)?;
			}
		},
	}
	Ok(())
}

/// How long the operator serves a board, and every coin resting on it, from
/// the median time of the block that confirms the board: a batch's lifetime,
/// 28 days, so a board carries the dates a batch made then would have
/// (`info.boards`). Its exit deadline is three days before
/// ([`WalletPolicy::EXIT_DEADLINE`]): up to it the operator co-signs spends
/// of a coin resting on the board and takes it into a refresh; after it, the
/// wallet takes the coin on the chain; from the expiry the operator may bring
/// the coin's lineage on the chain.
pub const BOARD_LIFETIME: u32 = 28 * 86_400;

/// Whether `record`'s lineage holds a board.
pub(crate) fn rests_on_board(record: &CoinRecord) -> bool {
	match record {
		CoinRecord::Board(_) => true,
		CoinRecord::Leaf { .. } => false,
		CoinRecord::Transfer(t) => t.inputs.iter().any(|i| rests_on_board(&i.coin)),
	}
}

/// What the re-check finds of one coin.
enum Checked {
	/// It holds, in this state, with this note.
	Holds(&'static str, String),
	/// A base the chain holds fails the wallet's checks, for this reason.
	Fails(String),
	/// A base is out of the chain while an input of it is spent by another
	/// transaction that is final; it returns only if the parent chain takes
	/// that one out.
	Lost(Txid),
}

/// A coin the wallet has checked against the chain.
pub(crate) struct Assessed {
	pub valid: ValidCoin,
	/// The rounds and boards it rests on, with where each stands.
	pub bases: Vec<(Transaction, Finality)>,
}

impl Assessed {
	pub fn all_final(&self) -> bool {
		self.bases.iter().all(|(_, f)| f.is_final())
	}

	/// Why the coin is not spendable yet, for people; empty when it is.
	pub fn waiting(&self) -> String {
		self.bases.iter().filter(|(_, f)| !f.is_final())
			.map(|(t, f)| format!("{} is {}", t.txid(), f.word())).collect::<Vec<_>>().join("; ")
	}

	pub fn lowest_height(&self) -> u64 {
		self.bases.iter().filter_map(|(_, f)| f.height()).min().unwrap_or(0)
	}
}

impl Wallet {
	// -----------------------------------------------------------------------
	// Creating and opening
	// -----------------------------------------------------------------------

	/// Creates a wallet in `datadir`: a new mnemonic unless one is given, the
	/// node's chain, and the server's operator key, pinned. Refuses a node that
	/// does not validate its anchors, and a server on another chain.
	pub fn create(datadir: &Path, mnemonic: Option<&str>, cfg: Config) -> Result<Wallet, Error> {
		if datadir.join(DB_FILE).exists() {
			return Err(Error::Refused(format!("{} already holds a wallet", datadir.display())));
		}
		std::fs::create_dir_all(datadir).map_err(|e| Error::Io(format!("{}: {}", datadir.display(), e)))?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let _ = std::fs::set_permissions(datadir, std::fs::Permissions::from_mode(0o700));
		}
		let mnemonic = match mnemonic {
			Some(m) => bip39::Mnemonic::from_str(m).map_err(|e| Error::Parse(format!("the mnemonic: {}", e)))?,
			None => bip39::Mnemonic::generate(12).map_err(|e| Error::Keys(e.to_string()))?,
		};
		let pins = Self::pins(&cfg)?;
		write_private(&datadir.join(MNEMONIC_FILE), &mnemonic.to_string())?;
		if let Some(p) = &cfg.node_password {
			write_private(&datadir.join(NODE_PASSWORD_FILE), p)?;
		}
		let store = Store::open(&datadir.join(DB_FILE))?;
		set_private(&datadir.join(DB_FILE))?;
		Self::write_pins(&store, &cfg, pins)?;
		drop(store);
		Wallet::open(datadir)
	}

	/// Creates a wallet in a store the program opened itself, with no
	/// directory and no file: a browser worker's, whose page holds the
	/// mnemonic and hands it over on every open ([`Wallet::open_in`]). The
	/// checks are those of [`Wallet::create`]. The store keeps no mnemonic,
	/// only the wallet's mailbox key, so that an open with another mnemonic
	/// is refused.
	pub fn create_in(store: Store, mnemonic: &str, cfg: Config) -> Result<Wallet, Error> {
		if store.meta("genesis")?.is_some() {
			return Err(Error::Refused("this store already holds a wallet".into()));
		}
		let mnemonic = bip39::Mnemonic::from_str(mnemonic).map_err(|e| Error::Parse(format!("the mnemonic: {}", e)))?.to_string();
		let pins = Self::pins(&cfg)?;
		let coin_type = if pins.chain_name == "sequentia" { 0 } else { 1 };
		let keys = Keys::new(&mnemonic, cfg.account, coin_type)?;
		let node_password = cfg.node_password.clone();
		Self::write_pins(&store, &cfg, pins)?;
		store.set_meta("mailbox_key", &keys.mailbox()?.x_only_public_key().0.to_string())?;
		Wallet::open_in(store, &mnemonic, node_password)
	}

	/// What [`Wallet::create`] pins, read from the node and the server.
	fn pins(cfg: &Config) -> Result<Pins, Error> {
		let chain = ChainSource::new(&cfg.node_url, cfg.node_user.as_deref(), cfg.node_password.as_deref(), cfg.node_cookie.as_deref());
		if !chain.validates_anchors()? {
			return Err(Error::Refused("the node does not validate its anchors against the parent chain (-validateanchor): \
				without that it has no notion of finality".into()));
		}
		let genesis = chain.genesis()?;
		let chain_name = chain.chain_name()?;
		let server = ServerClient::new(&cfg.server)?;
		let info = server.info()?;
		let server_genesis = info["genesis_hash"].as_str().unwrap_or("");
		if server_genesis != genesis.to_string() {
			return Err(Error::Refused(format!("the server serves the chain of genesis {}; the node is on {}", server_genesis, genesis)));
		}
		let operator: XOnlyPublicKey = parse("the operator key", info["operator"].as_str().unwrap_or(""))?;
		for (what, d) in [("asked", cfg.exit_delay_units), ("least", cfg.min_exit_delay_units), ("most", cfg.max_exit_delay_units)] {
			RelativeTime::from_units(d).map_err(|e| Error::Refused(format!("the {} exit delay: {}", what, e)))?;
		}
		if !(cfg.min_exit_delay_units..=cfg.max_exit_delay_units).contains(&cfg.exit_delay_units) {
			return Err(Error::Refused("the exit delay asked for is outside the bounds the wallet accepts".into()));
		}
		let keepers = Self::keepers_of(&info)?.to_string();
		let tip = chain.tip()?;
		Ok(Pins { genesis: genesis.to_string(), chain_name, operator: operator.to_string(), keepers, tip_height: tip.height, tip_hash: tip.hash.to_string() })
	}

	fn write_pins(store: &Store, cfg: &Config, pins: Pins) -> Result<(), Error> {
		let meta = [
			("server", cfg.server.clone()), ("node_url", cfg.node_url.clone()),
			("node_user", cfg.node_user.clone().unwrap_or_default()),
			("node_cookie", cfg.node_cookie.clone().unwrap_or_default()),
			("account", cfg.account.to_string()), ("exit_delay_units", cfg.exit_delay_units.to_string()),
			("min_exit_delay_units", cfg.min_exit_delay_units.to_string()), ("max_exit_delay_units", cfg.max_exit_delay_units.to_string()),
			("genesis", pins.genesis), ("chain_name", pins.chain_name), ("operator", pins.operator),
			("keepers", pins.keepers),
			("birthday", pins.tip_height.to_string()), ("tip_height", pins.tip_height.to_string()), ("tip_hash", pins.tip_hash),
		];
		for (k, v) in meta {
			store.set_meta(k, &v)?;
		}
		Ok(())
	}

	/// Opens the wallet in `datadir`. Contacts neither node nor server.
	pub fn open(datadir: &Path) -> Result<Wallet, Error> {
		let db = datadir.join(DB_FILE);
		if !db.exists() {
			return Err(Error::Refused(format!("{} holds no wallet; create one first", datadir.display())));
		}
		let store = Store::open(&db)?;
		set_private(&db)?;
		// The node's password, from its own file; a store that still holds it
		// gives it up to that file.
		let password_file = datadir.join(NODE_PASSWORD_FILE);
		if let Some(p) = store.meta("node_password")?.filter(|v| !v.is_empty()) {
			write_private(&password_file, &p)?;
			store.set_meta("node_password", "")?;
		}
		let node_password = match std::fs::read_to_string(&password_file) {
			Ok(p) => Some(p.trim_end_matches(['\r', '\n']).to_string()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
			Err(e) => return Err(Error::Io(format!("{}: {}", password_file.display(), e))),
		};
		let mnemonic = std::fs::read_to_string(datadir.join(MNEMONIC_FILE))
			.map_err(|e| Error::Io(format!("{}: {}", datadir.join(MNEMONIC_FILE).display(), e)))?;
		Self::assemble(datadir.to_path_buf(), store, mnemonic.trim(), node_password)
	}

	/// Opens the wallet a store holds ([`Wallet::create_in`]), with the
	/// mnemonic the program holds and the node's password, if the node needs
	/// one. Refuses a store that holds no wallet, and a mnemonic whose
	/// mailbox key is not the one the store was made with. Contacts neither
	/// node nor server.
	pub fn open_in(store: Store, mnemonic: &str, node_password: Option<String>) -> Result<Wallet, Error> {
		if store.meta("genesis")?.is_none() {
			return Err(Error::Refused("this store holds no wallet; create one first".into()));
		}
		let w = Self::assemble(PathBuf::new(), store, mnemonic.trim(), node_password)?;
		match w.store.meta("mailbox_key")? {
			Some(k) if k == w.keys.mailbox()?.x_only_public_key().0.to_string() => Ok(w),
			Some(_) => Err(Error::Refused("this store holds the wallet of another mnemonic".into())),
			None => Err(Error::Refused("this store names no mailbox key, so it cannot tell whether the mnemonic is its own".into())),
		}
	}

	/// The wallet over an open store, its keys from `mnemonic`.
	fn assemble(datadir: PathBuf, store: Store, mnemonic: &str, node_password: Option<String>) -> Result<Wallet, Error> {
		let get = |k: &str| -> Result<String, Error> { store.meta(k)?.ok_or_else(|| Error::Store(format!("{} is not set", k))) };
		let opt = |k: &str| -> Result<Option<String>, Error> { Ok(store.meta(k)?.filter(|v| !v.is_empty())) };
		let cfg = Config {
			server: get("server")?, node_url: get("node_url")?,
			node_user: opt("node_user")?, node_password, node_cookie: opt("node_cookie")?,
			account: parse("account", &get("account")?)?,
			exit_delay_units: parse("exit delay", &get("exit_delay_units")?)?,
			min_exit_delay_units: parse("exit delay", &get("min_exit_delay_units")?)?,
			max_exit_delay_units: parse("exit delay", &get("max_exit_delay_units")?)?,
		};
		let genesis = Chain::new(parse("the genesis hash", &get("genesis")?)?);
		let operator = parse("the operator key", &get("operator")?)?;
		let coin_type = if get("chain_name")? == "sequentia" { 0 } else { 1 };
		let keys = Keys::new(mnemonic, cfg.account, coin_type)?;
		let chain = ChainSource::new(&cfg.node_url, cfg.node_user.as_deref(), cfg.node_password.as_deref(), cfg.node_cookie.as_deref());
		let server = ServerClient::new(&cfg.server)?;
		Ok(Wallet { datadir, store, keys, chain, server, genesis, operator, cfg, secp: Secp256k1::new(),
			witnessed: std::cell::RefCell::new(None), witness_patience: WITNESS_PATIENCE, change_in_flight: Default::default(),
			spelling: Spelling::default() })
	}

	/// Spells what the wallet says from now on as `s` says ([`Spelling`]).
	pub fn spell(&mut self, s: Spelling) {
		self.spelling = s;
	}

	pub fn mnemonic_path(&self) -> PathBuf {
		self.datadir.join(MNEMONIC_FILE)
	}

	// -----------------------------------------------------------------------
	// Policies
	// -----------------------------------------------------------------------

	/// The chain's median time at the tip: what the wallet takes as now.
	pub(crate) fn now(&self) -> Result<MedianTime, Error> {
		MedianTime::from_consensus(self.chain.tip()?.median_time).map_err(|e| Error::Node(e.to_string()))
	}

	fn delay(units: u16) -> RelativeTime {
		RelativeTime::from_units(units).expect("checked when the wallet was created")
	}

	pub(crate) fn exit_delay(&self) -> RelativeTime {
		Self::delay(self.cfg.exit_delay_units)
	}

	/// The policy for accepting a leaf from a round, at `now`.
	pub(crate) fn accept_policy(&self, now: MedianTime) -> WalletPolicy {
		WalletPolicy {
			min_exit_delay: Self::delay(self.cfg.min_exit_delay_units),
			max_exit_delay: Self::delay(self.cfg.max_exit_delay_units),
			..WalletPolicy::new(self.genesis, self.operator, now)
		}
	}

	/// The policy for accepting a leaf of `asset` from a round, at `now`,
	/// and whether every exit of it will need a fee coin: its reserves must
	/// cover [`RESERVE_MULTIPLE`] times the node's relay floor in `asset`
	/// when the node accepts `asset` for fees, so the leaf's own value pays
	/// its way out; where the node does not accept it, one atom, the
	/// operator's own rule, and each transaction of an exit then takes a fee
	/// coin in an accepted asset.
	pub(crate) fn leaf_policy(&self, asset: AssetId, now: MedianTime) -> Result<(WalletPolicy, bool), Error> {
		let floor = self.chain.floor_per_kvb(asset)?;
		Ok((WalletPolicy { min_reserve: reserve_floor(floor), ..self.accept_policy(now) }, floor.is_none()))
	}

	/// The policy for a coin held or received out of round, at `now`.
	pub(crate) fn receipt_policy(&self, now: MedianTime) -> WalletPolicy {
		self.accept_policy(now).receipt()
	}

	/// The policy for a coin the wallet holds, looked at again on the way
	/// to what the chain decides of it, at `now`; `expiry` is the coin's
	/// first expiry, or a board's service expiry where that comes first.
	/// The coin is the one the wallet accepted, checked with no horizon, as
	/// of now or, once its expiry has passed, as of that expiry. A coin is
	/// followed past its expiry by design (its exit, its forfeit until a
	/// spend of the forfeit's output is final, its re-check after a
	/// rollback, however deep), and what decides it then is the chain, not
	/// the date: checked as of now, it would be refused the moment the
	/// median time passed its expiry, and whatever the chain still holds of
	/// it would go to the operator.
	pub(crate) fn followed_policy(&self, expiry: u32, now: MedianTime) -> WalletPolicy {
		let as_of = match MedianTime::from_consensus(expiry) {
			Ok(e) if expiry != u32::MAX && e < now => e,
			_ => now,
		};
		WalletPolicy { horizon: 0, ..self.receipt_policy(as_of) }
	}

	/// The server's `info`, checked against what the wallet pinned when it was
	/// created: the same chain and the same operator key; and the head of
	/// its signer's record it shows, signed, against every head the wallet
	/// holds. An operator whose record the wallet found rolled back is
	/// refused, and so is one whose record the wallet could not witness
	/// within [`WITNESS_FOR`] ([`Self::witnessed_now`]): every entry point
	/// that reads `info` before it takes a coin or signs a spend witnesses
	/// the record first.
	pub(crate) fn server_info(&self) -> Result<Value, Error> {
		if let Some((at, why)) = self.rolled_back()? {
			return Err(Error::Refused(format!("the operator's signer's record was rolled back or replaced past entry {} ({}): the wallet \
				goes no further with this operator, and takes on the chain every coin resting on what it signed after", at, why)));
		}
		self.witnessed_now()?;
		let info = self.server.info()?;
		if let Some(l) = info["boards"]["lifetime_seconds"].as_u64() {
			if l < BOARD_LIFETIME as u64 {
				return Err(Error::Refused(format!("the server serves a board for {} s from its confirmation; this wallet counts on {} s, \
					and would show dates the operator does not keep", l, BOARD_LIFETIME)));
			}
		}
		if info["genesis_hash"].as_str() != Some(&self.genesis.genesis_hash().to_string()) {
			return Err(Error::Refused(format!("the server now serves the chain of genesis {}; this wallet is on {}",
				info["genesis_hash"], self.genesis.genesis_hash())));
		}
		if info["operator"].as_str() != Some(&self.operator.to_string()) {
			return Err(Error::Refused(format!("the server now names operator key {}; this wallet was created with {}",
				info["operator"], self.operator)));
		}
		// The keepers are part of the operator's identity, fixed in its
		// signer's record when it is made: the wallet pins them as it pins the
		// operator key, and an operator showing others is not the one it
		// pinned. A wallet made before keepers existed pins them here, from
		// the first `info` it reads; such an operator never gains any.
		match self.store.meta("keepers")? {
			None if !info["keepers"].is_null() => self.store.set_meta("keepers", &Self::keepers_of(&info)?.to_string())?,
			None => {},
			Some(pinned) => {
				let shown = match info["keepers"].is_null() {
					true => json!({"keys": [], "required": 0}),
					false => Self::keepers_of(&info)?,
				};
				let pinned: Value = serde_json::from_str(&pinned).map_err(|e| Error::Store(format!("keepers: {}", e)))?;
				if shown != pinned {
					return Err(Error::Refused(format!("the server now names the keepers {}; this wallet was created with {}: the keepers \
						are part of the operator's identity, fixed when its signer's record was made", shown, pinned)));
				}
			},
		}
		self.witness_record(&info["signer_record"], true)?;
		Ok(info)
	}

	/// The keepers `info` names, checked, as the wallet pins them:
	/// `{"keys": […], "required": n}`, no keys and 0 for an operator with no
	/// keeper.
	fn keepers_of(info: &Value) -> Result<Value, Error> {
		let k = &info["keepers"];
		let mut keys = vec![];
		for x in k["keys"].as_array().cloned().unwrap_or_default() {
			let key: XOnlyPublicKey = parse("a keeper's key", x.as_str().unwrap_or(""))?;
			if keys.contains(&key.to_string()) {
				return Err(Error::Refused(format!("the server names the keeper {} twice", key)));
			}
			keys.push(key.to_string());
		}
		let required = k["required"].as_u64().unwrap_or(0) as usize;
		if (keys.is_empty() && required != 0) || (!keys.is_empty() && !(1..=keys.len()).contains(&required)) {
			return Err(Error::Refused(format!("the server names {} keeper(s), {} of them required", keys.len(), required)));
		}
		Ok(json!({"keys": keys, "required": required}))
	}

	/// The keepers of the operator's signer's record the wallet pinned when
	/// it was created, and how many must hold a head; none for an operator
	/// with no keeper. A wallet made before keepers existed pins them from
	/// the first `info` it reads, as it pinned the operator key then.
	pub(crate) fn keepers(&self) -> Result<(Vec<XOnlyPublicKey>, usize), Error> {
		let v: Value = match self.store.meta("keepers")? {
			Some(v) => serde_json::from_str(&v).map_err(|e| Error::Store(format!("keepers: {}", e)))?,
			None => return Ok((vec![], 0)),
		};
		let keys = v["keys"].as_array().cloned().unwrap_or_default().iter()
			.map(|k| parse("a keeper's key", k.as_str().unwrap_or(""))).collect::<Result<Vec<XOnlyPublicKey>, _>>()?;
		Ok((keys, v["required"].as_u64().unwrap_or(0) as usize))
	}

	/// Whether `head` (`{entry, hash, signature, acks}`) is held outside the
	/// operator's machine as the wallet requires: acknowledged by as many of
	/// the keepers it pinned as must hold a head, each acknowledgement the
	/// keeper's signature over the head ([`super::client::keeper_ack_digest`]).
	/// Always, for an operator with no keeper.
	pub(crate) fn held_outside(&self, head: &Value) -> Result<(), String> {
		let (keys, required) = self.keepers().map_err(|e| e.to_string())?;
		if keys.is_empty() {
			return Ok(());
		}
		let (Some(entry), Some(hash)) = (head["entry"].as_u64(), head["hash"].as_str().and_then(|h| unhex32(h).ok())) else {
			return Err("no head of the operator's signer's record comes with it".into());
		};
		let acks = head["acks"].as_array().cloned().unwrap_or_default();
		let held = keys.iter().filter(|k| acks.iter().any(|a| {
			a["key"].as_str() == Some(&hex(&k.serialize()))
				&& unhex32(a["nonce"].as_str().unwrap_or("")).ok()
					.zip(unhex(a["signature"].as_str().unwrap_or("")).ok().and_then(|b| elements::secp256k1_zkp::schnorr::Signature::from_slice(&b).ok()))
					.is_some_and(|(n, s)| arca_covenant::sign::verify_digest(&s, &super::client::keeper_ack_digest(&self.genesis, &self.operator,
						entry, &hash, &n), k))
		})).count();
		if held < required {
			return Err(format!("entry {} of the operator's signer's record comes with {} of the {} acknowledgements of its keepers the \
				wallet requires: it is not held outside the operator's machine", entry, held, required));
		}
		Ok(())
	}

	/// The rollback of the operator's signer's record the wallet found on
	/// the signer's own proof, if it found one: the highest entry the record
	/// still agreed with, and why. A note an older version of the wallet kept
	/// without that proof is not acted on: the next witness that succeeds
	/// checks it against the signer and drops it unless the signer proves it.
	pub(crate) fn rolled_back(&self) -> Result<Option<(u64, String)>, Error> {
		Ok(self.store.meta(ROLLED_BACK)?.and_then(|v| serde_json::from_str::<Value>(&v).ok())
			.filter(|v| v["proven"] == json!(true))
			.map(|v| (v["at"].as_u64().unwrap_or(0), v["why"].as_str().unwrap_or("").to_string())))
	}

	/// Drops a rollback note kept without the signer's proof, once a witness
	/// found the record agreeing with the wallet: the signer proved nothing.
	fn drop_unproven_rollback(&self) -> Result<(), Error> {
		let Some(note) = self.store.meta(ROLLED_BACK)? else { return Ok(()) };
		if serde_json::from_str::<Value>(&note).ok().is_some_and(|v| v["proven"] == json!(true)) {
			return Ok(());
		}
		self.store.delete_meta(ROLLED_BACK)?;
		self.store.refused("the operator's signer's record", &format!("a rollback note an older version of the wallet kept without the \
			signer's proof ({}) was checked against the signer, whose witness proves no rollback: dropped, nothing refused for it", note))
	}

	/// Keeps the rollback found, `why`, the record agreeing with the wallet
	/// up to entry `at`: the lowest such entry found stands.
	fn found_rollback(&self, at: u64, why: &str) -> Result<(), Error> {
		let prior = self.rolled_back()?;
		let at = prior.as_ref().map_or(at, |(was, _)| (*was).min(at));
		if prior.is_some_and(|(was, w)| was == at && w == why) {
			return Ok(());
		}
		self.store.set_meta(ROLLED_BACK, &json!({"at": at, "why": why, "proven": true}).to_string())?;
		self.store.refused("the operator's signer's record", why)
	}

	/// Whether `sig` (hex) is `S`'s signature over the head `entry`, `hash` of
	/// its signer's record ([`super::client::record_head_digest`]).
	pub(crate) fn head_signed(&self, entry: u64, hash: &str, sig: Option<&str>) -> bool {
		let Some(sig) = sig else { return false };
		unhex32(hash).ok().zip(unhex(sig).ok().and_then(|b| elements::secp256k1_zkp::schnorr::Signature::from_slice(&b).ok()))
			.is_some_and(|(h, s)| arca_covenant::sign::verify_digest(&s, &super::client::record_head_digest(&self.genesis, entry, &h), &self.operator))
	}

	/// Whether `sig` (hex) is `S`'s signature over its record's end, entry
	/// `entry` with the running hash `hash`, together with `nonce`
	/// ([`super::client::record_end_digest`]).
	fn end_signed(&self, entry: u64, hash: &str, sig: Option<&str>, nonce: &[u8; 32]) -> bool {
		let Some(sig) = sig else { return false };
		unhex32(hash).ok().zip(unhex(sig).ok().and_then(|b| elements::secp256k1_zkp::schnorr::Signature::from_slice(&b).ok()))
			.is_some_and(|(h, s)| arca_covenant::sign::verify_digest(&s, &super::client::record_end_digest(&self.genesis, entry, &h, nonce),
				&self.operator))
	}

	/// Checks a head of the operator's signer's record it shows,
	/// `{entry, hash, signature}` (the latest, in `info`, when `latest`; a
	/// round's, in its published tree, or a transfer's, with the coins it
	/// made, otherwise). The wallet acts on a rollback only on proof the
	/// signer made: another running hash at an entry the wallet holds is one
	/// when `S` signed both, since `S` signs only what its record holds; the
	/// rollback is kept, the coins resting on what was signed after it are
	/// taken on the chain at the wallet's next witness ([`Self::witness`]),
	/// and the wallet goes no further with the operator. Anything else that
	/// does not fit is no proof, and the server is taken for unreachable
	/// ([`Error::Unreachable`]): a signature that is not `S`'s, another hash
	/// where one of the two is unsigned, or a latest entry below the highest
	/// the wallet holds, which a head handed out without the wallet's nonce
	/// does not prove (an older head replayed shows that much). A signed
	/// head is kept; one without a signature (a round's tree from before
	/// heads were signed) only compared.
	pub(crate) fn witness_record(&self, shown: &Value, latest: bool) -> Result<(), Error> {
		let (Some(entry), Some(hash)) = (shown["entry"].as_u64(), shown["hash"].as_str()) else { return Ok(()) };
		let signature = shown["signature"].as_str();
		let signed = self.head_signed(entry, hash, signature);
		if signature.is_some() && !signed {
			let why = format!("the operator shows entry {} of its signer's record with a signature that is not its signer's: the \
				wallet takes nothing from it, and holds the server unreachable until a witness succeeds", entry);
			self.store.refused("the operator's signer's record", &why)?;
			return Err(Error::Unreachable(why));
		}
		if let Some((seen, seen_sig)) = self.store.seen_at(entry)? {
			if seen != hash {
				if signed && self.head_signed(entry, &seen, seen_sig.as_deref()) {
					let why = format!("the operator's signer signed entry {} of its record with the running hash {}, and signed {} for that \
						entry before: its record has been replaced or rolled back, with its database, so it may sign again what it signed; \
						the wallet goes no further with this operator", entry, hash, seen);
					self.found_rollback(entry.saturating_sub(1), &why)?;
					return Err(Error::Refused(why));
				}
				return Err(Error::Unreachable(format!("the operator shows entry {} of its signer's record with the running hash {}, and \
					showed {} for that entry before, one of them without the signer's signature: no proof of a rollback; the wallet takes \
					nothing from it until a witness succeeds", entry, hash, seen)));
			}
		}
		if latest {
			if let Some((top, _)) = self.store.seen_latest()? {
				if entry < top {
					return Err(Error::Unreachable(format!("the operator shows its signer's record ending at entry {}, below entry {} the \
						wallet holds: a head handed out without the wallet's nonce may be an older one replayed, so this proves no rollback; \
						the wallet takes nothing from the operator until a witness succeeds", entry, top)));
				}
			}
		}
		// A head is kept only once it is held outside the operator's machine
		// as the wallet requires; one that is not is compared, not kept.
		if signed && self.held_outside(shown).is_ok() {
			self.store.put_seen(entry, hash, signature)?;
		}
		Ok(())
	}

	/// Keeps the head of the signer's record the transfer that made coin
	/// `leaf_id` was recorded at (`{entry, hash, signature}`, from the
	/// transfer's answer or the coin's mailbox message), and the coin's entry
	/// with it. A head missing or not the signer's leaves the coin's entry
	/// unknown, which a rollback counts as after every entry.
	pub(crate) fn keep_coin_head(&self, leaf_id: &str, head: &Value) -> Result<(), Error> {
		if head["signature"].as_str().is_none() {
			return Ok(());
		}
		self.witness_record(head, false)?;
		if let Some(entry) = head["entry"].as_u64() {
			self.store.put_coin_entry(leaf_id, entry)?;
		}
		Ok(())
	}

	/// Witnesses the operator's signer's record, once a command: hands the
	/// server the highest head the wallet holds, the heads its coins were
	/// recorded at, and as many more as fit in [`MAX_WITNESS`], with a nonce
	/// drawn fresh for the call, and checks what comes back, each part signed
	/// by the signer ([`Self::judge_witness`]): the running hash the record
	/// holds at each entry, its latest entry, and its end signed together
	/// with the nonce. Each signed head the wallet hands over that the record
	/// does not hold stops the signer. A rollback is acted on only on proof
	/// the signer made: another hash the signer signed at an entry the wallet
	/// holds signed, a record that ends, signed with this call's nonce, before
	/// such an entry, or a stopped signer's own proof (a head it signed and
	/// the head its record holds there, signed, or its end before it). The
	/// wallet then finds the highest entry it holds that the record still
	/// agrees with, and takes on the chain at once every coin it holds that a
	/// transfer recorded after it made (a coin whose entry it was never given
	/// counts as after); its own leaves and boards, which no transfer made,
	/// stay. It goes no further with the operator after that, and says why.
	/// An answer without that proof, or with a part the signer did not sign,
	/// is an unreachable server ([`Error::Unreachable`]): the wallet exits
	/// nothing and refuses nothing for good, and tries again.
	pub fn witness(&mut self) -> Result<Value, Error> {
		if let Some((at, v)) = self.witnessed.borrow().as_ref() {
			if at.elapsed() < WITNESS_FOR {
				return Ok(v.clone());
			}
		}
		let mut v = self.witness_check()?;
		if let Some(at) = v["rolled_back"]["at"].as_u64() {
			let why = v["rolled_back"]["why"].as_str().unwrap_or("").to_string();
			v["exits"] = json!(self.exit_after(at, &why)?);
			*self.witnessed.borrow_mut() = Some((web_time::Instant::now(), v.clone()));
		}
		Ok(v)
	}

	/// Refuses unless a witness of the operator's signer's record succeeded
	/// within [`WITNESS_FOR`], running one when none did: what every entry
	/// point that takes a coin or signs a spend through the operator runs
	/// first (`send`, `participate`, `board`, the swap calls, `sync`'s work
	/// with the server, `mailbox`), so a client built on the library cannot
	/// forget it. A witness that fails is an unreachable server; one that
	/// finds a rollback refuses, and the wallet's next [`Self::witness`] takes
	/// the coins resting on what was lost on the chain.
	pub(crate) fn witnessed_now(&self) -> Result<(), Error> {
		let v = self.witness_check()?;
		match v["rolled_back"]["at"].as_u64() {
			Some(at) => Err(Error::Refused(format!("the operator's signer's record was rolled back or replaced past entry {} ({}): the \
				wallet goes no further with this operator, and takes on the chain every coin resting on what it signed after", at,
				v["rolled_back"]["why"].as_str().unwrap_or("")))),
			None => Ok(()),
		}
	}

	/// The witness itself ([`Self::witness`]), without acting on a
	/// rollback: what the record agrees with (kept for [`WITNESS_FOR`]), or
	/// the rollback found, now or before (kept in the store), its exits not
	/// yet made.
	fn witness_check(&self) -> Result<Value, Error> {
		if let Some((at, v)) = self.witnessed.borrow().as_ref() {
			if at.elapsed() < WITNESS_FOR {
				return Ok(v.clone());
			}
		}
		let held = self.store.seen_heads()?;
		let mut ask: Vec<(u64, String, Option<String>)> = vec![];
		// The signer answers few heads without its signature, which prove
		// nothing; the wallet names few.
		let add = |h: &(u64, String, Option<String>), ask: &mut Vec<(u64, String, Option<String>)>| {
			let unsigned = ask.iter().filter(|a| a.2.is_none()).count();
			if ask.len() < MAX_WITNESS && !ask.iter().any(|a| a.0 == h.0) && (h.2.is_some() || unsigned < MAX_UNSIGNED_WITNESS) {
				ask.push(h.clone());
			}
		};
		if let Some(top) = held.first() {
			add(top, &mut ask);
		}
		for c in self.store.coins()? {
			if c.kind != "transfer" || !HELD.contains(&c.state.as_str()) {
				continue;
			}
			if let Some(e) = self.store.coin_entry(&c.leaf_id)? {
				if let Some(h) = held.iter().find(|h| h.0 == e) {
					add(h, &mut ask);
				}
			}
		}
		for h in &held {
			add(h, &mut ask);
		}
		let heads: Vec<Value> = ask.iter().map(|(e, h, s)| {
			let mut v = json!({"entry": e, "hash": h});
			if let Some(s) = s {
				v["signature"] = json!(s);
			}
			v
		}).collect();
		let nonce = super::random32();
		let prior = self.rolled_back()?;
		let answer = self.server.witness(&heads, &nonce).and_then(|a| {
			let top = held.first().map(|h| h.0).unwrap_or(0);
			self.judge_witness(&ask, &a, &nonce, top).map(|j| (a, j)).map_err(|why| Error::Unreachable(format!(
				"the operator's witness answer carries no proof the signer made: {}; the wallet exits nothing and refuses nothing for \
				it, takes no coin and signs no spend until a witness succeeds", why)))
		});
		let (answer, judged) = match answer {
			Ok(a) => a,
			Err(e) => {
				// A rollback found before is acted on whatever the server says.
				if let Some((at, why)) = prior {
					return Ok(json!({"rolled_back": {"at": at, "why": why}, "server": e.to_string()}));
				}
				return Err(e);
			},
		};
		if judged.is_none() && prior.is_none() {
			self.drop_unproven_rollback()?;
			if !answer["head"].is_null() {
				self.witness_record(&answer["head"], false)?;
			}
			let v = json!({"witnessed": ask.len(), "record": answer["head"]});
			*self.witnessed.borrow_mut() = Some((web_time::Instant::now(), v.clone()));
			return Ok(v);
		}
		if let Some((at, why)) = judged {
			self.found_rollback(at, &why)?;
		}
		let (at, why) = self.rolled_back()?.expect("a rollback kept");
		Ok(json!({"rolled_back": {"at": at, "why": why},
			"note": "the operator's signer's record was rolled back or replaced: the wallet takes on the chain every coin a transfer \
			recorded after the entry it last agrees with made, and goes no further with this operator"}))
	}

	/// Judges a witness answer to the heads `ask` (the wallet's, `top` the
	/// highest it holds) and `nonce`: `Ok(None)` when the record agrees,
	/// `Ok(Some((at, why)))` on proof the signer made of a rollback, the
	/// record agreeing with the wallet up to entry `at`, and `Err(why)` when
	/// the answer is not the signer's, or claims what the signer did not
	/// sign. Every part is checked against `S`: the record's end, signed
	/// with `nonce`; the latest head, when shown, that same end, signed; the
	/// running hash at each entry named, in order, signed; and a stop, with
	/// its proof.
	fn judge_witness(&self, ask: &[(u64, String, Option<String>)], answer: &Value, nonce: &[u8; 32], top: u64)
		-> Result<Option<(u64, String)>, String>
	{
		let end = &answer["end"];
		let (Some(end_n), Some(end_h)) = (end["entry"].as_u64(), end["hash"].as_str()) else {
			return Err("it shows no end of the record signed with the wallet's nonce".into());
		};
		if !self.end_signed(end_n, end_h, end["signature"].as_str(), nonce) {
			return Err(format!("the record's end it shows, entry {}, is not signed by the signer with the wallet's nonce", end_n));
		}
		let head = &answer["head"];
		if !head.is_null() && (head["entry"].as_u64() != Some(end_n) || head["hash"].as_str() != Some(end_h)
			|| !self.head_signed(end_n, end_h, head["signature"].as_str()))
		{
			return Err(format!("the latest head it shows, entry {}, is not the record's end the signer signed with the wallet's nonce, \
				entry {}", head["entry"], end_n));
		}
		let hashes = answer["hashes"].as_array().cloned().unwrap_or_default();
		if hashes.len() != ask.len() {
			return Err(format!("it answers {} running hashes for the {} entries the wallet named", hashes.len(), ask.len()));
		}
		let mut found: Vec<String> = vec![];
		let mut agrees = 0u64;
		let mut below: Option<u64> = None;
		for ((e, h, s), got) in ask.iter().zip(&hashes) {
			if got["entry"].as_u64() != Some(*e) {
				return Err("it answers for other entries than the wallet named".into());
			}
			// What the wallet holds proves anything only with the signer's
			// signature.
			let mine = self.head_signed(*e, h, s.as_deref());
			match got["hash"].as_str() {
				Some(x) => {
					if !self.head_signed(*e, x, got["signature"].as_str()) {
						return Err(format!("the running hash it shows at entry {} is not signed by the signer", e));
					}
					if x == h {
						agrees = agrees.max(*e);
					} else if mine {
						found.push(format!("the signer signed {} at entry {} of its record, and signed {} there before, which the wallet \
							holds", x, e, h));
						below = Some(below.map_or(*e, |b| b.min(*e)));
					}
				},
				None if end_n < *e && mine => {
					found.push(format!("the signer's record ends at entry {}, signed with the wallet's nonce, before entry {} the signer \
						signed and the wallet holds", end_n, e));
					below = Some(below.map_or(*e, |b| b.min(*e)));
				},
				None => {},
			}
		}
		if let Some(why) = answer["stopped"].as_str() {
			let p = &answer["proof"]["head"];
			let (Some(pn), Some(ph)) = (p["entry"].as_u64(), p["hash"].as_str()) else {
				return Err(format!("it says the signer is stopped ({}), and shows no head that stopped it", why));
			};
			if !self.head_signed(pn, ph, p["signature"].as_str()) {
				return Err(format!("it says the signer is stopped ({}), on a head the signer did not sign", why));
			}
			let held = &answer["proof"]["held"];
			let shown = match held["hash"].as_str() {
				Some(x) if held["entry"].as_u64() == Some(pn) && x != ph && self.head_signed(pn, x, held["signature"].as_str()) => {
					format!("its record holds {} there, signed", x)
				},
				Some(_) => return Err(format!("it says the signer is stopped ({}), and the head it shows the record holding is not another \
					one the signer signed at that entry", why)),
				None if end_n < pn => format!("its record ends at entry {}, signed with the wallet's nonce", end_n),
				None => return Err(format!("it says the signer is stopped ({}), and its record holds entry {}: no proof", why, pn)),
			};
			found.push(format!("the operator's signer is stopped on its own proof: it signed entry {} with the running hash {}, and {}",
				pn, ph, shown));
		}
		if found.is_empty() {
			return Ok(None);
		}
		let mut at = agrees;
		if let Some(b) = below {
			at = at.min(b.saturating_sub(1));
		}
		if end_n < top {
			at = at.min(end_n);
		}
		Ok(Some((at, found.join("; "))))
	}

	/// Takes on the chain every coin the wallet holds that a transfer
	/// recorded after entry `at` of the signer's record made, or one whose
	/// entry it was never given; `why` is noted on each.
	fn exit_after(&mut self, at: u64, why: &str) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for c in self.store.coins()? {
			if c.kind != "transfer" || !HELD.contains(&c.state.as_str()) || self.given_up_for_held_leaves(&c)? {
				continue;
			}
			let entry = self.store.coin_entry(&c.leaf_id)?;
			if entry.is_some_and(|e| e <= at) {
				continue;
			}
			let r = self.exit(&c.leaf_id, None);
			if let Ok(row) = self.store.coin(&c.leaf_id) {
				if let Some(row) = row.filter(|r| r.state == "exiting") {
					self.store.set_coin_state(&row.leaf_id, "exiting", &format!("taken on the chain: it rests on a transfer the \
						operator's signer recorded at entry {}, after entry {} its record still agrees with ({})",
						entry.map(|e| e.to_string()).unwrap_or_else(|| "unknown".into()), at, why))?;
				}
			}
			out.push(match r {
				Ok(v) => json!({"leaf_id": c.leaf_id, "entry": entry, "exit": v}),
				Err(e) => json!({"leaf_id": c.leaf_id, "entry": entry, "error": e.to_string()}),
			});
		}
		Ok(out)
	}

	/// Whether coin `c` was given up, under its forfeit, in a participation
	/// that was released, whose new leaves the wallet holds, each on a round
	/// that is final (not `pending`): the coin is then paid for already, and
	/// exiting it would only be answered with the forfeit, at the holder's
	/// cost. One given up for a leaf whose round is out of the chain is not
	/// refreshed: `sync` takes it home by its date.
	pub(crate) fn given_up_for_held_leaves(&self, c: &CoinRow) -> Result<bool, Error> {
		if c.state != "forfeited" {
			return Ok(false);
		}
		for (pid, _, given, wanted, state, _, _) in self.store.participations()? {
			if state != "released" || !given.contains(&format!("\"{}\"", c.leaf_id)) {
				continue;
			}
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let nonces: Vec<[u8; 32]> = wanted.as_array().cloned().unwrap_or_default().iter()
				.filter_map(|w| w["nonce"].as_str().and_then(|n| unhex32(n).ok())).collect();
			let mut held = !nonces.is_empty();
			for n in &nonces {
				let leaf = self.store.nonce(n)?.and_then(|r| r.leaf_id);
				let row = match leaf {
					Some(l) => self.store.coin(&l)?,
					None => None,
				};
				// A new leaf whose round is out of the chain, or not final yet
				// (`pending`), is not held: the coin given up for it is not
				// refreshed until it is.
				held &= row.is_some_and(|r| !matches!(r.state.as_str(), "lost" | "spent" | "pending"));
			}
			if held {
				let _ = pid;
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// D57: the coins `sync` takes on the chain because it cannot have them
	/// refreshed. Every coin the wallet holds off the chain (but one given up
	/// for new leaves the wallet holds, which is paid for already) whose
	/// refresh has not completed by a day before its exit date
	/// ([`HOME_FROM`]) goes on the chain from then on, in whatever state
	/// (`live`, `sending`, `given`, `forfeited`, `offered`), for whatever
	/// reason: the operator does not answer, shows no proof, is stopped,
	/// refuses, answers but co-signs nothing, or builds no round. A coin
	/// counts as refreshed only once the wallet holds its new leaf,
	/// validated: the coin given up is spent then, and is not held. Before
	/// that day nothing is taken on the chain because the operator fails to
	/// answer: the coin is shown with its dates, and `sync` tries again.
	/// After a stop of the operator's signer, each held coin within three
	/// days of its exit date ([`HOME_WINDOW`]). Listed: each coin taken, each
	/// coin in its last three days before its exit date, and, after a stop or
	/// while the operator cannot be reached (`why`), every held coin. With
	/// `exit`, `sync`'s work (`arca exit` takes any of them at once, on the
	/// user's word); the fee coin an exit needs is the wallet's choice
	/// ([`Self::choose_fee_asset`]).
	pub(crate) fn home(&mut self, exit: bool, why: &Home) -> Result<Vec<Value>, Error> {
		let now = self.now()?.to_consensus_u32() as u64;
		let refused = self.refused_refreshes()?;
		let window = match why {
			Home::Stopped => HOME_WINDOW,
			_ => HOME_FROM,
		};
		let mut out = vec![];
		for c in self.store.coins()? {
			if !Self::homeward(&c.state) || self.given_up_for_held_leaves(&c)? {
				continue;
			}
			let dates = CoinDates::of(c.expiry);
			let by = dates.map(|d| d.exit_by);
			// A coin with no date yet (a board not in a block) goes only after
			// a stop, as every coin then.
			let due = match by {
				Some(b) => now + window as u64 >= b as u64,
				None => matches!(why, Home::Stopped),
			};
			let near = dates.is_some_and(|d| now >= d.sync_daily_from as u64);
			if !due && !near && matches!(why, Home::Answering) {
				continue;
			}
			let note = match why {
				Home::Stopped => self.spelling.say(HOME_NOTE),
				Home::Unreachable(w) => format!("{} (as this sync found: {})", self.spelling.say(UNREACHABLE_NOTE), w),
				Home::Answering => match refused.get(&c.leaf_id) {
					Some(p) => refusal_note(&self.spelling, p),
					None => self.spelling.say(SYNC_NOTE),
				},
			};
			let mut v = json!({"leaf_id": c.leaf_id, "kind": c.kind, "asset": c.asset, "value": c.value.to_string(), "state": c.state,
				"exit_by": by, "note": note});
			if let Some(d) = dates {
				v["sync_daily_from"] = json!(d.sync_daily_from);
				v["refresh_from"] = json!(d.refresh_from);
				v["home_from"] = json!(d.home_from);
			}
			if exit && due {
				v["exit"] = self.exit(&c.leaf_id, None).unwrap_or_else(|e| json!({"error": e.to_string()}));
				if let Some(row) = self.store.coin(&c.leaf_id)?.filter(|r| r.state == "exiting") {
					let date = by.map(|b| format!(" (median time {})", b)).unwrap_or_default();
					let because = match why {
						Home::Stopped => format!("the operator's signer is stopped, and the coin's exit date{} is within three days", date),
						Home::Unreachable(w) => format!("its refresh has not completed a day before its exit date{}, and the operator \
							cannot be reached ({})", date, w),
						Home::Answering => match refused.get(&c.leaf_id) {
							Some(p) if p.ends_with(" expired") => format!("its refresh has not completed a day before its exit date{}: \
								it expired at the server, its forfeits not completed by the server's deadline (participation {})", date, p),
							Some(p) => format!("its refresh has not completed a day before its exit date{}: the operator refused it \
								(participation {})", date, p),
							None => format!("its refresh has not completed a day before its exit date{} (it was {})", date, c.state),
						},
					};
					self.store.set_coin_state(&row.leaf_id, "exiting", &format!("taken on the chain: {}", because))?;
				}
			}
			out.push(v);
		}
		Ok(out)
	}

	/// Every receive request the wallet handed out that is still unpaid: the
	/// key it names (`owner`), the median time it was handed out
	/// (`asked_at`; for one handed out before the wallet kept that, the time
	/// it was stored), and whether it still holds the schedule at a day
	/// (`waiting`, until `lapses_at`, the lapse the request carries) or no
	/// longer does (`lapsed`, since `lapsed_at`: no sender pays it from
	/// then). A request handed out before requests carried their lapse is
	/// `waiting` with `lapses_at` null: its sender is told no lapse, so the
	/// wallet waits for it until it is paid or forgotten
	/// ([`Self::forget_request`]).
	pub(crate) fn receive_requests(&self, now: u32) -> Result<Vec<Value>, Error> {
		let asked: BTreeMap<String, u32> = self.store.meta(RECEIVE_ASKED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let until: BTreeMap<String, u32> = self.store.meta(RECEIVE_UNTIL)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut out = vec![];
		for n in self.store.nonces()?.into_iter().filter(|n| n.purpose == "receive" && n.state == "pending") {
			let at = match asked.get(&hex(&n.nonce)) {
				Some(t) => *t,
				None => self.store.nonce_created_at(&n.nonce)?.unwrap_or(0).clamp(0, u32::MAX as i64) as u32,
			};
			out.push(match until.get(&hex(&n.nonce)) {
				Some(&ends) if now < ends => json!({"owner": hex(&n.owner_key), "asked_at": at, "state": "waiting", "lapses_at": ends}),
				Some(&ends) => json!({"owner": hex(&n.owner_key), "asked_at": at, "state": "lapsed", "lapsed_at": ends,
					"note": "no sender pays the request from then: a coin paid to it before is read by the next sync"}),
				None => json!({"owner": hex(&n.owner_key), "asked_at": at, "state": "waiting", "lapses_at": null,
					"note": "handed out without a lapse date, so a sender may pay it at any time: the wallet waits for it until it is \
						paid or forgotten"}),
			});
		}
		Ok(out)
	}

	/// Stops waiting for a payment to the unpaid receive request whose key is
	/// `owner` (as `receive_requests` names it): it lapses now, and holds the
	/// schedule no more. A coin paid to it is still read, by any later sync.
	pub fn forget_request(&mut self, owner: &str) -> Result<Value, Error> {
		let now = self.now()?.to_consensus_u32();
		let n = self.store.nonces()?.into_iter()
			.find(|n| n.purpose == "receive" && n.state == "pending" && hex(&n.owner_key) == owner.to_ascii_lowercase())
			.ok_or_else(|| Error::Refused(format!("no unpaid receive request of the wallet's names the key {}", owner)))?;
		let mut until: BTreeMap<String, u32> = self.store.meta(RECEIVE_UNTIL)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let ends = until.get(&hex(&n.nonce)).copied().map_or(now, |t| t.min(now));
		until.insert(hex(&n.nonce), ends);
		self.store.set_meta(RECEIVE_UNTIL, &serde_json::to_string(&until).expect("a map"))?;
		Ok(json!({"owner": owner, "state": "lapsed", "lapsed_at": ends,
			"note": "the wallet no longer waits for a payment to it: a coin paid to it is still read, by any later sync"}))
	}

	/// When `sync` last asked for the refresh of each live coin (median
	/// times), from the wallet's store; coins no longer live are forgotten.
	pub(crate) fn refresh_asked(&self) -> Result<BTreeMap<String, u32>, Error> {
		let all: BTreeMap<String, u32> = self.store.meta(REFRESH_ASKED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut out = BTreeMap::new();
		for (l, t) in all {
			if self.store.coin(&l)?.is_some_and(|c| c.state == "live") {
				out.insert(l, t);
			}
		}
		Ok(out)
	}

	/// D57: asks for the refresh of every live coin in its refresh window,
	/// from [`REFRESH_FROM`] to [`HOME_FROM`] before its exit date, one
	/// participation for each, as `participate` makes it: the refresh is
	/// free there, so a fee the operator asks is refused before anything is
	/// signed, and the coin stays live, asked for again at the next `sync`.
	/// A coin whose refresh the operator refused, voided or let expire is
	/// asked for again six hours ([`REFUSED_AGAIN`]) after it was last asked
	/// for, while it is still in its refresh window.
	/// From a day before its exit date, a coin not refreshed goes home
	/// ([`Self::home`]).
	pub(crate) fn refresh_due(&mut self) -> Result<Vec<Value>, Error> {
		let now = self.now()?.to_consensus_u32();
		let refused = self.refused_refreshes()?;
		let mut asked_at = self.refresh_asked()?;
		let mut out = vec![];
		for c in self.store.coins_in("live")? {
			let Some(d) = CoinDates::of(c.expiry) else { continue };
			if now < d.refresh_from || now >= d.home_from {
				continue;
			}
			// A refresh the operator refused is asked for again six hours
			// after it was asked, not at every sync.
			if let (Some(_), Some(t)) = (refused.get(&c.leaf_id), asked_at.get(&c.leaf_id)) {
				if now < t.saturating_add(REFUSED_AGAIN) {
					continue;
				}
			}
			asked_at.insert(c.leaf_id.clone(), now);
			self.store.set_meta(REFRESH_ASKED, &serde_json::to_string(&asked_at).expect("a map"))?;
			let asked = self.refresh_quote(std::slice::from_ref(&c.leaf_id), None).and_then(|q| self.participate(q, None));
			out.push(match asked {
				Ok(v) => json!({"leaf_id": c.leaf_id, "participation": v["participation"], "state": v["state"], "fees": v["fees"]}),
				Err(e) => json!({"leaf_id": c.leaf_id, "error": e.to_string(),
					"note": "the coin stays live: sync asks for its refresh again, and takes it on the chain from home_from"}),
			});
		}
		Ok(out)
	}

	/// D57 and D58, for a client that runs `sync` on a timer: when `sync`
	/// must next run, and the dates of every coin the wallet holds off the
	/// chain. `next_sync_at` (a median time) is now while `sync` has work
	/// that cannot wait (a live coin in its refresh window not refused there,
	/// a coin a day or less from its exit date, or after a stop three days or
	/// less, not yet on its way home), else the coming date of a coin
	/// (`refresh_from`, then `home_from`), and never more than a day ahead
	/// while a coin is in its last three days before its exit date, or while
	/// the wallet waits for a payment to a receive request it handed out
	/// that has not lapsed (a coin paid to it is read only by `sync`, and its
	/// sender may have paid with a coin days from its exit date; one handed
	/// out before requests carried their lapse holds it until it is paid or
	/// forgotten); `null` when nothing waits. `due` says whether it is now;
	/// `why` says what holds the time back; `receive_requests` lists every
	/// unpaid request, waiting or lapsed, with its dates
	/// ([`Self::receive_requests`]).
	/// Asks nothing of the operator or the node but the tip.
	pub fn sync_schedule(&self) -> Result<Value, Error> {
		let now = self.now()?.to_consensus_u32();
		let stopped = self.rolled_back()?.is_some();
		let refused = self.refused_refreshes()?;
		let asked_at = self.refresh_asked()?;
		let mut next: Option<u32> = None;
		let mut coins = vec![];
		for c in self.store.coins()? {
			if !Self::homeward(&c.state) || self.given_up_for_held_leaves(&c)? {
				continue;
			}
			let Some(d) = CoinDates::of(c.expiry) else { continue };
			let at = if stopped {
				d.exit_by.saturating_sub(HOME_WINDOW).max(now)
			} else if now >= d.home_from {
				now
			} else if now >= d.refresh_from {
				match (c.state.as_str(), refused.contains_key(&c.leaf_id)) {
					("live", false) => now,
					// Refused: asked for again six hours after it was last
					// asked, or gone home from home_from.
					("live", true) => d.home_from.min(asked_at.get(&c.leaf_id).map_or(now, |t| t.saturating_add(REFUSED_AGAIN)).max(now)),
					_ => d.home_from.min(now.saturating_add(3600)),
				}
			} else {
				d.refresh_from
			};
			let at = if now >= d.sync_daily_from { at.min(now.saturating_add(86_400)) } else { at };
			next = Some(next.map_or(at, |n| n.min(at)));
			let mut v = d.json();
			v["leaf_id"] = json!(c.leaf_id);
			v["state"] = json!(c.state);
			coins.push(v);
		}
		// D58: a payment the wallet waits for is read only by `sync`, and
		// may rest on a coin days from its exit date: a day at most, while
		// the request counts. One past the lapse it carries holds the
		// schedule no more (no sender pays it from then, and one paid before
		// is read by the sync the last day's schedule named), and is shown
		// lapsed.
		let requests = self.receive_requests(now)?;
		let mut out = json!({"now": now, "due": false, "coins": coins, "note": self.spelling.say(if stopped { HOME_NOTE } else { SYNC_NOTE })});
		if requests.iter().any(|r| r["state"] == "waiting") && !stopped {
			let day = now.saturating_add(86_400);
			next = Some(next.map_or(day, |n| n.min(day)));
			out["why"] = json!(WAITING_NOTE);
		}
		if !requests.is_empty() {
			out["receive_requests"] = json!(requests);
		}
		out["next_sync_at"] = json!(next);
		out["due"] = json!(next.is_some_and(|n| n <= now));
		Ok(out)
	}

	/// Whether a coin in `state` is one the wallet may still hold off the
	/// chain, and so brings home when it cannot have it refreshed.
	fn homeward(state: &str) -> bool {
		matches!(state, "live" | "pending" | "given" | "forfeited" | "offered" | "sending")
	}

	/// The coins the wallet holds live whose latest refresh the operator
	/// refused: given in a participation it refused, voided or let expire,
	/// and not refreshed since (a coin refreshed since is spent, or given
	/// again). By leaf id, with the participation's state.
	pub(crate) fn refused_refreshes(&self) -> Result<BTreeMap<String, String>, Error> {
		let mut out = BTreeMap::new();
		for (pid, _, given, _, state, _, _) in self.store.participations()? {
			if !matches!(state.as_str(), "refused" | "void" | "expired") {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			for l in given {
				if self.store.coin(&l)?.is_some_and(|c| c.state == "live") {
					out.insert(l, format!("{} {}", &pid[..16.min(pid.len())], state));
				}
			}
		}
		Ok(out)
	}

	/// Why the operator could not refresh the wallet's coins, as `sync` last
	/// found it; `None` once a `sync` found it answering.
	pub(crate) fn unreachable(&self) -> Result<Option<String>, Error> {
		Ok(self.store.meta(UNREACHABLE)?.and_then(|v| serde_json::from_str::<Value>(&v).ok())
			.and_then(|v| v["why"].as_str().map(str::to_string)))
	}

	/// Keeps why the operator cannot refresh the wallet's coins now, or
	/// forgets it (`None`) once it answers: nothing is refused for good.
	pub(crate) fn set_unreachable(&self, why: Option<&str>) -> Result<(), Error> {
		match why {
			Some(w) => {
				let since = match self.store.meta(UNREACHABLE)?.and_then(|v| serde_json::from_str::<Value>(&v).ok()) {
					Some(v) => v["since"].clone(),
					None => json!(self.now()?.to_consensus_u32()),
				};
				self.store.set_meta(UNREACHABLE, &json!({"since": since, "why": w}).to_string())
			},
			None => self.store.delete_meta(UNREACHABLE),
		}
	}

	/// The smallest leaf the server takes in `asset`, or a refusal when it
	/// does not serve `asset`.
	pub(crate) fn min_leaf(info: &Value, asset: AssetId) -> Result<u64, Error> {
		info["assets"].as_array().into_iter().flatten()
			.find(|a| a["asset"].as_str() == Some(&asset.to_string()))
			.map(|a| amount(&a["min_leaf"], "min_leaf"))
			.unwrap_or_else(|| Err(Error::Refused(format!("the server does not serve asset {}", asset))))
	}

	// -----------------------------------------------------------------------
	// Coins against the chain
	// -----------------------------------------------------------------------

	/// The transactions `record` rests on, as the chain holds them now: for
	/// each batch or board output, the one the wallet stored when that one is
	/// in the active chain or the mempool, else whichever transaction of the
	/// active chain pays the output (another round paying the same batch
	/// output after a rollback, say), and only when none does, the one the
	/// wallet stored, which is then out of the chain. What the wallet stored
	/// is never taken over what the chain holds.
	pub(crate) fn base_txs(&self, record: &CoinRecord) -> Result<Vec<Transaction>, Error> {
		let mut outs = vec![];
		base_outputs(record, &mut outs)?;
		let mut txs: Vec<Transaction> = vec![];
		for o in outs {
			if txs.iter().any(|t| t.output.contains(&o)) {
				continue;
			}
			let stored = self.known_base(&o)?;
			if let Some(t) = &stored {
				let (in_chain, in_mempool) = self.chain.whereabouts(&t.txid())?;
				if in_chain || in_mempool {
					txs.push(t.clone());
					continue;
				}
			}
			match (self.chain_payer(&o)?, stored) {
				(Some(t), _) => {
					self.store.put_tx(&t.txid().to_string(), &elements::encode::serialize(&t), "base")?;
					txs.push(t);
				},
				(None, Some(t)) => txs.push(t),
				(None, None) => return Err(Error::Missing(format!("no transaction on the chain pays the batch or board output {} it rests on",
					hex(o.script_pubkey.as_bytes())))),
			}
		}
		Ok(txs)
	}

	/// The transactions `record` rests on as the wallet accepted it: from the
	/// store when it has them, else as the chain holds them.
	pub(crate) fn accepted_bases(&self, record: &CoinRecord) -> Result<Vec<Transaction>, Error> {
		let mut outs = vec![];
		base_outputs(record, &mut outs)?;
		let mut txs: Vec<Transaction> = vec![];
		for o in outs {
			if txs.iter().any(|t| t.output.contains(&o)) {
				continue;
			}
			match self.known_base(&o)? {
				Some(t) => txs.push(t),
				None => match self.chain_payer(&o)? {
					Some(t) => txs.push(t),
					None => return Err(Error::Missing(format!("no transaction on the chain pays the batch or board output {} it rests on",
						hex(o.script_pubkey.as_bytes())))),
				},
			}
		}
		Ok(txs)
	}

	/// The transaction of the active chain that pays `o`: found in the set of
	/// unspent outputs, else by reading the blocks from before the wallet's
	/// birthday.
	fn chain_payer(&self, o: &TxOut) -> Result<Option<Transaction>, Error> {
		let found = self.chain.coins_at(std::slice::from_ref(&o.script_pubkey))?.into_iter()
			.find(|(_, out, _)| out == o).map(|(op, _, _)| op.txid);
		match found {
			Some(txid) => self.chain.transaction(&txid),
			None => {
				let from: u64 = self.store.meta("birthday")?.and_then(|b| b.parse().ok()).unwrap_or(0);
				Ok(self.chain.find_payment(o, from.saturating_sub(1000))?.map(|(t, _)| t))
			},
		}
	}

	fn known_base(&self, o: &TxOut) -> Result<Option<Transaction>, Error> {
		// The wallet's few base transactions, scanned.
		for c in self.store.coins()? {
			for txid in &c.bases {
				if let Some(raw) = self.store.tx(txid)? {
					let t: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
					if t.output.contains(o) {
						return Ok(Some(t));
					}
				}
			}
		}
		Ok(None)
	}

	/// Checks `record` against the chain under `policy`, owned by the wallet
	/// key of `nonce` when given: the library's validation, and where each
	/// base transaction stands.
	pub(crate) fn assess(&self, record: &CoinRecord, policy: &WalletPolicy, owner: Option<(&XOnlyPublicKey, &[u8; 32])>)
		-> Result<Assessed, Error>
	{
		let txs = self.base_txs(record)?;
		let valid = match owner {
			Some((k, n)) => record.validate(&txs, policy, k, n),
			None => record.resolve(&txs, policy),
		}.map_err(|e| Error::Refused(e.to_string()))?;
		let mut bases = vec![];
		for t in txs {
			let f = self.chain.finality(&t.txid())?;
			bases.push((t, f));
		}
		Ok(Assessed { valid, bases })
	}

	/// The earliest service expiry of the boards `record` rests on, each
	/// [`BOARD_LIFETIME`] after the median time of the block of the active
	/// chain that holds it (`bases`, as [`Self::assess`] finds them); `None`
	/// when no board it rests on is in a block.
	pub(crate) fn board_expiry(&self, record: &CoinRecord, bases: &[(Transaction, Finality)]) -> Result<Option<u32>, Error> {
		fn boards(r: &CoinRecord, out: &mut Vec<TxOut>) {
			match r {
				CoinRecord::Board(b) => out.push(b.output().txout()),
				CoinRecord::Leaf { .. } => {},
				CoinRecord::Transfer(t) => t.inputs.iter().for_each(|i| boards(&i.coin, out)),
			}
		}
		let mut outs = vec![];
		boards(record, &mut outs);
		let mut earliest: Option<u32> = None;
		for o in outs {
			let Some(h) = bases.iter().find(|(t, _)| t.output.contains(&o)).and_then(|(_, f)| f.height()) else { continue };
			if let Some(m) = self.chain.median_time_at(h)? {
				let e = m.saturating_add(BOARD_LIFETIME);
				earliest = Some(earliest.map_or(e, |x| x.min(e)));
			}
		}
		Ok(earliest)
	}

	/// When a coin expires as the operator serves it: its first expiry, or
	/// the service expiry of a board it rests on, whichever comes first.
	pub(crate) fn service_expiry(&self, record: &CoinRecord, a: &Assessed) -> Result<u32, Error> {
		let e = a.valid.expiry.to_consensus_u32();
		Ok(self.board_expiry(record, &a.bases)?.map_or(e, |b| b.min(e)))
	}

	/// The store's row for a coin the wallet accepts.
	pub(crate) fn row(&self, record: &CoinRecord, a: &Assessed, state: &str, note: &str) -> Result<CoinRow, Error> {
		let (_, nonce) = owner_of(record);
		let bytes = record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?;
		for (t, _) in &a.bases {
			self.store.put_tx(&t.txid().to_string(), &elements::encode::serialize(t), "base")?;
		}
		Ok(CoinRow {
			leaf_id: a.valid.id.to_string(), owner_nonce: nonce, kind: kind_of(record).into(),
			asset: a.valid.asset.to_string(), value: a.valid.value, record: bytes, salt: a.valid.leaf.salt,
			state: state.into(), note: note.into(), expiry: self.service_expiry(record, a)?,
			bases: a.bases.iter().map(|(t, _)| t.txid().to_string()).collect(), spent_by: None,
		})
	}

	/// A held coin's record, decoded.
	pub(crate) fn record_of(c: &CoinRow) -> Result<CoinRecord, Error> {
		CoinRecord::from_bytes(&c.record).map_err(|e| Error::Store(format!("coin {}: {}", c.leaf_id, e)))
	}

	/// A held coin, resolved as its owner holds it now.
	pub(crate) fn held(&self, c: &CoinRow) -> Result<(CoinRecord, Assessed), Error> {
		let record = Self::record_of(c)?;
		let a = self.assess(&record, &self.receipt_policy(self.now()?), None)?;
		Ok((record, a))
	}

	// -----------------------------------------------------------------------
	// The re-check
	// -----------------------------------------------------------------------

	/// Checks every coin the wallet can spend, or is waiting on, against the
	/// chain as it is now: a coin whose round or board is not final (a
	/// rollback took it out, or it has not got there yet) is not spendable,
	/// and one whose bases are final again is. A board held as lost whose
	/// transaction the chain holds and the server reports credited is checked
	/// with them. Each base is read from the
	/// chain first: when another transaction now pays a batch output the
	/// wallet's coin rests on, the checks run on that one, and a coin that
	/// fails them on a base the chain holds goes into its exit at once. Run on
	/// start and after any reorganisation. Returns what changed, and whether
	/// the tip the wallet last saw has been reorganised away.
	pub fn recheck(&mut self) -> Result<Value, Error> {
		let tip = self.chain.tip()?;
		let last_h: Option<u64> = self.store.meta("tip_height")?.and_then(|v| v.parse().ok());
		let last_hash = self.store.meta("tip_hash")?;
		let reorg = match (last_h, last_hash) {
			(Some(h), Some(hash)) => self.chain.block_hash(h)?.map(|b| b.to_string()) != Some(hash),
			_ => false,
		};
		let now = MedianTime::from_consensus(tip.median_time).map_err(|e| Error::Node(e.to_string()))?;
		let before: BTreeMap<String, String> = self.store.coins()?.into_iter().map(|c| (c.leaf_id, c.state)).collect();
		let mut changes = vec![];
		let revived: Vec<String> = self.lost_boards_credited()?.into_iter().map(|c| c.leaf_id).collect();
		for c in self.store.coins()? {
			if !matches!(c.state.as_str(), "pending" | "live") && !revived.contains(&c.leaf_id) {
				continue;
			}
			let record = Self::record_of(&c)?;
			// What the chain holds of the coin, checked as of its expiry once
			// that has passed; its dates are looked at on their own.
			let policy = self.followed_policy(c.expiry, now);
			let (state, note) = match self.recheck_one(&c, &record, &policy, now)? {
				Checked::Holds(state, note) => (state, note),
				Checked::Lost(base) => {
					let why = format!("rests on {}, which is out of the chain while a coin it spends is spent by another transaction that is \
						final: the coin is worth nothing while that stands, and the wallet follows it should the parent chain bring {} back", base, base);
					self.store.set_coin_state(&c.leaf_id, "lost", &why)?;
					let back = self.round_lost(&base)?;
					changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": "lost", "why": why, "given_back": back}));
					continue;
				},
				Checked::Fails(why) => {
					// A base the chain holds fails the wallet's checks: the coin
					// is brought on-chain from its record now, before anyone
					// can use what the failing base lets them.
					let why = format!("{}: the wallet takes it on-chain", why);
					self.store.set_coin_state(&c.leaf_id, "exiting", &why)?;
					let exit = self.exit(&c.leaf_id, None).unwrap_or_else(|e| json!({"error": e.to_string()}));
					changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": "exiting", "why": why, "exit": exit}));
					continue;
				},
			};
			if state != c.state || note != c.note {
				if state != c.state {
					changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": state, "why": note}));
				}
				self.store.set_coin_state(&c.leaf_id, state, &note)?;
			}
		}
		// A round a participation was released in that can never return,
		// whatever became of its new leaves (one paid on, say): the
		// operator runs the participation again, and the wallet follows it.
		for (pid, _, _, _, state, _, pround) in self.store.participations()? {
			let Some(r) = pround.filter(|_| state == "released") else { continue };
			if self.new_leaves_expired(&pid)? {
				continue;
			}
			let Some(raw) = self.store.tx(&r)? else { continue };
			let round: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
			if self.chain.gone(&round)? {
				let back = self.round_lost(&round.txid())?;
				changes.push(json!({"round": r, "can_never_return": true, "participations": back}));
			}
		}
		// Each participation follows the one of its rounds that stands.
		changes.extend(self.follow_standing_rounds()?);
		// What the lineage watch does to a coin is the coin's one change.
		for mut ch in self.watch_lineages()? {
			let id = ch["leaf_id"].as_str().unwrap_or("").to_string();
			changes.retain(|c| c["leaf_id"].as_str() != Some(id.as_str()));
			ch["from"] = json!(before.get(&id));
			changes.push(ch);
		}
		self.store.set_meta("tip_height", &tip.height.to_string())?;
		self.store.set_meta("tip_hash", &tip.hash.to_string())?;
		Ok(json!({"tip": {"height": tip.height, "hash": tip.hash.to_string()}, "reorganised": reorg, "changes": changes}))
	}

	/// Every coin the wallet still holds, live or handed over, against the
	/// chain, for anything of its lineage there: a leaf or checkpoint it
	/// descends from, its own leaf, or a board it rests on spent. Any of them
	/// on the chain means someone has started to bring the coin, or one it
	/// rests on, on-chain (a sender converting the board it paid from, or
	/// exiting a coin it gave up), and that no off-chain spend of the coin is
	/// co-signed any more: the wallet takes the coin on-chain at once, from
	/// where the chain holds it, publishing what it signed in advance (the
	/// checkpoint from a converted board's leaf, then the reassignment) before
	/// any exit delay runs out. One look at the chain covers every coin.
	fn watch_lineages(&mut self) -> Result<Vec<Value>, Error> {
		let policy = WalletPolicy { horizon: 0, ..self.receipt_policy(self.now()?) };
		let mut held = vec![];
		for c in self.store.coins()? {
			if !matches!(c.state.as_str(), "live" | "pending" | "given" | "forfeited" | "offered" | "sending") {
				continue;
			}
			let record = Self::record_of(&c)?;
			let Ok(txs) = self.accepted_bases(&record) else { continue };
			let Ok(coin) = record.resolve(&txs, &policy) else { continue };
			held.push((c, coin));
		}
		let mut outputs = vec![];
		for (_, coin) in &held {
			outputs.extend(coin.lineage().into_iter().map(|o| o.output.txout()));
			outputs.push(coin.output().txout());
		}
		let here = self.chain.locate(&outputs)?;
		let on_chain = |o: &elements::TxOut| outputs.iter().zip(&here).any(|(w, at)| w == o && at.is_some());
		let mut changes = vec![];
		for (c, coin) in held {
			let mut seen: Vec<String> = coin.lineage().into_iter().filter(|o| on_chain(&o.output.txout()))
				.map(|o| format!("a {} it descends from ({})", o.kind, hex(o.output.script_pubkey.as_bytes()))).collect();
			if on_chain(&coin.output().txout()) && coin.board().is_none() {
				seen.push("its own leaf".into());
			}
			for b in coin.boards() {
				if !self.chain.unspent(&b)? && coin.board().is_none() {
					seen.push(format!("the board at {} it rests on, spent", b));
				}
			}
			if seen.is_empty() {
				continue;
			}
			let why = format!("on the chain: {}; no off-chain spend of it is co-signed any more, and the wallet takes it on-chain \
				before any exit delay runs out", seen.join("; "));
			let exit = self.exit(&c.leaf_id, None).unwrap_or_else(|e| json!({"error": e.to_string()}));
			let to = self.store.coin(&c.leaf_id)?.map(|r| r.state).unwrap_or_default();
			if to == "exiting" {
				self.store.set_coin_state(&c.leaf_id, "exiting", &why)?;
			}
			changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": to, "why": why, "exit": exit}));
		}
		Ok(changes)
	}

	/// One coin against the chain at `now`: where it stands, or why a base
	/// the chain holds fails the wallet's checks, or that it is past its exit
	/// date. `policy` checks the coin as of its expiry once that has passed
	/// ([`Self::followed_policy`]): what the chain holds of it is looked at
	/// past its expiry as before it.
	fn recheck_one(&self, c: &CoinRow, record: &CoinRecord, policy: &WalletPolicy, now: MedianTime) -> Result<Checked, Error> {
		let txs = match self.base_txs(record) {
			Ok(t) => t,
			Err(e @ (Error::Refused(_) | Error::Missing(_) | Error::Parse(_))) => return Ok(Checked::Holds("pending", format!("re-check: {}", e))),
			Err(e) => return Err(e),
		};
		let mut bases = vec![];
		for t in &txs {
			bases.push((t.clone(), self.chain.finality(&t.txid())?));
		}
		let waiting = bases.iter().filter(|(_, f)| !f.is_final())
			.map(|(t, f)| format!("{} is {}", t.txid(), f.word())).collect::<Vec<_>>().join("; ");
		// The bases that are not the ones the wallet stored for the coin.
		let replaced: Vec<String> = txs.iter().map(|t| t.txid().to_string()).filter(|t| !c.bases.contains(t)).collect();
		let valid = match record.resolve(&txs, policy) {
			Ok(v) => v,
			Err(e) if bases.iter().all(|(_, f)| f.in_chain()) => {
				return Ok(Checked::Fails(if replaced.is_empty() {
					format!("re-check: {}", e)
				} else {
					format!("re-check: {}, which now pays an output the coin rests on in place of what the wallet accepted, \
						fails the wallet's checks: {}", replaced.join(", "), e)
				}));
			},
			Err(e) => return Ok(Checked::Holds("pending", format!("waiting: {}; re-check: {}", waiting, e))),
		};
		let extra = if replaced.is_empty() { String::new() } else {
			// The wallet holds the coin on what the chain holds from now on.
			self.store.set_coin_bases(&c.leaf_id, &txs.iter().map(|t| t.txid().to_string()).collect::<Vec<_>>())?;
			format!("; {} now pays an output it rests on, in place of what the wallet accepted, and passes every check: \
				nothing the wallet signed for the other round carries over", replaced.join(", "))
		};
		for (t, f) in &bases {
			if matches!(f, Finality::NotInChain { in_mempool: false }) && self.chain.gone(t)? {
				return Ok(Checked::Lost(t.txid()));
			}
		}
		let a = Assessed { valid, bases };
		// The coin's dates, from where the chain holds its boards now.
		let expiry = self.service_expiry(record, &a)?;
		if expiry != c.expiry {
			self.store.set_coin_expiry(&c.leaf_id, expiry)?;
		}
		// Past its exit date, three days before the first expiry of a batch
		// it rests on, the operator co-signs no spend of the coin and takes
		// it into no round: the wallet takes it on the chain at once, past
		// its expiry as before it, and its exit checks it as of the expiry.
		let first = a.valid.expiry.to_consensus_u32();
		if now.to_consensus_u32() as u64 + WalletPolicy::EXIT_DEADLINE as u64 > first as u64 {
			let why = format!("past its exit date (median time {}, three days before its first expiry, {}): the operator co-signs no \
				spend of it and takes it into no round", first.saturating_sub(WalletPolicy::EXIT_DEADLINE), first);
			return Ok(if a.bases.iter().all(|(_, f)| f.in_chain()) {
				Checked::Fails(why)
			} else {
				Checked::Holds("pending", format!("waiting: {}; {}", waiting, why))
			});
		}
		Ok(if let Err(e) = a.valid.check_boards(|op| self.chain.unspent(op).unwrap_or(false)) {
			Checked::Holds("pending", format!("{}{}", e, extra))
		} else if a.all_final() {
			Checked::Holds("live", extra.trim_start_matches("; ").to_string())
		} else {
			Checked::Holds("pending", format!("waiting: {}{}", waiting, extra))
		})
	}

	/// Round `round` can never return: every participation it completed or
	/// was completing runs again, in a later round, as the operator runs it
	/// again. Its coins are given up to that run (`given`), and the wallet
	/// follows it as it follows any participation: it hands over its
	/// forfeits for the new round and takes its new leaves, or, when the
	/// operator will never take it, gives each coin back or holds it under
	/// its forfeit, as the operator's status says ([`Self::progress_participations`]).
	/// Each forfeit the wallet signed for the lost round is followed again
	/// ([`Self::watch_forfeits`]): one the operator published is the wallet's
	/// to refund once its delay has run; one never published can never be
	/// claimed, and is void.
	fn round_lost(&mut self, round: &Txid) -> Result<Vec<Value>, Error> {
		let r = round.to_string();
		let mut back = vec![];
		for (pid, _, given, wanted, state, _, pround) in self.store.participations()? {
			if pround.as_deref() != Some(r.as_str()) || !matches!(state.as_str(), "released" | "forfeiting") {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let nonces: Vec<[u8; 32]> = wanted.as_array().cloned().unwrap_or_default().iter()
				.filter_map(|w| w["nonce"].as_str().and_then(|n| unhex32(n).ok())).collect();
			let why = format!("round {} of participation {} can never return: the coin is given up to the participation's next run", r, pid);
			self.store.atomically(|s| {
				// The next run wants its leaves under the same owner nonces.
				for n in &nonces {
					s.wait_on_nonce(n)?;
				}
				for l in &given {
					for f in s.forfeits_of(l)? {
						if f.round == r && matches!(f.state.as_str(), "settled" | "claimed" | "claiming") {
							s.set_forfeit_state(l, &r, "signed", &why)?;
						}
					}
					if s.coin(l)?.is_some_and(|c| matches!(c.state.as_str(), "spent" | "forfeited")) {
						s.set_coin_state(l, "given", &why)?;
					}
				}
				s.set_participation(&pid, "pending", None, None)
			})?;
			for f in self.store.forfeits_in("signed")?.into_iter().filter(|f| f.round == r) {
				back.push(self.watch_forfeit_now(&f));
			}
			back.push(json!({"participation": pid, "state": "pending", "note": why}));
		}
		Ok(back)
	}

	// -----------------------------------------------------------------------
	// Reading
	// -----------------------------------------------------------------------

	/// What a coin's state is for people: a coin the wallet received out of
	/// round and has not refreshed rests on a reassignment the operator
	/// co-signed, and is `operator-confirmed` (it relies on the operator and
	/// the sender not colluding) until a round makes it a leaf of a batch.
	pub(crate) fn standing(c: &CoinRow) -> &str {
		if c.kind == "transfer" && c.state == "live" { "operator-confirmed" } else { &c.state }
	}

	/// A coin for people: its dates (median times) are its expiry and its
	/// exit deadline, three days before; a coin resting on a board carries
	/// the board's ([`BOARD_LIFETIME`]).
	fn coin_json(c: &CoinRow) -> Value {
		let on_board = Self::record_of(c).map(|r| rests_on_board(&r)).unwrap_or(false);
		let (expiry, deadline) = if c.expiry == u32::MAX { (Value::Null, Value::Null) } else {
			(json!(c.expiry), json!(c.expiry.saturating_sub(WalletPolicy::EXIT_DEADLINE)))
		};
		json!({
			"leaf_id": c.leaf_id, "kind": c.kind, "asset": c.asset, "value": c.value.to_string(), "state": c.state,
			"standing": Self::standing(c), "note": c.note, "expiry": expiry, "exit_deadline": deadline, "rests_on_board": on_board,
			"spent_by": c.spent_by,
		})
	}

	/// Every coin the wallet holds or held. From an operator with no keeper,
	/// a coin received out of round and held says it rests on the operator's
	/// machine alone. Every coin it holds off the chain shows its dates
	/// (D57: `sync_daily_from`, `refresh_from`, `home_from`, `exit_by`,
	/// median times) and how `sync` keeps it alive; one whose exit needs a fee
	/// coin says which asset would pay, or that it cannot come home until the
	/// wallet holds one.
	pub fn coins(&self) -> Result<Value, Error> {
		let alone = self.keepers()?.0.is_empty();
		let stopped = self.rolled_back()?.is_some();
		let unreachable = self.unreachable()?;
		let refused = self.refused_refreshes()?;
		let mut fee_view: Option<Vec<FeeHolding>> = None;
		let mut out = vec![];
		for c in self.store.coins()? {
			let mut v = Self::coin_json(&c);
			if alone && c.kind == "transfer" && HELD.contains(&c.state.as_str()) {
				v["record_held"] = json!(NO_KEEPER);
			}
			if Self::homeward(&c.state) && !self.given_up_for_held_leaves(&c)? {
				if let Some(d) = CoinDates::of(c.expiry) {
					v["sync_daily_from"] = json!(d.sync_daily_from);
					v["refresh_from"] = json!(d.refresh_from);
					v["home_from"] = json!(d.home_from);
					v["exit_by"] = json!(d.exit_by);
				}
				v["sync"] = json!(self.spelling.say(if stopped { HOME_NOTE } else { SYNC_NOTE }));
				// When the wallet cannot have the coin refreshed now (after a
				// stop, while the operator cannot be reached, or once it
				// refused this coin's refresh), why.
				let home = if stopped {
					Some(self.spelling.say(HOME_NOTE))
				} else if let Some(why) = &unreachable {
					Some(format!("{} (as the last sync found: {})", self.spelling.say(UNREACHABLE_NOTE), why))
				} else {
					refused.get(&c.leaf_id).map(|p| refusal_note(&self.spelling, p))
				};
				if let Some(note) = home {
					v["home"] = json!(note);
				}
				if let Some(f) = self.exit_fee(&c, &mut fee_view)? {
					v["exit_fee"] = f;
				}
			}
			out.push(v);
		}
		Ok(Value::Array(out))
	}

	/// The accepted fee assets the wallet holds on the chain, each with its
	/// largest coin and the fee of 1,000 vbytes in it, as the node prices
	/// fees now.
	pub(crate) fn fee_holdings(&self) -> Result<Vec<FeeHolding>, Error> {
		let mut largest: BTreeMap<AssetId, u64> = BTreeMap::new();
		for (_, o, _) in self.fee_candidates()? {
			if let (Some(a), Some(v)) = (o.asset.explicit(), o.value.explicit()) {
				let e = largest.entry(a).or_default();
				*e = (*e).max(v);
			}
		}
		let mut out = vec![];
		for (asset, value) in largest {
			if self.chain.floor_per_kvb(asset)?.is_some() {
				out.push(FeeHolding { asset, largest: value, per_kvb: self.fee_for(asset, 1000)? });
			}
		}
		Ok(out)
	}

	/// The wallet's on-chain coins an exit may pay fees with: those in a
	/// block, and the change an earlier exit of this process made from one,
	/// while unspent.
	pub(crate) fn fee_candidates(&self) -> Result<Vec<(OutPoint, TxOut, Keypair)>, Error> {
		let mut out: Vec<(OutPoint, TxOut, Keypair)> = self.onchain_coins()?.into_iter().map(|(op, o, k, _)| (op, o, k)).collect();
		for (op, o, k) in self.change_in_flight.borrow().iter() {
			if !out.iter().any(|c| c.0 == *op) && self.chain.unspent(op)? {
				out.push((*op, o.clone(), *k));
			}
		}
		Ok(out)
	}

	/// D57: the asset an exit of a coin of `moved` pays its fee coins in when
	/// the coin's own reserves cannot pay, and no asset was named: the moved
	/// asset where the node takes it for fees and the wallet holds a coin of
	/// it on the chain; otherwise no asset is preferred, and the one whose
	/// largest coin covers the most fees of 1,000 vbytes is taken (by asset
	/// id when two cover as many). A refusal when the wallet holds no
	/// on-chain coin in any asset the node takes: the coin cannot come home
	/// until it does.
	pub(crate) fn choose_fee_asset(&self, moved: AssetId, holdings: &[FeeHolding]) -> Result<AssetId, Error> {
		if holdings.iter().any(|h| h.asset == moved) {
			return Ok(moved);
		}
		holdings.iter().max_by(|a, b| {
			let (fa, fb) = (a.largest / a.per_kvb.max(1), b.largest / b.per_kvb.max(1));
			fa.cmp(&fb).then_with(|| b.asset.cmp(&a.asset))
		}).map(|h| h.asset).ok_or_else(|| Error::Refused(format!("{}: the wallet holds no on-chain coin in an asset the node accepts for \
			fees", self.spelling.say(FEE_COIN_MISSING))))
	}

	/// What the exit of coin `c` needs in fees beyond its own reserves: a coin
	/// in an asset the node does not take for fees now, or a board (whose
	/// conversion carries no reserve), takes a fee coin of the wallet's, in
	/// the asset [`Self::choose_fee_asset`] names. `None` when its own
	/// reserves pay. `view` keeps the wallet's fee holdings between calls.
	pub(crate) fn exit_fee(&self, c: &CoinRow, view: &mut Option<Vec<FeeHolding>>) -> Result<Option<Value>, Error> {
		let asset = AssetId::from_str(&c.asset).map_err(|e| Error::Store(e.to_string()))?;
		let accepted = self.chain.floor_per_kvb(asset)?.is_some();
		if accepted && c.kind != "board" {
			return Ok(None);
		}
		if view.is_none() {
			*view = Some(self.fee_holdings()?);
		}
		let why = if accepted { "the coin is a board, whose conversion carries no reserve" } else {
			"the node does not accept the coin's asset for fees now"
		};
		Ok(Some(match self.choose_fee_asset(asset, view.as_deref().unwrap_or(&[])) {
			Ok(a) => json!({"fee_coin": "needed", "asset": a.to_string(), "note": format!("{}: its exit takes a fee coin of the wallet's, in \
				asset {}", why, a)}),
			Err(_) => json!({"fee_coin": "missing", "note": format!("{}: {}", why, self.spelling.say(FEE_COIN_MISSING))}),
		}))
	}

	/// What the wallet holds, per asset: off-chain coins by state (a coin
	/// received out of round and not yet refreshed as `operator-confirmed`),
	/// and its on-chain coins on Sequentia. No asset is set apart.
	pub fn balance(&self) -> Result<Value, Error> {
		let mut per: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
		for c in self.store.coins()? {
			if matches!(c.state.as_str(), "spent" | "exited" | "lost") {
				continue;
			}
			*per.entry(c.asset.clone()).or_default().entry(Self::standing(&c).to_string()).or_default() += c.value;
		}
		let mut onchain: BTreeMap<String, u64> = BTreeMap::new();
		for (_, o, _, _) in self.onchain_coins()? {
			if let (Some(a), Some(v)) = (o.asset.explicit(), o.value.explicit()) {
				*onchain.entry(a.to_string()).or_default() += v;
			}
		}
		let arca: Value = per.into_iter().map(|(a, m)| (a, json!(m.into_iter().map(|(s, v)| (s, json!(v.to_string()))).collect::<serde_json::Map<_, _>>())))
			.collect::<serde_json::Map<_, _>>().into();
		let onchain: Value = onchain.into_iter().map(|(a, v)| (a, json!(v.to_string()))).collect::<serde_json::Map<_, _>>().into();
		Ok(json!({"arca": arca, "sequentia_onchain": onchain}))
	}

	/// The wallet's own view: its chain, its operator, its policy, its tip.
	pub fn info(&self) -> Result<Value, Error> {
		let tip = self.chain.tip()?;
		// The server's view first: a wallet made before keepers existed pins
		// them from it, and shows what it pinned.
		let server_info = self.server_info().map_err(|e| e.to_string()).unwrap_or_else(|e| json!({"unreachable": e}));
		Ok(json!({
			"datadir": self.datadir.display().to_string(),
			"server": self.cfg.server, "node": self.cfg.node_url,
			"genesis_hash": self.genesis.genesis_hash().to_string(),
			"chain": self.store.meta("chain_name")?,
			"operator": self.operator.to_string(),
			"mailbox_key": self.keys.mailbox()?.x_only_public_key().0.to_string(),
			"exit_delay_units": self.cfg.exit_delay_units,
			"accepted_exit_delay_units": {"min": self.cfg.min_exit_delay_units, "max": self.cfg.max_exit_delay_units},
			"keepers": self.keepers_json()?,
			"tip": {"height": tip.height, "hash": tip.hash.to_string(), "median_time": tip.median_time},
			"server_info": server_info,
		}))
	}

	/// The keepers the wallet pinned, for people.
	fn keepers_json(&self) -> Result<Value, Error> {
		let (keys, required) = self.keepers()?;
		Ok(if keys.is_empty() {
			json!({"keys": [], "required": 0, "note": NO_KEEPER})
		} else {
			json!({"keys": keys.iter().map(|k| k.to_string()).collect::<Vec<_>>(), "required": required,
				"note": format!("the operator's signer answers an entry only once {} of these keepers, on other machines, hold its head; the \
					wallet takes no coin and keeps no head without their acknowledgements", required)})
		})
	}

	/// Every refusal the wallet made, with its reason.
	pub fn refusals(&self) -> Result<Value, Error> {
		Ok(Value::Array(self.store.refusals()?.into_iter().map(|(at, what, why)| json!({"at": at, "what": what, "reason": why})).collect()))
	}

	// -----------------------------------------------------------------------
	// On-chain coins
	// -----------------------------------------------------------------------

	/// A new on-chain script of `chain`.
	pub(crate) fn new_script(&self, chain: u32) -> Result<Script, Error> {
		let i = self.store.take_index(chain)?;
		self.keys.onchain_script(chain, i)
	}

	/// A new on-chain receive address on Sequentia (an unblinded P2WPKH, the
	/// same key as the Bitcoin address of that script), and its script.
	pub fn address(&self) -> Result<Value, Error> {
		let s = self.new_script(RECEIVE)?;
		Ok(json!({"address": self.chain.address(&s)?, "script_pubkey": hex(s.as_bytes())}))
	}

	/// The wallet's unspent on-chain coins (spends in the mempool excluded),
	/// each with its key and height. The scripts it looks at run to a gap of
	/// [`GAP`] unused ones past the last index in use, whether the store
	/// handed that index out or the chain shows it used, as after a restore;
	/// an index found in use is never handed out again.
	pub(crate) fn onchain_coins(&self) -> Result<Vec<(OutPoint, TxOut, Keypair, u64)>, Error> {
		let mut out = vec![];
		for chain in [RECEIVE, CHANGE] {
			let mut from = 0u32;
			let mut end = self.store.indices(chain)? + GAP;
			while from < end {
				let window: Vec<(u32, Script, Keypair)> = (from..end).map(|i| {
					let k = self.keys.onchain(chain, i)?;
					Ok((i, p2wpkh(&k), k))
				}).collect::<Result<_, Error>>()?;
				let scripts: Vec<Script> = window.iter().map(|(_, s, _)| s.clone()).collect();
				let mut last_used = None;
				for (op, o, h) in self.chain.coins_at(&scripts)? {
					let Some((i, _, k)) = window.iter().find(|(_, s, _)| *s == o.script_pubkey) else { continue };
					last_used = last_used.max(Some(*i));
					if self.chain.unspent(&op)? {
						out.push((op, o, *k, h));
					}
				}
				from = end;
				if let Some(i) = last_used {
					self.store.bump_index(chain, i + 1)?;
					end = end.max(i + 1 + GAP);
				}
			}
		}
		Ok(out)
	}

	/// Signs input `i` of `tx`, a P2WPKH coin `prev` of `key`.
	pub(crate) fn sign_p2wpkh(&self, tx: &mut Transaction, i: usize, prev: &TxOut, key: &Keypair) {
		let pk = key.public_key();
		let h = elements::hashes::hash160::Hash::hash(&pk.serialize());
		let code = Script::new_p2pkh(&elements::PubkeyHash::from_raw_hash(h));
		let sighash = elements::sighash::SighashCache::new(&*tx)
			.segwitv0_sighash(i, &code, prev.value, elements::EcdsaSighashType::All);
		let msg = Message::from_digest(sighash.to_byte_array());
		let sig = self.secp.sign_ecdsa_low_r(&msg, &key.secret_key());
		let mut der = sig.serialize_der().to_vec();
		der.push(elements::EcdsaSighashType::All as u8);
		tx.input[i].witness.script_witness = vec![der, pk.serialize().to_vec()];
	}

	/// The fee for `vsize` vbytes in `asset`'s own atoms, from the node's floor
	/// and rate now; a refusal when the node does not accept `asset` for fees.
	pub(crate) fn fee_for(&self, asset: AssetId, vsize: u64) -> Result<u64, Error> {
		let floor = self.chain.floor_per_kvb(asset)?.ok_or_else(|| Self::not_accepted(asset))?;
		Ok(vsize.saturating_mul(floor).div_ceil(1000).max(1))
	}

	pub(crate) fn not_accepted(asset: AssetId) -> Error {
		Error::Refused(format!("asset {} is not accepted for fees by the node now; name an asset it accepts (--fee-asset): \
			the wallet pays fees in no other asset than the one named, or the one moved", asset))
	}

	/// The vsize `tx` will have once each of its P2WPKH inputs is signed
	/// (inputs at `p2wpkh`), the others as they are.
	pub(crate) fn signed_vsize(tx: &Transaction, p2wpkh: &[usize]) -> u64 {
		let mut t = tx.clone();
		for &i in p2wpkh {
			t.input[i].witness.script_witness = vec![vec![0; 72], vec![0; 33]];
		}
		(t.weight() as u64).div_ceil(4)
	}

	// -----------------------------------------------------------------------
	// The board
	// -----------------------------------------------------------------------

	/// Brings `value` of `asset` from the wallet's on-chain coins into Arca:
	/// a board record under a fresh key, the operator's nonce, the board
	/// transaction paying it, the fee in `fee_asset` (the boarded asset unless
	/// another is named). The server registers it first; only then is it
	/// broadcast, so a refused board spends nothing. The coin is spendable once
	/// the board transaction is final.
	///
	/// Only a refusal (a 4xx with one of the server's refusal codes) marks the
	/// board lost. Any other failure (no answer, a timeout, a 5xx, a gateway's
	/// page) says nothing of what the server did, and a server that took the
	/// board broadcasts it itself: the coin stays pending with its
	/// transaction, and `sync` posts the same registration again until the
	/// server answers it ([`Self::retry_boards`]).
	pub fn board(&mut self, asset: AssetId, value: u64, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let fee_asset = fee_asset.unwrap_or(asset);
		self.fee_for(fee_asset, 1)?;
		let info = self.server_info()?;
		let min = Self::min_leaf(&info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("a board of {} is below the server's smallest leaf in asset {}, {}", value, asset, min)));
		}
		// The coins to spend: the boarded asset's, then the fee asset's.
		let coins = self.onchain_coins()?;
		let mut chosen: Vec<(OutPoint, TxOut, Keypair)> = vec![];
		let mut fee = self.fee_for(fee_asset, 300)?;
		let change = self.new_script(CHANGE)?;
		let operator_nonce = self.server.operator_nonce()?;
		let owner_nonce = random32();
		let key = self.keys.leaf(&owner_nonce)?;
		let owner = key.x_only_public_key().0;
		self.store.put_nonce(&owner_nonce, &owner.serialize(), "board")?;
		let record = BoardRecord {
			template: Template::Board1, owner, owner_nonce, operator_nonce, exit_delay: self.exit_delay(),
			asset, value, chain: self.genesis, operator: self.operator,
		};
		let tx = loop {
			chosen.clear();
			let mut need: BTreeMap<AssetId, u64> = BTreeMap::new();
			*need.entry(asset).or_default() += value;
			*need.entry(fee_asset).or_default() += fee;
			for (a, n) in &need {
				let mut have = 0u64;
				let mut of: Vec<_> = coins.iter().filter(|(_, o, _, _)| o.asset.explicit() == Some(*a)).collect();
				of.sort_by_key(|(_, o, _, _)| std::cmp::Reverse(o.value.explicit().unwrap_or(0)));
				for (op, o, k, _) in of {
					if have >= *n {
						break;
					}
					have += o.value.explicit().unwrap_or(0);
					chosen.push((*op, o.clone(), *k));
				}
				if have < *n {
					return Err(Error::Refused(format!("the wallet holds {} of asset {} on-chain that it can spend, and needs {}", have, a, n)));
				}
			}
			let pairs: Vec<(OutPoint, TxOut)> = chosen.iter().map(|(op, o, _)| (*op, o.clone())).collect();
			let mut tx = record.tx(&pairs, fee_asset, fee, &change).map_err(|e| Error::Refused(e.to_string()))?.tx;
			let all: Vec<usize> = (0..tx.input.len()).collect();
			let needed = self.fee_for(fee_asset, Self::signed_vsize(&tx, &all))?;
			if needed <= fee {
				for (i, (_, o, k)) in chosen.iter().enumerate() {
					self.sign_p2wpkh(&mut tx, i, o, k);
				}
				break tx;
			}
			fee = needed;
		};
		let valid = record.validate(&tx, &self.accept_policy(self.now()?)).map_err(|e| Error::Refused(e.to_string()))?;
		let leaf_id = valid.leaf_id.to_string();
		let coin = CoinRecord::Board(record);
		let row = CoinRow {
			leaf_id: leaf_id.clone(), owner_nonce, kind: "board".into(), asset: asset.to_string(), value,
			record: coin.to_bytes().map_err(|e| Error::Refused(e.to_string()))?, salt: record.salt(), state: "pending".into(),
			note: "board registered; waiting for its transaction to be final".into(), expiry: u32::MAX,
			bases: vec![tx.txid().to_string()], spent_by: None,
		};
		let body = json!({
			"record": hex(&record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?),
			"tx": hex(&elements::encode::serialize(&tx)),
		});
		self.store.atomically(|s| {
			s.put_tx(&tx.txid().to_string(), &elements::encode::serialize(&tx), "base")?;
			s.put_coin(&row)?;
			s.use_nonce(&owner_nonce, &leaf_id)?;
			s.put_board_request(&leaf_id, &body.to_string())
		})?;
		let state = self.post_board(&leaf_id, &body, &tx)?;
		let mut out = json!({
			"leaf_id": leaf_id, "txid": tx.txid().to_string(), "vsize": tx.vsize(), "asset": asset.to_string(),
			"value": value.to_string(), "fee": {"asset": fee_asset.to_string(), "amount": fee.to_string()},
			"state": state,
		});
		// A board's conversion carries no reserve: its exit takes a fee coin,
		// and a wallet holding none says so.
		if let Some(f) = self.exit_fee(&row, &mut None)?.filter(|f| f["fee_coin"] == "missing") {
			out["exit_fee"] = f;
		}
		Ok(out)
	}

	/// Posts the registration of board `leaf_id` and takes the answer: the
	/// board transaction broadcast once the server holds the board, the coin
	/// lost only on a refusal. Anything else leaves the registration
	/// standing, the coin pending with its transaction, to be posted again
	/// byte for byte: the server answers a board it already holds with its
	/// status. Returns the coin's state.
	fn post_board(&mut self, leaf_id: &str, body: &Value, tx: &Transaction) -> Result<&'static str, Error> {
		match self.server.post("register_board", body) {
			Ok(status) => {
				self.store.set_board_request(leaf_id, "done", &status.to_string())?;
				if status["state"].as_str() == Some("lost") {
					let why = "the server holds the board as lost: its transaction can no longer confirm, or stayed out of every block";
					self.store.set_coin_state(leaf_id, "lost", why)?;
					return Ok("lost");
				}
				self.chain.broadcast(tx)?;
				Ok("pending")
			},
			Err(e @ Error::Server { .. }) => {
				self.store.atomically(|s| {
					s.set_coin_state(leaf_id, "lost", &format!("the server refused the board, which was never broadcast: {}", e))?;
					s.set_board_request(leaf_id, "refused", &e.to_string())?;
					s.refused(&format!("board {}", leaf_id), &e.to_string())
				})?;
				Err(e)
			},
			Err(e) => {
				let seen = match &e {
					Error::Unreachable(m) => m.clone(),
					e => e.to_string(),
				};
				let why = format!("registering: the server's answer was not seen ({}); the server may hold the board and broadcast it, \
					so the coin is kept with its transaction, and sync posts the same registration again", seen);
				self.store.set_coin_state(leaf_id, "pending", &why)?;
				Err(Error::Unreachable(format!("{}; board {} is kept pending with its transaction, and sync posts the same registration \
					again", seen, leaf_id)))
			},
		}
	}

	/// Posts again every board registration the server has not answered.
	pub(crate) fn retry_boards(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (leaf_id, body) in self.store.board_requests_in("requested")? {
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			let raw = super::chain::unhex(body["tx"].as_str().unwrap_or(""))?;
			let tx: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
			out.push(match self.post_board(&leaf_id, &body, &tx) {
				Ok(state) => json!({"board": leaf_id, "registered": true, "state": state}),
				Err(e) => json!({"board": leaf_id, "error": e.to_string()}),
			});
		}
		Ok(out)
	}

	/// Every board the wallet holds as lost whose transaction the chain holds
	/// all the same, followed again when the server reports it credited: the
	/// coin is then the re-check's like any other. The server credits a board
	/// it took, whatever answer the wallet saw.
	fn lost_boards_credited(&self) -> Result<Vec<CoinRow>, Error> {
		let mut out = vec![];
		for c in self.store.coins_in("lost")?.into_iter().filter(|c| c.kind == "board") {
			let Some(Ok(txid)) = c.bases.first().map(|t| Txid::from_str(t)) else { continue };
			let (in_chain, in_mempool) = self.chain.whereabouts(&txid)?;
			if !in_chain && !in_mempool {
				continue;
			}
			match self.server.post("board_status", &json!({"leaf_id": c.leaf_id})) {
				Ok(st) if st["state"].as_str() == Some("credited") && st["txid"].as_str() == Some(&txid.to_string()) => out.push(c),
				_ => {},
			}
		}
		Ok(out)
	}

	/// Where each board the wallet holds stands, by the server and by the
	/// wallet's own reading of the chain.
	pub fn boards(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for c in self.store.coins()?.into_iter().filter(|c| c.kind == "board") {
			let server = self.server.post("board_status", &json!({"leaf_id": c.leaf_id})).unwrap_or_else(|e| json!({"error": e.to_string()}));
			let own = match c.bases.first().map(|t| Txid::from_str(t)) {
				Some(Ok(t)) => self.chain.finality(&t)?.word().to_string(),
				_ => "unknown".into(),
			};
			out.push(json!({"leaf_id": c.leaf_id, "state": c.state, "finality": own, "server": server}));
		}
		Ok(Value::Array(out))
	}
}

/// Signs `digest` with `key`, BIP340, fresh randomness.
pub(crate) fn sign(key: &Keypair, digest: &[u8; 32]) -> elements::secp256k1_zkp::schnorr::Signature {
	arca_covenant::sign::sign_digest(key, digest, &random32())
}

use elements::hashes::Hash as _;

#[cfg(test)]
mod tests {
	use super::*;
	use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
	use arca_covenant::{ClockSchedule, RecordError};
	use elements::hashes::Hash as _;

	fn key(i: u8) -> Keypair {
		Keypair::from_seckey_slice(&Secp256k1::new(), &[i.max(1); 32]).unwrap()
	}

	/// A wallet in a store the program opened itself: it opens with its own
	/// mnemonic only, and a store with no wallet, or one that cannot say whose
	/// it is, is refused. Opening contacts neither node nor server.
	#[test]
	fn a_store_opens_with_its_own_mnemonic_only() {
		const A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		const B: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
		let store = || Store::open_connection(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
		let refused = |r: Result<Wallet, Error>| match r {
			Err(Error::Refused(why)) => why,
			Err(e) => panic!("refused for another reason: {}", e),
			Ok(_) => panic!("opened"),
		};
		assert_eq!(refused(Wallet::open_in(store(), A, None)), "this store holds no wallet; create one first");

		let made = || {
			let s = store();
			let cfg = Config::spec_delays("https://example.org/arca", "http://127.0.0.1:1/");
			let pins = Pins { genesis: "00".repeat(32), chain_name: "elementsregtest".into(), operator: key(7).x_only_public_key().0.to_string(),
				keepers: json!({"keys": [], "required": 0}).to_string(), tip_height: 1, tip_hash: "00".repeat(32) };
			Wallet::write_pins(&s, &cfg, pins).unwrap();
			s
		};
		let s = made();
		s.set_meta("mailbox_key", &Keys::new(A, 0, 1).unwrap().mailbox().unwrap().x_only_public_key().0.to_string()).unwrap();
		let w = Wallet::open_in(s, A, None).expect("its own mnemonic opens it");
		assert_eq!(w.cfg.server, "https://example.org/arca");

		let s = made();
		s.set_meta("mailbox_key", &Keys::new(A, 0, 1).unwrap().mailbox().unwrap().x_only_public_key().0.to_string()).unwrap();
		assert_eq!(refused(Wallet::open_in(s, B, None)), "this store holds the wallet of another mnemonic");

		assert!(refused(Wallet::open_in(made(), A, None)).contains("names no mailbox key"));
	}

	/// A 16-leaf tree with one-atom reserves on every node and entry, as the
	/// operator builds for an asset the node does not accept for fees.
	fn one_atom_tree() -> (arca_covenant::LeafRecord, WalletPolicy) {
		let s = key(200).x_only_public_key().0;
		let chain = Chain::new(elements::BlockHash::all_zeros());
		let asset = AssetId::from_slice(&[7; 32]).unwrap();
		let now = MedianTime::from_consensus(1_800_000_000).unwrap();
		let w = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
		let e: Vec<MedianTime> = (1..=3u32).map(|k| MedianTime::from_consensus(1_800_000_000 + k * 28 * 86_400).unwrap()).collect();
		let schedule = ClockSchedule::new(AssetId::from_slice(&[9; 32]).unwrap(), s, w, e).unwrap();
		let leaves: Vec<LeafSpec> = (0..16u8).map(|i| LeafSpec {
			template: Template::Vtxo1, owner: key(i + 1).x_only_public_key().0, value: 1_000_000,
			owner_nonce: [i; 32], operator_nonce: [i + 100; 32], exit_delay: w, unlock_hash: [i + 50; 32],
		}).collect();
		let params = TreeParams { asset, chain, schedule, burn: false, radix: 4, reserve: ReserveRule::Fixed { node: 1, entry: 1 }, min_leaf: 1000 };
		let tree = Tree::build(params, &leaves).unwrap();
		(tree.record(5), WalletPolicy::new(chain, s, now))
	}

	/// D49 amended: a coin given up in a released participation, whose new
	/// leaf the wallet holds, is not exited after a stop; once that leaf is
	/// gone, it is.
	#[test]
	fn a_coin_given_up_for_new_leaves_the_wallet_holds_is_not_exited() {
		let dir = std::env::temp_dir().join(format!("arca-wallet-unit-{}-given-up", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join(MNEMONIC_FILE), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
			.unwrap();
		let store = Store::open(&dir.join(DB_FILE)).unwrap();
		let operator = key(9).x_only_public_key().0;
		for (k, v) in [("server", "http://127.0.0.1:1"), ("node_url", "http://127.0.0.1:1/"), ("account", "0"), ("exit_delay_units", "254"),
			("min_exit_delay_units", "254"), ("max_exit_delay_units", "338"), ("genesis", &elements::BlockHash::all_zeros().to_string()),
			("chain_name", "elementsregtest"), ("operator", &operator.to_string())]
		{
			store.set_meta(k, v).unwrap();
		}
		let row = |id: &str, kind: &str, state: &str, nonce: [u8; 32]| CoinRow {
			leaf_id: id.into(), owner_nonce: nonce, kind: kind.into(), asset: AssetId::from_slice(&[7; 32]).unwrap().to_string(),
			value: 1_000, record: vec![], salt: [nonce[0]; 32], state: state.into(), note: String::new(), expiry: u32::MAX, bases: vec![],
			spent_by: None,
		};
		let (old, new) = ([1u8; 32], [2u8; 32]);
		store.put_nonce(&old, &key(2).x_only_public_key().0.serialize(), "receive").unwrap();
		store.put_coin(&row("old", "transfer", "forfeited", old)).unwrap();
		store.use_nonce(&old, "old").unwrap();
		store.put_nonce(&new, &key(3).x_only_public_key().0.serialize(), "participation").unwrap();
		store.put_coin(&row("new", "batch", "live", new)).unwrap();
		store.use_nonce(&new, "new").unwrap();
		store.put_participation("p", "{}", "[\"old\"]", &json!([{"nonce": hex(&new)}]).to_string()).unwrap();
		store.set_participation("p", "released", Some(&hex(&[5; 32])), None).unwrap();
		drop(store);
		let mut w = Wallet::open(&dir).unwrap();
		let c = w.store.coin("old").unwrap().unwrap();
		assert!(w.given_up_for_held_leaves(&c).unwrap());
		assert!(w.exit_after(0, "a stop").unwrap().is_empty(), "nothing exited");
		// The new leaf's round out of the chain: not refreshed yet.
		w.store.set_coin_state("new", "pending", "waiting: its round is out of the chain").unwrap();
		assert!(!w.given_up_for_held_leaves(&c).unwrap(), "a coin given up for a leaf on a round out of the chain is not refreshed");
		w.store.set_coin_state("new", "live", "").unwrap();
		assert!(w.given_up_for_held_leaves(&c).unwrap());
		// The new leaf lost: the old coin is the wallet's to take on the chain.
		w.store.set_coin_state("new", "lost", "gone").unwrap();
		assert!(!w.given_up_for_held_leaves(&c).unwrap());
		let tried = w.exit_after(0, "a stop").unwrap();
		assert_eq!(tried.len(), 1, "{:?}", tried);
		assert_eq!(tried[0]["leaf_id"], "old");
		let _ = std::fs::remove_dir_all(&dir);
	}

	/// A wallet's directory and store, as the unit tests make one: its
	/// meta set, nothing else in it.
	fn bare_wallet(tag: &str) -> std::path::PathBuf {
		let dir = std::env::temp_dir().join(format!("arca-wallet-unit-{}-{}", std::process::id(), tag));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join(MNEMONIC_FILE), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
			.unwrap();
		let store = Store::open(&dir.join(DB_FILE)).unwrap();
		let operator = key(9).x_only_public_key().0;
		for (k, v) in [("server", "http://127.0.0.1:1"), ("node_url", "http://127.0.0.1:1/"), ("account", "0"), ("exit_delay_units", "254"),
			("min_exit_delay_units", "254"), ("max_exit_delay_units", "338"), ("genesis", &elements::BlockHash::all_zeros().to_string()),
			("chain_name", "elementsregtest"), ("operator", &operator.to_string())]
		{
			store.set_meta(k, v).unwrap();
		}
		dir
	}

	/// F1 of R7i: a receive request carries its lapse, and is waiting until
	/// then and lapsed from then, with both dates; one handed out before
	/// requests carried their lapse waits until it is paid or forgotten
	/// (forgetting one is run in `arca_adversity`).
	#[test]
	fn a_receive_request_lapses_at_the_date_it_carries_and_an_old_one_waits() {
		let dir = bare_wallet("request-lapse");
		let (new, old) = ([5u8; 32], [6u8; 32]);
		{
			let store = Store::open(&dir.join(DB_FILE)).unwrap();
			store.put_nonce(&new, &key(5).x_only_public_key().0.serialize(), "receive").unwrap();
			store.put_nonce(&old, &key(6).x_only_public_key().0.serialize(), "receive").unwrap();
			store.set_meta(RECEIVE_ASKED, &json!({hex(&new): 1_000, hex(&old): 1_000}).to_string()).unwrap();
			store.set_meta(RECEIVE_UNTIL, &json!({hex(&new): 1_000 + REQUEST_HOLDS}).to_string()).unwrap();
		}
		let w = Wallet::open(&dir).unwrap();
		let of = |at: u32| -> BTreeMap<String, Value> {
			w.receive_requests(at).unwrap().into_iter().map(|r| (r["owner"].as_str().unwrap().to_string(), r)).collect()
		};
		let (kn, ko) = (hex(&key(5).x_only_public_key().0.serialize()), hex(&key(6).x_only_public_key().0.serialize()));
		let before = of(1_000 + REQUEST_HOLDS - 1);
		assert_eq!((before[&kn]["state"].as_str(), before[&kn]["lapses_at"].as_u64()), (Some("waiting"), Some(1_000 + REQUEST_HOLDS as u64)));
		let after = of(1_000 + REQUEST_HOLDS);
		println!("a request at its lapse: {}; one with none, a year on: {}", after[&kn], of(1_000 + 365 * 86_400)[&ko]);
		assert_eq!((after[&kn]["state"].as_str(), after[&kn]["asked_at"].as_u64(), after[&kn]["lapsed_at"].as_u64()),
			(Some("lapsed"), Some(1_000), Some(1_000 + REQUEST_HOLDS as u64)));
		let year = of(1_000 + 365 * 86_400);
		assert_eq!(year[&ko]["state"], "waiting", "an old request waits until it is paid or forgotten");
		assert!(year[&ko]["lapses_at"].is_null());
		let _ = std::fs::remove_dir_all(&dir);
	}

	/// R7f F9: a second record of a coin the wallet holds, whose checks all
	/// passed (so validly signed), with other checkpoint values: kept as
	/// evidence that the operator co-signed two checkpoint values for one
	/// coin, and reported; the same record again is held, as before.
	#[test]
	fn a_second_record_of_a_held_coin_is_kept_as_evidence() {
		let dir = bare_wallet("second-record");
		{
			let store = Store::open(&dir.join(DB_FILE)).unwrap();
			let nonce = [4u8; 32];
			store.put_nonce(&nonce, &key(4).x_only_public_key().0.serialize(), "receive").unwrap();
			store.put_coin(&CoinRow {
				leaf_id: "c".into(), owner_nonce: nonce, kind: "transfer".into(), asset: AssetId::from_slice(&[7; 32]).unwrap().to_string(),
				value: 1_000, record: vec![1, 2, 3], salt: [4; 32], state: "live".into(), note: String::new(), expiry: u32::MAX,
				bases: vec![], spent_by: None,
			}).unwrap();
			store.use_nonce(&nonce, "c").unwrap();
		}
		let w = Wallet::open(&dir).unwrap();
		assert!(w.held_again("not held", &[1, 2, 3]).unwrap().is_none());
		let same = w.held_again("c", &[1, 2, 3]).unwrap().unwrap();
		assert_eq!(same, json!({"leaf_id": "c", "already_held": "live"}));
		let other = w.held_again("c", &[1, 2, 4]).unwrap().unwrap();
		println!("a second record of a held coin: {}", other["evidence"]);
		assert_eq!(other["already_held"], "live");
		assert!(other["evidence"].as_str().unwrap().contains("the operator co-signed two checkpoint values for one coin")
			&& other["evidence"].as_str().unwrap().ends_with("010204"), "{}", other);
		let refusals = w.refusals().unwrap();
		assert!(refusals.as_array().unwrap().iter().any(|r| r["what"] == "evidence: coin c"), "{}", refusals);
		assert_eq!(w.store.coin("c").unwrap().unwrap().record, vec![1, 2, 3], "the coin held stays as it was");
		let _ = std::fs::remove_dir_all(&dir);
	}

	/// R7f F9: a rollback note an older version of the wallet kept without
	/// the signer's proof is not acted on, and a witness that finds the
	/// record agreeing drops it; a note kept on the signer's proof stands.
	#[test]
	fn a_rollback_note_without_the_signers_proof_is_not_acted_on() {
		let dir = bare_wallet("old-note");
		let w = Wallet::open(&dir).unwrap();
		w.store.set_meta(ROLLED_BACK, &json!({"at": 2, "why": "an older wallet's note"}).to_string()).unwrap();
		assert_eq!(w.rolled_back().unwrap(), None, "not acted on");
		w.drop_unproven_rollback().unwrap();
		assert_eq!(w.store.meta(ROLLED_BACK).unwrap(), None, "dropped once the record agrees");
		assert!(w.refusals().unwrap().as_array().unwrap().iter().any(|r| r["reason"].as_str().unwrap_or("").contains("was checked against the \
			signer, whose witness proves no rollback: dropped")));
		w.found_rollback(3, "the signer's proof").unwrap();
		assert_eq!(w.rolled_back().unwrap(), Some((3, "the signer's proof".to_string())));
		w.drop_unproven_rollback().unwrap();
		assert_eq!(w.rolled_back().unwrap(), Some((3, "the signer's proof".to_string())), "a proven note stands");
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn reserves_cover_four_times_the_floor_where_the_asset_pays_fees() {
		let (record, policy) = one_atom_tree();
		let accepted = WalletPolicy { min_reserve: reserve_floor(Some(100)), ..policy };
		assert!(matches!(accepted.check(&record), Err(RecordError::NodeReserve { level: 0, reserve: 1, .. })),
			"{:?}", accepted.check(&record));
		// The operator's own rule where the node does not take the asset.
		let not_accepted = WalletPolicy { min_reserve: reserve_floor(None), ..policy };
		assert!(not_accepted.check(&record).is_ok());
	}
}
