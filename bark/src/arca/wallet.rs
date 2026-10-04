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
	Ok(())
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
	pub(crate) witnessed: std::cell::RefCell<Option<(std::time::Instant, Value)>>,
}

/// How long a witness of the operator's signer's record stands before the
/// wallet witnesses it again.
pub const WITNESS_FOR: std::time::Duration = std::time::Duration::from_secs(10);

/// The most heads one witness hands the server: the server's bound.
pub const MAX_WITNESS: usize = 32;

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
/// of a coin resting on the board; after it, it takes the coin only into a
/// refresh, up to [`BOARD_REFRESH_UNTIL`] before the expiry; from the expiry
/// it may bring the coin's lineage on the chain.
pub const BOARD_LIFETIME: u32 = 28 * 86_400;

/// How long before a board's service expiry a coin resting on it is still
/// taken into a refresh: a day.
pub const BOARD_REFRESH_UNTIL: u32 = 86_400;

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
	/// A base can never return to the chain: an input of it is spent by
	/// another transaction that is final.
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
		write_private(&datadir.join(MNEMONIC_FILE), &mnemonic.to_string())?;
		if let Some(p) = &cfg.node_password {
			write_private(&datadir.join(NODE_PASSWORD_FILE), p)?;
		}
		let store = Store::open(&datadir.join(DB_FILE))?;
		set_private(&datadir.join(DB_FILE))?;
		let tip = chain.tip()?;
		let meta = [
			("server", cfg.server.clone()), ("node_url", cfg.node_url.clone()),
			("node_user", cfg.node_user.clone().unwrap_or_default()),
			("node_cookie", cfg.node_cookie.clone().unwrap_or_default()),
			("account", cfg.account.to_string()), ("exit_delay_units", cfg.exit_delay_units.to_string()),
			("min_exit_delay_units", cfg.min_exit_delay_units.to_string()), ("max_exit_delay_units", cfg.max_exit_delay_units.to_string()),
			("genesis", genesis.to_string()), ("chain_name", chain_name), ("operator", operator.to_string()),
			("birthday", tip.height.to_string()), ("tip_height", tip.height.to_string()), ("tip_hash", tip.hash.to_string()),
		];
		for (k, v) in meta {
			store.set_meta(k, &v)?;
		}
		drop(store);
		Wallet::open(datadir)
	}

	/// Opens the wallet in `datadir`. Contacts neither node nor server.
	pub fn open(datadir: &Path) -> Result<Wallet, Error> {
		let db = datadir.join(DB_FILE);
		if !db.exists() {
			return Err(Error::Refused(format!("{} holds no wallet; create one first", datadir.display())));
		}
		let store = Store::open(&db)?;
		set_private(&db)?;
		let get = |k: &str| -> Result<String, Error> { store.meta(k)?.ok_or_else(|| Error::Store(format!("{} is not set", k))) };
		let opt = |k: &str| -> Result<Option<String>, Error> { Ok(store.meta(k)?.filter(|v| !v.is_empty())) };
		// The node's password, from its own file; a store that still holds it
		// gives it up to that file.
		let password_file = datadir.join(NODE_PASSWORD_FILE);
		if let Some(p) = opt("node_password")? {
			write_private(&password_file, &p)?;
			store.set_meta("node_password", "")?;
		}
		let node_password = match std::fs::read_to_string(&password_file) {
			Ok(p) => Some(p.trim_end_matches(['\r', '\n']).to_string()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
			Err(e) => return Err(Error::Io(format!("{}: {}", password_file.display(), e))),
		};
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
		let mnemonic = std::fs::read_to_string(datadir.join(MNEMONIC_FILE))
			.map_err(|e| Error::Io(format!("{}: {}", datadir.join(MNEMONIC_FILE).display(), e)))?;
		let keys = Keys::new(mnemonic.trim(), cfg.account, coin_type)?;
		let chain = ChainSource::new(&cfg.node_url, cfg.node_user.as_deref(), cfg.node_password.as_deref(), cfg.node_cookie.as_deref());
		let server = ServerClient::new(&cfg.server)?;
		Ok(Wallet { datadir: datadir.to_path_buf(), store, keys, chain, server, genesis, operator, cfg, secp: Secp256k1::new(),
			witnessed: std::cell::RefCell::new(None) })
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

	/// The server's `info`, checked against what the wallet pinned when it was
	/// created: the same chain and the same operator key; and the head of
	/// its signer's record it shows, signed, against every head the wallet
	/// holds. An operator whose record the wallet found rolled back is
	/// refused.
	pub(crate) fn server_info(&self) -> Result<Value, Error> {
		if let Some((at, why)) = self.rolled_back()? {
			return Err(Error::Refused(format!("the operator's signer's record was rolled back or replaced past entry {} ({}): the wallet \
				goes no further with this operator, and takes on the chain every coin resting on what it signed after", at, why)));
		}
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
		self.witness_record(&info["signer_record"], true)?;
		Ok(info)
	}

	/// The rollback of the operator's signer's record the wallet found, if
	/// it found one: the highest entry the record still agreed with, and why.
	pub(crate) fn rolled_back(&self) -> Result<Option<(u64, String)>, Error> {
		Ok(self.store.meta(ROLLED_BACK)?.and_then(|v| serde_json::from_str::<Value>(&v).ok())
			.map(|v| (v["at"].as_u64().unwrap_or(0), v["why"].as_str().unwrap_or("").to_string())))
	}

	/// Keeps the rollback found, `why`, the record agreeing with the wallet
	/// up to entry `at`: the lowest such entry found stands.
	fn found_rollback(&self, at: u64, why: &str) -> Result<(), Error> {
		let prior = self.rolled_back()?;
		let at = prior.as_ref().map_or(at, |(was, _)| (*was).min(at));
		if prior.is_some_and(|(was, w)| was == at && w == why) {
			return Ok(());
		}
		self.store.set_meta(ROLLED_BACK, &json!({"at": at, "why": why}).to_string())?;
		self.store.refused("the operator's signer's record", why)
	}

	/// Checks a head of the operator's signer's record it shows,
	/// `{entry, hash, signature}` (the latest, in `info` or a witness, when
	/// `latest`; a round's, in its published tree, or a transfer's, with the
	/// coins it made, otherwise): a signature that is not `S`'s over it
	/// ([`super::client::record_head_digest`]) is refused; another running
	/// hash at an entry the wallet holds, or a latest entry below the highest
	/// it holds, is a rollback of the record, with the operator's database:
	/// the signer may then sign again what it signed. The wallet keeps the
	/// rollback found, takes the coins resting on what was signed after it
	/// on the chain at its next witness ([`Self::witness`]), and refuses to go
	/// on with the operator, saying why. A signed head is kept; one without a
	/// signature (a round's tree from before heads were signed) only
	/// compared.
	pub(crate) fn witness_record(&self, shown: &Value, latest: bool) -> Result<(), Error> {
		let (Some(entry), Some(hash)) = (shown["entry"].as_u64(), shown["hash"].as_str()) else { return Ok(()) };
		let signature = shown["signature"].as_str();
		if let Some(sig) = signature {
			let ok = unhex32(hash).ok().zip(unhex(sig).ok().and_then(|b| elements::secp256k1_zkp::schnorr::Signature::from_slice(&b).ok()))
				.is_some_and(|(h, s)| arca_covenant::sign::verify_digest(&s, &super::client::record_head_digest(&self.genesis, entry, &h), &self.operator));
			if !ok {
				let why = format!("the operator shows entry {} of its signer's record with a signature that is not its signer's: the \
					wallet takes nothing from it", entry);
				self.store.refused("the operator's signer's record", &why)?;
				return Err(Error::Refused(why));
			}
		}
		if let Some(seen) = self.store.seen_entry(entry)? {
			if seen != hash {
				let why = format!("the operator shows entry {} of its signer's record with the running hash {}, and showed {} for that \
					entry before: its record has been replaced or rolled back, with its database, so it may sign again what it signed; \
					the wallet goes no further with this operator", entry, hash, seen);
				self.found_rollback(entry.saturating_sub(1), &why)?;
				return Err(Error::Refused(why));
			}
		}
		if latest {
			if let Some((top, _)) = self.store.seen_latest()? {
				if entry < top {
					let why = format!("the operator shows its signer's record ending at entry {}, and showed entry {} before: its record \
						and its database have been rolled back together, so it may sign again what it signed; the wallet goes no further \
						with this operator", entry, top);
					self.found_rollback(entry, &why)?;
					return Err(Error::Refused(why));
				}
			}
		}
		if signature.is_some() {
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
	/// recorded at, and as many more as fit in [`MAX_WITNESS`], and checks the
	/// running hash the record holds at each, and its latest entry, signed.
	/// A latest entry below the highest the wallet holds, another hash at an
	/// entry it holds, an entry it holds past the record's end, or a signer
	/// stopped by such a proof (handed over by any wallet) is a rollback of
	/// the record, and each signed head the wallet hands over that the record
	/// does not hold stops the signer. The wallet then finds the highest
	/// entry it holds that the record still agrees with, and takes on the
	/// chain at once every coin it holds that a transfer recorded after it
	/// made (a coin whose entry it was never given counts as after); its own
	/// leaves and boards, which no transfer made, stay. It goes no further
	/// with the operator after that, and says why.
	pub fn witness(&mut self) -> Result<Value, Error> {
		if let Some((at, v)) = self.witnessed.borrow().as_ref() {
			if at.elapsed() < WITNESS_FOR {
				return Ok(v.clone());
			}
		}
		let held = self.store.seen_heads()?;
		let mut ask: Vec<(u64, String, Option<String>)> = vec![];
		let add = |h: &(u64, String, Option<String>), ask: &mut Vec<(u64, String, Option<String>)>| {
			if ask.len() < MAX_WITNESS && !ask.iter().any(|a| a.0 == h.0) {
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
		let answer = match self.server.witness(&heads) {
			Ok(a) => a,
			Err(e) => {
				// A rollback found before is acted on whatever the server says.
				if let Some((at, why)) = self.rolled_back()? {
					let exits = self.exit_after(at, &why)?;
					return Ok(json!({"rolled_back": {"at": at, "why": why}, "exits": exits, "server": e.to_string()}));
				}
				return Err(e);
			},
		};
		let mut found: Vec<String> = vec![];
		let mut below: Option<u64> = None;
		let top = held.first().map(|h| h.0).unwrap_or(0);
		let record_end = answer["head"]["entry"].as_u64();
		if !answer["head"].is_null() {
			match self.witness_record(&answer["head"], true) {
				Ok(()) => {},
				Err(e) => found.push(e.to_string()),
			}
		}
		let mut agrees = 0u64;
		for ((e, h, _), got) in ask.iter().zip(answer["hashes"].as_array().cloned().unwrap_or_default()) {
			if got["entry"].as_u64() != Some(*e) {
				return Err(Error::Refused("the operator's witness answers for other entries than the wallet named".into()));
			}
			match got["hash"].as_str() {
				Some(x) if x == h => agrees = agrees.max(*e),
				Some(x) => {
					found.push(format!("the record holds {} at entry {}, where the wallet holds {}", x, e, h));
					below = Some(below.map_or(*e, |b| b.min(*e)));
				},
				None if record_end.is_some_and(|end| *e > end) => {
					found.push(format!("the record ends at entry {}, before entry {} the wallet holds", record_end.unwrap_or(0), e));
					below = Some(below.map_or(*e, |b| b.min(*e)));
				},
				None => {},
			}
		}
		if let Some(why) = answer["stopped"].as_str() {
			found.push(format!("the operator's signer is stopped: {}", why));
		}
		let prior = self.rolled_back()?;
		if found.is_empty() && prior.is_none() {
			let v = json!({"witnessed": ask.len(), "record": answer["head"]});
			*self.witnessed.borrow_mut() = Some((std::time::Instant::now(), v.clone()));
			return Ok(v);
		}
		// The highest entry the record still agrees with: below any it
		// disagrees at, and below the end of a record ending below the
		// wallet's highest.
		let mut at = agrees;
		if let Some(b) = below {
			at = at.min(b.saturating_sub(1));
		}
		if let Some(end) = record_end.filter(|end| *end < top) {
			at = at.min(end);
		}
		let why = if found.is_empty() { prior.as_ref().map(|p| p.1.clone()).unwrap_or_default() } else { found.join("; ") };
		if !found.is_empty() {
			self.found_rollback(at, &why)?;
		}
		let at = self.rolled_back()?.map_or(at, |(a, _)| a);
		let exits = self.exit_after(at, &why)?;
		let v = json!({"rolled_back": {"at": at, "why": why}, "exits": exits,
			"note": "the operator's signer's record was rolled back or replaced: the wallet takes on the chain every coin a transfer \
			recorded after the entry it last agrees with made, and goes no further with this operator"});
		*self.witnessed.borrow_mut() = Some((std::time::Instant::now(), v.clone()));
		Ok(v)
	}

	/// Takes on the chain every coin the wallet holds that a transfer
	/// recorded after entry `at` of the signer's record made, or one whose
	/// entry it was never given; `why` is noted on each.
	fn exit_after(&mut self, at: u64, why: &str) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for c in self.store.coins()? {
			if c.kind != "transfer" || !HELD.contains(&c.state.as_str()) {
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
		let policy = self.receipt_policy(now);
		let before: BTreeMap<String, String> = self.store.coins()?.into_iter().map(|c| (c.leaf_id, c.state)).collect();
		let mut changes = vec![];
		let revived: Vec<String> = self.lost_boards_credited()?.into_iter().map(|c| c.leaf_id).collect();
		for c in self.store.coins()? {
			if !matches!(c.state.as_str(), "pending" | "live") && !revived.contains(&c.leaf_id) {
				continue;
			}
			let record = Self::record_of(&c)?;
			let (state, note) = match self.recheck_one(&c, &record, &policy)? {
				Checked::Holds(state, note) => (state, note),
				Checked::Lost(base) => {
					let why = format!("{} can never return to the chain: a coin it spends is spent by another transaction that is final", base);
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

	/// One coin against the chain: where it stands, or why a base the chain
	/// holds fails the wallet's checks.
	fn recheck_one(&self, c: &CoinRow, record: &CoinRecord, policy: &WalletPolicy) -> Result<Checked, Error> {
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

	/// Every coin the wallet holds or held.
	pub fn coins(&self) -> Result<Value, Error> {
		Ok(Value::Array(self.store.coins()?.iter().map(Self::coin_json).collect()))
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
		Ok(json!({
			"datadir": self.datadir.display().to_string(),
			"server": self.cfg.server, "node": self.cfg.node_url,
			"genesis_hash": self.genesis.genesis_hash().to_string(),
			"chain": self.store.meta("chain_name")?,
			"operator": self.operator.to_string(),
			"mailbox_key": self.keys.mailbox()?.x_only_public_key().0.to_string(),
			"exit_delay_units": self.cfg.exit_delay_units,
			"accepted_exit_delay_units": {"min": self.cfg.min_exit_delay_units, "max": self.cfg.max_exit_delay_units},
			"tip": {"height": tip.height, "hash": tip.hash.to_string(), "median_time": tip.median_time},
			"server_info": self.server_info().map_err(|e| e.to_string()).unwrap_or_else(|e| json!({"unreachable": e})),
		}))
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
		Ok(json!({
			"leaf_id": leaf_id, "txid": tx.txid().to_string(), "vsize": tx.vsize(), "asset": asset.to_string(),
			"value": value.to_string(), "fee": {"asset": fee_asset.to_string(), "amount": fee.to_string()},
			"state": state,
		}))
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
