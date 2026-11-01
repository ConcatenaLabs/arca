//! The tower itself: it takes deposits and withdrawals, and passes over its
//! deposits, bringing each coin on chain when its time comes.
//!
//! Its data directory holds its phrase (`mnemonic`, which holds the coins it
//! pays children with), its Bitcoin wallet (`float.sqlite`, the phrase's
//! BIP84 account) and its deposits (`deposits.json`). Its rescue fees are
//! paid to the account's first address, which its `info` names.
//!
//! It takes only what its own coins can pay for:
//! - **value:** the rescue fees of the deposits it holds never exceed its
//!   coins ([Tower::info]'s `capacity_sat`); a deposit beyond that is
//!   refused, and `short_sat` says when spent coins left it unable to pay
//!   for every deposit it holds;
//! - **count:** each child spends one confirmed coin of its own, so it
//!   brings about one exit transaction on chain per coin per block. The exit
//!   transactions of the deposits whose expiries fall within one margin of
//!   each other may not exceed its coins times half the margin
//!   ([THROUGHPUT_SHARE]), the other half left for fees to rise.
//!
//! It refuses a coin whose path out conflicts with a coin it holds (two
//! coins spending one output: only one can ever reach the chain) or is
//! already spent on chain by another transaction.
//!
//! A pass reads every deposit's state from the chain again: a rescue a reorg
//! undid goes back to `rescuing` or `claiming`, and a claim counts as final
//! once it is [CLAIM_DEPTH] blocks deep.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use bdk_wallet::KeychainKind;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Transaction, Txid};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::PublicKey;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::Full;
use bitcoin_ext::{BlockHeight, TxStatus};
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::fee::P2A_SCRIPT;

use crate::chain::{BroadcastError, ChainSource, ChainSourceSpec};
use crate::onchain::{OnchainWallet, OnchainWalletTrait};
use crate::persist::sqlite::SqliteClient;
use super::{check_claim, check_withdrawal, fee_is_worth, rescue_cost, KIND, WORTH_FACTOR};

/// The blocks an exit or claim may sit in the mempool before the tower
/// replaces its child with one paying more.
pub const STUCK_BLOCKS: u32 = 2;

/// The most deposits one tower holds.
pub const MAX_DEPOSITS: usize = 100_000;

/// The largest deposit a tower takes, in bytes of its JSON body.
pub const MAX_DEPOSIT_BYTES: usize = 256 * 1024;

/// The blocks a claim must be buried under before the tower stops watching
/// it: until then a reorg can undo it, and the tower broadcasts it again.
pub const CLAIM_DEPTH: u32 = 6;

/// The share of a margin's blocks a tower counts on to bring the deposits due
/// in it on chain: one exit transaction per coin of its own per block, for
/// half the margin.
pub const THROUGHPUT_SHARE: u32 = 2;

/// How a tower is set up.
#[derive(Debug, Clone)]
pub struct TowerConfig {
	pub network: Network,
	pub chain: ChainSourceSpec,
	/// The least rate a deposit's rescue fee must cover, in sat/vB.
	pub min_rate: FeeRate,
	/// The rate used when the chain gives no estimate (regtest).
	pub fallback_rate: Option<FeeRate>,
	/// The arks (their server keys) whose coins it takes; empty, any ark's.
	pub arks: Vec<PublicKey>,
	/// The blocks before expiry it acts at.
	pub margin: u32,
}

/// One deposit, as the tower keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
	pub vtxo: String,
	pub claim: String,
	pub vtxo_id: String,
	pub expiry: BlockHeight,
	pub fee: u64,
	/// `waiting`, `rescuing`, `claiming`, then `claimed` or `taken`.
	pub state: String,
	#[serde(default)]
	pub note: String,
	/// The txids this tower broadcast for the deposit, children included.
	#[serde(default)]
	pub broadcast: Vec<String>,
	/// The height the claim was confirmed at, while it is not yet
	/// [CLAIM_DEPTH] deep.
	#[serde(default)]
	pub claimed_at: Option<BlockHeight>,
	/// What the tower has paid in children for it so far.
	#[serde(default)]
	pub paid: u64,
}

const LIVE: [&str; 3] = ["waiting", "rescuing", "claiming"];

impl Deposit {
	fn live(&self) -> bool {
		LIVE.contains(&self.state.as_str())
	}
	/// Whether a pass still looks at it: live, or claimed and not yet buried.
	fn watched(&self, tip: BlockHeight) -> bool {
		self.live() || (self.state == "claimed"
			&& self.claimed_at.map_or(true, |h| tip < h.saturating_add(CLAIM_DEPTH - 1)))
	}
}

/// What the tower knows of the exit transactions of the coins it holds.
#[derive(Default)]
struct Paths {
	/// The exit transactions of each live deposit's coin, by the claim's txid.
	txs: std::collections::HashMap<String, (BlockHeight, Vec<Txid>)>,
	/// For every output an exit transaction spends, the transaction.
	spends: std::collections::HashMap<OutPoint, Txid>,
}

impl Paths {
	fn of(store: &Store) -> Paths {
		let mut p = Paths::default();
		for (k, d) in store.deposits.iter().filter(|(_, d)| d.live()) {
			if let Ok(v) = parse_vtxo(&d.vtxo) {
				p.add(k, &v);
			}
		}
		p
	}
	fn add(&mut self, k: &str, v: &Vtxo<Full>) {
		let mut ids = vec![];
		for t in v.transactions() {
			let txid = t.tx.compute_txid();
			for i in &t.tx.input {
				self.spends.insert(i.previous_output, txid);
			}
			ids.push(txid);
		}
		self.txs.insert(k.to_string(), (v.expiry_height(), ids));
	}
	/// A transaction of a held coin's path that spends what one of `v`'s
	/// does, differently.
	fn conflict(&self, v: &Vtxo<Full>) -> Option<(OutPoint, Txid)> {
		for t in v.transactions() {
			let txid = t.tx.compute_txid();
			for i in &t.tx.input {
				if let Some(o) = self.spends.get(&i.previous_output) {
					if *o != txid {
						return Some((i.previous_output, *o));
					}
				}
			}
		}
		None
	}
	/// The distinct exit transactions of the held coins expiring within
	/// `margin` of `expiry`, with those of `v`.
	fn due_with(&self, v: &Vtxo<Full>, margin: u32) -> usize {
		let e = v.expiry_height();
		let mut set: std::collections::HashSet<Txid> = v.transactions().map(|t| t.tx.compute_txid()).collect();
		for (x, ids) in self.txs.values() {
			if x.abs_diff(e) < margin {
				set.extend(ids.iter().copied());
			}
		}
		set.len()
	}
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
	deposits: BTreeMap<String, Deposit>,
	/// The tip at which a transaction this tower waits on was first seen
	/// in the mempool.
	#[serde(default)]
	mempool_since: BTreeMap<String, BlockHeight>,
}

pub struct Tower {
	dir: PathBuf,
	cfg: TowerConfig,
	chain: Arc<ChainSource>,
	float: OnchainWallet,
	payout: Address,
	store: Store,
	paths: Paths,
	/// The chain's fast rate at the last pass.
	fast: FeeRate,
}

fn load_store(path: &Path) -> anyhow::Result<Store> {
	match std::fs::read(path) {
		Ok(b) => serde_json::from_slice(&b).with_context(|| format!("reading {}", path.display())),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
		Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
	}
}

fn parse_vtxo(hex: &str) -> anyhow::Result<Vtxo<Full>> {
	let b = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(hex).context("the coin is not hex")?;
	Vtxo::<Full>::deserialize(&b).map_err(|e| anyhow!("the coin does not decode: {}", e))
}

impl Tower {
	/// Opens the tower in `dir`, making its phrase the first time.
	pub async fn open(dir: &Path, cfg: TowerConfig) -> anyhow::Result<Tower> {
		if !dir.exists() {
			std::fs::create_dir_all(dir).with_context(|| format!("making {}", dir.display()))?;
			// its phrase and its wallet are in it: only its owner reads them
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
			}
		}
		let mpath = dir.join("mnemonic");
		let mnemonic = match std::fs::read_to_string(&mpath) {
			Ok(s) => bip39::Mnemonic::from_str(s.trim()).context("the tower's mnemonic")?,
			Err(_) => {
				let m = bip39::Mnemonic::generate(12).context("making a mnemonic")?;
				std::fs::write(&mpath, m.to_string()).context("writing the mnemonic")?;
				#[cfg(unix)]
				{
					use std::os::unix::fs::PermissionsExt;
					std::fs::set_permissions(&mpath, std::fs::Permissions::from_mode(0o600))?;
				}
				m
			},
		};
		let db = Arc::new(SqliteClient::open(dir.join("float.sqlite"))?);
		let mut float = OnchainWallet::load_or_create_bip84(cfg.network, mnemonic.to_seed(""), db).await?;
		let payout = float.inner.peek_address(KeychainKind::External, 0).address;
		let _ = float.inner.reveal_addresses_to(KeychainKind::External, 20).count();
		let chain = Arc::new(ChainSource::new(cfg.chain.clone(), cfg.network, cfg.fallback_rate,
			#[cfg(feature = "socks5-proxy")] None).await?);
		let _ = chain.update_fee_rates(cfg.fallback_rate).await;
		let fast = chain.fee_rates().await.fast;
		let store = load_store(&dir.join("deposits.json"))?;
		let paths = Paths::of(&store);
		let mut t = Tower { dir: dir.to_path_buf(), cfg, chain, float, payout, store, paths, fast };
		if let Err(e) = t.float.sync(&t.chain).await {
			warn!("btc tower: the float did not sync: {:#}", e);
		}
		Ok(t)
	}

	fn save(&self) -> anyhow::Result<()> {
		let path = self.dir.join("deposits.json");
		let tmp = self.dir.join("deposits.json.tmp");
		std::fs::write(&tmp, serde_json::to_vec_pretty(&self.store)?)?;
		std::fs::rename(&tmp, &path)?;
		Ok(())
	}

	pub fn chain(&self) -> &Arc<ChainSource> { &self.chain }

	/// The address the tower's coins are funded at, and its rescue fees paid to.
	pub fn payout(&self) -> &Address { &self.payout }

	/// A fresh address of the tower's own account, to fund it.
	pub async fn funding_address(&mut self) -> anyhow::Result<Address> {
		self.float.address().await
	}

	/// The rate the tower prices a rescue at today.
	pub fn rate(&self) -> FeeRate {
		self.fast.max(self.cfg.min_rate)
	}

	/// The tower's own coins: those confirmed and its own change on the way.
	fn float_sat(&self) -> Amount {
		let b = self.float.balance();
		b.confirmed + b.trusted_pending
	}

	/// What the deposits it holds may still cost it: each one's rescue fee,
	/// less what it has paid for it already.
	fn committed(&self) -> Amount {
		Amount::from_sat(self.store.deposits.values().filter(|d| d.live()).map(|d| d.fee.saturating_sub(d.paid)).sum())
	}

	/// The confirmed coins of its own that can each pay a child at its rate.
	fn float_coins(&self) -> usize {
		let child = self.rate().to_sat_per_vb_ceil().saturating_mul(super::CHILD_VB) + 330;
		self.float.list_unspent().iter()
			.filter(|u| u.chain_position.is_confirmed() && u.txout.value.to_sat() >= child).count()
	}

	/// The exit transactions it can bring on chain within one margin.
	fn exits_per_margin(&self) -> usize {
		self.float_coins().saturating_mul((self.cfg.margin / THROUGHPUT_SHARE) as usize)
	}

	/// What a wallet reads before depositing: its terms, and what its own
	/// coins can still pay for.
	pub async fn info(&self) -> Value {
		let live = self.store.deposits.values().filter(|d| d.live()).count();
		let (float, committed) = (self.float_sat(), self.committed());
		json!({
			"kind": KIND,
			"network": self.cfg.network.to_string(),
			"payout": self.payout.to_string(),
			"min_rate_sat_vb": self.cfg.min_rate.to_sat_per_vb_ceil(),
			"rate_sat_vb": self.rate().to_sat_per_vb_ceil(),
			"margin": self.cfg.margin,
			"worth_factor": WORTH_FACTOR,
			"arks": self.cfg.arks.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
			"deposits": live,
			"float_sat": float.to_sat(),
			"committed_sat": committed.to_sat(),
			"capacity_sat": float.checked_sub(committed).unwrap_or(Amount::ZERO).to_sat(),
			"short_sat": committed.checked_sub(float).unwrap_or(Amount::ZERO).to_sat(),
			"float_coins": self.float_coins(),
			"exits_per_margin": self.exits_per_margin(),
		})
	}

	/// Every deposit and its state.
	pub fn deposits(&self) -> Value {
		json!(self.store.deposits.iter().map(|(k, d)| json!({
			"claim_txid": k, "vtxo": d.vtxo_id, "expiry": d.expiry, "fee": d.fee, "state": d.state,
			"note": d.note, "broadcast": d.broadcast,
		})).collect::<Vec<_>>())
	}

	/// Takes a deposit `{"vtxo", "claim"}`: the coin's signatures checked
	/// against its anchor on chain, the claim against the coin. A deposit
	/// for a coin the tower already holds a claim for replaces it.
	pub async fn deposit(&mut self, body: &Value) -> anyhow::Result<Value> {
		let vtxo = parse_vtxo(body["vtxo"].as_str().context("refused: no vtxo")?)
			.map_err(|e| anyhow!("refused: {:#}", e))?;
		let claim: Transaction = deserialize_hex(body["claim"].as_str().context("refused: no claim")?)
			.map_err(|e| anyhow!("refused: the claim does not decode: {}", e))?;
		if !self.cfg.arks.is_empty() && !self.cfg.arks.contains(&vtxo.server_pubkey()) {
			bail!("refused: this tower does not watch that coin's ark");
		}
		let tip = self.chain.tip().await?;
		if vtxo.expiry_height() <= tip {
			bail!("refused: the coin expired at {} (tip {})", vtxo.expiry_height(), tip);
		}
		let anchor = vtxo.chain_anchor();
		let anchor_tx = self.chain.get_tx(&anchor.txid).await?
			.with_context(|| format!("refused: the coin's anchor {} is not on chain", anchor.txid))?;
		vtxo.validate(&anchor_tx).map_err(|e| anyhow!("refused: the coin does not validate: {}", e))?;
		let min_fee = rescue_cost(&vtxo, self.cfg.min_rate)?;
		let paid = check_claim(&vtxo, &claim, &self.payout.script_pubkey(), min_fee)
			.map_err(|e| anyhow!("refused: {}", e))?;
		if !fee_is_worth(vtxo.amount(), paid) {
			bail!("refused: the rescue fee {} is more than 1/{} of the coin ({}): it is not worth rescuing",
				paid, WORTH_FACTOR, vtxo.amount());
		}
		let txid = claim.compute_txid().to_string();
		let id = vtxo.id().to_string();
		if self.store.deposits.contains_key(&txid) {
			return Ok(json!({"deposited": txid, "vtxo": id, "fee": paid.to_sat(), "replaced": 0,
				"acts_at": vtxo.expiry_height().saturating_sub(self.cfg.margin)}));
		}
		// the deposits this one would replace: the same coin's, still waiting
		let old: Vec<String> = self.store.deposits.iter()
			.filter(|(k, d)| d.vtxo_id == id && **k != txid && d.state == "waiting")
			.map(|(k, _)| k.clone()).collect();
		// a deposit it replaces is of the same coin, so its way out is the same
		if let Some((o, t)) = self.paths.conflict(&vtxo) {
			bail!("refused: the coin's way out spends {} differently from a coin the tower holds ({}): only one of them can reach the chain", o, t);
		}
		self.check_unspent(&vtxo).await?;
		let freed: u64 = old.iter().filter_map(|k| self.store.deposits.get(k)).map(|d| d.fee.saturating_sub(d.paid)).sum();
		let cap = (self.float_sat() + Amount::from_sat(freed)).checked_sub(self.committed()).unwrap_or(Amount::ZERO);
		if paid > cap {
			bail!("refused: the tower's coins can pay for {} more and this rescue costs {}: it cannot take it", cap, paid);
		}
		let due = self.paths.due_with(&vtxo, self.cfg.margin);
		let can = self.exits_per_margin();
		if due > can {
			bail!("refused: with this coin, {} exit transactions come due within {} blocks and the tower's {} coins bring about {} on chain in that time: it cannot take it",
				due, self.cfg.margin, self.float_coins(), can);
		}
		let replaced = old.len();
		for k in &old {
			self.store.deposits.remove(k);
			self.paths.txs.remove(k);
		}
		{
			if self.store.deposits.len() >= MAX_DEPOSITS {
				bail!("refused: the tower is full");
			}
			self.store.deposits.insert(txid.clone(), Deposit {
				vtxo: body["vtxo"].as_str().unwrap_or_default().to_string(),
				claim: serialize_hex(&claim),
				vtxo_id: id.clone(),
				expiry: vtxo.expiry_height(),
				fee: paid.to_sat(),
				state: "waiting".into(),
				note: String::new(),
				broadcast: vec![],
				claimed_at: None,
				paid: 0,
			});
		}
		self.paths.add(&txid, &vtxo);
		self.save()?;
		Ok(json!({"deposited": txid, "vtxo": id, "fee": paid.to_sat(), "replaced": replaced, "acts_at": vtxo.expiry_height().saturating_sub(self.cfg.margin)}))
	}

	/// Drops the deposit `{"claim_txid", "sig"}` names, the signature by its
	/// coin's key. A deposit the tower does not hold is reported, not refused.
	pub fn withdraw(&mut self, body: &Value) -> anyhow::Result<Value> {
		let txid = body["claim_txid"].as_str().and_then(|t| Txid::from_str(t).ok())
			.context("refused: no claim_txid")?;
		let sig = body["sig"].as_str().context("refused: no sig")?;
		let Some(d) = self.store.deposits.get(&txid.to_string()) else {
			return Ok(json!({"withdrawn": false, "reason": "no such deposit"}));
		};
		let vtxo = parse_vtxo(&d.vtxo)?;
		let pk = vtxo.user_pubkey().x_only_public_key().0;
		check_withdrawal(self.cfg.network, &pk, &txid, sig).map_err(|e| anyhow!("refused: {}", e))?;
		if d.state != "waiting" {
			return Ok(json!({"withdrawn": false, "reason": format!("the rescue has started ({})", d.state)}));
		}
		self.store.deposits.remove(&txid.to_string());
		self.paths = Paths::of(&self.store);
		self.save()?;
		Ok(json!({"withdrawn": true}))
	}

	async fn status(&self, txid: Txid) -> anyhow::Result<TxStatus> {
		self.chain.tx_status(txid).await
	}

	/// Refuses a coin whose way out is already spent on chain by another
	/// transaction: the output under the first of its transactions not yet
	/// confirmed, or the coin's own output once all are.
	async fn check_unspent(&self, vtxo: &Vtxo<Full>) -> anyhow::Result<()> {
		let txs: Vec<Transaction> = vtxo.transactions().map(|i| i.tx).collect();
		for t in &txs {
			if let TxStatus::Confirmed(_) = self.status(t.compute_txid()).await? {
				continue;
			}
			for i in &t.input {
				if let TxStatus::Confirmed(_) = self.status(i.previous_output.txid).await? {
					if self.chain.outpoint_spent_confirmed(i.previous_output).await? {
						bail!("refused: {} on the coin's way out is spent on chain by another transaction", i.previous_output);
					}
				}
			}
			return Ok(());
		}
		if self.chain.outpoint_spent_confirmed(vtxo.point()).await? {
			bail!("refused: the coin's output {} is spent on chain", vtxo.point());
		}
		Ok(())
	}

	fn p2a_point(tx: &Transaction) -> Option<OutPoint> {
		tx.output.iter().position(|o| o.script_pubkey == *P2A_SCRIPT)
			.map(|i| OutPoint::new(tx.compute_txid(), i as u32))
	}

	/// Broadcasts `tx` with a child spending its anchor, paid at `fees` from
	/// the tower's own confirmed coins, for the deposit `k`, which it counts
	/// as paid (a replacement, only what it adds). Returns the child's txid.
	async fn push(&mut self, k: &str, tx: &Transaction, fees: MakeCpfpFees) -> Result<Txid, BroadcastError> {
		let replaced = match &fees {
			MakeCpfpFees::Rbf { current_package_fee, .. } => *current_package_fee,
			_ => Amount::ZERO,
		};
		let child = self.float.make_signed_p2a_cpfp(tx, fees).await
			.map_err(|e| BroadcastError::Other(format!("cannot pay a child: {}", e)))?;
		self.chain.broadcast_package(&[tx, &child]).await?;
		let fee = self.float.inner.calculate_fee(&child).unwrap_or(Amount::ZERO);
		let _ = self.float.store_signed_p2a_cpfp(&child).await;
		if let Some(d) = self.store.deposits.get_mut(k) {
			d.paid = d.paid.saturating_add(fee.checked_sub(replaced).unwrap_or(Amount::ZERO).to_sat());
		}
		Ok(child.compute_txid())
	}

	/// Replaces the child of `tx`, waiting in the mempool, with one paying
	/// more: at least the fast rate and above the package now waiting.
	async fn bump(&mut self, k: &str, tx: &Transaction, fast: FeeRate) -> anyhow::Result<Option<Txid>> {
		let Some(anchor) = Self::p2a_point(tx) else { return Ok(None) };
		let tip = self.chain.tip().await?;
		let spends = self.chain.txs_spending_inputs([anchor], tip).await?;
		let Some((child, TxStatus::Mempool)) = spends.get(&anchor).cloned() else { return Ok(None) };
		let info = self.chain.mempool_ancestor_info(child).await?;
		let now = info.effective_fee_rate().unwrap_or(FeeRate::BROADCAST_MIN);
		let rate = FeeRate::from_sat_per_kwu(now.to_sat_per_kwu().saturating_mul(2)).max(fast);
		let fees = MakeCpfpFees::Rbf { min_effective_fee_rate: rate, current_package_fee: info.total_fee };
		match self.push(k, tx, fees).await {
			Ok(t) => Ok(Some(t)),
			Err(e) => Err(anyhow!("{}", e)),
		}
	}

	/// Whether `point` is spent, in a block or the mempool, by another
	/// transaction than `ours`.
	async fn spent_elsewhere(&self, point: OutPoint, ours: &Transaction) -> anyhow::Result<bool> {
		let from = match self.status(point.txid).await? {
			TxStatus::Confirmed(b) => b.height,
			_ => self.chain.tip().await?,
		};
		let r = self.chain.txs_spending_inputs([point], from).await?;
		Ok(r.get(&point).is_some_and(|(t, _)| *t != ours.compute_txid()))
	}

	/// One pass over every deposit still to act on. Returns what it did.
	pub async fn pass(&mut self) -> anyhow::Result<Value> {
		// Every pass reads the chain as it is now: the source's cached tip
		// can lag by blocks, and a pass acts at exact heights.
		self.chain.invalidate_caches().await;
		let _ = self.chain.update_fee_rates(self.cfg.fallback_rate).await;
		let fast = self.chain.fee_rates().await.fast;
		self.fast = fast;
		let tip = self.chain.tip().await?;
		if let Err(e) = self.float.sync(&self.chain).await {
			warn!("btc tower: the float did not sync: {:#}", e);
		}
		let keys: Vec<String> = self.store.deposits.iter()
			.filter(|(_, d)| d.watched(tip))
			.map(|(k, _)| k.clone()).collect();
		let mut acted = vec![];
		for k in keys {
			match self.one(&k, tip, fast).await {
				Ok(Some(v)) => acted.push(v),
				Ok(None) => {},
				Err(e) => {
					warn!("btc tower: deposit {}: {:#}", k, e);
					if let Some(d) = self.store.deposits.get_mut(&k) { d.note = format!("{:#}", e); }
				},
			}
		}
		self.paths = Paths::of(&self.store);
		self.save()?;
		Ok(json!({"tip": tip, "acted": acted}))
	}

	fn note(&mut self, k: &str, state: Option<&str>, note: String, txids: &[Txid]) {
		if let Some(d) = self.store.deposits.get_mut(k) {
			if let Some(s) = state { d.state = s.into(); }
			d.note = note;
			d.broadcast.extend(txids.iter().map(|t| t.to_string()));
		}
	}

	/// Whether `tx` has waited in the mempool long enough to be bumped.
	fn stuck(&mut self, txid: Txid, tip: BlockHeight) -> bool {
		let since = *self.store.mempool_since.entry(txid.to_string()).or_insert(tip);
		tip >= since + STUCK_BLOCKS
	}

	async fn one(&mut self, k: &str, tip: BlockHeight, fast: FeeRate) -> anyhow::Result<Option<Value>> {
		let d = self.store.deposits.get(k).cloned().context("gone")?;
		let vtxo = parse_vtxo(&d.vtxo)?;
		let claim: Transaction = deserialize_hex(&d.claim).map_err(|e| anyhow!("claim: {}", e))?;
		let txs: Vec<Transaction> = vtxo.transactions().map(|i| i.tx).collect();
		let mut st = Vec::with_capacity(txs.len());
		for t in &txs {
			st.push(self.status(t.compute_txid()).await?);
		}
		let on = |s: &TxStatus| !matches!(s, TxStatus::NotFound);

		// A reorg can undo what was confirmed, and the mempool can then drop
		// it: read the state from the chain again.
		if d.state == "claimed" {
			match self.status(claim.compute_txid()).await? {
				TxStatus::Confirmed(b) => {
					if let Some(x) = self.store.deposits.get_mut(k) { x.claimed_at = Some(b.height); }
					return Ok(None);
				},
				_ => {
					warn!("btc tower: {}'s claim is no longer confirmed (a reorg): claiming again", d.vtxo_id);
					if let Some(x) = self.store.deposits.get_mut(k) { x.claimed_at = None; }
					self.note(k, Some("claiming"), "the claim was undone by a reorg".into(), &[]);
				},
			}
		}
		if self.store.deposits[k].state == "claiming" && st.iter().any(|s| !on(s)) {
			warn!("btc tower: {}'s exit is no longer on chain (a reorg): rescuing again", d.vtxo_id);
			self.note(k, Some("rescuing"), "the exit was undone by a reorg".into(), &[]);
		}

		if d.state == "waiting" {
			let due = tip.saturating_add(self.cfg.margin) >= vtxo.expiry_height();
			let lineage = vtxo.arkoor_levels().into_iter()
				.find(|&i| i > 0 && on(&st[i - 1]) && !on(&st[i]));
			let why = if let Some(i) = lineage {
				format!("an earlier holder's coin is on chain (level {}): answering", i - 1)
			} else if due {
				format!("{} blocks to expiry", vtxo.expiry_height().saturating_sub(tip))
			} else {
				return Ok(None);
			};
			info!("btc tower: rescuing {} ({})", d.vtxo_id, why);
			self.note(k, Some("rescuing"), why, &[]);
		}

		let state = self.store.deposits[k].state.clone();
		if state == "rescuing" {
			let Some(i) = st.iter().position(|s| !matches!(s, TxStatus::Confirmed(_))) else {
				self.note(k, Some("claiming"), "the coin's output is on chain".into(), &[]);
				return Box::pin(self.one(k, tip, fast)).await;
			};
			let txid = txs[i].compute_txid();
			if let TxStatus::Mempool = st[i] {
				if self.stuck(txid, tip) {
					if let Some(c) = self.bump(k, &txs[i], fast).await? {
						self.store.mempool_since.insert(txid.to_string(), tip);
						self.note(k, None, format!("level {} was stuck: its child replaced", i), &[c]);
						return Ok(Some(json!({"vtxo": d.vtxo_id, "bumped": txid.to_string(), "level": i, "child": c.to_string()})));
					}
				}
				return Ok(None);
			}
			if i > 0 && !matches!(st[i - 1], TxStatus::Confirmed(_)) {
				return Ok(None);
			}
			return match self.push(k, &txs[i], MakeCpfpFees::Effective(fast)).await {
				Ok(c) => {
					self.store.mempool_since.insert(txid.to_string(), tip);
					self.note(k, None, format!("level {} of {} broadcast", i, txs.len()), &[txid, c]);
					Ok(Some(json!({"vtxo": d.vtxo_id, "level": i, "tx": txid.to_string(), "child": c.to_string()})))
				},
				Err(BroadcastError::AlreadyKnown) => Ok(None),
				Err(BroadcastError::MissingOrSpentInputs) if self.spent_elsewhere(txs[i].input[0].previous_output, &txs[i]).await? => {
					let why = format!("level {}'s input was spent by another transaction: the coin is not this deposit's to rescue", i);
					self.note(k, Some("taken"), why.clone(), &[]);
					Ok(Some(json!({"vtxo": d.vtxo_id, "taken": why})))
				},
				Err(e) => Err(anyhow!("level {}: {}", i, e)),
			};
		}

		if state == "claiming" {
			let ctxid = claim.compute_txid();
			match self.status(ctxid).await? {
				TxStatus::Confirmed(b) => {
					if let Some(x) = self.store.deposits.get_mut(k) { x.claimed_at = Some(b.height); }
					self.note(k, Some("claimed"), format!("claimed in block {}", b.height), &[]);
					return Ok(Some(json!({"vtxo": d.vtxo_id, "claimed": ctxid.to_string(), "height": b.height})));
				},
				TxStatus::Mempool => {
					if self.stuck(ctxid, tip) {
						if let Some(c) = self.bump(k, &claim, fast).await? {
							self.store.mempool_since.insert(ctxid.to_string(), tip);
							self.note(k, None, "the claim was stuck: its child replaced".into(), &[c]);
							return Ok(Some(json!({"vtxo": d.vtxo_id, "bumped": ctxid.to_string(), "child": c.to_string()})));
						}
					}
					return Ok(None);
				},
				TxStatus::NotFound => {},
			}
			let TxStatus::Confirmed(at) = st.last().cloned().context("no exit transactions")? else {
				return Ok(None);
			};
			let ready = at.height.saturating_add(vtxo.exit_delta() as BlockHeight);
			if tip.saturating_add(1) < ready {
				return Ok(None);
			}
			return match self.push(k, &claim, MakeCpfpFees::Effective(fast)).await {
				Ok(c) => {
					self.store.mempool_since.insert(ctxid.to_string(), tip);
					self.note(k, None, "the claim broadcast".into(), &[ctxid, c]);
					Ok(Some(json!({"vtxo": d.vtxo_id, "claim": ctxid.to_string(), "child": c.to_string()})))
				},
				Err(BroadcastError::AlreadyKnown) => Ok(None),
				Err(BroadcastError::MissingOrSpentInputs) if self.spent_elsewhere(vtxo.point(), &claim).await? => {
					let why = "the coin's output was spent by another transaction (its holder's own claim, or a forfeit)".to_string();
					self.note(k, Some("taken"), why.clone(), &[]);
					Ok(Some(json!({"vtxo": d.vtxo_id, "taken": why})))
				},
				Err(e) => Err(anyhow!("claim: {}", e)),
			};
		}
		Ok(None)
	}

	/// The tower's own coins.
	pub async fn balance(&self) -> Amount {
		self.float.balance().total()
	}

	/// Calls by name, as the HTTP service routes them.
	pub async fn call(&mut self, call: &str, body: &Value) -> anyhow::Result<Value> {
		match call {
			"info" => Ok(self.info().await),
			"deposit" => self.deposit(body).await,
			"withdraw" => self.withdraw(body),
			_ => bail!("refused: no call {}", call),
		}
	}
}
