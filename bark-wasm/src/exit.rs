//! Taking coins out of the ark alone: Bark's unilateral exit, its fees paid
//! from the phrase's own Bitcoin coins.
//!
//! A coin's exit is already signed: every transaction from the round down to
//! the coin carries its signatures, so the wallet broadcasts them without the
//! server. Each is a zero-fee transaction with a pay-to-anchor output, so each
//! needs a child paying its fee, and a child spends only confirmed coins. The
//! children are paid from the phrase's BIP84 account (`m/84'/coin'/0'`), the
//! account a dual-chain wallet keeps its BTC in at its shared address: Bark is
//! given that account as its onchain wallet ([attach_funding]), so no second
//! wallet is funded. Once the coin's own output is on the chain and its exit
//! delta has passed, the wallet claims it to the holder's Bitcoin address.
//!
//! An exit costs Bitcoin fees for every transaction above the coin, about
//! 1,700 vB for a coin of a round of 64. A coin worth less than that is not
//! offered: [run] refuses it in words.
//!
//! `exit_auto` is the one rule every wallet's default mode follows: it starts an
//! exit only when the ark has refused or cannot be reached, for the coins worth
//! their exit that are within [EXIT_MARGIN] blocks of their expiry.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};

use bark::ark::bitcoin::{self, Amount, Network};
use bark::ark::bitcoin::bip32::Fingerprint;
use bark::ark::VtxoId;
use bark::exit::{ExitError, ExitState, ExitStateKind};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;
use bark::vtxo::VtxoStateKind;
use bark::{OpenWalletArgs, Wallet};

/// The blocks before a coin's expiry from which default mode takes it out of an
/// ark that refuses it or cannot be reached: a day, one block per level of the
/// coin's exit with room for fees to rise.
pub const EXIT_MARGIN: u32 = 144;

/// A coin is worth its exit when what reaches the holder's address is more
/// than this after every fee.
const WORTH_MARGIN_SAT: u64 = 330;

/// The commands of this module.
pub const COMMANDS: &[&str] = &["exit_estimate", "exit_start", "exit_progress", "exit_claim", "exit_status", "exit_auto"];

type Funding = Arc<tokio::sync::RwLock<OnchainWallet>>;

/// The funding wallet of each open wallet, and those scanned since this
/// program started.
static FUNDING: Mutex<Option<HashMap<Fingerprint, Funding>>> = Mutex::new(None);
static SCANNED: Mutex<Option<HashSet<Fingerprint>>> = Mutex::new(None);
/// Wallets whose server refused them last time it was asked.
static REFUSED: Mutex<Option<HashSet<Fingerprint>>> = Mutex::new(None);

/// Gives the wallet about to be opened with `args` the phrase's BIP84 account
/// as its onchain wallet, which pays its exits' fees. Call it before
/// [bark::Wallet::open], with the same `network` and phrase.
pub async fn attach_funding(args: &mut OpenWalletArgs, network: Network, mnemonic: &str) -> anyhow::Result<()> {
	let m = bark::bip39::Mnemonic::from_str(mnemonic.trim()).context("the phrase is not a valid mnemonic")?;
	let fp = bark::WalletSeed::new_from_mnemonic(network, &m).fingerprint();
	let db: Arc<dyn BarkPersister> = match args.persister.clone() {
		Some(p) => p,
		None => {
			#[cfg(not(target_arch = "wasm32"))]
			if let Some(d) = args.datadir.as_ref() {
				std::fs::create_dir_all(d).with_context(|| format!("making {}", d.display()))?;
			}
			bark::persist::platform_default(args.datadir.clone(), Some(fp)).await?
		},
	};
	args.persister = Some(db.clone());
	let w = OnchainWallet::load_or_create_bip84(network, m.to_seed(""), db).await?;
	let w: Funding = Arc::new(tokio::sync::RwLock::new(w));
	FUNDING.lock().unwrap().get_or_insert_with(HashMap::new).insert(fp, w.clone());
	args.onchain = Some(w);
	Ok(())
}

fn funding(wallet: &Wallet) -> anyhow::Result<Funding> {
	FUNDING.lock().unwrap().as_ref().and_then(|m| m.get(&wallet.fingerprint()).cloned())
		.ok_or_else(|| anyhow!("this wallet was opened without its Bitcoin coins, so it cannot pay an exit"))
}

/// Brings the funding wallet up to the chain: the whole account the first time
/// in this program, its known addresses after.
async fn sync_funding(wallet: &Wallet) -> anyhow::Result<Funding> {
	let f = funding(wallet)?;
	let fp = wallet.fingerprint();
	let first = SCANNED.lock().unwrap().get_or_insert_with(HashSet::new).insert(fp);
	let mut w = f.write().await;
	let fresh = w.inner.latest_checkpoint().height() == 0;
	let r = if first && (fresh || wallet.config().esplora_address.is_some()) {
		w.initial_wallet_scan(wallet.chain(), None).await.map(|_| ())
	} else {
		w.sync(wallet.chain()).await
	};
	if let Err(e) = r {
		SCANNED.lock().unwrap().as_mut().map(|s| s.remove(&fp));
		return Err(e.context("reading the wallet's Bitcoin coins"));
	}
	drop(w);
	Ok(f)
}

/// Notes whether the server last refused this wallet: `refresh` and
/// `schedule_refreshes` call it with their outcome.
pub fn note_server(wallet: &Wallet, refused: bool) {
	let mut g = REFUSED.lock().unwrap();
	let s = g.get_or_insert_with(HashSet::new);
	if refused { s.insert(wallet.fingerprint()); } else { s.remove(&wallet.fingerprint()); }
}

fn sat(a: Amount) -> String { a.to_sat().to_string() }

fn btc_address(wallet_net: Network, s: &str) -> anyhow::Result<bitcoin::Address> {
	let a = bitcoin::Address::from_str(s).context("not a Bitcoin address")?;
	a.require_network(wallet_net).context("the address is for another Bitcoin network")
}

/// The wallet's coins an exit can take: in the ark, or held for a payment or a
/// scheduled renewal, and not already leaving.
async fn exitable(wallet: &Wallet) -> anyhow::Result<Vec<bark::vtxo::WalletVtxo>> {
	let exiting = wallet.exit_mgr().get_exit_vtxo_ids().await;
	Ok(wallet.vtxos().await?.into_iter()
		.filter(|v| VtxoStateKind::UNSPENT_STATES.contains(&v.state.kind()))
		.filter(|v| !exiting.contains(&v.vtxo.id()))
		.collect())
}

/// One coin's exit, priced alone.
struct Priced {
	id: VtxoId,
	amount: Amount,
	expiry: u32,
	cost: Option<Amount>,
	why_not: Option<String>,
}

impl Priced {
	fn worth(&self) -> bool {
		match self.cost {
			Some(c) => self.amount > c + Amount::from_sat(WORTH_MARGIN_SAT),
			None => false,
		}
	}

	fn json(&self, tip: u32) -> Value {
		json!({
			"id": self.id.to_string(),
			"amount": sat(self.amount),
			"expiry_height": self.expiry,
			"blocks_left": self.expiry as i64 - tip as i64,
			"cost": self.cost.map(sat),
			"worth": self.worth(),
			"why_not": self.why_not.clone().or_else(|| if self.worth() { None } else {
				self.cost.map(|c| not_worth_words(self.amount, c))
			}),
		})
	}
}

fn not_worth_words(amount: Amount, cost: Amount) -> String {
	format!("This coin holds {} sat; taking it out of the ark alone would cost about {} sat in Bitcoin fees, \
		so it stays in the ark, where it is renewed.", amount.to_sat(), cost.to_sat())
}

async fn price(wallet: &Wallet, coins: &[bark::vtxo::WalletVtxo]) -> Vec<Priced> {
	let mut out = Vec::with_capacity(coins.len());
	for c in coins {
		let id = c.vtxo.id();
		let (cost, why_not) = match wallet.exit_mgr().estimate_emergency_exit_fee(&[id], wallet, None, None).await {
			Ok(e) => (Some(e.total()), None),
			Err(ExitError::DustLimit { .. }) | Err(ExitError::NonStandardVtxo { .. }) =>
				(None, Some("This coin is too small to go on the Bitcoin chain by itself; it stays in the ark, where it is renewed.".to_owned())),
			Err(e) => (None, Some(format!("This coin's exit cannot be priced: {}", e))),
		};
		out.push(Priced { id, amount: c.vtxo.amount(), expiry: c.vtxo.expiry_height(), cost, why_not });
	}
	out
}

/// The confirmed BTC the funding wallet holds.
async fn funding_confirmed(f: &Funding) -> Amount {
	f.read().await.inner.balance().confirmed
}

/// The holder's Bitcoin address holds too little confirmed BTC to pay an
/// exit's fees as it goes.
#[derive(Debug)]
struct Unfunded {
	needed: Amount,
	available: Amount,
}

impl std::fmt::Display for Unfunded {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "refused: taking these coins out needs about {} sat of confirmed BTC at your Bitcoin address \
			to pay the Bitcoin fees as it goes; it holds {} sat. Nothing was started.",
			self.needed.to_sat(), self.available.to_sat())
	}
}

impl std::error::Error for Unfunded {}

/// Starts the exits of `ids`, all worth their exit, refused in words when the
/// holder's Bitcoin address holds too little confirmed BTC to pay their fees.
async fn start(wallet: &Wallet, f: &Funding, coins: &[bark::vtxo::WalletVtxo], ids: &[VtxoId]) -> anyhow::Result<Value> {
	let est = wallet.exit_mgr().estimate_emergency_exit_fee(ids, wallet, None, None).await
		.map_err(|e| anyhow!("refused: the exit cannot be priced: {}", e))?;
	if !est.fundable {
		let have = funding_confirmed(f).await;
		return Err(Unfunded { needed: est.exit_broadcast_fee, available: have }.into());
	}
	let chosen = coins.iter().filter(|c| ids.contains(&c.vtxo.id())).map(|c| c.vtxo.clone()).collect::<Vec<_>>();
	wallet.exit_mgr().start_exit_for_vtxos(&chosen).await?;
	let progress = wallet.exit_mgr().progress_exits_with_cpfp(wallet, None).await?;
	Ok(json!({
		"started": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
		"amount": sat(chosen.iter().map(|v| v.amount()).sum()),
		"fees": sat(est.exit_broadcast_fee),
		"claim_fee": sat(est.claim_fee),
		"cost": sat(est.total()),
		"transactions": est.txs_to_broadcast,
		"exits": statuses(progress.unwrap_or_default()),
	}))
}

fn state_name(s: &ExitState) -> &'static str {
	match s.kind() {
		ExitStateKind::Start => "starting",
		ExitStateKind::Processing => "on_its_way",
		ExitStateKind::AwaitingDelta => "waiting_out_its_delay",
		ExitStateKind::Claimable => "claimable",
		ExitStateKind::ClaimInProgress => "claiming",
		ExitStateKind::Claimed => "claimed",
		ExitStateKind::VtxoAlreadySpent => "spent_elsewhere",
		ExitStateKind::Canceled => "canceled",
	}
}

fn statuses(s: Vec<bark::exit::ExitProgressStatus>) -> Vec<Value> {
	s.into_iter().map(|p| json!({
		"id": p.vtxo_id.to_string(),
		"state": state_name(&p.state),
		"claimable_height": p.state.claimable_height(),
		"error": p.error.map(|e| match e {
			ExitError::InsufficientConfirmedFunds { needed, available } => format!(
				"Waiting for confirmed BTC at your Bitcoin address to pay the next Bitcoin fee: \
				it needs {} sat, {} sat is confirmed.", needed.to_sat(), available.to_sat()),
			e => e.to_string(),
		}),
	})).collect()
}

/// Claims every exit whose coin can be claimed to `address`. -> txid and amount, or null.
async fn claim(wallet: &Wallet, address: &bitcoin::Address) -> anyhow::Result<Option<Value>> {
	let claimable = wallet.exit_mgr().list_claimable().await;
	if claimable.is_empty() {
		return Ok(None);
	}
	let psbt = wallet.exit_mgr().drain_exits(&claimable, wallet, address.clone(), None).await
		.map_err(|e| anyhow!("the claim could not be made: {}", e))?;
	let tx = psbt.extract_tx().context("the claim does not finalise")?;
	wallet.chain().broadcast_tx(&tx).await.context("the claim was not accepted by the Bitcoin network")?;
	// The wallet learns the claim from the chain; tell it now.
	if let Some(o) = wallet.onchain() { let _ = o.write().await.register_tx(&tx).await; }
	Ok(Some(json!({
		"txid": tx.compute_txid().to_string(),
		"address": address.to_string(),
		"amount": sat(tx.output.iter().map(|o| o.value).sum()),
		"coins": claimable.iter().map(|e| e.id().to_string()).collect::<Vec<_>>(),
	})))
}

/// Moves every exit on, then claims to `address` what can be claimed.
async fn progress(wallet: &Wallet, address: &bitcoin::Address) -> anyhow::Result<Value> {
	let s = wallet.exit_mgr().progress_exits_with_cpfp(wallet, None).await?.unwrap_or_default();
	let claimed = claim(wallet, address).await?;
	let live = wallet.exit_mgr().get_exit_vtxos().await;
	Ok(json!({
		"exits": statuses(s),
		"claimed": claimed,
		"pending": live.iter().filter(|e| !matches!(e.state(), ExitState::Claimed(_))).count(),
		"claimable_at": wallet.exit_mgr().all_claimable_at_height().await,
	}))
}

fn ids_arg(args: &Value) -> anyhow::Result<Option<Vec<VtxoId>>> {
	match args.get("vtxos") {
		None | Some(Value::Null) => Ok(None),
		Some(Value::Array(a)) => a.iter().map(|v| v.as_str().context("a coin id is not text")
			.and_then(|s| VtxoId::from_str(s).map_err(|_| anyhow!("'{}' is not a coin id", s))))
			.collect::<anyhow::Result<Vec<_>>>().map(Some),
		Some(_) => bail!("'vtxos' is not a list of coin ids"),
	}
}

/// Where a claim goes: `address`, or else the holder's own first Bitcoin
/// address (`m/84'/coin'/0'/0/0`), the one its wallet shows on both chains.
async fn address_arg(wallet: &Wallet, net: Network, args: &Value) -> anyhow::Result<bitcoin::Address> {
	match args.get("address").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
		Some(s) => btc_address(net, s),
		None => Ok(funding(wallet)?.read().await.inner
			.peek_address(bark::onchain::bdk_wallet::KeychainKind::External, 0).address),
	}
}

/// Runs one exit command.
pub async fn run(wallet: &Wallet, cmd: &str, args: &Value) -> anyhow::Result<Value> {
	let net = wallet.properties().await?.network;
	match cmd {
		// Each coin's exit priced alone: its cost in Bitcoin fees, whether it is
		// worth it and, when not, why in words; and what the holder's address holds.
		"exit_estimate" => {
			let f = sync_funding(wallet).await?;
			let tip = wallet.chain().tip().await?;
			let mut coins = exitable(wallet).await?;
			if let Some(ids) = ids_arg(args)? { coins.retain(|c| ids.contains(&c.vtxo.id())); }
			let priced = price(wallet, &coins).await;
			let worth = priced.iter().filter(|p| p.worth()).map(|p| p.id).collect::<Vec<_>>();
			let together = if worth.is_empty() { None } else {
				wallet.exit_mgr().estimate_emergency_exit_fee(&worth, wallet, None, None).await.ok()
			};
			Ok(json!({
				"tip": tip,
				"address": address_arg(wallet, net, &json!({})).await?.to_string(),
				"fee_rate": wallet.exit_mgr().default_exit_fee_rate().await.to_sat_per_vb_ceil(),
				"funding_confirmed": sat(funding_confirmed(&f).await),
				"coins": priced.iter().map(|p| p.json(tip)).collect::<Vec<_>>(),
				"worth": together.map(|e| json!({
					"vtxos": worth.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
					"fees": sat(e.exit_broadcast_fee), "claim_fee": sat(e.claim_fee), "cost": sat(e.total()),
					"transactions": e.txs_to_broadcast, "fundable": e.fundable,
				})),
			}))
		},
		// Starts the exit of `vtxos`, or of every coin worth its exit. A coin not
		// worth it, or fees the holder's address cannot pay, is refused in words.
		"exit_start" => {
			let f = sync_funding(wallet).await?;
			let coins = exitable(wallet).await?;
			let ids = match ids_arg(args)? {
				Some(ids) => {
					for id in &ids {
						if !coins.iter().any(|c| c.vtxo.id() == *id) {
							bail!("refused: coin {} is not in the ark, or is already leaving it", id);
						}
					}
					let chosen = coins.iter().filter(|c| ids.contains(&c.vtxo.id())).cloned().collect::<Vec<_>>();
					for p in price(wallet, &chosen).await {
						if !p.worth() {
							bail!("refused: {}", p.why_not.clone().unwrap_or_else(|| not_worth_words(p.amount, p.cost.unwrap_or_default())));
						}
					}
					ids
				},
				None => {
					let priced = price(wallet, &coins).await;
					let ids = priced.iter().filter(|p| p.worth()).map(|p| p.id).collect::<Vec<_>>();
					if ids.is_empty() {
						match priced.first() {
							None => bail!("refused: there is nothing in the ark to take out"),
							Some(p) => bail!("refused: no coin is worth its exit. {}", p.json(0)["why_not"].as_str().unwrap_or("")),
						}
					}
					ids
				},
			};
			start(wallet, &f, &coins, &ids).await
		},
		// Moves every exit on by a step: broadcasts what can be, pays its fee from the
		// holder's Bitcoin coins, and claims each coin whose exit is done to `address`
		// (the holder's own first address when none is named).
		"exit_progress" => {
			sync_funding(wallet).await?;
			let a = address_arg(wallet, net, args).await?;
			progress(wallet, &a).await
		},
		"exit_claim" => {
			sync_funding(wallet).await?;
			let a = address_arg(wallet, net, args).await?;
			wallet.exit_mgr().progress_exits(wallet).await?;
			match claim(wallet, &a).await? {
				Some(c) => Ok(c),
				None => bail!("refused: no exit can be claimed yet{}", match wallet.exit_mgr().all_claimable_at_height().await {
					Some(h) => format!("; the last can be at block {}", h),
					None => String::new(),
				}),
			}
		},
		"exit_status" => {
			let all = wallet.exit_mgr().list_all(false, false).await?;
			Ok(json!({ "exits": all.into_iter().map(|s| json!({
				"id": s.vtxo_id.to_string(),
				"state": state_name(&s.state),
				"claimable_height": s.state.claimable_height(),
			})).collect::<Vec<_>>() }))
		},
		// Default mode's rule, the same in every wallet. When the ark has refused
		// the wallet (`ark_refused`, or a refused renewal since it opened) or cannot
		// be reached now, every coin worth its exit within `margin` (EXIT_MARGIN)
		// blocks of its expiry is taken out; otherwise nothing starts. Exits already
		// under way are moved on and claimed, as `exit_progress` does.
		"exit_auto" => {
			let margin = args.get("margin").and_then(|v| v.as_u64()).map(|m| m as u32).unwrap_or(EXIT_MARGIN);
			let address = address_arg(wallet, net, args).await?;
			let refused = args.get("ark_refused").and_then(|v| v.as_bool()).unwrap_or(false)
				|| REFUSED.lock().unwrap().as_ref().map(|s| s.contains(&wallet.fingerprint())).unwrap_or(false);
			let reachable = wallet.refresh_server().await.is_ok();
			let had_exits = !wallet.exit_mgr().get_exit_vtxo_ids().await.is_empty();
			if reachable && !refused {
				let moved = if had_exits { sync_funding(wallet).await?; Some(progress(wallet, &address).await?) } else { None };
				return Ok(json!({ "action": "none", "ark": "answering", "progress": moved }));
			}
			let ark = if reachable { "refused" } else { "unreachable" };
			let f = sync_funding(wallet).await?;
			let tip = wallet.chain().tip().await?;
			let coins = exitable(wallet).await?;
			let due = coins.iter().filter(|c| c.vtxo.expiry_height() <= tip + margin).cloned().collect::<Vec<_>>();
			let priced = price(wallet, &due).await;
			let not_worth = priced.iter().filter(|p| !p.worth()).map(|p| p.json(tip)).collect::<Vec<_>>();
			let ids = priced.iter().filter(|p| p.worth()).map(|p| p.id).collect::<Vec<_>>();
			let mut out = json!({ "ark": ark, "tip": tip, "margin": margin, "not_worth": not_worth });
			if ids.is_empty() {
				out["action"] = json!("none");
			} else {
				match start(wallet, &f, &coins, &ids).await {
					Ok(s) => { out["action"] = json!("started"); out["started"] = s; },
					Err(e) => {
						out["action"] = json!("cannot_start");
						out["reason"] = json!(format!("{:#}", e));
						out["amount"] = json!(sat(priced.iter().filter(|p| p.worth()).map(|p| p.amount).sum()));
						if let Some(u) = e.downcast_ref::<Unfunded>() {
							out["needed"] = json!(sat(u.needed));
							out["available"] = json!(sat(u.available));
						}
					},
				}
			}
			if had_exits || out["action"] == "started" {
				out["progress"] = progress(wallet, &address).await?;
			}
			Ok(out)
		},
		other => bail!("unknown command '{}'", other),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn worth_needs_more_than_the_cost() {
		let p = |a, c| Priced { id: VtxoId::from_str(&format!("{}:0", "00".repeat(32))).unwrap(),
			amount: Amount::from_sat(a), expiry: 0, cost: Some(Amount::from_sat(c)), why_not: None };
		assert!(!p(50_000, 51_000).worth());
		assert!(!p(51_330, 51_000).worth());
		assert!(p(51_331, 51_000).worth());
		let j = p(10_000, 51_000).json(0);
		assert_eq!(j["worth"], false);
		assert!(j["why_not"].as_str().unwrap().contains("would cost about 51000 sat"));
	}
}
