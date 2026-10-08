//! SeqLN nodes beside the server, on the chain SeqLN's `sequentia-regtest`
//! network assumes ([`super::running::Running::start_seqln`]).
//!
//! A test that needs them reads `LIGHTNINGD_EXEC`, the path of a SeqLN
//! `lightningd`; without it the test says so and passes, as the suite runs
//! on machines with no SeqLN build.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use elements::AssetId;
use sequentia_ext::lightning::{hold_plugin, lightningd_from_env, LightningNode};
use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, AssetAmount};

use super::node::Purse;

/// The SeqLN `lightningd` the tests run, or `None` with a line saying the
/// test is skipped.
pub fn lightningd(test: &str) -> Option<PathBuf> {
	let l = lightningd_from_env();
	if l.is_none() {
		println!("{}: skipped, LIGHTNINGD_EXEC names no SeqLN lightningd", test);
	}
	l
}

/// A SeqLN node on `rt` named `name`, with the hold-invoice plugin when
/// `holds`, its wallet paid `amount` of `asset` from `purse` and confirmed.
pub fn node(rt: &Regtest, purse: &mut Purse, lightningd: &PathBuf, name: &str, holds: bool, asset: AssetId, amount: u64)
	-> LightningNode
{
	static N: AtomicUsize = AtomicUsize::new(0);
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
		.join(format!("ln{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst), name));
	let plugins = if holds { vec![hold_plugin(lightningd)] } else { vec![] };
	let n = LightningNode::start(rt, lightningd, &dir, &plugins).unwrap_or_else(|e| panic!("{}: {}", name, e));
	let to = n.receive_script(rt);
	purse.pay(rt, vec![explicit_txout(AssetAmount::new(asset, amount), to)]);
	rt.produce_block().unwrap();
	n.wait_funds(1);
	n
}

/// A server serving X and Y over Lightning: an operator node in each asset
/// with a channel to a node of its own, the operator's side holding most of
/// it; its wallet funded in X and Y and final.
pub struct Gateway {
	pub r: super::running::Running,
	pub ox: LightningNode,
	pub px: LightningNode,
	pub oy: LightningNode,
	pub py: LightningNode,
}

/// The gateway, with `tune` applied to the configuration first (given asset
/// Y); `None` when no SeqLN `lightningd` is named.
pub async fn gateway<F: FnOnce(&mut server::server::Config, AssetId)>(test: &str, tune: F) -> Option<Gateway> {
	use server::server::{AssetSection, LegSection};
	let lnd = lightningd(test)?;
	let mut r = super::running::Running::start_seqln(|c, y| {
		c.assets.push(AssetSection::new(y, super::running::MIN_LEAF));
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		// SeqLN's final lock time on a Sequentia network is 180 blocks:
		// eight hours leave a payment 240.
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		tune(c, y);
	}).await;
	let (x, y) = (r.x, r.y);
	super::node::list_fee_asset(&r.rt, y, 100_000_000);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (ox, px, oy, py) = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "ox", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "px", true, x, 1_000_000_000);
		let oy = node(&r.rt, &mut r.purse, &lnd, "oy", true, y, 2_000_000_000);
		let py = node(&r.rt, &mut r.purse, &lnd, "py", true, y, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		oy.open_channel(&r.rt, &py, y, 1_000_000_000, 300_000_000);
		(ox, px, oy, py)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.server.config();
	for a in config.assets.iter_mut() {
		if a.asset == x.to_string() {
			a.lightning = Some(LegSection { rpc: ox.rpc_path() });
		}
		if a.asset == y.to_string() {
			a.lightning = Some(LegSection { rpc: oy.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("both legs up", || g.leg(&x, true).is_ok() && g.leg(&y, true).is_ok()).await;
	Some(Gateway { r, ox, px, oy, py })
}

/// A fresh invoice of `node` for `atoms` of `asset`: its BOLT11 and its
/// payment hash.
pub fn invoice(node: &LightningNode, asset: AssetId, atoms: u64, label: &str) -> (String, [u8; 32]) {
	let r = node.ok("invoice", serde_json::json!({ "amount_msat": atoms * 1000, "label": label, "description": label,
		"asset": asset.to_string() }));
	let h = r["payment_hash"].as_str().unwrap();
	let mut hash = [0u8; 32];
	for i in 0..32 {
		hash[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
	}
	(r["bolt11"].as_str().unwrap().to_string(), hash)
}

/// What `node` holds on its side of its open channels in `asset`, in atoms.
pub fn channel_balance(node: &LightningNode, asset: AssetId) -> u64 {
	node.ok("listpeerchannels", serde_json::json!({}))["channels"].as_array().unwrap().iter()
		.filter(|c| c["channel_asset"].as_str() == Some(&asset.to_string()) && c["state"] == "CHANNELD_NORMAL")
		.map(|c| c["to_us_msat"].as_u64().unwrap_or(0) / 1000).sum()
}
