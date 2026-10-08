//! SeqLN nodes beside a whole server, on the chain SeqLN's
//! `sequentia-regtest` network assumes ([`super::running::Running::start_seqln`]).
//!
//! A scenario that needs them reads `LIGHTNINGD_EXEC`, the path of a SeqLN
//! `lightningd`; without it the scenario says so and passes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use elements::AssetId;
use serde_json::{json, Value};
use sequentia_ext::lightning::{hold_plugin, lightningd_from_env, LightningNode};
use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, AssetAmount};

use super::node::Purse;

/// The SeqLN `lightningd` the scenarios run, or `None` with a line saying
/// the scenario is skipped.
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
		.join(format!("cln{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst), name));
	let plugins = if holds { vec![hold_plugin(lightningd)] } else { vec![] };
	let n = LightningNode::start(rt, lightningd, &dir, &plugins).unwrap_or_else(|e| panic!("{}: {}", name, e));
	let to = n.receive_script(rt);
	purse.pay(rt, vec![explicit_txout(AssetAmount::new(asset, amount), to)]);
	rt.produce_block().unwrap();
	n.wait_funds(1);
	n
}

/// A fresh invoice of `node` for `atoms` of `asset`: its BOLT11 and its
/// payment hash.
pub fn invoice(node: &LightningNode, asset: AssetId, atoms: u64, label: &str) -> (String, String) {
	let r = node.ok("invoice", json!({ "amount_msat": atoms * 1000, "label": label, "description": label, "asset": asset.to_string() }));
	(r["bolt11"].as_str().unwrap().to_string(), r["payment_hash"].as_str().unwrap().to_string())
}

/// The invoice of `node` labelled `label`.
pub fn invoice_status(node: &LightningNode, label: &str) -> Value {
	node.ok("listinvoices", json!({ "label": label }))["invoices"][0].clone()
}

/// What `node` holds in its channels in `asset`, in atoms: its side.
pub fn channel_balance(node: &LightningNode, asset: AssetId) -> u64 {
	node.ok("listpeerchannels", json!({}))["channels"].as_array().unwrap().iter()
		.filter(|c| c["channel_asset"].as_str() == Some(&asset.to_string()) && c["state"] == "CHANNELD_NORMAL")
		.map(|c| c["to_us_msat"].as_u64().unwrap_or(0) / 1000).sum()
}
