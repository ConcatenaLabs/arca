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
