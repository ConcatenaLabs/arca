//! `arca sync-size`: what a pass of `sync` in slices would cost on a store,
//! read from the store alone.
//!
//! It opens no wallet and needs no phrase: it reads the store's own tables,
//! and never the operator, the node or a watchtower. It writes nothing: a
//! caller opens the store read-only ([`super::store::Store::open_read_only`])
//! or hands it a copy. For each step a slice can stop inside
//! ([`super::slice::ITEMS`]) whose items the store holds, it counts the items a
//! pass would look at, and times the reads the step makes before its first
//! item, which every slice that goes on with the step pays again unless the
//! library keeps them for the pass: those reads decide how far a slice
//! advances. `refresh` is timed both as this library reads it (once per
//! change of the participations it reads, then the live coins alone) and as
//! a library that read every refused participation and looked up each coin
//! they name in every slice did, so a store can be judged before either
//! library goes onto it. The operator's part of a step (`holding_back`, one
//! call per 64 coins) is counted, not made.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::store::Store;
use super::Error;

fn ms(t: web_time::Instant) -> u64 {
	t.elapsed().as_millis() as u64
}

/// The sizing of a pass on `store`: see the [module documentation](self).
pub fn sync_size(store: &Store) -> Result<Value, Error> {
	let started = web_time::Instant::now();
	let mut steps = serde_json::Map::new();

	// The coins: how many a state, and the live ones' records read and
	// decoded, as `refresh` reads them to leave a resting order's coin out.
	let t = web_time::Instant::now();
	let live = store.coins_in("live")?;
	let order_coins = live.iter().filter(|c| super::resting::is_order_coin(c)).count();
	let live_read = ms(t);
	let asked: BTreeMap<String, u32> = store.meta(super::wallet::REFRESH_ASKED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();

	// `refresh` as this library reads it: the refused participations once,
	// then, in each slice, the store's count of their writes and the live
	// coins' ids.
	let t = web_time::Instant::now();
	let mut last: std::collections::HashMap<String, String> = std::collections::HashMap::new();
	let rows = store.refused_givens()?;
	let mut named = 0usize;
	for (pid, given, state) in &rows {
		let given: Vec<String> = serde_json::from_str(given).map_err(|e| Error::Store(e.to_string()))?;
		named += given.len();
		for l in given {
			last.insert(l, format!("{} {}", &pid[..16.min(pid.len())], state));
		}
	}
	let refused_once = ms(t);
	let t = web_time::Instant::now();
	let writes = store.refused_writes().ok();
	let live_ids = store.coin_ids_in("live")?;
	let refused_live = live_ids.iter().filter(|l| last.contains_key(*l)).count();
	let refused_slice = ms(t);
	// As a library before it read them: every row, its body included, and a
	// look-up of every coin named, in every slice.
	let t = web_time::Instant::now();
	let mut looked = 0usize;
	for (_, _, given, ..) in store.participations_in(&["refused", "void", "expired"])? {
		let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
		for l in given {
			let _ = store.coin(&l)?;
			looked += 1;
		}
	}
	let refused_each_slice = ms(t);
	let by_state = |s: &str| rows.iter().filter(|r| r.2 == s).count();
	steps.insert("refresh".into(), json!({
		"items": live.len(), "operator_calls": live.len().div_ceil(64), "resting_order_coins": order_coins, "asked_before": asked.len(),
		"refused_participations": {"refused": by_state("refused"), "void": by_state("void"), "expired": by_state("expired"), "coins_named": named,
			"live_coins_named": refused_live},
		"before_items_ms": {"live_coins_read": live_read, "refused_read_once": refused_once, "refused_each_slice": refused_slice,
			"refused_each_slice_by_an_older_library": refused_each_slice, "coin_lookups_by_an_older_library": looked},
		"refused_writes": writes,
	}));

	// `participations`: those not yet done, read twice before the items.
	let t = web_time::Instant::now();
	let open = store.participations_not_in(&["released", "void", "expired", "refused", "lost"])?;
	let _ = store.participations_not_in(&["released", "void", "expired", "refused", "lost"])?;
	steps.insert("participations".into(), json!({"items": open.len(), "before_items_ms": ms(t)}));

	// `home` and `exits`: the coins still to bring home or spend, and the exits.
	let t = web_time::Instant::now();
	let homeward = store.coins_in_states(super::Wallet::HOMEWARD)?;
	steps.insert("home".into(), json!({"items": homeward.len(), "before_items_ms": ms(t)}));
	let t = web_time::Instant::now();
	let exits = store.exit_ids()?;
	steps.insert("exits".into(), json!({"items": exits.len(), "before_items_ms": ms(t)}));

	Ok(json!({
		"store": store.shape()?,
		"steps": steps,
		"took_ms": ms(started),
		"reads": "the store only: no operator, node or watchtower is asked, and nothing is written",
	}))
}
