//! The operator's exchange rate for each asset it serves.
//!
//! Each asset may name a source of its own (`[assets.rate]` in `arcad.toml`):
//!
//! - `node`: the node's own rate for the asset, the one it values fees in
//!   it at (`-con_any_asset_fees`, read with `getfeeexchangerates`), where
//!   the node lists the asset; a reading is as old as the server's read of
//!   it;
//! - `file`: a file the operator's price process writes, holding one
//!   reading;
//! - `command`: a program the server runs, which prints one reading.
//!
//! A reading is a JSON object, `{"rate": <integer>, "time": <unix seconds>}`
//! (the rate as a number or a decimal string), or the same two numbers on
//! one line, the time optional. Its time is when the price was taken: from
//! the reading when it carries one, else the file's modification time, or
//! when the command ran; a reading dated more than [`AHEAD`] ahead of the
//! server's clock is not taken. A rate is the node's unit: what 10^8 atoms of the
//! asset are worth in atoms of the reference unit, so `a` atoms are worth
//! `a × rate / 10^8` of it ([`value_of`], [`atoms_of`]). The reference unit is
//! the one the node's fee rates count in, which no asset of the chain is.
//!
//! Every source is read when the server starts, when it takes its
//! configuration anew, and every [`READ_EVERY`] after; a source that fails
//! leaves the last reading standing, with the failure beside it. A rate is
//! good for its asset's `max_age_seconds` from its time. Past that it is
//! stale, and the server takes no new work in that asset (a board, a
//! participation): it refuses it `rate_stale` (503), naming the asset, the
//! source and the age, until it reads a fresh one. Work already taken goes
//! on: a participation accepted before is built into its round, completed
//! and released, coins are paid on out of round, and the watcher answers
//! exits, claims and sweeps; where any of them needs the rate (a smallest
//! leaf set in reference units) it takes the last one read. An asset with no
//! source has no rate, and nothing of it is priced from one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use elements::AssetId;

use crate::chain::FinalityService;

/// How often every source is read again.
pub const READ_EVERY: Duration = Duration::from_secs(15);

/// How long a command source may run before it is stopped and its reading
/// counted as failed.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How far ahead of the server's clock a reading's time may lie, in
/// seconds: room for two clocks that disagree a little. A reading dated
/// further ahead is not taken, since its age would read nothing until that
/// time and its rate never go stale.
pub const AHEAD: u64 = 300;

/// Where an asset's rate comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateSource {
	/// The node's own rate for the asset (`getfeeexchangerates`).
	Node,
	/// A file holding one reading.
	File(PathBuf),
	/// A program and its arguments, printing one reading.
	Command(Vec<String>),
}

impl std::fmt::Display for RateSource {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			RateSource::Node => write!(f, "node"),
			RateSource::File(p) => write!(f, "file {}", p.display()),
			RateSource::Command(c) => write!(f, "command {}", c.join(" ")),
		}
	}
}

impl RateSource {
	/// The source's kind, as `info` names it.
	pub fn kind(&self) -> &'static str {
		match self {
			RateSource::Node => "node",
			RateSource::File(_) => "file",
			RateSource::Command(_) => "command",
		}
	}
}

/// An asset's rate source and how long a reading is good for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateConfig {
	pub source: RateSource,
	/// In seconds from the reading's time.
	pub max_age: u64,
}

/// One rate read: the rate, when the price was taken, and when the server
/// read it (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
	pub rate: u64,
	pub time: u64,
	pub read_at: u64,
}

#[derive(Debug, Clone, Default)]
struct Entry {
	config: Option<RateConfig>,
	last: Option<Reading>,
	/// Why the last read failed, if it did.
	failed: Option<String>,
}

/// Why the server takes no new work in an asset now.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RateError {
	#[error("the operator's rate for asset {asset} is stale: its {from} gave a rate of {rate} taken at {time} (unix time), {age} s \
		ago, and a rate is good for {max_age} s{failed}; the server takes no new work in asset {asset} until it reads a fresh one")]
	Stale { asset: AssetId, from: String, rate: u64, time: u64, age: u64, max_age: u64, failed: String },
	#[error("the operator has no rate for asset {asset}: its {from} has given none{failed}; the server takes no new work in asset \
		{asset} until it has one")]
	Missing { asset: AssetId, from: String, failed: String },
}

/// What `info` publishes of an asset's rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateView {
	pub source: &'static str,
	pub rate: Option<u64>,
	pub time: Option<u64>,
	pub age: Option<u64>,
	pub max_age: u64,
	pub stale: bool,
	pub failed: Option<String>,
}

/// The rates of every asset served, by their sources: see the [module
/// documentation](self). Clones share one book.
#[derive(Debug, Clone, Default)]
pub struct Rates(Arc<Mutex<BTreeMap<AssetId, Entry>>>);

/// The time now, in unix seconds.
pub fn unix_now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `atoms` of an asset at `rate`, in atoms of the reference unit, rounded
/// down.
pub fn value_of(atoms: u64, rate: u64) -> u64 {
	((atoms as u128 * rate as u128) / 100_000_000).min(u64::MAX as u128) as u64
}

/// `value` atoms of the reference unit in atoms of an asset at `rate`,
/// rounded up: at least `value` is worth.
pub fn atoms_of(value: u64, rate: u64) -> u64 {
	if rate == 0 {
		return u64::MAX;
	}
	((value as u128 * 100_000_000).div_ceil(rate as u128)).min(u64::MAX as u128) as u64
}

/// Reads one reading from `text`; `time` when it carries none.
pub fn parse_reading(text: &str, time: u64) -> Result<(u64, u64), String> {
	let text = text.trim();
	let number = |v: &serde_json::Value, what: &str| -> Result<Option<u64>, String> {
		match v {
			serde_json::Value::Null => Ok(None),
			serde_json::Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| format!("the {} {} is not a whole number", what, n)),
			serde_json::Value::String(s) => s.trim().parse::<u64>().map(Some).map_err(|_| format!("the {} {:?} is not a whole number", what, s)),
			other => Err(format!("the {} {} is not a number", what, other)),
		}
	};
	let (rate, at) = if text.starts_with('{') {
		let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not a reading: {}", e))?;
		let rate = number(&v["rate"], "rate")?.ok_or("the reading has no rate")?;
		(rate, number(&v["time"], "time")?)
	} else {
		let mut parts = text.split_whitespace();
		let rate = parts.next().ok_or("the reading is empty")?.parse::<u64>().map_err(|_| format!("not a reading: {:?}", text))?;
		let at = parts.next().map(|t| t.parse::<u64>().map_err(|_| format!("the time {:?} is not a whole number", t))).transpose()?;
		if parts.next().is_some() {
			return Err(format!("not a reading: {:?}", text));
		}
		(rate, at)
	};
	if rate == 0 {
		return Err("a rate of 0".into());
	}
	Ok((rate, at.unwrap_or(time)))
}

impl Rates {
	/// Takes each served asset's source, as the configuration names it: a
	/// reading already held is kept for an asset whose source is unchanged,
	/// and dropped for one whose source changed; an asset no longer listed is
	/// forgotten.
	pub fn configure(&self, list: &[(AssetId, Option<RateConfig>)]) {
		let mut book = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let mut next = BTreeMap::new();
		for (asset, config) in list {
			let mut e = book.remove(asset).unwrap_or_default();
			if e.config.as_ref().map(|c| &c.source) != config.as_ref().map(|c| &c.source) {
				e = Entry::default();
			}
			e.config = config.clone();
			next.insert(*asset, e);
		}
		*book = next;
	}

	/// The source of `asset`'s rate, if it has one.
	pub fn config(&self, asset: &AssetId) -> Option<RateConfig> {
		self.0.lock().unwrap_or_else(|e| e.into_inner()).get(asset).and_then(|e| e.config.clone())
	}

	/// `asset`'s rate for new work at `now` (unix seconds): `None` for an
	/// asset with no source, the rate while it is fresh, and why the server
	/// takes no new work in the asset otherwise.
	pub fn fresh(&self, asset: &AssetId, now: u64) -> Result<Option<u64>, RateError> {
		let book = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let Some(e) = book.get(asset) else { return Ok(None) };
		let Some(config) = &e.config else { return Ok(None) };
		let failed = e.failed.as_ref().map(|f| format!(" (its last read failed: {})", f)).unwrap_or_default();
		match e.last {
			None => Err(RateError::Missing { asset: *asset, from: config.source.to_string(), failed }),
			Some(r) => {
				let age = now.saturating_sub(r.time);
				if age > config.max_age {
					return Err(RateError::Stale { asset: *asset, from: config.source.to_string(), rate: r.rate, time: r.time, age,
						max_age: config.max_age, failed });
				}
				Ok(Some(r.rate))
			},
		}
	}

	/// `asset`'s last rate read, however old: what work already taken uses.
	pub fn last(&self, asset: &AssetId) -> Option<u64> {
		self.0.lock().unwrap_or_else(|e| e.into_inner()).get(asset).and_then(|e| e.last).map(|r| r.rate)
	}

	/// What `info` publishes of `asset`'s rate at `now`; `None` for an asset
	/// with no source.
	pub fn view(&self, asset: &AssetId, now: u64) -> Option<RateView> {
		let book = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let e = book.get(asset)?;
		let config = e.config.as_ref()?;
		let age = e.last.map(|r| now.saturating_sub(r.time));
		Some(RateView {
			source: config.source.kind(),
			rate: e.last.map(|r| r.rate),
			time: e.last.map(|r| r.time),
			age,
			max_age: config.max_age,
			stale: age.is_none_or(|a| a > config.max_age),
			failed: e.failed.clone(),
		})
	}

	/// Sets `asset`'s reading, as a source would give it: for a test, or a
	/// caller with a source of its own.
	pub fn set(&self, asset: &AssetId, rate: u64, time: u64) {
		let mut book = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let e = book.entry(*asset).or_default();
		e.last = Some(Reading { rate, time, read_at: unix_now() });
		e.failed = None;
	}

	/// Reads every source once, the node through `finality`.
	pub async fn read_all(&self, finality: &FinalityService) {
		let sources: Vec<(AssetId, RateConfig)> = {
			let book = self.0.lock().unwrap_or_else(|e| e.into_inner());
			book.iter().filter_map(|(a, e)| e.config.clone().map(|c| (*a, c))).collect()
		};
		let mut node: Option<Result<BTreeMap<AssetId, u64>, String>> = None;
		for (asset, config) in sources {
			let now = unix_now();
			let got: Result<(u64, u64), String> = match &config.source {
				RateSource::Node => {
					if node.is_none() {
						node = Some(finality.call(|c| c.fee_rates()).await.map_err(|e| format!("the node: {}", e)));
					}
					match node.as_ref().expect("read") {
						Ok(rates) => match rates.get(&asset) {
							Some(r) if *r > 0 => Ok((*r, now)),
							_ => Err(format!("the node lists no rate for asset {}", asset)),
						},
						Err(e) => Err(e.clone()),
					}
				},
				RateSource::File(path) => read_file(path, now),
				RateSource::Command(argv) => run_command(argv, now).await,
			};
			let mut book = self.0.lock().unwrap_or_else(|e| e.into_inner());
			let Some(e) = book.get_mut(&asset) else { continue };
			if e.config.as_ref() != Some(&config) {
				continue;
			}
			let got = got.and_then(|(rate, time)| match time.checked_sub(now) {
				Some(ahead) if ahead > AHEAD => Err(format!("a reading dated {} s ahead of the server's clock (time {}): a rate is taken at a \
					time that has come, or its age would read nothing and it would never go stale", ahead, time)),
				_ => Ok((rate, time)),
			});
			match got {
				Ok((rate, time)) => {
					e.last = Some(Reading { rate, time, read_at: now });
					e.failed = None;
				},
				Err(why) => {
					if e.failed.as_deref() != Some(why.as_str()) {
						log::warn!("rates: asset {}: its {} gave no rate: {}", asset, config.source, why);
					}
					e.failed = Some(why);
				},
			}
		}
	}

	/// Reads every source every [`READ_EVERY`], until the task is dropped.
	pub fn spawn(&self, finality: Arc<FinalityService>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(READ_EVERY).await;
				me.read_all(&finality).await;
			}
		})
	}
}

/// One reading from the file at `path`, its time the file's modification
/// time when it carries none.
fn read_file(path: &std::path::Path, now: u64) -> Result<(u64, u64), String> {
	let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
	let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()
		.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(now);
	parse_reading(&text, modified).map_err(|e| format!("{}: {}", path.display(), e))
}

/// One reading from running `argv`, its time when it ran when it carries
/// none; stopped after [`COMMAND_TIMEOUT`].
async fn run_command(argv: &[String], now: u64) -> Result<(u64, u64), String> {
	let argv = argv.to_vec();
	tokio::task::spawn_blocking(move || {
		let (program, args) = argv.split_first().ok_or("an empty command")?;
		let mut child = std::process::Command::new(program).args(args).stdin(std::process::Stdio::null())
			.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn()
			.map_err(|e| format!("{}: {}", program, e))?;
		let start = std::time::Instant::now();
		loop {
			match child.try_wait().map_err(|e| format!("{}: {}", program, e))? {
				Some(_) => break,
				None if start.elapsed() > COMMAND_TIMEOUT => {
					let _ = child.kill();
					let _ = child.wait();
					return Err(format!("{} gave no answer within {} s", program, COMMAND_TIMEOUT.as_secs()));
				},
				None => std::thread::sleep(Duration::from_millis(20)),
			}
		}
		let out = child.wait_with_output().map_err(|e| format!("{}: {}", program, e))?;
		if !out.status.success() {
			return Err(format!("{} exited with {}: {}", program, out.status, String::from_utf8_lossy(&out.stderr).trim()));
		}
		parse_reading(&String::from_utf8_lossy(&out.stdout), now).map_err(|e| format!("{}: {}", program, e))
	}).await.map_err(|e| format!("the command: {}", e))?
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_reading_is_read_in_either_form() {
		assert_eq!(parse_reading("{\"rate\": 250000000, \"time\": 1800000000}", 7), Ok((250_000_000, 1_800_000_000)));
		assert_eq!(parse_reading("{\"rate\": \"250000000\"}", 7), Ok((250_000_000, 7)));
		assert_eq!(parse_reading("250000000 1800000000\n", 7), Ok((250_000_000, 1_800_000_000)));
		assert_eq!(parse_reading("250000000", 7), Ok((250_000_000, 7)));
		assert!(parse_reading("0", 7).is_err());
		assert!(parse_reading("2.5", 7).is_err());
		assert!(parse_reading("{\"time\": 1}", 7).is_err());
		assert!(parse_reading("1 2 3", 7).is_err());
	}

	#[test]
	fn a_value_and_its_atoms() {
		// One reference coin per coin: 1:1.
		assert_eq!(atoms_of(1_000, 100_000_000), 1_000);
		// An asset worth 2.5 reference coins a coin: a value of 1,000 is 400
		// atoms, rounded up.
		assert_eq!(atoms_of(1_000, 250_000_000), 400);
		assert_eq!(atoms_of(1_001, 250_000_000), 401);
		assert_eq!(value_of(400, 250_000_000), 1_000);
		assert_eq!(atoms_of(1, 0), u64::MAX);
	}

	#[test]
	fn a_rate_is_fresh_for_its_max_age_and_kept_while_its_source_stands() {
		let rates = Rates::default();
		let a = AssetId::from_slice(&[1; 32]).unwrap();
		let b = AssetId::from_slice(&[2; 32]).unwrap();
		rates.configure(&[(a, Some(RateConfig { source: RateSource::File("/x".into()), max_age: 600 })), (b, None)]);
		assert!(matches!(rates.fresh(&a, 1_000), Err(RateError::Missing { .. })));
		assert_eq!(rates.fresh(&b, 1_000), Ok(None), "no source, no rate, nothing refused");
		rates.set(&a, 5, 1_000);
		assert_eq!(rates.fresh(&a, 1_600), Ok(Some(5)));
		let e = rates.fresh(&a, 1_601).unwrap_err();
		assert!(e.to_string().contains("601 s ago"), "{}", e);
		assert_eq!(rates.last(&a), Some(5), "old work takes the last rate");
		// The same source configured again keeps the reading; another drops it.
		rates.configure(&[(a, Some(RateConfig { source: RateSource::File("/x".into()), max_age: 3_600 }))]);
		assert_eq!(rates.fresh(&a, 1_601), Ok(Some(5)));
		rates.configure(&[(a, Some(RateConfig { source: RateSource::Node, max_age: 3_600 }))]);
		assert_eq!(rates.last(&a), None);
	}
}
