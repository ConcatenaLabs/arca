//! The wallet's chain source: a `sequentiad` reached over JSON-RPC.
//!
//! The wallet never counts confirmations. A transaction it relies on (a round,
//! a board) is **final** when its block is in the node's active chain,
//! certified by the committee (the node reports the certificate for that block
//! or for one above it), and its Bitcoin anchor is buried: the anchor height of
//! the tip less the block's is at least the anchor depth (2), while the node
//! reports its tip's anchor as validated and `ok`. That is the server's rule
//! and SeqLN's. Sequentia reorganises whenever its anchor does, with no depth
//! limit, so finality is read from the node in every view it is asked in
//! (below), and never remembered past it.
//!
//! The node must run with `-txindex`, so the wallet can fetch any transaction
//! by its id, and with `-validateanchor`, without which it has no notion of
//! finality.
//!
//! **The view.** Every answer the wallet reads of the chain is fixed by three
//! things: the tip of the active chain (`bestblockhash`), the node's view of
//! its anchors (`getanchorstatus`), and the transactions in its mempool
//! (`getrawmempool`). A reorganisation of any depth, an anchor-driven one
//! included, changes the tip; a parent chain the node can no longer follow
//! changes the anchor status; a broadcast, a replacement or an eviction
//! changes the mempool. While those three stand, the node gives the same
//! answer to the same read, so the source keeps each read's answer for the
//! view it was read in ([`ChainSource::new_command`]): the reads of a block
//! header, a transaction, an output, a scan of the set of unspent outputs, a
//! block, an address. It looks at the three again before it answers anything
//! at the start of every command, after anything else may have moved the
//! chain (a request to the operator, who may broadcast; a pause; a broadcast
//! of the wallet's own; [`gap`]), and at least once a second; any change to
//! one of them drops every answer kept but those fixed by what they name (a
//! transaction's bytes by its id, a header's or a block's by its hash, a
//! script's address), which no view changes. What the node values at broadcast
//! (its fee whitelist, its rates, its relay floor) can change while the view
//! stands, and is read again in every command. The wallet's checks run as
//! often as before; they read the chain as it is when they run, at the price
//! of one look (three calls) when it has not moved.
//!
//! **Reads at once.** The reads one check makes of many coins do not depend
//! on each other (where each round and board is, its block's header, each
//! board's output), so the re-check asks for them together, as a JSON-RPC
//! batch: two requests for a wallet's rounds and boards, and one for the look
//! at the view, where the node takes a batch ([`ChainSource::read_ahead_of`]).
//! A look that is due carries the read that made it due in the same request,
//! so over a link where every request costs a round trip a look costs none
//! of its own; what is kept within a command, or named by an id or a hash,
//! is answered without a look. A node behind a proxy that takes one call at
//! a time refuses the first batch, and the source makes each read on its own
//! from then on; one that refuses only some methods in a batch has those
//! asked on their own. A read ahead changes no answer, only the number of
//! requests that make it.
//!
//! **A busy node.** The node runs one scan of its set of unspent outputs at
//! a time for all its clients, and refuses a scan while another runs (two
//! wallets on one node, or two commands of one wallet). That refusal is no
//! answer of the view: it is never kept, and the read waits for the other
//! scan to end and asks again, for two minutes at most.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use elements::{AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use serde::de::DeserializeOwned;

use sequentia_ext::rpc::{Auth, BlockchainInfo, Client, Error as RpcError};
use sequentia_ext::{Block, BlockHeader, BlockHeaderExt};

use super::Error;

/// The Bitcoin blocks that bury a final block's anchor.
pub const ANCHOR_DEPTH: u64 = 2;

/// How far above a block the wallet looks for a committee certificate.
const CERT_LOOKAHEAD: u64 = 200;

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
	/// Not in a block of the active chain (perhaps in the mempool).
	NotInChain { in_mempool: bool },
	/// In a block the committee has not certified.
	Unsettled { height: u64 },
	/// In a certified block, its anchor buried fewer than [`ANCHOR_DEPTH`]
	/// Bitcoin blocks.
	Settled { height: u64, depth: u64 },
	/// Certified, and its anchor buried.
	Final { height: u64, depth: u64 },
}

impl Finality {
	pub fn is_final(&self) -> bool {
		matches!(self, Finality::Final { .. })
	}

	pub fn in_chain(&self) -> bool {
		!matches!(self, Finality::NotInChain { .. })
	}

	pub fn height(&self) -> Option<u64> {
		match self {
			Finality::NotInChain { .. } => None,
			Finality::Unsettled { height } | Finality::Settled { height, .. } | Finality::Final { height, .. } => Some(*height),
		}
	}

	/// One word for people.
	pub fn word(&self) -> &'static str {
		match self {
			Finality::NotInChain { in_mempool: true } => "in_mempool",
			Finality::NotInChain { in_mempool: false } => "not_in_chain",
			Finality::Unsettled { .. } => "unsettled",
			Finality::Settled { .. } => "settled",
			Finality::Final { .. } => "final",
		}
	}
}

/// The tip of the active chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
	pub height: u64,
	pub hash: BlockHash,
	pub median_time: u32,
}

/// The node, and the answers it gave in the view they were read in.
#[derive(Debug, Clone)]
pub struct ChainSource {
	client: Client,
	memo: Arc<Mutex<Memo>>,
}

/// How long a view stands, at most, before the source looks at the node again.
pub const VIEW_FOR: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a look serves a command that reads only and asks to share the
/// view ([`ChainSource::share_view`]): a burst of such commands (a quote runs
/// several, one after the other) shares one look, so a wallet on a slow or far
/// link pays one round trip for the view rather than one a command. Every other
/// command looks when it starts, and a gap the wallet knows of (its own
/// broadcast, say) calls for a look at once.
pub const BURST_VIEW_FOR: std::time::Duration = std::time::Duration::from_secs(3);

/// The moments the chain may have moved without the wallet reading it: a
/// request to the operator, a pause, a broadcast. Each makes the next read
/// look at the view again ([`gap`]).
static GAPS: AtomicU64 = AtomicU64::new(0);

/// Something may have moved the chain: the next read of it looks at the
/// tip, the anchor status and the mempool again before it answers from what
/// it kept.
pub fn gap() {
	GAPS.fetch_add(1, Ordering::SeqCst);
}

/// How many gaps came since the program started: every request to the
/// operator is one ([`gap`]).
pub fn gaps() -> u64 {
	GAPS.load(Ordering::SeqCst)
}

/// What fixes every answer kept for a view: the tip, the node's anchor
/// status, and the mempool's transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ViewKey {
	tip: String,
	anchors: String,
	mempool: Vec<String>,
}

/// An answer kept: the result, or the node's refusal (a transaction it does
/// not know, a height above the tip), which the same view gives again.
type Kept = Result<Value, (i64, String)>;

#[derive(Debug, Default)]
struct Memo {
	key: Option<ViewKey>,
	looked: Option<web_time::Instant>,
	gaps: u64,
	/// Whether the view has been looked at since the command started.
	looked_this_command: bool,
	/// The command started may answer from another command's look made
	/// within [`BURST_VIEW_FOR`].
	shared: bool,
	/// Answers fixed by the view.
	view: HashMap<String, Kept>,
	/// Answers fixed by the view's mempool as well (a mempool entry, an
	/// output looked up with the mempool's spends, a transaction in no
	/// block): dropped when the mempool changes, while what is fixed by the
	/// tip and the anchors alone stays ([`pooled`]).
	pool: HashMap<String, Kept>,
	/// Answers fixed by what they name, whatever the view: a transaction's
	/// bytes by its id, a header's or a block's bytes by its hash, a script's
	/// address. Only what the node found is kept so.
	named: HashMap<String, Value>,
	/// Answers the node may change while the view stands (its fee whitelist,
	/// rates and relay floor): kept within one command, between gaps.
	command: HashMap<String, Kept>,
	/// Whether the node takes a batch of calls in one request: unknown until
	/// one is tried; a proxy that takes one call at a time is asked one by one.
	batch: Option<bool>,
	/// Methods the node refused in a batch although it takes batches (a
	/// proxy that allows some methods only on their own): asked alone.
	unbatched: std::collections::HashSet<String>,
	/// Requests made of the node, and reads answered from what was kept.
	asked: u64,
	kept: u64,
}

/// The reads a look at the view makes.
const LOOK: [&str; 3] = ["getblockchaininfo", "getanchorstatus", "getrawmempool"];

/// The most calls one batch carries: the testnet's RPC proxy refuses a
/// batch of more.
pub const BATCH_MOST: usize = 64;

/// How a read is kept.
enum Keep {
	/// Whatever the view, once the node found it: its answer is fixed by the
	/// id or hash it names.
	Named,
	/// Fixed by the view.
	View,
	/// Within one command, between gaps.
	Command,
	/// Never: a broadcast, and anything not named.
	Never,
}

fn keep_of(method: &str, params: &[Value]) -> Keep {
	// The bytes of a transaction or a block, a header's serialisation, a
	// script's address: what the id, hash or script names, whichever chain.
	match method {
		"getrawtransaction" if params.len() == 1 => return Keep::Named,
		"getblockheader" if params.len() == 2 && params[1] == json!(false) => return Keep::Named,
		"getblock" if params.len() == 2 && params[1] == json!(0) => return Keep::Named,
		"decodescript" | "validateaddress" => return Keep::Named,
		_ => {},
	}
	match method {
		"getblockchaininfo" | "getblockhash" | "getblockheader" | "getblock" | "getrawtransaction" | "gettxout" | "scantxoutset"
		| "getrawmempool" | "getmempoolentry" | "getanchorstatus" | "decodescript" | "validateaddress" | "getsupervisedassets" => Keep::View,
		"getfeeexchangerates" | "dumpassetlabels" | "getmempoolinfo" => Keep::Command,
		_ => Keep::Never,
	}
}

/// Whether the answer `a` to the read keyed `k` ([`ChainSource::read_key`])
/// depends on the mempool, not only on the tip and the anchors: the mempool
/// itself and its entries, an output looked up with the mempool's spends,
/// and a transaction the node holds in no block (or does not hold, while one
/// could enter the mempool).
fn pooled(k: &str, a: &Kept) -> bool {
	let method = k.split(' ').next().unwrap_or("");
	match method {
		"getrawmempool" | "getmempoolentry" => true,
		"gettxout" => k.ends_with(",true]"),
		"getrawtransaction" => match a {
			Ok(v) if k.ends_with(",true]") => !v["blockhash"].is_string(),
			Ok(_) => false,
			Err(_) => true,
		},
		_ => false,
	}
}

/// Whether the node refused a read only because it is busy: it runs one scan
/// of its set of unspent outputs at a time, for every client it has, and
/// refuses another while one runs. That says nothing of the chain.
fn busy(code: i64, message: &str) -> bool {
	(code == -8 && message.starts_with("Scan already in progress")) || slow_down(code, message)
}

/// Whether a proxy in front of the node refused a call for its rate limit,
/// which counts every call of a batch: the call is made again after a
/// pause, and says nothing of the chain.
fn slow_down(code: i64, message: &str) -> bool {
	code == -32000 && message.contains("slow down")
}

/// Whether a batch was refused for the proxy's rate limit (answered with
/// one error for the whole batch).
fn batch_slowed(e: &RpcError) -> bool {
	match e {
		RpcError::Rpc { code, message } => slow_down(*code, message),
		RpcError::Http { body, .. } => body.contains("slow down"),
		_ => false,
	}
}

/// How long a read waits for the node to be free of another client's scan.
pub const BUSY_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);

fn kept_of(r: Result<Value, RpcError>) -> Result<Kept, RpcError> {
	match r {
		Ok(v) => Ok(Ok(v)),
		// Busy is no answer of the view: never kept.
		Err(RpcError::Rpc { code, message }) if busy(code, &message) => Err(RpcError::Rpc { code, message }),
		Err(RpcError::Rpc { code, message }) => Ok(Err((code, message))),
		Err(e) => Err(e),
	}
}

fn answer_of(k: &Kept) -> Result<Value, RpcError> {
	k.clone().map_err(|(code, message)| RpcError::Rpc { code, message })
}

fn decode<T: elements::encode::Decodable>(what: &'static str, hex: &str) -> Result<T, RpcError> {
	let bytes = unhex(hex).map_err(|e| RpcError::Decode { what, error: e.to_string() })?;
	elements::encode::deserialize(&bytes).map_err(|e| RpcError::Decode { what, error: e.to_string() })
}

fn node(e: RpcError) -> Error {
	Error::Node(e.to_string())
}

fn not_found(e: &RpcError) -> bool {
	matches!(e, RpcError::Rpc { code: -5, .. } | RpcError::Rpc { code: -8, .. })
}

impl ChainSource {
	/// The node at `url`, authenticated with `user` and `password`, or with
	/// its cookie file when `cookie` is given.
	pub fn new(url: &str, user: Option<&str>, password: Option<&str>, cookie: Option<&str>) -> ChainSource {
		let auth = match (cookie, user, password) {
			(Some(c), _, _) => Auth::CookieFile(c.into()),
			(None, Some(u), Some(p)) => Auth::UserPass(u.into(), p.into()),
			(None, Some(u), None) => Auth::UserPass(u.into(), String::new()),
			(None, None, _) => Auth::UserPass(String::new(), String::new()),
		};
		ChainSource { client: Client::new(url, auth).with_timeout(60), memo: Arc::new(Mutex::new(Memo::default())) }
	}

	pub fn client(&self) -> &Client {
		&self.client
	}

	/// A command starts: the view is looked at again before the first read
	/// answers, and what the node may change while it stands is read again
	/// (see the [module documentation](self)).
	pub fn new_command(&self) {
		let mut m = self.memo.lock().expect("the chain memo");
		m.looked_this_command = false;
		m.shared = false;
		m.command.clear();
	}

	/// Lets the command just started answer from another command's look made
	/// within [`BURST_VIEW_FOR`]: for a command that reads only, of a caller
	/// that runs it as one of a burst.
	pub fn share_view(&self) {
		self.memo.lock().expect("the chain memo").shared = true;
	}


	/// The requests this source made of the node (a batch is one), and the
	/// reads it answered from what it kept for the view, since it was made.
	pub fn calls(&self) -> (u64, u64) {
		let m = self.memo.lock().expect("the chain memo");
		(m.asked, m.kept)
	}

	/// Whether the view is to be looked at again before the next answer: the
	/// command has just started (unless it shares the view and the last look
	/// is younger than [`BURST_VIEW_FOR`]), a gap came, or a second passed
	/// since the command's look.
	fn look_due(m: &Memo) -> bool {
		let window = if m.looked_this_command { VIEW_FOR } else if m.shared { BURST_VIEW_FOR } else { return true };
		!(m.gaps == GAPS.load(Ordering::SeqCst) && m.looked.is_some_and(|t| t.elapsed() < window))
	}

	/// Looks at the view again when it is due ([`Self::look_due`]): the tip,
	/// the anchor status and the mempool. A change to any drops every answer
	/// kept.
	fn look(&self, m: &mut Memo) -> Result<(), RpcError> {
		self.look_with(m, &[]).map(|_| ())
	}

	/// [`Self::look`], with `reads` asked in the same request where the node
	/// takes a batch (and where it is not yet known whether it does): a look
	/// then costs no request of its own, which over a proxy that answers each
	/// request after a round trip halves a command's requests. Their answers
	/// come back when they were asked with the look (read at the same moment as
	/// the view they are kept for), `None` when no look was due or the node
	/// takes no batch, and the caller asks them itself.
	fn look_with(&self, m: &mut Memo, reads: &[(String, Vec<Value>)]) -> Result<Option<Vec<Result<Value, RpcError>>>, RpcError> {
		if !Self::look_due(m) {
			return Ok(None);
		}
		let gaps = GAPS.load(Ordering::SeqCst);
		if m.gaps != gaps {
			m.command.clear();
		}
		// One request where the node takes a batch, three where it does not.
		let mut calls: Vec<(String, Vec<Value>)> = LOOK.map(|c| (c.to_string(), vec![])).to_vec();
		calls.extend(reads.iter().cloned());
		let mut extra = None;
		let batched = match m.batch {
			Some(false) => None,
			_ => match self.batch_patiently(&calls) {
				Ok(mut a) if a.len() == calls.len() => {
					m.asked += 1;
					m.batch = Some(true);
					let rest = a.split_off(3);
					let pool = kept_of(a.pop().expect("three"))?;
					let anchors = kept_of(a.pop().expect("three"))?;
					let info = kept_of(a.pop().expect("three"))?;
					extra = Some(rest);
					Some((info, anchors, pool))
				},
				Err(RpcError::Transport(e)) => return Err(RpcError::Transport(e)),
				// The node took the look alone before: what it carried was
				// refused. One read carried alone is a method the node takes
				// only on its own, asked so from now on; the look is made
				// again, and the reads are the caller's to ask.
				_ if !reads.is_empty() && m.batch == Some(true) => {
					m.asked += 1;
					if reads.len() == 1 {
						m.unbatched.insert(reads[0].0.clone());
					}
					return self.look_with(m, &[]).map(|_| None);
				},
				_ => {
					m.asked += 1;
					m.batch = Some(false);
					None
				},
			},
		};
		let (info, anchors, pool) = match batched {
			Some(t) => t,
			None => {
				m.asked += 3;
				(kept_of(self.client.call::<Value>("getblockchaininfo", &[]))?, kept_of(self.client.call::<Value>("getanchorstatus", &[]))?,
					kept_of(self.client.call::<Value>("getrawmempool", &[]))?)
			},
		};
		let tip = match &info {
			Ok(v) => v["bestblockhash"].as_str().unwrap_or("").to_string(),
			Err((c, e)) => format!("refused {} {}", c, e),
		};
		let anchors_word = match &anchors {
			Ok(v) => format!("{} {}", v["validateanchor"], v["anchorstatus"]),
			Err((c, e)) => format!("refused {} {}", c, e),
		};
		let mut mempool: Vec<String> = match &pool {
			Ok(v) => v.as_array().cloned().unwrap_or_default().iter().filter_map(|t| t.as_str().map(String::from)).collect(),
			Err((c, e)) => vec![format!("refused {} {}", c, e)],
		};
		mempool.sort();
		let key = ViewKey { tip, anchors: anchors_word, mempool };
		match &m.key {
			// The same tip and anchors, another mempool: only what the mempool
			// fixes is read again. On a busy chain the mempool changes between
			// nearly every two looks, and the headers and confirmed
			// transactions a command reads stay as they were.
			Some(k) if k.tip == key.tip && k.anchors == key.anchors => if k.mempool != key.mempool { m.pool.clear() },
			_ => {
				m.view.clear();
				m.pool.clear();
			},
		}
		m.key = Some(key);
		m.view.insert(Self::read_key("getblockchaininfo", &[]), info);
		m.view.insert(Self::read_key("getanchorstatus", &[]), anchors);
		m.pool.insert(Self::read_key("getrawmempool", &[]), pool);
		m.looked = Some(web_time::Instant::now());
		m.looked_this_command = true;
		m.gaps = gaps;
		Ok(extra)
	}

	fn read_key(method: &str, params: &[Value]) -> String {
		format!("{} {}", method, Value::Array(params.to_vec()))
	}

	/// One call of the node: answered from what the view keeps when the read
	/// is one the view fixes and was made in it, else asked of the node.
	fn read(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
		let keep = keep_of(method, params);
		if matches!(keep, Keep::Never) {
			// A broadcast changes the mempool: the next read looks again,
			// whatever window the view stands in.
			let r = self.ask(method, params);
			let mut m = self.memo.lock().expect("the chain memo");
			m.asked += 1;
			m.looked = None;
			return r;
		}
		let k = Self::read_key(method, params);
		{
			let mut m = self.memo.lock().expect("the chain memo");
			// What an id or a hash names, found before, needs no look: no
			// view changes it.
			if matches!(keep, Keep::Named) {
				if let Some(v) = m.named.get(&k).cloned() {
					m.kept += 1;
					return Ok(v);
				}
			}
			// What is kept within a command needs no look either, only that
			// no gap came since it was read.
			if matches!(keep, Keep::Command) {
				if m.gaps != GAPS.load(Ordering::SeqCst) {
					m.command.clear();
				}
				if let Some(a) = m.command.get(&k).cloned() {
					m.kept += 1;
					return answer_of(&a);
				}
			}
			// A look that is due carries the read in its own request, unless
			// the node takes the read only on its own. The three reads of the
			// look are its own answers.
			// A read the view already holds goes in no look: the look alone
			// says whether that answer still stands.
			let held = m.view.contains_key(&k) || m.pool.contains_key(&k);
			let carried: Vec<(String, Vec<Value>)> = if held || m.batch != Some(true) || m.unbatched.contains(method) || LOOK.contains(&method) {
				vec![]
			} else {
				vec![(method.to_string(), params.to_vec())]
			};
			match self.look_with(&mut m, &carried)?.filter(|_| !carried.is_empty()) {
				Some(mut answers) => {
					if let Ok(a) = kept_of(answers.pop().expect("the read")) {
						Self::keep(&mut m, &keep, k, &a);
						return answer_of(&a);
					}
				},
				None => {
					let found = match keep {
						Keep::Named | Keep::View => m.view.get(&k).or_else(|| m.pool.get(&k)).cloned(),
						_ => m.command.get(&k).cloned(),
					};
					if let Some(a) = found {
						m.kept += 1;
						return answer_of(&a);
					}
				},
			}
		}
		let a = kept_of(self.ask(method, params))?;
		let mut m = self.memo.lock().expect("the chain memo");
		m.asked += 1;
		Self::keep(&mut m, &keep, k, &a);
		answer_of(&a)
	}

	/// Keeps `a`, the answer to the read `k`, as `keep` says.
	fn keep(m: &mut Memo, keep: &Keep, k: String, a: &Kept) {
		match (keep, a) {
			(Keep::Named, Ok(v)) => { m.named.insert(k, v.clone()); },
			(Keep::Named | Keep::View, _) if pooled(&k, a) => { m.pool.insert(k, a.clone()); },
			(Keep::Named | Keep::View, _) => { m.view.insert(k, a.clone()); },
			_ => { m.command.insert(k, a.clone()); },
		}
	}

	/// One batch of calls to the node; while a proxy in front of it refuses
	/// the batch for its rate limit, the batch waits and is sent again, for
	/// [`BUSY_PATIENCE`] at most, as [`Self::ask`] does for one call.
	fn batch_patiently(&self, calls: &[(String, Vec<Value>)]) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
		let start = web_time::Instant::now();
		let mut pause = std::time::Duration::from_millis(250);
		loop {
			match self.client.batch(calls) {
				Err(e) if batch_slowed(&e) && start.elapsed() < BUSY_PATIENCE => {
					sequentia_ext::platform::sleep(pause);
					pause = (pause * 2).min(std::time::Duration::from_secs(2));
				},
				r => return r,
			}
		}
	}

	/// One call to the node. While the node is busy with another client's
	/// scan of its set of unspent outputs ([`busy`]), the call waits for it
	/// and is made again, for [`BUSY_PATIENCE`] at most: two wallets, or two
	/// commands of one wallet, share a node.
	fn ask(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
		let start = web_time::Instant::now();
		let mut pause = std::time::Duration::from_millis(50);
		loop {
			match self.client.call::<Value>(method, params) {
				Err(RpcError::Rpc { code, message }) if busy(code, &message) && start.elapsed() < BUSY_PATIENCE => {
					sequentia_ext::platform::sleep(pause);
					pause = (pause * 2).min(std::time::Duration::from_secs(1));
				},
				r => return r,
			}
		}
	}

	/// Reads `reads` of the node at once, where it takes a batch (one request
	/// for up to [`BATCH_MOST`] of them), into what the view keeps; the reads
	/// a command then makes are answered from it. Where it takes none, or the
	/// batch fails, nothing is kept and each read is made on its own when it
	/// comes: a read ahead changes no answer, only how many requests make it.
	fn read_ahead(&self, reads: Vec<(String, Vec<Value>)>) {
		let mut m = self.memo.lock().expect("the chain memo");
		if m.batch == Some(false) {
			drop(m);
			let _ = self.look(&mut self.memo.lock().expect("the chain memo"));
			return;
		}
		// Whether the node takes a batch is learnt from a look alone.
		if m.batch.is_none() && self.look(&mut m).is_err() {
			return;
		}
		if m.batch == Some(false) {
			return;
		}
		let due = Self::look_due(&m);
		let mut seen = std::collections::HashSet::new();
		let todo: Vec<(String, Vec<Value>)> = reads.into_iter().filter(|(method, params)| {
			let k = Self::read_key(method, params);
			// A look that is due may drop what the view keeps: read it again
			// in the same request.
			let kept = m.named.contains_key(&k) || (!due && (m.view.contains_key(&k) || m.pool.contains_key(&k) || m.command.contains_key(&k)));
			!matches!(keep_of(method, params), Keep::Never) && !m.unbatched.contains(method) && !kept && seen.insert(k)
		}).collect();
		let mut rest: &[(String, Vec<Value>)] = &todo;
		if due {
			// The look carries the first reads, within one batch's calls.
			let first = rest.len().min(BATCH_MOST - LOOK.len());
			match self.look_with(&mut m, &rest[..first]) {
				Ok(Some(answers)) => {
					Self::keep_all(&mut m, &rest[..first], answers);
					rest = &rest[first..];
				},
				Ok(None) if m.batch == Some(true) => {},
				_ => return,
			}
		}
		if rest.len() < 2 {
			return;
		}
		drop(m);
		for chunk in rest.chunks(BATCH_MOST) {
			let answers = self.batch_patiently(chunk);
			let mut m = self.memo.lock().expect("the chain memo");
			m.asked += 1;
			match answers {
				Ok(answers) => {
					m.batch = Some(true);
					Self::keep_all(&mut m, chunk, answers);
				},
				Err(RpcError::Transport(_)) => return,
				Err(_) => {
					m.batch = Some(false);
					return;
				},
			}
		}
	}

	/// Keeps the answers to `reads`, each as its read is kept; a node busy
	/// with another scan gave no answer, and none is kept for it.
	fn keep_all(m: &mut Memo, reads: &[(String, Vec<Value>)], answers: Vec<Result<Value, RpcError>>) {
		for ((method, params), a) in reads.iter().zip(answers) {
			let Ok(a) = kept_of(a) else { continue };
			Self::keep(m, &keep_of(method, params), Self::read_key(method, params), &a);
		}
	}

	/// Reads ahead what [`Self::finality`] and [`Self::median_time_at`] read
	/// of each of `txids` (its bytes, where it is, its block's header, its
	/// height's hash)
	/// and of the tip, in two batches ([`Self::read_ahead`]); and, for each
	/// of `outpoints`, whether it is unspent ([`Self::unspent`]).
	pub fn read_ahead_of(&self, txids: &[Txid], outpoints: &[OutPoint]) {
		let Ok(info) = self.info() else { return };
		let tip = json!(info.best_block_hash.to_string());
		let mut first = vec![("getblockheader".to_string(), vec![tip.clone(), json!(true)]), ("getblockheader".to_string(), vec![tip, json!(false)])];
		first.extend(txids.iter().map(|t| ("getrawtransaction".to_string(), vec![json!(t.to_string()), json!(true)])));
		first.extend(txids.iter().map(|t| ("getrawtransaction".to_string(), vec![json!(t.to_string())])));
		first.extend(outpoints.iter().map(|o| ("gettxout".to_string(), vec![json!(o.txid.to_string()), json!(o.vout), json!(true)])));
		self.read_ahead(first);
		if self.memo.lock().expect("the chain memo").batch != Some(true) {
			return;
		}
		let mut second = vec![];
		for t in txids {
			match self.call::<Value>("getrawtransaction", &[json!(t.to_string()), json!(true)]) {
				Ok(v) => if let Some(h) = v["blockhash"].as_str() {
					second.push(("getblockheader".to_string(), vec![json!(h), json!(true)]));
					second.push(("getblockheader".to_string(), vec![json!(h), json!(false)]));
					// Its height, from its confirmations in this view.
					if let Some(c) = v["confirmations"].as_u64().filter(|c| *c >= 1 && *c <= info.blocks + 1) {
						second.push(("getblockhash".to_string(), vec![json!(info.blocks + 1 - c)]));
					}
				},
				Err(_) => second.push(("getmempoolentry".to_string(), vec![json!(t.to_string())])),
			}
		}
		self.read_ahead(second);
	}

	/// [`Self::read`], its answer as `T`.
	fn call<T: DeserializeOwned>(&self, method: &str, params: &[Value]) -> Result<T, RpcError> {
		serde_json::from_value(self.read(method, params)?).map_err(|e| RpcError::Json(e.to_string()))
	}

	fn info(&self) -> Result<BlockchainInfo, RpcError> {
		self.call("getblockchaininfo", &[])
	}

	fn raw_block(&self, hash: &BlockHash) -> Result<Block, RpcError> {
		let hex: String = self.call("getblock", &[json!(hash.to_string()), json!(0)])?;
		decode("block", &hex)
	}

	pub fn genesis(&self) -> Result<BlockHash, Error> {
		self.call("getblockhash", &[json!(0)]).map_err(node)
	}

	/// The node's chain name (`test`, `sequentia`, `elementsregtest`, …).
	pub fn chain_name(&self) -> Result<String, Error> {
		Ok(self.info().map_err(node)?.chain)
	}

	pub fn tip(&self) -> Result<Tip, Error> {
		let info = self.info().map_err(node)?;
		Ok(Tip { height: info.blocks, hash: info.best_block_hash, median_time: info.median_time as u32 })
	}

	/// The hash of the active chain's block at `height`, if the chain is that
	/// long.
	pub fn block_hash(&self, height: u64) -> Result<Option<BlockHash>, Error> {
		match self.call::<BlockHash>("getblockhash", &[json!(height)]) {
			Ok(h) => Ok(Some(h)),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// A transaction from the chain or the mempool, if the node has it.
	pub fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
		let hex = match self.call::<String>("getrawtransaction", &[json!(txid.to_string())]) {
			Ok(h) => h,
			Err(e) if not_found(&e) => return Ok(None),
			Err(e) => return Err(node(e)),
		};
		decode("transaction", &hex).map(Some).map_err(node)
	}

	/// The median time of the active chain's block at `height`.
	pub fn median_time_at(&self, height: u64) -> Result<Option<u32>, Error> {
		let Some(hash) = self.block_hash(height)? else { return Ok(None) };
		let v: Value = self.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		Ok(v["mediantime"].as_u64().map(|t| t.min(u32::MAX as u64) as u32))
	}

	/// Whether `txid` is in a block of the active chain, and whether it is in
	/// the mempool: a cheap look, without the finality of the block.
	pub fn whereabouts(&self, txid: &Txid) -> Result<(bool, bool), Error> {
		if self.tx_block(txid)?.is_some() {
			return Ok((true, false));
		}
		Ok((false, self.in_mempool(txid)?))
	}

	fn in_mempool(&self, txid: &Txid) -> Result<bool, Error> {
		match self.call::<Value>("getmempoolentry", &[json!(txid.to_string())]) {
			Ok(_) => Ok(true),
			Err(e) if not_found(&e) => Ok(false),
			Err(e) => Err(node(e)),
		}
	}

	/// The active-chain block holding `txid`, and its height.
	pub(crate) fn tx_block(&self, txid: &Txid) -> Result<Option<(BlockHash, u64)>, Error> {
		let v: Value = match self.call("getrawtransaction", &[json!(txid.to_string()), json!(true)]) {
			Ok(v) => v,
			Err(e) if not_found(&e) => return Ok(None),
			Err(e) => return Err(node(e)),
		};
		let Some(hash) = v["blockhash"].as_str() else { return Ok(None) };
		let hash = BlockHash::from_str(hash).map_err(|e| Error::Node(e.to_string()))?;
		let h: Value = self.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		// A block the node holds off its active chain reports -1.
		if h["confirmations"].as_i64().unwrap_or(-1) < 1 {
			return Ok(None);
		}
		Ok(Some((hash, h["height"].as_u64().unwrap_or(0))))
	}

	fn header(&self, hash: &BlockHash) -> Result<(u64, Option<bool>), Error> {
		let hex: String = self.call("getblockheader", &[json!(hash.to_string()), json!(false)]).map_err(node)?;
		let raw: BlockHeader = decode("block header", &hex).map_err(node)?;
		let v: Value = self.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		Ok((raw.bitcoin_anchor().height as u64, v["poscertified"].as_bool()))
	}

	/// Where `txid` stands now. See the [module documentation](self).
	pub fn finality(&self, txid: &Txid) -> Result<Finality, Error> {
		let Some((block, height)) = self.tx_block(txid)? else {
			return Ok(Finality::NotInChain { in_mempool: self.in_mempool(txid)? });
		};
		let tip = self.tip()?;
		let (anchor, certified) = self.header(&block)?;
		// A chain without a committee reports no certificate at all; on a
		// committee chain a block is certified when it or a block above it is.
		let certified = match certified {
			None => true,
			Some(true) => true,
			Some(false) => {
				let mut found = false;
				let top = tip.height.min(height + CERT_LOOKAHEAD);
				for h in (height + 1)..=top {
					let Some(hash) = self.block_hash(h)? else { break };
					if self.header(&hash)?.1 == Some(true) {
						found = true;
						break;
					}
				}
				found
			},
		};
		if !certified {
			return Ok(Finality::Unsettled { height });
		}
		let (tip_anchor, _) = self.header(&tip.hash)?;
		let depth = tip_anchor.saturating_sub(anchor);
		let anchor_ok = {
			let v: Value = self.call("getanchorstatus", &[]).map_err(node)?;
			v["validateanchor"].as_bool().unwrap_or(false) && v["anchorstatus"].as_str() == Some("ok")
		};
		if depth >= ANCHOR_DEPTH && anchor_ok {
			Ok(Finality::Final { height, depth })
		} else {
			Ok(Finality::Settled { height, depth })
		}
	}

	/// The node's anchor status in a word (whether it validates anchors and
	/// how it finds them): a block's finality counts on it, so a change of it
	/// is a change of what the wallet read as final.
	pub fn anchor_word(&self) -> Result<String, Error> {
		let v: Value = self.call("getanchorstatus", &[]).map_err(node)?;
		Ok(format!("{} {}", v["validateanchor"], v["anchorstatus"]))
	}

	/// Whether the node validates its anchors against the parent chain.
	pub fn validates_anchors(&self) -> Result<bool, Error> {
		let v: Value = self.call("getanchorstatus", &[]).map_err(node)?;
		Ok(v["validateanchor"].as_bool().unwrap_or(false))
	}

	/// Broadcasts `tx`. One the node already holds is not an error.
	pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
		match self.call::<Txid>("sendrawtransaction", &[json!(hex(&elements::encode::serialize(tx)))]) {
			Ok(txid) => Ok(txid),
			Err(RpcError::Rpc { message, .. }) if message.contains("txn-already-in-mempool")
				|| message.contains("txn-already-known")
				|| message.contains("already in utxo set")
				|| message.contains("already in block chain") => Ok(tx.txid()),
			Err(RpcError::Rpc { message, .. }) => Err(Error::Refused(format!("the node refused {}: {}", tx.txid(), message))),
			Err(e) => Err(node(e)),
		}
	}

	/// Broadcasts `tx` whatever fee rate it pays: a claim racing a refund for
	/// a received leaf may pay most of the leaf in fees, above the ceiling
	/// `sendrawtransaction` puts on a fee rate unless told otherwise. One the
	/// node already holds is not an error.
	pub fn broadcast_any_fee(&self, tx: &Transaction) -> Result<Txid, Error> {
		match self.call::<String>("sendrawtransaction", &[json!(hex(&elements::encode::serialize(tx))), json!(0)]) {
			Ok(t) => Txid::from_str(&t).map_err(|e| Error::Node(e.to_string())),
			Err(RpcError::Rpc { message, .. }) if message.contains("txn-already-in-mempool")
				|| message.contains("txn-already-known")
				|| message.contains("already in utxo set")
				|| message.contains("already in block chain") => Ok(tx.txid()),
			Err(RpcError::Rpc { message, .. }) => Err(Error::Refused(format!("the node refused {}: {}", tx.txid(), message))),
			Err(e) => Err(node(e)),
		}
	}

	/// The node's fee whitelist now: each accepted fee asset and its rate.
	pub fn fee_rates(&self) -> Result<BTreeMap<AssetId, u64>, Error> {
		// What the node values at broadcast, read together: a relay floor
		// asks all three.
		self.read_ahead(["getfeeexchangerates", "dumpassetlabels", "getmempoolinfo"].map(|c| (c.to_string(), vec![])).to_vec());
		let rates: BTreeMap<String, u64> = self.call("getfeeexchangerates", &[]).map_err(node)?;
		let labels: BTreeMap<String, AssetId> = self.call("dumpassetlabels", &[]).map_err(node)?;
		rates.into_iter().map(|(name, rate)| {
			let asset = match labels.get(&name) {
				Some(a) => *a,
				None => AssetId::from_str(&name).map_err(|e| Error::Node(format!("the node's fee whitelist names {}: {}", name, e)))?,
			};
			Ok((asset, rate))
		}).collect()
	}

	/// The supervised assets the node lists now (`getsupervisedassets`):
	/// assets whose issuer can freeze holdings by consensus rule, committed
	/// in their ids. A node without the supervision registry lists none.
	pub fn supervised_assets(&self) -> Result<BTreeSet<AssetId>, Error> {
		let v: Value = match self.call("getsupervisedassets", &[]) {
			Ok(v) => v,
			Err(RpcError::Rpc { code: -32601, .. }) => return Ok(BTreeSet::new()),
			Err(e) => return Err(node(e)),
		};
		v.as_array().cloned().unwrap_or_default().iter()
			.map(|a| AssetId::from_str(a["asset"].as_str().unwrap_or("")).map_err(|e| Error::Node(format!("getsupervisedassets: {}", e))))
			.collect()
	}

	/// Whether `script`, a single-owner script (a landing's P2WPKH), is
	/// frozen for the supervised `asset` at the node's tip, and whether the
	/// asset is paused (`isassetfrozen`). Never asked of an Arca script: the
	/// node calls one frozen once it is named, although its script-path
	/// spends confirm.
	pub fn freeze_status(&self, asset: AssetId, script: &Script) -> Result<(bool, bool), Error> {
		let v: Value = self.call("isassetfrozen", &[json!(asset.to_string()), json!(hex(script.as_bytes()))]).map_err(node)?;
		Ok((v["frozen"].as_bool().unwrap_or(false), v["paused"].as_bool().unwrap_or(false)))
	}

	/// The node's relay floor in `asset`'s own atoms per 1,000 vbytes, now;
	/// `None` when the node does not accept `asset` for fees.
	pub fn floor_per_kvb(&self, asset: AssetId) -> Result<Option<u64>, Error> {
		let rates = self.fee_rates()?;
		let rate = match rates.get(&asset) {
			Some(r) if *r > 0 => *r as u128,
			_ => return Ok(None),
		};
		let v: Value = self.call("getmempoolinfo", &[]).map_err(node)?;
		let units = v["minrelaytxfee"].as_f64().ok_or_else(|| Error::Node("no minrelaytxfee".into()))?;
		let floor = (units * 100_000_000.0).round() as u128;
		// The node values a atoms at a × rate / 10^8 reference units.
		Ok(Some((floor * 100_000_000).div_ceil(rate).max(1).min(u64::MAX as u128) as u64))
	}

	/// The fee `txid` pays as the node valued it when its mempool took it, in
	/// atoms of the node's reference unit (`getmempoolentry`'s `fees.base`);
	/// `None` when it is not in the mempool. A replacement outbids it on
	/// that value, whatever the fee asset's rate is now.
	pub fn mempool_fee_value(&self, txid: &Txid) -> Result<Option<u64>, Error> {
		match self.call::<Value>("getmempoolentry", &[json!(txid.to_string())]) {
			Ok(v) => Ok(v["fees"]["base"].as_f64().map(|f| (f * 100_000_000.0).round().max(0.0) as u64)),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// The active chain's block at `height`, if the chain is that long.
	pub fn block_at(&self, height: u64) -> Result<Option<Block>, Error> {
		let Some(hash) = self.block_hash(height)? else { return Ok(None) };
		self.raw_block(&hash).map(Some).map_err(node)
	}

	/// The txids in the node's mempool.
	pub fn mempool(&self) -> Result<Vec<Txid>, Error> {
		self.call("getrawmempool", &[]).map_err(node)
	}

	/// The median time a relative lock on an output of `txid` counts from:
	/// that of the block before the one holding `txid` (BIP68); `None` while
	/// `txid` is in no block of the active chain.
	pub fn coin_time(&self, txid: &Txid) -> Result<Option<u32>, Error> {
		let Some((_, height)) = self.tx_block(txid)? else { return Ok(None) };
		if height == 0 {
			return Ok(None);
		}
		self.median_time_at(height - 1)
	}

	/// Whether `outpoint` is unspent, the mempool's spends included.
	pub fn unspent(&self, outpoint: &OutPoint) -> Result<bool, Error> {
		let v: Value = self.call("gettxout", &[json!(outpoint.txid.to_string()), json!(outpoint.vout), json!(true)])
			.map_err(node)?;
		Ok(!v.is_null())
	}

	/// The unspent outputs of the active chain paying any of `scripts`, each
	/// with its height, read from the node's UTXO set.
	pub fn coins_at(&self, scripts: &[Script]) -> Result<Vec<(OutPoint, TxOut, u64)>, Error> {
		if scripts.is_empty() {
			return Ok(vec![]);
		}
		let descs: Vec<Value> = scripts.iter().map(|s| json!(format!("raw({})", hex(s.as_bytes())))).collect();
		let v: Value = self.call("scantxoutset", &[json!("start"), Value::Array(descs)]).map_err(node)?;
		let mut out = vec![];
		for u in v["unspents"].as_array().cloned().unwrap_or_default() {
			let txid = Txid::from_str(u["txid"].as_str().unwrap_or("")).map_err(|e| Error::Node(e.to_string()))?;
			let vout = u["vout"].as_u64().unwrap_or(0) as u32;
			let Some(tx) = self.transaction(&txid)? else { continue };
			let Some(o) = tx.output.get(vout as usize) else { continue };
			out.push((OutPoint::new(txid, vout), o.clone(), u["height"].as_u64().unwrap_or(0)));
		}
		Ok(out)
	}

	/// Where each of `outputs` is now: an output equal to it (asset, value and
	/// script) that is unspent in the active chain's set of unspent outputs or
	/// made by a transaction in the mempool, and spent by nothing in the
	/// mempool; `None` where there is none. Outputs are found by script, so
	/// one paying the script another amount is not taken for it.
	pub fn locate(&self, outputs: &[TxOut]) -> Result<Vec<Option<OutPoint>>, Error> {
		let mut found: Vec<Option<OutPoint>> = vec![None; outputs.len()];
		if outputs.is_empty() {
			return Ok(found);
		}
		let mut scripts: Vec<Script> = outputs.iter().map(|o| o.script_pubkey.clone()).collect();
		scripts.sort();
		scripts.dedup();
		for (op, o, _) in self.coins_at(&scripts)? {
			if let Some(i) = outputs.iter().enumerate().position(|(i, w)| *w == o && found[i].is_none()) {
				if self.unspent(&op)? {
					found[i] = Some(op);
				}
			}
		}
		let ids: Vec<String> = self.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			let Some(tx) = self.transaction(&txid)? else { continue };
			for (j, o) in tx.output.iter().enumerate() {
				if let Some(i) = outputs.iter().enumerate().position(|(i, w)| w == o && found[i].is_none()) {
					let op = OutPoint::new(txid, j as u32);
					if self.unspent(&op)? {
						found[i] = Some(op);
					}
				}
			}
		}
		Ok(found)
	}

	/// Which of `scripts`, the lineage of a coin that descends from `roots`
	/// ([`arca_covenant::ValidCoin::roots`]), an output of the active chain or
	/// of the mempool pays. Every output of the lineage is made only by a
	/// chain of spends that starts at a root, so a root unspent in the chain
	/// and in the mempool has nothing of it on-chain, and no block is read for
	/// it: one batch of `gettxout` answers a coin whose roots all stand, as a
	/// received coin's do. The blocks are read only from the lowest block
	/// holding a spent root, where its spender and every descendant are; and
	/// from `from_height` when a spent root's transaction is in no block of
	/// the active chain (the node read it for no root it holds).
	pub fn lineage_seen(&self, scripts: &BTreeSet<Script>, roots: &[OutPoint], from_height: u64) -> Result<BTreeSet<Script>, Error> {
		if scripts.is_empty() {
			return Ok(BTreeSet::new());
		}
		match self.descendants_from(roots, from_height)? {
			None => Ok(BTreeSet::new()),
			Some(from) => self.scripts_seen(scripts, from),
		}
	}

	/// The lowest height of the active chain at which an output descending
	/// from `roots` can be, `None` when none can: every root unspent, in the
	/// chain and in the mempool, has nothing made from it anywhere. A spent
	/// root's descendants are at or above its own block, or in the mempool
	/// alone (above the tip) when the root was made there; `from_height`
	/// where its transaction is in no block of the active chain.
	pub fn descendants_from(&self, roots: &[OutPoint], from_height: u64) -> Result<Option<u64>, Error> {
		self.read_ahead(roots.iter().map(|o| ("gettxout".to_string(), vec![json!(o.txid.to_string()), json!(o.vout), json!(true)])).collect());
		let mut from: Option<u64> = None;
		for root in roots {
			if self.unspent(root)? {
				continue;
			}
			let at = match self.tx_block(&root.txid)? {
				Some((_, h)) => h,
				None if self.in_mempool(&root.txid)? => self.tip()?.height.saturating_add(1),
				None => from_height,
			};
			from = Some(from.map_or(at, |f| f.min(at)));
		}
		Ok(from)
	}

	/// Which of `scripts` an output of the active chain from `from_height` up,
	/// or of the mempool, pays: the index of the chain the lineage check asks.
	pub fn scripts_seen(&self, scripts: &BTreeSet<Script>, from_height: u64) -> Result<BTreeSet<Script>, Error> {
		let mut seen = BTreeSet::new();
		if scripts.is_empty() {
			return Ok(seen);
		}
		let mut look = |tx: &Transaction| {
			for o in &tx.output {
				if scripts.contains(&o.script_pubkey) {
					seen.insert(o.script_pubkey.clone());
				}
			}
		};
		self.each_block(from_height, |_, block| {
			block.txdata.iter().for_each(&mut look);
			Ok(false)
		})?;
		for tx in self.mempool_txs()? {
			look(&tx);
		}
		Ok(seen)
	}

	/// The first transaction of the active chain from `from_height` up that
	/// pays `output` (asset, value and script), if any: what a wallet re-checks
	/// a leaf against when its round is gone.
	pub fn find_payment(&self, output: &TxOut, from_height: u64) -> Result<Option<(Transaction, u64)>, Error> {
		let mut found = None;
		self.each_block(from_height, |h, block| {
			found = block.txdata.into_iter().find(|tx| tx.output.iter().any(|o| o == output)).map(|tx| (tx, h));
			Ok(found.is_some())
		})?;
		Ok(found)
	}

	/// The transaction that spends `outpoint`, in the mempool or in a block
	/// of the active chain from `from_height` up, and its height (`None` for
	/// the mempool). An output unspent in the chain and in the mempool has
	/// none, and no block is read for it; a spent one's spender is in no
	/// block below the one holding the output.
	pub fn spender(&self, outpoint: &OutPoint, from_height: u64) -> Result<Option<(Transaction, Option<u64>)>, Error> {
		if self.unspent(outpoint)? {
			return Ok(None);
		}
		let spends = |tx: &Transaction| tx.input.iter().any(|i| i.previous_output == *outpoint);
		if let Some(tx) = self.mempool_txs()?.into_iter().find(|tx| spends(tx)) {
			return Ok(Some((tx, None)));
		}
		let from = match self.tx_block(&outpoint.txid)? {
			Some((_, h)) => from_height.max(h),
			None => from_height,
		};
		let mut found = None;
		self.each_block(from, |h, block| {
			found = block.txdata.into_iter().find(|tx| spends(tx)).map(|tx| (tx, Some(h)));
			Ok(found.is_some())
		})?;
		Ok(found)
	}

	/// Every block of the active chain from `from_height` to the tip, in
	/// order, handed to `f` until it answers `true`. Read [`BATCH_MOST`] at a
	/// time, where the node takes a batch: a node behind a proxy answers each
	/// request after a round trip, and one read per block made a scan of an
	/// hour of blocks take minutes.
	fn each_block(&self, from_height: u64, f: impl FnMut(u64, Block) -> Result<bool, Error>) -> Result<(), Error> {
		let tip = self.tip()?.height;
		self.each_block_to(from_height, tip, f)
	}

	/// [`Self::each_block`], from `from_height` to `to_height` at most.
	pub fn each_block_to(&self, from_height: u64, to_height: u64, mut f: impl FnMut(u64, Block) -> Result<bool, Error>) -> Result<(), Error> {
		let tip = Tip { height: to_height.min(self.tip()?.height), ..self.tip()? };
		let mut h = from_height;
		while h <= tip.height {
			let end = h.saturating_add(BATCH_MOST as u64 - 1).min(tip.height);
			self.read_ahead((h..=end).map(|x| ("getblockhash".to_string(), vec![json!(x)])).collect());
			let mut hashes = Vec::with_capacity((end - h + 1) as usize);
			for x in h..=end {
				match self.block_hash(x)? {
					Some(hash) => hashes.push((x, hash)),
					None => break,
				}
			}
			self.read_ahead(hashes.iter().map(|(_, hash)| ("getblock".to_string(), vec![json!(hash.to_string()), json!(0)])).collect());
			let short = hashes.len() as u64 != end - h + 1;
			for (x, hash) in hashes {
				if f(x, self.raw_block(&hash).map_err(node)?)? {
					return Ok(());
				}
			}
			if short {
				break;
			}
			h = end + 1;
		}
		Ok(())
	}

	/// The transactions in the node's mempool, read at once where the node
	/// takes a batch.
	pub fn mempool_txs(&self) -> Result<Vec<Transaction>, Error> {
		let ids: Vec<String> = self.call("getrawmempool", &[]).map_err(node)?;
		self.read_ahead(ids.iter().map(|t| ("getrawtransaction".to_string(), vec![json!(t)])).collect());
		let mut txs = Vec::with_capacity(ids.len());
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			if let Some(tx) = self.transaction(&txid)? {
				txs.push(tx);
			}
		}
		Ok(txs)
	}

	/// Whether `tx` can never return to the chain: it is in no block of the
	/// active chain and not in the mempool, and one of the coins it spends is
	/// spent by another transaction that is final. One that is merely out of
	/// the chain, its coins unspent or spent only in blocks not yet final,
	/// can still return.
	pub fn gone(&self, tx: &Transaction) -> Result<bool, Error> {
		if self.whereabouts(&tx.txid())? != (false, false) {
			return Ok(false);
		}
		for i in &tx.input {
			let op = i.previous_output;
			let Some((_, height)) = self.tx_block(&op.txid)? else { continue };
			let v: Value = self.call("gettxout", &[json!(op.txid.to_string()), json!(op.vout), json!(false)]).map_err(node)?;
			if !v.is_null() {
				continue;
			}
			if let Some((other, Some(_))) = self.spender(&op, height)? {
				if other.txid() != tx.txid() && self.finality(&other.txid())?.is_final() {
					return Ok(true);
				}
			}
		}
		Ok(false)
	}

	/// The script the node reads `address` as, on its own chain: refused for
	/// a text that is no address of it.
	pub fn script_of(&self, address: &str) -> Result<Script, Error> {
		let v: Value = self.call("validateaddress", &[json!(address)]).map_err(node)?;
		if v["isvalid"].as_bool() != Some(true) {
			return Err(Error::Parse(format!("{} is no address of this chain", address)));
		}
		let spk = v["scriptPubKey"].as_str().ok_or_else(|| Error::Node(format!("the node reads {} as no script", address)))?;
		Ok(Script::from(unhex(spk)?))
	}

	/// Whether `address` is a confidential (blinded) address of the chain the
	/// node follows: one carrying a blinding key.
	pub fn is_confidential(&self, address: &str) -> Result<bool, Error> {
		let v: Value = self.call("validateaddress", &[json!(address)]).map_err(node)?;
		Ok(v["confidential_key"].as_str().is_some_and(|k| !k.is_empty()) || v["isconfidential"].as_bool() == Some(true))
	}

	/// The node's address for `script`, unblinded, on its own chain.
	pub fn address(&self, script: &Script) -> Result<Option<String>, Error> {
		let v: Value = self.call("decodescript", &[json!(hex(script.as_bytes()))]).map_err(node)?;
		Ok(v["address"].as_str().or_else(|| v["segwit"]["address"].as_str()).map(|s| s.to_string()))
	}
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Bytes from hex.
pub fn unhex(s: &str) -> Result<Vec<u8>, Error> {
	if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
		return Err(Error::Parse(format!("not hex: {}", s)));
	}
	Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked")).collect())
}

/// 32 bytes from hex.
pub fn unhex32(s: &str) -> Result<[u8; 32], Error> {
	unhex(s)?.try_into().map_err(|_| Error::Parse(format!("not 32 bytes: {}", s)))
}

#[cfg(test)]
mod test {
	use super::*;

	/// A command that shares the view answers from another's look made within
	/// BURST_VIEW_FOR; one that does not looks when it starts; one started
	/// later looks again, and a gap calls for a look at once.
	#[test]
	fn a_burst_of_commands_shares_one_look() {
		let mut m = Memo { looked: Some(web_time::Instant::now()), gaps: GAPS.load(Ordering::SeqCst), ..Default::default() };
		m.looked_this_command = true;
		assert!(!ChainSource::look_due(&m), "this command's own fresh look stands");
		m.looked_this_command = false;
		assert!(ChainSource::look_due(&m), "a command that does not share the view looks when it starts");
		m.shared = true;
		assert!(!ChainSource::look_due(&m), "the next command that shares it answers from it");
		m.looked = Some(web_time::Instant::now() - BURST_VIEW_FOR - std::time::Duration::from_millis(1));
		assert!(ChainSource::look_due(&m), "a look older than the burst window is not shared");
		m.looked = Some(web_time::Instant::now() - VIEW_FOR - std::time::Duration::from_millis(1));
		m.looked_this_command = true;
		assert!(ChainSource::look_due(&m), "within a command, a view stands a second at most");
		m.looked = Some(web_time::Instant::now());
		m.looked_this_command = false;
		gap();
		assert!(ChainSource::look_due(&m), "a gap calls for a look at once");
	}

	/// A broadcast calls for a look before the next read, within a command
	/// and in a burst alike: a command that sends one exit step and then the
	/// next must see its own transaction in the mempool.
	#[test]
	fn a_broadcast_calls_for_a_look_before_the_next_read() {
		let (url, requests) = picky_proxy();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let sent = || requests.load(Ordering::SeqCst);
		assert!(chain.validates_anchors().unwrap());
		let n = sent();
		chain.new_command();
		chain.share_view();
		let _ = chain.read("sendrawtransaction", &[json!("00")]);
		assert_eq!(sent(), n + 1, "the broadcast itself");
		assert!(chain.validates_anchors().unwrap());
		assert_eq!(sent(), n + 2, "a look before the next read, though the last was a moment ago");
	}

	#[test]
	fn what_a_view_keeps_and_what_it_never_keeps() {
		let txid = json!("00".repeat(32));
		// Fixed by the id, hash or script they name, whatever the view.
		assert!(matches!(keep_of("getrawtransaction", &[txid.clone()]), Keep::Named));
		assert!(matches!(keep_of("getblockheader", &[txid.clone(), json!(false)]), Keep::Named));
		assert!(matches!(keep_of("getblock", &[txid.clone(), json!(0)]), Keep::Named));
		assert!(matches!(keep_of("decodescript", &[json!("51")]), Keep::Named));
		// Fixed by the view: where a transaction is, a header's confirmations
		// and certificate, an output, the set of unspent outputs, the tip.
		assert!(matches!(keep_of("getrawtransaction", &[txid.clone(), json!(true)]), Keep::View));
		assert!(matches!(keep_of("getblockheader", &[txid.clone(), json!(true)]), Keep::View));
		for m in ["getblockchaininfo", "getblockhash", "gettxout", "scantxoutset", "getrawmempool", "getmempoolentry", "getanchorstatus",
			"getsupervisedassets"] {
			assert!(matches!(keep_of(m, &[]), Keep::View), "{}", m);
		}
		// What the node values at broadcast changes while the view stands:
		// read again in every command.
		for m in ["getfeeexchangerates", "dumpassetlabels", "getmempoolinfo"] {
			assert!(matches!(keep_of(m, &[]), Keep::Command), "{}", m);
		}
		// A broadcast, and anything not named, is never kept.
		for m in ["sendrawtransaction", "testmempoolaccept", "getnewaddress"] {
			assert!(matches!(keep_of(m, &[]), Keep::Never), "{}", m);
		}
	}

	#[test]
	fn the_nodes_refusals_are_kept_and_its_silence_is_not() {
		assert_eq!(kept_of(Err(RpcError::Rpc { code: -5, message: "No such transaction".into() })).unwrap(), Err((-5, "No such transaction".into())));
		assert!(kept_of(Err(RpcError::Transport("refused".into()))).is_err(), "no answer is no answer of the view");
		assert!(matches!(answer_of(&Err((-8, "out of range".into()))), Err(RpcError::Rpc { code: -8, .. })));
		let busy = RpcError::Rpc { code: -8, message: "Scan already in progress, use action \"abort\" or \"status\"".into() };
		assert!(kept_of(Err(busy)).is_err(), "a node busy with another scan gave no answer of the view");
	}

	/// A node on a local port that answers the view's three reads the same
	/// every time and refuses the first `busy` scans of its set of unspent
	/// outputs as a node does while another client's scan runs; it counts
	/// the scans it was asked for.
	fn busy_node(busy: u64) -> (String, Arc<AtomicU64>) {
		use std::io::{BufRead, BufReader, Read, Write};
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let scans = Arc::new(AtomicU64::new(0));
		let counted = scans.clone();
		std::thread::spawn(move || {
			let answer = |call: &Value| -> Value {
				let (id, method) = (call["id"].clone(), call["method"].as_str().unwrap_or(""));
				let result = match method {
					"getblockchaininfo" => json!({"bestblockhash": "11".repeat(32), "blocks": 1}),
					"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
					"getrawmempool" => json!([]),
					"scantxoutset" => {
						if counted.fetch_add(1, Ordering::SeqCst) < busy {
							return json!({"id": id, "result": null, "error": {"code": -8,
								"message": "Scan already in progress, use action \"abort\" or \"status\""}});
						}
						json!({"success": true, "unspents": []})
					},
					_ => return json!({"id": id, "result": null, "error": {"code": -32601, "message": "Method not found"}}),
				};
				json!({"id": id, "result": result, "error": null})
			};
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else { continue };
				let mut reader = BufReader::new(stream.try_clone().unwrap());
				let mut length = 0usize;
				loop {
					let mut line = String::new();
					if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
						break;
					}
					if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
						length = v.trim().parse().unwrap_or(0);
					}
				}
				let mut body = vec![0u8; length];
				if reader.read_exact(&mut body).is_err() {
					continue;
				}
				let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
				let out = match &req {
					Value::Array(calls) => Value::Array(calls.iter().map(|c| answer(c)).collect()),
					call => answer(call),
				}.to_string();
				let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
					out.len(), out);
			}
		});
		(url, scans)
	}

	/// The node runs one scan of its set of unspent outputs at a time, for
	/// every client it has: while another wallet's scan runs, it refuses
	/// this one. That refusal says nothing of the chain, so it is never kept
	/// as the view's answer: the scan waits for the other one to end and is
	/// asked again, and the answer is the chain's.
	#[test]
	fn a_scan_waits_while_another_clients_scan_runs() {
		let (url, scans) = busy_node(3);
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let script = Script::from(vec![0x51]);
		let found = chain.coins_at(std::slice::from_ref(&script));
		assert!(matches!(found, Ok(ref v) if v.is_empty()), "the scan answers once the other one is over: {:?}", found);
		assert_eq!(scans.load(Ordering::SeqCst), 4, "three refused while busy, then the one answered");
		// The view stands: the answer is kept, and the node not asked again.
		assert!(chain.coins_at(std::slice::from_ref(&script)).is_ok());
		assert_eq!(scans.load(Ordering::SeqCst), 4);
	}

	/// A transaction spending `from` (an output at a bare `OP_TRUE` of
	/// `asset` holding `value`) into one output at `script`, less a fee.
	fn spend_to(from: OutPoint, asset: AssetId, value: u64, script: Script) -> Transaction {
		use elements::confidential;
		let fee = 10_000;
		Transaction {
			version: 2,
			lock_time: elements::LockTime::ZERO,
			input: vec![elements::TxIn { previous_output: from, sequence: elements::Sequence::MAX, ..Default::default() }],
			output: vec![
				TxOut { asset: confidential::Asset::Explicit(asset), value: confidential::Value::Explicit(value - fee),
					nonce: confidential::Nonce::Null, script_pubkey: script, witness: Default::default() },
				TxOut::new_fee(fee, asset),
			],
		}
	}

	/// A node behind a proxy that takes batches but refuses `getsupervisedassets`
	/// in one, answering the whole batch with a single error as the testnet's
	/// does; it counts the requests it was sent.
	fn picky_proxy() -> (String, Arc<AtomicU64>) {
		use std::io::{BufRead, BufReader, Read, Write};
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let requests = Arc::new(AtomicU64::new(0));
		let counted = requests.clone();
		std::thread::spawn(move || {
			let answer = |call: &Value| -> Value {
				let (id, method) = (call["id"].clone(), call["method"].as_str().unwrap_or(""));
				let result = match method {
					"getblockchaininfo" => json!({"bestblockhash": "11".repeat(32), "blocks": 1}),
					"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
					"getrawmempool" => json!([]),
					"getsupervisedassets" => json!([]),
					"getfeeexchangerates" | "dumpassetlabels" => json!({}),
					"getmempoolinfo" => json!({"minrelaytxfee": 0.00001}),
					_ => return json!({"id": id, "result": null, "error": {"code": -32601, "message": "Method not found"}}),
				};
				json!({"id": id, "result": result, "error": null})
			};
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else { continue };
				let mut reader = BufReader::new(stream.try_clone().unwrap());
				let mut length = 0usize;
				loop {
					let mut line = String::new();
					if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
						break;
					}
					if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
						length = v.trim().parse().unwrap_or(0);
					}
				}
				let mut body = vec![0u8; length];
				if reader.read_exact(&mut body).is_err() {
					continue;
				}
				counted.fetch_add(1, Ordering::SeqCst);
				let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
				let out = match &req {
					Value::Array(calls) if calls.iter().any(|c| c["method"] == "getsupervisedassets") =>
						json!({"id": 2, "result": null, "error": {"code": -32601, "message": "in a batch: method not allowed here: getsupervisedassets"}}),
					Value::Array(calls) => Value::Array(calls.iter().map(|c| answer(c)).collect()),
					call => answer(call),
				}.to_string();
				let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
					out.len(), out);
			}
		});
		(url, requests)
	}

	/// Over a link where each request is a round trip, a look at the view
	/// rides in the request of the read that made it due; a method the node
	/// refuses in a batch is learnt and asked on its own, and the node is
	/// still asked in batches for the rest.
	#[test]
	fn a_look_rides_with_a_read_and_a_refused_method_is_asked_alone() {
		let (url, requests) = picky_proxy();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let sent = || requests.load(Ordering::SeqCst);
		// The first look learns that the node takes a batch: one request.
		assert!(chain.validates_anchors().unwrap());
		assert_eq!(sent(), 1);
		// A new command: the look is due and carries the fee reads.
		chain.new_command();
		assert!(chain.fee_rates().unwrap().is_empty());
		assert_eq!(sent(), 2, "the look and the three fee reads in one request");
		// Kept within the command: no look, no request.
		assert!(chain.floor_per_kvb(AssetId::from_slice(&[7; 32]).unwrap()).unwrap().is_none());
		assert_eq!(sent(), 2);
		// A look carrying the supervised assets is refused whole; the look is
		// made again on its own and the read alone.
		chain.new_command();
		assert!(chain.supervised_assets().unwrap().is_empty());
		assert_eq!(sent(), 5, "the refused batch, the look again, the read alone");
		// From then on it is never carried, and batches go on.
		chain.new_command();
		assert!(chain.supervised_assets().unwrap().is_empty());
		assert_eq!(sent(), 6, "a look alone; the read is kept for the view");
		chain.new_command();
		assert!(chain.fee_rates().unwrap().is_empty());
		assert_eq!(sent(), 7, "the node is still asked in batches");
	}

	/// A node whose mempool changes at every look and whose tip does not; it
	/// counts the calls of each method it was asked.
	fn busy_mempool() -> (String, Arc<Mutex<HashMap<String, u64>>>) {
		use std::io::{BufRead, BufReader, Read, Write};
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let counts: Arc<Mutex<HashMap<String, u64>>> = Default::default();
		let counted = counts.clone();
		std::thread::spawn(move || {
			let mut looks = 0u64;
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else { continue };
				let mut reader = BufReader::new(stream.try_clone().unwrap());
				let mut length = 0usize;
				loop {
					let mut line = String::new();
					if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
						break;
					}
					if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
						length = v.trim().parse().unwrap_or(0);
					}
				}
				let mut body = vec![0u8; length];
				if reader.read_exact(&mut body).is_err() {
					continue;
				}
				let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
				let mut answer = |call: &Value| -> Value {
					let (id, method) = (call["id"].clone(), call["method"].as_str().unwrap_or("").to_string());
					*counted.lock().unwrap().entry(method.clone()).or_default() += 1;
					let result = match method.as_str() {
						"getblockchaininfo" => json!({"bestblockhash": "11".repeat(32), "blocks": 1}),
						"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
						"getrawmempool" => { looks += 1; json!([format!("{:064x}", looks)]) },
						"getblockheader" => json!({"confirmations": 1, "height": 1}),
						"gettxout" => json!({"value": 1}),
						_ => return json!({"id": id, "result": null, "error": {"code": -32601, "message": "Method not found"}}),
					};
					json!({"id": id, "result": result, "error": null})
				};
				let out = match &req {
					Value::Array(calls) => Value::Array(calls.iter().map(|c| answer(c)).collect()),
					call => answer(call),
				}.to_string();
				let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
					out.len(), out);
			}
		});
		(url, counts)
	}

	/// On a busy chain the mempool changes between nearly every two looks:
	/// what the tip fixes (a block's header) is kept across such a change,
	/// and what the mempool fixes (an output looked up with its spends) is
	/// read again.
	#[test]
	fn a_change_of_the_mempool_keeps_what_the_tip_fixes() {
		let (url, counts) = busy_mempool();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let asked = |m: &str| counts.lock().unwrap().get(m).copied().unwrap_or(0);
		let hash = BlockHash::from_str(&"22".repeat(32)).unwrap();
		let op = OutPoint::new(Txid::from_str(&"33".repeat(32)).unwrap(), 0);
		for _ in 0..3 {
			chain.new_command();
			let h: Value = chain.call("getblockheader", &[json!(hash.to_string()), json!(true)]).unwrap();
			assert_eq!(h["height"], 1);
			assert!(chain.unspent(&op).unwrap());
		}
		assert!(asked("getrawmempool") >= 3, "a look in each command, the mempool another each time");
		assert_eq!(asked("getblockheader"), 1, "the header is read once: the tip did not move");
		assert_eq!(asked("gettxout"), 3, "the output with the mempool's spends is read again in each view");
	}

	/// What a receiver asks of the chain for a coin's lineage, on a regtest
	/// node: while the batch output the lineage descends from is unspent,
	/// no block is read and nothing is found; once a transaction spending
	/// it publishes a lineage output, in the mempool and then in a block, it
	/// is found, and the batch output's spender with it. The blocks are
	/// read only from the batch output's own block, a batch at a time.
	///
	/// Needs `SEQUENTIAD_EXEC`.
	#[cfg(not(target_arch = "wasm32"))]
	#[test]
	fn a_lineage_is_read_from_the_chain_only_once_its_root_is_spent() {
		use sequentia_ext::regtest::Regtest;
		if std::env::var_os("SEQUENTIAD_EXEC").is_none() {
			eprintln!("SEQUENTIAD_EXEC is not set: skipped");
			return;
		}
		let dir = tempfile::tempdir().unwrap();
		let r = Regtest::from_env(dir.path(), &["-acceptnonstdtxn=1"]);
		let url = format!("http://127.0.0.1:{}/", r.node.rpc_port());
		let chain = ChainSource::new(&url, Some("arca"), Some("arca"), None);
		let op_true = Script::from(vec![0x51]);
		// The genesis block's free coins, at a bare `OP_TRUE`.
		let genesis = chain.genesis().unwrap();
		let block = chain.raw_block(&genesis).unwrap();
		let (free, coin) = block.txdata.iter().flat_map(|t| t.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(t.txid(), i as u32), o.clone())))
			.find(|(_, o)| o.script_pubkey == op_true && o.value.explicit().is_some_and(|v| v > 1_000_000)).expect("free coins");
		let asset = coin.asset.explicit().unwrap();
		let value = coin.value.explicit().unwrap();
		// The batch output: a round's, standing in for one.
		let round = spend_to(free, asset, value, op_true.clone());
		r.node.client().send_raw_transaction(&round).unwrap();
		r.produce_block().unwrap();
		let root = OutPoint::new(round.txid(), 0);
		for _ in 0..(BATCH_MOST as u64 + 6) {
			r.produce_block().unwrap();
		}
		// Blocks made outside the source: its next read looks again.
		gap();
		chain.new_command();
		let round_height = chain.tx_block(&round.txid()).unwrap().unwrap().1;
		let tip = chain.tip().unwrap().height;
		println!("the round at height {}, the tip {} blocks above it", round_height, tip - round_height);
		// A lineage output: what an unroll of the batch's tree publishes.
		let leaf = Script::from(vec![0x01, 0xab, 0x75, 0x51]);
		let lineage: BTreeSet<Script> = [leaf.clone()].into();

		// BEFORE: the root stands, so no block is read and nothing is found.
		chain.new_command();
		let (asked, _) = chain.calls();
		assert!(chain.lineage_seen(&lineage, &[root], round_height).unwrap().is_empty());
		assert!(chain.spender(&root, round_height).unwrap().is_none());
		let (after, _) = chain.calls();
		println!("BEFORE: the root unspent; lineage_seen and spender took {} requests of the node", after - asked);
		// A look at the view (three calls, the node not yet asked for a
		// batch) and one gettxout: no block.
		assert!(after - asked <= 4, "{} requests", after - asked);
		// What reading every block from the round up costs, for the record.
		chain.new_command();
		let (asked, _) = chain.calls();
		assert!(chain.scripts_seen(&lineage, round_height).unwrap().is_empty());
		let (after, _) = chain.calls();
		println!("reading the {} blocks from the round up: {} requests (batches of {})", tip - round_height + 1, after - asked, BATCH_MOST);
		assert!(after - asked <= 2 * ((tip - round_height) / BATCH_MOST as u64 + 1) + 4, "{} requests", after - asked);

		// AFTER, in the mempool: the root's spender publishes the lineage output.
		let unroll = spend_to(root, asset, value - 10_000, leaf.clone());
		r.node.client().send_raw_transaction(&unroll).unwrap();
		gap();
		chain.new_command();
		assert_eq!(chain.lineage_seen(&lineage, &[root], round_height).unwrap(), lineage, "found in the mempool");
		let (by, at) = chain.spender(&root, round_height).unwrap().expect("the root's spender, in the mempool");
		assert_eq!((by.txid(), at), (unroll.txid(), None));
		println!("AFTER (mempool): the lineage output {} is found, the root's spender {}", hex(leaf.as_bytes()), by.txid());

		// AFTER, in a block.
		r.produce_block().unwrap();
		gap();
		chain.new_command();
		let height = chain.tip().unwrap().height;
		assert_eq!(chain.lineage_seen(&lineage, &[root], round_height).unwrap(), lineage, "found in a block");
		assert_eq!(chain.spender(&root, round_height).unwrap().map(|(t, h)| (t.txid(), h)), Some((unroll.txid(), Some(height))));
		assert_eq!(chain.find_payment(&unroll.output[0], round_height).unwrap().map(|(t, h)| (t.txid(), h)), Some((unroll.txid(), height)));
		// A spender is found whatever height it is asked from below the
		// root's block: never below it.
		assert_eq!(chain.spender(&root, 0).unwrap().map(|(t, _)| t.txid()), Some(unroll.txid()));
		println!("AFTER (block {}): the lineage output is found, the root's spender {}", height, unroll.txid());
	}
}
