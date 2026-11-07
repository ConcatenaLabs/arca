//! The wallet's chain source: a `sequentiad` reached over JSON-RPC.
//!
//! The wallet never counts confirmations. A transaction it relies on (a round,
//! a board) is **final** when its block is in the node's active chain,
//! certified by the committee (the node reports the certificate for that block
//! or for one above it), and its Bitcoin anchor is buried: the anchor height of
//! the tip less the block's is at least the anchor depth, while the node
//! reports its tip's anchor as validated and `ok`. That is the server's rule
//! and SeqLN's. Sequentia reorganises whenever its anchor does, with no depth
//! limit, so finality is read from the node in every view it is asked in
//! (below), and never remembered past it. Only a block's certificate is
//! kept, by the block's hash: the committee's countersignatures for a block
//! are only added, so a block certified stays certified. Whether it is still
//! in the active chain, how deep its anchor is buried and the node's anchor
//! status are read again in every view.
//!
//! **The anchor depth** is the operator's: the wallet judges finality as the
//! operator it uses does, from the `finality.anchor_depth` its `info`
//! publishes ([`ChainSource::follow_anchor_depth`]), so that a coin the
//! operator takes into a round is one the wallet calls final, and the other
//! way round. An operator that publishes none is held to [`ANCHOR_DEPTH`].
//! On the main chain (`sequentia`) the wallet never goes below
//! [`ANCHOR_DEPTH`], whatever the operator publishes. At depth 0 a coin is
//! final once its block is certified while the node's anchor status is `ok`:
//! a Bitcoin reorganisation of the anchored block still takes the block, and
//! everything built on it, out of the chain, and the wallet follows that as
//! it follows any other.
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
//! asked on their own. Both are learnt only from an answer that says so,
//! and tried again after ten minutes ([`BATCH_AGAIN_AFTER`]): a route that
//! is busy, restarting or out of time has that batch's reads made alone and
//! the next batch sent as before. A read ahead changes no answer, only the
//! number of requests that make it.
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

/// The Bitcoin blocks that bury a final block's anchor, when the operator
/// publishes no depth of its own, and the least the wallet accepts on the
/// main chain ([`ChainSource::follow_anchor_depth`]).
pub const ANCHOR_DEPTH: u64 = 2;

/// The most transactions [`ChainSource::gone`] reads walking back through
/// parents that are off the chain.
pub const GONE_REACH: usize = 512;

/// What is left of one [`ChainSource::gone`] walk: the transactions it may
/// still read, and whether it was cut short.
struct GoneWalk {
	left: usize,
	cut: bool,
}

/// The most transactions [`ChainSource::rebroadcast_with_parents`] sends
/// for one.
pub const REDO_REACH: usize = 64;

/// How far above a block the wallet looks for a committee certificate.
const CERT_LOOKAHEAD: u64 = 200;

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
	/// Not in a block of the active chain (perhaps in the mempool).
	NotInChain { in_mempool: bool },
	/// In a block the committee has not certified.
	Unsettled { height: u64 },
	/// In a certified block, its anchor buried fewer than the anchor depth's
	/// Bitcoin blocks ([`ChainSource::anchor_depth`]).
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
	/// The anchor depth finality counts ([`ChainSource::anchor_depth`]).
	anchor_depth: Arc<AtomicU64>,
	/// The most scripts one scan carries here: [`SCAN_WHOLE`] until the
	/// node's route refuses a scan of that many, then [`SCAN_MOST`]
	/// ([`ChainSource::coins_at`]).
	scan_most: Arc<AtomicU64>,
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

/// The requests made of the operator since the program started, by call:
/// how many, and the milliseconds spent waiting for their answers. What tells
/// a slow step's wait for the operator from its own work.
static OPERATOR_CALLS: Mutex<BTreeMap<String, (u64, u64)>> = Mutex::new(BTreeMap::new());

/// A request to the operator's `call` took `took`.
pub fn operator_call(call: &str, took: std::time::Duration) {
	let mut m = OPERATOR_CALLS.lock().expect("the operator's calls");
	let e = m.entry(call.to_string()).or_default();
	e.0 += 1;
	e.1 += took.as_millis() as u64;
}

/// [`operator_call`]'s counts so far.
pub fn operator_calls() -> BTreeMap<String, (u64, u64)> {
	OPERATOR_CALLS.lock().expect("the operator's calls").clone()
}

/// The requests to the operator between `before` and `after`
/// ([`operator_calls`]): the milliseconds waited in all, and by call `[count,
/// ms]`.
pub fn operator_between(before: &BTreeMap<String, (u64, u64)>, after: &BTreeMap<String, (u64, u64)>) -> (u64, Value) {
	let mut total = 0;
	let mut by = serde_json::Map::new();
	for (k, (n, ms)) in after {
		let (n0, ms0) = before.get(k).copied().unwrap_or((0, 0));
		if n > &n0 {
			total += ms - ms0;
			by.insert(k.clone(), json!([n - n0, ms - ms0]));
		}
	}
	(total, Value::Object(by))
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
	/// Whether each transaction asked of [`ChainSource::gone`] can never
	/// return, in this view and its mempool: a walk back through parents
	/// off the chain reads each transaction once, however many coins rest on
	/// it.
	gone: HashMap<Txid, bool>,
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
	/// The answers [`Memo::command`] held when the last command ended: a
	/// command that shares that command's look ([`ChainSource::share_view`])
	/// shares them too.
	last_command: HashMap<String, Kept>,
	/// Whether the node takes a batch of calls in one request: unknown until
	/// one is tried; a proxy that takes one call at a time is asked one by one.
	/// Learnt only from an answer that says so ([`refuses_batch`]): a route
	/// that is busy, restarting or slow says nothing of batches.
	batch: Option<bool>,
	/// Methods the node refused in a batch although it takes batches (a
	/// proxy that allows some methods only on their own): asked alone.
	unbatched: std::collections::HashSet<String>,
	/// When the route last refused a batch or a method in one: after
	/// [`BATCH_AGAIN_AFTER`], batches are tried again ([`ChainSource::batch_again`]).
	refused_batch: Option<web_time::Instant>,
	/// Requests made of the node, and reads answered from what was kept.
	asked: u64,
	kept: u64,
	/// The requests made of the node one read at a time, by method: what a
	/// command's cost names when it made many ([`ChainSource::asked_by_method`]).
	alone: BTreeMap<String, u64>,
	/// Blocks the node reported certified by the committee, by hash. A block's
	/// certificate is judged against the stake state its parent leaves, so every
	/// node answers alike for that hash, and the committee's countersignatures
	/// it counts are only ever added: once certified, a block of that hash stays
	/// certified. Whether it is still in the active chain is read in each view
	/// (by height, in [`ChainSource::finality`]), so a reorganisation of any
	/// depth is seen as before; only the header's re-read is spared.
	certified: std::collections::HashSet<BlockHash>,
	/// Each block header read for its times, by hash: its median time and
	/// its parent's hash. Neither changes for a hash, whatever the active
	/// chain is (whether the block is in it is read in each view, by its
	/// transaction's confirmations), so each is read once.
	headers: HashMap<BlockHash, (u32, Option<BlockHash>)>,
	/// What each script scanned for in this view's set of unspent outputs
	/// pays there (outpoint and height), whether found or not. A scan reads
	/// the set at the tip, so its answer for a script stands until the tip
	/// or the anchor status moves, when it is dropped with every answer of
	/// the view: a later scan for scripts all scanned before is answered
	/// from here, and one for some new ones scans only those.
	scanned: HashMap<Script, Vec<(OutPoint, u64)>>,
	/// Counts each drop of the view's answers: what tells a scan answered in
	/// one view from one answered in the next.
	view_drops: u64,
}

/// The reads a look at the view makes.
const LOOK: [&str; 3] = ["getblockchaininfo", "getanchorstatus", "getrawmempool"];

/// The most calls one batch carries: the testnet's RPC proxy refuses a
/// batch of more.
pub const BATCH_MOST: usize = 64;

/// The most scripts one scan of the set of unspent outputs carries where the
/// node's route takes no more: the testnet's public node proxy refuses a
/// `scantxoutset` of more descriptors (`-32602`), so there a scan of more is
/// made in parts ([`ChainSource::coins_at`]).
pub const SCAN_MOST: usize = 256;

/// The most scripts one scan carries where the node's route takes them: a
/// node's own RPC (a program next to its node) reads its whole set of
/// unspent outputs once for any number of scripts, so a wallet of thousands
/// of on-chain scripts scans in one request rather than one a
/// [`SCAN_MOST`]. Each scan holds the node's one scan slot, which every
/// client of the node waits on. A request of this many descriptors is about
/// a megabyte.
pub const SCAN_WHOLE: usize = 20_000;

/// Whether `e` is a route's refusal of a scan for its size (the public
/// proxy's `-32602`, or an HTTP refusal of the request), after which the scan
/// is made again in parts of [`SCAN_MOST`]. The node itself refuses no
/// number of scripts; a node busy with another scan is not a refusal, nor is
/// a route that is busy, restarting or out of time ([`transient_status`]).
fn scan_too_large(e: &RpcError) -> bool {
	match e {
		RpcError::Rpc { code, message } => !busy(*code, message) && matches!(*code, -32602 | -32600),
		RpcError::Http { status, .. } => (400..500).contains(status) && !transient_status(*status),
		_ => false,
	}
}

/// Whether an HTTP status says the route could not answer now, not what it
/// makes of the request: a gateway or a proxy restarting or out of upstream
/// slots (5xx), a rate limit (429), a request that ran out of time (408), a
/// credential refused while a restarted node's cookie is read again (401).
fn transient_status(status: i32) -> bool {
	status >= 500 || matches!(status, 401 | 408 | 429)
}

/// Whether a batch's failure says that the route takes no batch, or not one
/// carrying these calls: a well-formed answer that is not a list (a proxy
/// that takes one call at a time answers a list with one error, `-32600`; one
/// that allows a method only alone, `-32601`), or a refusal of the request
/// itself (4xx). A route that is busy, restarting, rate limited or out of
/// time ([`transient_status`]), or unreachable, says nothing of batches: that
/// batch's reads are made alone, and the next batch is tried as before.
fn refuses_batch(e: &RpcError) -> bool {
	match e {
		RpcError::Http { status, body } => {
			if transient_status(*status) {
				return false;
			}
			if (400..500).contains(status) {
				return true;
			}
			serde_json::from_str::<Value>(body).is_ok()
		},
		_ => false,
	}
}

/// How long a route's refusal of batches is taken as its answer: a proxy
/// can change, and a refusal learnt from an answer that only looked like one
/// should not cost a wallet its batches until it restarts. A route that does
/// refuse them costs one request a period.
pub const BATCH_AGAIN_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

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
/// refuses another while one runs; a proxy in front of it refuses a call
/// while its upstream slots are full or the scans before it run long ("…;
/// try again", HTTP 503), or for its rate limit. That says nothing of the
/// chain.
fn busy(code: i64, message: &str) -> bool {
	(code == -8 && message.starts_with("Scan already in progress")) || slow_down(code, message)
		|| (code == -32000 && message.ends_with("try again"))
}

/// Whether a proxy in front of the node refused a call for its rate limit,
/// which counts every call of a batch: the call is made again after a
/// pause, and says nothing of the chain.
fn slow_down(code: i64, message: &str) -> bool {
	code == -32000 && message.contains("slow down")
}

/// Whether a batch was refused whole because the node or the proxy in front
/// of it is busy ([`busy`]: its rate limit, its upstream slots full),
/// answered with one error for the whole batch.
fn batch_busy(e: &RpcError) -> bool {
	match e {
		RpcError::Rpc { code, message } => busy(*code, message),
		RpcError::Http { body, .. } => body.contains("slow down") || serde_json::from_str::<Value>(body).is_ok_and(|v|
			busy(v["error"]["code"].as_i64().unwrap_or(0), v["error"]["message"].as_str().unwrap_or(""))),
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

/// The anchor depth the wallet counts for an operator that publishes
/// `published` on the chain named `chain_name` ([`ChainSource::follow_anchor_depth`]).
pub fn anchor_depth_of(published: Option<u64>, chain_name: &str) -> u64 {
	match published {
		None => ANCHOR_DEPTH,
		Some(d) if chain_name == "sequentia" => d.max(ANCHOR_DEPTH),
		Some(d) => d,
	}
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
		ChainSource {
			client: Client::new(url, auth).with_timeout(60), memo: Arc::new(Mutex::new(Memo::default())),
			anchor_depth: Arc::new(AtomicU64::new(ANCHOR_DEPTH)),
			scan_most: Arc::new(AtomicU64::new(SCAN_WHOLE as u64)),
		}
	}

	/// The Bitcoin blocks that must bury a certified block's anchor for the
	/// wallet to call it final: the operator's, once
	/// [`ChainSource::follow_anchor_depth`] has read it, and [`ANCHOR_DEPTH`]
	/// until then.
	pub fn anchor_depth(&self) -> u64 {
		self.anchor_depth.load(Ordering::SeqCst)
	}

	/// Follows the anchor depth an operator publishes (`published`, its
	/// `info`'s `finality.anchor_depth`) on the chain named `chain_name`, and
	/// returns the depth finality counts from now on: the operator's;
	/// [`ANCHOR_DEPTH`] when it publishes none; and never less than
	/// [`ANCHOR_DEPTH`] on the main chain. Every clone of the source follows
	/// it.
	pub fn follow_anchor_depth(&self, published: Option<u64>, chain_name: &str) -> u64 {
		let d = anchor_depth_of(published, chain_name);
		self.anchor_depth.store(d, Ordering::SeqCst);
		d
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
		m.last_command = std::mem::take(&mut m.command);
	}

	/// Lets the command just started answer from another command's look made
	/// within [`BURST_VIEW_FOR`]: for a command that reads only, of a caller
	/// that runs it as one of a burst.
	pub fn share_view(&self) {
		let mut m = self.memo.lock().expect("the chain memo");
		m.shared = true;
		// The node's rates and whitelist read with that look, as the look
		// itself: while it serves (no gap since, younger than the burst's
		// window), so do they.
		if !Self::look_due(&m) {
			m.command = std::mem::take(&mut m.last_command);
		}
	}


	/// The requests this source made of the node (a batch is one), and the
	/// reads it answered from what it kept for the view, since it was made.
	pub fn calls(&self) -> (u64, u64) {
		let m = self.memo.lock().expect("the chain memo");
		(m.asked, m.kept)
	}

	/// The requests made of the node one read at a time since the source was
	/// made, by method (a batch, a look and a broadcast are not among them).
	pub fn asked_by_method(&self) -> BTreeMap<String, u64> {
		self.memo.lock().expect("the chain memo").alone.clone()
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
		Self::batch_again(m);
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
				// A route busy, restarting or out of time: this look is made
				// alone, the reads are the caller's to ask, and what is known
				// of batches stands.
				Err(e) if !refuses_batch(&e) => {
					m.asked += 1;
					None
				},
				// The node took the look alone before: what it carried was
				// refused. One read carried alone is a method the node takes
				// only on its own, asked so from now on; the look is made
				// again, and the reads are the caller's to ask.
				_ if !reads.is_empty() && m.batch == Some(true) => {
					m.asked += 1;
					if reads.len() == 1 {
						m.unbatched.insert(reads[0].0.clone());
						m.refused_batch = Some(web_time::Instant::now());
					}
					return self.look_with(m, &[]).map(|_| None);
				},
				_ => {
					m.asked += 1;
					m.batch = Some(false);
					m.refused_batch = Some(web_time::Instant::now());
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
			Some(k) if k.tip == key.tip && k.anchors == key.anchors => if k.mempool != key.mempool { m.pool.clear(); m.gone.clear() },
			_ => {
				m.view.clear();
				m.scanned.clear();
				m.view_drops += 1;
				m.pool.clear();
				m.gone.clear();
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
		*m.alone.entry(method.to_string()).or_default() += 1;
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
	/// the batch as busy ([`batch_busy`]), the batch waits and is sent again,
	/// for [`BUSY_PATIENCE`] at most, as [`Self::ask`] does for one call.
	fn batch_patiently(&self, calls: &[(String, Vec<Value>)]) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
		let start = web_time::Instant::now();
		let mut pause = std::time::Duration::from_millis(250);
		loop {
			match self.client.batch(calls) {
				Err(e) if batch_busy(&e) && start.elapsed() < BUSY_PATIENCE => {
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
		Self::batch_again(&mut m);
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
				// A route busy, restarting or out of time: the reads are made
				// alone as they come, and the next read ahead batches again.
				Err(e) if !refuses_batch(&e) => return,
				Err(_) => {
					m.batch = Some(false);
					m.refused_batch = Some(web_time::Instant::now());
					return;
				},
			}
		}
	}

	/// Forgets a route's refusal of batches, and of methods in one, once it
	/// is [`BATCH_AGAIN_AFTER`] old: the next look tries a batch again.
	fn batch_again(m: &mut Memo) {
		if m.refused_batch.is_some_and(|t| t.elapsed() >= BATCH_AGAIN_AFTER) {
			m.refused_batch = None;
			m.unbatched.clear();
			if m.batch == Some(false) {
				m.batch = None;
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
		// A block found certified stays so ([`Memo::certified`]).
		if self.memo.lock().expect("the chain memo").certified.contains(hash) {
			return Ok((raw.bitcoin_anchor().height as u64, Some(true)));
		}
		let v: Value = self.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		let certified = v["poscertified"].as_bool();
		if certified == Some(true) {
			self.memo.lock().expect("the chain memo").certified.insert(*hash);
		}
		Ok((raw.bitcoin_anchor().height as u64, certified))
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
		if depth >= self.anchor_depth() && anchor_ok {
			Ok(Finality::Final { height, depth })
		} else {
			Ok(Finality::Settled { height, depth })
		}
	}

	/// The node's anchor status in a word (whether it validates anchors and
	/// how it finds them), with the anchor depth finality counts: a block's
	/// finality counts on both, so a change of either is a change of what the
	/// wallet read as final.
	pub fn anchor_word(&self) -> Result<String, Error> {
		let v: Value = self.call("getanchorstatus", &[]).map_err(node)?;
		Ok(format!("{} {} depth {}", v["validateanchor"], v["anchorstatus"], self.anchor_depth()))
	}

	/// Whether the node validates its anchors against the parent chain.
	pub fn validates_anchors(&self) -> Result<bool, Error> {
		let v: Value = self.call("getanchorstatus", &[]).map_err(node)?;
		Ok(v["validateanchor"].as_bool().unwrap_or(false))
	}

	/// Broadcasts `tx` again, with every transaction it rests on that is in
	/// no block of the active chain and not in the mempool, parents first: a
	/// chain an anchor-driven reorganisation took out of the chain, which the
	/// node did not keep. Each parent comes from the node's own index; at most
	/// [`REDO_REACH`] of them. Answers each transaction sent, with the node's
	/// refusal when it refused one (the rest are sent all the same).
	pub fn rebroadcast_with_parents(&self, tx: &Transaction) -> Result<Vec<Value>, Error> {
		let mut order: Vec<Transaction> = vec![];
		let mut seen: BTreeSet<Txid> = BTreeSet::new();
		let mut stack: Vec<(Transaction, bool)> = vec![(tx.clone(), false)];
		while let Some((t, expanded)) = stack.pop() {
			if expanded {
				order.push(t);
				continue;
			}
			if !seen.insert(t.txid()) || seen.len() > REDO_REACH {
				continue;
			}
			if self.whereabouts(&t.txid())? != (false, false) {
				continue;
			}
			let parents: Vec<Txid> = t.input.iter().map(|i| i.previous_output.txid).collect();
			stack.push((t, true));
			for p in parents {
				if seen.contains(&p) || self.tx_block(&p)?.is_some() {
					continue;
				}
				if let Some(parent) = self.transaction(&p)? {
					stack.push((parent, false));
				}
			}
		}
		let mut out = vec![];
		for t in order {
			out.push(match self.broadcast(&t) {
				Ok(id) => json!({"txid": id.to_string()}),
				Err(e) => json!({"txid": t.txid().to_string(), "refused": e.to_string()}),
			});
		}
		gap();
		Ok(out)
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

	/// The fee `txid` pays as the node values it, in atoms of the node's
	/// reference unit (`getmempoolentry`'s `fees.value`; `fees.base` is the
	/// amount in the fee asset's own atoms, and is the value only on a node
	/// without fees in any asset); `None` when it is not in the mempool. A
	/// replacement outbids it on that value, whatever the fee asset's rate.
	pub fn mempool_fee_value(&self, txid: &Txid) -> Result<Option<u64>, Error> {
		match self.call::<Value>("getmempoolentry", &[json!(txid.to_string())]) {
			Ok(v) => Ok(v["fees"]["value"].as_f64().or_else(|| v["fees"]["base"].as_f64())
				.map(|f| (f * 100_000_000.0).round().max(0.0) as u64)),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// What the node's mempool holds of `txid` for ranking it in a block
	/// ([`MempoolEntry`]); `None` when it is not in the mempool.
	pub fn mempool_entry(&self, txid: &Txid) -> Result<Option<MempoolEntry>, Error> {
		let rfa = |v: &Value| v.as_f64().map(|f| (f * 100_000_000.0).round().max(0.0) as u64).unwrap_or(0);
		match self.call::<Value>("getmempoolentry", &[json!(txid.to_string())]) {
			Ok(v) => Ok(Some(MempoolEntry {
				vsize: v["vsize"].as_u64().unwrap_or(0),
				fee_value: rfa(&v["fees"]["value"]).max(rfa(&v["fees"]["modified"])),
				ancestor_vsize: v["ancestorsize"].as_u64().unwrap_or(0),
				ancestor_fee_value: rfa(&v["fees"]["ancestor"]),
				height: v["height"].as_u64().unwrap_or(0),
			})),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// The transactions in the mempool that descend from `txid`, which is in
	/// it; none when it is not.
	pub fn mempool_descendants(&self, txid: &Txid) -> Result<Vec<Txid>, Error> {
		match self.call::<Vec<String>>("getmempooldescendants", &[json!(txid.to_string())]) {
			Ok(ids) => ids.iter().map(|t| Txid::from_str(t).map_err(|e| Error::Node(e.to_string()))).collect(),
			Err(e) if not_found(&e) => Ok(vec![]),
			Err(e) => Err(node(e)),
		}
	}

	/// The least fee rate the node relays now, in atoms of the reference unit
	/// per 1,000 vbytes: the larger of its relay floor and its mempool's own
	/// minimum.
	pub fn relay_floor_value(&self) -> Result<u64, Error> {
		let v: Value = self.call("getmempoolinfo", &[]).map_err(node)?;
		let rfa = |k: &str| v[k].as_f64().map(|f| (f * 100_000_000.0).round().max(0.0) as u64).unwrap_or(0);
		Ok(rfa("minrelaytxfee").max(rfa("mempoolminfee")).max(1))
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
		let Some((hash, height)) = self.tx_block(txid)? else { return Ok(None) };
		if height == 0 {
			return Ok(None);
		}
		let Some(parent) = self.header_times(&hash)?.1 else { return Ok(None) };
		Ok(Some(self.header_times(&parent)?.0))
	}

	/// The median time of the block of the active chain holding `txid`;
	/// `None` while it is in none. Read through [`Self::header_times`], so a
	/// wallet that dates each of its coins from its board's or batch's block
	/// at every complete re-check reads each block's header once, not a
	/// block hash by height and a header in every view.
	pub fn block_time(&self, txid: &Txid) -> Result<Option<u32>, Error> {
		let Some((hash, _)) = self.tx_block(txid)? else { return Ok(None) };
		Ok(Some(self.header_times(&hash)?.0))
	}

	/// A block's median time and its parent's hash, by its hash, read once
	/// ([`Memo::headers`]).
	fn header_times(&self, hash: &BlockHash) -> Result<(u32, Option<BlockHash>), Error> {
		if let Some(t) = self.memo.lock().expect("the chain memo").headers.get(hash) {
			return Ok(*t);
		}
		let v: Value = self.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		let time = v["mediantime"].as_u64().map(|t| t.min(u32::MAX as u64) as u32)
			.ok_or_else(|| Error::Node(format!("the header of block {} names no median time", hash)))?;
		let parent = v["previousblockhash"].as_str().and_then(|h| BlockHash::from_str(h).ok());
		self.memo.lock().expect("the chain memo").headers.insert(*hash, (time, parent));
		Ok((time, parent))
	}

	/// Whether `outpoint` is unspent, the mempool's spends included.
	pub fn unspent(&self, outpoint: &OutPoint) -> Result<bool, Error> {
		let v: Value = self.call("gettxout", &[json!(outpoint.txid.to_string()), json!(outpoint.vout), json!(true)])
			.map_err(node)?;
		Ok(!v.is_null())
	}

	/// The most scripts one scan carries now ([`SCAN_WHOLE`], or
	/// [`SCAN_MOST`] once the node's route refused that many).
	pub fn scan_most(&self) -> u64 {
		self.scan_most.load(Ordering::SeqCst)
	}

	/// The unspent outputs of the active chain paying any of `scripts`, each
	/// with its height, read from the node's UTXO set.
	///
	/// Scripts scanned for before in this view are answered from what that
	/// scan found ([`Memo::scanned`]); only the others are scanned for.
	pub fn coins_at(&self, scripts: &[Script]) -> Result<Vec<(OutPoint, TxOut, u64)>, Error> {
		if scripts.is_empty() {
			return Ok(vec![]);
		}
		let found = loop {
			// The view as it stands now: a look that is due is made first, and
			// drops what an earlier view scanned.
			let (drops, missing) = {
				let mut m = self.memo.lock().expect("the chain memo");
				self.look(&mut m).map_err(node)?;
				let mut missing: Vec<Script> = scripts.iter().filter(|s| !m.scanned.contains_key(*s)).cloned().collect();
				missing.sort();
				missing.dedup();
				(m.view_drops, missing)
			};
			if !missing.is_empty() {
				let mut by: HashMap<Script, Vec<(OutPoint, u64)>> = missing.iter().map(|s| (s.clone(), vec![])).collect();
				// In parts of at most `scan_most` scripts, each part a scan of
				// its own: all in one where the node's route takes it, else
				// SCAN_MOST a part, from the first refusal on. Every part's
				// answer is taken only if the view stood through all of them
				// (below).
				let mut parts: std::collections::VecDeque<&[Script]> = missing.chunks(self.scan_most() as usize).collect();
				while let Some(part) = parts.pop_front() {
					let descs: Vec<Value> = part.iter().map(|s| json!(format!("raw({})", hex(s.as_bytes())))).collect();
					let v: Value = match self.call("scantxoutset", &[json!("start"), Value::Array(descs)]) {
						Ok(v) => v,
						Err(e) if part.len() > SCAN_MOST && scan_too_large(&e) => {
							self.scan_most.store(SCAN_MOST as u64, Ordering::SeqCst);
							for p in part.chunks(SCAN_MOST).rev() {
								parts.push_front(p);
							}
							continue;
						},
						Err(e) => return Err(node(e)),
					};
					for u in v["unspents"].as_array().cloned().unwrap_or_default() {
						let txid = Txid::from_str(u["txid"].as_str().unwrap_or("")).map_err(|e| Error::Node(e.to_string()))?;
						let vout = u["vout"].as_u64().unwrap_or(0) as u32;
						let script = Script::from(unhex(u["scriptPubKey"].as_str().unwrap_or("")).map_err(|e| Error::Node(e.to_string()))?);
						if let Some(e) = by.get_mut(&script) {
							e.push((OutPoint::new(txid, vout), u["height"].as_u64().unwrap_or(0)));
						}
					}
				}
				let mut m = self.memo.lock().expect("the chain memo");
				// The view moved while the scan ran: what it found may be of
				// the next view, the rest of the last. Read again.
				if m.view_drops != drops {
					continue;
				}
				m.scanned.extend(by);
			}
			let m = self.memo.lock().expect("the chain memo");
			if m.view_drops != drops {
				continue;
			}
			let mut seen = std::collections::HashSet::new();
			let mut found = vec![];
			for s in scripts {
				if seen.insert(s) {
					found.extend(m.scanned.get(s).cloned().unwrap_or_default());
				}
			}
			break found;
		};
		// The transactions that pay them, read ahead: a wallet's on-chain
		// coins can number thousands, and each transaction is kept by its id.
		let mut txids: Vec<Txid> = found.iter().map(|(op, _)| op.txid).collect();
		txids.sort();
		txids.dedup();
		if txids.len() > 1 {
			self.read_ahead(txids.iter().map(|t| ("getrawtransaction".to_string(), vec![json!(t.to_string())])).collect());
		}
		let mut out = vec![];
		for (op, height) in found {
			let Some(tx) = self.transaction(&op.txid)? else { continue };
			let Some(o) = tx.output.get(op.vout as usize) else { continue };
			out.push((op, o.clone(), height));
		}
		Ok(out)
	}

	/// Whether each of `outpoints` is unspent ([`Self::unspent`]), read a
	/// batch at a time where the node takes one, each batch's answers used
	/// at once: read ahead all together, a few thousand of them take longer
	/// than a view stands, and the next look on a busy chain drops the
	/// answers that depend on the mempool before they are used.
	pub fn unspent_many(&self, outpoints: &[OutPoint]) -> Result<Vec<bool>, Error> {
		let mut out = Vec::with_capacity(outpoints.len());
		for (k, chunk) in outpoints.chunks(BATCH_MOST - LOOK.len()).enumerate() {
			if chunk.len() > 1 {
				// After the first, a chunk that would find the view more than
				// half spent takes a look of its own, carried in the same request
				// as the chunk: the view then stands while its answers are used.
				// The first (all of a wallet's few) reads in the view the
				// command stands in, as any read does, and keeps what a burst
				// of commands shares.
				if k > 0 {
					let mut m = self.memo.lock().expect("the chain memo");
					if m.looked.is_none_or(|t| t.elapsed() > VIEW_FOR / 2) {
						m.looked = None;
					}
				}
				self.read_ahead(chunk.iter().map(|o| ("gettxout".to_string(), vec![json!(o.txid.to_string()), json!(o.vout), json!(true)])).collect());
			}
			for o in chunk {
				out.push(self.unspent(o)?);
			}
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
		// Whether each output found is spent in the mempool, a batch at a
		// time; and the mempool's transactions read ahead in batches
		// ([`Self::mempool_txs`]), not one request each: a wallet following
		// many forfeits locates each, and a busy mempool holds dozens.
		let paying: Vec<(OutPoint, TxOut)> = self.coins_at(&scripts)?.into_iter().map(|(op, o, _)| (op, o)).collect();
		let unspent = self.unspent_many(&paying.iter().map(|(op, _)| *op).collect::<Vec<_>>())?;
		for ((op, o), unspent) in paying.into_iter().zip(unspent) {
			if let Some(i) = outputs.iter().enumerate().position(|(i, w)| *w == o && found[i].is_none()) {
				if unspent {
					found[i] = Some(op);
				}
			}
		}
		for tx in self.mempool_txs()? {
			let txid = tx.txid();
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
	/// spent by another transaction that is final, or is made by a
	/// transaction that can never return either (a chain of transactions left
	/// on a branch an anchor-driven reorganisation invalidated, whose first
	/// transaction lost its coins to another that is final). One that is
	/// merely out of the chain, its coins unspent or spent only in blocks not
	/// yet final, can still return. The walk back reads at most
	/// [`GONE_REACH`] transactions; past that, it says the transaction can
	/// return.
	pub fn gone(&self, tx: &Transaction) -> Result<bool, Error> {
		let mut walk = GoneWalk { left: GONE_REACH, cut: false };
		self.gone_in(tx, &mut walk)
	}

	/// [`Self::gone`] of `tx`, answered from what this view already found of
	/// it, or found now and kept: a walk cut short by [`GONE_REACH`] keeps no
	/// "can return" it could not finish.
	fn gone_in(&self, tx: &Transaction, walk: &mut GoneWalk) -> Result<bool, Error> {
		let id = tx.txid();
		if let Some(g) = self.memo.lock().expect("the chain memo").gone.get(&id) {
			return Ok(*g);
		}
		if walk.left == 0 {
			walk.cut = true;
			return Ok(false);
		}
		walk.left -= 1;
		let cut_before = walk.cut;
		walk.cut = false;
		let g = self.gone_found(tx, walk)?;
		if g || !walk.cut {
			self.memo.lock().expect("the chain memo").gone.insert(id, g);
		}
		walk.cut |= cut_before;
		Ok(g)
	}

	fn gone_found(&self, tx: &Transaction, walk: &mut GoneWalk) -> Result<bool, Error> {
		if self.whereabouts(&tx.txid())? != (false, false) {
			return Ok(false);
		}
		for i in &tx.input {
			let op = i.previous_output;
			let Some((_, height)) = self.tx_block(&op.txid)? else {
				// Made by a transaction off the chain: this one returns only
				// if that one does.
				if let Some(parent) = self.transaction(&op.txid)? {
					if self.gone_in(&parent, walk)? {
						return Ok(true);
					}
				}
				continue;
			};
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
/// A transaction in the node's mempool, as the node ranks it for a block:
/// its size, its fee's value in atoms of the reference unit, the same for it
/// with every ancestor still in the mempool, and the height it entered at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolEntry {
	pub vsize: u64,
	pub fee_value: u64,
	pub ancestor_vsize: u64,
	pub ancestor_fee_value: u64,
	pub height: u64,
}

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

	/// The gaps are counted for the whole process: the tests that count a
	/// source's requests, or call for a gap, run one at a time.
	static GAPS_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

	fn serial() -> std::sync::MutexGuard<'static, ()> {
		GAPS_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// A command that shares the view answers from another's look made within
	/// BURST_VIEW_FOR; one that does not looks when it starts; one started
	/// later looks again, and a gap calls for a look at once.
	#[test]
	fn the_anchor_depth_is_the_operators_and_never_below_two_on_the_main_chain() {
		assert_eq!(anchor_depth_of(None, "test"), ANCHOR_DEPTH, "an operator that publishes none is held to the constant");
		assert_eq!(anchor_depth_of(Some(0), "test"), 0, "the testnet operator's 0 is followed");
		assert_eq!(anchor_depth_of(Some(5), "elementsregtest"), 5);
		assert_eq!(anchor_depth_of(Some(0), "sequentia"), ANCHOR_DEPTH, "the main chain keeps its depth");
		assert_eq!(anchor_depth_of(Some(3), "sequentia"), 3);
		let chain = ChainSource::new("http://127.0.0.1:1/", None, None, None);
		let other = chain.clone();
		assert_eq!(chain.anchor_depth(), ANCHOR_DEPTH, "the constant until the operator's is read");
		assert_eq!(chain.follow_anchor_depth(Some(0), "test"), 0);
		assert_eq!(other.anchor_depth(), 0, "every clone follows it");
		assert_eq!(chain.follow_anchor_depth(None, "test"), ANCHOR_DEPTH);
	}

	#[test]
	fn a_burst_of_commands_shares_one_look() {
		let _serial = serial();
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
		let _serial = serial();
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

	/// A burst of commands that only read shares one look, and the node's
	/// rates read with it: a page that reads the balance, the coins and the
	/// rest one after another asks the node once.
	#[test]
	fn a_burst_shares_the_rates_read_with_its_look() {
		let _serial = serial();
		let (url, requests) = picky_proxy();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let sent = || requests.load(Ordering::SeqCst);
		chain.new_command();
		chain.fee_rates().unwrap();
		let n = sent();
		assert!(n >= 1);
		chain.new_command();
		chain.share_view();
		chain.fee_rates().unwrap();
		assert!(chain.validates_anchors().unwrap());
		assert_eq!(sent(), n, "the next command of the burst asks the node nothing");
		chain.new_command();
		chain.fee_rates().unwrap();
		assert!(sent() > n, "a command that does not share the view reads them again");
		let m = sent();
		gap();
		chain.new_command();
		chain.share_view();
		chain.fee_rates().unwrap();
		assert!(sent() > m, "and so does one after a gap");
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
	/// the scans it was asked for. In front of it, a route that refuses a
	/// scan of more than SCAN_MOST descriptors, as the testnet's public proxy
	/// does.
	fn busy_node(busy: u64) -> (String, Arc<AtomicU64>) {
		let (url, scans, _) = scan_node(busy, Some(SCAN_MOST));
		(url, scans)
	}

	/// [`busy_node`], behind a route that refuses a scan of more than
	/// `bound` descriptors (none: a node's own RPC); also counts those
	/// refusals.
	fn scan_node(busy: u64, bound: Option<usize>) -> (String, Arc<AtomicU64>, Arc<AtomicU64>) {
		use std::io::{BufRead, BufReader, Read, Write};
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let scans = Arc::new(AtomicU64::new(0));
		let counted = scans.clone();
		let refusals = Arc::new(AtomicU64::new(0));
		let refused = refusals.clone();
		std::thread::spawn(move || {
			let answer = |call: &Value| -> Value {
				let (id, method) = (call["id"].clone(), call["method"].as_str().unwrap_or(""));
				let result = match method {
					"getblockchaininfo" => json!({"bestblockhash": "11".repeat(32), "blocks": 1}),
					"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
					"getrawmempool" => json!([]),
					"scantxoutset" => {
						// As the testnet's public proxy: no more than its bound.
						if call["params"][1].as_array().is_some_and(|d| bound.is_some_and(|b| d.len() > b)) {
							refused.fetch_add(1, Ordering::SeqCst);
							return json!({"id": id, "result": null, "error": {"code": -32602, "message": "scantxoutset: arguments not allowed here"}});
						}
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
		(url, scans, refusals)
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

	/// Scripts scanned for once in a view are answered from that scan: a
	/// later scan for a subset asks the node nothing, and one with new
	/// scripts asks only for those; a new tip drops them all
	/// ([`Memo::scanned`]).
	#[test]
	fn a_script_is_scanned_for_once_a_view() {
		let (url, scans) = busy_node(0);
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let (a, b, c) = (Script::from(vec![0x51]), Script::from(vec![0x52]), Script::from(vec![0x53]));
		chain.coins_at(&[a.clone(), b.clone()]).unwrap();
		assert_eq!(scans.load(Ordering::SeqCst), 1);
		for _ in 0..3 {
			chain.new_command();
			chain.coins_at(std::slice::from_ref(&a)).unwrap();
			chain.coins_at(&[b.clone(), a.clone()]).unwrap();
		}
		assert_eq!(scans.load(Ordering::SeqCst), 1, "every script already scanned for in this view");
		chain.coins_at(&[b.clone(), c.clone()]).unwrap();
		assert_eq!(scans.load(Ordering::SeqCst), 2, "the new script only");
		chain.coins_at(&[a, b, c]).unwrap();
		assert_eq!(scans.load(Ordering::SeqCst), 2);
		// A new view (here: the memo dropped as a new tip drops it).
		{
			let mut m = chain.memo.lock().unwrap();
			m.scanned.clear();
			m.view_drops += 1;
		}
		chain.coins_at(&[Script::from(vec![0x51])]).unwrap();
		assert_eq!(scans.load(Ordering::SeqCst), 3);
	}

	/// What a scan found is not kept past the view it was read in: at a new
	/// tip (a block, or a reorganisation of any depth) the same scripts are
	/// scanned for again.
	#[test]
	fn a_new_tip_scans_again() {
		let _serial = serial();
		let (url, counts) = moving_tip();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let asked = |m: &str| counts.lock().unwrap().get(m).copied().unwrap_or(0);
		let a = Script::from(vec![0x51]);
		for n in 1..=3 {
			chain.new_command();
			chain.coins_at(std::slice::from_ref(&a)).unwrap();
			chain.coins_at(std::slice::from_ref(&a)).unwrap();
			assert_eq!(asked("scantxoutset"), n, "once in each view, each at a new tip");
		}
	}

	/// A scan of more scripts than a proxy takes in one ([`SCAN_MOST`]) is
	/// made in parts, each answered, and kept for the view as one scan is.
	/// The proxy's refusal comes once: every later scan goes in parts at once.
	#[test]
	fn a_scan_of_many_scripts_goes_in_parts() {
		let (url, scans, refusals) = scan_node(0, Some(SCAN_MOST));
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let scripts: Vec<Script> = (0..600u32).map(|i| Script::from(i.to_be_bytes().to_vec())).collect();
		assert!(chain.coins_at(&scripts).is_ok(), "600 scripts answered");
		assert_eq!(scans.load(Ordering::SeqCst), 3, "256, 256 and 88");
		assert_eq!(refusals.load(Ordering::SeqCst), 1, "the whole scan, refused once");
		assert_eq!(chain.scan_most(), SCAN_MOST as u64);
		assert!(chain.coins_at(&scripts[100..400]).is_ok());
		assert_eq!(scans.load(Ordering::SeqCst), 3, "kept for the view");
		let more: Vec<Script> = (600..1200u32).map(|i| Script::from(i.to_be_bytes().to_vec())).collect();
		assert!(chain.coins_at(&more).is_ok());
		assert_eq!(scans.load(Ordering::SeqCst), 6, "in parts at once");
		assert_eq!(refusals.load(Ordering::SeqCst), 1, "not refused again");
		// The mock refuses a scan past the bound, as the proxy does.
		let one = Value::Array((0..=SCAN_MOST).map(|i| json!(format!("raw({:04x})", i))).collect());
		assert!(chain.call::<Value>("scantxoutset", &[json!("start"), one]).is_err());
	}

	/// Where the node's route takes any number of scripts (a node's own
	/// RPC), a wallet's thousands of on-chain scripts are one scan, not one a
	/// SCAN_MOST: each scan reads the node's whole set of unspent outputs,
	/// and holds the one scan every client of the node waits on.
	#[test]
	fn a_node_that_takes_every_script_scans_once() {
		let (url, scans, refusals) = scan_node(0, None);
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let scripts: Vec<Script> = (0..14_000u32).map(|i| Script::from(i.to_be_bytes().to_vec())).collect();
		assert!(chain.coins_at(&scripts).is_ok());
		assert_eq!(scans.load(Ordering::SeqCst), 1, "14,000 scripts in one scan");
		let more: Vec<Script> = (14_000..39_000u32).map(|i| Script::from(i.to_be_bytes().to_vec())).collect();
		assert!(chain.coins_at(&more).is_ok());
		assert_eq!(scans.load(Ordering::SeqCst), 3, "25,000 more: SCAN_WHOLE, then the rest");
		assert_eq!(refusals.load(Ordering::SeqCst), 0);
		assert_eq!(chain.scan_most(), SCAN_WHOLE as u64);
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

	/// A node whose mempool holds `txs`, served by id, in batches or one at
	/// a time; it counts the requests it was sent, and the calls of each
	/// method that came alone (not in a batch).
	fn mempool_node(txs: Vec<Transaction>) -> (String, Arc<AtomicU64>, Arc<Mutex<HashMap<String, u64>>>) {
		mempool_route(txs, Arc::new(|_, _| None))
	}

	/// How a route answers a batch instead of passing it on: given how many
	/// batches of more than a look's three calls came before it and how many
	/// calls it carries, an HTTP status and a body, or `None` to answer it.
	type Refusal = Arc<dyn Fn(u64, usize) -> Option<(u16, String)> + Send + Sync>;

	/// [`mempool_node`], behind a route that answers some batches with
	/// `refuse`; the calls that came alone are counted by method, and the
	/// batches it was sent under `"batch"`.
	fn mempool_route(txs: Vec<Transaction>, refuse: Refusal) -> (String, Arc<AtomicU64>, Arc<Mutex<HashMap<String, u64>>>) {
		use std::io::{BufRead, BufReader, Read, Write};
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let requests = Arc::new(AtomicU64::new(0));
		let alone: Arc<Mutex<HashMap<String, u64>>> = Default::default();
		let (counted, single) = (requests.clone(), alone.clone());
		let by_id: HashMap<String, String> = txs.iter().map(|t| (t.txid().to_string(), hex(&elements::encode::serialize(t)))).collect();
		std::thread::spawn(move || {
			let mut big = 0u64;
			let answer = |call: &Value| -> Value {
				let (id, method) = (call["id"].clone(), call["method"].as_str().unwrap_or(""));
				let result = match method {
					"getblockchaininfo" => json!({"bestblockhash": "11".repeat(32), "blocks": 1}),
					"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
					"getrawmempool" => json!(by_id.keys().collect::<Vec<_>>()),
					"getrawtransaction" => match by_id.get(call["params"][0].as_str().unwrap_or("")) {
						Some(h) => json!(h),
						None => return json!({"id": id, "result": null, "error": {"code": -5, "message": "No such mempool or blockchain transaction"}}),
					},
					"gettxout" => json!({"value": 1}),
					"scantxoutset" => json!({"success": true, "unspents": []}),
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
				let (status, out) = match &req {
					Value::Array(calls) => {
						*single.lock().unwrap().entry("batch".into()).or_default() += 1;
						let refusal = refuse(big, calls.len());
						if calls.len() > LOOK.len() {
							big += 1;
						}
						match refusal {
							Some(r) => r,
							None => (200, Value::Array(calls.iter().map(|c| answer(c)).collect()).to_string()),
						}
					},
					call => {
						*single.lock().unwrap().entry(call["method"].as_str().unwrap_or("").to_string()).or_default() += 1;
						(200, answer(call).to_string())
					},
				};
				let _ = write!(stream, "HTTP/1.1 {} Answer\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
					status, out.len(), out);
			}
		});
		(url, requests, alone)
	}

	/// The proxy's refusal of a request as a whole (`node-rpc-proxy`'s own).
	fn proxy_refusal(status: u16, code: i64, message: &str) -> (u16, String) {
		(status, json!({"result": null, "error": {"code": code, "message": message}, "id": null}).to_string())
	}

	/// A route that fails a wallet's first batch of more than a look's three
	/// calls as a busy or restarting one does, and answers every request after
	/// it, keeps the wallet's batches: that batch's reads are made alone, and
	/// later reads go in batches again. Before, any such failure turned
	/// batching off until the process restarted, and every later read was a
	/// request of its own. Each failure is met first by the read ahead of a
	/// mempool's transactions (a sync's forfeits step), then by a look that
	/// carries one read.
	#[test]
	fn a_route_busy_once_keeps_its_batches() {
		let _serial = serial();
		let asset = AssetId::from_slice(&[7; 32]).unwrap();
		let txs: Vec<Transaction> = (0..40u8).map(|i| spend_to(OutPoint::new(Txid::from_str(&format!("{:02x}", i + 1).repeat(32)).unwrap(), 0),
			asset, 100_000, Script::from(vec![0x51, i]))).collect();
		let wanted = txs[17].output[0].clone();
		let ops: Vec<OutPoint> = (0..40u32).map(|i| OutPoint::new(Txid::from_str(&format!("{:064x}", i + 1)).unwrap(), 0)).collect();
		let failures: Vec<(&str, (u16, String))> = vec![
			("the proxy's upstream slots full", proxy_refusal(503, -32000, "the node is busy; try again")),
			("the node behind the proxy not answering", proxy_refusal(502, -32000, "the node did not answer: TimeoutError")),
			("Caddy while the proxy restarts", (502, String::new())),
			("a gateway's own page", (504, "<html><body>Gateway Timeout</body></html>".into())),
			("a rate limit with no JSON", (429, "Too Many Requests".into())),
		];
		for (what, failure) in failures {
			// The read ahead of the mempool's 40 transactions fails once.
			let first = failure.clone();
			let (url, _, alone) = mempool_route(txs.clone(), Arc::new(move |big, n| (big == 0 && n > LOOK.len()).then(|| first.clone())));
			let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
			let asked = |m: &str| alone.lock().unwrap().get(m).copied().unwrap_or(0);
			assert_eq!(chain.locate(std::slice::from_ref(&wanted)).unwrap(), vec![Some(OutPoint::new(txs[17].txid(), 0))], "{}", what);
			let (lone, outputs) = (asked("getrawtransaction"), asked("gettxout"));
			assert!(lone <= 40, "{}: the failed batch's reads made alone, at most once each: {}", what, lone);
			chain.new_command();
			assert!(chain.unspent_many(&ops).unwrap().iter().all(|u| *u), "{}", what);
			assert_eq!(asked("gettxout"), outputs, "{}: a later command's 40 outputs read in a batch", what);
			chain.new_command();
			let more: Vec<TxOut> = txs[20..30].iter().map(|t| t.output[0].clone()).collect();
			assert!(chain.locate(&more).unwrap().iter().all(|o| o.is_some()), "{}", what);
			assert_eq!(asked("getrawtransaction"), lone, "{}: the mempool read in batches again", what);

			// A look carrying one read fails once: the method stays batched.
			let first = failure.clone();
			let (url, _, alone) = mempool_route(txs.clone(), Arc::new(move |big, n| (big == 0 && n > LOOK.len()).then(|| first.clone())));
			let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
			let asked = |m: &str| alone.lock().unwrap().get(m).copied().unwrap_or(0);
			assert!(chain.validates_anchors().unwrap(), "{}", what);
			chain.new_command();
			assert!(chain.unspent(&ops[0]).unwrap(), "{}", what);
			chain.new_command();
			assert!(chain.unspent_many(&ops).unwrap().iter().all(|u| *u), "{}", what);
			assert!(asked("gettxout") <= 1, "{}: gettxout still carried in batches: {} asked alone", what, asked("gettxout"));
		}
	}

	/// A route that takes no batch at all (a proxy that takes one call at a
	/// time answers a list with one error) is asked one call at a time after
	/// its first refusal, and asked for a batch again only after
	/// [`BATCH_AGAIN_AFTER`].
	#[test]
	fn a_route_that_takes_no_batch_is_asked_one_call_at_a_time() {
		let _serial = serial();
		let asset = AssetId::from_slice(&[7; 32]).unwrap();
		let txs: Vec<Transaction> = (0..10u8).map(|i| spend_to(OutPoint::new(Txid::from_str(&format!("{:02x}", i + 1).repeat(32)).unwrap(), 0),
			asset, 100_000, Script::from(vec![0x51, i]))).collect();
		let ops: Vec<OutPoint> = (0..20u32).map(|i| OutPoint::new(Txid::from_str(&format!("{:064x}", i + 1)).unwrap(), 0)).collect();
		let refusals: Vec<(&str, (u16, String))> = vec![
			("a list refused as no call", proxy_refusal(400, -32600, "a call is a JSON object")),
			("a server answering an object", (200, json!({"result": null, "error": {"code": -32700, "message": "Parse error"}, "id": null}).to_string())),
		];
		for (what, refusal) in refusals {
			let (url, requests, alone) = mempool_route(txs.clone(), Arc::new(move |_, _| Some(refusal.clone())));
			let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
			let asked = |m: &str| alone.lock().unwrap().get(m).copied().unwrap_or(0);
			assert_eq!(chain.mempool_txs().unwrap().len(), 10, "{}", what);
			chain.new_command();
			assert!(chain.unspent_many(&ops).unwrap().iter().all(|u| *u), "{}", what);
			assert_eq!(asked("batch"), 1, "{}: one batch tried, then none", what);
			assert_eq!((asked("getrawtransaction"), asked("gettxout")), (10, 20), "{}: each read alone", what);
			let n = requests.load(Ordering::SeqCst);
			// Ten minutes on, a batch is tried once again.
			chain.memo.lock().unwrap().refused_batch = Some(web_time::Instant::now() - BATCH_AGAIN_AFTER);
			chain.new_command();
			assert!(chain.unspent_many(&ops).unwrap().iter().all(|u| *u), "{}", what);
			assert_eq!(asked("batch"), 2, "{}: tried again after a while", what);
			assert_eq!(requests.load(Ordering::SeqCst), n + 4, "{}: the batch and the look alone; the outputs are kept for the view", what);
		}
	}

	/// What tells a refusal of batches from a route that could not answer.
	#[test]
	fn a_batch_refused_is_told_from_a_route_that_could_not_answer() {
		let http = |status: i32, body: &str| RpcError::Http { status, body: body.into() };
		let (_, busy) = proxy_refusal(503, -32000, "the node is busy; try again");
		for e in [http(503, &busy), http(502, ""), http(504, "<html></html>"), http(429, "slow down"), http(408, ""), http(401, ""),
			RpcError::Transport("timed out".into())] {
			assert!(!refuses_batch(&e), "{:?}", e);
			assert!(!scan_too_large(&e), "{:?}", e);
		}
		let (_, list) = proxy_refusal(400, -32600, "a call is a JSON object");
		let (_, only_alone) = proxy_refusal(403, -32601, "in a batch: getsupervisedassets is taken one call at a time");
		for e in [http(400, &list), http(403, &only_alone), http(200, "{\"result\": 1}"), http(404, "")] {
			assert!(refuses_batch(&e), "{:?}", e);
		}
		assert!(batch_busy(&http(503, &busy)), "the proxy's busy refusal is waited out");
		assert!(!batch_busy(&http(502, "")));
		assert!(kept_of(Err(RpcError::Rpc { code: -32000, message: "the node is busy; try again".into() })).is_err(),
			"a busy route's refusal is no answer of the view");
	}

	/// Locating an output reads the mempool's transactions in batches, not
	/// one request each: a wallet's sync locates the output of every forfeit
	/// it follows, and before this a busy mempool's few dozen transactions
	/// were as many requests in a row (seconds over a phone's link). The
	/// output paid in the mempool is found there.
	#[test]
	fn locating_an_output_reads_the_mempool_in_batches() {
		let _serial = serial();
		let asset = AssetId::from_slice(&[7; 32]).unwrap();
		let txs: Vec<Transaction> = (0..40u8).map(|i| spend_to(OutPoint::new(Txid::from_str(&format!("{:02x}", i + 1).repeat(32)).unwrap(), 0),
			asset, 100_000, Script::from(vec![0x51, i]))).collect();
		let wanted = txs[17].output[0].clone();
		let (url, requests, alone) = mempool_node(txs.clone());
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let found = chain.locate(std::slice::from_ref(&wanted)).unwrap();
		assert_eq!(found, vec![Some(OutPoint::new(txs[17].txid(), 0))]);
		let alone = alone.lock().unwrap().clone();
		assert_eq!(alone.get("getrawtransaction"), None, "no transaction asked alone: {:?}", alone);
		assert!(requests.load(Ordering::SeqCst) <= 5, "{} requests for 40 transactions", requests.load(Ordering::SeqCst));
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
		let _serial = serial();
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
		busy_mempool_slow(0)
	}

	/// [`busy_mempool`], answering each request after `ms` milliseconds.
	fn busy_mempool_slow(ms: u64) -> (String, Arc<Mutex<HashMap<String, u64>>>) {
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
				std::thread::sleep(std::time::Duration::from_millis(ms));
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
		let _serial = serial();
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

	/// A node whose tip moves at every look, so nothing the view keeps
	/// outlives a command, with two blocks: CERTIFIED, which it reports
	/// certified, and the other, which it does not. Counts each method asked.
	fn moving_tip() -> (String, Arc<Mutex<HashMap<String, u64>>>) {
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
					let verbose = call["params"][1] == json!(true);
					*counted.lock().unwrap().entry(format!("{}{}", method, if verbose { " verbose" } else { "" })).or_default() += 1;
					let result = match method.as_str() {
						"getblockchaininfo" => { looks += 1; json!({"bestblockhash": format!("{:064x}", looks), "blocks": looks}) },
						"getanchorstatus" => json!({"validateanchor": true, "anchorstatus": "ok"}),
						"getrawmempool" => json!([]),
						"getblockheader" if !verbose => json!(HEADER_HEX),
						"getblockheader" => json!({"confirmations": 1, "height": 1, "poscertified": call["params"][0] == json!(CERTIFIED)}),
						"scantxoutset" => json!({"success": true, "unspents": []}),
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

	/// A testnet block header (height 200,000), as the node serialises it.
	const HEADER_HEX: &str = "00000020f3618ae0c56f9a5ab4c159d69e139f9e70c73074294609b020041a3b74dc6c46ddaddc61d69d046efbbe8e990c42ddc121e6672fa7ec23cecc8ee0daad8be39b0183ec6a400d0300be6d02003cfa44d44b51f6006b0923d068b931ac204c1f303703dce70016f20a00000000235221020cde0a7aa5dbfeadfecfce3a125ad2973ab5e6d6da85a2fc3ebff21369904b52ac463044022034b82df0d37459d534ba489758a92c35062d7be40c6154601e8afd5901da6da502207433c92b91b8771767124a81c0a77d0017d1a4088fd001b1eba68fbd01f478694c608544a9782ca886fda71d6c80344df162aff5515373f714fe011c27f4f7e6f0f08d56eedf4ab956e6ecffa68c423478aa1634e59a17f7d890094224cb20e052287e39c6f5799bf2cecb9918bc7b75f78250c5db92fba96ed12043e947b5859c74010559";
	const CERTIFIED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

	/// A block found certified is not asked again in a later view, whatever
	/// the tip; a block not certified is asked again in every view, as a
	/// certificate may come for it. Requests made one at a time are counted
	/// by method.
	#[test]
	fn a_certified_block_is_not_asked_again() {
		let _serial = serial();
		let (url, counts) = moving_tip();
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		let asked = |m: &str| counts.lock().unwrap().get(m).copied().unwrap_or(0);
		let (yes, no) = (BlockHash::from_str(CERTIFIED).unwrap(), BlockHash::from_str(&"bb".repeat(32)).unwrap());
		let before = chain.asked_by_method();
		for _ in 0..3 {
			chain.new_command();
			assert_eq!(chain.header(&yes).unwrap().1, Some(true));
			assert_eq!(chain.header(&no).unwrap().1, Some(false));
		}
		assert!(asked("getblockchaininfo") >= 3, "a look in each command, at a new tip each time");
		assert_eq!(asked("getblockheader"), 2, "each header's bytes once: named by its hash");
		assert_eq!(asked("getblockheader verbose"), 1 + 3, "the certified block once, the other in each view");
		// Those not carried in a look's batch were asked one at a time, and
		// counted so, by method.
		let after = chain.asked_by_method();
		let alone = after.get("getblockheader").copied().unwrap_or(0) - before.get("getblockheader").copied().unwrap_or(0);
		assert!(alone >= 1 && alone <= 2 + 1 + 3, "{} of the headers asked alone", alone);
	}

	/// Hundreds of outputs looked up unspent, on a slow node whose mempool
	/// changes at every look: read ahead all at once, most answers are
	/// dropped by the next look (a second later) before they are used, and
	/// each is asked again alone; read a batch at a time and used at once
	/// ([`ChainSource::unspent_many`]), none is.
	#[test]
	fn many_outputs_are_read_unspent_a_batch_at_a_time() {
		let _serial = serial();
		let ops: Vec<OutPoint> = (0..600u32).map(|i| OutPoint::new(Txid::from_str(&format!("{:064x}", i + 1)).unwrap(), i % 3)).collect();
		let alone = |c: &ChainSource| c.asked_by_method().get("gettxout").copied().unwrap_or(0);
		// As before: one read ahead, then each looked up.
		let (url, _) = busy_mempool_slow(40);
		let before = ChainSource::new(&url, Some("u"), Some("p"), None);
		before.new_command();
		before.read_ahead_of(&[], &ops);
		for o in &ops {
			assert!(before.unspent(o).unwrap());
		}
		assert!(alone(&before) > 300, "the read ahead lost to the next look: {} asked alone", alone(&before));
		let (url, counts) = busy_mempool_slow(40);
		let chain = ChainSource::new(&url, Some("u"), Some("p"), None);
		chain.new_command();
		assert!(chain.unspent_many(&ops).unwrap().iter().all(|u| *u));
		assert_eq!(alone(&chain), 0, "every answer used in the view it was read in");
		assert_eq!(counts.lock().unwrap().get("gettxout").copied(), Some(600), "each asked once");
	}

	/// A coin's dates read again at every complete re-check, in a view after
	/// each new block: a block's times are read by its hash once, so the
	/// second view asks the node for no header and no block hash by height
	/// (a wallet with hundreds of coins asked both for each, one at a time,
	/// in every view: 436 s before a command on the testnet).
	///
	/// Needs `SEQUENTIAD_EXEC`.
	#[cfg(not(target_arch = "wasm32"))]
	#[test]
	fn a_blocks_times_are_read_once_by_its_hash() {
		let _serial = serial();
		use sequentia_ext::regtest::Regtest;
		if std::env::var_os("SEQUENTIAD_EXEC").is_none() {
			eprintln!("SEQUENTIAD_EXEC is not set: skipped");
			return;
		}
		let dir = tempfile::tempdir().unwrap();
		let r = Regtest::pos_from_env(dir.path(), &["-acceptnonstdtxn=1"]);
		let url = format!("http://127.0.0.1:{}/", r.node.rpc_port());
		let chain = ChainSource::new(&url, Some("arca"), Some("arca"), None);
		let op_true = Script::from(vec![0x51]);
		let genesis = chain.genesis().unwrap();
		let block = chain.raw_block(&genesis).unwrap();
		let (free, coin) = block.txdata.iter().flat_map(|t| t.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(t.txid(), i as u32), o.clone())))
			.find(|(_, o)| o.script_pubkey == op_true && o.value.explicit().is_some_and(|v| v > 1_000_000)).expect("free coins");
		let tx = spend_to(free, coin.asset.explicit().unwrap(), coin.value.explicit().unwrap(), op_true);
		r.node.client().send_raw_transaction(&tx).unwrap();
		r.produce_block().unwrap();
		r.produce_block().unwrap();
		chain.new_command();
		let (hash, height) = chain.tx_block(&tx.txid()).unwrap().expect("in a block");
		let first = (chain.block_time(&tx.txid()).unwrap(), chain.coin_time(&tx.txid()).unwrap());
		assert_eq!(first.0, chain.median_time_at(height).unwrap(), "the block's own median time");
		assert_eq!(first.1, chain.median_time_at(height - 1).unwrap(), "its parent's");
		// A new block, a new view: the times again, with no header read and
		// no block hash asked by height.
		r.produce_block().unwrap();
		chain.new_command();
		let headers = |c: &ChainSource| c.asked_by_method().get("getblockheader").copied().unwrap_or(0);
		let hashes = |c: &ChainSource| c.asked_by_method().get("getblockhash").copied().unwrap_or(0);
		assert!(chain.tx_block(&tx.txid()).unwrap().is_some_and(|(h, _)| h == hash));
		let (h0, b0) = (headers(&chain), hashes(&chain));
		for _ in 0..5 {
			assert_eq!((chain.block_time(&tx.txid()).unwrap(), chain.coin_time(&tx.txid()).unwrap()), first);
		}
		assert_eq!((headers(&chain) - h0, hashes(&chain) - b0), (0, 0), "no header, no block hash read again");
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
	/// A parent and its child left in no block and out of the mempool by an
	/// anchor-driven reorganisation, their coin unspent: broadcast again from
	/// the child, the parent goes first, and both are mined.
	#[test]
	fn a_chain_a_reorganisation_dropped_is_broadcast_again_parents_first() {
		let _serial = serial();
		use sequentia_ext::regtest::Regtest;
		if std::env::var_os("SEQUENTIAD_EXEC").is_none() {
			eprintln!("SEQUENTIAD_EXEC is not set: skipped");
			return;
		}
		let dir = tempfile::tempdir().unwrap();
		let mut r = Regtest::pos_from_env(dir.path(), &["-acceptnonstdtxn=1"]);
		let url = format!("http://127.0.0.1:{}/", r.node.rpc_port());
		let chain = ChainSource::new(&url, Some("arca"), Some("arca"), None);
		let op_true = Script::from(vec![0x51]);
		let genesis = chain.genesis().unwrap();
		let block = chain.raw_block(&genesis).unwrap();
		let (free, coin) = block.txdata.iter().flat_map(|t| t.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(t.txid(), i as u32), o.clone())))
			.find(|(_, o)| o.script_pubkey == op_true && o.value.explicit().is_some_and(|v| v > 1_000_000)).expect("free coins");
		let asset = coin.asset.explicit().unwrap();
		let value = coin.value.explicit().unwrap();
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		let parent = spend_to(free, asset, value, op_true.clone());
		let child = spend_to(OutPoint::new(parent.txid(), 0), asset, value - 10_000, op_true.clone());
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		let anchored = r.parent.client().block_count().unwrap();
		r.node.client().send_raw_transaction(&parent).unwrap();
		r.node.client().send_raw_transaction(&child).unwrap();
		r.produce_block().unwrap();
		r.orphan_parent_from(anchored).unwrap();
		r.node.restart(&["-persistmempool=0"]).unwrap();
		gap();
		chain.new_command();
		assert_eq!(chain.whereabouts(&child.txid()).unwrap(), (false, false));
		assert!(!chain.gone(&child).unwrap(), "its coin is unspent: it can return");
		let sent = chain.rebroadcast_with_parents(&child).unwrap();
		println!("broadcast again: {}", serde_json::to_string(&sent).unwrap());
		assert_eq!(sent.iter().map(|v| v["txid"].as_str().unwrap().to_string()).collect::<Vec<_>>(),
			vec![parent.txid().to_string(), child.txid().to_string()], "the parent first");
		assert!(sent.iter().all(|v| v.get("refused").is_none()), "{:?}", sent);
		chain.new_command();
		assert_eq!(chain.whereabouts(&child.txid()).unwrap(), (false, true), "in the mempool again");
		r.produce_block().unwrap();
		gap();
		chain.new_command();
		assert!(chain.tx_block(&child.txid()).unwrap().is_some() && chain.tx_block(&parent.txid()).unwrap().is_some(), "both mined");
		// Asked again, nothing is sent: both are in the chain.
		assert!(chain.rebroadcast_with_parents(&child).unwrap().is_empty());
	}

	/// A chain of transactions left off the chain by an anchor-driven
	/// reorganisation, and gone from the mempool: the child can return while
	/// its parent can, and can never return once another transaction, final,
	/// takes the parent's coin, although the child's own coin is made by a
	/// transaction in no block.
	#[test]
	fn a_transaction_whose_parent_can_never_return_is_gone() {
		let _serial = serial();
		use sequentia_ext::regtest::Regtest;
		if std::env::var_os("SEQUENTIAD_EXEC").is_none() {
			eprintln!("SEQUENTIAD_EXEC is not set: skipped");
			return;
		}
		let dir = tempfile::tempdir().unwrap();
		let mut r = Regtest::pos_from_env(dir.path(), &["-acceptnonstdtxn=1"]);
		let url = format!("http://127.0.0.1:{}/", r.node.rpc_port());
		let chain = ChainSource::new(&url, Some("arca"), Some("arca"), None);
		let op_true = Script::from(vec![0x51]);
		let genesis = chain.genesis().unwrap();
		let block = chain.raw_block(&genesis).unwrap();
		let (free, coin) = block.txdata.iter().flat_map(|t| t.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(t.txid(), i as u32), o.clone())))
			.find(|(_, o)| o.script_pubkey == op_true && o.value.explicit().is_some_and(|v| v > 1_000_000)).expect("free coins");
		let asset = coin.asset.explicit().unwrap();
		let value = coin.value.explicit().unwrap();
		// Blocks anchored below the parent block the reorganisation takes,
		// for the chain to fall back to.
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		// A parent and its child, in one block anchored to a parent block of
		// its own.
		let parent = spend_to(free, asset, value, op_true.clone());
		let child = spend_to(OutPoint::new(parent.txid(), 0), asset, value - 10_000, op_true.clone());
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		let anchored = r.parent.client().block_count().unwrap();
		r.node.client().send_raw_transaction(&parent).unwrap();
		r.node.client().send_raw_transaction(&child).unwrap();
		r.produce_block().unwrap();
		gap();
		chain.new_command();
		assert!(chain.tx_block(&child.txid()).unwrap().is_some());
		// Bitcoin reorganises that parent block away; the node forgets its
		// mempool.
		r.orphan_parent_from(anchored).unwrap();
		r.node.restart(&["-persistmempool=0"]).unwrap();
		gap();
		chain.new_command();
		assert_eq!(chain.whereabouts(&child.txid()).unwrap(), (false, false), "in no block and not in the mempool");
		assert!(chain.tx_block(&parent.txid()).unwrap().is_none(), "the child's coin is made by a transaction in no block");
		assert!(!chain.gone(&child).unwrap(), "the parent's coin is unspent: both can return");
		println!("the parent {} and the child {} are off the chain; both can return", parent.txid(), child.txid());
		// Another transaction takes the parent's coin, and is final.
		let other = spend_to(free, asset, value, Script::from(vec![0x52]));
		r.node.client().send_raw_transaction(&other).unwrap();
		r.produce_block().unwrap();
		r.mine_parent(2).unwrap();
		r.anchor_to_parent_tip().unwrap();
		gap();
		chain.new_command();
		assert!(chain.finality(&other.txid()).unwrap().is_final(), "{:?}", chain.finality(&other.txid()).unwrap());
		assert!(chain.gone(&parent).unwrap(), "its coin is spent by a final transaction");
		assert!(chain.gone(&child).unwrap(), "its parent can never return, so neither can it");
		// What the walk found is kept for the view: asked again, it reads
		// nothing but, at most, a look at the view.
		let (before, _) = chain.calls();
		assert!(chain.gone(&child).unwrap() && chain.gone(&parent).unwrap());
		let (after, _) = chain.calls();
		println!("asked again: {} request(s) of the node", after - before);
		assert!(after - before <= 1, "{} requests", after - before);
		println!("{} took the parent's coin and is final: the parent and the child are gone", other.txid());
	}

	/// A source that has a certified block kept ([`Memo::certified`])
	/// answers, after every reorganisation, as a source opened afresh does,
	/// and never `Final` for a block a reorganisation took or left unburied:
	/// a Sequentia reorganisation that takes the block, a Bitcoin one above
	/// its anchor, and a Bitcoin one that orphans its anchor, with the node
	/// restarted while its index still names the orphaned block. The kept
	/// certificate stands for nothing but the certificate.
	///
	/// Needs `SEQUENTIAD_EXEC`.
	#[cfg(not(target_arch = "wasm32"))]
	#[test]
	fn a_kept_certificate_follows_every_reorganisation() {
		let _serial = serial();
		use sequentia_ext::regtest::Regtest;
		if std::env::var_os("SEQUENTIAD_EXEC").is_none() {
			eprintln!("SEQUENTIAD_EXEC is not set: skipped");
			return;
		}
		const DEPTH: u64 = 2;
		let dir = tempfile::tempdir().unwrap();
		let mut r = Regtest::pos_from_env(dir.path(), &["-acceptnonstdtxn=1"]);
		let url = format!("http://127.0.0.1:{}/", r.node.rpc_port());
		let open = |_: ()| { let c = ChainSource::new(&url, Some("arca"), Some("arca"), None); c.follow_anchor_depth(Some(DEPTH), "elementsregtest"); c };
		let a = open(());
		let op_true = Script::from(vec![0x51]);
		let genesis = a.genesis().unwrap();
		let block = a.raw_block(&genesis).unwrap();
		let (free, coin) = block.txdata.iter().flat_map(|t| t.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(t.txid(), i as u32), o.clone())))
			.find(|(_, o)| o.script_pubkey == op_true && o.value.explicit().is_some_and(|v| v > 1_000_000)).expect("free coins");
		let (asset, value) = (coin.asset.explicit().unwrap(), coin.value.explicit().unwrap());
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		r.mine_parent(1).unwrap();
		r.anchor_to_parent_tip().unwrap();
		let t = spend_to(free, asset, value, op_true.clone());
		r.node.client().send_raw_transaction(&t).unwrap();
		let b = r.produce_block().unwrap();
		let (b_anchor, b_cert) = a.header(&b).unwrap();
		assert_eq!(b_cert, Some(true), "the committee certified it");
		r.mine_parent(3).unwrap();
		r.anchor_to_parent_tip().unwrap();
		// Reads `t` in the open source A (memo kept), and in one closed and
		// opened again (a fresh source): both must agree.
		let step = |label: &str| -> Finality {
			gap();
			a.new_command();
			let held = a.memo.lock().unwrap().certified.contains(&b);
			let fa = a.finality(&t.txid()).unwrap();
			let reopened = open(());
			let fc = reopened.finality(&t.txid()).unwrap();
			let block_now = a.tx_block(&t.txid()).unwrap();
			println!("{:<46} memo holds B: {:<5} open: {:?}  reopened: {:?}  block: {:?}", label, held, fa, fc,
				block_now.map(|(h, n)| (if h == b { "B".to_string() } else { h.to_string()[..8].to_string() }, n)));
			assert_eq!(fa, fc, "{}: the open source answers as a reopened one", label);
			fa
		};
		let f = step("0 B certified, anchor buried 3");
		assert!(f.is_final(), "{:?}", f);
		assert!(a.memo.lock().unwrap().certified.contains(&b), "the certificate is memoised");
		// A closed wallet, opened and filled before the reorganisation.
		let closed = open(()); assert!(closed.finality(&t.txid()).unwrap().is_final()); drop(closed);

		// R1: a Sequentia reorganisation that takes B (B invalidated).
		let _: Value = r.node.client().call("invalidateblock", &[json!(b.to_string())]).unwrap();
		let f = step("R1 Sequentia reorg takes B");
		assert!(matches!(f, Finality::NotInChain { .. }), "{:?}", f);
		let _: Value = r.node.client().call("reconsiderblock", &[json!(b.to_string())]).unwrap();
		let f = step("R1' B reconsidered, back in the chain");
		assert!(f.is_final(), "{:?}", f);

		// R2: a Bitcoin reorganisation above B's anchor: B stays, its anchor
		// is no longer buried at the depth asked.
		r.orphan_parent_from(b_anchor + 1).unwrap();
		let f = step("R2 Bitcoin reorg above B's anchor");
		assert!(!f.is_final(), "B's anchor is not buried {} deep now: {:?}", DEPTH, f);
		r.anchor_to_parent_tip().unwrap();
		let f = step("R2' new parent blocks bury it again");
		assert!(f.is_final(), "{:?}", f);

		// R3: a Bitcoin reorganisation that orphans B's anchor: B goes.
		let closed = open(()); assert!(closed.finality(&t.txid()).unwrap().is_final()); drop(closed);
		assert!(a.memo.lock().unwrap().certified.contains(&b));
		r.orphan_parent_from(b_anchor).unwrap();
		let f = step("R3 Bitcoin reorg orphans B's anchor");
		assert!(matches!(f, Finality::NotInChain { .. }), "{:?}", f);
		// The node restarts without its mempool: the index may still name B.
		r.node.restart(&["-persistmempool=0"]).unwrap();
		let raw: Value = r.node.client().call("getrawtransaction", &[json!(t.txid().to_string()), json!(true)]).unwrap_or(Value::Null);
		println!("after restart the node gives T's blockhash {:?} (B {})", raw["blockhash"], b);
		let f = step("R3 restarted, T out of the mempool");
		assert!(matches!(f, Finality::NotInChain { .. }), "{:?}", f);
		// T is mined again, in another block.
		if matches!(f, Finality::NotInChain { in_mempool: false }) {
			r.node.client().send_raw_transaction(&t).unwrap();
		}
		r.produce_block().unwrap();
		let f = step("R3' T mined again in another block");
		assert!(!f.is_final(), "its new block's anchor is not buried yet: {:?}", f);
		r.mine_parent(3).unwrap();
		r.anchor_to_parent_tip().unwrap();
		let f = step("R3'' buried again");
		assert!(f.is_final(), "{:?}", f);
		assert_ne!(a.tx_block(&t.txid()).unwrap().unwrap().0, b, "another block");
	}

	#[test]
	fn a_lineage_is_read_from_the_chain_only_once_its_root_is_spent() {
		let _serial = serial();
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
