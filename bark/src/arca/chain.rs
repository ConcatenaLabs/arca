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
//! A node behind a proxy that takes one call at a time refuses the first
//! batch, and the source makes each read on its own from then on. A read
//! ahead changes no answer, only the number of requests that make it.

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
	/// Answers fixed by the view.
	view: HashMap<String, Kept>,
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
	/// Requests made of the node, and reads answered from what was kept.
	asked: u64,
	kept: u64,
}

/// The most calls one batch carries.
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
		| "getrawmempool" | "getmempoolentry" | "getanchorstatus" | "decodescript" | "validateaddress" => Keep::View,
		"getfeeexchangerates" | "dumpassetlabels" | "getmempoolinfo" => Keep::Command,
		_ => Keep::Never,
	}
}

fn kept_of(r: Result<Value, RpcError>) -> Result<Kept, RpcError> {
	match r {
		Ok(v) => Ok(Ok(v)),
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
		m.command.clear();
	}

	/// The requests this source made of the node (a batch is one), and the
	/// reads it answered from what it kept for the view, since it was made.
	pub fn calls(&self) -> (u64, u64) {
		let m = self.memo.lock().expect("the chain memo");
		(m.asked, m.kept)
	}

	/// Looks at the view again when the command has just started, a gap came
	/// or a second passed since the last look: the tip, the anchor status and
	/// the mempool. A change to any drops every answer kept.
	fn look(&self, m: &mut Memo) -> Result<(), RpcError> {
		let gaps = GAPS.load(Ordering::SeqCst);
		if m.looked_this_command && m.gaps == gaps && m.looked.is_some_and(|t| t.elapsed() < VIEW_FOR) {
			return Ok(());
		}
		if m.gaps != gaps {
			m.command.clear();
		}
		// One request where the node takes a batch, three where it does not.
		let three = ["getblockchaininfo", "getanchorstatus", "getrawmempool"].map(|c| (c.to_string(), vec![]));
		let batched = match m.batch {
			Some(true) => match self.client.batch(&three) {
				Ok(mut a) if a.len() == 3 => {
					m.asked += 1;
					let pool = kept_of(a.pop().expect("three"))?;
					let anchors = kept_of(a.pop().expect("three"))?;
					Some((kept_of(a.pop().expect("three"))?, anchors, pool))
				},
				Err(RpcError::Transport(e)) => return Err(RpcError::Transport(e)),
				_ => {
					m.asked += 1;
					m.batch = Some(false);
					None
				},
			},
			_ => None,
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
		if m.key.as_ref() != Some(&key) {
			m.view.clear();
			m.key = Some(key);
		}
		m.view.insert(Self::read_key("getblockchaininfo", &[]), info);
		m.view.insert(Self::read_key("getanchorstatus", &[]), anchors);
		m.view.insert(Self::read_key("getrawmempool", &[]), pool);
		m.looked = Some(web_time::Instant::now());
		m.looked_this_command = true;
		m.gaps = gaps;
		Ok(())
	}

	fn read_key(method: &str, params: &[Value]) -> String {
		format!("{} {}", method, Value::Array(params.to_vec()))
	}

	/// One call of the node: answered from what the view keeps when the read
	/// is one the view fixes and was made in it, else asked of the node.
	fn read(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
		let keep = keep_of(method, params);
		if matches!(keep, Keep::Never) {
			// A broadcast changes the mempool: the next read looks again.
			let r = self.client.call::<Value>(method, params);
			let mut m = self.memo.lock().expect("the chain memo");
			m.asked += 1;
			m.looked_this_command = false;
			return r;
		}
		let k = Self::read_key(method, params);
		{
			let mut m = self.memo.lock().expect("the chain memo");
			self.look(&mut m)?;
			let found = match keep {
				Keep::Named => m.named.get(&k).cloned().map(Ok).or_else(|| m.view.get(&k).cloned()),
				Keep::View => m.view.get(&k).cloned(),
				_ => m.command.get(&k).cloned(),
			};
			if let Some(a) = found {
				m.kept += 1;
				return answer_of(&a);
			}
		}
		let a = kept_of(self.client.call::<Value>(method, params))?;
		let mut m = self.memo.lock().expect("the chain memo");
		m.asked += 1;
		match (&keep, &a) {
			(Keep::Named, Ok(v)) => { m.named.insert(k, v.clone()); },
			(Keep::Named | Keep::View, _) => { m.view.insert(k, a.clone()); },
			_ => { m.command.insert(k, a.clone()); },
		}
		answer_of(&a)
	}

	/// Reads `reads` of the node at once, where it takes a batch (one request
	/// for up to [`BATCH_MOST`] of them), into what the view keeps; the reads
	/// a command then makes are answered from it. Where it takes none, or the
	/// batch fails, nothing is kept and each read is made on its own when it
	/// comes: a read ahead changes no answer, only how many requests make it.
	fn read_ahead(&self, reads: Vec<(String, Vec<Value>)>) {
		let todo: Vec<(String, Vec<Value>)> = {
			let mut m = self.memo.lock().expect("the chain memo");
			if self.look(&mut m).is_err() || m.batch == Some(false) {
				return;
			}
			let mut seen = std::collections::HashSet::new();
			reads.into_iter().filter(|(method, params)| {
				let k = Self::read_key(method, params);
				let keep = keep_of(method, params);
				let kept = m.view.contains_key(&k) || m.named.contains_key(&k);
				matches!(keep, Keep::View | Keep::Named) && !kept && seen.insert(k)
			}).collect()
		};
		if todo.len() < 2 {
			return;
		}
		for chunk in todo.chunks(BATCH_MOST) {
			let answers = self.client.batch(chunk);
			let mut m = self.memo.lock().expect("the chain memo");
			m.asked += 1;
			match answers {
				Ok(answers) => {
					m.batch = Some(true);
					for ((method, params), a) in chunk.iter().zip(answers) {
						let Ok(a) = kept_of(a) else { continue };
						let k = Self::read_key(method, params);
						match (keep_of(method, params), a) {
							(Keep::Named, Ok(v)) => { m.named.insert(k, v); },
							(_, a) => { m.view.insert(k, a); },
						}
					}
				},
				Err(RpcError::Transport(_)) => return,
				Err(_) => {
					m.batch = Some(false);
					return;
				},
			}
		}
	}

	/// Reads ahead what [`Self::finality`] and [`Self::median_time_at`] read
	/// of each of `txids` (where it is, its block's header, its height's hash)
	/// and of the tip, in two batches ([`Self::read_ahead`]); and, for each
	/// of `outpoints`, whether it is unspent ([`Self::unspent`]).
	pub fn read_ahead_of(&self, txids: &[Txid], outpoints: &[OutPoint]) {
		let Ok(info) = self.info() else { return };
		let tip = json!(info.best_block_hash.to_string());
		let mut first = vec![("getblockheader".to_string(), vec![tip.clone(), json!(true)]), ("getblockheader".to_string(), vec![tip, json!(false)])];
		first.extend(txids.iter().map(|t| ("getrawtransaction".to_string(), vec![json!(t.to_string()), json!(true)])));
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
	fn tx_block(&self, txid: &Txid) -> Result<Option<(BlockHash, u64)>, Error> {
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

	/// Which of `scripts` an output of the active chain from `from_height` up,
	/// or of the mempool, pays: the index of the chain the lineage check asks.
	pub fn scripts_seen(&self, scripts: &BTreeSet<Script>, from_height: u64) -> Result<BTreeSet<Script>, Error> {
		let mut seen = BTreeSet::new();
		if scripts.is_empty() {
			return Ok(seen);
		}
		let tip = self.tip()?;
		let mut look = |tx: &Transaction| {
			for o in &tx.output {
				if scripts.contains(&o.script_pubkey) {
					seen.insert(o.script_pubkey.clone());
				}
			}
		};
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.raw_block(&hash).map_err(node)?.txdata {
				look(&tx);
			}
		}
		let ids: Vec<String> = self.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			if let Some(tx) = self.transaction(&txid)? {
				look(&tx);
			}
		}
		Ok(seen)
	}

	/// The first transaction of the active chain from `from_height` up that
	/// pays `output` (asset, value and script), if any: what a wallet re-checks
	/// a leaf against when its round is gone.
	pub fn find_payment(&self, output: &TxOut, from_height: u64) -> Result<Option<(Transaction, u64)>, Error> {
		let tip = self.tip()?;
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.raw_block(&hash).map_err(node)?.txdata {
				if tx.output.iter().any(|o| o == output) {
					return Ok(Some((tx, h)));
				}
			}
		}
		Ok(None)
	}

	/// The transaction that spends `outpoint`, in the mempool or in a block
	/// of the active chain from `from_height` up, and its height (`None` for
	/// the mempool).
	pub fn spender(&self, outpoint: &OutPoint, from_height: u64) -> Result<Option<(Transaction, Option<u64>)>, Error> {
		let spends = |tx: &Transaction| tx.input.iter().any(|i| i.previous_output == *outpoint);
		let ids: Vec<String> = self.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			if let Some(tx) = self.transaction(&txid)? {
				if spends(&tx) {
					return Ok(Some((tx, None)));
				}
			}
		}
		let tip = self.tip()?;
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.raw_block(&hash).map_err(node)?.txdata {
				if spends(&tx) {
					return Ok(Some((tx, Some(h))));
				}
			}
		}
		Ok(None)
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
		for m in ["getblockchaininfo", "getblockhash", "gettxout", "scantxoutset", "getrawmempool", "getmempoolentry", "getanchorstatus"] {
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
	}
}
