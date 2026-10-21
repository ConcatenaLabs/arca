//! The wallet's commands by name, with JSON arguments and JSON answers, for a
//! program that embeds the library and drives it as the `arca` command line
//! is driven: a browser worker (`wallet-wasm/`) or a mobile app's core. Each
//! program adds only its transport, its pause and its store; the commands,
//! their arguments, what runs before each, and the shape of a refusal are
//! these, so that every embedding says the same things in the same words.
//!
//! [`run`] answers `{"result", "start"}`: the command's JSON, and what the
//! start of the command found (the witness of the operator's signer's record,
//! and the re-check of every coin against the chain), which the command line
//! runs on every start and prints when it changed something. A refusal is
//! [`refusal`]: the JSON the command line prints, `{"error": {"kind",
//! "message"}}`, with the server's `code` and `status` when the server refused.

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::AssetId;
use serde_json::{json, Value};

use super::keys::Keys;
use super::{Config, Error, Wallet};

/// Every command [`run`] takes, with its arguments.
pub const COMMANDS: &str = "info, address, openamp_key, balance, coins, record {leaf_id}, board_quote {asset, amount, fee_asset?}, \
	board {asset, amount, fee_asset?, shown?}, boards, receive {asset?, amount?}, forget_request {owner}, send {request, amount?, \
	asset?}, mailbox, restore, quote {leaves?, max_fee_ppm?}, participate {leaves?, not_before?, max_fee_ppm?, shown}, \
	participations, sync, schedule, recheck, exit_quote {leaf_id, fee_asset?}, exit {leaf_id, fee_asset?, shown?}, refusals, \
	take_quote {order, amount?, max_fee_ppm?}, take {order, amount?, max_fee_ppm?, shown?}, order_quote {sell, amount, want, rate_num, \
	rate_den, min_lot?, expiry, maker_prog?, max_fee_ppm?}, order_place {sell, amount, want, rate_num, rate_den, min_lot?, expiry, \
	maker_prog?, max_fee_ppm?, shown?}, orders, order_refund {order, fee_asset?}, order_fill_quote and order_fill (take_quote and take, \
	by the name an order's side goes by), swap_offer {give_asset, give, want_asset, want}, swap_read {offer, accept_near_deadline?}, \
	swap_accept {offer, accept_near_deadline?, shown?}, swap_complete {accept, accept_near_deadline?}, swap_cancel {swap}, swaps, btc_swap_offer {gives, asset, atoms, sats, lapse_seconds?, bitcoin}, btc_swap_read {offer, \
	bitcoin}, btc_swap_take {offer, bitcoin}, btc_swap_complete {take, bitcoin}, btc_swap_follow {swap?, bitcoin}, btc_swap_bitcoin \
	{swap, result}, btc_swaps, btc_swap_cancel {swap}, distribute_quote {asset, claims: [{key, amount}]}, distribute {asset, claims, \
	return_address?, shown?}, distributions, claims {scan?}, claim {claims?, scan?}, plan_quote {leaves?, expiries?, max_fee_ppm?}, \
	plan {leaves?, expiries?, max_fee_ppm?}, plans, plan_cancel {plan}";

/// A refusal as the command line prints it.
pub fn refusal(e: &Error) -> Value {
	let mut out = json!({"error": {"kind": e.kind(), "message": e.to_string()}});
	if let Error::Server { code, status, .. } = e {
		out["error"]["code"] = json!(code);
		out["error"]["status"] = json!(status);
	}
	out
}

/// The name of the store of the wallet of `mnemonic`: one per wallet, named
/// after its mailbox key, so that two mnemonics never meet in one store.
pub fn store_name(mnemonic: &str) -> Result<String, Error> {
	let keys = Keys::new(mnemonic.trim(), 0, 1)?;
	let k = keys.mailbox()?.x_only_public_key().0.serialize();
	let h = sha256::Hash::hash(&k).to_byte_array();
	Ok(format!("arca-{}.sqlite", h[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>()))
}

/// The configuration a wallet is created with, from JSON: `{"server",
/// "node_url", "node_user"?, "node_password"?, "exit_delay_units"?,
/// "min_exit_delay_units"?, "max_exit_delay_units"?}`, the delays as
/// [`Config::spec_delays`] sets them unless given. In place of `server`,
/// `{"from_registry": KEY, "registry": URL}` joins the operator of key `KEY`
/// that the registry at `URL` lists: its record's signature is checked, its
/// address is the server's, and the wallet is created only when the server
/// shows the record's key, chain and keepers ([`super::registry`]).
pub fn config(c: &Value) -> Result<Config, Error> {
	let (server, expect) = match c["from_registry"].as_str().filter(|k| !k.is_empty()) {
		Some(key) => {
			if c.get("server").is_some_and(|s| !s.is_null()) {
				return Err(Error::Parse("the server and from_registry: name one".into()));
			}
			let registry = super::registry::RegistryClient::new(req_str(&c["registry"], "the registry")?)?;
			let (record, _) = registry.operator(key)?;
			let api = record["api"].as_str().unwrap_or("").to_string();
			(api, Some(super::registry::Expected::of(&record)?))
		},
		None => (req_str(&c["server"], "the server")?.to_string(), None),
	};
	let mut cfg = Config::spec_delays(&server, req_str(&c["node_url"], "the node")?);
	cfg.expect = expect;
	cfg.node_user = c["node_user"].as_str().map(String::from);
	cfg.node_password = c["node_password"].as_str().map(String::from);
	for (k, slot) in [("exit_delay_units", &mut cfg.exit_delay_units), ("min_exit_delay_units", &mut cfg.min_exit_delay_units),
		("max_exit_delay_units", &mut cfg.max_exit_delay_units)]
	{
		if let Some(v) = opt_u64(&c[k], k)? {
			*slot = u16::try_from(v).map_err(|_| Error::Refused(format!("{} is out of range", k)))?;
		}
	}
	Ok(cfg)
}

/// The operators the registry at `registry` lists, each record's signature
/// checked, as `arca operators` prints them; with `genesis`, those of that
/// chain only.
pub fn operators(registry: &str, genesis: Option<&str>) -> Result<Value, Error> {
	super::registry::RegistryClient::new(registry)?.operators(genesis)
}

/// Runs one command, as `arca <command>` does, `args` a JSON object of its
/// arguments ([`COMMANDS`]). The answer is `{"result", "start"}`.
pub fn run(w: &mut Wallet, command: &str, args: &Value) -> Result<Value, Error> {
	let start = start(w, command);
	let result = command_of(w, command, args)?;
	Ok(json!({"result": result, "start": start}))
}

/// What `arca` runs before a command: the witness (unless the command stays
/// on this machine and the node), then the re-check (unless the command is
/// itself `recheck`, `sync` or `schedule`).
fn start(w: &mut Wallet, command: &str) -> Value {
	let local = matches!(command, "address" | "openamp_key" | "balance" | "coins" | "record" | "refusals" | "participations" | "exit" | "exit_quote" | "schedule"
		| "orders" | "order_refund" | "swaps" | "plans");
	let mut out = json!({});
	if !local {
		out["witness"] = match w.witness() {
			Ok(v) => v,
			Err(e) => json!({"error": {"kind": e.kind(), "message": format!("the witness on start could not run ({}): the wallet takes \
				no coin and signs no spend through the operator until a witness succeeds", e)}}),
		};
	}
	if !matches!(command, "recheck" | "sync" | "schedule") {
		out["recheck"] = match w.recheck() {
			Ok(v) => v,
			Err(e) => json!({"error": {"kind": e.kind(), "message": format!("the re-check on start could not run: {}", e)}}),
		};
	}
	out
}

fn command_of(w: &mut Wallet, command: &str, a: &Value) -> Result<Value, Error> {
	match command {
		"info" => w.info(),
		"address" => w.address(),
		"openamp_key" => w.openamp_key().map(|k| json!({"key": k.to_string(), "path": "m/5/0"})),
		"balance" => w.balance(),
		"coins" => w.coins(),
		"record" => w.record(req_str(&a["leaf_id"], "the coin")?),
		"board" => {
			let amount = opt_u64(&a["amount"], "the amount")?.ok_or_else(|| Error::Parse("the amount is missing".into()))?;
			// With `shown`, the board goes ahead only on the fee the program
			// showed (a `board_quote`'s `fee`).
			let shown = Some(&a["shown"]).filter(|v| !v.is_null());
			w.board_shown(asset(req_str(&a["asset"], "the asset")?)?, amount, opt_asset(&a["fee_asset"])?, shown)
		},
		"board_quote" => {
			let amount = opt_u64(&a["amount"], "the amount")?.ok_or_else(|| Error::Parse("the amount is missing".into()))?;
			w.board_quote(asset(req_str(&a["asset"], "the asset")?)?, amount, opt_asset(&a["fee_asset"])?)
		},
		"boards" => w.boards(),
		"receive" => w.receive(opt_asset(&a["asset"])?, opt_u64(&a["amount"], "the amount")?),
		"forget_request" => w.forget_request(req_str(&a["owner"], "the request's key")?),
		"send" => w.send(req_str(&a["request"], "the receive request")?, opt_u64(&a["amount"], "the amount")?, opt_asset(&a["asset"])?),
		"mailbox" => w.mailbox(),
		"restore" => w.restore(),
		"quote" => {
			let quote = w.refresh_quote(&leaves(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?)?;
			Ok(json!({"coins": quote.coins()}))
		},
		"participate" => {
			// The fee is shown before anything is signed: the program shows
			// the quote, and the participation goes ahead only on the very
			// fees it showed.
			let quote = w.refresh_quote(&leaves(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?)?;
			let now = json!(quote.coins());
			if a["shown"] != now {
				return Err(Error::Refused(format!("the refresh fees changed since they were shown; they are now {}", now)));
			}
			let not_before = opt_u64(&a["not_before"], "not before")?
				.map(|t| u32::try_from(t).map_err(|_| Error::Parse("not before is out of range".into()))).transpose()?;
			w.participate(quote, not_before)
		},
		"participations" => w.participations(),
		"sync" => w.sync(),
		"schedule" => w.sync_schedule(),
		"recheck" => w.recheck(),
		"exit" => {
			// With `shown`, the path is broadcast only on the fees the program
			// showed (an `exit_quote`'s `unroll`).
			let shown = Some(&a["shown"]).filter(|v| !v.is_null());
			w.exit_shown(req_str(&a["leaf_id"], "the coin")?, opt_asset(&a["fee_asset"])?, shown)
		},
		"exit_quote" => w.exit_quote(req_str(&a["leaf_id"], "the coin")?, opt_asset(&a["fee_asset"])?),
		"refusals" => w.refusals(),
		// The order as the relay serves it: its JSON, as text or as an
		// object.
		"take_quote" | "order_fill_quote" => w.take_quote(&order(a)?, opt_u64(&a["amount"], "the amount")?, opt_u64(&a["max_fee_ppm"], "the fee bound")?),
		"take" | "order_fill" => {
			// With `shown`, the take goes ahead only on the fill, price and
			// fee the program showed (a `take_quote`'s).
			let shown = Some(&a["shown"]).filter(|v| !v.is_null());
			w.take(&order(a)?, opt_u64(&a["amount"], "the amount")?, opt_u64(&a["max_fee_ppm"], "the fee bound")?, shown)
		},
		// An order placed on the chain from the wallet's leaves: its terms as
		// an object (`super::order::ask_of`).
		"order_quote" => w.order_quote(&super::order::ask_of(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?),
		"order_place" => {
			// With `shown`, the order is placed only on the fee and the coins
			// the program showed (an `order_quote`'s).
			let shown = Some(&a["shown"]).filter(|v| !v.is_null());
			w.order_place(&super::order::ask_of(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?, shown)
		},
		"orders" => w.orders(),
		// An in-tree swap of two assets with another wallet: the maker
		// offers (its coins held, nothing signed), the taker reads the offer
		// and accepts it (signing its side), the maker completes it (signing
		// its side; the server co-signs). With `shown`, an acceptance goes
		// ahead only on the terms a `swap_read` showed.
		"swap_offer" => {
			let give = opt_u64(&a["give"], "what the wallet gives")?.ok_or_else(|| Error::Parse("what the wallet gives is missing".into()))?;
			let want = opt_u64(&a["want"], "what the wallet wants")?.ok_or_else(|| Error::Parse("what the wallet wants is missing".into()))?;
			w.swap_offer(asset(req_str(&a["give_asset"], "the asset given")?)?, give, asset(req_str(&a["want_asset"], "the asset wanted")?)?, want)
		},
		"swap_read" => w.swap_read(req_str(&a["offer"], "the offer")?, a["accept_near_deadline"].as_bool().unwrap_or(false)),
		"swap_accept" => {
			let shown = Some(&a["shown"]).filter(|v| !v.is_null());
			w.swap_accept_shown(req_str(&a["offer"], "the offer")?, a["accept_near_deadline"].as_bool().unwrap_or(false), shown)
		},
		"swap_complete" => w.swap_complete(req_str(&a["accept"], "the acceptance")?, a["accept_near_deadline"].as_bool().unwrap_or(false)),
		"swap_cancel" => w.swap_cancel(req_str(&a["swap"], "the swap")?),
		"swaps" => w.swaps(),
		"order_refund" => w.order_refund(req_str(&a["order"], "the order")?, opt_asset(&a["fee_asset"])?),
		// A swap of BTC in a Bitcoin ark for an asset here (`super::btc_swap`):
		// `bitcoin` is what the program that runs Bark hands in (`ark_info`,
		// `fee`, `invoice`), and `btc_swap_follow` says what Bark must run
		// next, whose outcome `btc_swap_bitcoin` takes.
		"btc_swap_offer" => {
			let atoms = opt_u64(&a["atoms"], "the atoms")?.ok_or_else(|| Error::Parse("the atoms are missing".into()))?;
			let sats = opt_u64(&a["sats"], "the satoshis")?.ok_or_else(|| Error::Parse("the satoshis are missing".into()))?;
			w.btc_swap_offer(req_str(&a["gives"], "what the maker gives")?, asset(req_str(&a["asset"], "the asset")?)?, atoms, sats,
				opt_u64(&a["lapse_seconds"], "the lapse")?.unwrap_or(1800), &a["bitcoin"])
		},
		"btc_swap_read" => w.btc_swap_read(req_str(&a["offer"], "the offer")?, &a["bitcoin"]),
		"btc_swap_take" => w.btc_swap_take(req_str(&a["offer"], "the offer")?, &a["bitcoin"]),
		"btc_swap_complete" => w.btc_swap_complete(req_str(&a["take"], "the take")?, &a["bitcoin"]),
		"btc_swap_follow" => Ok(Value::Array(w.btc_swap_follow(a["swap"].as_str().filter(|s| !s.is_empty()), &a["bitcoin"])?)),
		"btc_swap_bitcoin" => w.btc_swap_bitcoin(req_str(&a["swap"], "the swap")?, &a["result"]),
		"btc_swaps" => w.btc_swaps(),
		"btc_swap_cancel" => w.btc_swap_cancel(req_str(&a["swap"], "the swap")?),
		"distribute_quote" => {
			let (asset, claims) = distribution_of(w, a)?;
			w.distribute_quote(asset, &claims)
		},
		"distribute" => {
			let (asset, claims) = distribution_of(w, a)?;
			let return_to = match a["return_address"].as_str().filter(|s| !s.is_empty()) {
				Some(r) => Some(w.chain.script_of(r)?),
				None => None,
			};
			w.distribute(asset, &claims, return_to, opt_u64(&a["shown"], "the fee shown")?)
		},
		"distributions" => w.distributions(),
		"claims" => w.claims(opt_u64(&a["scan"], "the keys to scan")?.map(|n| n.min(u32::MAX as u64) as u32)),
		"claim" => w.claim(&texts(&a["claims"], "the claims")?, opt_u64(&a["scan"], "the keys to scan")?.map(|n| n.min(u32::MAX as u64) as u32)),
		"plan_quote" | "plan" => {
			let leaves = texts(&a["leaves"], "the coins")?;
			let steps = opt_u64(&a["expiries"], "the expiries")?.map_or(super::plan::DEFAULT_STEPS, |n| n.min(64) as usize);
			let bound = opt_u64(&a["max_fee_ppm"], "the bound")?;
			if command == "plan" { w.plan(&leaves, steps, bound) } else { w.plan_quote(&leaves, steps, bound) }
		},
		"plans" => w.plans(),
		"plan_cancel" => w.plan_cancel(req_str(&a["plan"], "the plan")?),
		other => Err(Error::Refused(format!("no command {}", other))),
	}
}

fn asset(s: &str) -> Result<AssetId, Error> {
	AssetId::from_str(s).map_err(|e| Error::Parse(format!("the asset {}: {}", s, e)))
}

fn opt_asset(v: &Value) -> Result<Option<AssetId>, Error> {
	match v.as_str().filter(|s| !s.is_empty()) {
		Some(s) => asset(s).map(Some),
		None => Ok(None),
	}
}

fn opt_u64(v: &Value, what: &str) -> Result<Option<u64>, Error> {
	match v {
		Value::Null => Ok(None),
		Value::String(s) if s.is_empty() => Ok(None),
		Value::String(s) => s.parse().map(Some).map_err(|_| Error::Parse(format!("{}: {}", what, s))),
		Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| Error::Parse(format!("{}: {}", what, n))),
		_ => Err(Error::Parse(format!("{}: {}", what, v))),
	}
}

fn req_str<'a>(v: &'a Value, what: &str) -> Result<&'a str, Error> {
	v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| Error::Parse(format!("{} is missing", what)))
}

/// The order a take names: the relay's JSON of it, as text or as an object.
fn order(a: &Value) -> Result<String, Error> {
	match &a["order"] {
		Value::String(s) if !s.is_empty() => Ok(s.clone()),
		Value::Object(_) => Ok(a["order"].to_string()),
		_ => Err(Error::Parse("the order is missing".into())),
	}
}

/// A list of texts, or none.
fn texts(v: &Value, what: &str) -> Result<Vec<String>, Error> {
	match v {
		Value::Null => Ok(vec![]),
		Value::Array(v) => v.iter().map(|l| l.as_str().map(String::from).ok_or_else(|| Error::Parse(format!("{}: an entry is not text", what))))
			.collect(),
		other => Err(Error::Parse(format!("{}: {}", what, other))),
	}
}

fn leaves(a: &Value) -> Result<Vec<String>, Error> {
	match &a["leaves"] {
		Value::Null => Ok(vec![]),
		Value::Array(v) => v.iter().map(|l| l.as_str().map(String::from).ok_or_else(|| Error::Parse("a coin is not text".into()))).collect(),
		other => Err(Error::Parse(format!("the coins: {}", other))),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn arguments_are_read_as_the_command_line_reads_them() {
		assert_eq!(opt_u64(&json!("2000000"), "the amount").unwrap(), Some(2_000_000));
		assert_eq!(opt_u64(&json!(5), "the amount").unwrap(), Some(5));
		assert_eq!(opt_u64(&json!(""), "the amount").unwrap(), None);
		assert_eq!(opt_u64(&Value::Null, "the amount").unwrap(), None);
		assert_eq!(opt_u64(&json!("-1"), "the amount").unwrap_err().to_string(), "cannot parse the amount: -1");
		assert_eq!(req_str(&json!(""), "the coin").unwrap_err().to_string(), "cannot parse the coin is missing");
		assert_eq!(leaves(&json!({"leaves": ["a", "b"]})).unwrap(), vec!["a".to_string(), "b".to_string()]);
		assert!(leaves(&json!({"leaves": [1]})).is_err());
		assert!(opt_asset(&json!("zz")).is_err());
		// A take's order: the relay's JSON, as text or as an object.
		assert_eq!(order(&json!({"order": "{\"covenant_txid\": \"a\"}"})).unwrap(), "{\"covenant_txid\": \"a\"}");
		assert_eq!(order(&json!({"order": {"covenant_txid": "a"}})).unwrap(), "{\"covenant_txid\":\"a\"}");
		assert_eq!(order(&json!({})).unwrap_err().to_string(), "cannot parse the order is missing");
	}

	#[test]
	fn a_configuration_takes_the_specification_delays_unless_given() {
		let c = config(&json!({"server": "http://s", "node_url": "http://n"})).unwrap();
		let spec = Config::spec_delays("http://s", "http://n");
		assert_eq!((c.exit_delay_units, c.min_exit_delay_units, c.max_exit_delay_units),
			(spec.exit_delay_units, spec.min_exit_delay_units, spec.max_exit_delay_units));
		assert_eq!(c.node_password, None);
		let c = config(&json!({"server": "http://s", "node_url": "http://n", "exit_delay_units": "3"})).unwrap();
		assert_eq!(c.exit_delay_units, 3);
		assert_eq!(config(&json!({"node_url": "http://n"})).unwrap_err().to_string(), "cannot parse the server is missing");
		assert_eq!(config(&json!({"server": "s", "node_url": "n", "exit_delay_units": 70000})).unwrap_err().to_string(),
			"refused: exit_delay_units is out of range");
		assert_eq!(config(&json!({"server": "https://s", "from_registry": "ab", "registry": "https://r", "node_url": "n"})).unwrap_err()
			.to_string(), "cannot parse the server and from_registry: name one");
		assert_eq!(config(&json!({"from_registry": "ab", "node_url": "n"})).unwrap_err().to_string(), "cannot parse the registry is missing");
		assert!(c.expect.is_none());
	}

	#[test]
	fn a_refusal_carries_the_servers_code() {
		let e = Error::Server { call: "cosign_transfer".into(), status: 409, code: "key_reused".into(), message: "m".into() };
		let r = refusal(&e);
		assert_eq!(r["error"]["kind"], "server_refused");
		assert_eq!(r["error"]["code"], "key_reused");
		assert_eq!(r["error"]["status"], 409);
		assert_eq!(r["error"]["message"], "the server refused cosign_transfer (409 key_reused): m");
		assert_eq!(refusal(&Error::Refused("no".into())), json!({"error": {"kind": "refused", "message": "refused: no"}}));
	}

	#[test]
	fn a_store_is_named_after_the_mailbox_key() {
		let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let a = store_name(m).unwrap();
		assert_eq!(a, store_name(&format!("  {}\n", m)).unwrap());
		assert!(a.starts_with("arca-") && a.ends_with(".sqlite") && a.len() == "arca-.sqlite".len() + 16);
		assert_ne!(a, store_name("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap());
	}
}

/// A distribution's asset and claims from a command's arguments: `asset`,
/// and `claims`, each `{key, amount}`, the key 64 hex digits (x-only), 66 (a
/// compressed public key) or a taproot address.
fn distribution_of(w: &Wallet, a: &Value) -> Result<(AssetId, Vec<(elements::secp256k1_zkp::XOnlyPublicKey, u64)>), Error> {
	let asset = asset(req_str(&a["asset"], "the asset")?)?;
	let list = a["claims"].as_array().ok_or_else(|| Error::Parse("the claims: a list of {key, amount}".into()))?;
	let mut claims = Vec::with_capacity(list.len());
	for c in list {
		let key = super::claim::named_key(req_str(&c["key"], "a claim's key")?, &w.chain)?;
		let amount = opt_u64(&c["amount"], "a claim's amount")?.ok_or_else(|| Error::Parse("a claim names no amount".into()))?;
		claims.push((key, amount));
	}
	Ok((asset, claims))
}
