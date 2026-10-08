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
pub const COMMANDS: &str = "info, address, balance, coins, record {leaf_id}, board {asset, amount, fee_asset?}, boards, \
	receive {asset?, amount?}, forget_request {owner}, send {request, amount?, asset?}, mailbox, restore, quote {leaves?, \
	max_fee_ppm?}, participate {leaves?, not_before?, max_fee_ppm?, shown}, participations, sync, schedule, recheck, \
	exit {leaf_id, fee_asset?}, refusals";

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
/// [`Config::spec_delays`] sets them unless given.
pub fn config(c: &Value) -> Result<Config, Error> {
	let mut cfg = Config::spec_delays(req_str(&c["server"], "the server")?, req_str(&c["node_url"], "the node")?);
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
	let local = matches!(command, "address" | "balance" | "coins" | "record" | "refusals" | "participations" | "exit" | "schedule");
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
		"balance" => w.balance(),
		"coins" => w.coins(),
		"record" => w.record(req_str(&a["leaf_id"], "the coin")?),
		"board" => {
			let amount = opt_u64(&a["amount"], "the amount")?.ok_or_else(|| Error::Parse("the amount is missing".into()))?;
			w.board(asset(req_str(&a["asset"], "the asset")?)?, amount, opt_asset(&a["fee_asset"])?)
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
		"exit" => w.exit(req_str(&a["leaf_id"], "the coin")?, opt_asset(&a["fee_asset"])?),
		"refusals" => w.refusals(),
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
