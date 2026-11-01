//! The Bitcoin ark wallet's commands by name.
//!
//! Every command takes a JSON object and answers one, so a browser's worker and
//! a program linking the wallet natively drive it the same way. Amounts are
//! whole sats, as decimal strings or numbers; hashes and preimages are hex.
//!
//! The commands only call [bark::Wallet]: every amount, fee and refusal is the
//! wallet's or its server's.

use std::str::FromStr;

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};

use bark::ark::bitcoin::{self, Amount, Network, Psbt};
use bark::ark::bitcoin::hex::FromHex;
use bark::ark::lightning::{Invoice, PaymentHash};
use bark::lightning_invoice::Bolt11Invoice;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::actions::lightning::pay::LightningSendState;
use bark::{Config, Wallet, WalletSeed};

/// The names [run] answers to.
pub const COMMANDS: &[&str] = &[
	"info", "balance", "address", "board_address", "board_psbt", "send", "send_fee",
	"pay", "pay_status", "pay_fee", "invoice", "receive_status", "receive_fee",
	"offboard", "offboard_fee", "refresh", "schedule_refreshes", "sync", "catch_up", "history",
	"coins", "exit_estimate", "exit_start", "exit_progress", "exit_claim", "exit_status", "exit_auto",
	"tower_plan",
];

/// The Bitcoin network a name stands for. Testnet4 is the network the
/// Sequentia testnet anchors to.
pub fn network(name: &str) -> anyhow::Result<Network> {
	Ok(match name {
		"bitcoin" | "mainnet" => Network::Bitcoin,
		"testnet4" => Network::Testnet4,
		"signet" => Network::Signet,
		"regtest" => Network::Regtest,
		other => bail!("unknown Bitcoin network '{}'", other),
	})
}

/// The wallet's seed from the page's phrase: one phrase holds the page's own
/// Bitcoin keys and, under Bark's own path, this wallet's.
pub fn seed(network: Network, mnemonic: &str) -> anyhow::Result<WalletSeed> {
	let m = bark::bip39::Mnemonic::from_str(mnemonic.trim()).context("the phrase is not a valid mnemonic")?;
	Ok(WalletSeed::new_from_mnemonic(network, &m))
}

/// The wallet's configuration: its ark server and an Esplora chain source.
pub fn config(network: Network, server: &str, esplora: &str) -> Config {
	let mut c = Config::network_default(network);
	c.server_address = server.to_owned();
	c.esplora_address = Some(esplora.to_owned());
	c
}

fn sats_arg(args: &Value, key: &str) -> anyhow::Result<Amount> {
	let v = args.get(key).ok_or_else(|| anyhow!("'{}' is missing", key))?;
	let n = match v {
		Value::String(s) => s.trim().parse::<u64>().map_err(|_| anyhow!("'{}' is not a whole number of sats", key))?,
		Value::Number(n) => n.as_u64().ok_or_else(|| anyhow!("'{}' is not a whole number of sats", key))?,
		_ => bail!("'{}' is not a whole number of sats", key),
	};
	Ok(Amount::from_sat(n))
}

fn str_arg<'a>(args: &'a Value, key: &str) -> anyhow::Result<&'a str> {
	args.get(key).and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty())
		.ok_or_else(|| anyhow!("'{}' is missing", key))
}

fn bool_arg(args: &Value, key: &str) -> bool {
	args.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn sat(a: Amount) -> String { a.to_sat().to_string() }

fn hash_arg(args: &Value) -> anyhow::Result<PaymentHash> {
	PaymentHash::from_str(str_arg(args, "hash")?).map_err(|_| anyhow!("'hash' is not a payment hash"))
}

fn btc_address(wallet_net: Network, s: &str) -> anyhow::Result<bitcoin::Address> {
	let a = bitcoin::Address::from_str(s).context("not a Bitcoin address")?;
	a.require_network(wallet_net).context("the address is for another Bitcoin network")
}

/// The longest lock, in blocks, a Lightning payment out of the ark can take:
/// the server pays with at most its HTLC-send delta less its own margin.
fn max_route_delay(info: &bark::ark::ArkInfo) -> u32 {
	(info.htlc_send_expiry_delta as u32).saturating_sub(info.htlc_expiry_delta as u32)
}

fn send_state(st: LightningSendState) -> Value {
	match st {
		LightningSendState::Paid(p) => json!({ "state": "complete", "preimage": p.preimage.to_string() }),
		LightningSendState::InProgress(s) => json!({ "state": "pending", "fee": sat(s.fee), "amount": sat(s.payment_amount) }),
		LightningSendState::Unknown => json!({ "state": "none" }),
	}
}

fn receive_state(st: LightningReceiveState) -> Value {
	match st {
		LightningReceiveState::Settled(r) => json!({
			"state": "paid", "preimage": r.preimage.to_string(), "amount": sat(r.amount),
		}),
		LightningReceiveState::InProgress(r) => json!({
			"state": "waiting", "invoice": r.invoice.to_string(),
		}),
	}
}

/// Runs one command on an open wallet.
pub async fn run(wallet: &Wallet, cmd: &str, args: &Value) -> anyhow::Result<Value> {
	match cmd {
		"info" => {
			let info = wallet.require_ark_info().await?;
			Ok(json!({
				"network": info.network.to_string(),
				"server_pubkey": info.server_pubkey.to_string(),
				"min_board_sat": sat(info.min_board_amount),
				"max_vtxo_sat": info.max_vtxo_amount.map(sat),
				"required_board_confirmations": info.required_board_confirmations,
				"vtxo_lifetime": info.vtxo_lifetime,
				"vtxo_exit_delta": info.vtxo_exit_delta,
				"max_route_delay": max_route_delay(&info),
			}))
		},
		"balance" => {
			let b = wallet.balance().await?;
			let pending_exit = b.pending_exit.unwrap_or(Amount::ZERO);
			let total = b.spendable + b.pending_lightning_send + b.claimable_lightning_receive
				+ b.pending_in_round + b.pending_board + pending_exit;
			Ok(json!({
				"spendable": sat(b.spendable),
				"pending_lightning_send": sat(b.pending_lightning_send),
				"claimable_lightning_receive": sat(b.claimable_lightning_receive),
				"pending_in_round": sat(b.pending_in_round),
				"pending_board": sat(b.pending_board),
				"pending_exit": sat(pending_exit),
				"total": sat(total),
			}))
		},
		"address" => Ok(json!({ "address": wallet.new_address().await?.to_string() })),
		// The address a board's funding pays, under a fresh key of the wallet's.
		// The funding transaction is built and signed by whoever holds the coins;
		// `board_psbt` then takes it with the same key index and expiry.
		"board_address" => {
			let (key, index) = wallet.derive_store_next_keypair().await?;
			let (address, expiry_height) = wallet.board_funding_address(&key).await?;
			let info = wallet.require_ark_info().await?;
			let fee = match args.get("sats") {
				Some(_) => Some(info.fees.board.calculate(sats_arg(args, "sats")?).context("fee overflowed")?),
				None => None,
			};
			Ok(json!({
				"address": address.to_string(), "key_index": index, "expiry_height": expiry_height,
				"min_sat": sat(info.min_board_amount), "max_sat": info.max_vtxo_amount.map(sat),
				"fee": fee.map(sat),
			}))
		},
		// A funding PSBT that pays the board address (hex). Unsigned, the wallet
		// waits for the transaction to appear on the chain; finalised, it
		// broadcasts it itself. Either way the server cosigns first.
		"board_psbt" => {
			let raw = Vec::<u8>::from_hex(str_arg(args, "psbt")?).context("the PSBT is not hex")?;
			let psbt = Psbt::deserialize(&raw).context("the PSBT does not decode")?;
			let index = args.get("key_index").and_then(|v| v.as_u64()).context("'key_index' is missing")? as u32;
			let expiry = args.get("expiry_height").and_then(|v| v.as_u64()).context("'expiry_height' is missing")? as u32;
			let key = wallet.peek_keypair(index).await?;
			let b = wallet.board_psbt(psbt, key, expiry).await?;
			Ok(json!({
				"funding_txid": b.funding_tx.compute_txid().to_string(),
				"amount": sat(b.amount),
				"vtxos": b.vtxos.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
			}))
		},
		"send" => {
			let dest = bark::ark::Address::from_str(str_arg(args, "address")?).context("not an Ark address")?;
			let amount = sats_arg(args, "sats")?;
			wallet.validate_arkoor_address(&dest).await.map_err(|e| anyhow!("{}", e))?;
			let fee = wallet.estimate_arkoor_payment_fee(amount).await?.fee;
			wallet.send_arkoor_payment(&dest, amount).await?;
			Ok(json!({ "sent": sat(amount), "fee": sat(fee) }))
		},
		"send_fee" => {
			let e = wallet.estimate_arkoor_payment_fee(sats_arg(args, "sats")?).await?;
			Ok(json!({ "fee": sat(e.fee), "gross": sat(e.gross_amount) }))
		},
		// Pays a BOLT11 invoice, refused before anything moves when the fee would be
		// more than `max_fee_sats` or the route's lock could run past `max_delay`.
		"pay" => {
			let s = str_arg(args, "invoice")?;
			let inv = Bolt11Invoice::from_str(s).map_err(|e| anyhow!("the invoice does not decode: {}", e))?;
			let hash = PaymentHash::from(&inv);
			match wallet.lightning_send_state(hash).await? {
				LightningSendState::Unknown => {},
				st => return Ok(send_state(st)),
			}
			let amount = Amount::from_sat(inv.amount_milli_satoshis().context("the invoice names no amount")?.div_ceil(1000));
			let info = wallet.require_ark_info().await?;
			if let Some(max) = args.get("max_delay").and_then(|v| v.as_u64()) {
				if (max_route_delay(&info) as u64) > max {
					bail!("refused: a payment from the ark may lock for {} blocks, more than the {} allowed",
						max_route_delay(&info), max);
				}
			}
			let fee = wallet.estimate_lightning_send_fee(amount).await?.fee;
			if args.get("max_fee_sats").is_some() && fee > sats_arg(args, "max_fee_sats")? {
				bail!("refused: the payment's fee of {} sat is more than the {} allowed", fee.to_sat(), sats_arg(args, "max_fee_sats")?.to_sat());
			}
			let wait = args.get("wait").and_then(|v| v.as_bool()).unwrap_or(true);
			match wallet.pay_lightning_invoice(Invoice::Bolt11(inv), None, wait).await {
				Ok(_) => Ok(send_state(wallet.lightning_send_state(hash).await?)),
				Err(e) => match wallet.lightning_send_state(hash).await? {
					LightningSendState::Unknown => Ok(json!({ "state": "failed", "reason": format!("{:#}", e) })),
					st => Ok(send_state(st)),
				},
			}
		},
		"pay_status" => {
			let hash = hash_arg(args)?;
			let st = if bool_arg(args, "drive") {
				wallet.check_lightning_payment(hash, false).await?
			} else {
				wallet.lightning_send_state(hash).await?
			};
			Ok(send_state(st))
		},
		"pay_fee" => {
			let info = wallet.require_ark_info().await?;
			let e = wallet.estimate_lightning_send_fee(sats_arg(args, "sats")?).await?;
			Ok(json!({ "fee": sat(e.fee), "gross": sat(e.gross_amount), "max_route_delay": max_route_delay(&info) }))
		},
		// An invoice the server holds a payment to until the wallet claims it;
		// the wallet's daemon claims it as soon as it is held.
		"invoice" => {
			let amount = sats_arg(args, "sats")?;
			let desc = args.get("description").and_then(|v| v.as_str()).map(|s| s.to_owned());
			let inv = wallet.bolt11_invoice(amount, desc, None).await?;
			let expires_at = inv.duration_since_epoch().as_secs() + inv.expiry_time().as_secs();
			Ok(json!({
				"invoice": inv.to_string(),
				"payment_hash": PaymentHash::from(&inv).to_string(),
				"expires_at": expires_at,
			}))
		},
		// A receive's state; with `claim`, the wallet first tries to claim a payment
		// the server holds (with `wait`, until it is claimed or gone).
		"receive_status" => {
			let hash = hash_arg(args)?;
			let st = if bool_arg(args, "claim") {
				wallet.try_claim_lightning_receive(hash, bool_arg(args, "wait")).await
			} else {
				wallet.lightning_receive_state(hash).await
			};
			// The wallet knows no receive under the hash: never made, or given up.
			Ok(st.map(receive_state).unwrap_or_else(|e| json!({ "state": "unknown", "reason": format!("{:#}", e) })))
		},
		"receive_fee" => {
			let e = wallet.estimate_lightning_receive_fee(sats_arg(args, "sats")?).await?;
			Ok(json!({ "fee": sat(e.fee), "net": sat(e.net_amount) }))
		},
		// Leaves the ark to a Bitcoin address: `sats`, or everything with `all`.
		"offboard" => {
			let net = wallet.properties().await?.network;
			let dest = btc_address(net, str_arg(args, "address")?)?;
			let txid = if bool_arg(args, "all") {
				wallet.offboard_all(dest).await?
			} else {
				wallet.send_onchain(dest, sats_arg(args, "sats")?).await?
			};
			Ok(json!({ "txid": txid.to_string() }))
		},
		"offboard_fee" => {
			let net = wallet.properties().await?.network;
			let dest = btc_address(net, str_arg(args, "address")?)?;
			let e = wallet.estimate_send_onchain(&dest, sats_arg(args, "sats")?).await?;
			Ok(json!({ "fee": sat(e.fee), "gross": sat(e.gross_amount) }))
		},
		// Refreshes the coins that are due, in the server's next round. A coin whose refresh
		// is scheduled is left to the server.
		"refresh" => {
			let due = wallet.get_vtxos_to_refresh().await?;
			if due.is_empty() {
				return Ok(json!({ "refreshed": 0 }));
			}
			let n = due.len();
			let r = wallet.refresh_vtxos(due).await;
			crate::exit::note_server(wallet, r.is_err());
			r?;
			Ok(json!({ "refreshed": n }))
		},
		// Schedules with the server the refresh of every coin that has none yet, so the
		// server renews it with the wallet closed; the wallet takes the new coin in at its
		// next sync. `except` (coin ids): the coins a Bitcoin ark watchtower covers
		// (`tower_plan`'s `no_refresh`), which get no refresh.
		"schedule_refreshes" => {
			let mut except = std::collections::HashSet::new();
			for v in args.get("except").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
				let id: bark::ark::VtxoId = v.as_str().unwrap_or("").parse()
					.map_err(|_| anyhow!("except: {} is not a coin id", v))?;
				except.insert(id);
			}
			let s = wallet.schedule_refreshes_except(&except).await;
			crate::exit::note_server(wallet, s.is_err());
			let s = s?;
			Ok(json!({
				"scheduled": s.iter().map(|r| json!({
					"height": r.height,
					"vtxos": r.vtxos.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
					"amount": sat(r.amount),
				})).collect::<Vec<_>>(),
			}))
		},
		"sync" => {
			wallet.sync().await;
			Ok(json!({}))
		},
		// What other wallets of the phrase did since this store was made: coins
		// they made or received, from the server's recovery mailbox, and coins of
		// this store they spent.
		"catch_up" => {
			let r = wallet.catch_up_from_server().await?;
			Ok(json!({
				"recovered": r.recovery.recovered().ids().map(|i| i.to_string()).collect::<Vec<_>>(),
				"recovered_sat": sat(r.recovery.recovered().total_amount()),
				"spent_elsewhere": r.spent_elsewhere.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
				"failed": r.recovery.failed().ids().map(|i| i.to_string()).collect::<Vec<_>>(),
				"complete": r.recovery.is_complete(),
			}))
		},
		"history" => Ok(serde_json::to_value(wallet.history().await?)?),
		"coins" => {
			let tip = wallet.chain().tip().await.ok();
			let scheduled = wallet.scheduled_refresh_heights().await?;
			let coins = wallet.vtxos().await?.into_iter().map(|v| json!({
				"id": v.vtxo.id().to_string(),
				"amount": sat(v.vtxo.amount()),
				"expiry_height": v.vtxo.expiry_height(),
				"refresh_height": scheduled.get(&v.vtxo.id()),
				"state": format!("{:?}", v.state.kind()),
			})).collect::<Vec<_>>();
			Ok(json!({ "tip": tip, "coins": coins }))
		},
		c if crate::exit::COMMANDS.contains(&c) => crate::exit::run(wallet, c, args).await,
		c if crate::tower::COMMANDS.contains(&c) => crate::tower::run(wallet, c, args).await,
		other => bail!("unknown command '{}'", other),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn networks() {
		assert_eq!(network("testnet4").unwrap(), Network::Testnet4);
		assert_eq!(network("regtest").unwrap(), Network::Regtest);
		assert!(network("testnet").is_err());
	}

	#[test]
	fn amounts() {
		let a = json!({ "s": "1500", "n": 2500, "bad": "1.5", "neg": -3 });
		assert_eq!(sats_arg(&a, "s").unwrap(), Amount::from_sat(1500));
		assert_eq!(sats_arg(&a, "n").unwrap(), Amount::from_sat(2500));
		assert!(sats_arg(&a, "bad").is_err());
		assert!(sats_arg(&a, "neg").is_err());
		assert!(sats_arg(&a, "missing").is_err());
	}

	#[test]
	fn one_phrase_one_wallet() {
		let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let a = seed(Network::Testnet4, phrase).unwrap();
		let b = seed(Network::Testnet4, &format!("  {}\n", phrase)).unwrap();
		assert_eq!(a.fingerprint(), b.fingerprint());
		assert!(seed(Network::Testnet4, "not a phrase").is_err());
	}

	#[test]
	fn addresses_keep_to_their_network() {
		let t4 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
		assert!(btc_address(Network::Testnet4, t4).is_ok());
		assert!(btc_address(Network::Bitcoin, t4).is_err());
		assert!(btc_address(Network::Testnet4, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
	}
}
