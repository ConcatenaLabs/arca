//! A whole Arca server on an anchored proof-of-stake regtest chain, kept
//! running for a wallet driven from outside this process: a browser wallet
//! built on the wallet library's wasm package (`wallet-wasm/`), or anything
//! else that speaks the server's HTTP and the node's JSON-RPC.
//!
//! It is the scenarios' server (`tests/common/running.rs`): asset X listed
//! for fees on the node, asset Y not, rounds built only when asked, leaves
//! with exit delays from one 512-second unit. It is ignored by default and
//! runs until it is told to stop:
//!
//! ```sh
//! ARCA_OPERATOR_CONTROL=127.0.0.1:18640 \
//!   cargo test -p arca-cli --test arca_operator_for_browsers -- --ignored --nocapture
//! ```
//!
//! with `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` as for the
//! scenarios (`tests/common/mod.rs`). It writes nothing a browser must read:
//! `GET /state` on the control address answers with the server's URL, the
//! node's RPC URL and credentials, the two assets, the chain's genesis hash,
//! and the file of the test operator key (for `arca-signer
//! --sign-operator-record`). The control address
//! takes, each a `POST` whose body is a JSON object:
//!
//! | Path | Does |
//! |---|---|
//! | `/fund {script, asset, amount}` | Pays `amount` of `asset` to the script (hex) from the test's coins, broadcast |
//! | `/fund_server {asset, amount}` | Pays `amount` of `asset` to the operator's own wallet, which funds its rounds, from the test's coins, broadcast |
//! | `/produce` | Produces one block |
//! | `/bury` | Buries the chain two Bitcoin blocks deep and waits for the server to follow |
//! | `/round` | Builds a round of whatever participations stand, mines it, buries it and waits for it to be final; its txid, or `null` when none stood |
//! | `/advance {seconds}` | Moves the chain's median time at least that far on |
//! | `/rpc {method, params}` | One call to the node, its result |
//! | `/fees {asset, refresh_ppm?, offboard_base?}` | Sets the asset's refresh fee, or the fixed part of its offboard fee (what a take pays), and reloads the server's configuration, as an operator's SIGHUP does |
//! | `/build` | Builds the rounds of whatever participations stand, and broadcasts none that waits on a take's forfeits: their txids, sizes and the orders each fills |
//! | `/pass` | One pass over the rounds: a round held for takes' forfeits goes out once every one is in |
//! | `/settle` | One pass of the watcher (releases, notices, sweeps, the return of unclaimed claims), a block buried two Bitcoin blocks deep, one pass of the nursery and another of the watcher, as an operator's timers do between them; the chain's tip |
//! | `/round_state {txid}` | Where the server says the round stands: built, broadcast, final or lost |
//! | `/orphan {height}` | Reorganises the parent chain from that height (an anchor rollback): every block anchored there or above leaves the chain |
//! | `/quit` | Stops the server, the signer and the chain, and ends the test |
//!
//! With `ARCA_OPERATOR_LIGHTNING` set (and `LIGHTNINGD_EXEC`, a SeqLN
//! `lightningd`), the chain is the one SeqLN's `sequentia-regtest` network
//! assumes and the operator runs a SeqLN node in X that receives, with a
//! channel to a node of its own, as the Lightning scenarios do; its payments
//! out of the tree time out four to eight days out, which a swap of BTC for
//! an asset (`arca btc-swap`) needs between wallets with the specification's
//! 36-hour exit delays against a Bitcoin ark's 88-hour HTLC delays. `/state`
//! then says `lightning: true`.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use common::running::Running;
use server::store::RoundState;

/// One request: its path and its JSON body.
fn read_request(s: &mut TcpStream) -> Option<(String, String, Value)> {
	s.set_nonblocking(false).ok()?;
	s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
	let mut buf = vec![];
	let mut chunk = [0u8; 4096];
	let head_end = loop {
		let n = s.read(&mut chunk).ok()?;
		if n == 0 {
			return None;
		}
		buf.extend_from_slice(&chunk[..n]);
		if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
			break i + 4;
		}
	};
	let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
	let mut lines = head.lines();
	let mut first = lines.next()?.split_whitespace();
	let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
	let len: usize = lines.filter_map(|l| l.split_once(':')).find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.trim().parse().ok()).unwrap_or(0);
	while buf.len() < head_end + len {
		let n = s.read(&mut chunk).ok()?;
		if n == 0 {
			break;
		}
		buf.extend_from_slice(&chunk[..n]);
	}
	let body = &buf[head_end..(head_end + len).min(buf.len())];
	let json = if body.is_empty() { json!({}) } else { serde_json::from_slice(body).unwrap_or(Value::Null) };
	Some((method, path, json))
}

fn answer(s: &mut TcpStream, status: u16, v: &Value) {
	let body = v.to_string();
	let _ = write!(s, "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
		status, if status == 200 { "OK" } else { "Error" }, body.len(), body);
}

fn script(h: &str) -> Result<Script, String> {
	if h.len() % 2 != 0 {
		return Err("the script is not hex".into());
	}
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string()))
		.collect::<Result<Vec<u8>, _>>().map(Script::from)
}

async fn handle(r: &mut Running, path: &str, b: &Value) -> Result<Value, String> {
	match path {
		"/state" => Ok(json!({
			"server": r.url(), "node_url": r.node_url(), "node_user": "arca", "node_password": "arca",
			"lightning": r.config.assets.iter().any(|a| a.lightning.is_some()),
			"x": r.x.to_string(), "y": r.y.to_string(),
			// The test operator key's file, for `arca-signer --key-file …
			// --sign-operator-record`, and the chain it signs for.
			"signer_key_file": r.signer.dir.join("operator.key").display().to_string(),
			"genesis_hash": r.rt.client().call::<String>("getblockhash", &[json!(0)]).map_err(|e| e.to_string())?,
			"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks,
		})),
		"/fund" => {
			let s = script(b["script"].as_str().ok_or("no script")?)?;
			// The purse pays whatever it is given: an empty script or more than
			// it holds would end the test, and the chain with it.
			if s.is_empty() {
				return Err("an empty script".into());
			}
			let asset = AssetId::from_str(b["asset"].as_str().ok_or("no asset")?).map_err(|e| e.to_string())?;
			let amount = b["amount"].as_u64().or_else(|| b["amount"].as_str().and_then(|a| a.parse().ok())).ok_or("no amount")?;
			let tx = r.pay_to(s, asset, amount);
			Ok(json!({"txid": tx.txid().to_string()}))
		},
		"/fund_server" => {
			let asset = AssetId::from_str(b["asset"].as_str().ok_or("no asset")?).map_err(|e| e.to_string())?;
			let amount = b["amount"].as_u64().ok_or("no amount")?;
			let tx = r.fund_server(asset, amount).await;
			Ok(json!({"txid": tx.txid().to_string()}))
		},
		"/produce" => {
			r.produce().await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/bury" => {
			r.bury().await;
			r.synced().await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/round" => {
			let built = r.server.rounds.run_round().await.map_err(|e| e.to_string())?;
			let Some(built) = built else { return Ok(json!({"round": null})) };
			let txid = built.tx.txid();
			r.produce().await;
			r.bury().await;
			r.round_state(&txid, RoundState::Final).await;
			r.synced().await;
			Ok(json!({"round": txid.to_string(), "vsize": built.tx.vsize()}))
		},
		"/advance" => {
			let seconds = b["seconds"].as_u64().ok_or("no seconds")? as u32;
			tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, seconds));
			r.synced().await;
			Ok(json!({"median_time": common::node::median_time(&r.rt)}))
		},
		"/rpc" => {
			let method = b["method"].as_str().ok_or("no method")?;
			let params: Vec<Value> = b["params"].as_array().cloned().unwrap_or_default();
			r.rt.client().call::<Value>(method, &params).map_err(|e| e.to_string())
		},
		"/build" => {
			let (built, failed) = r.server.rounds.run_rounds().await.map_err(|e| e.to_string())?;
			Ok(json!({
				"rounds": built.iter().map(|b| json!({"txid": b.tx.txid().to_string(), "vsize": b.tx.vsize(),
					"fills": b.fills.iter().map(|o| format!("{}:{}", o.txid, o.vout)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
				"failed": failed.iter().map(|(a, e)| json!({"asset": a.to_string(), "error": e.to_string()})).collect::<Vec<_>>(),
			}))
		},
		"/pass" => {
			r.server.rounds.pass().await.map_err(|e| e.to_string())?;
			Ok(json!({"passed": true}))
		},
		"/settle" => {
			r.server.watcher.pass().await.map_err(|e| e.to_string())?;
			tokio::time::sleep(Duration::from_millis(300)).await;
			r.produce().await;
			r.bury().await;
			r.synced().await;
			r.server.nursery.pass().await.map_err(|e| e.to_string())?;
			r.server.watcher.pass().await.map_err(|e| e.to_string())?;
			tokio::time::sleep(Duration::from_millis(300)).await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/round_state" => {
			use elements::hashes::Hash;
			let txid = elements::Txid::from_str(b["txid"].as_str().ok_or("no txid")?).map_err(|e| e.to_string())?;
			let st = r.server.store.round_by_txid(&txid.to_byte_array()).await.map_err(|e| e.to_string())?;
			Ok(json!({"state": st.map(|x| x.state.as_str())}))
		},
		"/orphan" => {
			let height = b["height"].as_u64().ok_or("no height")?;
			let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(height))?;
			Ok(json!({"orphaned": gone.len()}))
		},
		"/fees" => {
			let asset = b["asset"].as_str().ok_or("no asset")?;
			let ppm = b["refresh_ppm"].as_u64();
			let offboard_base = b["offboard_base"].as_u64();
			if ppm.is_none() && offboard_base.is_none() {
				return Err("name refresh_ppm or offboard_base".into());
			}
			let mut config = r.config.clone();
			let a = config.assets.iter_mut().find(|a| a.asset == asset).ok_or("the server does not serve that asset")?;
			if let Some(p) = ppm {
				a.refresh_ppm = Some(p);
			}
			if let Some(base) = offboard_base {
				a.offboard_base = Some(base.to_string());
			}
			let reloaded = r.server.reload(&config).await.map_err(|e| e.to_string())?;
			r.config = config;
			Ok(json!({"changed": reloaded.changed.iter().map(|a| a.to_string()).collect::<Vec<_>>()}))
		},
		other => Err(format!("no path {}", other)),
	}
}

/// The server on SeqLN's chain, with its SeqLN node in X that receives and
/// a channel to a node of its own; its Lightning terms short except a
/// payment's timeout, four to eight days out.
async fn with_lightning() -> (Running, Vec<sequentia_ext::lightning::LightningNode>) {
	let lnd = common::lightning::lightningd("operator_for_browsers").expect("ARCA_OPERATOR_LIGHTNING needs LIGHTNINGD_EXEC");
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 4 * 86_400;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let (ox, px) = tokio::task::block_in_place(|| {
		let ox = common::lightning::node(&r.rt, &mut r.purse, &lnd, "browsers-o", true, x, 2_000_000_000);
		let px = common::lightning::node(&r.rt, &mut r.purse, &lnd, "browsers-p", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		(ox, px)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == x.to_string() {
			a.lightning = Some(server::server::LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	(r, vec![ox, px])
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a server kept running for a wallet outside this process; run by hand"]
async fn operator_for_browsers() {
	let addr = std::env::var("ARCA_OPERATOR_CONTROL").unwrap_or_else(|_| "127.0.0.1:18640".into());
	let (mut r, _nodes) = match std::env::var_os("ARCA_OPERATOR_LIGHTNING") {
		Some(_) => with_lightning().await,
		None => (Running::start().await, vec![]),
	};
	let listener = TcpListener::bind(&addr).expect("bind the control address");
	listener.set_nonblocking(true).unwrap();
	println!("operator for browsers: control {}, server {}, node {}, X {}, Y {}", addr, r.url(), r.node_url(), r.x, r.y);
	loop {
		let mut s = match listener.accept() {
			Ok((s, _)) => s,
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
				tokio::time::sleep(Duration::from_millis(50)).await;
				continue;
			},
			Err(e) => panic!("accept: {}", e),
		};
		let Some((method, path, body)) = read_request(&mut s) else { continue };
		if method == "OPTIONS" {
			answer(&mut s, 200, &json!({}));
			continue;
		}
		if path == "/quit" {
			answer(&mut s, 200, &json!({"quit": true}));
			break;
		}
		let out = handle(&mut r, &path, &body).await;
		println!("operator for browsers: {} {} -> {}", path, body, match &out { Ok(v) => v.to_string(), Err(e) => format!("error: {}", e) });
		match out {
			Ok(v) => answer(&mut s, 200, &v),
			Err(e) => answer(&mut s, 400, &json!({"error": e})),
		}
	}
	r.server.stop();
}
