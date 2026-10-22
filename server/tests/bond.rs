//! The operator's equivocation bond, posted, named in `info` and noticed,
//! on an anchored proof-of-stake regtest chain: `bond-post` refuses a
//! service's wallet and pays the bond from an operating one, `info.bond`
//! reads the coin's state from the node (unposted, bonded, a notice the
//! configuration does not name read as spent, then in notice with its
//! withdrawal time), the withdrawal before the delay is refused by the node,
//! and a configuration whose notice is too short, or whose withdrawal key is
//! the operator key, does not start.

mod common;


use elements::Script;
use serde_json::{json, Value};

use arca_covenant::{BondPolicy, RelativeTime};
use common::running::Running;
use sequentia_ext::rpc::{Auth, Client};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::bond::{min_notice_seconds, BondSection, LIFETIME};
use server::server::{bond_address, bond_notice, bond_post, bond_withdraw, Server};

const BOND: u64 = 1_000_000_000;

fn wallet_rpc(r: &Running, name: &str) -> Client {
	Client::new(format!("http://127.0.0.1:{}/wallet/{}", r.rt.node.rpc_port(), name), Auth::UserPass("arca".into(), "arca".into()))
}

fn info_bond(r: &Running) -> Value {
	r.http.get("info").ok()["bond"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bond_is_posted_named_and_noticed() {
	let dir = std::env::temp_dir().join(format!("arca-bond-test-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let key_file = dir.join("withdraw.key");
	let _ = std::fs::remove_file(&key_file);
	let w = server::bond::new_key(&key_file).unwrap();
	assert!(server::bond::new_key(&key_file).unwrap_err().contains("exists"), "a key file is never overwritten");
	let max_exit = RelativeTime::from_units(338).unwrap();
	let units = min_notice_seconds(LIFETIME, max_exit).div_ceil(512) as u16;
	// The node with its wallet, which the harness turns off: the bond is
	// posted from a node wallet.
	let mut r = Running::start_on(&["-disablewallet=0"], |c, _| {
		c.assets[0].rate = Some(toml::from_str("source = \"node\"").unwrap());
		c.bond = Some(BondSection { withdraw_key: w.to_string(), notice_units: units, outpoint: None, notice: None });
	}).await;
	let x = r.x;

	// Named before it is posted.
	let b = info_bond(&r);
	println!("info.bond before the bond is posted: {}", b);
	assert_eq!(b["state"], "unposted");
	assert_eq!(b["operator"], r.http.get("info").ok()["operator"], "the bond binds the operator key S");
	assert_eq!(b["withdraw_key"], w.to_string());
	assert_eq!(b["notice_units"], json!(units));
	let policy = BondPolicy::new(r.chain, r.s.x_only_public_key().0, w, RelativeTime::from_units(units).unwrap()).unwrap();
	let hexs = |s: &Script| s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
	assert_eq!(b["script_pubkey"], hexs(&policy.script_pubkey()));
	assert_eq!(b["notice_script_pubkey"], hexs(&policy.notice_script_pubkey()));
	let addr = bond_address(&r.config).await.unwrap();
	println!("bond-address: {}", addr);
	assert_eq!(addr["script_pubkey"], b["script_pubkey"]);

	// Two node wallets: an operating one, and one named a treasury.
	for name in ["operating", "treasury-x"] {
		let _: Value = r.rt.client().call("createwallet", &[json!(name)]).unwrap();
	}
	let a: String = wallet_rpc(&r, "operating").call("getnewaddress", &[]).unwrap();
	let info: Value = wallet_rpc(&r, "operating").call("getaddressinfo", &[json!(a)]).unwrap();
	let spk = Script::from(Vec::<u8>::from_str_hex(info["scriptPubKey"].as_str().unwrap()));
	tokio::task::block_in_place(|| r.purse.pay(&r.rt, vec![explicit_txout(AssetAmount::new(x, 2 * BOND), spk)]));
	r.produce().await;

	// Posting: a service's wallet refused by name, before anything is sent.
	for refused in ["treasury-x", "sbtc-reserve", "seqpal-escrow", "faucet"] {
		let e = bond_post(&r.config, refused, x, BOND, None).await.unwrap_err();
		println!("bond-post from {}: {}", refused, e);
		assert!(e.to_string().contains("never posted from one"), "{}", e);
	}
	let posted = bond_post(&r.config, "operating", x, BOND, None).await.unwrap();
	println!("bond-post from operating: {}", posted);
	assert_eq!(posted["fee_asset"], x.to_string(), "the fee in the asset moved, never another");
	let outpoint = posted["outpoint"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Named in [bond]: bonded, final, valued at the operator's rate.
	r.config.bond.as_mut().unwrap().outpoint = Some(outpoint.clone());
	r.restart_server().await;
	r.synced().await;
	let b = info_bond(&r);
	println!("info.bond once posted: {}", b);
	assert_eq!(b["state"], "bonded");
	assert_eq!(b["outpoint"], json!(outpoint));
	assert_eq!(b["asset"], x.to_string());
	assert_eq!(b["value"], BOND.to_string());
	assert_eq!(b["final"], true, "certified, its anchor buried");
	assert_eq!(b["reference_value"], BOND.to_string(), "X at the node's 1:1 rate");

	// The notice, its fee from the operator's wallet.
	r.fund_wallet(50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let noticed = bond_notice(&r.config, &key_file).await.unwrap();
	println!("bond-notice: {}", noticed);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// A notice the configuration does not name reads as no bond.
	r.restart_server().await;
	let b = info_bond(&r);
	println!("info.bond with the notice unnamed: {}", b);
	assert_eq!(b["state"], "spent");
	r.config.bond.as_mut().unwrap().notice = Some(noticed["notice"].as_str().unwrap().into());
	r.restart_server().await;
	r.synced().await;
	let b = info_bond(&r);
	println!("info.bond in notice: {}", b);
	assert_eq!(b["state"], "noticed");
	assert_eq!(b["notice"], noticed["notice"]);
	let notice_op = server::bond::parse_outpoint(noticed["notice"].as_str().unwrap()).unwrap();
	let block: Value = r.rt.client().call("getrawtransaction", &[json!(notice_op.txid.to_string()), json!(true)]).unwrap();
	let h: Value = r.rt.client().call("getblockheader", &[block["blockhash"].clone()]).unwrap();
	let prev: Value = r.rt.client().call("getblockheader", &[h["previousblockhash"].clone()]).unwrap();
	assert_eq!(b["withdrawable_at"], json!(prev["mediantime"].as_u64().unwrap() + units as u64 * 512));
	// The second notice of a bond in notice, and its withdrawal before the
	// delay: refused.
	let e = bond_notice(&r.config, &key_file).await.unwrap_err();
	println!("bond-notice again: {}", e);
	assert!(e.to_string().contains("not bonded"), "{}", e);
	let to: String = wallet_rpc(&r, "operating").call("getnewaddress", &[]).unwrap();
	let e = bond_withdraw(&r.config, &key_file, &to).await.unwrap_err();
	println!("bond-withdraw before the delay: {}", e);
	assert!(e.to_string().contains("non-BIP68-final"), "{}", e);

	// A notice too short, and the withdrawal key the operator key: no start.
	let mut short = r.config.clone();
	short.bond.as_mut().unwrap().notice_units = units - 1;
	let e = Server::start(&short).await.err().expect("refused");
	println!("a notice one unit short: {}", e);
	assert!(e.to_string().contains("shorter than a coin's lifetime"), "{}", e);
	let mut same = r.config.clone();
	same.bond.as_mut().unwrap().withdraw_key = r.s.x_only_public_key().0.to_string();
	let e = Server::start(&same).await.err().expect("refused");
	println!("the withdrawal key S: {}", e);
	assert!(e.to_string().contains("operator key"), "{}", e);
	std::fs::remove_dir_all(&dir).unwrap();
}

trait FromStrHex {
	fn from_str_hex(s: &str) -> Vec<u8>;
}

impl FromStrHex for Vec<u8> {
	fn from_str_hex(s: &str) -> Vec<u8> {
		(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
	}
}
