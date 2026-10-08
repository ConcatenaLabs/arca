//! The gateway's nodes: one SeqLN node per asset served over Lightning,
//! checked, named in `info`, and refused with the reason when the asset is
//! not served, has no node, or its node is down or holds no channel in it.
//!
//! Needs what the other end-to-end tests need, and `LIGHTNINGD_EXEC`.

mod common;

use serde_json::Value;

use sequentia_ext::lightning::{BitcoinRegtest, LightningNode};
use server::lightning::LegRefusal;
use server::server::{AssetSection, BitcoinLightningSection, LegSection};

use common::lightning;
use common::running::{Running, MIN_LEAF};

fn info(r: &Running) -> Value {
	serde_json::from_str(minreq::get(format!("{}/v1/info", r.http.base)).send().unwrap().as_str().unwrap()).unwrap()
}

fn leg(info: &Value, asset: &elements::AssetId) -> Value {
	info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == asset.to_string()).unwrap()["lightning"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn each_asset_has_its_own_node_and_info_names_it() {
	let Some(lnd) = lightning::lightningd("each_asset_has_its_own_node_and_info_names_it") else { return };
	// The chain, its assets X and Y, and Z served with no node.
	let (mut dirs, mut ox, mut px, mut oy, mut py) = (vec![], None, None, None, None);
	let mut r = Running::start_seqln(|_, _| {}).await;
	let (x, y) = (r.x, r.y);
	let z = tokio::task::block_in_place(|| r.purse.issue(&r.rt, "asset Z", 100_000_000_000));
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	tokio::task::block_in_place(|| {
		let o_x = lightning::node(&r.rt, &mut r.purse, &lnd, "ox", true, x, 2_000_000_000);
		let p_x = lightning::node(&r.rt, &mut r.purse, &lnd, "px", true, x, 1_000_000_000);
		let o_y = lightning::node(&r.rt, &mut r.purse, &lnd, "oy", false, y, 2_000_000_000);
		let p_y = lightning::node(&r.rt, &mut r.purse, &lnd, "py", true, y, 1_000_000_000);
		o_x.open_channel(&r.rt, &p_x, x, 1_000_000_000, 100_000_000);
		o_y.open_channel(&r.rt, &p_y, y, 1_000_000_000, 100_000_000);
		dirs = vec![o_x.rpc_path(), o_y.rpc_path(), p_x.rpc_path()];
		ox = Some(o_x);
		px = Some(p_x);
		oy = Some(o_y);
		py = Some(p_y);
	});
	let (ox, px, mut oy, _py) = (ox.unwrap(), px.unwrap(), oy.unwrap(), py.unwrap());

	// The Bitcoin side, when a Bitcoin Core is named: the operator's node on
	// Bitcoin regtest with a channel to another.
	let btc = BitcoinRegtest::exe_from_env().map(|exe| tokio::task::block_in_place(|| {
		let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("btc{}", std::process::id()));
		let btc = BitcoinRegtest::start(&exe, &dir).unwrap();
		btc.mine(101);
		let ob = LightningNode::start_on_bitcoin(&btc, &lnd, &dir.with_extension("ob"), &[]).unwrap();
		let pb = LightningNode::start_on_bitcoin(&btc, &lnd, &dir.with_extension("pb"), &[]).unwrap();
		let addr = ob.ok("newaddr", serde_json::json!({ "addresstype": "bech32" }))["bech32"].as_str().unwrap().to_string();
		btc.cli(&["sendtoaddress", &addr, "1"]).unwrap();
		btc.mine(1);
		ob.wait_funds(1);
		ob.open_bitcoin_channel(&btc, &pb, 10_000_000, 1_000_000);
		(btc, ob, pb)
	}));
	if btc.is_none() {
		println!("the Bitcoin node: skipped, BITCOIND_EXEC names no bitcoind");
	}

	// X and Y each with its node, Z with none; checked every second.
	let mut config = r.config.clone();
	if let Some((_, ob, _)) = &btc {
		config.lightning.bitcoin = Some(BitcoinLightningSection { rpc: ob.rpc_path(), ark: Some("https://ark.example.org".into()) });
	}
	let mut sx = AssetSection::new(x, MIN_LEAF);
	sx.lightning = Some(LegSection { rpc: dirs[0].clone() });
	let mut sy = AssetSection::new(y, MIN_LEAF);
	sy.lightning = Some(LegSection { rpc: dirs[1].clone() });
	config.assets = vec![sx, sy, AssetSection::new(z, MIN_LEAF)];
	config.lightning.poll_seconds = 1;
	r.config = config;
	r.restart_server().await;
	let i = info(&r);
	println!("info, X's leg: {}", leg(&i, &x));
	println!("info, Y's leg: {}", leg(&i, &y));
	println!("info, Z's leg: {}", leg(&i, &z));
	println!("info, lightning: {}", i["lightning"]);
	assert_eq!(leg(&i, &x)["state"], "up");
	assert_eq!(leg(&i, &x)["node"], ox.id);
	assert_eq!(leg(&i, &x)["network"], "sequentia-regtest");
	assert_eq!(leg(&i, &x)["channels"], 1);
	assert_eq!(leg(&i, &x)["receives"], true);
	assert_eq!(leg(&i, &x)["spendable"].as_str().unwrap().parse::<u64>().unwrap() > 800_000_000, true);
	assert_eq!(leg(&i, &y)["state"], "up");
	assert_eq!(leg(&i, &y)["node"], oy.id);
	assert_eq!(leg(&i, &y)["receives"], false, "Y's node runs no hold-invoice plugin");
	assert!(leg(&i, &z).is_null(), "Z has no Lightning leg");
	match &btc {
		Some((_, ob, _)) => {
			let b = &i["lightning"]["bitcoin"];
			assert_eq!((b["node"]["state"].as_str(), b["node"]["node"].as_str()), (Some("up"), Some(ob.id.as_str())), "{}", b);
			assert_eq!((b["node"]["network"].as_str(), b["node"]["channels"].as_u64()), (Some("regtest"), Some(1)));
			assert_eq!(b["ark"], "https://ark.example.org");
			assert!(r.server.gateway.bitcoin_leg().is_ok());
		},
		None => assert!(i["lightning"]["bitcoin"].is_null()),
	}

	// The refusals every entry takes from the gateway.
	let g = &r.server.gateway;
	let served = |a| r.server.params.assets.contains(a);
	assert!(g.leg(&x, served(&x)).is_ok());
	let e = g.leg(&z, served(&z)).unwrap_err();
	println!("Z: {} [{}]", e, e.code());
	assert_eq!((e.clone(), e.code()), (LegRefusal::NoLeg(z), "no_lightning"));
	let w = elements::AssetId::from_byte_array([7; 32]);
	let e = g.leg(&w, served(&w)).unwrap_err();
	println!("W: {} [{}]", e, e.code());
	assert_eq!((e.clone(), e.code()), (LegRefusal::NotServed(w), "out_of_bounds"));
	let e = g.receiving_leg(&y, served(&y)).unwrap_err();
	println!("receiving in Y: {} [{}]", e, e.code());
	assert!(matches!(e, LegRefusal::NoHold(_)) && e.code() == "no_lightning");

	// Y's node stops: Y is down, with the reason, and refused.
	tokio::task::block_in_place(|| oy.stop());
	r.wait("Y's leg down", || leg(&info(&r), &y)["state"] == "down").await;
	let i = info(&r);
	println!("info, Y's leg with its node stopped: {}", leg(&i, &y));
	assert!(leg(&i, &y)["reason"].as_str().unwrap().contains("could not be reached"));
	let e = r.server.gateway.leg(&y, true).unwrap_err();
	println!("Y: {} [{}]", e, e.code());
	assert_eq!(e.code(), "lightning_unavailable");
	assert!(e.to_string().contains(&format!("the node of asset {}", y)), "{}", e);
	assert!(r.server.gateway.leg(&x, true).is_ok(), "X's leg is X's alone");

	// Y named a node that holds channels in X only, by a reload: down, and
	// the reason names the assets its channels are in.
	let mut config = r.config.clone();
	config.assets[1].lightning = Some(LegSection { rpc: dirs[2].clone() });
	let changed = r.server.reload(&config).await.unwrap();
	assert_eq!(changed.changed, vec![y]);
	let i = info(&r);
	println!("info, Y's leg on a node with channels in X only: {}", leg(&i, &y));
	assert_eq!(leg(&i, &y)["state"], "down");
	let why = leg(&i, &y)["reason"].as_str().unwrap().to_string();
	assert!(why.contains(&format!("no open channel in asset {}", y)) && why.contains(&format!("asset {} (1)", x)), "{}", why);
	drop(px);
	drop(btc);
}
