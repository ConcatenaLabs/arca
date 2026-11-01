//! Bitcoin ark watchtowers ([bark::btc_tower]) on a real Bitcoin Core regtest
//! chain. The ark's coins are made with the library and its server's key, as
//! the ark's server makes them: a round tree funded on chain, a board, and a
//! coin paid out of round through a checkpoint. Holding the server's key also
//! lets the test play a hostile operator and force its sweep into a block.
//!
//! The node runs with `-par=1`, so a block refused for a script names the
//! script failure, and `-blockmintxfee` at 5 sat/vB, so a child paying less
//! waits in the mempool as it would in a fee spike. The towers log in as a
//! user of their own limited to [TOWER_RPCS] (`-rpcwhitelist`), so every
//! call a tower makes is shown to need nothing more.
//!
//!     ARCA_TEST_BITCOIND=/path/to/bitcoind (version 29 or later) \
//!     cargo test -p arca-wallet --features onchain-bdk --test btc_tower_regtest -- --nocapture
//!
//! Without `ARCA_TEST_BITCOIND` the test says so and passes. It needs the
//! crate's `onchain-bdk` feature (`--features onchain-bdk`).

#![cfg(feature = "onchain-bdk")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, PublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{json, Value};

use ark::{musig, Vtxo, VtxoPolicy, VtxoRequest, SECP};
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::tree::signed::{expiry_clause, UnlockPreimage, UnlockHash, VtxoLeafSpec, VtxoTreeSpec};
use ark::vtxo::Full;
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::rpc::{Auth, Client, RpcApi};
use bitcoin_ext::TxStatus;

use bark::btc_tower::{self, tower::{Tower, TowerConfig}, TowerTerms};
use bark::chain::{ChainSource, ChainSourceSpec};
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bark::persist::sqlite::SqliteClient;

const EXIT_DELTA: u16 = 12;
const RATE: u64 = 10; // sat/vB the towers and payers use (the node's fallback)

/// The RPCs a tower's login needs, and no more: the node refuses any other
/// call by the towers' user.
pub const TOWER_RPCS: &str = "getblockchaininfo,getnetworkinfo,getindexinfo,getblockcount,getbestblockhash,getblockhash,\
getblockheader,getblock,getrawtransaction,gettxout,getrawmempool,getmempoolentry,estimatesmartfee,\
sendrawtransaction,submitpackage";
const TOWER_USER: &str = "tower";
const TOWER_PASSWORD: &str = "tower-regtest-login";

/// An `-rpcauth` line for `user` and `password`, as Bitcoin Core's rpcauth.py
/// makes it.
fn rpcauth(user: &str, password: &str) -> String {
	use bitcoin::hashes::{hmac, HashEngine};
	let salt = "0123456789abcdef0123456789abcdef";
	let mut e = hmac::HmacEngine::<sha256::Hash>::new(salt.as_bytes());
	e.input(password.as_bytes());
	let h = hmac::Hmac::<sha256::Hash>::from_engine(e);
	format!("{}:{}${}", user, salt, h)
}

struct Node {
	child: Child,
	rpc: Client,
	url: String,
	cookie: PathBuf,
	miner: Address,
}

impl Drop for Node {
	fn drop(&mut self) {
		let _ = self.rpc.call::<Value>("stop", &[]);
		for _ in 0..60 {
			if let Ok(Some(_)) = self.child.try_wait() { return; }
			std::thread::sleep(Duration::from_millis(500));
		}
		let _ = self.child.kill();
	}
}

fn key(tag: &str) -> Keypair {
	Keypair::from_seckey_slice(&SECP, sha256::Hash::hash(tag.as_bytes()).as_byte_array()).unwrap()
}

impl Node {
	fn start(bin: &str, dir: &Path, port: u16) -> Node {
		std::fs::create_dir_all(dir).unwrap();
		let child = Command::new(bin).args([
			"-regtest", &format!("-datadir={}", dir.display()), &format!("-rpcport={}", port),
			&format!("-port={}", port + 1), "-listen=0", "-txindex=1", "-par=1", "-server=1",
			"-fallbackfee=0.0001", "-blockmintxfee=0.00005", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
			"-printtoconsole=0", "-dnsseed=0",
			&format!("-rpcauth={}", rpcauth(TOWER_USER, TOWER_PASSWORD)),
			&format!("-rpcwhitelist={}:{}", TOWER_USER, TOWER_RPCS),
			// the cookie's user (the test, the holders) keeps every call
			"-rpcwhitelistdefault=0",
		]).spawn().expect("bitcoind");
		let cookie = dir.join("regtest/.cookie");
		let url = format!("http://127.0.0.1:{}", port);
		let mut tries = 0;
		let rpc = loop {
			std::thread::sleep(Duration::from_millis(500));
			if cookie.exists() {
				if let Ok(c) = Client::new(&url, Auth::CookieFile(cookie.clone())) {
					if c.call::<Value>("getblockcount", &[]).is_ok() { break c; }
				}
			}
			tries += 1;
			assert!(tries < 120, "bitcoind did not start");
		};
		rpc.call::<Value>("createwallet", &[json!("miner")]).unwrap();
		let miner = Address::from_str(&rpc.call::<String>("getnewaddress", &[]).unwrap()).unwrap().assume_checked();
		let n = Node { child, rpc, url, cookie, miner };
		n.mine(150);
		n
	}

	fn mine(&self, n: u64) {
		self.rpc.call::<Value>("generatetoaddress", &[json!(n), json!(self.miner.to_string())]).unwrap();
	}
	fn tip(&self) -> u32 { self.rpc.call::<u64>("getblockcount", &[]).unwrap() as u32 }

	/// Pays `amount` to `spk` from the miner and confirms it; the outpoint and the tx.
	fn fund(&self, spk: &ScriptBuf, amount: Amount) -> (OutPoint, Transaction) {
		let addr = Address::from_script(spk, Network::Regtest).unwrap();
		let txid: String = self.rpc.call("sendtoaddress", &[json!(addr.to_string()), json!(amount.to_btc())]).unwrap();
		self.mine(1);
		let tx = self.tx(&Txid::from_str(&txid).unwrap());
		let vout = tx.output.iter().position(|o| o.script_pubkey == *spk).unwrap();
		(OutPoint::new(tx.compute_txid(), vout as u32), tx)
	}

	fn tx(&self, txid: &Txid) -> Transaction {
		let hex: String = self.rpc.call("getrawtransaction", &[json!(txid.to_string())]).unwrap();
		deserialize_hex(&hex).unwrap()
	}

	fn confirmed(&self, txid: &Txid) -> bool {
		self.rpc.call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)])
			.map(|v| v["confirmations"].as_u64().unwrap_or(0) > 0).unwrap_or(false)
	}

	fn vsize(&self, txid: &Txid) -> u64 {
		self.rpc.call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap()["vsize"].as_u64().unwrap()
	}

	/// Mines one block holding exactly `txs`, as a miner who ignores relay
	/// policy would: the error, if the block is refused.
	fn force(&self, txs: &[&Transaction]) -> Result<(), String> {
		let raw: Vec<String> = txs.iter().map(|t| serialize_hex(*t)).collect();
		self.rpc.call::<Value>("generateblock", &[json!(self.miner.to_string()), json!(raw)])
			.map(|_| ()).map_err(|e| e.to_string())
	}

	fn spec(&self) -> ChainSourceSpec {
		ChainSourceSpec::Bitcoind { url: self.url.clone(), auth: Auth::CookieFile(self.cookie.clone()), zmq: None }
	}

	/// The towers' own login, limited to [TOWER_RPCS].
	fn tower_spec(&self) -> ChainSourceSpec {
		ChainSourceSpec::Bitcoind { url: self.url.clone(), auth: Auth::UserPass(TOWER_USER.into(), TOWER_PASSWORD.into()), zmq: None }
	}
}

/// A Bitcoin wallet of a phrase's BIP84 account: a holder's or an operator's
/// own coins, paying children as Bark's exit does.
struct Payer {
	w: OnchainWallet,
	chain: Arc<ChainSource>,
}

impl Payer {
	async fn new(node: &Node, dir: &Path, phrase: &bip39::Mnemonic) -> Payer {
		std::fs::create_dir_all(dir).unwrap();
		let db = Arc::new(SqliteClient::open(dir.join("w.sqlite")).unwrap());
		let w = OnchainWallet::load_or_create_bip84(Network::Regtest, phrase.to_seed(""), db).await.unwrap();
		let chain = Arc::new(ChainSource::new(node.spec(), Network::Regtest, Some(FeeRate::from_sat_per_vb(RATE).unwrap()),
			#[cfg(feature = "socks5-proxy")] None).await.unwrap());
		Payer { w, chain }
	}
	async fn sync(&mut self) { self.w.sync(&self.chain).await.unwrap(); }
	async fn first_address(&self) -> Address {
		self.w.inner.peek_address(bdk_wallet::KeychainKind::External, 0).address
	}
	/// Broadcasts `tx` with a child paying `rate` sat/vB for the package.
	async fn push(&mut self, tx: &Transaction, rate: u64) -> Txid {
		self.sync().await;
		let child = self.w.make_signed_p2a_cpfp(tx, MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(rate).unwrap())).await.unwrap();
		self.chain.broadcast_package(&[tx, &child]).await.unwrap();
		self.w.store_signed_p2a_cpfp(&child).await.unwrap();
		child.compute_txid()
	}
}

fn phrase(tag: &str) -> bip39::Mnemonic {
	bip39::Mnemonic::from_entropy(&sha256::Hash::hash(tag.as_bytes()).as_byte_array()[..16]).unwrap()
}

/// A round: a tree of `amounts` for `users`, its funding output confirmed on
/// chain, signed by the users' cosign key and the server's. Returns the
/// coins, the round tx and a sweep the server can sign of the tree's root.
struct Round {
	vtxos: Vec<Vtxo<Full>>,
	root: OutPoint,
	root_value: Amount,
	root_spk: ScriptBuf,
	root_cb: bitcoin::taproot::ControlBlock,
	expiry: u32,
}

fn make_round(node: &Node, server: &Keypair, users: &[(&Keypair, Amount)], expiry: u32, tag: &str) -> Round {
	let user_cosign = key(&format!("{}-user-cosign", tag));
	let server_cosign = key(&format!("{}-server-cosign", tag));
	let preimage: UnlockPreimage = sha256::Hash::hash(format!("{}-unlock", tag).as_bytes()).to_byte_array().into();
	let unlock_hash = UnlockHash::hash(&preimage);
	let reqs = users.iter().map(|(k, a)| VtxoLeafSpec {
		vtxo: VtxoRequest { amount: *a, policy: VtxoPolicy::new_pubkey(k.public_key()) },
		cosign_pubkey: None,
		unlock_hash,
	}).collect::<Vec<_>>();
	let spec = VtxoTreeSpec::new(reqs, server.public_key(), expiry, EXIT_DELTA,
		vec![user_cosign.public_key(), server_cosign.public_key()]);
	let txout = spec.funding_tx_txout();
	let root_tap = spec.internal_taproot(spec.funding_tx_cosign_pubkey());
	let leaf = expiry_clause(server.public_key(), expiry);
	let root_cb = root_tap.control_block(&(leaf, LeafVersion::TapScript)).unwrap();
	let (root, round_tx) = node.fund(&txout.script_pubkey, txout.value);
	let unsigned = spec.into_unsigned_tree(root);
	let nonces = |k: &Keypair| -> (Vec<_>, Vec<_>) {
		unsigned.internal_sighashes.iter().map(|sh| musig::nonce_pair_with_msg(k, &sh.to_byte_array())).unzip()
	};
	let (us, up) = nonces(&user_cosign);
	let (ss, sp) = nonces(&server_cosign);
	let agg = up.iter().zip(&sp).map(|(u, s)| musig::AggregatedNonce::new(&[u, s])).collect::<Vec<_>>();
	let usig = unsigned.cosign_tree(&agg, &user_cosign, us);
	let ssig = unsigned.cosign_tree(&agg, &server_cosign, ss);
	let sigs = unsigned.combine_partial_signatures(&agg, &Default::default(), &[&usig, &ssig]).unwrap();
	let tree = unsigned.into_signed_tree(sigs).into_cached_tree();
	let mut vtxos = tree.output_vtxos().collect::<Vec<_>>();
	for (v, (k, _)) in vtxos.iter_mut().zip(users) {
		v.finalize_hark_leaf(k, server, &round_tx, preimage);
		v.validate(&round_tx).unwrap();
	}
	Round { vtxos, root, root_value: txout.value, root_spk: txout.script_pubkey, root_cb, expiry }
}

/// The operator's sweep of a round's root, valid from its expiry.
fn sweep(r: &Round, server: &Keypair, to: &Address) -> Transaction {
	let script = expiry_clause(server.public_key(), r.expiry);
	let mut tx = Transaction {
		version: Version::TWO,
		lock_time: absolute::LockTime::from_height(r.expiry).unwrap(),
		input: vec![TxIn { previous_output: r.root, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new() }],
		output: vec![TxOut { value: r.root_value - Amount::from_sat(2_000), script_pubkey: to.script_pubkey() }],
	};
	let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
	let prev = [TxOut { value: r.root_value, script_pubkey: r.root_spk.clone() }];
	let sh = SighashCache::new(&tx).taproot_script_spend_signature_hash(0, &Prevouts::All(&prev), leaf, TapSighashType::Default).unwrap();
	let sig = SECP.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), server);
	tx.input[0].witness = Witness::from_slice(&[&sig[..], script.as_bytes(), &r.root_cb.serialize()[..]]);
	tx
}

/// Pays `to` out of round from `from` (held by `from_key`) through a
/// checkpoint, with the change back to `from_key`: the receiver's coin.
fn pay_out_of_round(from: &Vtxo<Full>, from_key: &Keypair, server: &Keypair, to: &PublicKey, amount: Amount) -> (Vtxo<Full>, Vtxo<Full>) {
	let dests = vec![
		ArkoorDestination { total_amount: amount, policy: VtxoPolicy::new_pubkey(*to) },
		ArkoorDestination { total_amount: from.amount() - amount, policy: VtxoPolicy::new_pubkey(from_key.public_key()) },
	];
	let b = ArkoorPackageBuilder::new_with_checkpoints([from.clone()], dests).unwrap()
		.generate_user_nonces(&[*from_key]).unwrap();
	let cosign = ArkoorPackageBuilder::from_cosign_request(b.cosign_request()).unwrap()
		.server_cosign(server).unwrap().cosign_response();
	let [paid, change]: [Vtxo<Full>; 2] = b.user_cosign(&[*from_key], cosign).unwrap().build_signed_vtxos().try_into().unwrap();
	(paid, change)
}

async fn open_tower(node: &Node, dir: &Path, arks: Vec<PublicKey>) -> Tower {
	open_tower_with(node, dir, arks, 5, btc_tower::RESCUE_MARGIN).await
}

async fn open_tower_with(node: &Node, dir: &Path, arks: Vec<PublicKey>, min_rate: u64, margin: u32) -> Tower {
	Tower::open(dir, TowerConfig {
		network: Network::Regtest,
		chain: node.tower_spec(),
		min_rate: FeeRate::from_sat_per_vb(min_rate).unwrap(),
		fallback_rate: Some(FeeRate::from_sat_per_vb(RATE).unwrap()),
		arks,
		margin,
	}).await.unwrap()
}

/// Funds a tower's own coins with `n` coins of 0.01 BTC.
async fn fund_tower(node: &Node, t: &mut Tower, n: usize) {
	fund_tower_with(node, t, n, Amount::from_sat(1_000_000)).await
}

/// Funds a tower's own coins with `n` coins of `each`, and lets it see them.
async fn fund_tower_with(node: &Node, t: &mut Tower, n: usize, each: Amount) {
	for _ in 0..n {
		let a = t.funding_address().await.unwrap();
		node.rpc.call::<Value>("sendtoaddress", &[json!(a.to_string()), json!(each.to_btc())]).unwrap();
	}
	node.mine(1);
	t.pass().await.unwrap();
}

/// Mines one block at a time, running the towers' passes after each, until
/// `done` or `max` blocks.
async fn run(node: &Node, towers: &mut [&mut Tower], max: u32, mut done: impl FnMut(&Node) -> bool) -> u32 {
	for i in 0..max {
		for t in towers.iter_mut() {
			let v = t.pass().await.unwrap();
			if v["acted"].as_array().is_some_and(|a| !a.is_empty()) { println!("  tower @{}: {}", v["tip"], v["acted"]); }
		}
		if done(node) { return i; }
		node.mine(1);
	}
	panic!("not done within {} blocks", max);
}

fn deposit_for(t: &TowerTerms, v: &Vtxo<Full>, k: &Keypair, holder: &Address) -> (Value, Txid) {
	btc_tower::make_deposit(v, k, holder, t, FeeRate::from_sat_per_vb(RATE).unwrap()).unwrap()
}

fn expect_err(r: Result<(), String>, want: &str, what: &str) {
	match r {
		Ok(()) => panic!("{}: the block was ACCEPTED", what),
		Err(e) => {
			println!("  NEG {}: {}", what, e);
			assert!(e.contains(want), "{}: expected '{}', got {}", what, want, e);
		},
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn bitcoin_ark_towers() {
	let Ok(bin) = std::env::var("ARCA_TEST_BITCOIND") else {
		println!("ARCA_TEST_BITCOIND is not set: the regtest proof did not run");
		return;
	};
	let base = PathBuf::from(std::env::var("ARCA_TEST_DIR").unwrap_or_else(|_| std::env::temp_dir().join("btc-tower-regtest").display().to_string()));
	let _ = std::fs::remove_dir_all(&base);
	let port: u16 = std::env::var("ARCA_TEST_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(28710);
	let node = Node::start(&bin, &base.join("btc"), port);

	// Two arks, A and B; each operator's tower watches the other's users.
	let server_a = key("server-a");
	let server_b = key("server-b");
	let mut tower_a = open_tower(&node, &base.join("tower-a"), vec![server_b.public_key()]).await; // operator A's: B's users
	let mut tower_b = open_tower(&node, &base.join("tower-b"), vec![server_a.public_key()]).await; // operator B's: A's users
	fund_tower(&node, &mut tower_a, 6).await;
	fund_tower(&node, &mut tower_b, 6).await;
	let _terms_a = TowerTerms::from_info(&tower_a.info().await).unwrap();
	let terms_b = TowerTerms::from_info(&tower_b.info().await).unwrap();
	println!("tower A info: {}", tower_a.info().await);

	// Holders: each with a phrase, its claims paid to the phrase's first BIP84 address.
	let h1_phrase = phrase("holder-1");
	let h1_dir = base.join("h1");
	let h1_addr = Payer::new(&node, &h1_dir, &h1_phrase).await.first_address().await;
	let h1 = key("h1");
	let s2 = key("sender-2");
	let r2 = key("receiver-2");
	let r2_addr = Payer::new(&node, &base.join("r2"), &phrase("receiver-2")).await.first_address().await;
	let h3 = key("h3");
	let r3 = key("r3");
	let h4 = key("h4");
	let h4_addr = Payer::new(&node, &base.join("h4"), &phrase("holder-4")).await.first_address().await;
	let h5 = key("h5");
	let h6 = key("h6");

	let tip = node.tip();
	let expiry = tip + 220;
	println!("tip {}, expiry {}, towers act from {}", tip, expiry, expiry - btc_tower::RESCUE_MARGIN);
	// Ark A's round: six holders, 1,000,000 to 1,500,000 sat each.
	let round = make_round(&node, &server_a, &[
		(&h1, Amount::from_sat(1_000_000)), (&s2, Amount::from_sat(1_500_000)), (&h3, Amount::from_sat(1_200_000)),
		(&h4, Amount::from_sat(1_100_000)), (&h5, Amount::from_sat(1_300_000)), (&h6, Amount::from_sat(1_400_000)),
	], expiry, "round-a");
	let [c1, c2, c3, c4, c5, _c6]: [Vtxo<Full>; 6] = round.vtxos.clone().try_into().unwrap();
	println!("round root {}; coin 1 exits in {} transactions; rescue estimate {} vB",
		round.root, c1.transactions().count(), btc_tower::rescue_vbytes(&c1).unwrap());
	// A second round of ark A whose holder deposits nowhere: the operator's sweep, the control.
	let lonely = key("lonely");
	let round2 = make_round(&node, &server_a, &[(&lonely, Amount::from_sat(900_000)), (&key("x"), Amount::from_sat(900_000))], expiry, "round-a2");

	// --- deposits, and what a tower refuses
	println!("== deposits");
	let (d1b, claim1b) = deposit_for(&terms_b, &c1, &h1, &h1_addr);
	println!("  h1 at tower B: {}", tower_b.deposit(&d1b).await.unwrap());
	let r = tower_a.deposit(&deposit_for(&terms_b, &c1, &h1, &h1_addr).0).await;
	println!("  NEG ark A's coin at tower A (watches B only): {}", r.as_ref().unwrap_err());
	assert!(r.unwrap_err().to_string().contains("does not watch"));
	let mut bad = d1b.clone();
	let mut ctx: Transaction = deserialize_hex(d1b["claim"].as_str().unwrap()).unwrap();
	ctx.output[0].value -= Amount::from_sat(1);
	ctx.output[1].value += Amount::from_sat(1);
	bad["claim"] = json!(serialize_hex(&ctx));
	let r = tower_b.deposit(&bad).await;
	println!("  NEG a claim with an amount moved: {}", r.as_ref().unwrap_err());
	assert!(r.unwrap_err().to_string().contains("signature"));
	let cheap = btc_tower::TowerTerms { min_rate: FeeRate::from_sat_per_vb(1).unwrap(), rate: FeeRate::from_sat_per_vb(1).unwrap(), ..terms_b.clone() };
	let (lowfee, _) = btc_tower::make_deposit(&c1, &h1, &h1_addr, &cheap, FeeRate::from_sat_per_vb(1).unwrap()).unwrap();
	let r = tower_b.deposit(&lowfee).await;
	println!("  NEG a rescue fee below the tower's rate: {}", r.as_ref().unwrap_err());
	assert!(r.unwrap_err().to_string().contains("costs"));
	// a withdrawal by another key is refused; the coin's own key drops it
	let (d6, claim6) = deposit_for(&terms_b, &_c6, &h6, &h1_addr);
	tower_b.deposit(&d6).await.unwrap();
	let forged = json!({"claim_txid": claim6.to_string(), "sig": btc_tower::withdrawal(Network::Regtest, &c1, &claim1b, &h1).unwrap()["sig"]});
	let r = tower_b.withdraw(&forged);
	println!("  NEG a withdrawal signed for another claim: {}", r.as_ref().unwrap_err());
	assert!(r.is_err());
	println!("  h6 withdraws: {}", tower_b.withdraw(&btc_tower::withdrawal(Network::Regtest, &_c6, &claim6, &h6).unwrap()).unwrap());

	// h3 deposits, then pays r3 out of round and forgets to withdraw: a stale deposit.
	tower_b.deposit(&deposit_for(&terms_b, &c3, &h3, &h1_addr).0).await.unwrap();
	let (c3_paid, _c3_change) = pay_out_of_round(&c3, &h3, &server_a, &r3.public_key(), Amount::from_sat(700_000));

	// s2 pays r2 out of round; r2 deposits the received coin with both towers.
	let (c2_paid, _c2_change) = pay_out_of_round(&c2, &s2, &server_a, &r2.public_key(), Amount::from_sat(900_000));
	println!("  r2's coin: {} transactions, arkoor levels {:?}", c2_paid.transactions().count(), c2_paid.arkoor_levels());
	let (d2, claim2) = deposit_for(&terms_b, &c2_paid, &r2, &r2_addr);
	println!("  r2 at tower B: {}", tower_b.deposit(&d2).await.unwrap());

	// h4 deposits with tower B and starts its own exit with a child too cheap to be mined.
	let (d4, claim4) = deposit_for(&terms_b, &c4, &h4, &h4_addr);
	tower_b.deposit(&d4).await.unwrap();

	// --- B6: s2 takes its earlier coin home while the operator is away
	println!("== a sender's exit answered (B6)");
	let mut s2_wallet = Payer::new(&node, &base.join("s2"), &phrase("sender-2")).await;
	let a = s2_wallet.first_address().await;
	node.rpc.call::<Value>("sendtoaddress", &[json!(a.to_string()), json!(0.02)]).unwrap();
	node.rpc.call::<Value>("sendtoaddress", &[json!(a.to_string()), json!(0.02)]).unwrap();
	node.mine(1);
	let s2_txs: Vec<Transaction> = c2.transactions().map(|i| i.tx).collect();
	for (i, t) in s2_txs.iter().enumerate() {
		if !node.confirmed(&t.compute_txid()) {
			let c = s2_wallet.push(t, RATE).await;
			println!("  s2 broadcasts its level {} {} (child {})", i, t.compute_txid(), c);
		}
		node.mine(1);
		// the towers run between the sender's blocks
		let v = tower_b.pass().await.unwrap();
		if v["acted"].as_array().is_some_and(|a| !a.is_empty()) { println!("  tower @{}: {}", v["tip"], v["acted"]); }
	}
	let s2_point = c2.point();
	println!("  s2's coin {} is on chain; its exit clause opens in {} blocks", s2_point, EXIT_DELTA);
	let r2_txs: Vec<Transaction> = c2_paid.transactions().map(|i| i.tx).collect();
	let checkpoint = &r2_txs[c2_paid.arkoor_levels()[0]];
	let n = run(&node, &mut [&mut tower_b], EXIT_DELTA as u32 - 1, |n| n.confirmed(&checkpoint.compute_txid())).await;
	println!("  tower B confirmed r2's checkpoint {} within {} blocks of s2's coin", checkpoint.compute_txid(), n + 1);
	// s2's own claim of its old coin, forced into a block once its delta has passed: already spent
	let s2_claim = {
		let fake = btc_tower::TowerTerms { payout: a.clone(), ..terms_b.clone() };
		let fee = btc_tower::rescue_fee(&c2, &fake, FeeRate::from_sat_per_vb(1).unwrap()).unwrap();
		let mut t = btc_tower::claim_template(&c2, &a, &a, fee).unwrap();
		btc_tower::sign_claim(&c2, &mut t, &s2).unwrap();
		t
	};
	node.mine(EXIT_DELTA as u64);
	expect_err(node.force(&[&s2_claim]), "bad-txns-inputs-missingorspent", "the sender claims its old coin after the tower answered");

	// --- h4's stuck exit
	println!("== a stuck exit rescued by CPFP");
	let mut h4_wallet = Payer::new(&node, &base.join("h4"), &phrase("holder-4")).await;
	node.rpc.call::<Value>("sendtoaddress", &[json!(h4_wallet.first_address().await.to_string()), json!(0.01)]).unwrap();
	node.mine(1);

	// operator A's watchman: it answers an old coin brought on chain with what its holder signed
	let mut operator_a = Payer::new(&node, &base.join("op-a"), &phrase("operator-a")).await;
	let oa = operator_a.first_address().await;
	node.rpc.call::<Value>("sendtoaddress", &[json!(oa.to_string()), json!(0.02)]).unwrap();
	node.mine(1);
	let c3_txs: Vec<Transaction> = c3_paid.transactions().map(|i| i.tx).collect();
	let c3_checkpoint = c3_txs[c3_paid.arkoor_levels()[0]].clone();

	// --- run to the towers' margin: every coin still on deposit is rescued
	println!("== dormant holders: mining to expiry − {}", btc_tower::RESCUE_MARGIN);
	let h4_txs: Vec<Transaction> = c4.transactions().map(|i| i.tx).collect();
	let first4 = h4_txs.iter().position(|t| !node.confirmed(&t.compute_txid())).unwrap();
	let start = expiry - btc_tower::RESCUE_MARGIN - 4;
	while node.tip() < start { node.mine((start - node.tip()) as u64); }
	let stuck_child = h4_wallet.push(&h4_txs[first4], 2).await;
	println!("  h4 broadcast its level {} with a child at 2 sat/vB: {} (below the block minimum of 5)", first4, stuck_child);

	// h1's coin: hold back the claim to force tampered copies into blocks.
	let before_b = tower_b.balance().await;
	let claim1: Transaction = deserialize_hex(d1b["claim"].as_str().unwrap()).unwrap();
	let c1_point = c1.point();
	let h4_level = h4_txs[first4].compute_txid();
	run(&node, &mut [&mut tower_b], 60, |n| n.confirmed(&c1_point.txid) && n.confirmed(&h4_level)).await;
	println!("  coin 1's output {} is on chain at tip {} (expiry {})", c1_point, node.tip(), expiry);
	// h3's old coin came on chain with it; the watchman answers within its exit delta
	assert!(node.confirmed(&c3.point().txid), "h3's old coin is not on chain yet");
	let c = operator_a.push(&c3_checkpoint, RATE).await;
	println!("  operator A answers h3's old coin {} with the checkpoint h3 signed: {} (child {})", c3.point(), c3_checkpoint.compute_txid(), c);
	node.mine(1);
	assert!(node.confirmed(&c3_checkpoint.compute_txid()));
	assert!(node.confirmed(&h4_txs[first4].compute_txid()), "h4's stuck level was not rescued: {}", tower_b.deposits());
	assert!(!node.rpc.call::<Value>("getrawtransaction", &[json!(stuck_child.to_string()), json!(true)]).is_ok_and(|v| v["confirmations"].as_u64().unwrap_or(0) > 0),
		"h4's cheap child confirmed: it was not stuck");
	println!("  h4's level {} confirmed with the tower's replacement child; h4's own 2 sat/vB child never confirmed", first4);

	println!("== the claim, any output changed, forced into blocks");
	expect_err(node.force(&[&claim1]), "non-BIP68-final", "the true claim before the exit delta");
	let tamper = |f: &dyn Fn(&mut Transaction)| { let mut t = claim1.clone(); f(&mut t); t };
	let thief = node.miner.script_pubkey();
	let cases: Vec<(&str, Transaction)> = vec![
		("holder's amount −1 sat, tower's +1", tamper(&|t| { t.output[0].value -= Amount::ONE_SAT; t.output[1].value += Amount::ONE_SAT; })),
		("holder's output to another address", tamper(&|t| { t.output[0].script_pubkey = thief.clone(); })),
		("tower's output to another address", tamper(&|t| { t.output[1].script_pubkey = thief.clone(); })),
		("tower's output dropped, its value to the holder", tamper(&|t| { let v = t.output[1].value; t.output.remove(1); t.output[0].value += v; })),
		("anchor dropped", tamper(&|t| { t.output.pop(); })),
		("an output added (1,000 sat from the holder's)", tamper(&|t| { t.output[0].value -= Amount::from_sat(1000); t.output.push(TxOut { value: Amount::from_sat(1000), script_pubkey: thief.clone() }); })),
		("version 2", tamper(&|t| { t.version = Version::TWO; })),
		("lock time set", tamper(&|t| { t.lock_time = absolute::LockTime::from_height(1).unwrap(); })),
	];
	node.mine(EXIT_DELTA as u64);
	for (what, t) in &cases {
		expect_err(node.force(&[t]), "Invalid Schnorr signature", what);
	}
	let mut seq = claim1.clone();
	seq.input[0].sequence = Sequence::from_height(EXIT_DELTA + 1);
	expect_err(node.force(&[&seq]), "Invalid Schnorr signature", "a longer sequence");
	let mut short = claim1.clone();
	short.input[0].sequence = Sequence::from_height(1);
	expect_err(node.force(&[&short]), "Locktime requirement not satisfied", "a shorter sequence (the script's CSV fails before its signature check)");

	// The towers finish: h1's claim by tower B, r2's claim, h3's stale deposit, h4.
	println!("== the towers finish");
	// h3's stale deposit: tower B walks h3's old coin; the operator answers with the checkpoint h3 signed.
	let mut ticks = 0;
	loop {
		let v = tower_b.pass().await.unwrap();
		if v["acted"].as_array().is_some_and(|a| !a.is_empty()) { println!("  tower B @{}: {}", v["tip"], v["acted"]); }
		let ds = tower_b.deposits();
		let all = ds.as_array().unwrap().iter().all(|d| ["claimed", "taken"].contains(&d["state"].as_str().unwrap()));
		if all { break; }
		ticks += 1;
		assert!(ticks < 80, "towers did not finish: {}", ds);
		node.mine(1);
	}
	let after_b = tower_b.balance().await;
	println!("  tower B deposits: {}", serde_json::to_string_pretty(&tower_b.deposits()).unwrap());
	let ds = tower_b.deposits();
	let state = |t: &Txid| ds.as_array().unwrap().iter().find(|d| d["claim_txid"] == json!(t.to_string())).unwrap()["state"].as_str().unwrap().to_string();
	assert_eq!(state(&claim1b), "claimed");
	assert_eq!(state(&claim2), "claimed");
	assert_eq!(state(&claim4), "claimed");
	let h3_state = ds.as_array().unwrap().iter().find(|d| d["vtxo"] == json!(c3.id().to_string())).unwrap().clone();
	assert_eq!(h3_state["state"], json!("taken"));
	println!("  tower B's own coins: {} before the rescues, {} after (its rescue fees included)", before_b, after_b);

	// What the stale deposit cost: the children tower B paid for h3's old coin, and nothing of h3's.
	let h3_claim = ds.as_array().unwrap().iter().find(|d| d["vtxo"] == json!(c3.id().to_string())).unwrap()["claim_txid"].clone();
	assert!(!h3_state["broadcast"].as_array().unwrap().contains(&h3_claim), "h3's stale claim was broadcast");
	let mut stale_fees = 0u64;
	for t in h3_state["broadcast"].as_array().unwrap() {
		match node.rpc.call::<Value>("getrawtransaction", &[json!(t.as_str().unwrap()), json!(2)]) {
			Ok(v) => stale_fees += (v["fee"].as_f64().unwrap_or(0.0) * 1e8).round() as u64,
			Err(_) => println!("  (h3's {} is not on chain: replaced)", t),
		}
	}
	println!("  h3's stale deposit cost tower B {} sat in fees ({} transactions) and paid it nothing; {}",
		stale_fees, h3_state["broadcast"].as_array().unwrap().len(), h3_state["note"]);
	assert!(stale_fees > 0);
	assert!(node.confirmed(&c3_checkpoint.compute_txid()), "h3's checkpoint is on chain: r3's coin stands");

	// Measured sizes of coin 1's rescue.
	let mut vb = 0;
	let d1 = ds.as_array().unwrap().iter().find(|d| d["claim_txid"] == json!(claim1b.to_string())).unwrap();
	for t in d1["broadcast"].as_array().unwrap() {
		let txid = Txid::from_str(t.as_str().unwrap()).unwrap();
		if node.confirmed(&txid) { vb += node.vsize(&txid); } else { println!("  ({} is not on chain: replaced)", txid); }
	}
	println!("  coin 1's rescue as broadcast by tower B: {} vB in {} transactions (estimate {} vB)",
		vb, d1["broadcast"].as_array().unwrap().len(), btc_tower::rescue_vbytes(&c1).unwrap());

	// Measured sizes of every transaction of one coin's path, its claim and the claim's child.
	let mut sizes = vec![];
	for t in c1.transactions().map(|i| i.tx) { sizes.push(format!("{}", node.vsize(&t.compute_txid()))); }
	let claim_child = d1["broadcast"].as_array().unwrap().iter().map(|t| Txid::from_str(t.as_str().unwrap()).unwrap())
		.filter(|t| *t != claim1b).last().unwrap();
	println!("  measured vB: coin 1's exit transactions [{}], its claim {}, the claim's child {}; a level's child {}",
		sizes.join(", "), node.vsize(&claim1b), node.vsize(&claim_child),
		node.vsize(&Txid::from_str(d1["broadcast"][1].as_str().unwrap()).unwrap()));

	// The holders' addresses hold their coins less the rescue fee.
	let claim_tx = node.tx(&claim1b);
	assert_eq!(claim_tx.output[0].script_pubkey, h1_addr.script_pubkey());
	println!("  h1's claim {} pays {} to h1's own address {}", claim1b, claim_tx.output[0].value, h1_addr);

	// --- h5, with no tower, exits alone before expiry and claims with its own key
	println!("== a solo exit that beats a hostile operator");
	let mut h5_wallet = Payer::new(&node, &base.join("h5"), &phrase("holder-5")).await;
	let h5_addr = h5_wallet.first_address().await;
	node.rpc.call::<Value>("sendtoaddress", &[json!(h5_addr.to_string()), json!(0.02)]).unwrap();
	node.rpc.call::<Value>("sendtoaddress", &[json!(h5_addr.to_string()), json!(0.02)]).unwrap();
	node.mine(1);
	for t in c5.transactions().map(|i| i.tx) {
		if !node.confirmed(&t.compute_txid()) {
			let c = h5_wallet.push(&t, RATE).await;
			println!("  h5 broadcasts {} (child {})", t.compute_txid(), c);
			node.mine(1);
		}
	}
	node.mine(EXIT_DELTA as u64);
	let mut own = btc_tower::claim_template(&c5, &h5_addr, &h5_addr, Amount::from_sat(1_000)).unwrap();
	btc_tower::sign_claim(&c5, &mut own, &h5).unwrap();
	h5_wallet.push(&own, RATE).await;
	node.mine(1);
	assert!(node.confirmed(&own.compute_txid()));
	println!("  h5 claimed its coin {} at tip {}, before expiry {}", own.compute_txid(), node.tip(), expiry);

	// --- the hostile operator at expiry
	println!("== the operator sweeps at expiry");
	while node.tip() + 1 < expiry { node.mine((expiry - 1 - node.tip()) as u64); }
	let op = Address::from_str(&node.rpc.call::<String>("getnewaddress", &[]).unwrap()).unwrap().assume_checked();
	expect_err(node.force(&[&sweep(&round, &server_a, &op)]), "non-final", "the sweep one block before expiry");
	node.mine(1);
	expect_err(node.force(&[&sweep(&round, &server_a, &op)]), "bad-txns-inputs-missingorspent", "the sweep of the rescued round");
	node.force(&[&sweep(&round2, &server_a, &op)]).expect("the control: the operator sweeps a round no tower watched");
	println!("  CONTROL the sweep of round 2 (no deposit) was mined: its holder's 900,000 sat are the operator's");


	// --- a restore from the phrase finds the claimed coin, and the holder spends it
	println!("== restore from the phrase");
	let restored = base.join("h1-restored");
	let mut w = Payer::new(&node, &restored, &h1_phrase).await;
	w.w.initial_wallet_scan(&w.chain, None).await.unwrap();
	let bal = w.w.balance().total();
	println!("  a wallet restored from h1's phrase finds {} (its claim paid {})", bal, claim_tx.output[0].value);
	assert_eq!(bal, claim_tx.output[0].value);
	let back = w.w.send(&w.chain, node.miner.clone(), Amount::from_sat(500_000), FeeRate::from_sat_per_vb(RATE).unwrap()).await.unwrap();
	node.mine(1);
	assert!(node.confirmed(&back));
	println!("  and spends 500,000 of it: {}", back);

	let _ = (tower_a, h4_addr, r2_addr, TxStatus::NotFound, claim2, claim4, _c3_change, _c2_change);
	println!("DONE");
}

/// The wallet's side: a Bark wallet holding coins of an ark plans its
/// deposits, the tower takes them, and a coin the wallet stops holding in the
/// ark (here, one it starts to exit) gets its deposit withdrawn.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_plans_its_deposits() {
	let Ok(bin) = std::env::var("ARCA_TEST_BITCOIND") else {
		println!("ARCA_TEST_BITCOIND is not set: the regtest proof did not run");
		return;
	};
	let base = PathBuf::from(std::env::var("ARCA_TEST_DIR").unwrap_or_else(|_| std::env::temp_dir().join("btc-tower-regtest").display().to_string())).join("wallet");
	let _ = std::fs::remove_dir_all(&base);
	let port: u16 = std::env::var("ARCA_TEST_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(28710) + 20;
	let node = Node::start(&bin, &base.join("btc"), port);
	let server = key("server-w");
	let mut tower = open_tower(&node, &base.join("tower"), vec![server.public_key()]).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();
	let plan0 = {
		// unfunded, it can pay for nothing: the plan sends it nothing
		let (wallet, _) = open_wallet(&node, &base.join("bark0"), "bark-wallet-0").await;
		let k = futures_keys(&wallet).await;
		let r = make_round(&node, &server, &[(&k[0], Amount::from_sat(1_000_000)), (&k[1], Amount::from_sat(30_000))], node.tip() + 250, "round-w0");
		wallet.import_vtxos(&r.vtxos, bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
		let holder = Payer::new(&node, &base.join("holder0"), &phrase("bark-wallet-0")).await.first_address().await;
		wallet.btc_tower_plan(&holder, &[("http://tower.example/btc-tower".to_string(), terms.clone())], &[],
			FeeRate::from_sat_per_vb(RATE).unwrap()).await.unwrap()
	};
	println!("  an unfunded tower (capacity {}): deposit {}, uncovered {}", terms.capacity, plan0["deposit"], plan0["uncovered"]);
	assert!(plan0["deposit"].as_array().unwrap().is_empty());
	assert!(plan0["uncovered"][0]["reason"].as_str().unwrap().contains("can pay for"), "{}", plan0);
	fund_tower(&node, &mut tower, 4).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();

	// A Bark wallet whose ark is unreachable: it holds the coins below.
	let m = phrase("bark-wallet");
	let seed = bark::WalletSeed::new_from_mnemonic(Network::Regtest, &m);
	let mut cfg = bark::Config::network_default(Network::Regtest);
	cfg.server_address = "http://127.0.0.1:9".into();
	cfg.bitcoind_address = Some(node.url.clone());
	cfg.bitcoind_cookiefile = Some(node.cookie.clone());
	cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb(RATE).unwrap());
	let mut open = bark::OpenWalletArgs::default();
	open.run_daemon = false;
	open.datadir = Some(base.join("bark"));
	open.create_without_server = true;
	let wallet = bark::Wallet::open(Network::Regtest, seed, cfg, open).await.unwrap();
	let k: Vec<Keypair> = futures_keys(&wallet).await;
	let expiry = node.tip() + 250;
	let round = make_round(&node, &server, &[(&k[0], Amount::from_sat(1_000_000)), (&k[1], Amount::from_sat(1_200_000)),
		(&k[2], Amount::from_sat(20_000))], expiry, "round-w");
	let ids = wallet.import_vtxos(&round.vtxos, bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
	println!("the wallet imported {} coins", ids.len());
	let holder = Payer::new(&node, &base.join("holder"), &m).await.first_address().await;
	let url = "http://tower.example/btc-tower".to_string();
	let towers = vec![(url.clone(), terms.clone())];
	let fast = FeeRate::from_sat_per_vb(RATE).unwrap();

	let plan = wallet.btc_tower_plan(&holder, &towers, &[], fast).await.unwrap();
	println!("plan: deposit {} coins, covered {}, not worth {}, refresh due {}", plan["deposit"].as_array().unwrap().len(),
		plan["covered"], plan["not_worth"], plan["refresh_due"]);
	assert_eq!(plan["deposit"].as_array().unwrap().len(), 2);
	assert_eq!(plan["not_worth"].as_array().unwrap().len(), 1);
	assert_eq!(plan["refresh_due"].as_array().unwrap().len(), 3, "every coin is within 2M of expiry");
	let mut held = vec![];
	for d in plan["deposit"].as_array().unwrap() {
		let r = tower.deposit(&d["body"]).await.unwrap();
		println!("  the tower took {}: {}", d["vtxo"], r);
		let claim: Transaction = deserialize_hex(d["body"]["claim"].as_str().unwrap()).unwrap();
		assert_eq!(claim.output[0].script_pubkey, holder.script_pubkey(), "the claim pays the phrase's address");
		held.push(btc_tower::Deposited { tower: url.clone(), vtxo: d["vtxo"].as_str().unwrap().into(), claim_txid: d["claim_txid"].as_str().unwrap().into() });
	}
	let again = wallet.btc_tower_plan(&holder, &towers, &held, fast).await.unwrap();
	assert!(again["deposit"].as_array().unwrap().is_empty() && again["withdraw"].as_array().unwrap().is_empty(), "{}", again);
	println!("  planned again: nothing to send");

	// The wallet starts to exit the first coin: its deposit stays until the exit is claimed.
	let first = wallet.get_vtxo_by_id(held[0].vtxo.parse().unwrap()).await.unwrap().vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[first]).await.unwrap();
	let after = wallet.btc_tower_plan(&holder, &towers, &held, fast).await.unwrap();
	assert!(after["withdraw"].as_array().unwrap().is_empty(), "{}", after);
	let c = after["covered"].as_array().unwrap().iter().find(|c| c["vtxo"] == json!(held[0].vtxo)).unwrap();
	assert_eq!(c["exiting"], json!(true));
	println!("  the exiting coin keeps its deposit: {}", c);
	assert_eq!(tower.deposits().as_array().unwrap().len(), 2);
	println!("DONE");
}

async fn futures_keys(w: &bark::Wallet) -> Vec<Keypair> {
	let mut v = vec![];
	for _ in 0..3 { v.push(w.derive_store_next_keypair().await.unwrap().0); }
	v
}

/// A Bark wallet of phrase `tag` whose ark is unreachable, reading the chain
/// from the node.
async fn open_wallet(node: &Node, dir: &Path, tag: &str) -> (bark::Wallet, bip39::Mnemonic) {
	let m = phrase(tag);
	let seed = bark::WalletSeed::new_from_mnemonic(Network::Regtest, &m);
	let mut cfg = bark::Config::network_default(Network::Regtest);
	cfg.server_address = "http://127.0.0.1:9".into();
	cfg.bitcoind_address = Some(node.url.clone());
	cfg.bitcoind_cookiefile = Some(node.cookie.clone());
	cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb(RATE).unwrap());
	let mut open = bark::OpenWalletArgs::default();
	open.run_daemon = false;
	open.datadir = Some(dir.to_path_buf());
	open.create_without_server = true;
	(bark::Wallet::open(Network::Regtest, seed, cfg, open).await.unwrap(), m)
}

fn start_node(tag: &str, offset: u16) -> Option<(Node, PathBuf)> {
	let Ok(bin) = std::env::var("ARCA_TEST_BITCOIND") else {
		println!("ARCA_TEST_BITCOIND is not set: the regtest proof did not run");
		return None;
	};
	let base = PathBuf::from(std::env::var("ARCA_TEST_DIR").unwrap_or_else(|_| std::env::temp_dir().join("btc-tower-regtest").display().to_string())).join(tag);
	let _ = std::fs::remove_dir_all(&base);
	let port: u16 = std::env::var("ARCA_TEST_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(28710) + offset;
	let node = Node::start(&bin, &base.join("btc"), port);
	Some((node, base))
}

fn held_of(plan: &Value, url: &str, tower_took: impl Fn(&Value) -> bool) -> Vec<btc_tower::Deposited> {
	plan["deposit"].as_array().unwrap().iter().filter(|d| tower_took(&d["body"])).map(|d| btc_tower::Deposited {
		tower: url.to_string(), vtxo: d["vtxo"].as_str().unwrap().into(), claim_txid: d["claim_txid"].as_str().unwrap().into(),
	}).collect()
}

/// #562: a wallet starts a coin's own exit (as `exit_auto` does when the ark
/// stops) and closes before the exit is done. Its deposit stays, the tower
/// finishes the exit, and the operator's sweep at expiry finds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_exit_the_wallet_started_stays_covered() {
	let Some((node, base)) = start_node("own-exit", 40) else { return };
	let server = key("ox-server");
	let mut tower = open_tower(&node, &base.join("tower"), vec![]).await;
	fund_tower(&node, &mut tower, 6).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();
	let (wallet, m) = open_wallet(&node, &base.join("bark"), "ox-wallet").await;
	let k = futures_keys(&wallet).await;
	let expiry = node.tip() + 200;
	// each coin on its own round, so the sweep of one root is that coin alone
	let ra = make_round(&node, &server, &[(&k[0], Amount::from_sat(1_000_000)), (&key("ox-f1"), Amount::from_sat(100_000))], expiry, "ox-a");
	let rb = make_round(&node, &server, &[(&k[1], Amount::from_sat(1_000_000)), (&key("ox-f2"), Amount::from_sat(100_000))], expiry, "ox-b");
	// CONTROL: a round of the same ark whose holder deposited nowhere
	let rc = make_round(&node, &server, &[(&key("ox-c"), Amount::from_sat(1_000_000)), (&key("ox-f3"), Amount::from_sat(100_000))], expiry, "ox-c");
	wallet.import_vtxos(&[ra.vtxos[0].clone(), rb.vtxos[0].clone()], bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
	let holder = Payer::new(&node, &base.join("holder"), &m).await.first_address().await;
	let url = "http://tower.example/btc-tower".to_string();
	let towers = vec![(url.clone(), terms.clone())];
	let fast = FeeRate::from_sat_per_vb(RATE).unwrap();
	let plan = wallet.btc_tower_plan(&holder, &towers, &[], fast).await.unwrap();
	for d in plan["deposit"].as_array().unwrap() { tower.deposit(&d["body"]).await.unwrap(); }
	let held = held_of(&plan, &url, |_| true);
	assert_eq!(held.len(), 2);
	// the wallet starts to exit coin A, plans, and closes
	let first = wallet.get_vtxo_by_id(ra.vtxos[0].id()).await.unwrap().vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[first]).await.unwrap();
	let after = wallet.btc_tower_plan(&holder, &towers, &held, fast).await.unwrap();
	println!("  after the wallet starts coin A's exit: withdraw {}, covered {}", after["withdraw"], after["covered"]);
	assert!(after["withdraw"].as_array().unwrap().is_empty(), "the plan withdrew a deposit: {}", after);
	assert!(after["covered"].as_array().unwrap().iter().any(|c| c["vtxo"] == json!(ra.vtxos[0].id().to_string()) && c["exiting"] == json!(true)));
	drop(wallet);
	println!("  the wallet is closed with coin A's exit started and nothing broadcast");
	run(&node, &mut [&mut tower], 220, |n| n.tip() + 1 >= expiry).await;
	let (pa, pb) = (ra.vtxos[0].point(), rb.vtxos[0].point());
	println!("  at tip {} (expiry {}): coin A's output on chain: {}; coin B's: {}", node.tip(), expiry, node.confirmed(&pa.txid), node.confirmed(&pb.txid));
	assert!(node.confirmed(&pa.txid) && node.confirmed(&pb.txid));
	node.mine(1);
	let op = Address::from_str(&node.rpc.call::<String>("getnewaddress", &[]).unwrap()).unwrap().assume_checked();
	expect_err(node.force(&[&sweep(&ra, &server, &op)]), "bad-txns-inputs-missingorspent", "the sweep of coin A's round (its exit started by the wallet)");
	expect_err(node.force(&[&sweep(&rb, &server, &op)]), "bad-txns-inputs-missingorspent", "the sweep of coin B's round");
	node.force(&[&sweep(&rc, &server, &op)]).expect("CONTROL: the sweep of a round nobody deposited");
	println!("  CONTROL the sweep of round C (no deposit) was mined");
	println!("DONE");
}

/// #563: worth and fee at one rate. A 40,000-sat coin at a tower charging
/// testnet4's 30 sat/vB floor is not worth rescuing; the wallet plans no
/// deposit even when its own fast rate is 1, and the tower refuses one made
/// by hand at either rate.
#[tokio::test(flavor = "multi_thread")]
async fn a_small_coin_is_judged_at_the_rate_it_pays() {
	let Some((node, base)) = start_node("worth", 50) else { return };
	let server = key("w-server");
	let mut tower = open_tower_with(&node, &base.join("tower"), vec![], 30, btc_tower::RESCUE_MARGIN).await;
	fund_tower(&node, &mut tower, 4).await;
	let info = tower.info().await;
	let terms = TowerTerms::from_info(&info).unwrap();
	println!("  the tower charges {} sat/vB (least {})", info["rate_sat_vb"], info["min_rate_sat_vb"]);
	let (wallet, m) = open_wallet(&node, &base.join("bark"), "w-wallet").await;
	let k = futures_keys(&wallet).await;
	let r = make_round(&node, &server, &[(&k[0], Amount::from_sat(40_000)), (&k[1], Amount::from_sat(1_000_000)),
		(&key("w-f1"), Amount::from_sat(100_000)), (&key("w-f2"), Amount::from_sat(100_000))], node.tip() + 400, "w-round");
	let small = r.vtxos[0].clone();
	wallet.import_vtxos(&r.vtxos[..2], bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
	let holder = Payer::new(&node, &base.join("holder"), &m).await.first_address().await;
	let one = FeeRate::from_sat_per_vb(1).unwrap();
	let vb = btc_tower::rescue_vbytes(&small).unwrap();
	println!("  the 40,000-sat coin's rescue: {} vB; at 1 sat/vB {} sat (worth: {}), at 30 sat/vB {} sat ({}% of the coin)",
		vb, vb, btc_tower::worth_rescuing(&small, one), vb * 30, vb * 30 * 100 / 40_000);
	let plan = wallet.btc_tower_plan(&holder, &[("t".to_string(), terms.clone())], &[], one).await.unwrap();
	println!("  plan at the wallet's 1 sat/vB: deposit {} coin(s); not worth {}", plan["deposit"].as_array().unwrap().len(), plan["not_worth"]);
	assert_eq!(plan["not_worth"][0]["vtxo"], json!(small.id().to_string()));
	assert_eq!(plan["not_worth"][0]["rate_sat_vb"], json!(30));
	assert_eq!(plan["deposit"].as_array().unwrap().len(), 1, "the 1,000,000-sat coin is deposited");
	assert_eq!(plan["deposit"][0]["rate_sat_vb"], json!(30));
	let r1 = btc_tower::make_deposit(&small, &k[0], &holder, &terms, one);
	println!("  NEG make_deposit for the small coin: {}", r1.as_ref().unwrap_err());
	assert!(r1.unwrap_err().to_string().contains("not worth"));
	// by hand: the claim paying the tower the rescue at 30 sat/vB, and at 1 sat/vB
	for rate in [30u64, 1] {
		let fee = Amount::from_sat(vb * rate);
		let mut tx = btc_tower::claim_template(&small, &holder, &terms.payout, fee).unwrap();
		btc_tower::sign_claim(&small, &mut tx, &k[0]).unwrap();
		let e = tower.deposit(&btc_tower::deposit_body(&small, &tx)).await.unwrap_err().to_string();
		println!("  NEG the small coin's deposit with a fee at {} sat/vB ({}): {}", rate, fee, e);
		assert!(e.contains(if rate == 30 { "not worth" } else { "costs" }), "{}", e);
	}
	// the large coin is taken, at the plan's fee
	println!("  the 1,000,000-sat coin: {}", tower.deposit(&plan["deposit"][0]["body"]).await.unwrap());
	println!("DONE");
}

/// #564: a tower takes only what its own coins can pay for, and the wallet
/// shows a coin covered only once a tower that can pay has taken it.
#[tokio::test(flavor = "multi_thread")]
async fn a_tower_at_the_edge_of_its_coins() {
	let Some((node, base)) = start_node("edge", 60) else { return };
	let server = key("e-server");
	let mut tower = open_tower(&node, &base.join("tower"), vec![]).await;
	let (wallet, m) = open_wallet(&node, &base.join("bark"), "e-wallet").await;
	let keys: Vec<Keypair> = { let mut v = vec![]; for _ in 0..4 { v.push(wallet.derive_store_next_keypair().await.unwrap().0); } v };
	let users: Vec<(&Keypair, Amount)> = keys.iter().map(|k| (k, Amount::from_sat(1_000_000))).collect();
	let r = make_round(&node, &server, &users, node.tip() + 400, "e-round");
	wallet.import_vtxos(&r.vtxos, bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
	let holder = Payer::new(&node, &base.join("holder"), &m).await.first_address().await;
	let fast = FeeRate::from_sat_per_vb(RATE).unwrap();
	let fee = btc_tower::rescue_cost(&r.vtxos[0], fast).unwrap();
	// coins for two and a half rescues
	fund_tower_with(&node, &mut tower, 1, fee * 5 / 2).await;
	let info = tower.info().await;
	println!("  each rescue costs {}; the tower holds {} sat in {} coin(s), capacity {}", fee, info["float_sat"], info["float_coins"], info["capacity_sat"]);
	let url = "http://tower.example/btc-tower".to_string();
	let terms = TowerTerms::from_info(&info).unwrap();
	let plan = wallet.btc_tower_plan(&holder, &[(url.clone(), terms)], &[], fast).await.unwrap();
	println!("  plan: deposit {} coin(s); uncovered {}", plan["deposit"].as_array().unwrap().len(), plan["uncovered"]);
	assert_eq!(plan["deposit"].as_array().unwrap().len(), 2, "two deposits fit the tower's coins");
	assert!(plan["covered"].as_array().unwrap().is_empty(), "nothing is covered before the tower takes it");
	let waiting: Vec<_> = plan["uncovered"].as_array().unwrap().iter().filter(|u| u["reason"] == json!("deposits sent, not yet accepted")).collect();
	let unpaid: Vec<_> = plan["uncovered"].as_array().unwrap().iter().filter(|u| u["reason"].as_str().unwrap().contains("can pay for")).collect();
	assert_eq!((waiting.len(), unpaid.len()), (2, 2));
	for d in plan["deposit"].as_array().unwrap() { println!("  the tower takes {}: {}", d["vtxo"], tower.deposit(&d["body"]).await.unwrap()); }
	// the next deposit, made by hand, is refused
	let left: Vec<String> = unpaid.iter().map(|u| u["vtxo"].as_str().unwrap().to_string()).collect();
	let i = r.vtxos.iter().position(|v| v.id().to_string() == left[0]).unwrap();
	let (third, _) = btc_tower::make_deposit(&r.vtxos[i], &keys[i], &holder, &TowerTerms::from_info(&tower.info().await).unwrap(), fast).unwrap();
	let e = tower.deposit(&third).await.unwrap_err().to_string();
	println!("  NEG a third deposit: {}", e);
	assert!(e.contains("can pay for"));
	let info = tower.info().await;
	println!("  tower info now: capacity {} committed {} short {}", info["capacity_sat"], info["committed_sat"], info["short_sat"]);
	let held = held_of(&plan, &url, |_| true);
	let again = wallet.btc_tower_plan(&holder, &[(url.clone(), TowerTerms::from_info(&info).unwrap())], &held, fast).await.unwrap();
	println!("  plan again: covered {}, uncovered {}", again["covered"].as_array().unwrap().len(), again["uncovered"]);
	assert_eq!(again["covered"].as_array().unwrap().len(), 2);
	assert!(again["deposit"].as_array().unwrap().is_empty());
	let third_id = r.vtxos[i].id().to_string();
	assert!(again["uncovered"].as_array().unwrap().iter().any(|u| u["vtxo"] == json!(third_id) && u["reason"].as_str().unwrap().contains("can pay for")),
		"the third coin is shown uncovered: {}", again);
	assert_eq!(again["no_refresh"].as_array().unwrap().len(), 2, "only the covered coins skip their refresh");
	// a tower short of coins for what it holds covers nothing
	let mut short = info.clone();
	short["short_sat"] = json!(1);
	let s = wallet.btc_tower_plan(&holder, &[(url.clone(), TowerTerms::from_info(&short).unwrap())], &held, fast).await.unwrap();
	assert!(s["covered"].as_array().unwrap().is_empty() && s["skipped"][0]["reason"].as_str().unwrap().contains("short"), "{}", s);
	println!("  a tower reporting itself short: covered {}, skipped {}", s["covered"], s["skipped"]);

	// throughput: a tower of one coin and a margin of 20 blocks brings about 10 exit transactions on chain in it
	let mut slow = open_tower_with(&node, &base.join("slow"), vec![], 5, 20).await;
	fund_tower_with(&node, &mut slow, 1, Amount::from_sat(5_000_000)).await;
	let si = slow.info().await;
	println!("  a tower of {} coin(s), margin 20: {} exit transactions per margin", si["float_coins"], si["exits_per_margin"]);
	let st = TowerTerms::from_info(&si).unwrap();
	let many: Vec<Keypair> = (0..16).map(|i| key(&format!("e-many-{}", i))).collect();
	let users: Vec<(&Keypair, Amount)> = many.iter().map(|k| (k, Amount::from_sat(1_000_000))).collect();
	let r16 = make_round(&node, &server, &users, node.tip() + 400, "e-round-16");
	let mut took = 0;
	let mut refused = None;
	for (v, k) in r16.vtxos.iter().zip(&many) {
		let (b, _) = btc_tower::make_deposit(v, k, &holder, &st, fast).unwrap();
		match slow.deposit(&b).await { Ok(_) => took += 1, Err(e) => { refused = Some(e.to_string()); break; } }
	}
	let e = refused.expect("the slow tower took every coin");
	println!("  it took {} of the round's coins; NEG the next: {}", took, e);
	assert!(e.contains("exit transactions come due"));
	println!("DONE");
}

/// #565: a coin gets a tower or a delegated refresh, never both. A coin with
/// a refresh scheduled with the ark gets no deposit and its deposits are
/// withdrawn; a covered coin is left out of the refreshes to schedule.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_gets_a_tower_or_a_refresh_never_both() {
	let Some((node, base)) = start_node("tower-or-refresh", 70) else { return };
	let server = key("tr-server");
	let mut tower = open_tower(&node, &base.join("tower"), vec![]).await;
	fund_tower(&node, &mut tower, 4).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();
	let (wallet, m) = open_wallet(&node, &base.join("bark"), "tr-wallet").await;
	let k = futures_keys(&wallet).await;
	let r = make_round(&node, &server, &[(&k[0], Amount::from_sat(1_000_000)), (&k[1], Amount::from_sat(1_200_000)), (&k[2], Amount::from_sat(1_300_000))],
		node.tip() + 600, "tr-round");
	wallet.import_vtxos(&r.vtxos, bark::ImportVtxoArgs { skip_status_check: true, ..Default::default() }).await.unwrap();
	let [a, b, c] = [r.vtxos[0].id(), r.vtxos[1].id(), r.vtxos[2].id()];
	let holder = Payer::new(&node, &base.join("holder"), &m).await.first_address().await;
	let url = "http://tower.example/btc-tower".to_string();
	let towers = vec![(url.clone(), terms)];
	let fast = FeeRate::from_sat_per_vb(RATE).unwrap();
	let none = std::collections::HashSet::new();
	let before = wallet.refreshes_to_schedule(&none).await.unwrap();
	let n: usize = before.iter().map(|(_, v)| v.len()).sum();
	println!("  with no tower the wallet would schedule the refresh of {} coins", n);
	assert_eq!(n, 3);
	// coin A's refresh is scheduled with the ark (as a wallet that called schedule_refreshes has)
	let scheduled: std::collections::HashSet<_> = [a].into_iter().collect();
	let plan = wallet.btc_tower_plan_with(&holder, &towers, &[], fast, &scheduled).await.unwrap();
	let dep: Vec<&str> = plan["deposit"].as_array().unwrap().iter().map(|d| d["vtxo"].as_str().unwrap()).collect();
	println!("  plan with coin A's refresh scheduled: deposits for {:?}; uncovered {}", dep, plan["uncovered"]);
	assert!(!dep.contains(&a.to_string().as_str()) && dep.len() == 2);
	assert!(plan["uncovered"].as_array().unwrap().iter().any(|u| u["vtxo"] == json!(a.to_string()) && u["reason"].as_str().unwrap().contains("scheduled")));
	for d in plan["deposit"].as_array().unwrap() { tower.deposit(&d["body"]).await.unwrap(); }
	let held = held_of(&plan, &url, |_| true);
	let again = wallet.btc_tower_plan_with(&holder, &towers, &held, fast, &scheduled).await.unwrap();
	let except: std::collections::HashSet<ark::VtxoId> = again["no_refresh"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect();
	println!("  no_refresh {:?}", except);
	assert_eq!(except, [b, c].into_iter().collect());
	let after = wallet.refreshes_to_schedule(&except).await.unwrap();
	let ids: Vec<ark::VtxoId> = after.iter().flat_map(|(_, v)| v.iter().map(|w| w.id())).collect();
	println!("  the refreshes the wallet would schedule now: {:?}", ids);
	assert_eq!(ids, vec![a], "only the coin no tower covers gets a refresh");
	// coin B's refresh gets scheduled after all (a program that skipped `except`): its deposit is withdrawn
	let both: std::collections::HashSet<_> = [a, b].into_iter().collect();
	let w = wallet.btc_tower_plan_with(&holder, &towers, &held, fast, &both).await.unwrap();
	println!("  with coin B's refresh scheduled too: withdraw {:?}", w["withdraw"].as_array().unwrap().iter().map(|x| x["vtxo"].clone()).collect::<Vec<_>>());
	assert_eq!(w["withdraw"].as_array().unwrap().len(), 1);
	assert_eq!(w["withdraw"][0]["vtxo"], json!(b.to_string()));
	println!("  the tower: {}", tower.withdraw(&w["withdraw"][0]["body"]).unwrap());
	assert!(w["covered"].as_array().unwrap().iter().all(|x| x["vtxo"] != json!(b.to_string())));
	println!("DONE");
}

/// #561: a tower refuses a coin whose way out conflicts with a coin it holds,
/// or is already spent on chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_tower_refuses_conflicting_and_spent_coins() {
	let Some((node, base)) = start_node("conflicts", 80) else { return };
	let server = key("cf-server");
	let a = key("cf-a");
	let mut tower = open_tower(&node, &base.join("tower"), vec![]).await;
	fund_tower(&node, &mut tower, 4).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();
	let holder = Address::from_str(&node.rpc.call::<String>("getnewaddress", &[]).unwrap()).unwrap().assume_checked();
	let expiry = node.tip() + 300;
	let r = make_round(&node, &server, &[(&a, Amount::from_sat(1_000_000)), (&key("cf-o"), Amount::from_sat(1_000_000))], expiry, "cf-round");
	let c = r.vtxos[0].clone();
	// two out-of-round payments of one coin: two valid coins, only one can ever reach the chain
	let (r1, r2) = (key("cf-r1"), key("cf-r2"));
	let (p1, _) = pay_out_of_round(&c, &a, &server, &r1.public_key(), Amount::from_sat(700_000));
	let (p2, _) = pay_out_of_round(&c, &a, &server, &r2.public_key(), Amount::from_sat(700_000));
	println!("  the first: {}", tower.deposit(&deposit_for(&terms, &p1, &r1, &holder).0).await.unwrap());
	let e = tower.deposit(&deposit_for(&terms, &p2, &r2, &holder).0).await.unwrap_err().to_string();
	println!("  NEG a second payment of the same coin: {}", e);
	assert!(e.contains("spends") && e.contains("differently"));
	// a coin whose own output is spent on chain: its holder exits and claims it, then deposits it
	let o = key("cf-o");
	let oc = r.vtxos[1].clone();
	let mut ow = Payer::new(&node, &base.join("o"), &phrase("cf-o")).await;
	let oa = ow.first_address().await;
	node.rpc.call::<Value>("sendtoaddress", &[json!(oa.to_string()), json!(0.02)]).unwrap();
	node.rpc.call::<Value>("sendtoaddress", &[json!(oa.to_string()), json!(0.02)]).unwrap();
	node.mine(1);
	for t in oc.transactions().map(|i| i.tx) {
		if !node.confirmed(&t.compute_txid()) { ow.push(&t, RATE).await; node.mine(1); }
	}
	node.mine(EXIT_DELTA as u64);
	let mut own = btc_tower::claim_template(&oc, &oa, &oa, Amount::from_sat(1_000)).unwrap();
	btc_tower::sign_claim(&oc, &mut own, &o).unwrap();
	ow.push(&own, RATE).await;
	node.mine(1);
	assert!(node.confirmed(&own.compute_txid()));
	let e = tower.deposit(&deposit_for(&terms, &oc, &o, &holder).0).await.unwrap_err().to_string();
	println!("  NEG a coin already claimed on chain: {}", e);
	assert!(e.contains("spent on chain"));
	println!("DONE");
}

/// #566: a rescue a reorg undid, its transactions then dropped from the
/// mempool, is broadcast again: the tower reads each deposit's state from
/// the chain at every pass until its claim is buried.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_undone_by_a_reorg_is_broadcast_again() {
	let Some((node, base)) = start_node("reorg", 90) else { return };
	let server = key("rg-server");
	let h = key("rg-h");
	let mut tower = open_tower(&node, &base.join("tower"), vec![]).await;
	fund_tower(&node, &mut tower, 6).await;
	let terms = TowerTerms::from_info(&tower.info().await).unwrap();
	let holder = Payer::new(&node, &base.join("h"), &phrase("rg-h")).await.first_address().await;
	let expiry = node.tip() + 170;
	let r = make_round(&node, &server, &[(&h, Amount::from_sat(1_000_000)), (&key("rg-o"), Amount::from_sat(1_000_000))], expiry, "rg-round");
	let c = r.vtxos[0].clone();
	let (d, ctxid) = deposit_for(&terms, &c, &h, &holder);
	tower.deposit(&d).await.unwrap();
	let mut worst_short = 0;
	for _ in 0..80 {
		let v = tower.pass().await.unwrap();
		if v["acted"].as_array().is_some_and(|a| !a.is_empty()) { println!("  tower @{}: {}", v["tip"], v["acted"]); }
		let i = tower.info().await;
		worst_short = worst_short.max(i["short_sat"].as_u64().unwrap());
		if node.confirmed(&ctxid) { break; }
		node.mine(1);
	}
	assert!(node.confirmed(&ctxid));
	tower.pass().await.unwrap();
	println!("  during the rescue the tower never reported itself short (most: {} sat); committed now {}", worst_short, tower.info().await["committed_sat"]);
	assert_eq!(worst_short, 0);
	let state = |t: &Tower| t.deposits()[0]["state"].as_str().unwrap().to_string();
	println!("  the claim {} confirmed at tip {}: deposit {}", ctxid, node.tip(), state(&tower));
	assert_eq!(state(&tower), "claimed");
	// a reorg from the block holding the coin's output, then the mempool drops what it took back
	let leaf = c.point().txid;
	let bh = node.rpc.call::<Value>("getrawtransaction", &[json!(leaf.to_string()), json!(true)]).unwrap()["blockhash"].as_str().unwrap().to_string();
	node.rpc.call::<Value>("invalidateblock", &[json!(bh)]).unwrap();
	let now = node.rpc.call::<Value>("getblockheader", &[json!(node.rpc.call::<String>("getbestblockhash", &[]).unwrap())]).unwrap()["time"].as_u64().unwrap();
	node.rpc.call::<Value>("setmocktime", &[json!(now + 15 * 24 * 3600)]).unwrap();
	node.rpc.call::<Value>("sendtoaddress", &[json!(node.miner.to_string()), json!(0.001)]).unwrap(); // a new entry expires the old
	let in_pool = |t: &Txid| node.rpc.call::<Value>("getmempoolentry", &[json!(t.to_string())]).is_ok();
	println!("  after the reorg and the mempool's expiry: the coin's output in a block {}, in the mempool {}; the claim in the mempool {}",
		node.confirmed(&leaf), in_pool(&leaf), in_pool(&ctxid));
	assert!(!node.confirmed(&leaf) && !in_pool(&leaf) && !in_pool(&ctxid));
	run(&node, &mut [&mut tower], 40, |n| n.confirmed(&ctxid)).await;
	println!("  the tower broadcast them again: the claim confirmed at tip {}; deposit {}", node.tip(), state(&tower));
	while node.tip() + 1 < expiry { node.mine((expiry - 1 - node.tip()) as u64); }
	node.mine(1);
	let op = Address::from_str(&node.rpc.call::<String>("getnewaddress", &[]).unwrap()).unwrap().assume_checked();
	expect_err(node.force(&[&sweep(&r, &server, &op)]), "bad-txns-inputs-missingorspent", "the sweep at expiry after the reorg");
	// buried: the tower stops watching it
	node.mine(btc_tower::tower::CLAIM_DEPTH as u64);
	tower.pass().await.unwrap();
	println!("  claimed and buried: {}", tower.deposits()[0]["note"]);
	println!("DONE");
}

/// A tower's wallet reads the chain from its birthday, the first block within
/// two hours of its phrase being made, never from genesis.
#[tokio::test(flavor = "multi_thread")]
async fn a_towers_wallet_starts_at_its_birthday() {
	let Some((node, base)) = start_node("birthday", 100) else { return };
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	// 150 blocks of today, then 50 blocks ten days on
	node.rpc.call::<Value>("setmocktime", &[json!(now + 10 * 24 * 3600)]).unwrap();
	node.mine(50);
	let dir = base.join("tower");
	std::fs::create_dir_all(&dir).unwrap();
	// a phrase made five days on: its birthday is the first block of the later 50
	let m = base.join("tower/mnemonic");
	std::fs::write(&m, phrase("bd-tower").to_string()).unwrap();
	std::fs::File::options().write(true).open(&m).unwrap()
		.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(now + 5 * 24 * 3600)).unwrap();
	let mut tower = open_tower(&node, &dir, vec![]).await;
	let birthday: u32 = std::fs::read_to_string(dir.join("birthday")).unwrap().trim().parse().unwrap();
	let info = tower.info().await;
	println!("  tip {}; the tower's birthday {}; its wallet starts at {}", node.tip(), birthday, info["float_synced_to"]);
	assert_eq!(birthday, 151);
	assert_eq!(info["float_synced_to"], json!(150));
	fund_tower(&node, &mut tower, 2).await;
	let info = tower.info().await;
	println!("  after funding and a pass: synced to {}, {} sat in {} coins", info["float_synced_to"], info["float_sat"], info["float_coins"]);
	assert_eq!(info["float_synced_to"], json!(node.tip()));
	assert_eq!(info["float_sat"], json!(2_000_000));
	// reopened, it keeps its birthday and its wallet's height
	drop(tower);
	let tower = open_tower(&node, &dir, vec![]).await;
	assert_eq!(tower.info().await["float_synced_to"], json!(node.tip()));
	println!("DONE");
}
