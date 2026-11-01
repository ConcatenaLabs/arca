//! Bitcoin ark watchtowers ([bark::btc_tower]) on a real Bitcoin Core regtest
//! chain. The ark's coins are made with the library and its server's key, as
//! the ark's server makes them: a round tree funded on chain, a board, and a
//! coin paid out of round through a checkpoint. Holding the server's key also
//! lets the test play a hostile operator and force its sweep into a block.
//!
//! The node runs with `-par=1`, so a block refused for a script names the
//! script failure, and `-blockmintxfee` at 5 sat/vB, so a child paying less
//! waits in the mempool as it would in a fee spike.
//!
//!     ARCA_TEST_BITCOIND=/path/to/bitcoind (version 31 or later) \
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
	Tower::open(dir, TowerConfig {
		network: Network::Regtest,
		chain: node.spec(),
		min_rate: FeeRate::from_sat_per_vb(5).unwrap(),
		fallback_rate: Some(FeeRate::from_sat_per_vb(RATE).unwrap()),
		arks,
		margin: btc_tower::RESCUE_MARGIN,
	}).await.unwrap()
}

/// Funds a tower's own coins with `n` coins of 0.01 BTC.
async fn fund_tower(node: &Node, t: &mut Tower, n: usize) {
	for _ in 0..n {
		let a = t.funding_address().await.unwrap();
		node.rpc.call::<Value>("sendtoaddress", &[json!(a.to_string()), json!(0.01)]).unwrap();
	}
	node.mine(1);
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
	let cheap = btc_tower::TowerTerms { min_rate: FeeRate::from_sat_per_vb(1).unwrap(), ..terms_b.clone() };
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

	// The wallet starts to exit the first coin: it no longer holds it in the ark.
	let first = wallet.get_vtxo_by_id(held[0].vtxo.parse().unwrap()).await.unwrap().vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[first]).await.unwrap();
	let after = wallet.btc_tower_plan(&holder, &towers, &held, fast).await.unwrap();
	let w = &after["withdraw"].as_array().unwrap()[0];
	assert_eq!(w["vtxo"], json!(held[0].vtxo));
	println!("  the exiting coin's deposit is withdrawn: {}", tower.withdraw(&w["body"]).unwrap());
	assert_eq!(tower.deposits().as_array().unwrap().len(), 1);
	println!("DONE");
}

async fn futures_keys(w: &bark::Wallet) -> Vec<Keypair> {
	let mut v = vec![];
	for _ in 0..3 { v.push(w.derive_store_next_keypair().await.unwrap().0); }
	v
}
