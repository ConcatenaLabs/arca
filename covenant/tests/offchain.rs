//! The off-chain transactions of a refresh and an offboard, on a Sequentia
//! regtest chain: the board, the forfeit bound to its leaf and its round, the
//! connector asset, and the offboard output.
//!
//! Every transaction is built with this crate's builders, signed with test
//! keys and broadcast to a node on an anchored `elementsregtest` chain. A
//! spend that should confirm must pass `testmempoolaccept`, be broadcast and
//! be mined. A negative case must be refused by `testmempoolaccept`, by
//! `sendrawtransaction`, and again when forced into a block with
//! `generateblock`, the block for the same reason (the node checks scripts
//! inline, `-par=1`).
//!
//! 1. A board (`board-1`), its record checked against the board transaction
//!    under the wallet's policy, and its refresh into a round, the preimage
//!    handed over on the forfeit pair alone. The conversion signed by the
//!    operator, unsigned, one atom short, or into another script is refused;
//!    the owner's own conversion confirms, its exit waits the leaf's delay, and
//!    the operator answers with the forfeit on the converted leaf, so the exit
//!    has nothing left. The operator issues the round's connector asset and
//!    claims; the owner learns the preimage from the chain, unrolls the new
//!    batch and exits. A second board never converted: the operator publishes
//!    the forfeit straight from the board output and claims.
//!    One atom of the connector asset serves two claims of one round.
//! 2. The round's connector output, spent any way but by the issuance of
//!    exactly `M`: with no issuance, two atoms, a reissuance token, another
//!    asset under a contract hash, or another key's signature. Each is
//!    refused; the issuance confirms.
//! 3. Two forfeits of one participation cannot share one forfeit output, with
//!    distinct keys and with the same key.
//! 4. The offboard: the operator's claim publishes the preimage, a third party
//!    moves the output to the owner's destination; an output pinned at its own
//!    index cannot be merged with another to one destination; the operator
//!    reclaims an offboard whose preimage never came, after the delay.
//! 5. An out-of-round chain three hops deep, one hop a swap of two owners'
//!    coins in two assets: the last receiver validates it from its record and
//!    the rounds alone, brings it on-chain from the record (unrolls, entries,
//!    checkpoints and reassignments, outside fee coins wherever the asset is
//!    not accepted for fees) and exits. A reassignment's pair cannot skip the
//!    checkpoint, a checkpoint's pair cannot spend the checkpoint, the swap's
//!    outputs cannot be paid from one input's value alone, and the first
//!    sender's exit fails once the receiver has published the checkpoint.
//!
//! Rollbacks are in `rollback.rs`.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction's size
//! beside the specification's, and every refusal.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::json;

use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{margin_for, FeeSource};
use arca_covenant::spend::{collab_tx, UnrollTx};
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::witness::find_preimage;
use arca_covenant::*;

use common::chain::*;
use common::net::*;
use common::*;

const LEAF: u64 = 10_000_000;
const DAY: u64 = 24 * H as u64;

fn sizes_spec(name: &str) -> &'static str {
	match name {
		n if n.contains("reclaim") || n.contains("issuance") || n.contains("unlock") => "",
		n if n.contains("the forfeit") => "280",
		n if n.contains("claim") => "224 (no connector)",
		n if n.contains("refund") => "207 (P2WPKH out)",
		n if n.contains("exit") => "207 (P2WPKH out)",
		_ => "",
	}
}

struct Ctx {
	net: Net,
	sizes: Vec<(String, String)>,
	floor_per_kvb: u64,
}

impl Ctx {
	fn pass(&mut self, name: &str, tx: &Transaction) -> Txid {
		let txid = self.net.pass(name, tx);
		let v = self.net.rows.last().unwrap().vsize.clone();
		self.sizes.push((format!("{} ({} vB)", name, v), sizes_spec(name).into()));
		txid
	}

	fn policy(&self, s: &Keypair) -> WalletPolicy {
		WalletPolicy::new(self.net.chain, xonly(s), mt(self.net.mtp()))
	}

	fn schedule(&mut self, s: &Keypair) -> (Coin, ClockSchedule) {
		let issuer = self.net.fund(vec![explicit(self.net.x, 2_000_000_000, op_true_spk())]).remove(0);
		let now = self.net.now();
		let sched = ClockSchedule::new(token_of(&issuer), xonly(s), delay(),
			vec![mt(now + 28 * DAY), mt(now + 56 * DAY)]).unwrap();
		(issuer, sched)
	}

	/// A tree of one leaf per spec, reserves at four times the node's floor.
	fn tree(&self, sched: &ClockSchedule, leaves: &[LeafSpec]) -> Tree {
		Tree::build(TreeParams {
			asset: self.net.x, chain: self.net.chain, schedule: sched.clone(), burn: false, radix: 4,
			reserve: ReserveRule::FeeRate { floor_per_kvb: self.floor_per_kvb, multiple: 4 }, min_leaf: 1,
		}, leaves).unwrap()
	}
}

/// A round: it spends `issuer`, which issues the token when there is a tree,
/// and pays the batch output and the token's atom to clock 0, then the
/// connector output under `s`'s connector script, then `extra`, change and
/// the fee. Returns the transaction and the connector's index.
fn round_tx(net: &Net, issuer: &Coin, tree: Option<&Tree>, extra: Vec<TxOut>, s: &Keypair) -> (Transaction, u32) {
	let total = issuer.txout.value.explicit().unwrap();
	let mut outs = vec![];
	if let Some(t) = tree {
		outs.push(t.batch_output().txout());
		outs.push(explicit(t.params().schedule.token, 1, t.clock0_script_pubkey()));
	}
	let c = outs.len() as u32;
	outs.push(ConnectorPolicy { operator: xonly(s) }.output(net.x, 5_000).txout());
	outs.extend(extra);
	let spent: u64 = outs.iter().filter(|o| o.asset.explicit() == Some(net.x)).map(|o| o.value.explicit().unwrap()).sum();
	outs.push(explicit(net.x, total - spent - 2_000, op_true_spk()));
	outs.push(fee(net.x, 2_000));
	let mut s = spend(0).coin(issuer, 0xffff_ffff).outputs(outs);
	if tree.is_some() {
		s.tx.input[0].asset_issuance = AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
			amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
			denomination: 0,
		};
	}
	s.witness(0, op_true_witness());
	(s.tx, c)
}

/// Signs `ks` with `key` and finishes it with the signature, then `after`.
fn signed(net: &Net, ks: KeySpend, key: &Keypair, after: Vec<Vec<u8>>) -> UnrollTx {
	let sg = sign_digest(key, &ks.sighash(net.genesis).unwrap(), &ZERO_AUX);
	let mut below = vec![sg.as_ref().to_vec()];
	below.extend(after);
	ks.finish(below)
}

fn pair(f: &Forfeit, owner: &Keypair, operator: &Keypair) -> Pair {
	let d = f.message().digest;
	Pair { operator: sig(operator, &d), owner: sig(owner, &d) }
}

/// A leaf funded directly (as a board pays it), its id the board form's.
fn funded_leaf(net: &mut Net, owner: &Keypair, s: &Keypair, label: &str) -> (LeafPolicy, Coin, LeafId) {
	let leaf = LeafPolicy {
		owner: xonly(owner), operator: xonly(s),
		salt: arca_covenant::leaf::leaf_salt(&label32(&format!("{} owner nonce", label)), &label32(&format!("{} operator nonce", label))),
		chain: net.chain, exit_delay: delay(),
	};
	let coin = net.fund(vec![explicit(net.x, LEAF, leaf.script_pubkey())]).remove(0);
	let p = leaf.program();
	(leaf, coin, LeafId::compute(&p, &[], &p))
}

/// The operator's issuance of the round's connector asset, spending its
/// connector output, signed by `s`.
fn connector_issuance_tx(net: &Net, round: &Transaction, round_txid: Txid, vout: u32, s: &Keypair) -> Transaction {
	let conn = coin_of(round_txid, vout, round);
	let (a, v) = (conn.txout.asset.explicit().unwrap(), conn.txout.value.explicit().unwrap());
	let ks = ConnectorPolicy { operator: xonly(s) }.issuance(conn.outpoint, (a, v), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
	signed(net, ks, s, vec![]).tx
}

/// Issues the round's connector asset by spending its connector output.
fn issue_connector(c: &mut Ctx, name: &str, round: &Transaction, round_txid: Txid, vout: u32, s: &Keypair) -> Coin {
	let tx = connector_issuance_tx(&c.net, round, round_txid, vout, s);
	let it = c.pass(name, &tx);
	coin_of(it, 0, &tx)
}

/// The claim of `f` held at `f_coin`, with `m_coin` at input 1, its witness
/// items `[sig, preimage, k]`.
fn claim_tx(net: &Net, f: &Forfeit, f_coin: OutPoint, m_coin: &Coin, s: &Keypair, preimage: &[u8; 32], k: u32) -> Transaction {
	let ks = f.claim(f_coin, (m_coin.outpoint, m_coin.txout.clone()),
		&[ExplicitOutput::new(net.x, f.output().value - 1_500, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
	let mut u = signed(net, ks, s, vec![preimage.to_vec(), arca_covenant::script::scriptnum(k as i64)]);
	u.tx.input[1].witness.script_witness = op_true_witness();
	u.tx
}

// ---------------------------------------------------------------------------
// 1. The board and its refresh
// ---------------------------------------------------------------------------

fn board_and_refresh(c: &mut Ctx) {
	let s = keypair("board operator");
	let a1 = keypair("board owner, the board leaf's key");
	let a2 = keypair("board owner, the new leaf's key");
	let x = c.net.x;
	let rec = BoardRecord {
		template: Template::Board1, owner: xonly(&a1), owner_nonce: label32("board owner nonce"),
		operator_nonce: label32("board operator nonce"), exit_delay: delay(), asset: x, value: 20_000_000,
		chain: c.net.chain, operator: xonly(&s),
	};
	let bp = rec.policy();
	// The owner's wallet coin pays the board, with change, the fee in X.
	let wallet = c.net.fund(vec![explicit(x, 30_000_000, op_true_spk())]).remove(0);
	let mut b = rec.tx(&[(wallet.outpoint, wallet.txout.clone())], x, 1_500, &op_true_spk()).unwrap();
	b.tx.input[0].witness.script_witness = op_true_witness();
	let bt = c.pass("board/the board transaction", &b.tx);
	let on_chain = c.net.rt.client().raw_transaction(&bt).unwrap();
	let policy = c.policy(&s);
	let valid = BoardRecord::from_bytes(&rec.to_bytes().unwrap()).unwrap().validate(&on_chain, &policy).unwrap();
	assert_eq!((valid.vout, valid.leaf_id), (0, rec.leaf_id()));
	rec.check_owner(&xonly(&a1), &rec.owner_nonce).unwrap();
	let mut other = rec;
	other.owner_nonce = label32("not the board's nonce");
	assert_eq!(other.validate(&on_chain, &policy).unwrap_err().kind(), "board_output");
	println!("board: the record validates against board {} (leaf id {}); one with another owner nonce is refused", bt, valid.leaf_id);
	let board_coin = valid.outpoint();

	// A round that refreshes it: the owner's new leaf, under a new key and a
	// fresh nonce, behind an entry locked to h; the connector output.
	let (issuer, sched) = c.schedule(&s);
	let preimage = label32("board refresh preimage");
	let spec = LeafSpec {
		template: Template::Vtxo1, owner: xonly(&a2), value: 19_990_000, owner_nonce: label32("board new leaf nonce"),
		operator_nonce: label32("board new leaf operator nonce"), exit_delay: delay(), unlock_hash: sha256(&preimage),
	};
	let second_owner = keypair("refresh second owner, new leaf");
	let preimage_b = label32("second owner refresh preimage");
	let spec_b = LeafSpec {
		template: Template::Vtxo1, owner: xonly(&second_owner), value: LEAF - 2_000,
		owner_nonce: label32("second owner new nonce"), operator_nonce: label32("second owner operator nonce"),
		exit_delay: delay(), unlock_hash: sha256(&preimage_b),
	};
	let tree = c.tree(&sched, &[spec, spec_b]);
	let (round, cv) = round_tx(&c.net, &issuer, Some(&tree), vec![], &s);
	let rt = c.pass("board/refresh: the round", &round);
	c.net.purse.push(coin_of(rt, cv + 1, &round));
	let round = c.net.rt.client().raw_transaction(&rt).unwrap();
	let new_rec = tree.record(0);
	let new_valid = new_rec.validate(&round, &policy, &xonly(&a2), &spec.owner_nonce).unwrap();
	let m = connector_asset(rt, cv);

	// The owner signs the forfeit of the board's leaf, bound to that leaf and
	// to this round, and the operator hands over the preimage at once: the
	// one pair spends the board output and the leaf a conversion makes, and
	// the owner alone gets out only by converting, which gives the operator
	// the leaf's whole exit delay to answer.
	let margin = margin_for(280, c.floor_per_kvb, 4);
	let f = Forfeit::for_refresh(rec.leaf(), (x, rec.value), rec.leaf_id(), &new_valid, &round, cv, delay(), margin).unwrap();
	assert_eq!((f.policy.unlock_hash, f.policy.connector), (sha256(&preimage), m), "h from the new leaf, M from the round");
	let p = pair(&f, &a1, &s);
	f.verify(&p).unwrap();
	let bad = Pair { owner: sig(&a2, &f.message().digest), ..p };
	assert_eq!(f.verify(&bad).unwrap_err().to_string(), "the owner's signature does not verify");

	// The owner's conversion: only its own signature, only into its leaf.
	let fee_coin = |c: &mut Ctx| {
		let fc = c.net.fee_coin();
		FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() }
	};
	let convert = |c: &mut Ctx, key: Option<&Keypair>, edit: &dyn Fn(&mut Transaction)| {
		let fs = fee_coin(c);
		let mut ks = bp.conversion(board_coin, &fs).unwrap();
		edit(&mut ks.tx);
		let below = match key {
			Some(k) => vec![sign_digest(k, &ks.sighash(c.net.genesis).unwrap(), &ZERO_AUX).as_ref().to_vec()],
			None => vec![vec![]],
		};
		let mut u = ks.finish(below);
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	};
	let tx = convert(c, Some(&s), &|_| {});
	c.net.refuse("board/neg the conversion signed by the operator", &tx, "Invalid Schnorr signature");
	let tx = convert(c, None, &|_| {});
	c.net.refuse("board/neg the conversion with no signature", &tx, "Script failed an OP_CHECKSIGVERIFY operation");
	let tx = convert(c, Some(&a1), &|tx| {
		let v = tx.output[0].value.explicit().unwrap();
		tx.output[0].value = elements::confidential::Value::Explicit(v - 1);
		tx.output.insert(1, explicit(x, 1, op_true_spk()));
	});
	c.net.refuse("board/neg the conversion one atom short", &tx, "Script failed an OP_EQUALVERIFY operation");
	let tx = convert(c, Some(&a1), &|tx| tx.output[0].script_pubkey = op_true_spk());
	c.net.refuse("board/neg the conversion into another script", &tx,
		"Script evaluated without error but finished with a false/empty top stack element");
	let tx = convert(c, Some(&a1), &|_| {});
	let ct = c.pass("board/the owner's conversion into its leaf, a fee coin attached", &tx);
	let leaf_coin = OutPoint::new(ct, 0);

	// The owner's exit waits the leaf's delay; the operator answers within it
	// with the forfeit it holds, on the leaf, and the exit has nothing left.
	let ks = rec.leaf().exit_tx(leaf_coin, x, rec.value, &[ExplicitOutput::new(x, rec.value - 1_500, op_true_spk())],
		&FeeSource::Reserve).unwrap();
	let ex = signed(&c.net, ks, &a1, vec![]);
	c.net.refuse("board/neg the converted leaf's exit at once", &ex.tx, "non-BIP68-final");
	let u = f.tx(leaf_coin, &bad, &FeeSource::Reserve).unwrap();
	c.net.refuse("board/neg the forfeit signed by the new leaf's key", &u.tx, "Invalid Schnorr signature");
	let ft = c.pass("board/refresh: the forfeit, on the converted leaf", &f.tx(leaf_coin, &p, &FeeSource::Reserve).unwrap().tx);
	let f_coin = OutPoint::new(ft, 0);
	c.net.wait_csv(&ct, delay());
	c.net.refuse("board/neg the converted leaf's exit after its delay", &ex.tx, "bad-txns-inputs-missingorspent");

	// The operator issues M and claims; negatives first.
	let y_coin = c.net.fund(vec![explicit(c.net.y, 1, op_true_spk())]).remove(0);
	let tx = claim_tx(&c.net, &f, f_coin, &y_coin, &s, &preimage, 1);
	c.net.refuse("board/neg claim with another asset where M belongs", &tx, "Script failed an OP_EQUALVERIFY operation");
	let m_coin = issue_connector(c, "board/refresh: the issuance of the connector asset M", &round, rt, cv, &s);
	let tx = claim_tx(&c.net, &f, f_coin, &m_coin, &s, &label32("not the preimage"), 1);
	c.net.refuse("board/neg claim with M and a wrong preimage", &tx, "Script failed an OP_EQUALVERIFY operation");
	let tx = claim_tx(&c.net, &f, f_coin, &m_coin, &s, &preimage, 0);
	c.net.refuse("board/neg claim naming the forfeit itself as M's input", &tx, "Script failed an OP_EQUALVERIFY operation");
	let tx = claim_tx(&c.net, &f, f_coin, &m_coin, &keypair("not the operator"), &preimage, 1);
	c.net.refuse("board/neg claim by another key", &tx, "Invalid Schnorr signature");
	let mut no_m = spend(0).coin(&Coin { outpoint: f_coin, txout: f.output().txout() }, 0xffff_ffff)
		.outputs(vec![explicit(x, f.output().value - 1_500, op_true_spk()), fee(x, 1_500)]);
	let sg = no_m.sign(&s, 0, &f.policy.claim_script(), c.net.genesis);
	no_m.witness(0, f.policy.claim_witness(&sg, &preimage, 1));
	c.net.refuse("board/neg claim with no input holding M", &no_m.tx, "Introspection index out of bounds");
	let tx = claim_tx(&c.net, &f, f_coin, &m_coin, &s, &preimage, 1);
	let ct = c.pass("board/refresh: the operator's claim, with M at input 1", &tx);
	let m_coin = coin_of(ct, 1, &tx);
	assert_eq!(m_coin.txout.asset.explicit(), Some(m));

	// The same atom serves the second owner's claim, in another
	// transaction: its old leaf is given up for the same round.
	let (old_b, old_b_coin, old_b_id) = funded_leaf(&mut c.net, &keypair("refresh second owner, old leaf"), &s, "second owner old leaf");
	let valid_b = tree.record(1).validate(&round, &policy, &xonly(&second_owner), &spec_b.owner_nonce).unwrap();
	let fb = Forfeit::for_refresh(old_b, (x, LEAF), old_b_id, &valid_b, &round, cv, delay(), margin).unwrap();
	let pb = pair(&fb, &keypair("refresh second owner, old leaf"), &s);
	let fc = c.net.fee_coin();
	let mut u = fb.tx(old_b_coin.outpoint, &pb, &FeeSource::Coin {
		outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 4_000, change: op_true_spk(),
	}).unwrap();
	u.tx.input[1].witness.script_witness = op_true_witness();
	let fbt = c.pass("connector/the second owner's forfeit, a fee coin attached", &u.tx);
	let tx = claim_tx(&c.net, &fb, OutPoint::new(fbt, 0), &m_coin, &s, &preimage_b, 1);
	c.pass("connector/the second claim, with the same atom of M", &tx);

	// The owner learns the preimage from the claim, unrolls the new batch,
	// unlocks its entry and exits.
	let learned = find_preimage(&c.net.witness_of(&ct, 0), &sha256(&preimage)).expect("the claim reveals the preimage");
	let branch = new_valid.branch;
	let t = mt(c.net.mtp() - 60);
	let auths: Vec<_> = branch.nodes.iter().map(|n| n.owner_auth(sig(&a2, &n.unroll_authorisation(t).digest), t, xonly(&a2))).collect();
	let txs = branch.unroll(OutPoint::new(rt, new_valid.batch_vout), &auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		c.pass("board/refresh: the new batch unrolled", &u.tx);
	}
	let e = branch.entry_tx(branch.entry_outpoint(&txs).unwrap(), &learned, &FeeSource::Reserve).unwrap();
	let et = c.pass("board/refresh: the new entry unlocked with the learned preimage", &e.tx);
	let leaf_coin = OutPoint::new(et, 0);
	let exit = |c: &Ctx| {
		let ks = branch.leaf.exit_tx(leaf_coin, x, branch.entry.value,
			&[ExplicitOutput::new(x, branch.entry.value - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
		signed(&c.net, ks, &a2, vec![]).tx
	};
	c.net.refuse("board/neg the new leaf's exit before the delay", &exit(c), "non-BIP68-final");
	c.net.wait_csv(&et, delay());
	c.pass("board/refresh: the new leaf's exit after the delay", &exit(c));

	// A second board, refreshed the same way and never converted: the
	// operator takes its value when it chooses, by publishing the forfeit
	// straight from the board output with the same kind of pair, and claims.
	let a3 = keypair("board owner, a second board");
	let rec3 = BoardRecord { owner: xonly(&a3), owner_nonce: label32("second board nonce"),
		operator_nonce: label32("second board operator nonce"), value: 15_000_000, ..rec };
	let wallet = c.net.fund(vec![explicit(x, 16_000_000, op_true_spk())]).remove(0);
	let mut b = rec3.tx(&[(wallet.outpoint, wallet.txout.clone())], x, 1_500, &op_true_spk()).unwrap();
	b.tx.input[0].witness.script_witness = op_true_witness();
	let bt3 = c.pass("board/a second board", &b.tx);
	c.net.wait_csv(&bt3, delay());
	let (issuer, sched) = c.schedule(&s);
	let preimage3 = label32("second board preimage");
	let spec3 = LeafSpec {
		template: Template::Vtxo1, owner: xonly(&keypair("second board, new leaf")), value: 14_990_000,
		owner_nonce: label32("second board new nonce"), operator_nonce: label32("second board new operator nonce"),
		exit_delay: delay(), unlock_hash: sha256(&preimage3),
	};
	let tree3 = c.tree(&sched, &[spec3]);
	let (round3, cv3) = round_tx(&c.net, &issuer, Some(&tree3), vec![], &s);
	let rt3 = c.pass("board/a second board's refresh: the round", &round3);
	let round3 = c.net.rt.client().raw_transaction(&rt3).unwrap();
	let valid3 = tree3.record(0).validate(&round3, &policy, &spec3.owner, &spec3.owner_nonce).unwrap();
	let f3 = Forfeit::for_refresh(rec3.leaf(), (x, rec3.value), rec3.leaf_id(), &valid3, &round3, cv3, delay(), margin).unwrap();
	let p3 = pair(&f3, &a3, &s);
	assert_eq!(f3.board_tx(&rec.policy(), OutPoint::new(bt3, 0), &p3, &FeeSource::Reserve).unwrap_err(), SpendError::OtherBoard);
	let ft3 = c.pass("board/the forfeit straight from the board output, its delay long past",
		&f3.board_tx(&rec3.policy(), OutPoint::new(bt3, 0), &p3, &FeeSource::Reserve).unwrap().tx);
	let m3 = issue_connector(c, "board/the second board's round: the issuance of M", &round3, rt3, cv3, &s);
	c.pass("board/the claim of the second board's forfeit", &claim_tx(&c.net, &f3, OutPoint::new(ft3, 0), &m3, &s, &preimage3, 1));
}

// ---------------------------------------------------------------------------
// 2. The connector output: spent only by the issuance of M
// ---------------------------------------------------------------------------

/// The round's connector output spent every way but the issuance of exactly
/// `M`: each is refused, by the mempool and in a block, for the script's
/// reason. Then the issuance itself confirms.
fn connector(c: &mut Ctx) {
	let s = keypair("connector operator");
	let x = c.net.x;
	let policy = ConnectorPolicy { operator: xonly(&s) };
	let issuer = c.net.fund(vec![explicit(x, 1_000_000_000, op_true_spk())]).remove(0);
	let (round, cv) = round_tx(&c.net, &issuer, None, vec![], &s);
	let rt = c.pass("connector/a round with its connector output", &round);
	let round = c.net.rt.client().raw_transaction(&rt).unwrap();
	let conn = coin_of(rt, cv, &round);
	policy.check(&round, cv).unwrap();
	assert_eq!(policy.check(&round, cv + 1).unwrap_err(), SpendError::Connector(cv + 1));
	let m = connector_asset(rt, cv);
	println!("connector: script {} bytes, round {} output {}, M {}", policy.script().len(), rt, cv, m);

	// The issuance as the operator builds it, changed by `edit`, then signed by `key`.
	let built = |c: &Ctx, key: &Keypair, edit: &dyn Fn(&mut Transaction)| {
		let ks = policy.issuance(conn.outpoint, (x, 5_000), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
		let mut ks = ks;
		edit(&mut ks.tx);
		signed(&c.net, ks, key, vec![]).tx
	};
	let no_issuance = built(c, &s, &|tx| {
		tx.input[0].asset_issuance = AssetIssuance::default();
		tx.output.remove(0);
	});
	c.net.refuse("connector/neg spent with no issuance", &no_issuance, "Script failed an OP_EQUALVERIFY operation");
	let two = built(c, &s, &|tx| {
		tx.input[0].asset_issuance.amount = elements::confidential::Value::Explicit(2);
		tx.output[0].value = elements::confidential::Value::Explicit(2);
	});
	c.net.refuse("connector/neg issuing two atoms of M", &two, "Script failed an OP_EQUALVERIFY operation");
	let entropy = elements::AssetId::generate_asset_entropy(conn.outpoint, elements::ContractHash::from_byte_array([0; 32]));
	let token = elements::AssetId::reissuance_token_from_entropy(entropy, false);
	let reissuable = built(c, &s, &|tx| {
		tx.input[0].asset_issuance.inflation_keys = elements::confidential::Value::Explicit(1);
		tx.output.insert(1, explicit(token, 1, op_true_spk()));
	});
	c.net.refuse("connector/neg issuing M with a reissuance token", &reissuable,
		"Script evaluated without error but finished with a false/empty top stack element");
	let contract = label32("a contract hash");
	let other = elements::AssetId::new_issuance(conn.outpoint, elements::ContractHash::from_byte_array(contract));
	let other_asset = built(c, &s, &|tx| {
		tx.input[0].asset_issuance.asset_entropy = contract;
		tx.output[0].asset = elements::confidential::Asset::Explicit(other);
	});
	c.net.refuse("connector/neg issuing another asset (a contract hash)", &other_asset, "Script failed an OP_EQUALVERIFY operation");
	let by_other = built(c, &keypair("not the operator"), &|_| {});
	c.net.refuse("connector/neg the issuance signed by another key", &by_other, "Invalid Schnorr signature");
	let tx = built(c, &s, &|_| {});
	let it = c.pass("connector/the issuance of M, the connector's own spend", &tx);
	assert_eq!(c.net.rt.client().raw_transaction(&it).unwrap().output[0].asset.explicit(), Some(m));
}

// ---------------------------------------------------------------------------
// 3. Two forfeits of one participation, one forfeit output
// ---------------------------------------------------------------------------

fn no_merge(c: &mut Ctx) {
	let s = keypair("merge operator");
	let x = c.net.x;
	let preimage = label32("merge participation preimage");
	let m = connector_asset(Txid::from_raw_hash(elements::hashes::sha256d::Hash::hash(b"some round")), 2);
	for (label, k1, k2) in [("distinct keys", keypair("merge owner 1"), keypair("merge owner 2")),
		("one key", keypair("merge owner, one key"), keypair("merge owner, one key"))]
	{
		let (l1, c1, id1) = funded_leaf(&mut c.net, &k1, &s, &format!("merge {} leaf 1", label));
		let (l2, c2, id2) = funded_leaf(&mut c.net, &k2, &s, &format!("merge {} leaf 2", label));
		let f1 = Forfeit::new(l1, (x, LEAF), id1, sha256(&preimage), m, delay(), 1_500).unwrap();
		let f2 = Forfeit::new(l2, (x, LEAF), id2, sha256(&preimage), m, delay(), 1_500).unwrap();
		assert_ne!(f1.output().script_pubkey, f2.output().script_pubkey, "the leaf id makes each forfeit output its own");
		let (p1, p2) = (pair(&f1, &k1, &s), pair(&f2, &k2, &s));
		// Both leaves into ONE forfeit output, the second leaf's value to the broadcaster.
		let mut merged = spend(0).coin(&c1, 0xffff_ffff).coin(&c2, 0xffff_ffff).outputs(vec![
			f1.output().txout(), explicit(x, LEAF - 1_500, op_true_spk()), fee(x, 3_000)]);
		merged.witness(0, l1.witness(&p1, 1));
		merged.witness(1, l2.witness(&p2, 1));
		c.net.refuse(&format!("merge/neg two forfeits, {}, one forfeit output", label), &merged.tx, "Invalid Schnorr signature");
		// Each alone confirms.
		c.pass(&format!("merge/the forfeit of leaf 1 alone, {}", label), &f1.tx(c1.outpoint, &p1, &FeeSource::Reserve).unwrap().tx);
		c.pass(&format!("merge/the forfeit of leaf 2 alone, {}", label), &f2.tx(c2.outpoint, &p2, &FeeSource::Reserve).unwrap().tx);
	}
}

// ---------------------------------------------------------------------------
// 4. The offboard
// ---------------------------------------------------------------------------

fn offboard(c: &mut Ctx) {
	let s = keypair("offboard operator");
	let a = keypair("offboard owner, old leaf");
	let x = c.net.x;
	let reclaim = RelativeTime::from_seconds_ceil(5 * DAY).unwrap();
	let dest = ExplicitOutput::new(x, LEAF - 3_000, Script::from({
		let mut v = vec![0x00, 0x14];
		v.extend(&label32("the owner's on-chain address")[..20]);
		v
	}));
	let reserve = 1_000;
	let h = |l: &str| sha256(&label32(l));
	let off = |l: &str| OffboardPolicy { unlock_hash: h(l), destination: dest.clone(), operator: xonly(&s), reclaim_delay: reclaim };
	let (oa, ob, oc, od) = (off("offboard a"), off("offboard b"), off("offboard c"), off("offboard d"));
	let issuer = c.net.fund(vec![explicit(x, 1_000_000_000, op_true_spk())]).remove(0);
	let (round, cv) = round_tx(&c.net, &issuer, None, vec![oa.output(reserve).txout(), ob.output(reserve).txout(),
		oc.output(reserve).txout(), od.output(reserve).txout()], &s);
	let rt = c.pass("offboard/a round with four offboard outputs to one destination", &round);
	let round = c.net.rt.client().raw_transaction(&rt).unwrap();
	let at = |p: &OffboardPolicy| coin_of(rt, p.find(&round).unwrap(), &round);
	let (ca, cb, cc, cd) = (at(&oa), at(&ob), at(&oc), at(&od));

	// The owner gives up its old leaf against h_a, for this round.
	let (old, old_coin, old_id) = funded_leaf(&mut c.net, &a, &s, "offboard old leaf");
	let f = Forfeit::for_offboard(old, (x, LEAF), old_id, &oa, &round, cv, delay(), 1_500).unwrap();
	assert_eq!(f.policy.connector, connector_asset(rt, cv));
	let ft = c.pass("offboard/the forfeit against h_a", &f.tx(old_coin.outpoint, &pair(&f, &a, &s), &FeeSource::Reserve).unwrap().tx);
	let m_coin = issue_connector(c, "offboard/the issuance of the connector asset M", &round, rt, cv, &s);
	let ct = c.pass("offboard/the operator's claim, publishing the preimage",
		&claim_tx(&c.net, &f, OutPoint::new(ft, 0), &m_coin, &s, &label32("offboard a"), 1));
	let pre_a = find_preimage(&c.net.witness_of(&ct, 0), &oa.unlock_hash).unwrap();

	// Anyone with the preimage moves the output to the destination; nobody
	// can move it elsewhere.
	let v = oa.output(reserve).value;
	let unlock = |p: &OffboardPolicy, coin: &Coin, pre: &[u8; 32], out: ExplicitOutput| {
		let mut s = spend(0).coin(coin, 0xffff_ffff).outputs(vec![out.txout(), fee(x, v - out.value)]);
		s.witness(0, p.unlock_witness(pre));
		s.tx
	};
	c.net.refuse("offboard/neg the unlock with a wrong preimage", &unlock(&oa, &ca, &label32("wrong"), dest.clone()),
		"Script failed an OP_EQUALVERIFY operation");
	c.net.refuse("offboard/neg the unlock into another script", &unlock(&oa, &ca, &pre_a,
		ExplicitOutput::new(x, dest.value, op_true_spk())), "Script evaluated without error but finished with a false/empty top stack element");
	c.net.refuse("offboard/neg the unlock one atom short", &unlock(&oa, &ca, &pre_a,
		ExplicitOutput::new(x, dest.value - 1, dest.script_pubkey.clone())), "Script evaluated without error but finished with a false/empty top stack element");
	// Two offboards to one destination: one output cannot stand for both.
	let pre_b = label32("offboard b");
	let mut two = spend(0).coin(&ca, 0xffff_ffff).coin(&cb, 0xffff_ffff).outputs(vec![
		dest.txout(), explicit(x, dest.value, op_true_spk()), fee(x, 2 * v - 2 * dest.value)]);
	two.witness(0, oa.unlock_witness(&pre_a));
	two.witness(1, ob.unlock_witness(&pre_b));
	c.net.refuse("offboard/neg two offboards to one destination, paid once", &two.tx,
		"Script evaluated without error but finished with a false/empty top stack element");
	let mut both = spend(0).coin(&ca, 0xffff_ffff).coin(&cb, 0xffff_ffff).outputs(vec![
		dest.txout(), dest.txout(), fee(x, 2 * v - 2 * dest.value)]);
	both.witness(0, oa.unlock_witness(&pre_a));
	both.witness(1, ob.unlock_witness(&pre_b));
	c.pass("offboard/two offboards unlocked in one transaction, each paid at its index", &both.tx);
	// One unlock as the builder makes it, by a third party paying the fee
	// with its own coin and taking the output's margin as change.
	let fc = c.net.fee_coin();
	let mut u = od.unlock_tx(cd.outpoint, v, &label32("offboard d"), &FeeSource::Coin {
		outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 4_000, change: op_true_spk(),
	}).unwrap();
	u.tx.input[1].witness.script_witness = op_true_witness();
	c.pass("offboard/an unlock by a third party, its own fee coin attached", &u.tx);
	let u = od.unlock_tx(cd.outpoint, v, &label32("offboard d"), &FeeSource::Reserve).unwrap();
	c.net.refuse("offboard/neg the same output unlocked again", &u.tx, "bad-txns-inputs-missingorspent");

	// The third offboard's preimage never comes: the operator reclaims it
	// after the delay, and nobody else can.
	let rec = |c: &Ctx, key: &Keypair| {
		let ks = oc.reclaim(cc.outpoint, v, &[ExplicitOutput::new(x, v - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
		signed(&c.net, ks, key, vec![]).tx
	};
	c.net.refuse("offboard/neg the reclaim before the delay", &rec(c, &s), "non-BIP68-final");
	c.net.wait_csv(&rt, reclaim);
	c.net.refuse("offboard/neg the reclaim by another key", &rec(c, &a), "Invalid Schnorr signature");
	c.pass("offboard/the operator's reclaim after the delay", &rec(c, &s));
}

// ---------------------------------------------------------------------------
// 5. A chain three hops deep, received and exited by the last receiver
// ---------------------------------------------------------------------------

/// A round for a batch in `tree`'s asset, which may differ from X: the
/// issuer (X) issues the token; a coin of the batch asset funds the batch.
fn asset_round(c: &mut Ctx, name: &str, issuer: &Coin, tree: &Tree) -> Transaction {
	let x = c.net.x;
	let a = tree.params().asset;
	let batch = tree.batch_output();
	let fund = c.net.fund(vec![explicit(a, batch.value + 1_000, op_true_spk())]).remove(0);
	let total = issuer.txout.value.explicit().unwrap();
	let mut s = spend(0).coin(issuer, 0xffff_ffff).coin(&fund, 0xffff_ffff).outputs(vec![
		batch.txout(), explicit(tree.params().schedule.token, 1, tree.clock0_script_pubkey()),
		explicit(x, 5_000, op_true_spk()), explicit(a, 1_000, op_true_spk()),
		explicit(x, total - 5_000 - 2_000, op_true_spk()), fee(x, 2_000),
	]);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	s.witness(0, op_true_witness());
	s.witness(1, op_true_witness());
	let txid = c.pass(name, &s.tx);
	c.net.rt.client().raw_transaction(&txid).unwrap()
}

/// How a transaction moving value of `asset` pays its fee: from its margin
/// when the node accepts the asset for fees, else with an outside coin.
fn fee_for(c: &mut Ctx, asset: elements::AssetId) -> FeeSource {
	if asset == c.net.x {
		FeeSource::Reserve
	} else {
		let fc = c.net.fee_coin();
		FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() }
	}
}

/// Completes the fee coin's witness, if one was attached at `at`.
fn with_coin(mut u: UnrollTx, at: usize) -> Transaction {
	if u.tx.input.len() > at {
		u.tx.input[at].witness.script_witness = op_true_witness();
	}
	u.tx
}

/// Where [`bring`] stops to let a test act.
enum Event<'a> {
	/// An input coin is on-chain at the outpoint, before its checkpoint.
	Coin(&'a ValidCoin, OutPoint),
	/// The checkpoints of `coin`'s reassignment are on-chain, before it.
	Checkpoints(&'a ValidCoin, &'a [OutPoint]),
}

/// Brings `coin` on-chain from its record, paying each fee as `fee_for`
/// says; returns where it lands. `hook` sees each [`Event`].
fn bring(c: &mut Ctx, coin: &ValidCoin, label: &str, hook: &mut dyn FnMut(&mut Ctx, Event)) -> OutPoint {
	match &coin.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => {
			let mut at = OutPoint::new(valid.round_txid, valid.batch_vout);
			for (level, (node, auth)) in valid.branch.nodes.iter().zip(auths).enumerate() {
				let fs = fee_for(c, coin.asset);
				let u = node.unroll_tx(at, auth, &fs).unwrap();
				let id = c.pass(&format!("chain/{}: unroll, level {}", label, level), &with_coin(u, 1));
				at = OutPoint::new(id, node.index as u32);
			}
			let fs = fee_for(c, coin.asset);
			let e = valid.branch.entry_tx(at, preimage, &fs).unwrap();
			let id = c.pass(&format!("chain/{}: entry into the leaf", label), &with_coin(e, 1));
			OutPoint::new(id, 0)
		},
		ValidOrigin::Transfer { inputs, index, outputs } => {
			let mut cps = vec![];
			for (k, i) in inputs.iter().enumerate() {
				let at = bring(c, &i.coin, &format!("{}.{}", label, k), hook);
				hook(c, Event::Coin(&i.coin, at));
				let fs = fee_for(c, i.coin.asset);
				let cp = i.checkpoint_tx(at, &fs).unwrap();
				let id = c.pass(&format!("chain/{}: checkpoint of input {}", label, k), &with_coin(cp, 1));
				cps.push(OutPoint::new(id, 0));
			}
			// The margin is in one asset when the signers left it so; the
			// asset of the coin at `index` decides who pays.
			let margin_assets: Vec<_> = inputs.iter().map(|i| i.coin.asset).filter(|a| {
				let held: u64 = inputs.iter().filter(|i| i.coin.asset == *a).map(|i| i.checkpoint_value).sum();
				let out: u64 = outputs.iter().filter(|o| o.asset == *a).map(|o| o.value).sum();
				held > out
			}).collect();
			hook(c, Event::Checkpoints(coin, &cps));
			let fs = if margin_assets.iter().all(|a| *a == c.net.x) { FeeSource::Reserve } else { fee_for(c, outputs[*index].asset) };
			let re = coin.reassignment_tx(&cps, &fs).unwrap();
			let n = inputs.len();
			let id = c.pass(&format!("chain/{}: reassignment", label), &with_coin(re, n));
			OutPoint::new(id, *index as u32)
		},
		ValidOrigin::Board { .. } => unreachable!("the chain has no board"),
	}
}

fn transfer_chain(c: &mut Ctx) {
	let s = keypair("chain operator");
	let x = c.net.x;
	let (i1, sched1) = c.schedule(&s);
	let (i2, sched2) = c.schedule(&s);
	let b = batches(c.net.chain, x, c.net.y, s, sched1, sched2, delay(),
		ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 });
	let r1 = asset_round(c, "chain/round of batch 1, in X", &i1, &b.batch1);
	let r2 = asset_round(c, "chain/round of batch 2, in Y (not accepted for fees)", &i2, &b.batch2);
	let rounds = vec![r1, r2];
	let policy = c.policy(&s);
	let t = mt(c.net.mtp() - 60);
	let h = hops(&b, &rounds, &policy, t, delay());

	// D holds its record alone, as bytes from its mailbox, and the rounds as
	// the chain has them.
	let bytes = h.d_record.to_bytes().unwrap();
	let rec = CoinRecord::from_bytes(&bytes).unwrap();
	let coin = rec.validate(&rounds, &c.policy(&s), &h.d.leaf.owner, &h.d.leaf.owner_nonce).unwrap();
	println!("chain: D validates a {}-byte record, {} hops, coin {} of {} atoms of Y", bytes.len(), coin.hops, coin.id, coin.value);

	// Negative cases on the hop-1 input, once A's leaf is on-chain: the
	// reassignment's pair on the leaf, skipping the checkpoint.
	let hop1 = match &coin.origin { ValidOrigin::Transfer { inputs, .. } => inputs[0].coin.clone(), _ => unreachable!() };
	let hop2 = match &hop1.origin { ValidOrigin::Transfer { inputs, outputs, .. } => (inputs.clone(), outputs.clone()), _ => unreachable!() };
	let hop1_input = match &hop2.0[0].coin.origin { ValidOrigin::Transfer { inputs, outputs, .. } => (inputs[0].clone(), outputs.clone()), _ => unreachable!() };
	let a_key = b.a;
	let mut seen_a = false;
	let mut stale: Option<Transaction> = None;
	let mut seen_swap = false;
	let swap_id = hop1.id;
	let mut hook = |c: &mut Ctx, ev: Event| {
		let (inner, at) = match ev {
			Event::Coin(inner, at) => (inner, at),
			Event::Checkpoints(made, cps) => {
				if seen_swap || made.id != swap_id {
					return;
				}
				seen_swap = true;
				let (inputs, outputs) = match &made.origin { ValidOrigin::Transfer { inputs, outputs, .. } => (inputs, outputs), _ => unreachable!() };
				// A checkpoint's own pair on the checkpoint output: an outside
				// coin pays the fee, so the script is what refuses it.
				let i = &inputs[0];
				let fc = c.net.fee_coin();
				let again = collab_tx(&i.checkpoint, cps[0], i.coin.asset, i.checkpoint_value, &[i.checkpoint_output()],
					&i.checkpoint_pair, &FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() }).unwrap();
				c.net.refuse("chain/neg the checkpoint's pair on the checkpoint", &with_coin(again, 1), "Invalid Schnorr signature");
				// The swap's outputs from B's input alone, nothing paying C's
				// side: refused because the values do not balance, not by a
				// script. B's pair signs the outputs, never the other input, so
				// a third party who funds C's side makes the same swap confirm
				// with one leaf (the specification's limit 2).
				let alone = arca_covenant::transfer::reassignment_tx(&inputs[..1], outputs, &cps[..1], &FeeSource::Reserve);
				assert!(alone.is_err(), "the builder refuses to make it");
				let mut s = spend(0).coin(&Coin { outpoint: cps[0], txout: i.checkpoint_output().txout() }, 0xffff_ffff)
					.outputs(outputs.iter().map(|o| o.txout()).collect());
				s.witness(0, i.checkpoint.witness(&i.reassignment_pair, outputs.len() as u8));
				c.net.refuse("chain/neg the swap's outputs from B's input alone, unfunded", &s.tx, "bad-txns-in-ne-out");
				return;
			},
		};
		if seen_a || inner.id != hop1_input.0.coin.id {
			return;
		}
		seen_a = true;
		let (i, outs) = &hop1_input;
		let skip = collab_tx(&i.coin.leaf, at, i.coin.asset, i.coin.value, outs, &i.reassignment_pair, &FeeSource::Reserve).unwrap();
		c.net.refuse("chain/neg the reassignment's pair on the leaf, skipping the checkpoint", &skip.tx, "Invalid Schnorr signature");
		// A, the sender, holds its leaf now; its exit waits the delay, and the
		// receiver answers first with the checkpoint (below).
		let ks = i.coin.leaf.exit_tx(at, i.coin.asset, i.coin.value,
			&[ExplicitOutput::new(i.coin.asset, i.coin.value - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
		let ex = signed(&c.net, ks, &a_key, vec![]);
		c.net.refuse("chain/neg the sender's exit before its delay", &ex.tx, "non-BIP68-final");
		stale = Some(ex.tx);
	};
	let at = bring(c, &coin, "D", &mut hook);

	// After the receiver published the checkpoint, the sender's exit has no
	// coin to spend.
	let stale = stale.expect("A's leaf came on-chain");
	c.net.refuse("chain/neg the sender's exit after the receiver's checkpoint", &stale, "bad-txns-inputs-missingorspent");

	// D exits after the delay, with an outside fee coin: Y pays no fees here.
	let exit = |c: &mut Ctx| {
		let fs = fee_for(c, coin.asset);
		let ks = coin.leaf.exit_tx(at, coin.asset, coin.value, &[ExplicitOutput::new(coin.asset, coin.value, op_true_spk())], &fs).unwrap();
		let mut u = signed(&c.net, ks, &h.d.key, vec![]);
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	};
	let tx = exit(c);
	c.net.refuse("chain/neg D's exit before the delay", &tx, "non-BIP68-final");
	c.net.wait_csv(&at.txid, delay());
	let tx = exit(c);
	c.pass("chain/D's exit after the delay, a fee coin attached", &tx);
	let _ = hop2;
}

#[test]
fn offchain_transactions_on_regtest() {
	let net = Net::start();
	let info = net.rpc("getmempoolinfo", json!([]));
	let floor_per_kvb = (info["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
	let mut c = Ctx { net, sizes: vec![], floor_per_kvb };
	board_and_refresh(&mut c);
	connector(&mut c);
	no_merge(&mut c);
	offboard(&mut c);
	transfer_chain(&mut c);
	c.net.print();
	println!("\n{:<96} specification", "transaction");
	for (n, s) in &c.sizes {
		println!("{:<96} {}", n, s);
	}
}
