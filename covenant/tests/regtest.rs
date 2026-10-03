//! The frozen constructions on a Sequentia regtest chain.
//!
//! Every transaction here is built with this crate and broadcast to a node on
//! an anchored `elementsregtest` chain (`sequentia_ext::regtest`). A spend that
//! should confirm must pass `testmempoolaccept`, be broadcast and be mined. A
//! negative case must be refused by `testmempoolaccept`, by
//! `sendrawtransaction`, and again when forced into a block with
//! `generateblock`; relay policy can hide a consensus flaw, so no negative rests
//! on the mempool alone.
//!
//! The six runs close what the regtest prototype left open:
//!
//! 1. the checkpoint and reassignment chain, signed before the round exists,
//!    on the frozen message, with reserve fees and with outside fee coins;
//! 2. the forfeit and the entry it releases, and the abort path;
//! 3. `htlc-1`'s four paths, and the receiving direction;
//! 4. the swap of two leaves in two assets in one transaction;
//! 5. the hash-locked entry's sweep behind the token and the notice;
//! 6. the burn-only sweep behind the token;
//! 7. a 17-leaf and a 64-leaf batch built by the tree builder, with reserves
//!    at four times the node's own relay floor: every leaf's record checked
//!    against the confirmed round, and three leaves in different subtrees
//!    unrolled from their records, unlocked and exited, one of them with fee
//!    coins attached; their sizes are printed beside the prototype's.
//!
//! Locks are time based, as the specification requires: the exit delay, the
//! forfeit's refund delay and the notice `W` are 36 hours, and median time is
//! moved with `setmocktime`. Needs `SEQUENTIAD_EXEC`; run with `--nocapture`
//! to see every transaction's size and every refusal.

mod common;

use std::collections::HashMap;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use arca_covenant::htlc::HtlcPath;
use arca_covenant::script::sha256;
use arca_covenant::witness::find_preimage;
use arca_covenant::*;

use common::net::*;
use common::*;

const LEAF: u64 = 10_000_000;
const ENTRY_RESERVE: u64 = 1_000;
const NODE_RESERVE: u64 = 3_000;
const FEE: u64 = 1_500;
// ---------------------------------------------------------------------------
// A batch: leaves, their entries, lowest nodes and the batch output
// ---------------------------------------------------------------------------

struct Batch {
	owners: Vec<Keypair>,
	leaves: Vec<LeafPolicy>,
	preimages: Vec<[u8; 32]>,
	entries: Vec<EntryPolicy>,
	lowest: Vec<NodePolicy>,
	root: NodePolicy,
	schedule: ClockSchedule,
}

impl Batch {
	/// Sixteen leaves of `x` under four lowest nodes, each leaf behind its
	/// hash-locked entry; every sweep behind the schedule's token, burn-only
	/// when `burn`.
	fn new(net: &Net, label: &str, s: &Keypair, schedule: ClockSchedule, burn: bool) -> Batch {
		let owners: Vec<Keypair> = (0..16).map(|i| keypair(&format!("{} owner {}", label, i))).collect();
		let leaves: Vec<LeafPolicy> = owners.iter().enumerate()
			.map(|(i, o)| net.leaf(o, s, &format!("{} leaf {}", label, i))).collect();
		let preimages: Vec<[u8; 32]> = (0..16).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
		let entries: Vec<EntryPolicy> = (0..16).map(|i| EntryPolicy {
			unlock_hash: sha256(&preimages[i]), asset: net.x, value: LEAF, leaf_program: leaves[i].program(),
			sweep: schedule.sweep(true, burn),
		}).collect();
		let entry_value = LEAF + ENTRY_RESERVE;
		let lowest: Vec<NodePolicy> = (0..4).map(|j| {
			let children = (0..4).map(|i| Child::new(net.x, entry_value, entries[4 * j + i].taproot().program())).collect();
			let ow = (0..4).map(|i| xonly(&owners[4 * j + i])).collect();
			NodePolicy::new(children, xonly(s), ow, schedule.sweep(true, burn), Some(net.chain)).unwrap()
		}).collect();
		let lowest_value = 4 * entry_value + NODE_RESERVE;
		let children = lowest.iter().map(|n| Child::new(net.x, lowest_value, n.taproot().program())).collect();
		let root = NodePolicy::new(children, xonly(s), owners.iter().map(xonly).collect(), schedule.sweep(false, burn), None).unwrap();
		Batch { owners, leaves, preimages, entries, lowest, root, schedule }
	}

	fn value(&self) -> u64 {
		4 * (4 * (LEAF + ENTRY_RESERVE) + NODE_RESERVE) + NODE_RESERVE
	}

	/// The sweep paths above leaf `i`: the batch output's, its lowest node's
	/// and its entry's.
	fn sweeps_above(&self, i: usize) -> Vec<Sweep> {
		vec![*self.root.sweep(), *self.lowest[i / 4].sweep(), self.entries[i].sweep]
	}
}

/// The round: it spends an operator coin of `x` that also issues the token,
/// pays the batch output at 0 and one atom of the token to clock 0 at 1. Its
/// lock time is 0, so it returns to the mempool after a rollback.
struct RoundOut {
	batch: Coin,
	token: Coin,
}

fn round(net: &mut Net, name: &str, issuer: Coin, batch: &Batch) -> RoundOut {
	let total = issuer.txout.value.explicit().unwrap();
	let token = batch.schedule.token;
	assert_eq!(token, token_of(&issuer));
	let mut s = spend(0).coin(&issuer, 0xffff_ffff).outputs(vec![
		explicit(net.x, batch.value(), batch.root.script_pubkey()),
		explicit(token, 1, batch.schedule.clock0_script_pubkey()),
		explicit(net.x, total - batch.value() - 2_000, op_true_spk()),
		fee(net.x, 2_000),
	]);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	s.witness(0, op_true_witness());
	// What a wallet runs before it accepts a leaf of this batch.
	for i in [0, 5, 15] {
		let sweeps = batch.sweeps_above(i);
		check_round(&s.tx, &batch.schedule, &sweeps[0], &sweeps[1..]).unwrap();
	}
	let txid = net.pass(name, &s.tx);
	net.purse.push(coin_of(txid, 2, &s.tx));
	RoundOut { batch: coin_of(txid, 0, &s.tx), token: coin_of(txid, 1, &s.tx) }
}

/// An unroll of `node` held at `coin`, by `signer`'s authorisation for `t`.
/// With a fee coin the broadcaster pays and takes the reserve as change.
fn unroll(net: &Net, node: &NodePolicy, coin: &Coin, signer: &Keypair, t: u64, fee_coin: Option<&Coin>) -> Transaction {
	let auth = node.unroll_authorisation(mt(t));
	let w = node.unroll_witness(&sig(signer, &auth.digest), mt(t), &xonly(signer)).unwrap();
	let mut s = spend(t as u32).coin(coin, 0xffff_fffe).outputs(node.child_outputs());
	let value = coin.txout.value.explicit().unwrap();
	let kids: u64 = node.children().iter().map(|c| c.value).sum();
	match fee_coin {
		None => s = s.output(fee(net.x, value - kids)),
		Some(fc) => {
			s = s.coin(fc, 0xffff_fffe).outputs(vec![explicit(net.x, value - kids, op_true_spk()),
				explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
			s.witness(1, op_true_witness());
		},
	}
	s.witness(0, w);
	s.tx
}

fn children(txid: Txid, tx: &Transaction, n: usize) -> Vec<Coin> {
	(0..n).map(|i| coin_of(txid, i as u32, tx)).collect()
}

/// The unlock of entry `i` into its leaf.
fn unlock(net: &Net, b: &Batch, i: usize, coin: &Coin, preimage: &[u8; 32], to: Option<Script>, value: u64) -> Transaction {
	let e = &b.entries[i];
	let spk = to.unwrap_or_else(|| b.leaves[i].script_pubkey());
	let mut s = spend(0).coin(coin, 0xffff_ffff)
		.outputs(vec![explicit(net.x, value, spk), fee(net.x, LEAF + ENTRY_RESERVE - value)]);
	s.witness(0, e.unlock_witness(preimage));
	s.tx
}

/// Roll or release of clock `j`, built by `ClockSchedule::roll_tx` or
/// `release_tx`, an operator fee coin paying the fee. A release's lock time
/// is the clock's expiry; `lock` replaces it, for the negative cases.
#[allow(clippy::too_many_arguments)]
fn clock_move(net: &Net, s_key: &Keypair, sched: &ClockSchedule, j: usize, roll: bool, token: &Coin, fc: &Coin, lock: u32) -> Transaction {
	let fee = FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 4_000, change: op_true_spk() };
	let mut ks = if roll { sched.roll_tx(j, token.outpoint, &fee) } else { sched.release_tx(j, token.outpoint, &fee) }.unwrap();
	if !roll {
		ks.tx.lock_time = elements::LockTime::from_consensus(lock);
	}
	let sg = sig(s_key, &ks.sighash(net.genesis).unwrap());
	let mut tx = ks.finish(Clock::witness_items(&sg)).tx;
	tx.input[1].witness.script_witness = op_true_witness();
	tx
}

/// One wave of a sweep built by `sweep_tx`: `swept` behind the token at `R`
/// held at `token`, paying `to` with the swept outputs' margin as the fee, or
/// (a burn-only sweep, `to` empty) an operator fee coin paying.
fn built_sweep(net: &mut Net, s_key: &Keypair, sched: &ClockSchedule, swept: &[Sweepable], token: &Coin, to: &[ExplicitOutput]) -> Transaction {
	let burn = swept[0].sweep.burn;
	let fee = if burn {
		let fc = net.fee_coin();
		FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 5_000, change: op_true_spk() }
	} else {
		FeeSource::Reserve
	};
	let sw = sweep_tx(sched, token.outpoint, swept, to, &fee).unwrap();
	let sigs: Vec<_> = (0..sw.leaves.len()).map(|i| sig(s_key, &sw.sighash(i, net.genesis).unwrap())).collect();
	let n = sw.leaves.len();
	let mut tx = sw.finish(&sigs).unwrap().tx;
	if burn {
		tx.input[n].witness.script_witness = op_true_witness();
	}
	tx
}

fn r_sign(net: &Net, s_key: &Keypair, sched: &ClockSchedule, s: &mut Spend, idx: usize) {
	let script = sched.r_script();
	let sg = s.sign(s_key, idx, &script, net.genesis);
	s.witness(idx, sched.r().witness(&script, ClockSchedule::r_witness_items(&sg)));
}

// ---------------------------------------------------------------------------
// 1. The checkpoint and reassignment chain
// ---------------------------------------------------------------------------

fn checkpoint_chain(net: &mut Net, external: bool) {
	let tag = if external { "chain, outside fee coins" } else { "chain, reserve fees" };
	let s_key = keypair(&format!("{} operator", tag));
	let created = net.mtp() - 60;
	let issuer = net.fund(vec![explicit(net.x, 1_000_000_000, op_true_spk())]).remove(0);
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(),
		vec![mt(net.now() + 28 * 24 * H as u64)]).unwrap();
	let b = Batch::new(net, tag, &s_key, sched.clone(), false);
	let i = 5;
	let a = &b.owners[i];
	let receiver = keypair(&format!("{} receiver", tag));
	let leaf = b.leaves[i];

	// Every collaborative signature is made now, before the round exists.
	let margin = if external { 0 } else { FEE };
	let cp = CheckpointPolicy { owner: xonly(a), operator: xonly(&s_key), salt: label32(&format!("{} checkpoint", tag)),
		chain: net.chain, sweep: sched.sweep(true, false) };
	let v_cp = LEAF - margin;
	let cp_out = ExplicitOutput::new(net.x, v_cp, cp.script_pubkey());
	let m1 = leaf.collab_message(net.x, LEAF, std::slice::from_ref(&cp_out)).unwrap();
	let recv_leaf = net.leaf(&receiver, &s_key, &format!("{} receiver leaf", tag));
	let chg_leaf = net.leaf(a, &s_key, &format!("{} change leaf", tag));
	let v_recv = 7_000_000;
	let re = vec![ExplicitOutput::new(net.x, v_recv, recv_leaf.script_pubkey()),
		ExplicitOutput::new(net.x, v_cp - v_recv - margin, chg_leaf.script_pubkey())];
	let m2 = cp.collab_message(net.x, v_cp, &re).unwrap();
	let cp_sigs = (sig(&s_key, &m1.digest), sig(a, &m1.digest));
	let re_sigs = (sig(&s_key, &m2.digest), sig(a, &m2.digest));

	// The round, then the path to leaf 5: batch output, lowest node 1, entry 5.
	let r = round(net, &format!("{}/round", tag), issuer, &b);
	let fc = if external { Some(net.fee_coin()) } else { None };
	let tx = unroll(net, &b.root, &r.batch, a, created, fc.as_ref());
	let rt = net.pass(&format!("{}/batch output unroll", tag), &tx);
	let lowest = children(rt, &tx, 4);
	let fc = if external { Some(net.fee_coin()) } else { None };
	let tx = unroll(net, &b.lowest[1], &lowest[1], a, created, fc.as_ref());
	let lt = net.pass(&format!("{}/lowest node unroll", tag), &tx);
	let entries = children(lt, &tx, 4);
	let tx = unlock(net, &b, i, &entries[1], &b.preimages[i], None, LEAF);
	let et = net.pass(&format!("{}/entry unlock into the leaf", tag), &tx);
	let leaf_coin = coin_of(et, 0, &tx);

	let collab = |net: &mut Net, coin: &Coin, w: Vec<Vec<u8>>, outs: &[ExplicitOutput]| -> Transaction {
		let value = coin.txout.value.explicit().unwrap();
		let committed: u64 = outs.iter().map(|o| o.value).sum();
		let mut s = spend(0).coin(coin, 0xffff_ffff).outputs(outs.iter().map(|o| o.txout()).collect());
		if external {
			let fc = net.fee_coin();
			s = s.coin(&fc, 0xffff_ffff).outputs(vec![
				explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
			if value > committed {
				s = s.output(explicit(net.x, value - committed, op_true_spk()));
			}
			s.witness(1, op_true_witness());
		} else {
			s = s.output(fee(net.x, value - committed));
		}
		s.witness(0, w);
		s.tx
	};
	let tx = collab(net, &leaf_coin, leaf.collab_witness(&re_sigs.0, &re_sigs.1, 2), &re);
	net.refuse(&format!("{}/neg the reassignment's signatures on the leaf", tag), &tx, "Invalid Schnorr signature");
	let tx = collab(net, &leaf_coin, leaf.collab_witness(&cp_sigs.0, &cp_sigs.1, 1), std::slice::from_ref(&cp_out));
	let ct = net.pass(&format!("{}/checkpoint", tag), &tx);
	let cp_coin = coin_of(ct, 0, &tx);
	// The checkpoint's own pair on the checkpoint output: an outside coin pays
	// the fee, so the script is what refuses it.
	let fc = net.fee_coin();
	let mut s = spend(0).coin(&cp_coin, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(vec![cp_out.txout(),
		explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
	s.witness(0, cp.collab_witness(&cp_sigs.0, &cp_sigs.1, 1));
	s.witness(1, op_true_witness());
	net.refuse(&format!("{}/neg the checkpoint's signatures on the checkpoint", tag), &s.tx, "Invalid Schnorr signature");
	let tx = collab(net, &cp_coin, cp.collab_witness(&re_sigs.0, &re_sigs.1, 2), &re);
	let at = net.pass(&format!("{}/reassignment", tag), &tx);
	let recv_coin = coin_of(at, 0, &tx);
	assert_eq!(recv_coin.txout.script_pubkey, recv_leaf.script_pubkey());

	// The receiver exits alone after the delay.
	let exit = |net: &mut Net| -> Transaction {
		let mut s = spend(0).coin(&recv_coin, delay().to_sequence())
			.outputs(vec![explicit(net.x, v_recv - FEE, op_true_spk()), fee(net.x, FEE)]);
		let sg = s.sign(&receiver, 0, &recv_leaf.exit_script(), net.genesis);
		s.witness(0, recv_leaf.exit_witness(&sg));
		s.tx
	};
	let tx = exit(net);
	net.refuse(&format!("{}/neg the receiver's exit before the delay", tag), &tx, "non-BIP68-final");
	net.wait_csv(&at, delay());
	let tx = exit(net);
	net.pass(&format!("{}/the receiver's exit after the delay", tag), &tx);
}

// ---------------------------------------------------------------------------
// 2. The forfeit
// ---------------------------------------------------------------------------

fn forfeit(net: &mut Net) {
	let s_key = keypair("forfeit operator");
	let a = keypair("forfeit owner");
	let sched = ClockSchedule::new(asset("forfeit token"), xonly(&s_key), delay(), vec![mt(net.now() + 28 * 24 * H as u64)]).unwrap();
	// The round's connector output, and the asset M spending it issues.
	let conn_policy = ConnectorPolicy { operator: xonly(&s_key) };
	let connector = net.fund(vec![conn_policy.output(net.x, 5_000).txout()]).remove(0);
	let m = connector_asset(connector.outpoint.txid, connector.outpoint.vout);
	let run = |net: &mut Net, label: &str| {
		let old = net.leaf(&a, &s_key, &format!("forfeit old leaf {}", label));
		let new = net.leaf(&a, &s_key, &format!("forfeit new leaf {}", label));
		let preimage = label32(&format!("forfeit preimage {}", label));
		let entry = EntryPolicy { unlock_hash: sha256(&preimage), asset: net.x, value: LEAF, leaf_program: new.program(),
			sweep: sched.sweep(true, false) };
		let f = ForfeitPolicy {
			unlock_hash: sha256(&preimage), owner: xonly(&a), operator: xonly(&s_key), refund_delay: delay(),
			leaf_id: LeafId(label32(&format!("forfeit old leaf id {}", label))), connector: m,
		};
		let coins = net.fund(vec![explicit(net.x, LEAF, old.script_pubkey()),
			explicit(net.x, LEAF + ENTRY_RESERVE, entry.script_pubkey())]);
		(old, new, preimage, entry, f, coins[0].clone(), coins[1].clone())
	};

	// The refresh completes.
	let (old, new, preimage, entry, f, old_coin, entry_coin) = run(net, "happy");
	let f_out = ExplicitOutput::new(net.x, LEAF - FEE, f.script_pubkey());
	let msg = old.collab_message(net.x, LEAF, std::slice::from_ref(&f_out)).unwrap();
	let x = net.x;
	let forfeit_tx = |sa: Vec<u8>| {
		let mut s = spend(0).coin(&old_coin, 0xffff_ffff).outputs(vec![f_out.txout(), fee(x, FEE)]);
		let mut w = old.collab_witness(&sig(&s_key, &msg.digest), &sig(&a, &msg.digest), 1);
		w[1] = sa;
		s.witness(0, w);
		s.tx
	};
	let tx = unlock_entry(net, &entry, &entry_coin, &label32("not the preimage"), new.script_pubkey(), LEAF);
	net.refuse("forfeit/neg the entry without the preimage", &tx, "Script failed an OP_EQUALVERIFY operation");
	net.refuse("forfeit/neg the forfeit without the owner", &forfeit_tx(vec![]), "Script failed an OP_CHECKSIGVERIFY operation");
	let ft = net.pass("forfeit/forfeit (the old leaf by its collaborative path)", &forfeit_tx(sig(&a, &msg.digest).as_ref().to_vec()));
	let f_coin = Coin { outpoint: OutPoint::new(ft, 0), txout: f_out.txout() };
	// The operator issues M by spending the round's connector output.
	let ks = conn_policy.issuance(connector.outpoint, (net.x, 5_000), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
	let sg = sig(&s_key, &ks.sighash(net.genesis).unwrap());
	let iss = ks.finish(vec![sg.as_ref().to_vec()]);
	let it = net.pass("forfeit/the issuance of the connector asset M", &iss.tx);
	let m_coin = coin_of(it, 0, &iss.tx);
	let claim = |net: &Net, pre: &[u8; 32], key: Option<&Keypair>| {
		let mut s = spend(0).coin(&f_coin, 0xffff_ffff).coin(&m_coin, 0xffff_ffff).outputs(vec![
			explicit(net.x, LEAF - 2 * FEE, op_true_spk()), explicit(m, 1, op_true_spk()), fee(net.x, FEE)]);
		let sc = f.claim_script();
		let sg = key.map(|k| s.sign(k, 0, &sc, net.genesis)).map(|g| g.as_ref().to_vec()).unwrap_or_default();
		let mut items = ForfeitPolicy::claim_items(&sig(&s_key, &[0; 32]), pre, 1);
		items[0] = sg;
		s.witness(0, f.taproot().witness(&sc, items));
		s.witness(1, op_true_witness());
		s.tx
	};
	let refund = |net: &Net, coin: &Coin| {
		let mut s = spend(0).coin(coin, delay().to_sequence()).outputs(vec![explicit(net.x, LEAF - 2 * FEE, op_true_spk()), fee(net.x, FEE)]);
		let sg = s.sign(&a, 0, &f.refund_script(), net.genesis);
		s.witness(0, f.refund_witness(&sg));
		s.tx
	};
	net.refuse("forfeit/neg claim with a wrong preimage", &claim(net, &label32("wrong"), Some(&s_key)), "Script failed an OP_EQUALVERIFY operation");
	net.refuse("forfeit/neg claim with the preimage, not by the operator", &claim(net, &preimage, Some(&a)), "Invalid Schnorr signature");
	net.refuse("forfeit/neg claim with the preimage and no signature", &claim(net, &preimage, None), "Script evaluated without error but finished with a false/empty top stack element");
	net.refuse("forfeit/neg the owner's refund before the delay", &refund(net, &f_coin), "non-BIP68-final");
	let ct = net.pass("forfeit/the operator's claim, publishing the preimage", &claim(net, &preimage, Some(&s_key)));
	// The owner learns the preimage from the chain and unlocks the new entry.
	let learned = find_preimage(&net.witness_of(&ct, 0), &entry.unlock_hash).expect("the claim reveals the preimage");
	assert_eq!(learned, preimage);
	let tx = unlock_entry(net, &entry, &entry_coin, &learned, op_true_spk(), LEAF);
	net.refuse("forfeit/neg the entry into another script", &tx, "Script evaluated without error but finished with a false/empty top stack element");
	let tx = unlock_entry(net, &entry, &entry_coin, &learned, new.script_pubkey(), LEAF - 1);
	net.refuse("forfeit/neg the entry one atom short", &tx, "Script failed an OP_EQUALVERIFY operation");
	let tx = unlock_entry(net, &entry, &entry_coin, &learned, new.script_pubkey(), LEAF);
	net.pass("forfeit/the entry unlocked with the learned preimage", &tx);

	// The operator withholds the preimage: the owner takes the old coin back.
	let (old, _new, _preimage, _entry, f2, old_coin, _entry_coin) = run(net, "abort");
	let f_out = ExplicitOutput::new(net.x, LEAF - FEE, f2.script_pubkey());
	let msg = old.collab_message(net.x, LEAF, std::slice::from_ref(&f_out)).unwrap();
	let mut s = spend(0).coin(&old_coin, 0xffff_ffff).outputs(vec![f_out.txout(), fee(net.x, FEE)]);
	s.witness(0, old.collab_witness(&sig(&s_key, &msg.digest), &sig(&a, &msg.digest), 1));
	let ft = net.pass("forfeit/abort: forfeit", &s.tx);
	let f_coin = Coin { outpoint: OutPoint::new(ft, 0), txout: f_out.txout() };
	let refund2 = |net: &Net| {
		let mut s = spend(0).coin(&f_coin, delay().to_sequence()).outputs(vec![explicit(net.x, LEAF - 2 * FEE, op_true_spk()), fee(net.x, FEE)]);
		let sg = s.sign(&a, 0, &f2.refund_script(), net.genesis);
		s.witness(0, f2.refund_witness(&sg));
		s.tx
	};
	net.refuse("forfeit/neg abort: refund before the delay", &refund2(net), "non-BIP68-final");
	net.wait_csv(&ft, delay());
	net.pass("forfeit/abort: the owner's refund after the delay", &refund2(net));
	let _ = refund;
}

/// Three forfeits of one round claimed in one transaction against one atom of
/// its connector asset; each negative forced into a block.
fn claim_batch(net: &mut Net) {
	let s_key = keypair("batch operator");
	let conn_policy = ConnectorPolicy { operator: xonly(&s_key) };
	let connectors = net.fund(vec![conn_policy.output(net.x, 5_000).txout(), conn_policy.output(net.x, 5_000).txout()]);
	let m = connector_asset(connectors[0].outpoint.txid, connectors[0].outpoint.vout);
	let m2 = connector_asset(connectors[1].outpoint.txid, connectors[1].outpoint.vout);
	let make = |net: &Net, i: usize, conn: elements::AssetId| {
		let owner = keypair(&format!("batch owner {}", i));
		let leaf = net.leaf(&owner, &s_key, &format!("batch old leaf {}", i));
		let pre = label32(&format!("batch preimage {}", i));
		(Forfeit::new(leaf, (net.x, LEAF), LeafId(label32(&format!("batch leaf id {}", i))), sha256(&pre), conn, delay(), FEE).unwrap(), pre)
	};
	let fs: Vec<(Forfeit, [u8; 32])> = (0..3).map(|i| make(net, i, m)).collect();
	let (other, other_pre) = make(net, 3, m2);
	let mut outs: Vec<TxOut> = fs.iter().map(|(f, _)| f.output().txout()).collect();
	outs.push(other.output().txout());
	let coins = net.fund(outs);
	// The operator issues one atom of M.
	let ks = conn_policy.issuance(connectors[0].outpoint, (net.x, 5_000), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
	let sg = sig(&s_key, &ks.sighash(net.genesis).unwrap());
	let iss = ks.finish(vec![sg.as_ref().to_vec()]);
	let it = net.pass("claim batch/the issuance of one atom of M", &iss.tx);
	let atom = coin_of(it, 0, &iss.tx);
	assert_eq!(atom.txout.asset.explicit(), Some(m));

	let set: Vec<(&Forfeit, OutPoint)> = fs.iter().zip(&coins).map(|((f, _), c)| (f, c.outpoint)).collect();
	let to = vec![ExplicitOutput::new(net.x, 3 * (LEAF - FEE) - FEE, op_true_spk())];
	let c = batch_claim_tx(&set, (atom.outpoint, atom.txout.clone()), &to, op_true_spk(), &FeeSource::Reserve).unwrap();
	let preimages: Vec<[u8; 32]> = fs.iter().map(|(_, p)| *p).collect();
	let genesis = net.genesis;
	let sigs = |c: &ClaimTx| -> Vec<elements::secp256k1_zkp::schnorr::Signature> {
		(0..c.leaves.len()).map(|i| sig(&s_key, &c.sighash(i, genesis).unwrap())).collect()
	};
	let done = |c: &ClaimTx, s: Vec<elements::secp256k1_zkp::schnorr::Signature>, p: &[[u8; 32]]| -> Transaction {
		let k = c.connector_input() as usize;
		let mut tx = c.clone().finish(&s, p).unwrap().tx;
		tx.input[k].witness.script_witness = op_true_witness();
		tx
	};
	let mut wrong = preimages.clone();
	wrong[1] = label32("not the preimage");
	net.refuse("claim batch/neg a wrong preimage on the second claim", &done(&c, sigs(&c), &wrong), "Script failed an OP_EQUALVERIFY operation");
	let mut swapped = sigs(&c);
	swapped.swap(0, 1);
	net.refuse("claim batch/neg two claims' signatures swapped", &done(&c, swapped, &preimages), "Invalid Schnorr signature");
	let mut tx = done(&c, sigs(&c), &preimages);
	let n = tx.input[2].witness.script_witness.len();
	tx.input[2].witness.script_witness[n - 3] = arca_covenant::script::scriptnum(0);
	net.refuse("claim batch/neg a claim naming a forfeit input as M's", &tx, "Script failed an OP_EQUALVERIFY operation");
	// Another round's forfeit beside this round's, with this round's atom.
	let mixed = vec![set[0], (&other, coins[3].outpoint)];
	assert_eq!(batch_claim_tx(&mixed, (atom.outpoint, atom.txout.clone()), &to, op_true_spk(), &FeeSource::Reserve).unwrap_err(),
		arca_covenant::spend::SpendError::OtherConnector(1));
	let mut s = spend(0).coin(&coins[0], 0xffff_ffff).coin(&coins[3], 0xffff_ffff).coin(&atom, 0xffff_ffff).outputs(vec![
		explicit(net.x, 2 * (LEAF - FEE) - FEE, op_true_spk()), explicit(m, 1, op_true_spk()), fee(net.x, FEE)]);
	let (f0, f3) = (&fs[0].0.policy, &other.policy);
	let s0 = s.sign(&s_key, 0, &f0.claim_script(), net.genesis);
	let s3 = s.sign(&s_key, 1, &f3.claim_script(), net.genesis);
	s.witness(0, f0.taproot().witness(&f0.claim_script(), ForfeitPolicy::claim_items(&s0, &fs[0].1, 2)));
	s.witness(1, f3.taproot().witness(&f3.claim_script(), ForfeitPolicy::claim_items(&s3, &other_pre, 2)));
	s.witness(2, op_true_witness());
	net.refuse("claim batch/neg another round's forfeit claimed with this round's atom", &s.tx, "Script failed an OP_EQUALVERIFY operation");

	let tx = done(&c, sigs(&c), &preimages);
	let ct = net.pass("claim batch/three forfeits of one round, one atom of M", &tx);
	println!("claim batch: {} forfeits in {} vB", c.leaves.len(), tx.vsize());
	// Each owner learns its own preimage from the claim, and the atom is back.
	for (i, (f, p)) in fs.iter().enumerate() {
		assert_eq!(find_preimage(&net.witness_of(&ct, i), &f.policy.unlock_hash), Some(*p), "owner {} learns its preimage", i);
	}
	assert_eq!(tx.output[1], explicit(m, 1, op_true_spk()), "the atom goes back for the next claim");
}

fn unlock_entry(net: &Net, e: &EntryPolicy, coin: &Coin, preimage: &[u8; 32], to: Script, value: u64) -> Transaction {
	let mut s = spend(0).coin(coin, 0xffff_ffff)
		.outputs(vec![explicit(net.x, value, to), fee(net.x, LEAF + ENTRY_RESERVE - value)]);
	s.witness(0, e.unlock_witness(preimage));
	s.tx
}

// ---------------------------------------------------------------------------
// 3. htlc-1
// ---------------------------------------------------------------------------

fn htlc(net: &mut Net) {
	let s_key = keypair("htlc operator");
	let a = keypair("htlc owner");
	let preimage = label32("htlc payment");
	let timeout = net.now() + 6 * H as u64;
	let mk = |direction| HtlcPolicy {
		owner: xonly(&a), operator: xonly(&s_key), direction, payment_hash: sha256(&preimage), timeout: mt(timeout),
		salts: HtlcSalts { claim: label32("htlc claim"), claim_both: label32("htlc both"), refund_both: label32("htlc refund") },
		chain: net.chain,
	};
	let send = mk(HtlcDirection::Send);
	let recv = mk(HtlcDirection::Receive);
	let coins = net.fund(vec![
		explicit(net.x, LEAF, send.script_pubkey()), explicit(net.x, LEAF, send.script_pubkey()),
		explicit(net.x, LEAF, send.script_pubkey()), explicit(net.x, LEAF, send.script_pubkey()),
		explicit(net.x, LEAF, recv.script_pubkey()),
	]);
	let to = ExplicitOutput::new(net.x, LEAF - FEE, op_true_spk());
	let back = ExplicitOutput::new(net.x, LEAF - FEE, net.leaf(&a, &s_key, "htlc back").script_pubkey());
	let x = net.x;
	let tx = |coin: &Coin, lock: u32, seq: u32, out: &ExplicitOutput, w: Vec<Vec<u8>>| {
		let mut s = spend(lock).coin(coin, seq).outputs(vec![out.txout(), fee(x, LEAF - out.value)]);
		s.witness(0, w);
		s.tx
	};
	let m_claim = send.message(HtlcPath::Claim, net.x, LEAF, &to).unwrap();
	let m_both = send.message(HtlcPath::ClaimBoth, net.x, LEAF, &to).unwrap();
	let m_rb = send.message(HtlcPath::RefundBoth, net.x, LEAF, &back).unwrap();

	let w = send.claim_witness(&sig(&s_key, &m_claim.digest), &label32("wrong"));
	net.refuse("htlc/neg claim with a wrong preimage", &tx(&coins[0], 0, 0xffff_ffff, &to, w), "Script failed an OP_EQUALVERIFY operation");
	let w = send.claim_witness(&sig(&s_key, &m_claim.digest), &preimage);
	net.refuse("htlc/neg claim into an output not committed", &tx(&coins[0], 0, 0xffff_ffff, &back, w), "Invalid Schnorr signature");
	let w = send.claim_witness(&sig(&a, &m_claim.digest), &preimage);
	net.refuse("htlc/neg claim signed by the owner", &tx(&coins[0], 0, 0xffff_ffff, &to, w), "Invalid Schnorr signature");
	let w = send.claim_witness(&sig(&s_key, &m_claim.digest), &preimage);
	net.pass("htlc/claim: the preimage and the operator's signature", &tx(&coins[0], 0, 0xffff_ffff, &to, w));
	let mut w = send.claim_both_witness(&sig(&s_key, &m_both.digest), &sig(&a, &m_both.digest), &preimage);
	w[1] = vec![];
	net.refuse("htlc/neg claim_both without the owner", &tx(&coins[1], 0, 0xffff_ffff, &to, w), "Script failed an OP_CHECKSIGVERIFY operation");
	let w = send.claim_both_witness(&sig(&s_key, &m_both.digest), &sig(&a, &m_both.digest), &preimage);
	net.pass("htlc/claim_both: the preimage and both signatures", &tx(&coins[1], 0, 0xffff_ffff, &to, w));

	let refund = |net: &Net, lock: u32, key: &Keypair| {
		let mut s = spend(lock).coin(&coins[2], 0xffff_fffe).outputs(vec![back.txout(), fee(net.x, FEE)]);
		let sg = s.sign(key, 0, &send.script(HtlcPath::Refund), net.genesis);
		s.witness(0, send.refund_witness(&sg));
		s.tx
	};
	let rb = |lock: u32| tx(&coins[3], lock, 0xffff_fffe, &back, send.refund_both_witness(&sig(&s_key, &m_rb.digest), &sig(&a, &m_rb.digest)));
	let t = timeout as u32;
	net.refuse("htlc/neg refund before the timeout", &refund(net, t, &a), "non-final");
	net.refuse("htlc/neg refund_both before the timeout", &rb(t), "non-final");
	net.mtp_past(timeout);
	net.refuse("htlc/neg refund with a lock time below the timeout", &refund(net, t - 1, &a), "Locktime requirement not satisfied");
	net.refuse("htlc/neg refund signed by the operator", &refund(net, t, &s_key), "Invalid Schnorr signature");
	net.refuse("htlc/neg refund_both with a lock time below the timeout", &rb(t - 1), "Locktime requirement not satisfied");
	net.pass("htlc/refund: the owner after the timeout", &refund(net, t, &a));
	net.pass("htlc/refund_both: both signatures after the timeout", &rb(t));

	// A payment into the tree: the owner claims.
	let mine = ExplicitOutput::new(net.x, LEAF - FEE, net.leaf(&a, &s_key, "htlc received").script_pubkey());
	let m = recv.message(HtlcPath::Claim, net.x, LEAF, &mine).unwrap();
	let w = recv.claim_witness(&sig(&s_key, &m.digest), &preimage);
	net.refuse("htlc/neg receive: the operator claims", &tx(&coins[4], 0, 0xffff_ffff, &mine, w), "Invalid Schnorr signature");
	let w = recv.claim_witness(&sig(&a, &m.digest), &preimage);
	net.pass("htlc/receive: the owner claims with the preimage", &tx(&coins[4], 0, 0xffff_ffff, &mine, w));
}

// ---------------------------------------------------------------------------
// 4. The two-asset swap
// ---------------------------------------------------------------------------

fn swap(net: &mut Net) {
	let s_key = keypair("swap operator");
	let alice = keypair("swap alice");
	let bob = keypair("swap bob");
	let (vx, vy) = (LEAF - FEE, LEAF);
	let mut pairs = vec![];
	for i in 0..2 {
		let al = net.leaf(&alice, &s_key, &format!("swap alice {}", i));
		let bl = net.leaf(&bob, &s_key, &format!("swap bob {}", i));
		let outs = vec![
			ExplicitOutput::new(net.x, vx, net.leaf(&bob, &s_key, &format!("bob gets X {}", i)).script_pubkey()),
			ExplicitOutput::new(net.y, vy, net.leaf(&alice, &s_key, &format!("alice gets Y {}", i)).script_pubkey()),
		];
		// Signed before either leaf exists.
		let ma = al.collab_message(net.x, LEAF, &outs).unwrap();
		let mb = bl.collab_message(net.y, LEAF, &outs).unwrap();
		let wa = al.collab_witness(&sig(&s_key, &ma.digest), &sig(&alice, &ma.digest), 2);
		let wb = bl.collab_witness(&sig(&s_key, &mb.digest), &sig(&bob, &mb.digest), 2);
		pairs.push((al, bl, outs, wa, wb));
	}
	let coins = net.fund(vec![
		explicit(net.x, LEAF, pairs[0].0.script_pubkey()), explicit(net.y, LEAF, pairs[0].1.script_pubkey()),
		explicit(net.x, LEAF, pairs[1].0.script_pubkey()), explicit(net.y, LEAF, pairs[1].1.script_pubkey()),
	]);
	let (_, _, outs, wa, wb) = &pairs[0];
	let committed = vec![outs[0].txout(), outs[1].txout(), fee(net.x, FEE)];
	let both = |outputs: Vec<TxOut>, wa: Vec<Vec<u8>>, wb: Vec<Vec<u8>>| {
		let mut s = spend(0).coin(&coins[0], 0xffff_ffff).coin(&coins[1], 0xffff_ffff).outputs(outputs);
		s.witness(0, wa);
		s.witness(1, wb);
		s.tx
	};
	let mut s = spend(0).coin(&coins[0], 0xffff_ffff).outputs(vec![outs[0].txout(), fee(net.x, FEE)]);
	s.witness(0, wa.clone());
	net.refuse("swap/neg Alice's leaf alone, her output absent", &s.tx, "Invalid Schnorr signature");
	net.refuse("swap/neg outputs swapped", &both(vec![outs[1].txout(), outs[0].txout(), fee(net.x, FEE)], wa.clone(), wb.clone()), "Invalid Schnorr signature");
	let mut cross = wa.clone();
	let n = cross.len();
	cross[n - 2] = wb[n - 2].clone();
	cross[n - 1] = wb[n - 1].clone();
	net.refuse("swap/neg Bob's leaf with Alice's signatures", &both(committed.clone(), wa.clone(), cross), "Invalid Schnorr signature");
	// The other swap's signatures, on this swap's leaves and that swap's outputs.
	let other = &pairs[1];
	let graft = |sigs: &[Vec<u8>], leaf: &[Vec<u8>]| [&sigs[..3], &leaf[3..]].concat();
	net.refuse("swap/neg the other swap's signatures", &both(vec![other.2[0].txout(), other.2[1].txout(), fee(net.x, FEE)],
		graft(&other.3, wa), graft(&other.4, wb)), "Invalid Schnorr signature");
	let st = net.pass("swap/two leaves, X and Y, in one transaction", &both(committed, wa.clone(), wb.clone()));
	let o = net.rt.client().raw_transaction(&st).unwrap();
	assert_eq!(o.output[0].asset.explicit(), Some(net.x));
	assert_eq!(o.output[1].asset.explicit(), Some(net.y));

	// Alice's second leaf with a third party's Y: she gets exactly what she signed for.
	let third = net.fund(vec![explicit(net.y, LEAF, op_true_spk())]).remove(0);
	let (_, _, outs1, wa1, _) = &pairs[1];
	let mut s = spend(0).coin(&coins[2], 0xffff_ffff).coin(&third, 0xffff_ffff)
		.outputs(vec![outs1[0].txout(), outs1[1].txout(), fee(net.x, FEE)]);
	s.witness(0, wa1.clone());
	s.witness(1, op_true_witness());
	net.pass("swap/Alice's leaf with a third party's Y", &s.tx);
}

// ---------------------------------------------------------------------------
// 5. The entry's sweep behind the token and the notice
// ---------------------------------------------------------------------------

fn entry_sweep(net: &mut Net) {
	let s_key = keypair("entry sweep operator");
	let created = net.mtp() - 60;
	let issuer = net.fund(vec![explicit(net.x, 1_000_000_000, op_true_spk())]).remove(0);
	let e0 = net.now() + 2 * 24 * H as u64;
	let e1 = net.now() + 4 * 24 * H as u64;
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(), vec![mt(e0), mt(e1)]).unwrap();
	let b = Batch::new(net, "entry sweep", &s_key, sched.clone(), false);
	let r = round(net, "entry sweep/round", issuer, &b);

	// An owner exits early: the batch output and lowest node 0 go on-chain.
	let tx = unroll(net, &b.root, &r.batch, &b.owners[0], created, None);
	let rt = net.pass("entry sweep/batch output unroll", &tx);
	let lowest = children(rt, &tx, 4);
	let tx = unroll(net, &b.lowest[0], &lowest[0], &b.owners[0], created, None);
	let l0 = net.pass("entry sweep/lowest node 0 unroll", &tx);
	let old_entries = children(l0, &tx, 4);

	// The operator rolls the clock, then releases it at the new expiry.
	let fc = net.fee_coin();
	let tx = clock_move(net, &s_key, &sched, 0, true, &r.token, &fc, 0);
	let ro = net.pass("entry sweep/roll clock 0 into clock 1", &tx);
	let token = coin_of(ro, 0, &tx);
	let fc = net.fee_coin();
	let tx = clock_move(net, &s_key, &sched, 1, false, &token, &fc, e1 as u32);
	net.refuse("entry sweep/neg release before the expiry", &tx, "non-final");
	net.mtp_past(e0);
	let tx = clock_move(net, &s_key, &sched, 1, false, &token, &fc, e0 as u32);
	net.refuse("entry sweep/neg after the roll, release at the old expiry", &tx, "Locktime requirement not satisfied");
	net.mtp_past(e1);
	let tx = clock_move(net, &s_key, &sched, 1, false, &token, &fc, e1 as u32);
	let rl = net.pass("entry sweep/release clock 1 at its expiry", &tx);
	let mut at_r = coin_of(rl, 0, &tx);

	let w = delay().to_sequence();
	let sweep_entry = |net: &mut Net, i: usize, coin: &Coin, token: &Coin, with_token: bool| -> Transaction {
		let e = &b.entries[i];
		let value = coin.txout.value.explicit().unwrap();
		if with_token {
			// Built by the library.
			let to = [ExplicitOutput::new(net.x, value - 3_000, op_true_spk())];
			return built_sweep(net, &s_key, &sched, &[e.sweepable(coin.outpoint, value)], token, &to);
		}
		// Without the token, an ordinary coin of X stands at input 1.
		let t_in = if with_token { token.clone() } else { net.purse.iter().find(|c| c.txout.asset.explicit() == Some(net.x)).unwrap().clone() };
		let back = if with_token { explicit(sched.token, 1, sched.r().script_pubkey()) } else { explicit(net.x, t_in.txout.value.explicit().unwrap(), op_true_spk()) };
		let mut s = spend(0).coin(coin, w).coin(&t_in, if with_token { w } else { 0xffff_ffff })
			.outputs(vec![explicit(net.x, value - 3_000, op_true_spk()), back, fee(net.x, 3_000)]);
		let sg = s.sign(&s_key, 0, &e.sweep_script(), net.genesis);
		s.witness(0, e.sweep_witness(&sg, 1));
		s.witness(1, op_true_witness());
		s.tx
	};
	// The entries have been on-chain for days, but the token has not waited W at R.
	let tx = sweep_entry(net, 1, &old_entries[1], &at_r, true);
	net.refuse("entry sweep/neg an old entry swept in the release block's wake (no notice)", &tx, "non-BIP68-final");
	let tx = sweep_entry(net, 1, &old_entries[1], &at_r, false);
	net.refuse("entry sweep/neg an entry swept without the token", &tx, "Script failed an OP_EQUALVERIFY operation");
	// A watch service holds an authorisation that names a later time: it
	// cannot unroll before then.
	let t_watch = net.now() + 30 * 24 * H as u64;
	let tx = unroll(net, &b.lowest[1], &lowest[1], &b.owners[4], t_watch, None);
	net.refuse("entry sweep/neg a watch service's authorisation before its time", &tx, "non-final");
	// The owner's own authorisation unrolls lowest node 1 during the notice.
	let tx = unroll(net, &b.lowest[1], &lowest[1], &b.owners[4], created, None);
	let l1 = net.pass("entry sweep/lowest node 1 unrolled during the notice", &tx);
	let late_entries = children(l1, &tx, 4);
	net.wait_csv(&rl, delay());
	let tx = sweep_entry(net, 1, &old_entries[1], &at_r, true);
	let sw = net.pass("entry sweep/an old entry swept after the notice, behind the token", &tx);
	at_r = coin_of(sw, 1, &tx);
	// The token waits W again; a late entry also waits W from its own confirmation.
	let tx = sweep_entry(net, 5, &late_entries[1], &at_r, true);
	net.refuse("entry sweep/neg the next wave before the token has waited W again", &tx, "non-BIP68-final");
	// Lowest node 2 goes on-chain two hours later, so it ripens after the token.
	let later = net.now() + 2 * H as u64;
	net.mtp_past(later);
	let tx = unroll(net, &b.lowest[2], &lowest[2], &b.owners[8], created, None);
	let l2 = net.pass("entry sweep/lowest node 2 unrolled late", &tx);
	let later_entries = children(l2, &tx, 4);
	net.wait_csv(&sw, delay());
	let ready = net.csv_ready(&l2, delay());
	assert!(net.mtp() <= ready, "the late entry must not be ripe yet");
	let tx = sweep_entry(net, 9, &later_entries[1], &at_r, true);
	net.refuse("entry sweep/neg a late entry swept before its own W", &tx, "non-BIP68-final");
	let tx = sweep_entry(net, 5, &late_entries[1], &at_r, true);
	let sw2 = net.pass("entry sweep/an entry that appeared during the notice, swept after its W", &tx);
	at_r = coin_of(sw2, 1, &tx);
	net.wait_csv(&sw2, delay());
	net.wait_csv(&l2, delay());
	let tx = sweep_entry(net, 9, &later_entries[1], &at_r, true);
	net.pass("entry sweep/the late entry swept after its own W", &tx);
}

// ---------------------------------------------------------------------------
// 6. The burn-only sweep behind the token
// ---------------------------------------------------------------------------

fn burn(net: &mut Net) {
	let s_key = keypair("burn operator");
	let created = net.mtp() - 60;
	let issuer = net.fund(vec![explicit(net.x, 1_000_000_000, op_true_spk())]).remove(0);
	let e0 = net.now() + 24 * H as u64;
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(), vec![mt(e0)]).unwrap();
	let b = Batch::new(net, "burn", &s_key, sched.clone(), true);
	let r = round(net, "burn/round (issuer-operated batch)", issuer, &b);
	let w = delay().to_sequence();
	let burn_spk = Script::from(vec![0x6a]);

	// A second batch, so a lowest node can be burned too: its owner exits early.
	let issuer2 = net.fund(vec![explicit(net.x, 1_000_000_000, op_true_spk())]).remove(0);
	let sched2 = ClockSchedule::new(token_of(&issuer2), xonly(&s_key), delay(), vec![mt(e0)]).unwrap();
	let b2 = Batch::new(net, "burn second", &s_key, sched2.clone(), true);
	let r2 = round(net, "burn/round of a second issuer-operated batch", issuer2, &b2);
	let tx = unroll(net, &b2.root, &r2.batch, &b2.owners[0], created, None);
	let rt2 = net.pass("burn/second batch output unroll", &tx);
	let lowest2 = children(rt2, &tx, 4);

	// Release both clocks at the expiry.
	net.mtp_past(e0);
	let fc = net.fee_coin();
	let tx = clock_move(net, &s_key, &sched, 0, false, &r.token, &fc, e0 as u32);
	let rl = net.pass("burn/release", &tx);
	let at_r = coin_of(rl, 0, &tx);
	let fc = net.fee_coin();
	let tx = clock_move(net, &s_key, &sched2, 0, false, &r2.token, &fc, e0 as u32);
	let rl2 = net.pass("burn/release of the second batch", &tx);
	let at_r2 = coin_of(rl2, 0, &tx);

	// inputs: the swept nodes, the token, an operator fee coin.
	let burn_tx = |net: &mut Net, sched: &ClockSchedule, nodes: &[(&NodePolicy, &Coin, u32)], token: &Coin, outs: Vec<TxOut>, key: &Keypair| {
		let fc = net.fee_coin();
		let mut s = spend(0);
		for (_, c, seq) in nodes {
			s = s.coin(c, *seq);
		}
		let k = nodes.len();
		s = s.coin(token, w).coin(&fc, 0xffff_fffe).outputs(outs)
			.outputs(vec![explicit(net.policy, fc.txout.value.explicit().unwrap() - 5_000, op_true_spk()), fee(net.policy, 5_000)]);
		for (i, (n, _, _)) in nodes.iter().enumerate() {
			let sg = s.sign(key, i, &n.sweep_script(), net.genesis);
			s.witness(i, n.sweep_witness(&sg, k as u32));
		}
		r_sign(net, &s_key, sched, &mut s, k);
		s.witness(k + 1, op_true_witness());
		s.tx
	};
	let v = b.value();
	let t_back = explicit(sched.token, 1, sched.r().script_pubkey());
	let batch_node = (&b.root, &r.batch, 0xffff_fffe);
	let tx = built_sweep(net, &s_key, &sched, &[b.root.sweepable(r.batch.outpoint, v)], &at_r, &[]);
	net.refuse("burn/neg the batch output burned at the release (no notice)", &tx, "non-BIP68-final");
	net.wait_csv(&rl, delay());
	net.wait_csv(&rl2, delay());
	let cases: Vec<(&str, Vec<TxOut>, &Keypair, &str)> = vec![
		("burn/neg the batch output to the operator", vec![explicit(net.x, v, op_true_spk()), t_back.clone()], &s_key, "Script failed an OP_EQUALVERIFY operation"),
		("burn/neg 1000 atoms short, kept by the operator", vec![explicit(net.x, v - 1_000, burn_spk.clone()), t_back.clone(), explicit(net.x, 1_000, op_true_spk())], &s_key, "Script failed an OP_EQUALVERIFY operation"),
		("burn/neg OP_RETURN at another index", vec![t_back.clone(), explicit(net.x, v, burn_spk.clone())], &s_key, "Script failed an OP_EQUALVERIFY operation"),
		("burn/neg OP_TRUE in place of OP_RETURN", vec![explicit(net.x, v, Script::from(vec![0x51])), t_back.clone()], &s_key, "Script failed an OP_EQUALVERIFY operation"),
		("burn/neg signed by another key", vec![explicit(net.x, v, burn_spk.clone()), t_back.clone()], &b.owners[0], "Invalid Schnorr signature"),
	];
	for (name, outs, key, expect) in cases {
		let tx = burn_tx(net, &sched, &[batch_node], &at_r, outs, key);
		net.refuse(name, &tx, expect);
	}
	let tx = built_sweep(net, &s_key, &sched, &[b.root.sweepable(r.batch.outpoint, v)], &at_r, &[]);
	let bt = net.pass("burn/the batch output burned after the notice, behind the token", &tx);
	let gone: Value = net.rpc("gettxout", json!([bt.to_string(), 0]));
	assert!(gone.is_null(), "the OP_RETURN output never enters the UTXO set");

	// The second batch: lowest nodes 0 and 1 are on-chain; burn them.
	let t_back2 = explicit(sched2.token, 1, sched2.r().script_pubkey());
	let lv = lowest2[0].txout.value.explicit().unwrap();
	let n0 = (&b2.lowest[0], &lowest2[0], w);
	let n1 = (&b2.lowest[1], &lowest2[1], w);
	// Two nodes, one burn output: the second node's index holds the token,
	// and its value goes to the operator.
	let tx = burn_tx(net, &sched2, &[n0, n1], &at_r2,
		vec![explicit(net.x, lv, burn_spk.clone()), t_back2.clone(), explicit(net.x, lv, op_true_spk())], &s_key);
	net.refuse("burn/neg two lowest nodes sharing one burn output", &tx, "Script failed an OP_EQUALVERIFY operation");
	// Each node burns at its own index, the token going back to R after them.
	// A node relays several bare OP_RETURN burns in one transaction; one whose
	// relay policy still counts each against the one-OP_RETURN limit refuses
	// it (multi-op-return), and a producer mines it.
	let swept2 = [b2.lowest[0].sweepable(lowest2[0].outpoint, lv), b2.lowest[1].sweepable(lowest2[1].outpoint, lv)];
	let tx = built_sweep(net, &s_key, &sched2, &swept2, &at_r2, &[]);
	assert_eq!(tx.output[2], t_back2, "the token goes back to R after the burns");
	let bt2 = net.pass_or_mine("burn/two lowest nodes burned in one transaction", &tx, "multi-op-return");
	for i in [0, 1] {
		assert!(net.rpc("gettxout", json!([bt2.to_string(), i])).is_null());
	}
	// The next node: the token, back at R, waits W again.
	let at_r2 = coin_of(bt2, 2, &tx);
	let n2 = [b2.lowest[2].sweepable(lowest2[2].outpoint, lv)];
	let tx = built_sweep(net, &s_key, &sched2, &n2, &at_r2, &[]);
	net.refuse("burn/neg the next node before the token has waited W again", &tx, "non-BIP68-final");
	net.wait_csv(&bt2, delay());
	let tx = built_sweep(net, &s_key, &sched2, &n2, &at_r2, &[]);
	net.pass("burn/a lowest node burned after its notice, behind the token", &tx);
}

// ---------------------------------------------------------------------------
// 7. Batches built by the tree builder
// ---------------------------------------------------------------------------

/// What the prototype measured for the same transaction (T21 and T5; its exit
/// claims paid a P2WPKH output, these pay a P2TR one).
fn prototype_vsize(name: &str) -> &'static str {
	let fee = name.contains("fee coin");
	match (name.split(" / ").nth(1).unwrap_or(""), fee) {
		(n, false) if n.starts_with("unroll, member depth 3, 4 children") => "527",
		(n, true) if n.starts_with("unroll, member depth 3, 4 children") => "729",
		(n, false) if n.starts_with("unroll, member depth 5, 4 children") => "549",
		(n, true) if n.starts_with("unroll, member depth 5, 4 children") => "751",
		(n, false) if n.starts_with("unroll, member depth 7, 4 children") => "571",
		(n, true) if n.starts_with("unroll, member depth 7, 4 children") => "773",
		(n, false) if n.starts_with("entry") => "234",
		(n, false) if n.starts_with("exit") => "207 (P2WPKH out)",
		(n, true) if n.starts_with("exit") => "342 (P2WPKH out)",
		_ => "",
	}
}

fn built_tree(net: &mut Net, n: usize, exits: [usize; 3], sizes: &mut Vec<(String, usize, String)>) {
	let label = format!("tree {}", n);
	let s_key = keypair(&format!("{} operator", label));
	let created = net.mtp() - 60;
	let issuer = net.fund(vec![explicit(net.x, 2_000_000_000, op_true_spk())]).remove(0);
	let day = 24 * H as u64;
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(),
		vec![mt(net.now() + 28 * day), mt(net.now() + 56 * day), mt(net.now() + 84 * day)]).unwrap();

	// The reserve rule of the specification: four times the relay floor for
	// each output's own spend, the floor read from the node (X is listed 1:1).
	let info = net.rpc("getmempoolinfo", json!([]));
	let floor_per_kvb = (info["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
	let owners: Vec<Keypair> = (0..n).map(|i| keypair(&format!("{} owner {}", label, i))).collect();
	let preimages: Vec<[u8; 32]> = (0..n).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
	let leaves: Vec<LeafSpec> = (0..n).map(|i| LeafSpec {
		template: Template::Vtxo1, owner: xonly(&owners[i]), value: LEAF,
		owner_nonce: label32(&format!("{} owner nonce {}", label, i)),
		operator_nonce: label32(&format!("{} operator nonce {}", label, i)),
		exit_delay: delay(), unlock_hash: sha256(&preimages[i]),
	}).collect();
	let params = TreeParams {
		asset: net.x, chain: net.chain, schedule: sched.clone(), burn: false, radix: 4,
		reserve: ReserveRule::FeeRate { floor_per_kvb, multiple: 4 }, min_leaf: 1_000 * floor_per_kvb / 1_000,
	};
	let tree = Tree::build(params, &leaves).unwrap();

	// The round: the batch output at 0, the token's atom in clock 0 at 1.
	let batch = tree.batch_output();
	let total = issuer.txout.value.explicit().unwrap();
	let mut s = spend(0).coin(&issuer, 0xffff_ffff).outputs(vec![
		batch.txout(), explicit(sched.token, 1, tree.clock0_script_pubkey()),
		explicit(net.x, total - batch.value - 2_000, op_true_spk()), fee(net.x, 2_000),
	]);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	s.witness(0, op_true_witness());
	let round_txid = net.pass(&format!("{} / the round", label), &s.tx);
	net.purse.push(coin_of(round_txid, 2, &s.tx));

	// Every owner checks its record against the round as the chain has it,
	// under its wallet's policy, for its key and the nonce it picked.
	let round = net.rt.client().raw_transaction(&round_txid).unwrap();
	let policy = WalletPolicy::new(net.chain, xonly(&s_key), mt(net.mtp()));
	let records: Vec<Vec<u8>> = tree.records().iter().map(|r| r.to_bytes().unwrap()).collect();
	for (i, bytes) in records.iter().enumerate() {
		let rec = LeafRecord::from_bytes(bytes).unwrap();
		let ok = rec.validate(&round, &policy, &xonly(&owners[i]), &leaves[i].owner_nonce)
			.unwrap_or_else(|e| panic!("{} / leaf {}: {}", label, i, e));
		assert_eq!((ok.batch_vout, ok.round_txid), (0, round_txid));
		// A record naming another owner nonce than the one in the leaf's salt.
		let mut other = rec.clone();
		other.owner_nonce = label32(&format!("{} not the owner nonce {}", label, i));
		assert_eq!(other.validate(&round, &policy, &xonly(&owners[i]), &other.owner_nonce).unwrap_err().kind(), "batch_output");
	}
	println!("{}: {} records validate against the confirmed round {}", label, n, round_txid);

	// The unrolled nodes, by program: a later leaf starts below them.
	let mut unrolled: HashMap<[u8; 32], Txid> = HashMap::new();
	for (k, &i) in exits.iter().enumerate() {
		let external = k == 1;
		let shape = if external { ", fee coin" } else { "" };
		let rec = LeafRecord::from_bytes(&records[i]).unwrap();
		let branch = rec.validate(&round, &policy, &xonly(&owners[i]), &leaves[i].owner_nonce).unwrap().branch;
		let owner = &owners[i];
		let mut at = OutPoint::new(round_txid, 0);
		for (level, node) in branch.nodes.iter().enumerate() {
			let name = format!("{} / unroll, member depth {}, {} children, leaf {}{}", label, node.gate.depth,
				node.children.len(), i, shape);
			if let Some(txid) = unrolled.get(&node.program()) {
				at = OutPoint::new(*txid, node.index as u32);
				continue;
			}
			let auth = node.owner_auth(sig(owner, &node.unroll_authorisation(mt(created)).digest), mt(created), xonly(owner));
			let fee_source = |net: &mut Net| if external {
				let c = net.fee_coin();
				FeeSource::Coin { outpoint: c.outpoint, coin: c.txout, fee: 4_000, change: op_true_spk() }
			} else {
				FeeSource::Reserve
			};

			// Before the real one, what must not unroll it, forced into a block.
			if k == 0 && level == 0 {
				let mut bad = node.unroll_tx(at, &auth, &FeeSource::Reserve).unwrap().tx;
				let v = bad.output[1].value.explicit().unwrap();
				bad.output[1].value = elements::confidential::Value::Explicit(v - 1);
				let f = bad.output.len() - 1;
				bad.output[f].value = elements::confidential::Value::Explicit(node.reserve + 1);
				net.refuse(&format!("{} / neg a child one atom short", label), &bad, "Script failed an OP_EQUALVERIFY operation");
				let stranger = keypair(&format!("{} stranger", label));
				let forged = node.owner_auth(sig(&stranger, &node.unroll_authorisation(mt(created)).digest), mt(created), xonly(owner));
				let tx = node.unroll_tx(at, &forged, &FeeSource::Reserve).unwrap().tx;
				net.refuse(&format!("{} / neg a stranger's signature on the owner's proof", label), &tx, "Invalid Schnorr signature");
				let later = mt(net.now() + 2 * day);
				let early = node.owner_auth(sig(owner, &node.unroll_authorisation(later).digest), later, xonly(owner));
				let tx = node.unroll_tx(at, &early, &FeeSource::Reserve).unwrap().tx;
				net.refuse(&format!("{} / neg an authorisation used before its time", label), &tx, "non-final");
			}
			if k > 0 && level + 1 == branch.nodes.len() {
				// The owner of the first leaf, a member of the batch output but not
				// of this lowest node, offers its own proof.
				let other = &owners[exits[0]];
				let other_branch = LeafRecord::from_bytes(&records[exits[0]]).unwrap().branch().unwrap();
				let theirs = other_branch.nodes.last().unwrap();
				let a = arca_covenant::UnrollAuth {
					signature: sig(other, &node.unroll_authorisation(mt(created)).digest), time: mt(created),
					key: xonly(other), proof: theirs.proof.clone(),
				};
				let tx = node.unroll_tx(at, &a, &FeeSource::Reserve).unwrap().tx;
				net.refuse(&format!("{} / neg a lowest node unrolled by an owner of another one", label), &tx,
					"Script failed an OP_EQUALVERIFY operation");
			}

			let fs = fee_source(net);
			let mut u = node.unroll_tx(at, &auth, &fs).unwrap();
			if external {
				u.tx.input[1].witness.script_witness = op_true_witness();
			}
			let txid = net.pass(&name, &u.tx);
			sizes.push((name, net.rows.last().unwrap().vsize.parse().unwrap(),
				prototype_vsize(&format!("x / unroll, member depth {}, {} children{}", node.gate.depth, node.children.len(), shape)).into()));
			assert_eq!(u.tx.vsize().to_string(), net.rows.last().unwrap().vsize, "the size the builder reserves for");
			unrolled.insert(node.program(), txid);
			at = OutPoint::new(txid, node.index as u32);
		}

		// The entry, with the preimage.
		let tx = branch.entry_tx(at, &label32("not the preimage"), &FeeSource::Reserve).unwrap().tx;
		net.refuse(&format!("{} / neg entry {} with a wrong preimage", label, i), &tx, "Script failed an OP_EQUALVERIFY operation");
		let fs = if external {
			let c = net.fee_coin();
			FeeSource::Coin { outpoint: c.outpoint, coin: c.txout, fee: 4_000, change: op_true_spk() }
		} else {
			FeeSource::Reserve
		};
		let mut u = branch.entry_tx(at, &preimages[i], &fs).unwrap();
		if external {
			u.tx.input[1].witness.script_witness = op_true_witness();
		}
		let name = format!("{} / entry {} into its leaf{}", label, i, shape);
		let entry_txid = net.pass(&name, &u.tx);
		sizes.push((name.clone(), net.rows.last().unwrap().vsize.parse().unwrap(), prototype_vsize(&format!("x / entry{}", shape)).into()));

		// The exit, after the delay.
		let leaf = branch.leaf;
		let leaf_coin = Coin { outpoint: OutPoint::new(entry_txid, 0), txout: branch.leaf_output().txout() };
		let exit = |net: &mut Net| {
			let mut s = spend(0).coin(&leaf_coin, delay().to_sequence());
			if external {
				let c = net.fee_coin();
				s = s.coin(&c, 0xffff_fffe).outputs(vec![explicit(net.x, LEAF, op_true_spk()),
					explicit(net.policy, c.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
				s.witness(1, op_true_witness());
			} else {
				s = s.outputs(vec![explicit(net.x, LEAF - FEE, op_true_spk()), fee(net.x, FEE)]);
			}
			let sg = s.sign(owner, 0, &leaf.exit_script(), net.genesis);
			s.witness(0, leaf.exit_witness(&sg));
			s.tx
		};
		let tx = exit(net);
		net.refuse(&format!("{} / neg exit {} before the delay", label, i), &tx, "non-BIP68-final");
		net.wait_csv(&entry_txid, delay());
		let tx = exit(net);
		let name = format!("{} / exit of leaf {}{}", label, i, shape);
		net.pass(&name, &tx);
		sizes.push((name, net.rows.last().unwrap().vsize.parse().unwrap(), prototype_vsize(&format!("x / exit{}", shape)).into()));
	}
}

fn built_trees(net: &mut Net) {
	let mut sizes = vec![];
	built_tree(net, 17, [0, 6, 16], &mut sizes);
	built_tree(net, 64, [0, 27, 63], &mut sizes);
	println!("\n{:<70} {:>6}  prototype", "built by the tree builder", "vsize");
	for (n, v, p) in &sizes {
		println!("{:<70} {:>6}  {}", n, v, p);
	}
}

// ---------------------------------------------------------------------------
// 8. The review's probes B and F, turned around
// ---------------------------------------------------------------------------

/// A round that issues `sched`'s token from `issuer` and pays `batch` at 0
/// and the token's atom to clock 0 at 1.
fn plain_round(net: &mut Net, name: &str, issuer: &Coin, sched: &ClockSchedule, batch: &ExplicitOutput) -> (Txid, Transaction) {
	let total = issuer.txout.value.explicit().unwrap();
	let mut s = spend(0).coin(issuer, 0xffff_ffff).outputs(vec![
		batch.txout(), explicit(sched.token, 1, sched.clock0_script_pubkey()),
		explicit(net.x, total - batch.value - 2_000, op_true_spk()), fee(net.x, 2_000),
	]);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	s.witness(0, op_true_witness());
	let txid = net.pass(name, &s.tx);
	net.purse.push(coin_of(txid, 2, &s.tx));
	(txid, net.rt.client().raw_transaction(&txid).unwrap())
}

fn probes_turned_around(net: &mut Net) {
	let day = 24 * H as u64;

	// Probe B: one key on two leaves lets one release fill two RECLAIM slots.
	// The builder refuses that batch; built by hand and funded, each record of
	// the key that holds two leaves is refused by validation.
	let s_key = keypair("probe B operator");
	let a = keypair("probe B owner A, two leaves");
	let (b, c) = (keypair("probe B owner B"), keypair("probe B owner C"));
	let keys = [&a, &a, &b, &c];
	let issuer = net.fund(vec![explicit(net.x, 2_000_000_000, op_true_spk())]).remove(0);
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(),
		vec![mt(net.now() + 28 * day), mt(net.now() + 56 * day)]).unwrap();
	let specs: Vec<LeafSpec> = (0..4).map(|i| LeafSpec {
		template: Template::Vtxo1, owner: xonly(keys[i]), value: LEAF,
		owner_nonce: label32(&format!("probe B owner nonce {}", i)),
		operator_nonce: label32(&format!("probe B operator nonce {}", i)),
		exit_delay: delay(), unlock_hash: sha256(&label32(&format!("probe B preimage {}", i))),
	}).collect();
	let params = TreeParams {
		asset: net.x, chain: net.chain, schedule: sched.clone(), burn: false, radix: 4,
		reserve: ReserveRule::Fixed { node: NODE_RESERVE, entry: ENTRY_RESERVE }, min_leaf: 1,
	};
	assert_eq!(Tree::build(params.clone(), &specs).unwrap_err(), TreeError::DuplicateOwner { first: 0, second: 1 });
	// By hand: the four entries under one node, gated to [S, A, A, B, C],
	// whose RECLAIM names A twice.
	let entries: Vec<(LeafPolicy, EntryPolicy)> = specs.iter().map(|sp| {
		let leaf = LeafPolicy { owner: sp.owner, operator: xonly(&s_key), salt: sp.salt(), chain: net.chain, exit_delay: delay() };
		let entry = EntryPolicy { unlock_hash: sp.unlock_hash, asset: net.x, value: LEAF, leaf_program: leaf.program(),
			sweep: sched.sweep(true, false) };
		(leaf, entry)
	}).collect();
	let children: Vec<Child> = entries.iter().map(|(_, e)| Child::new(net.x, LEAF + ENTRY_RESERVE, e.taproot().program())).collect();
	let node = NodePolicy::new(children.clone(), xonly(&s_key), specs.iter().map(|sp| sp.owner).collect(),
		sched.sweep(false, false), Some(net.chain)).unwrap();
	let batch = ExplicitOutput::new(net.x, 4 * (LEAF + ENTRY_RESERVE) + NODE_RESERVE, node.script_pubkey());
	let (round_txid, round) = plain_round(net, "probe B turned around / round with key A on leaves 0 and 1", &issuer, &sched, &batch);
	let policy = WalletPolicy::new(net.chain, xonly(&s_key), mt(net.mtp()));
	for i in 0..4 {
		let others: Vec<usize> = (0..4).filter(|j| *j != i).collect();
		let rec = LeafRecord {
			template: Template::Vtxo1, owner: specs[i].owner, owner_nonce: specs[i].owner_nonce,
			operator_nonce: specs[i].operator_nonce, exit_delay: delay(), asset: net.x, value: LEAF,
			unlock_hash: specs[i].unlock_hash, entry_reserve: ENTRY_RESERVE, chain: net.chain, schedule: sched.clone(),
			burn: false, upper: vec![],
			lowest: arca_covenant::record::LowestLevel {
				index: i as u8, reserve: NODE_RESERVE,
				siblings: others.iter().map(|j| arca_covenant::record::Sibling { value: children[*j].value, program: children[*j].program }).collect(),
				owners: others.iter().map(|j| specs[*j].owner).collect(),
			},
		};
		let r = rec.validate(&round, &policy, &specs[i].owner, &specs[i].owner_nonce);
		if i < 2 {
			let e = r.unwrap_err();
			assert_eq!(e.kind(), "owner", "leaf {}: {}", i, e);
			println!("probe B turned around: A's record of leaf {} against the confirmed round {}: refused, {}", i, round_txid, e);
		} else {
			r.unwrap_or_else(|e| panic!("probe B: leaf {} of another key: {}", i, e));
		}
	}

	// Probe F: the operator builds a new leaf from a salt the owner signed
	// under before, so the old forfeit pair would spend it. With the
	// two-sided salt, the wallet's random nonce for the new leaf is not in
	// that salt: a record that says so is refused, and one that names the
	// wallet's nonce does not match the round.
	let s_key = keypair("probe F operator");
	let owner = keypair("probe F owner");
	let old_nonce = label32("probe F nonce of an old leaf");
	let old_op = label32("probe F operator nonce of an old leaf");
	let fresh = label32("probe F the wallet's random nonce for the new leaf");
	let issuer = net.fund(vec![explicit(net.x, 2_000_000_000, op_true_spk())]).remove(0);
	let sched = ClockSchedule::new(token_of(&issuer), xonly(&s_key), delay(),
		vec![mt(net.now() + 28 * day), mt(net.now() + 56 * day)]).unwrap();
	let replayed = LeafSpec {
		template: Template::Vtxo1, owner: xonly(&owner), value: LEAF, owner_nonce: old_nonce, operator_nonce: old_op,
		exit_delay: delay(), unlock_hash: sha256(&label32("probe F new entry preimage")),
	};
	let tree = Tree::build(TreeParams { schedule: sched.clone(), ..params.clone() }, &[replayed]).unwrap();
	let (_, round) = plain_round(net, "probe F turned around / round with a replayed salt", &issuer, &sched, &tree.batch_output());
	let policy = WalletPolicy::new(net.chain, xonly(&s_key), mt(net.mtp()));
	let rec = tree.record(0);
	assert_eq!(rec.salt(), arca_covenant::leaf::leaf_salt(&old_nonce, &old_op));
	let e = rec.validate(&round, &policy, &xonly(&owner), &fresh).unwrap_err();
	assert_eq!(e.to_string(), "the record's owner nonce is not the one the wallet picked for this leaf");
	println!("probe F turned around: the record built from the old salt: refused, {}", e);
	let mut lying = rec.clone();
	lying.owner_nonce = fresh;
	let e = lying.validate(&round, &policy, &xonly(&owner), &fresh).unwrap_err();
	assert_eq!(e.kind(), "batch_output");
	println!("probe F turned around: the same leaf, recorded with the wallet's nonce: refused, {}", e);
}

#[test]
fn frozen_constructions_on_regtest() {
	let mut net = Net::start();
	checkpoint_chain(&mut net, false);
	checkpoint_chain(&mut net, true);
	forfeit(&mut net);
	claim_batch(&mut net);
	htlc(&mut net);
	swap(&mut net);
	entry_sweep(&mut net);
	burn(&mut net);
	built_trees(&mut net);
	probes_turned_around(&mut net);
	net.print();
	assert!(net.refused >= 30, "only {} negative cases", net.refused);
}
