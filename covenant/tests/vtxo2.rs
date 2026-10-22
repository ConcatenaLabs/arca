//! `vtxo-2` on a real node: the Simplicity collaborative path `arca/collab-2`.
//!
//! An anchored regtest chain with Simplicity active, its node checking
//! scripts inline (`-par=1`), so a block refused for a script failure names
//! it. Every negative case is refused by the mempool and again when forced
//! into a block with `generateblock`, the block's reason asserted.
//!
//! **The bindings `vtxo-2` adds.** Each attack a `vtxo-1` pair allows is run
//! twice, against a `vtxo-1` leaf, where it is mined, and against a `vtxo-2`
//! leaf, where the block is refused:
//!
//! - one pair spending two coins of one leaf script in one transaction, the
//!   second coin's value to the broadcaster (the coin's index);
//! - two pairs over the same outputs, each made for a coin spent alone,
//!   satisfied by one transaction that pays the outputs once (the index);
//! - a swap leg spent without the other leg, a third party's coin in its
//!   place, and beside a coin of the other leg's script one atom larger (the
//!   named inputs);
//! - a blinding key put on a committed output (whole outputs).
//!
//! Beside them: the swap with both legs, mined; what `vtxo-2` still allows,
//! a coin funded twice spent alone a second time into the same outputs; the
//! operator alone, the two signatures swapped, a pair under another salt and
//! a `vtxo-1` pair under the same `K`, refused; the exit, refused before its
//! delay and mined after it at `vtxo-1`'s size; and the equivocation bond
//! burned in a block with a `vtxo-2` co-signature read from the chain beside
//! a second one under the same salt.
//!
//! **Rounds.** A batch of `vtxo-2` and `vtxo-1` leaves side by side; a
//! `vtxo-2` coin paid out of round into a `vtxo-2` leaf and brought on-chain
//! through its checkpoint and reassignment; a swap of a `vtxo-2` coin and a
//! `vtxo-1` coin in one reassignment; a `vtxo-1` coin and a `vtxo-2` coin each
//! refreshed into a `vtxo-2` leaf (forfeit, the connector's issuance, the
//! operator's claim, the new leaf brought with the published preimage); and
//! every `vtxo-2` leaf exited.
//!
//! Needs `SEQUENTIAD_EXEC`; run with `--nocapture` for the table.

mod common;

use elements::confidential::Nonce;
use elements::{OutPoint, Script, Transaction, TxOut};

use arca_covenant::bond::{collab2_signed_in, rebind_rest, BondPolicy, Evidence, Form, Signed};
use arca_covenant::collab::{collab_cmr, REST_BYTES};
use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::LeafSpec;
use arca_covenant::witness::find_preimage;
use arca_covenant::*;
use common::net::*;
use common::round::*;
use common::*;

const V: u64 = 10_000_000;
const FEE: u64 = 2_000;

fn leaf(net: &Net, owner: &elements::secp256k1_zkp::Keypair, s: &elements::secp256k1_zkp::Keypair, salt: &str, v2: bool) -> LeafPolicy {
	LeafPolicy {
		owner: xonly(owner), operator: xonly(s), salt: label32(salt), chain: net.chain, exit_delay: delay(), htlc: None, order: None,
		landing: None, channel: None, v2,
	}
}

/// Both signatures over `leaf`'s message for the coin at `index` of a spend
/// naming `named` and committing to `outputs`.
fn pair(leaf: &LeafPolicy, owner: &elements::secp256k1_zkp::Keypair, s: &elements::secp256k1_zkp::Keypair, index: u32, named: &[TxOut],
	outputs: &[ExplicitOutput]) -> Pair
{
	let d = leaf.message_in(index, named, outputs).unwrap().digest;
	Pair { operator: sig(s, &d), owner: sig(owner, &d) }
}

/// A transaction spending `coins` (each with the witness given), paying
/// `outs` and a fee in X.
fn tx(net: &Net, coins: &[(&Coin, Vec<Vec<u8>>)], outs: Vec<TxOut>) -> Transaction {
	let mut s = spend(0);
	for (c, _) in coins {
		s = s.coin(c, 0xffff_ffff);
	}
	let mut outs = outs;
	outs.push(fee(net.x, FEE));
	let mut s = s.outputs(outs);
	for (i, (_, w)) in coins.iter().enumerate() {
		s.witness(i, w.clone());
	}
	s.tx
}

/// Brings a batch leaf on-chain like [`Arca::bring_leaf`], skipping the
/// nodes another leaf's unroll already published.
fn bring_leaf(c: &mut Arca, name: &str, valid: &ValidLeaf, auths: &[UnrollAuth], preimage: &[u8; 32]) -> OutPoint {
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		if c.net.rt.client().confirmations(&u.tx.txid()).is_err() {
			c.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
		}
	}
	let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	OutPoint::new(c.net.pass(&format!("{}: entry into the leaf", name), &e.tx), 0)
}

/// [`bring_leaf`] for a coin that is a batch leaf.
fn bring(c: &mut Arca, name: &str, coin: &ValidCoin) -> OutPoint {
	let ValidOrigin::Leaf { valid, preimage, auths } = &coin.origin else { unreachable!("a batch leaf") };
	bring_leaf(c, name, valid, auths, preimage)
}

fn to(net: &Net, label: &str, value: u64) -> ExplicitOutput {
	ExplicitOutput::new(net.x, value, op_true_tagged(label))
}

/// A taproot output nobody here spends, distinct per label.
fn op_true_tagged(label: &str) -> Script {
	elements::script::Builder::new().push_int(1).push_slice(&label32(label)).into_script()
}

#[test]
fn the_bindings_vtxo_2_adds_refuse_what_vtxo_1_allowed() {
	let mut net = Net::start();
	let s = keypair("v2 operator");
	let x = net.x;
	println!("arca/collab-2: root {}", collab_cmr().iter().map(|b| format!("{:02x}", b)).collect::<String>());

	// ---- one coin alone, each template ------------------------------------
	let a = keypair("v2 owner A");
	for v2 in [false, true] {
		let l = leaf(&net, &a, &s, &format!("alone {}", v2), v2);
		let c = net.fund(vec![explicit(x, V, l.script_pubkey())]).remove(0);
		let outs = [to(&net, "alone", V - FEE)];
		let p = pair(&l, &a, &s, 0, &[c.txout.clone()], &outs);
		let t = tx(&net, &[(&c, l.witness_in(&p, 1, 1))], vec![outs[0].txout()]);
		net.pass(&format!("{}: a coin alone into one output", l.template()), &t);
	}

	// ---- A1: one pair, two coins of one script, one transaction ------------
	for v2 in [false, true] {
		let l = leaf(&net, &a, &s, &format!("funded twice {}", v2), v2);
		let coins = net.fund(vec![explicit(x, V, l.script_pubkey()), explicit(x, V, l.script_pubkey())]);
		let outs = [to(&net, "A1", V - FEE)];
		let p = pair(&l, &a, &s, 0, &[coins[0].txout.clone()], &outs);
		let w = l.witness_in(&p, 1, 1);
		let both = tx(&net, &[(&coins[0], w.clone()), (&coins[1], w.clone())], vec![outs[0].txout(), explicit(x, V, op_true_spk())]);
		if v2 {
			net.refuse("ATTACK on vtxo-2: one pair spends two coins of one script, the second to the broadcaster", &both,
				"Assertion failed inside jet");
			// What vtxo-2 still allows: no outpoint is signed, so each coin
			// alone pays the same outputs; never the broadcaster.
			net.pass("vtxo-2: the first coin alone, by the pair", &tx(&net, &[(&coins[0], w.clone())], vec![outs[0].txout()]));
			net.pass("vtxo-2 RESIDUAL: the second coin alone, the same pair, the same outputs again",
				&tx(&net, &[(&coins[1], w)], vec![outs[0].txout()]));
		} else {
			net.pass("ATTACK on vtxo-1, mined: one pair spends two coins of one script, the second to the broadcaster", &both);
		}
	}

	// ---- A2: two pairs over the same outputs, each for a coin alone --------
	for v2 in [false, true] {
		let (o1, o2) = (keypair("A2 owner 1"), keypair("A2 owner 2"));
		let (l1, l2) = (leaf(&net, &o1, &s, &format!("A2 one {}", v2), v2), leaf(&net, &o2, &s, &format!("A2 two {}", v2), v2));
		let coins = net.fund(vec![explicit(x, V, l1.script_pubkey()), explicit(x, V, l2.script_pubkey())]);
		let outs = [to(&net, "A2 shared output", V - FEE)];
		let p1 = pair(&l1, &o1, &s, 0, &[coins[0].txout.clone()], &outs);
		let p2 = pair(&l2, &o2, &s, 0, &[coins[1].txout.clone()], &outs);
		let both = tx(&net, &[(&coins[0], l1.witness_in(&p1, 1, 1)), (&coins[1], l2.witness_in(&p2, 1, 1))],
			vec![outs[0].txout(), explicit(x, V, op_true_spk())]);
		if v2 {
			net.refuse("ATTACK on vtxo-2: two pairs over one output, both leaves in one transaction, one paid to the broadcaster",
				&both, "Assertion failed inside jet");
		} else {
			net.pass("ATTACK on vtxo-1, mined: two pairs over one output, both leaves in one transaction, one to the broadcaster", &both);
		}
	}

	// ---- A3: a swap leg without the other leg ------------------------------
	for v2 in [false, true] {
		let (ox, oy) = (keypair("A3 owner X"), keypair("A3 owner Y"));
		let (lx, ly) = (leaf(&net, &ox, &s, &format!("A3 X {}", v2), v2), leaf(&net, &oy, &s, &format!("A3 Y {}", v2), v2));
		let coins = net.fund(vec![explicit(x, V, lx.script_pubkey()), explicit(x, V, ly.script_pubkey()),
			explicit(x, V, op_true_spk()), explicit(x, V + 1, ly.script_pubkey())]);
		let (cx, cy, third, bigger) = (&coins[0], &coins[1], &coins[2], &coins[3]);
		let outs = [to(&net, "A3 to Y", V - FEE / 2), to(&net, "A3 to X", V - FEE / 2)];
		let named = [cx.txout.clone(), cy.txout.clone()];
		let px = pair(&lx, &ox, &s, 0, &named, &outs);
		let py = pair(&ly, &oy, &s, 1, &named, &outs);
		let third_witness = op_true_witness();
		let alone = tx(&net, &[(cx, lx.witness_in(&px, 2, 2)), (third, third_witness.clone())],
			vec![outs[0].txout(), outs[1].txout()]);
		if v2 {
			net.refuse("ATTACK on vtxo-2: X's swap leg spent, a third party's coin in place of Y's", &alone, "Assertion failed inside jet");
			let mut big = tx(&net, &[(cx, lx.witness_in(&px, 2, 2)), (bigger, ly.witness_in(&py, 2, 2))],
				vec![outs[0].txout(), outs[1].txout()]);
			big.output[2] = fee(x, FEE + 1);
			net.refuse("vtxo-2: the swap beside a coin of Y's script one atom larger", &big, "Assertion failed inside jet");
			let both = tx(&net, &[(cx, lx.witness_in(&px, 2, 2)), (cy, ly.witness_in(&py, 2, 2))],
				vec![outs[0].txout(), outs[1].txout()]);
			net.pass("vtxo-2: the swap, both legs", &both);
		} else {
			net.pass("ATTACK on vtxo-1, mined: X's swap leg spent, a third party's coin in place of Y's", &alone);
		}
	}

	// ---- whole outputs: a blinding key put on a committed output -----------
	for v2 in [false, true] {
		let l = leaf(&net, &a, &s, &format!("nonce {}", v2), v2);
		let c = net.fund(vec![explicit(x, V, l.script_pubkey())]).remove(0);
		let outs = [to(&net, "nonce", V - FEE)];
		let p = pair(&l, &a, &s, 0, &[c.txout.clone()], &outs);
		let mut o = outs[0].txout();
		o.nonce = Nonce::Confidential(keypair("a blinding key").public_key());
		let t = tx(&net, &[(&c, l.witness_in(&p, 1, 1))], vec![o]);
		// sendrawtransaction refuses an unblinded output with a nonce before
		// it runs a script, so this case goes to testmempoolaccept and to a
		// block.
		let r = net.rt.client().test_mempool_accept(&[&t]).unwrap().remove(0);
		let h0 = net.height();
		let block = net.rt.client().generate_block("raw(51)", &[&t]);
		if v2 {
			let reason = r.reject_reason.clone().unwrap_or_default();
			assert!(!r.allowed && reason.contains("Assertion failed inside jet"), "testmempoolaccept said {:?}", reason);
			let block = format!("{:?}", block.expect_err("a block took a blinding key on a vtxo-2 committed output"));
			assert!(block.contains(&block_reason(&reason)), "the block was refused with {}, not for {:?}", block, reason);
			assert_eq!(net.height(), h0);
			net.refused += 1;
			net.rows.push(Row { name: "vtxo-2: a blinding key put on the committed output".into(), vsize: String::new(),
				mempool: reason, block });
		} else {
			assert!(r.allowed, "testmempoolaccept: {:?}", r.reject_reason);
			block.expect("generateblock takes it");
			assert!(net.rt.client().confirmations(&t.txid()).unwrap() >= 1);
			net.confirmed += 1;
			net.rows.push(Row { name: "vtxo-1, mined: a blinding key put on the committed output".into(),
				vsize: r.vsize.map(|v| v.to_string()).unwrap_or_default(), mempool: "accepted (testmempoolaccept)".into(),
				block: "mined with generateblock".into() });
		}
	}

	// ---- the pair itself ----------------------------------------------------
	let l = leaf(&net, &a, &s, "pair checks", true);
	let c = net.fund(vec![explicit(x, V, l.script_pubkey())]).remove(0);
	let outs = [to(&net, "pair checks", V - FEE)];
	let named = [c.txout.clone()];
	let d = l.message_in(0, &named, &outs).unwrap().digest;
	let spend_with = |net: &Net, p: Pair| tx(net, &[(&c, l.witness_in(&p, 1, 1))], vec![outs[0].txout()]);
	net.refuse("vtxo-2: the operator alone, its signature in both places", &spend_with(&net, Pair { operator: sig(&s, &d), owner: sig(&s, &d) }),
		"Assertion failed inside jet");
	net.refuse("vtxo-2: the two signatures swapped", &spend_with(&net, Pair { operator: sig(&a, &d), owner: sig(&s, &d) }),
		"Assertion failed inside jet");
	let other = leaf(&net, &a, &s, "another salt", true);
	let od = other.collab2().message(0, &named, &[outs[0].txout()]).unwrap().digest;
	net.refuse("vtxo-2: a pair made under another salt", &spend_with(&net, Pair { operator: sig(&s, &od), owner: sig(&a, &od) }),
		"Assertion failed inside jet");
	let v1 = LeafPolicy { v2: false, ..l };
	let vd = v1.collab_message(x, V, &outs).unwrap().digest;
	net.refuse("vtxo-2: a vtxo-1 pair under the same K", &spend_with(&net, Pair { operator: sig(&s, &vd), owner: sig(&a, &vd) }),
		"Assertion failed inside jet");
	let collab = spend_with(&net, Pair { operator: sig(&s, &d), owner: sig(&a, &d) });
	let spent_at = net.pass("vtxo-2: the honest pair", &collab);

	// ---- the bond burns on a vtxo-2 double-sign ----------------------------
	let bond = BondPolicy::new(net.chain, xonly(&s), xonly(&keypair("v2 bond W")), RelativeTime::from_units(4).unwrap()).unwrap();
	let mined = net.rt.client().raw_transaction(&spent_at).unwrap();
	let from_chain = collab2_signed_in(&net.chain, &l.salt, &mined, 0, &named).expect("the vtxo-2 spend, read from the chain");
	assert_eq!(from_chain.rest.len(), REST_BYTES);
	assert!(bond.verify(&l.salt, &from_chain), "S's signature as the chain carries it");
	let kept_msg = l.message_in(0, &named, &[to(&net, "the other spend S signed", V - FEE)]).unwrap();
	let kept = Signed { form: Form::Rebind, rest: rebind_rest(&kept_msg.preimage).unwrap(), signature: sig(&s, &kept_msg.digest) };
	let posted = net.fund(vec![explicit(x, 1_000_000, bond.script_pubkey())]).remove(0);
	let slash = |net: &mut Net, e: &Evidence| {
		let fee_coin = net.fund(vec![explicit(x, 20_000, op_true_spk())]).remove(0);
		let mut t = bond.slash_tx(&[(posted.outpoint, posted.txout.clone())], e, &FeeSource::Coin {
			outpoint: fee_coin.outpoint, coin: fee_coin.txout.clone(), fee: 2_000, change: op_true_spk() }).unwrap().tx;
		t.input[1].witness.script_witness = op_true_witness();
		t
	};
	let resigned = Signed { signature: elements::secp256k1_zkp::Secp256k1::new().sign_schnorr_with_aux_rand(
		&elements::secp256k1_zkp::Message::from_digest(bond.digest_of(&l.salt, &from_chain)), &s, &[9; 32]), ..from_chain.clone() };
	assert_ne!(resigned.signature, from_chain.signature);
	let one_digest = Evidence { salt: l.salt, a: from_chain.clone(), b: resigned };
	let t = slash(&mut net, &one_digest);
	net.refuse("slash on one vtxo-2 digest signed twice", &t, "Script failed an OP_VERIFY operation");
	let evidence = Evidence { salt: l.salt, a: kept, b: from_chain };
	assert_eq!(bond.check(&evidence), Ok(()));
	let t = slash(&mut net, &evidence);
	net.pass("slash of the bond on two vtxo-2 co-signatures under one salt", &t);

	// ---- the exit is vtxo-1's ---------------------------------------------
	for v2 in [false, true] {
		let l = leaf(&net, &a, &s, &format!("exit {}", v2), v2);
		let c = net.fund(vec![explicit(x, V, l.script_pubkey())]).remove(0);
		let e = exit_tx(&net, &l, c.outpoint, x, V, &a);
		if v2 {
			net.refuse("vtxo-2: the exit before its delay", &e, "non-BIP68-final");
		}
		net.wait_csv(&c.outpoint.txid, delay());
		net.pass(&format!("{}: the exit after its delay", l.template()), &e);
	}
	net.print();
}

/// The new leaf a coin is refreshed into: its spec in round two.
struct Fresh {
	owner: elements::secp256k1_zkp::Keypair,
	spec: LeafSpec,
	preimage: [u8; 32],
}

fn fresh(label: &str, v2: bool) -> Fresh {
	let owner = keypair(&format!("{} new owner", label));
	let preimage = label32(&format!("{} preimage", label));
	let mut sp = spec(&owner, &format!("{} new leaf", label), LEAF - 2_000, sha256(&preimage));
	if v2 {
		sp.template = Template::Vtxo2;
	}
	Fresh { owner, spec: sp, preimage }
}

#[test]
fn a_round_of_vtxo_2_leaves_transfers_refreshes_and_exits() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("round operator");
	let t0 = mt(c.net.mtp() - 60);

	// ---- round one: vtxo-2 and vtxo-1 leaves in one batch ------------------
	let owners: Vec<_> = (0..4).map(|i| keypair(&format!("round one owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..4).map(|i| label32(&format!("round one preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..4).map(|i| {
		let mut sp = spec(&owners[i], &format!("round one leaf {}", i), LEAF, sha256(&preimages[i]));
		if i < 3 {
			sp.template = Template::Vtxo2;
		}
		sp
	}).collect();
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &specs);
	let (round1, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass("round one: three vtxo-2 leaves and a vtxo-1 leaf in one batch", &round1);
	let coins: Vec<ValidCoin> = (0..4).map(|i| {
		let rec = base(&tree, i, &owners[i], preimages[i], t0);
		let coin = rec.validate(&[round1.clone()], &c.policy(&s), &xonly(&owners[i]), &specs[i].owner_nonce).unwrap();
		assert_eq!(coin.leaf.template(), if i < 3 { Template::Vtxo2 } else { Template::Vtxo1 });
		coin
	}).collect();
	let records: Vec<CoinRecord> = (0..4).map(|i| base(&tree, i, &owners[i], preimages[i], t0)).collect();
	println!("round one: leaves 0..2 vtxo-2, leaf 3 vtxo-1; each record checks against the round");

	// ---- a vtxo-2 coin paid out of round into a vtxo-2 leaf ----------------
	let (r_key, mut r_leaf) = party("v2 receiver", delay());
	r_leaf.v2 = true;
	let paid_rec = one_hop(&records[0], &coins[0], &owners[0], &s, r_leaf, c.net.chain);
	let paid_coin = paid_rec.validate(&[round1.clone()], &c.policy(&s).receipt(), &xonly(&r_key), &r_leaf.owner_nonce).unwrap();
	assert_eq!(paid_coin.leaf.template(), Template::Vtxo2);
	assert!(inputs(&paid_coin)[0].checkpoint.v2, "a vtxo-2 coin moves into a vtxo-2 checkpoint");
	let at0 = bring(&mut c, "leaf 0 (vtxo-2)", &coins[0]);
	let cp = inputs(&paid_coin)[0].checkpoint_tx(at0, &FeeSource::Reserve).unwrap();
	let cp_id = c.net.pass("leaf 0: its checkpoint (vtxo-2 path, n=1)", &cp.tx);
	let re = paid_coin.reassignment_tx(&[OutPoint::new(cp_id, 0)], &FeeSource::Reserve).unwrap();
	let re_id = c.net.pass("leaf 0: the reassignment into the receiver's vtxo-2 leaf (n=1)", &re.tx);
	c.net.wait_csv(&re_id, delay());
	c.net.pass("the receiver's exit of its vtxo-2 leaf", &exit_tx(&c.net, &paid_coin.leaf, OutPoint::new(re_id, 0), x, paid_coin.value,
		&r_key));

	// ---- a swap: a vtxo-2 coin and a vtxo-1 coin in one reassignment -------
	let (kb, mut lb) = party("swap to owner 3", delay());
	lb.v2 = true;
	let (kd, ld) = party("swap to owner 1", delay());
	let cpv = LEAF - MARGIN;
	let plan = TransferPlan {
		inputs: vec![(coins[1].clone(), cpv), (coins[3].clone(), cpv)],
		outputs: vec![
			ExplicitOutput::new(x, cpv - MARGIN, ld.policy(xonly(&s), c.net.chain).script_pubkey()),
			ExplicitOutput::new(x, cpv - MARGIN, lb.policy(xonly(&s), c.net.chain).script_pubkey()),
		],
	};
	let input_of = |k: usize, rec: &CoinRecord, key: &elements::secp256k1_zkp::Keypair| {
		let cpd = plan.checkpoint_message(k).unwrap().digest;
		let red = plan.reassignment_message(k).unwrap().digest;
		TransferInput { coin: rec.clone(), checkpoint_value: cpv, checkpoint: Pair { operator: sig(&s, &cpd), owner: sig(key, &cpd) },
			reassignment: Pair { operator: sig(&s, &red), owner: sig(key, &red) } }
	};
	let swap_inputs = vec![input_of(0, &records[1], &owners[1]), input_of(1, &records[3], &owners[3])];
	let to_d = CoinRecord::Transfer(Box::new(arca_covenant::transfer::Transfer { inputs: swap_inputs.clone(), outputs: plan.outputs.clone(),
		index: 0, leaf: ld }));
	let to_b = CoinRecord::Transfer(Box::new(arca_covenant::transfer::Transfer { inputs: swap_inputs, outputs: plan.outputs.clone(),
		index: 1, leaf: lb }));
	let coin_d = to_d.validate(&[round1.clone()], &c.policy(&s).receipt(), &xonly(&kd), &ld.owner_nonce).unwrap();
	let coin_b = to_b.validate(&[round1.clone()], &c.policy(&s).receipt(), &xonly(&kb), &lb.owner_nonce).unwrap();
	assert_eq!((coin_d.leaf.template(), coin_b.leaf.template()), (Template::Vtxo1, Template::Vtxo2));
	let ins = inputs(&coin_b);
	assert!(ins[0].checkpoint.v2 && !ins[1].checkpoint.v2);
	let at1 = bring(&mut c, "leaf 1 (vtxo-2)", &coins[1]);
	let at3 = bring(&mut c, "leaf 3 (vtxo-1)", &coins[3]);
	let cp1 = c.net.pass("leaf 1: its checkpoint (vtxo-2)", &ins[0].checkpoint_tx(at1, &FeeSource::Reserve).unwrap().tx);
	let cp3 = c.net.pass("leaf 3: its checkpoint (vtxo-1)", &ins[1].checkpoint_tx(at3, &FeeSource::Reserve).unwrap().tx);
	let swap = coin_b.reassignment_tx(&[OutPoint::new(cp1, 0), OutPoint::new(cp3, 0)], &FeeSource::Reserve).unwrap();
	// Each vtxo-2 checkpoint's pair names both checkpoints: the leg is not
	// spent with a coin in place of the other.
	let mut one_leg = swap.tx.clone();
	let stranger = c.net.fund(vec![explicit(x, cpv, op_true_spk())]).remove(0);
	one_leg.input[1].previous_output = stranger.outpoint;
	one_leg.input[1].witness.script_witness = op_true_witness();
	c.net.refuse("the swap's vtxo-2 leg with a stranger's coin in place of the vtxo-1 leg", &one_leg, "Assertion failed inside jet");
	let swap_id = c.net.pass("the swap: a vtxo-2 checkpoint (n=2, k=0) and a vtxo-1 checkpoint, one reassignment", &swap.tx);
	c.net.wait_csv(&swap_id, delay());
	c.net.pass("the swap's vtxo-2 output exited", &exit_tx(&c.net, &coin_b.leaf, OutPoint::new(swap_id, 1), x, coin_b.value, &kb));

	// ---- round two: refreshes into vtxo-2 ----------------------------------
	// Leaf 2 (vtxo-2) and a vtxo-1 coin each forfeited for a new vtxo-2 leaf.
	let (old_v1, old_v1_coin, old_v1_id) = funded_leaf(&mut c.net, &keypair("refresh v1 owner"), &s, "refresh v1", LEAF);
	let old_v1_owner = keypair("refresh v1 owner");
	let f_v2 = fresh("from vtxo-2", true);
	let f_v1 = fresh("from vtxo-1", true);
	let (issuer2, sched2) = c.schedule(&s);
	let tree2 = c.tree(&sched2, &[f_v2.spec.clone(), f_v1.spec.clone()]);
	let (round2, cv) = round_tx(&c.net, &issuer2, &[], &tree2.batch_output(), &sched2);
	c.net.pass("round two: two new vtxo-2 leaves", &round2);
	let valid = |i: usize, f: &Fresh| tree2.record(i).validate(&round2, &c.policy(&s), &xonly(&f.owner), &f.spec.owner_nonce).unwrap();
	let (v_new2, v_new1) = (valid(0, &f_v2), valid(1, &f_v1));
	assert_eq!((v_new2.branch.leaf.template(), v_new1.branch.leaf.template()), (Template::Vtxo2, Template::Vtxo2));
	let forfeit_v2 = Forfeit::for_refresh(coins[2].leaf, (x, LEAF), coins[2].id, &v_new2, &round2, cv, delay(), 1_500).unwrap();
	let forfeit_v1 = Forfeit::for_refresh(old_v1, (x, LEAF), old_v1_id, &v_new1, &round2, cv, delay(), 1_500).unwrap();
	let pair_v2 = forfeit_pair(&forfeit_v2, &owners[2], &s);
	let pair_v1 = forfeit_pair(&forfeit_v1, &old_v1_owner, &s);
	forfeit_v2.verify(&pair_v2).unwrap();
	forfeit_v1.verify(&pair_v1).unwrap();

	// The old coins reach the chain and the operator answers with the forfeits.
	let at2 = bring(&mut c, "leaf 2 (vtxo-2), given up", &coins[2]);
	let ft2 = c.net.pass("the forfeit of a vtxo-2 leaf (vtxo-2 path)", &forfeit_v2.tx(at2, &pair_v2, &FeeSource::Reserve).unwrap().tx);
	let ft1 = c.net.pass("the forfeit of a vtxo-1 coin (vtxo-1 path)",
		&forfeit_v1.tx(old_v1_coin.outpoint, &pair_v1, &FeeSource::Reserve).unwrap().tx);
	let it = c.net.pass("the issuance of round two's connector asset", &issuance_tx(&c.net, &round2, cv, &s));
	let m = coin_of(it, 0, &c.net.rt.client().raw_transaction(&it).unwrap());
	let ct2 = c.net.pass("the operator's claim of the vtxo-2 forfeit", &claim_tx(&c.net, &forfeit_v2, OutPoint::new(ft2, 0), &m, &s,
		&f_v2.preimage));
	let m2 = coin_of(ct2, 1, &c.net.rt.client().raw_transaction(&ct2).unwrap());
	let ct1 = c.net.pass("the operator's claim of the vtxo-1 forfeit", &claim_tx(&c.net, &forfeit_v1, OutPoint::new(ft1, 0), &m2, &s,
		&f_v1.preimage));

	// Each owner takes its new vtxo-2 leaf with the preimage the claim
	// published, and exits it. Both authorise the unroll at one time, so the
	// node they share is one transaction.
	let t2 = mt(c.net.mtp() - 60);
	for (name, f, v, claim) in [("vtxo-2 refreshed into vtxo-2", &f_v2, &v_new2, ct2), ("vtxo-1 refreshed into vtxo-2", &f_v1, &v_new1, ct1)] {
		let learned = find_preimage(&c.net.witness_of(&claim, 0), &sha256(&f.preimage)).unwrap();
		let auths = owner_auths(v, &f.owner, t2);
		let at = bring_leaf(&mut c, name, v, &auths, &learned);
		c.net.wait_csv(&at.txid, delay());
		c.net.pass(&format!("{}: the owner's exit of the new leaf", name), &exit_tx(&c.net, &v.branch.leaf, at, x, LEAF - 2_000, &f.owner));
	}
	c.net.print();
}
