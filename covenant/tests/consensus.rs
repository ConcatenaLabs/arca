//! Every policy's paths through the node's interpreter.
//!
//! Each path is spent by a transaction built with this crate and verified,
//! every input, with `arca-consensus` under the block rules and under the
//! node's mempool script checks. Each negative case the regtest prototype ran
//! at the script level is built the same way and must be refused by the block
//! rules, with the node's own error. (A lock-time or BIP68 refusal of a
//! non-final transaction is not a script error; those are forced into blocks
//! on a node in `tests/regtest.rs`.) `-- --nocapture` prints the table.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{AssetId, BlockHash, OutPoint, SchnorrSighashType, Script, TxOut, Txid};

use arca_consensus::Verifier;
use arca_covenant::htlc::HtlcPath;
use arca_covenant::message::rebind_message;
use arca_covenant::script::{record, sha256};
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{FeeSource, SpendError, UnrollError, UnrollTx};
use arca_covenant::*;

use common::*;

const LEAF: u64 = 10_000_000;
const RESERVE: u64 = 2_500;
const FEE: u64 = 600;

/// The verdict of every case, kept for the table.
struct Book {
	consensus: Verifier,
	standard: Verifier,
	rows: Vec<(String, String)>,
	passed: usize,
	refused: usize,
}

impl Book {
	fn new(genesis: BlockHash) -> Book {
		Book {
			consensus: Verifier::consensus(genesis),
			standard: Verifier::standard(genesis),
			rows: vec![],
			passed: 0,
			refused: 0,
		}
	}

	/// Every input verifies under the block rules and the mempool's checks.
	fn pass(&mut self, name: &str, s: &Spend) {
		self.consensus.verify_tx(&s.prevouts, &s.tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} refused by the block rules: {}", name, i, e));
		self.standard.verify_tx(&s.prevouts, &s.tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} refused by the mempool checks: {}", name, i, e));
		self.passed += 1;
		self.rows.push((name.to_string(), "valid".into()));
	}

	/// Input `idx` is refused by the block rules with an error naming `expect`.
	fn fail(&mut self, name: &str, s: &Spend, idx: usize, expect: &str) {
		let e = self.consensus.verify_input(&s.prevouts, idx, &s.tx)
			.err().unwrap_or_else(|| panic!("{}: ACCEPTED by the block rules", name));
		let msg = e.to_string();
		assert!(msg.contains(expect), "{}: refused with {:?}, expected {:?}", name, msg, expect);
		self.refused += 1;
		self.rows.push((name.to_string(), msg));
	}

	/// The block rules accept input `idx`; the mempool's checks refuse it
	/// with an error naming `expect`. Such a spend is not standard but a
	/// producer can mine it.
	fn policy_only(&mut self, name: &str, s: &Spend, idx: usize, expect: &str) {
		self.consensus.verify_input(&s.prevouts, idx, &s.tx)
			.unwrap_or_else(|e| panic!("{}: refused by the block rules: {}", name, e));
		let e = self.standard.verify_input(&s.prevouts, idx, &s.tx)
			.err().unwrap_or_else(|| panic!("{}: accepted by the mempool checks", name));
		let msg = e.to_string();
		assert!(msg.contains(expect), "{}: mempool refused with {:?}, expected {:?}", name, msg, expect);
		self.rows.push((name.to_string(), format!("valid in a block; mempool: {}", msg)));
	}

	fn print(&self) {
		println!("\n{:<70} verdict", "case");
		for (n, v) in &self.rows {
			println!("{:<70} {}", n, v);
		}
		println!("\n{} spends verified, {} negative cases refused", self.passed, self.refused);
	}
}

const BAD_SIG: &str = "Invalid Schnorr signature";
const EQUALVERIFY: &str = "Script failed an OP_EQUALVERIFY operation";
const FALSE: &str = "Script evaluated without error but finished with a false/empty top stack element";
const LOCKTIME: &str = "Locktime requirement not satisfied";

struct F {
	genesis: BlockHash,
	chain: Chain,
	s: Keypair,
	a: Keypair,
	b: Keypair,
	stranger: Keypair,
	x: AssetId,
	y: AssetId,
	w: RelativeTime,
	delay: RelativeTime,
	created: MedianTime,
	schedule: ClockSchedule,
}

impl F {
	fn new() -> F {
		let genesis = BlockHash::from_byte_array(label32("genesis"));
		let s = keypair("S");
		let w = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
		let created = MedianTime::from_consensus(1_791_000_000).unwrap();
		let e = |d: u32| MedianTime::from_consensus(1_791_000_000 + d * 86_400).unwrap();
		let schedule = ClockSchedule::new(asset("T"), xonly(&s), w, vec![e(28), e(56), e(84)]).unwrap();
		F {
			genesis,
			chain: Chain::new(genesis),
			s,
			a: keypair("A"),
			b: keypair("B"),
			stranger: keypair("stranger"),
			x: asset("X"),
			y: asset("Y"),
			w,
			delay: w,
			created,
			schedule,
		}
	}

	fn leaf(&self, owner: &Keypair, salt: &str) -> LeafPolicy {
		LeafPolicy { owner: xonly(owner), operator: xonly(&self.s), salt: label32(salt), chain: self.chain, exit_delay: self.delay }
	}

	fn r_coin(&self) -> TxOut {
		explicit(self.schedule.token, 1, self.schedule.r().script_pubkey())
	}

	/// The R input's witness for a transaction signed in full.
	fn r_witness(&self, s: &Spend, idx: usize) -> Vec<Vec<u8>> {
		let r = self.schedule.r();
		let script = self.schedule.r_script();
		r.witness(&script, ClockSchedule::r_witness_items(&s.sign(&self.s, idx, &script, self.genesis)))
	}

	fn fee_coin(&self, asset: AssetId, value: u64) -> TxOut {
		explicit(asset, value, op_true().script_pubkey())
	}

	fn operator_spk(&self) -> Script {
		TapOutput::new(vec![(0, Script::from(vec![0x51]))]).script_pubkey()
	}
}

fn out(o: &ExplicitOutput) -> TxOut {
	o.txout()
}

// ---------------------------------------------------------------------------
// The leaf
// ---------------------------------------------------------------------------

fn leaf_cases(f: &F, book: &mut Book) {
	let leaf = f.leaf(&f.a, "leaf");
	let coin = explicit(f.x, LEAF, leaf.script_pubkey());
	let recv = ExplicitOutput::new(f.x, 6_000_000, f.leaf(&f.b, "recv").script_pubkey());
	let chg = ExplicitOutput::new(f.x, LEAF - 6_000_000 - FEE, f.leaf(&f.a, "chg").script_pubkey());
	let outs = vec![recv.clone(), chg.clone()];
	let msg = leaf.collab_message(f.x, LEAF, &outs).unwrap();
	let (ss, sa) = (sig(&f.s, &msg.digest), sig(&f.a, &msg.digest));

	let spend = |coin: &TxOut, outs: Vec<TxOut>, w: Vec<Vec<u8>>| {
		let mut s = Spend::new(0).fake_input("leaf", coin.clone(), 0xffff_ffff).outputs(outs);
		s.witness(0, w);
		s
	};
	let paid = |outs: &[&ExplicitOutput], fee_v: u64| {
		let mut v: Vec<TxOut> = outs.iter().map(|o| out(o)).collect();
		v.push(fee(f.x, fee_v));
		v
	};
	let cw = |ss: &Signature, sa: &Signature, m: u8| leaf.collab_witness(ss, sa, m);

	book.pass("leaf/collab m=2: receiver and change", &spend(&coin, paid(&[&recv, &chg], FEE), cw(&ss, &sa, 2)));

	// Each committed field, changed after signing.
	let mut o = recv.clone();
	o.asset = f.y;
	book.fail("leaf/neg committed output's asset changed", &spend(&coin, paid(&[&o, &chg], FEE), cw(&ss, &sa, 2)), 0, BAD_SIG);
	let mut o = recv.clone();
	o.value -= 1;
	book.fail("leaf/neg committed output's value minus 1", &spend(&coin, paid(&[&o, &chg], FEE + 1), cw(&ss, &sa, 2)), 0, BAD_SIG);
	let mut o = recv.clone();
	o.value += 1;
	book.fail("leaf/neg committed output's value plus 1", &spend(&coin, paid(&[&o, &chg], FEE - 1), cw(&ss, &sa, 2)), 0, BAD_SIG);
	let mut o = recv.clone();
	o.script_pubkey = f.leaf(&f.stranger, "x").script_pubkey();
	book.fail("leaf/neg committed output's script changed", &spend(&coin, paid(&[&o, &chg], FEE), cw(&ss, &sa, 2)), 0, BAD_SIG);
	// A v0 program `P ‖ 0x01` in place of the v1 program `P`: same bytes under a raw version.
	let mut o = recv.clone();
	let mut p33 = o.script_pubkey.as_bytes()[2..].to_vec();
	p33.push(0x01);
	o.script_pubkey = elements::script::Builder::new().push_int(0).push_slice(&p33).into_script();
	book.fail("leaf/neg v0 33-byte program substituted", &spend(&coin, paid(&[&o, &chg], FEE), cw(&ss, &sa, 2)), 0, BAD_SIG);
	book.fail("leaf/neg outputs reordered", &spend(&coin, paid(&[&chg, &recv], FEE), cw(&ss, &sa, 2)), 0, BAD_SIG);
	book.fail("leaf/neg second committed output missing", &spend(&coin, paid(&[&recv], LEAF - 6_000_000), cw(&ss, &sa, 2)), 0, BAD_SIG);

	// m.
	book.fail("leaf/neg m=1 with signatures for 2", &spend(&coin, paid(&[&recv, &chg], FEE), cw(&ss, &sa, 1)), 0, BAD_SIG);
	let third = ExplicitOutput::new(f.x, 1, f.operator_spk());
	book.fail("leaf/neg m=3 with signatures for 2", &spend(&coin, paid(&[&recv, &chg, &third], FEE - 1), cw(&ss, &sa, 3)), 0, BAD_SIG);
	let with_m = |m: Vec<u8>| {
		let mut w = cw(&ss, &sa, 2);
		w[2] = m;
		spend(&coin, paid(&[&recv, &chg], FEE), w)
	};
	book.fail("leaf/neg m empty", &with_m(vec![]), 0, EQUALVERIFY);
	book.fail("leaf/neg m zero byte", &with_m(vec![0]), 0, "");
	book.fail("leaf/neg m=5, above the maximum", &with_m(vec![5]), 0, "Script failed an OP_VERIFY operation");
	book.fail("leaf/neg m as two bytes", &with_m(vec![2, 0]), 0, EQUALVERIFY);

	// Signatures.
	let other_salt = f.leaf(&f.a, "another leaf").collab_message(f.x, LEAF, &outs).unwrap();
	book.fail("leaf/neg signatures for a different salt",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&sig(&f.s, &other_salt.digest), &sig(&f.a, &other_salt.digest), 2)), 0, BAD_SIG);
	book.fail("leaf/neg owner's signature by the wrong key",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&ss, &sig(&f.stranger, &msg.digest), 2)), 0, BAD_SIG);
	book.fail("leaf/neg operator's signature by the wrong key",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&sig(&f.stranger, &msg.digest), &sa, 2)), 0, BAD_SIG);
	let empty_s = { let mut w = cw(&ss, &sa, 2); w[0] = vec![]; spend(&coin, paid(&[&recv, &chg], FEE), w) };
	book.fail("leaf/neg operator's signature missing", &empty_s, 0, FALSE);
	let empty_a = { let mut w = cw(&ss, &sa, 2); w[1] = vec![]; spend(&coin, paid(&[&recv, &chg], FEE), w) };
	book.fail("leaf/neg owner's signature missing (the operator alone)", &empty_a, 0, "OP_CHECKSIGVERIFY");
	book.fail("leaf/neg signatures swapped", &spend(&coin, paid(&[&recv, &chg], FEE), cw(&sa, &ss, 2)), 0, BAD_SIG);
	book.fail("leaf/neg the operator signs both slots (the operator alone)",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&ss, &sig(&f.s, &msg.digest), 2)), 0, BAD_SIG);
	// The message without the coin and the chain.
	let mut old = b"ArcaRbd1".to_vec();
	old.extend(label32("leaf"));
	old.push(2);
	for o in &outs {
		old.extend(sha256(&o.record()));
	}
	let old = sha256(&old);
	book.fail("leaf/neg signatures over the message without coin and chain",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&sig(&f.s, &old), &sig(&f.a, &old), 2)), 0, BAD_SIG);

	// The coin.
	let coin_plus = explicit(f.x, LEAF + 5_000, leaf.script_pubkey());
	book.fail("leaf/neg a coin of the same script with 5000 atoms more",
		&spend(&coin_plus, paid(&[&recv, &chg], FEE + 5_000), cw(&ss, &sa, 2)), 0, BAD_SIG);
	let coin_minus = explicit(f.x, LEAF - 1, leaf.script_pubkey());
	book.fail("leaf/neg a coin of the same script one atom short",
		&spend(&coin_minus, paid(&[&recv, &chg], FEE - 1), cw(&ss, &sa, 2)), 0, BAD_SIG);
	let coin_y = explicit(f.y, LEAF, leaf.script_pubkey());
	book.fail("leaf/neg a coin of the same script in another asset",
		&spend(&coin_y, paid(&[&recv, &chg], FEE), cw(&ss, &sa, 2)), 0, BAD_SIG);
	// A second coin with the same script, asset and amount: the pair spends it too,
	// which is why a leaf script is never funded twice.
	let mut s = spend(&coin, paid(&[&recv, &chg], FEE), cw(&ss, &sa, 2));
	s.tx.input[0].previous_output.vout = 7;
	book.pass("leaf/collab the same pair on a second coin of the same script, asset and amount", &s);

	// The chain.
	let other = Chain::new(BlockHash::from_byte_array(label32("another chain")));
	let m_other = rebind_message(&other.leaf_constant(&leaf.salt), f.x, LEAF, &outs).unwrap();
	book.fail("leaf/neg a pair made for another genesis hash",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&sig(&f.s, &m_other.digest), &sig(&f.a, &m_other.digest), 2)), 0, BAD_SIG);
	let mut rev = f.genesis.to_byte_array();
	rev.reverse();
	let display = Chain::new(BlockHash::from_byte_array(rev));
	let m_disp = rebind_message(&display.leaf_constant(&leaf.salt), f.x, LEAF, &outs).unwrap();
	book.fail("leaf/neg a pair made with the genesis hash in display order",
		&spend(&coin, paid(&[&recv, &chg], FEE), cw(&sig(&f.s, &m_disp.digest), &sig(&f.a, &m_disp.digest), 2)), 0, BAD_SIG);

	// m = 1 and m = 4, and an outside fee coin.
	let one = ExplicitOutput::new(f.x, LEAF - FEE, f.leaf(&f.b, "one").script_pubkey());
	let m1 = leaf.collab_message(f.x, LEAF, std::slice::from_ref(&one)).unwrap();
	book.pass("leaf/collab m=1", &spend(&coin, paid(&[&one], FEE), cw(&sig(&f.s, &m1.digest), &sig(&f.a, &m1.digest), 1)));
	let four: Vec<ExplicitOutput> = (0..4).map(|i| ExplicitOutput::new(f.x, 2_499_850, f.leaf(&f.b, &format!("four{}", i)).script_pubkey())).collect();
	let m4 = leaf.collab_message(f.x, LEAF, &four).unwrap();
	book.pass("leaf/collab m=4", &spend(&coin, paid(&four.iter().collect::<Vec<_>>(), LEAF - 4 * 2_499_850),
		cw(&sig(&f.s, &m4.digest), &sig(&f.a, &m4.digest), 4)));
	let mut s = Spend::new(0).fake_input("leaf", coin.clone(), 0xffff_ffff)
		.fake_input("fee coin", f.fee_coin(f.y, 5_000), 0xffff_ffff)
		.outputs(vec![out(&recv), out(&chg), explicit(f.x, FEE, f.operator_spk()), fee(f.y, 5_000)]);
	s.witness(0, cw(&ss, &sa, 2));
	s.witness(1, op_true_witness());
	book.pass("leaf/collab m=2 with an outside fee coin in another asset", &s);

	// The exit.
	let exit = |seq: u32, version: u32, key: &Keypair| {
		let mut s = Spend::new(0).fake_input("leaf", coin.clone(), seq)
			.outputs(vec![explicit(f.x, LEAF - FEE, f.operator_spk()), fee(f.x, FEE)]);
		s.tx.version = version;
		let sg = s.sign(key, 0, &leaf.exit_script(), f.genesis);
		s.witness(0, leaf.exit_witness(&sg));
		s
	};
	let d = f.delay.to_sequence();
	book.pass("leaf/exit after the delay", &exit(d, 2, &f.a));
	book.fail("leaf/neg exit one unit before the delay", &exit(d - 1, 2, &f.a), 0, LOCKTIME);
	book.fail("leaf/neg exit in a version 1 transaction", &exit(d, 1, &f.a), 0, LOCKTIME);
	book.fail("leaf/neg exit with a height-based sequence", &exit(f.delay.units() as u32, 2, &f.a), 0, LOCKTIME);
	book.fail("leaf/neg the operator signs the exit path", &exit(d, 2, &f.s), 0, BAD_SIG);

	// The operator's other routes.
	let tap = leaf.taproot();
	let mut s = spend(&coin, paid(&[&recv, &chg], FEE), vec![]);
	let h = SighashCache::new(&s.tx).taproot_key_spend_signature_hash(0, &Prevouts::All(&s.prevouts),
		SchnorrSighashType::Default, f.genesis).unwrap();
	s.witness(0, vec![sig(&f.s, &h.to_byte_array()).as_ref().to_vec()]);
	book.fail("leaf/neg a key-path signature by the operator", &s, 0, BAD_SIG);
	let sweep = f.schedule.sweep(true, false);
	let with_sweep = TapOutput::new(vec![(1, leaf.collab_script()), (2, leaf.exit_script()), (2, sweep.script())]);
	let mut s = spend(&coin, paid(&[&recv, &chg], FEE), vec![]);
	let sg = s.sign(&f.s, 0, &sweep.script(), f.genesis);
	s.witness(0, with_sweep.witness(&sweep.script(), Sweep::witness_items(&sg, 1)));
	book.fail("leaf/neg a sweep leaf from a tree that has one", &s, 0, "Witness program hash mismatch");
	let _ = tap;
}

// ---------------------------------------------------------------------------
// The tree node: gate, unroll and the timed authorisation
// ---------------------------------------------------------------------------

fn owners(n: usize) -> Vec<Keypair> {
	(0..n).map(|i| keypair(&format!("owner{}", i))).collect()
}

fn children_of(f: &F, owners: &[Keypair], value: u64) -> Vec<Child> {
	owners.iter().enumerate()
		.map(|(i, o)| Child::new(f.x, value, f.leaf(o, &format!("child{}", i)).program()))
		.collect()
}

/// The root of a member tree over raw member leaves, any length.
fn raw_root(members: &[Vec<u8>]) -> [u8; 32] {
	let mut level: Vec<[u8; 32]> = members.iter().map(|k| { let mut b = vec![0]; b.extend(k); sha256(&b) }).collect();
	while level.len() > 1 {
		level = level.chunks(2).map(|p| { let mut b = vec![1]; b.extend(p[0]); b.extend(p[1]); sha256(&b) }).collect();
	}
	level[0]
}

fn raw_path(members: &[Vec<u8>], mut idx: usize) -> Vec<Vec<u8>> {
	let mut level: Vec<[u8; 32]> = members.iter().map(|k| { let mut b = vec![0]; b.extend(k); sha256(&b) }).collect();
	let mut steps = vec![];
	while level.len() > 1 {
		steps.push((level[idx ^ 1], idx % 2 == 0));
		level = level.chunks(2).map(|p| { let mut b = vec![1]; b.extend(p[0]); b.extend(p[1]); sha256(&b) }).collect();
		idx /= 2;
	}
	let mut w = vec![];
	for (sib, left) in steps.iter().rev() {
		w.push(sib.to_vec());
		w.push(if *left { vec![1] } else { vec![] });
	}
	w
}

fn gate_cases(f: &F, book: &mut Book) {
	let os = owners(4);
	let keys: Vec<XOnlyPublicKey> = os.iter().map(xonly).collect();
	let children = children_of(f, &os, LEAF);
	let node = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(true, false), Some(f.chain)).unwrap();
	assert_eq!(node.members().depth(), 3, "four owners and the operator pad to eight");
	let value = 4 * LEAF + RESERVE;
	let coin = explicit(f.x, value, node.script_pubkey());
	let t = f.created;
	let kids = node.child_outputs();
	let unroll = |outs: Vec<TxOut>, lock: u32, seq: u32, w: Vec<Vec<u8>>| {
		let mut s = Spend::new(lock).fake_input("node", coin.clone(), seq).outputs(outs);
		s.witness(0, w);
		s
	};
	let with_fee = |mut v: Vec<TxOut>| { v.push(fee(f.x, RESERVE)); v };
	let auth = node.unroll_authorisation(t);
	let sa = sig(&os[1], &auth.digest);
	let w_ok = node.unroll_witness(&sa, t, &keys[1]).unwrap();
	let lt = t.to_consensus_u32();

	book.pass("node/unroll by an owner's authorisation, reserve fee", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w_ok.clone()));
	book.pass("node/unroll later than t", &unroll(with_fee(kids.clone()), lt + 86_400, 0xffff_fffe, w_ok.clone()));
	// The operator through a padding leaf: members 5 to 7 are the operator's key.
	let so = sig(&f.s, &auth.digest);
	let mut w_pad = node.unroll_witness(&so, t, &xonly(&f.s)).unwrap();
	let m = node.members();
	let pad_items = {
		let mut v = vec![so.as_ref().to_vec(), t.script_bytes()];
		for step in m.path(6).iter().rev() {
			v.push(step.sibling.to_vec());
			v.push(if step.is_left { vec![1] } else { vec![] });
		}
		v.push(xonly(&f.s).serialize().to_vec());
		v
	};
	let n_items = w_pad.len() - 2;
	w_pad.splice(0..n_items, pad_items);
	book.pass("node/unroll by the operator through a padding leaf", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w_pad));
	// A third party holding only the authorisation, paying with its own coin.
	let mut s = Spend::new(lt).fake_input("node", coin.clone(), 0xffff_fffe)
		.fake_input("fee coin", f.fee_coin(f.y, 5_000), 0xffff_fffe)
		.outputs(kids.clone())
		.outputs(vec![explicit(f.x, RESERVE, f.operator_spk()), fee(f.y, 5_000)]);
	s.witness(0, w_ok.clone());
	s.witness(1, op_true_witness());
	book.pass("node/unroll by a third party with its own fee coin", &s);

	// Time.
	book.fail("node/neg nLockTime below t", &unroll(with_fee(kids.clone()), lt - 1, 0xffff_fffe, w_ok.clone()), 0, LOCKTIME);
	book.fail("node/neg no lock time", &unroll(with_fee(kids.clone()), 0, 0xffff_fffe, w_ok.clone()), 0, LOCKTIME);
	book.fail("node/neg final sequence", &unroll(with_fee(kids.clone()), lt, 0xffff_ffff, w_ok.clone()), 0, LOCKTIME);
	book.fail("node/neg a height lock time", &unroll(with_fee(kids.clone()), 1_000, 0xffff_fffe, w_ok.clone()), 0, LOCKTIME);
	let with_t = |bytes: Vec<u8>| { let mut w = w_ok.clone(); w[1] = bytes; w };
	let earlier = MedianTime::from_consensus(lt - 1).unwrap();
	book.fail("node/neg t changed to earlier", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, with_t(earlier.script_bytes())), 0, BAD_SIG);
	let later = MedianTime::from_consensus(lt + 1).unwrap();
	book.fail("node/neg t changed to later", &unroll(with_fee(kids.clone()), lt + 1, 0xffff_fffe, with_t(later.script_bytes())), 0, BAD_SIG);
	let mut nonminimal = t.script_bytes();
	nonminimal.push(0);
	book.fail("node/neg t not minimally encoded", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, with_t(nonminimal)), 0, "");
	let mut w = w_ok.clone();
	w[0] = vec![];
	book.fail("node/neg empty signature", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w), 0, FALSE);
	let ss = sig(&f.stranger, &auth.digest);
	let mut w = w_ok.clone();
	w[0] = ss.as_ref().to_vec();
	book.fail("node/neg a stranger's signature with a member's key", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w), 0, BAD_SIG);
	// A stranger's key presented on the path of a padding leaf.
	let mut w = node.unroll_witness(&ss, t, &xonly(&f.s)).unwrap();
	let n = w.len();
	let mut items = vec![ss.as_ref().to_vec(), t.script_bytes()];
	for step in m.path(7).iter().rev() {
		items.push(step.sibling.to_vec());
		items.push(if step.is_left { vec![1] } else { vec![] });
	}
	items.push(xonly(&f.stranger).serialize().to_vec());
	w.splice(0..n - 2, items);
	book.fail("node/neg a stranger's key at a padding leaf", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w), 0, EQUALVERIFY);
	// An inner node's 64-byte preimage presented as the key.
	let mut w = w_ok.clone();
	let n = w.len();
	// w[n - 5] is the bottom level's sibling: a 64-byte inner preimage.
	w[n - 3] = [w[n - 5].clone(), w[n - 5].clone()].concat();
	book.fail("node/neg an inner node's preimage as the key", &unroll(with_fee(kids.clone()), lt, 0xffff_fffe, w), 0, EQUALVERIFY);

	// The children.
	let mut k = kids.clone();
	k[0] = explicit(f.x, LEAF - 1, children[0].script_pubkey());
	book.fail("node/neg a child one atom short", &unroll(with_fee(k), lt, 0xffff_fffe, w_ok.clone()), 0, EQUALVERIFY);
	let mut k = kids.clone();
	k[2] = explicit(f.y, LEAF, children[2].script_pubkey());
	book.fail("node/neg a child in another asset", &unroll(with_fee(k), lt, 0xffff_fffe, w_ok.clone()), 0, EQUALVERIFY);
	let mut k = kids.clone();
	k.swap(1, 2);
	book.fail("node/neg two children swapped", &unroll(with_fee(k), lt, 0xffff_fffe, w_ok.clone()), 0, EQUALVERIFY);
	let mut k = kids.clone();
	k.pop();
	book.fail("node/neg a child missing", &unroll(with_fee(k), lt, 0xffff_fffe, w_ok.clone()), 0, "");
	let mut k = kids.clone();
	let mut p33 = children[0].program.to_vec();
	p33.push(1);
	k[0] = explicit(f.x, LEAF, elements::script::Builder::new().push_int(0).push_slice(&p33).into_script());
	book.fail("node/neg a child replaced by a v0 33-byte program", &unroll(with_fee(k), lt, 0xffff_fffe, w_ok.clone()), 0, EQUALVERIFY);

	// A member tree that holds keys of the wrong length: the gate refuses them
	// before any signature check (without it, any non-empty signature passes).
	let bad_members: Vec<Vec<u8>> = vec![
		xonly(&f.s).serialize().to_vec(), keys[0].serialize().to_vec(), keys[1].serialize().to_vec(),
		{ let mut k = vec![2]; k.extend(xonly(&f.stranger).serialize()); k }, // 33 bytes
		[label32("k64a"), label32("k64b")].concat(), // 64 bytes
		label32("k31")[..31].to_vec(), // 31 bytes
		xonly(&f.s).serialize().to_vec(), xonly(&f.s).serialize().to_vec(),
	];
	let good_root = node.members().root();
	let bad_root = raw_root(&bad_members);
	let script = node.unroll_script();
	let mut bytes = script.to_bytes();
	let at = bytes.windows(32).position(|w| w == good_root).unwrap();
	bytes[at..at + 32].copy_from_slice(&bad_root);
	let bad_script = Script::from(bytes);
	let bad_tap = TapOutput::new(vec![(1, bad_script.clone()), (2, node.sweep_script()), (2, node.reclaim_script().unwrap())]);
	let bad_coin = explicit(f.x, value, bad_tap.script_pubkey());
	for (i, what) in [(3usize, "33"), (4, "64"), (5, "31")] {
		for (sig_bytes, sig_name) in [(vec![1u8; 64], "random 64-byte"), (vec![1u8], "one-byte")] {
			let mut below = vec![sig_bytes, t.script_bytes()];
			below.extend(raw_path(&bad_members, i));
			below.push(bad_members[i].clone());
			let mut s = Spend::new(lt).fake_input("bad node", bad_coin.clone(), 0xffff_fffe).outputs(with_fee(kids.clone()));
			s.witness(0, bad_tap.witness(&bad_script, below));
			book.fail(&format!("node/neg a {}-byte key in the member tree, {} signature", what, sig_name), &s, 0, EQUALVERIFY);
		}
	}
}

// ---------------------------------------------------------------------------
// The sweep, the clock and R
// ---------------------------------------------------------------------------

fn sweep_cases(f: &F, book: &mut Book) {
	let os = owners(4);
	let keys: Vec<XOnlyPublicKey> = os.iter().map(xonly).collect();
	let children = children_of(f, &os, LEAF);
	let value = 4 * LEAF + RESERVE;
	let batch = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(false, false), None).unwrap();
	let lowest = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(true, false), Some(f.chain)).unwrap();
	let r_spk = f.schedule.r().script_pubkey();
	let w = f.w.to_sequence();

	// inputs: the node at 0, the token at 1; outputs: the operator, the token back at R, the fee.
	let sweep = |node: &NodePolicy, node_seq: u32, t_in: TxOut, t_seq: u32, t_out: TxOut, k: u32, key: &Keypair, sign_r: bool| {
		let coin = explicit(f.x, value, node.script_pubkey());
		let mut s = Spend::new(0).fake_input("node", coin, node_seq).fake_input("token", t_in.clone(), t_seq)
			.outputs(vec![explicit(f.x, value - 3_000, f.operator_spk()), t_out, fee(f.x, 3_000)]);
		let sg = s.sign(key, 0, &node.sweep_script(), f.genesis);
		s.witness(0, node.sweep_witness(&sg, k));
		if sign_r {
			let rw = f.r_witness(&s, 1);
			s.witness(1, rw);
		} else {
			s.witness(1, op_true_witness());
		}
		s
	};
	let t_back = explicit(f.schedule.token, 1, r_spk.clone());
	book.pass("sweep/batch output, the token at R", &sweep(&batch, 0xffff_fffe, f.r_coin(), w, t_back.clone(), 1, &f.s, true));
	book.pass("sweep/lowest node after its notice", &sweep(&lowest, w, f.r_coin(), w, t_back.clone(), 1, &f.s, true));
	book.fail("sweep/neg lowest node one unit before its notice", &sweep(&lowest, w - 1, f.r_coin(), w, t_back.clone(), 1, &f.s, true), 0, LOCKTIME);
	book.fail("sweep/neg k names the swept node itself", &sweep(&batch, 0xffff_fffe, f.r_coin(), w, t_back.clone(), 0, &f.s, true), 0, EQUALVERIFY);
	book.fail("sweep/neg no token input", &sweep(&batch, 0xffff_fffe, f.fee_coin(f.x, 1), 0xffff_fffe, t_back.clone(), 1, &f.s, false), 0, EQUALVERIFY);
	book.fail("sweep/neg signed by a stranger", &sweep(&batch, 0xffff_fffe, f.r_coin(), w, t_back.clone(), 1, &f.stranger, true), 0, BAD_SIG);
	let mut s = sweep(&batch, 0xffff_fffe, f.r_coin(), w, t_back.clone(), 1, &f.s, true);
	s.tx.input[0].witness.script_witness[1] = vec![1, 0];
	// A non-minimal k changes the witness, not what the sweep does: only the
	// mempool's minimal-encoding rule refuses it.
	book.policy_only("sweep/k not minimally encoded", &s, 0, "");
	let mut s = sweep(&batch, 0xffff_fffe, f.r_coin(), w, t_back.clone(), 1, &f.s, true);
	s.tx.input[0].witness.script_witness[1] = vec![5];
	book.fail("sweep/neg k past the last input", &s, 0, "");
	// The token of another batch, at that batch's R.
	let other = ClockSchedule::new(asset("T2"), xonly(&f.s), f.w, f.schedule.expiries().to_vec()).unwrap();
	let other_coin = explicit(other.token, 1, other.r().script_pubkey());
	let mut s = sweep(&batch, 0xffff_fffe, other_coin, w, explicit(other.token, 1, other.r().script_pubkey()), 1, &f.s, false);
	let rw = other.r().witness(&other.r_script(), ClockSchedule::r_witness_items(&s.sign(&f.s, 1, &other.r_script(), f.genesis)));
	s.witness(1, rw);
	book.fail("sweep/neg the token of another batch", &s, 0, EQUALVERIFY);

	// Inside a roll or a release: the token is in the transaction but not at R.
	let clocks = f.schedule.clocks();
	let c0 = &clocks[0];
	let roll_with_sweep = {
		let coin = explicit(f.x, value, batch.script_pubkey());
		let t0 = explicit(f.schedule.token, 1, c0.output.script_pubkey());
		let mut s = Spend::new(0).fake_input("node", coin, 0xffff_fffe).fake_input("clock0", t0, 0xffff_fffe)
			.outputs(vec![explicit(f.x, value - 3_000, f.operator_spk()),
				explicit(f.schedule.token, 1, clocks[1].output.script_pubkey()), fee(f.x, 3_000)]);
		let sg = s.sign(&f.s, 0, &batch.sweep_script(), f.genesis);
		s.witness(0, batch.sweep_witness(&sg, 1));
		let roll = c0.roll.clone().unwrap();
		let rs = s.sign(&f.s, 1, &roll, f.genesis);
		s.witness(1, c0.output.witness(&roll, Clock::witness_items(&rs)));
		s
	};
	book.fail("sweep/neg a sweep inside the roll", &roll_with_sweep, 0, EQUALVERIFY);
	let release_with_sweep = {
		let e0 = c0.expiry.to_consensus_u32();
		let coin = explicit(f.x, value, batch.script_pubkey());
		let t0 = explicit(f.schedule.token, 1, c0.output.script_pubkey());
		let mut s = Spend::new(e0).fake_input("node", coin, 0xffff_fffe).fake_input("clock0", t0, 0xffff_fffe)
			.outputs(vec![explicit(f.x, value - 3_000, f.operator_spk()), t_back.clone(), fee(f.x, 3_000)]);
		let sg = s.sign(&f.s, 0, &batch.sweep_script(), f.genesis);
		s.witness(0, batch.sweep_witness(&sg, 1));
		let rs = s.sign(&f.s, 1, &c0.release, f.genesis);
		s.witness(1, c0.output.witness(&c0.release, Clock::witness_items(&rs)));
		s
	};
	book.fail("sweep/neg a sweep inside the release", &release_with_sweep, 0, EQUALVERIFY);

	// The clock: inputs the clock at 0 and a fee coin at 1.
	let clock_spend = |j: usize, roll: bool, to: Script, out_index: usize, lock: u32, seq: u32, key: Option<&Keypair>| {
		let c = &clocks[j];
		let t_in = explicit(f.schedule.token, 1, c.output.script_pubkey());
		let t_out = explicit(f.schedule.token, 1, to);
		let outs = if out_index == 0 {
			vec![t_out, fee(f.y, 5_001)]
		} else {
			vec![explicit(f.y, 1, f.operator_spk()), t_out, fee(f.y, 5_000)]
		};
		let mut s = Spend::new(lock).fake_input("clock", t_in, seq).fake_input("fee coin", f.fee_coin(f.y, 5_001), seq)
			.outputs(outs);
		let script = if roll { c.roll.clone().unwrap() } else { c.release.clone() };
		let below = match key {
			Some(k) => Clock::witness_items(&s.sign(k, 0, &script, f.genesis)),
			None => vec![vec![]],
		};
		s.witness(0, c.output.witness(&script, below));
		s.witness(1, op_true_witness());
		s
	};
	let c1_spk = clocks[1].output.script_pubkey();
	let c2_spk = clocks[2].output.script_pubkey();
	let e = |j: usize| clocks[j].expiry.to_consensus_u32();
	book.pass("clock/roll clock 0 into clock 1", &clock_spend(0, true, c1_spk.clone(), 0, 0, 0xffff_fffe, Some(&f.s)));
	book.pass("clock/roll clock 1 into clock 2", &clock_spend(1, true, c2_spk.clone(), 0, 0, 0xffff_fffe, Some(&f.s)));
	book.fail("clock/neg roll paying the token to R", &clock_spend(0, true, r_spk.clone(), 0, 0, 0xffff_fffe, Some(&f.s)), 0, FALSE);
	book.fail("clock/neg roll skipping to clock 2", &clock_spend(0, true, c2_spk.clone(), 0, 0, 0xffff_fffe, Some(&f.s)), 0, FALSE);
	book.fail("clock/neg roll without a signature", &clock_spend(0, true, c1_spk.clone(), 0, 0, 0xffff_fffe, None), 0, "OP_CHECKSIGVERIFY");
	book.fail("clock/neg roll signed by a stranger", &clock_spend(0, true, c1_spk.clone(), 0, 0, 0xffff_fffe, Some(&f.stranger)), 0, BAD_SIG);
	book.fail("clock/neg roll with the token at another output index", &clock_spend(0, true, c1_spk.clone(), 1, 0, 0xffff_fffe, Some(&f.s)), 0, FALSE);
	book.pass("clock/release clock 0 at its expiry", &clock_spend(0, false, r_spk.clone(), 0, e(0), 0xffff_fffe, Some(&f.s)));
	book.pass("clock/release the last clock at its expiry", &clock_spend(2, false, r_spk.clone(), 0, e(2), 0xffff_fffe, Some(&f.s)));
	book.fail("clock/neg release one second before the expiry", &clock_spend(0, false, r_spk.clone(), 0, e(0) - 1, 0xffff_fffe, Some(&f.s)), 0, LOCKTIME);
	book.fail("clock/neg release with a final sequence", &clock_spend(0, false, r_spk.clone(), 0, e(0), 0xffff_ffff, Some(&f.s)), 0, LOCKTIME);
	book.fail("clock/neg release paying the token elsewhere", &clock_spend(0, false, c1_spk.clone(), 0, e(0), 0xffff_fffe, Some(&f.s)), 0, FALSE);
	book.fail("clock/neg after a roll, release at the old expiry", &clock_spend(1, false, r_spk.clone(), 0, e(0), 0xffff_fffe, Some(&f.s)), 0, LOCKTIME);

	// R.
	let r_spend = |seq: u32| {
		let mut s = Spend::new(0).fake_input("token", f.r_coin(), seq).fake_input("fee coin", f.fee_coin(f.y, 5_000), 0xffff_fffe)
			.outputs(vec![t_back.clone(), fee(f.y, 5_000)]);
		let rw = f.r_witness(&s, 0);
		s.witness(0, rw);
		s.witness(1, op_true_witness());
		s
	};
	book.pass("r/the token leaves R after the notice", &r_spend(w));
	book.fail("r/neg one unit before the notice", &r_spend(w - 1), 0, LOCKTIME);
}

// ---------------------------------------------------------------------------
// Reclaim
// ---------------------------------------------------------------------------

fn reclaim_cases(f: &F, book: &mut Book) {
	// The connector assets of two rounds the owners refreshed in.
	let (m1, m2) = (asset("connector asset of round 1"), asset("connector asset of round 2"));
	let reclaim = |n_owners: usize, n_children: usize, label: &str| {
		let os: Vec<Keypair> = (0..n_owners).map(|i| keypair(&format!("{} owner{}", label, i))).collect();
		let keys: Vec<XOnlyPublicKey> = os.iter().map(xonly).collect();
		let children = children_of(f, &os[..n_children], LEAF);
		let node = NodePolicy::new(children, xonly(&f.s), keys, f.schedule.sweep(true, false), Some(f.chain)).unwrap();
		(os, node)
	};
	// The reclaim of `node`, built by the policy: the atoms `ms` at inputs
	// 1.., each paid back to OP_TRUE; the operator signs with `op_key`; then
	// `items` below that signature (each owner's release and index, owner
	// n-1 first). The atoms' own inputs spend OP_TRUE. The policy builds only
	// on explicit atoms; a blinded one is put in its place before signing.
	let spend = |node: &NodePolicy, op_key: &Keypair, ms: &[TxOut], items: Vec<Vec<u8>>| {
		let value = node.children().len() as u64 * LEAF + RESERVE;
		let connectors: Vec<(elements::OutPoint, TxOut)> = ms.iter().enumerate()
			.map(|(j, m)| {
				let at = elements::OutPoint::new(elements::Txid::from_raw_hash(elements::hashes::sha256d::Hash::hash(format!("atom {}", j).as_bytes())), 0);
				let built = if m.asset.explicit().is_some() { m.clone() } else { explicit(m1, 1, op_true().script_pubkey()) };
				(at, built)
			})
			.collect();
		let node_at = elements::OutPoint::new(elements::Txid::from_raw_hash(elements::hashes::sha256d::Hash::hash(b"lowest")), 0);
		let mut ks = node.reclaim_tx(node_at, value, &connectors, &[ExplicitOutput::new(f.x, value - FEE, f.operator_spk())],
			op_true().script_pubkey(), &FeeSource::Reserve).unwrap();
		for (j, m) in ms.iter().enumerate() {
			ks.prevouts[1 + j] = m.clone();
		}
		let os = sig(op_key, &ks.sighash(f.genesis).unwrap());
		let mut below = vec![os.as_ref().to_vec()];
		below.extend(items);
		let u = ks.finish(below);
		let mut s = Spend { tx: u.tx, prevouts: u.prevouts };
		for j in 0..ms.len() {
			s.witness(1 + j, op_true_witness());
		}
		s
	};
	let atom = |m: AssetId| explicit(m, 1, op_true().script_pubkey());
	// Each owner's release and index, owner n-1 first.
	let items = |sigs: &[Vec<u8>], ks: &[u32]| -> Vec<Vec<u8>> {
		sigs.iter().zip(ks).rev().flat_map(|(s, k)| [s.clone(), arca_covenant::script::scriptnum(*k as i64)]).collect()
	};
	let signed = |os: &[Keypair], node: &NodePolicy, ms: &[AssetId]| -> Vec<Vec<u8>> {
		os.iter().zip(ms).map(|(k, m)| sig(k, &node.release_message(*m).unwrap().digest).as_ref().to_vec()).collect()
	};

	let (os, node) = reclaim(4, 4, "four");
	let good = signed(&os, &node, &[m1; 4]);
	let k1 = [1u32; 4];
	// The witness built by the policy matches the one assembled here, and
	// the release a wallet builds is the one the node's RECLAIM checks.
	{
		let s = spend(&node, &f.s, &[atom(m1)], items(&good, &k1));
		let op = Signature::from_slice(&s.tx.input[0].witness.script_witness[0]).unwrap();
		let releases: Vec<(Signature, u32)> = good.iter().zip(k1).map(|(g, k)| (Signature::from_slice(g).unwrap(), k)).collect();
		assert_eq!(node.reclaim_witness(&op, &releases).unwrap(), s.tx.input[0].witness.script_witness);
		assert_eq!(arca_covenant::node::connector_index(&s.prevouts, m1), Some(1));
		let r = Release { chain: f.chain, node_hash: node.children_hash(), owner: xonly(&os[2]), connector: m1 };
		assert_eq!(r.message(), node.release_message(m1).unwrap());
		r.verify(&Signature::from_slice(&good[2]).unwrap()).unwrap();
		assert!(r.verify(&Signature::from_slice(&good[1]).unwrap()).is_err());
		assert_eq!(node.release_message(m1).unwrap().preimage.len(), 108);
	}
	book.pass("reclaim/four owners and the operator, M of their round at input 1", &spend(&node, &f.s, &[atom(m1)], items(&good, &k1)));
	book.fail("reclaim/neg without M", &spend(&node, &f.s, &[], items(&good, &k1)), 0, "Introspection index out of bounds");
	book.fail("reclaim/neg another round's M", &spend(&node, &f.s, &[atom(m2)], items(&good, &k1)), 0, BAD_SIG);
	book.fail("reclaim/neg another asset at k", &spend(&node, &f.s, &[atom(f.y)], items(&good, &k1)), 0, BAD_SIG);
	book.fail("reclaim/neg k names the node itself", &spend(&node, &f.s, &[atom(m1)], items(&good, &[0; 4])), 0, BAD_SIG);
	let blinded = {
		let secp = elements::secp256k1_zkp::Secp256k1::new();
		let bf = elements::confidential::AssetBlindingFactor::from_slice(&label32("blinding")).unwrap();
		TxOut { asset: elements::confidential::Asset::new_confidential(&secp, m1, bf), ..atom(m1) }
	};
	book.fail("reclaim/neg M blinded at k", &spend(&node, &f.s, &[blinded], items(&good, &k1)), 0, EQUALVERIFY);
	let mut v = good.clone();
	v[1] = vec![];
	book.fail("reclaim/neg three of four, one empty", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, "OP_CHECKSIGVERIFY");
	let mut v = good.clone();
	v[3] = vec![];
	book.fail("reclaim/neg three of four, the last empty", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, "OP_CHECKSIGVERIFY");
	let mut v = good.clone();
	v[2] = vec![7; 64];
	book.fail("reclaim/neg three of four, one junk", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, BAD_SIG);
	// Releases over the old message, SHA256("Arca/release" ‖ genesis ‖ H),
	// in the new witness shape and in the old one.
	let old_digest = sha256(&node.release_prefix().unwrap());
	let old: Vec<Vec<u8>> = os.iter().map(|k| sig(k, &old_digest).as_ref().to_vec()).collect();
	book.fail("reclaim/neg releases over the old message", &spend(&node, &f.s, &[atom(m1)], items(&old, &k1)), 0, BAD_SIG);
	book.fail("reclaim/neg releases over the old message, the old witness", &spend(&node, &f.s, &[atom(m1)], old.iter().rev().cloned().collect()),
		0, "unknown error");
	let mut v = good.clone();
	v[3] = signed(&os[3..], &node, &[m2])[0].clone();
	book.fail("reclaim/neg one release names round 2, its k round 1", &spend(&node, &f.s, &[atom(m1), atom(m2)], items(&v, &k1)), 0, BAD_SIG);
	let (_, other) = reclaim(4, 4, "other");
	let all_other = signed(&os, &other, &[m1; 4]);
	book.fail("reclaim/neg all four signed another node's release", &spend(&node, &f.s, &[atom(m1)], items(&all_other, &k1)), 0, BAD_SIG);
	let mut v = good.clone();
	v[0] = all_other[0].clone();
	book.fail("reclaim/neg one signature for another node", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, BAD_SIG);
	let other_chain = Chain::new(BlockHash::from_byte_array(label32("another chain")));
	let rel_chain = other_chain.release_message(&node.children_hash(), m1);
	let v: Vec<Vec<u8>> = os.iter().map(|k| sig(k, &rel_chain.digest).as_ref().to_vec()).collect();
	book.fail("reclaim/neg signed for another genesis hash", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, BAD_SIG);
	let mut s = spend(&node, &f.s, &[atom(m1)], items(&good, &k1));
	s.tx.input[0].witness.script_witness[0] = vec![];
	book.fail("reclaim/neg no operator signature", &s, 0, FALSE);
	book.fail("reclaim/neg the operator's signature by the wrong key", &spend(&node, &f.stranger, &[atom(m1)], items(&good, &k1)), 0, BAD_SIG);
	let mut v = good.clone();
	v.swap(1, 2);
	book.fail("reclaim/neg owner signatures out of order", &spend(&node, &f.s, &[atom(m1)], items(&v, &k1)), 0, BAD_SIG);

	// Owners 0 and 1 refreshed in round 1, owners 2 and 3 in round 2.
	let two = signed(&os, &node, &[m1, m1, m2, m2]);
	let k12 = [1, 1, 2, 2];
	book.pass("reclaim/owners of two rounds, one atom of each", &spend(&node, &f.s, &[atom(m1), atom(m2)], items(&two, &k12)));
	book.fail("reclaim/neg two rounds, every k names round 1", &spend(&node, &f.s, &[atom(m1), atom(m2)], items(&two, &k1)), 0, BAD_SIG);
	book.fail("reclaim/neg two rounds, round 2's M missing", &spend(&node, &f.s, &[atom(m1)], items(&two, &k12)), 0, "Introspection index out of bounds");

	let (os16, node16) = reclaim(16, 4, "sixteen");
	let good16 = signed(&os16, &node16, &[m1; 16]);
	book.pass("reclaim/sixteen owners and the operator", &spend(&node16, &f.s, &[atom(m1)], items(&good16, &[1; 16])));
	let mut v = good16.clone();
	v[9] = vec![];
	book.fail("reclaim/neg fifteen of sixteen", &spend(&node16, &f.s, &[atom(m1)], items(&v, &[1; 16])), 0, "OP_CHECKSIGVERIFY");

	let (os1, node1) = reclaim(1, 1, "one");
	let good1 = signed(&os1, &node1, &[m1]);
	book.pass("reclaim/one owner and the operator", &spend(&node1, &f.s, &[atom(m1)], items(&good1, &[1])));
	book.fail("reclaim/neg one owner, without M", &spend(&node1, &f.s, &[], items(&good1, &[1])), 0, "Introspection index out of bounds");
	book.fail("reclaim/neg one owner, another round's M", &spend(&node1, &f.s, &[atom(m2)], items(&good1, &[1])), 0, BAD_SIG);
	book.fail("reclaim/neg one owner, signature missing", &spend(&node1, &f.s, &[atom(m1)], items(&[vec![]], &[1])), 0, "OP_CHECKSIGVERIFY");
	let stranger = vec![sig(&f.stranger, &node1.release_message(m1).unwrap().digest).as_ref().to_vec()];
	book.fail("reclaim/neg one owner, signed by a stranger", &spend(&node1, &f.s, &[atom(m1)], items(&stranger, &[1])), 0, BAD_SIG);
}

// ---------------------------------------------------------------------------
// Entry, forfeit, checkpoint and the swap
// ---------------------------------------------------------------------------

fn entry_forfeit_cases(f: &F, book: &mut Book) {
	let preimage = label32("preimage");
	let leaf = f.leaf(&f.a, "new leaf");
	let entry = EntryPolicy {
		unlock_hash: sha256(&preimage), asset: f.x, value: LEAF, leaf_program: leaf.program(),
		sweep: f.schedule.sweep(true, false),
	};
	let coin = explicit(f.x, LEAF + 1_000, entry.script_pubkey());
	let unlock = |outs: Vec<TxOut>, item: Vec<u8>| {
		let mut s = Spend::new(0).fake_input("entry", coin.clone(), 0xffff_ffff).outputs(outs);
		let script = entry.unlock_script();
		s.witness(0, entry.taproot().witness(&script, vec![item]));
		s
	};
	let to_leaf = vec![explicit(f.x, LEAF, leaf.script_pubkey()), fee(f.x, 1_000)];
	assert_eq!(entry.unlock_witness(&preimage), unlock(to_leaf.clone(), preimage.to_vec()).tx.input[0].witness.script_witness);
	book.pass("entry/unlock into the owner's leaf", &unlock(to_leaf.clone(), preimage.to_vec()));
	book.fail("entry/neg a wrong preimage", &unlock(to_leaf.clone(), label32("wrong").to_vec()), 0, EQUALVERIFY);
	book.fail("entry/neg a 31-byte preimage", &unlock(to_leaf.clone(), preimage[..31].to_vec()), 0, EQUALVERIFY);
	book.fail("entry/neg a 33-byte preimage", &unlock(to_leaf.clone(), [&preimage[..], &[0]].concat()), 0, EQUALVERIFY);
	book.fail("entry/neg into another script", &unlock(vec![explicit(f.x, LEAF, f.operator_spk()), fee(f.x, 1_000)], preimage.to_vec()), 0, FALSE);
	book.fail("entry/neg one atom short", &unlock(vec![explicit(f.x, LEAF - 1, leaf.script_pubkey()), fee(f.x, 1_001)], preimage.to_vec()), 0, EQUALVERIFY);
	book.fail("entry/neg in another asset", &unlock(vec![explicit(f.y, LEAF, leaf.script_pubkey()), fee(f.x, LEAF + 1_000)], preimage.to_vec()), 0, EQUALVERIFY);
	book.fail("entry/neg the leaf at output 1", &unlock(vec![fee(f.x, 1_000), explicit(f.x, LEAF, leaf.script_pubkey())], preimage.to_vec()), 0, EQUALVERIFY);

	// The entry's sweep behind the token and the notice.
	let w = f.w.to_sequence();
	let sweep = |seq: u32, with_token: bool| {
		let t_in = if with_token { f.r_coin() } else { f.fee_coin(f.x, 1) };
		let mut s = Spend::new(0).fake_input("entry", coin.clone(), seq).fake_input("token", t_in, w)
			.outputs(vec![explicit(f.x, LEAF - 2_000, f.operator_spk()), f.r_coin(), fee(f.x, 3_000)]);
		let sg = s.sign(&f.s, 0, &entry.sweep_script(), f.genesis);
		s.witness(0, entry.sweep_witness(&sg, 1));
		if with_token { let rw = f.r_witness(&s, 1); s.witness(1, rw); } else { s.witness(1, op_true_witness()); }
		s
	};
	book.pass("entry/sweep after the notice, behind the token", &sweep(w, true));
	book.fail("entry/neg sweep one unit before the notice", &sweep(w - 1, true), 0, LOCKTIME);
	book.fail("entry/neg sweep without the token", &sweep(w, false), 0, EQUALVERIFY);

	// The forfeit, made through the old leaf's collaborative path.
	let old = f.leaf(&f.a, "old leaf");
	let m = arca_covenant::connector_asset(elements::Txid::from_byte_array(label32("the round")), 2);
	let forfeit = ForfeitPolicy {
		unlock_hash: sha256(&preimage), owner: xonly(&f.a), operator: xonly(&f.s), refund_delay: f.delay,
		leaf_id: LeafId(label32("the old leaf's id")), connector: m,
	};
	let old_coin = explicit(f.x, LEAF, old.script_pubkey());
	let f_out = ExplicitOutput::new(f.x, LEAF - FEE, forfeit.script_pubkey());
	let msg = old.collab_message(f.x, LEAF, std::slice::from_ref(&f_out)).unwrap();
	let forfeit_tx = |sa: Vec<u8>| {
		let mut s = Spend::new(0).fake_input("old leaf", old_coin.clone(), 0xffff_ffff).outputs(vec![f_out.txout(), fee(f.x, FEE)]);
		let mut w = old.collab_witness(&sig(&f.s, &msg.digest), &sig(&f.a, &msg.digest), 1);
		w[1] = sa;
		s.witness(0, w);
		s
	};
	book.pass("forfeit/the old leaf into the forfeit output", &forfeit_tx(sig(&f.a, &msg.digest).as_ref().to_vec()));
	book.fail("forfeit/neg without the owner's signature", &forfeit_tx(vec![]), 0, "OP_CHECKSIGVERIFY");
	let f_coin = f_out.txout();
	// The claim takes the connector asset M at input k (here 1).
	let claim_with = |item: Vec<u8>, key: Option<&Keypair>, at_1: AssetId, k: i64| {
		let mut s = Spend::new(0).fake_input("forfeit", f_coin.clone(), 0xffff_ffff)
			.fake_input("connector atom", explicit(at_1, 1, op_true().script_pubkey()), 0xffff_ffff)
			.outputs(vec![explicit(f.x, LEAF - 2 * FEE, f.operator_spk()), explicit(at_1, 1, f.operator_spk()), fee(f.x, FEE)]);
		let sc = forfeit.claim_script();
		let sg = key.map(|k| s.sign(k, 0, &sc, f.genesis).as_ref().to_vec()).unwrap_or_default();
		s.witness(0, forfeit.taproot().witness(&sc, vec![sg, item, arca_covenant::script::scriptnum(k)]));
		s.witness(1, op_true_witness());
		s
	};
	let claim = |item: Vec<u8>, key: Option<&Keypair>| claim_with(item, key, m, 1);
	book.pass("forfeit/claim with the preimage, M at input 1 and the operator's signature", &claim(preimage.to_vec(), Some(&f.s)));
	book.fail("forfeit/neg claim with a wrong preimage", &claim(label32("wrong").to_vec(), Some(&f.s)), 0, EQUALVERIFY);
	book.fail("forfeit/neg claim with the preimage but not the operator", &claim(preimage.to_vec(), Some(&f.stranger)), 0, BAD_SIG);
	book.fail("forfeit/neg claim with the preimage and no signature", &claim(preimage.to_vec(), None), 0, FALSE);
	book.fail("forfeit/neg claim with another asset where M belongs", &claim_with(preimage.to_vec(), Some(&f.s), f.y, 1), 0, EQUALVERIFY);
	book.fail("forfeit/neg claim naming the forfeit itself as M's input", &claim_with(preimage.to_vec(), Some(&f.s), m, 0), 0, EQUALVERIFY);
	book.fail("forfeit/neg claim naming an input that does not exist", &claim_with(preimage.to_vec(), Some(&f.s), m, 2), 0,
		"Introspection index out of bounds");
	let refund = |seq: u32| {
		let mut s = Spend::new(0).fake_input("forfeit", f_coin.clone(), seq)
			.outputs(vec![explicit(f.x, LEAF - 2 * FEE, f.operator_spk()), fee(f.x, FEE)]);
		let sg = s.sign(&f.a, 0, &forfeit.refund_script(), f.genesis);
		s.witness(0, forfeit.refund_witness(&sg));
		s
	};
	book.pass("forfeit/refund after the delay", &refund(f.delay.to_sequence()));
	book.fail("forfeit/neg refund one unit before the delay", &refund(f.delay.to_sequence() - 1), 0, LOCKTIME);
}

fn checkpoint_swap_cases(f: &F, book: &mut Book) {
	// The checkpoint and the reassignment, both signed before anything exists.
	let leaf = f.leaf(&f.a, "cp leaf");
	let cp = CheckpointPolicy { owner: xonly(&f.a), operator: xonly(&f.s), salt: label32("cp"), chain: f.chain, sweep: f.schedule.sweep(true, false) };
	let cp_out = ExplicitOutput::new(f.x, LEAF - FEE, cp.script_pubkey());
	let m1 = leaf.collab_message(f.x, LEAF, std::slice::from_ref(&cp_out)).unwrap();
	let recv = ExplicitOutput::new(f.x, 7_000_000, f.leaf(&f.b, "cp recv").script_pubkey());
	let chg = ExplicitOutput::new(f.x, LEAF - 2 * FEE - 7_000_000, f.leaf(&f.a, "cp chg").script_pubkey());
	let re = vec![recv.clone(), chg.clone()];
	let m2 = cp.collab_message(f.x, LEAF - FEE, &re).unwrap();
	let (cp_s, cp_a) = (sig(&f.s, &m1.digest), sig(&f.a, &m1.digest));
	let (re_s, re_a) = (sig(&f.s, &m2.digest), sig(&f.a, &m2.digest));

	let leaf_coin = explicit(f.x, LEAF, leaf.script_pubkey());
	let mut s = Spend::new(0).fake_input("leaf", leaf_coin.clone(), 0xffff_ffff).outputs(vec![cp_out.txout(), fee(f.x, FEE)]);
	s.witness(0, leaf.collab_witness(&cp_s, &cp_a, 1));
	book.pass("checkpoint/the leaf into its checkpoint", &s);
	let cp_coin = cp_out.txout();
	let mut s = Spend::new(0).fake_input("checkpoint", cp_coin.clone(), 0xffff_ffff).outputs(vec![recv.txout(), chg.txout(), fee(f.x, FEE)]);
	s.witness(0, cp.collab_witness(&re_s, &re_a, 2));
	book.pass("checkpoint/the reassignment to receiver and change", &s);
	let mut s = Spend::new(0).fake_input("leaf", leaf_coin, 0xffff_ffff).outputs(vec![recv.txout(), chg.txout(), fee(f.x, 2 * FEE)]);
	s.witness(0, leaf.collab_witness(&re_s, &re_a, 2));
	book.fail("checkpoint/neg the reassignment's signatures on the leaf", &s, 0, BAD_SIG);
	let mut s = Spend::new(0).fake_input("checkpoint", cp_coin.clone(), 0xffff_ffff).outputs(vec![cp_out.txout(), fee(f.x, 0)]);
	s.witness(0, cp.collab_witness(&cp_s, &cp_a, 1));
	book.fail("checkpoint/neg the checkpoint's signatures on the checkpoint", &s, 0, BAD_SIG);
	let w = f.w.to_sequence();
	let mut s = Spend::new(0).fake_input("checkpoint", cp_coin, w).fake_input("token", f.r_coin(), w)
		.outputs(vec![explicit(f.x, LEAF - FEE - 3_000, f.operator_spk()), f.r_coin(), fee(f.x, 3_000)]);
	let sg = s.sign(&f.s, 0, &cp.sweep_script(), f.genesis);
	s.witness(0, cp.sweep_witness(&sg, 1));
	let rw = f.r_witness(&s, 1);
	s.witness(1, rw);
	book.pass("checkpoint/sweep after the notice, behind the token", &s);

	// The swap: Alice's leaf in X and Bob's leaf in Y, one transaction, both
	// owners signing the same two outputs.
	let alice = f.leaf(&f.a, "swap alice");
	let bob = f.leaf(&f.b, "swap bob");
	let (vx, vy) = (LEAF - FEE, LEAF);
	let outs = vec![
		ExplicitOutput::new(f.x, vx, f.leaf(&f.b, "bob gets X").script_pubkey()),
		ExplicitOutput::new(f.y, vy, f.leaf(&f.a, "alice gets Y").script_pubkey()),
	];
	let ma = alice.collab_message(f.x, LEAF, &outs).unwrap();
	let mb = bob.collab_message(f.y, LEAF, &outs).unwrap();
	let wa = alice.collab_witness(&sig(&f.s, &ma.digest), &sig(&f.a, &ma.digest), 2);
	let wb = bob.collab_witness(&sig(&f.s, &mb.digest), &sig(&f.b, &mb.digest), 2);
	let a_coin = explicit(f.x, LEAF, alice.script_pubkey());
	let b_coin = explicit(f.y, LEAF, bob.script_pubkey());
	let swap = |outputs: Vec<TxOut>, wa: Vec<Vec<u8>>, wb: Vec<Vec<u8>>| {
		let mut s = Spend::new(0).fake_input("alice", a_coin.clone(), 0xffff_ffff).fake_input("bob", b_coin.clone(), 0xffff_ffff)
			.outputs(outputs);
		s.witness(0, wa);
		s.witness(1, wb);
		s
	};
	let committed = vec![outs[0].txout(), outs[1].txout(), fee(f.x, FEE)];
	book.pass("swap/two leaves in two assets, one transaction", &swap(committed.clone(), wa.clone(), wb.clone()));
	book.fail("swap/neg outputs swapped", &swap(vec![outs[1].txout(), outs[0].txout(), fee(f.x, FEE)], wa.clone(), wb.clone()), 0, BAD_SIG);
	book.fail("swap/neg Bob's input with Alice's leaf signatures", &swap(committed.clone(), wa.clone(), {
		let mut w = wa.clone();
		let n = w.len();
		w[n - 2] = wb[n - 2].clone();
		w[n - 1] = wb[n - 1].clone();
		w
	}), 1, BAD_SIG);
	let mut s = Spend::new(0).fake_input("alice", a_coin.clone(), 0xffff_ffff).outputs(vec![outs[0].txout(), fee(f.x, FEE)]);
	s.witness(0, wa.clone());
	book.fail("swap/neg Alice's input alone, her output absent", &s, 0, BAD_SIG);
	// A third party's coin of Y in place of Bob's leaf: Alice still gets exactly what she signed for.
	let mut s = Spend::new(0).fake_input("alice", a_coin, 0xffff_ffff).fake_input("third party", f.fee_coin(f.y, LEAF), 0xffff_ffff)
		.outputs(committed);
	s.witness(0, wa);
	s.witness(1, op_true_witness());
	book.pass("swap/Alice's leaf with a third party's Y: both committed outputs created", &s);
}

// ---------------------------------------------------------------------------
// The burn-only sweep
// ---------------------------------------------------------------------------

fn burn_cases(f: &F, book: &mut Book) {
	let os = owners(4);
	let keys: Vec<XOnlyPublicKey> = os.iter().map(xonly).collect();
	let children = children_of(f, &os, LEAF);
	let value = 4 * LEAF + RESERVE;
	let lowest = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(true, true), Some(f.chain)).unwrap();
	let batch = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(false, true), None).unwrap();
	let burn_spk = Script::from(vec![0x6a]);
	let w = f.w.to_sequence();
	// inputs: nodes, then the token, then a fee coin; outputs as given.
	let burn = |nodes: &[&NodePolicy], seq: u32, outs: Vec<TxOut>, key: &Keypair, k: Option<u32>| {
		let mut s = Spend::new(0);
		for (i, n) in nodes.iter().enumerate() {
			s = s.fake_input(&format!("node{}", i), explicit(f.x, value, n.script_pubkey()), seq);
		}
		let k_idx = nodes.len();
		s = s.fake_input("token", f.r_coin(), w).fake_input("fee coin", f.fee_coin(f.y, 10_000), 0xffff_fffe);
		s = s.outputs(outs);
		for (i, n) in nodes.iter().enumerate() {
			let sg = s.sign(key, i, &n.sweep_script(), f.genesis);
			s.witness(i, n.sweep_witness(&sg, k.unwrap_or(k_idx as u32)));
		}
		let rw = f.r_witness(&s, k_idx);
		s.witness(k_idx, rw);
		s.witness(k_idx + 1, op_true_witness());
		s
	};
	let tail = |v: Vec<TxOut>| { let mut v = v; v.push(fee(f.y, 10_000)); v };
	let burn_out = explicit(f.x, value, burn_spk.clone());
	book.pass("burn/lowest node after the notice, into OP_RETURN", &burn(&[&lowest], w, tail(vec![burn_out.clone(), f.r_coin()]), &f.s, None));
	book.pass("burn/batch output, into OP_RETURN", &burn(&[&batch], 0xffff_fffe, tail(vec![burn_out.clone(), f.r_coin()]), &f.s, None));
	book.fail("burn/neg one unit before the notice", &burn(&[&lowest], w - 1, tail(vec![burn_out.clone(), f.r_coin()]), &f.s, None), 0, LOCKTIME);
	book.fail("burn/neg to the operator", &burn(&[&lowest], w, tail(vec![explicit(f.x, value, f.operator_spk()), f.r_coin()]), &f.s, None), 0, EQUALVERIFY);
	book.fail("burn/neg one atom short", &burn(&[&lowest], w, tail(vec![explicit(f.x, value - 1, burn_spk.clone()), f.r_coin(), explicit(f.x, 1, f.operator_spk())]), &f.s, None), 0, EQUALVERIFY);
	book.fail("burn/neg the same amount of another asset", &burn(&[&lowest], w, tail(vec![explicit(f.y, value, burn_spk.clone()), f.r_coin(), explicit(f.x, value, f.operator_spk())]), &f.s, None), 0, EQUALVERIFY);
	book.fail("burn/neg OP_RETURN at another index", &burn(&[&lowest], w, tail(vec![f.r_coin(), burn_out.clone()]), &f.s, None), 0, EQUALVERIFY);
	book.fail("burn/neg OP_TRUE in place of OP_RETURN", &burn(&[&lowest], w, tail(vec![explicit(f.x, value, Script::from(vec![0x51])), f.r_coin()]), &f.s, None), 0, EQUALVERIFY);
	let lowest_b = NodePolicy::new(children_of(f, &owners(4)[..], LEAF), xonly(&f.s), keys, f.schedule.sweep(true, true), Some(Chain::new(BlockHash::from_byte_array(label32("b"))))).unwrap();
	book.fail("burn/neg two nodes sharing one burn output", &burn(&[&lowest, &lowest_b], w, tail(vec![burn_out.clone(), f.r_coin()]), &f.s, None), 1, EQUALVERIFY);
	book.fail("burn/neg signed by a stranger", &burn(&[&lowest], w, tail(vec![burn_out.clone(), f.r_coin()]), &f.stranger, None), 0, BAD_SIG);
	book.fail("burn/neg k names the fee coin", &burn(&[&lowest], w, tail(vec![burn_out, f.r_coin()]), &f.s, Some(2)), 0, EQUALVERIFY);
}

// ---------------------------------------------------------------------------
// The operator's builders: release, roll and the sweep
// ---------------------------------------------------------------------------

fn fake_outpoint(label: &str) -> OutPoint {
	OutPoint::new(Txid::from_raw_hash(elements::hashes::sha256d::Hash::hash(label.as_bytes())), 0)
}

fn fee_coin_source(f: &F, label: &str, value: u64, fee: u64) -> FeeSource {
	FeeSource::Coin { outpoint: fake_outpoint(label), coin: f.fee_coin(f.y, value), fee, change: op_true().script_pubkey() }
}

/// A built transaction as a `Spend`, with an attached fee coin's witness.
fn spend_of(u: UnrollTx, fee_coin: Option<usize>) -> Spend {
	let mut s = Spend { tx: u.tx, prevouts: u.prevouts };
	if let Some(i) = fee_coin {
		s.witness(i, op_true_witness());
	}
	s
}

fn builder_cases(f: &F, book: &mut Book) {
	let clocks = f.schedule.clocks();
	let token0 = fake_outpoint("token at clock 0");

	// Release and roll, a fee coin of Y paying.
	let release = f.schedule.release_tx(0, token0, &fee_coin_source(f, "fee coin", 9_000, 900)).unwrap();
	assert_eq!(release.tx.lock_time.to_consensus_u32(), clocks[0].expiry.to_consensus_u32(), "the release's lock time is E_0");
	assert_eq!(release.tx.input[0].sequence.0, 0xffff_fffe, "the token's input is not final");
	assert_eq!(release.tx.output[0], explicit(f.schedule.token, 1, f.schedule.r().script_pubkey()), "the token goes to R at output 0");
	let sg = sign_digest(&f.s, &release.sighash(f.genesis).unwrap(), &[0; 32]);
	book.pass("builder/release of clock 0, a fee coin paying", &spend_of(release.clone().finish(Clock::witness_items(&sg)), Some(1)));
	let bad = sign_digest(&f.stranger, &release.sighash(f.genesis).unwrap(), &[0; 32]);
	book.fail("builder/neg release signed by a stranger", &spend_of(release.clone().finish(Clock::witness_items(&bad)), Some(1)), 0, BAD_SIG);
	let mut early = release.clone();
	early.tx.lock_time = elements::LockTime::from_consensus(clocks[0].expiry.to_consensus_u32() - 1);
	let sg = sign_digest(&f.s, &early.sighash(f.genesis).unwrap(), &[0; 32]);
	book.fail("builder/neg release with a lock time one second before E_0", &spend_of(early.finish(Clock::witness_items(&sg)), Some(1)), 0, LOCKTIME);
	let roll = f.schedule.roll_tx(0, token0, &fee_coin_source(f, "fee coin", 9_000, 900)).unwrap();
	assert_eq!(roll.tx.output[0], explicit(f.schedule.token, 1, clocks[1].output.script_pubkey()));
	let sg = sign_digest(&f.s, &roll.sighash(f.genesis).unwrap(), &[0; 32]);
	book.pass("builder/roll of clock 0 into clock 1", &spend_of(roll.clone().finish(Clock::witness_items(&sg)), Some(1)));
	let mut stray = roll.clone();
	stray.tx.output[0] = explicit(f.schedule.token, 1, clocks[2].output.script_pubkey());
	let sg = sign_digest(&f.s, &stray.sighash(f.genesis).unwrap(), &[0; 32]);
	book.fail("builder/neg roll of clock 0 straight to clock 2", &spend_of(stray.finish(Clock::witness_items(&sg)), Some(1)), 0, FALSE);
	let last = f.schedule.release_tx(2, fake_outpoint("token at clock 2"), &fee_coin_source(f, "fee coin", 9_000, 900)).unwrap();
	let sg = sign_digest(&f.s, &last.sighash(f.genesis).unwrap(), &[0; 32]);
	book.pass("builder/release of the last clock", &spend_of(last.finish(Clock::witness_items(&sg)), Some(1)));
	assert_eq!(f.schedule.roll_tx(2, token0, &fee_coin_source(f, "c", 9_000, 900)).unwrap_err(), SpendError::LastClock(2));
	assert_eq!(f.schedule.release_tx(3, token0, &fee_coin_source(f, "c", 9_000, 900)).unwrap_err(), SpendError::ClockStep { step: 3, steps: 3 });
	assert_eq!(f.schedule.release_tx(0, token0, &FeeSource::Reserve).unwrap_err(), SpendError::NeedsFeeCoin("the token"));
	assert_eq!(f.schedule.place(&clocks[1].output.script_pubkey()), Some(TokenPlace::Clock(1)));
	assert_eq!(f.schedule.place(&f.schedule.r().script_pubkey()), Some(TokenPlace::Released));
	assert_eq!(f.schedule.place(&f.operator_spk()), None);

	// One wave of a sweep: the batch output, a lowest node, an entry and a
	// checkpoint, behind the token at R.
	let os = owners(4);
	let keys: Vec<XOnlyPublicKey> = os.iter().map(xonly).collect();
	let children = children_of(f, &os, LEAF);
	let value = 4 * LEAF + RESERVE;
	let batch = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(false, false), None).unwrap();
	let lowest = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(true, false), Some(f.chain)).unwrap();
	let entry = EntryPolicy { unlock_hash: label32("h"), asset: f.x, value: LEAF, leaf_program: f.leaf(&f.a, "salt").program(),
		sweep: f.schedule.sweep(true, false) };
	let cp = CheckpointPolicy { owner: xonly(&f.a), operator: xonly(&f.s), salt: label32("cp salt"), chain: f.chain,
		sweep: f.schedule.sweep(true, false) };
	let swept = vec![
		batch.sweepable(fake_outpoint("batch"), value),
		lowest.sweepable(fake_outpoint("lowest"), value),
		entry.sweepable(fake_outpoint("entry"), LEAF + RESERVE),
		cp.sweepable(fake_outpoint("checkpoint"), f.x, LEAF),
	];
	let total = 2 * value + LEAF + RESERVE + LEAF;
	let at_r = fake_outpoint("token at R");
	let to = vec![ExplicitOutput::new(f.x, total - FEE, f.operator_spk())];
	let sw = sweep_tx(&f.schedule, at_r, &swept, &to, &FeeSource::Reserve).unwrap();
	assert_eq!(sw.token_input(), 4);
	assert_eq!(sw.tx.input[0].sequence.0, 0xffff_fffe, "the batch output carries no notice");
	assert!(sw.tx.input[1..5].iter().all(|i| i.sequence.0 == f.w.to_sequence()), "every other input waits W");
	assert_eq!(sw.tx.output[1], f.r_coin(), "the token goes back to R");
	let sigs: Vec<_> = (0..5).map(|i| sign_digest(&f.s, &sw.sighash(i, f.genesis).unwrap(), &[0; 32])).collect();
	book.pass("builder/sweep of the batch output, a lowest node, an entry and a checkpoint", &spend_of(sw.clone().finish(&sigs).unwrap(), None));
	let mut one_bad = sigs.clone();
	one_bad[2] = sign_digest(&f.stranger, &sw.sighash(2, f.genesis).unwrap(), &[0; 32]);
	book.fail("builder/neg one swept input signed by a stranger", &spend_of(sw.clone().finish(&one_bad).unwrap(), None), 2, BAD_SIG);
	let mut r_bad = sigs.clone();
	r_bad[4] = sign_digest(&f.stranger, &sw.sighash(4, f.genesis).unwrap(), &[0; 32]);
	book.fail("builder/neg the token at R signed by a stranger", &spend_of(sw.clone().finish(&r_bad).unwrap(), None), 4, BAD_SIG);
	let mut late = sw.clone();
	late.tx.input[1].sequence = elements::Sequence(f.w.to_sequence() - 1);
	let sigs_late: Vec<_> = (0..5).map(|i| sign_digest(&f.s, &late.sighash(i, f.genesis).unwrap(), &[0; 32])).collect();
	book.fail("builder/neg a lowest node one unit before its notice", &spend_of(late.finish(&sigs_late).unwrap(), None), 1, LOCKTIME);
	assert!(matches!(sw.clone().finish(&sigs[..4]), Err(SpendError::SweepSignatures { given: 4, needed: 5 })));

	// With a fee coin, the swept value goes whole to the operator.
	let to_all = vec![ExplicitOutput::new(f.x, value, f.operator_spk())];
	let sw = sweep_tx(&f.schedule, at_r, &swept[..1], &to_all, &fee_coin_source(f, "fee coin", 9_000, 900)).unwrap();
	let sigs: Vec<_> = (0..2).map(|i| sign_digest(&f.s, &sw.sighash(i, f.genesis).unwrap(), &[0; 32])).collect();
	book.pass("builder/sweep of the batch output, a fee coin of another asset paying", &spend_of(sw.finish(&sigs).unwrap(), Some(2)));

	// Burn-only: the builder pays each input whole to an OP_RETURN at its index.
	let burn_lowest = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(true, true), Some(f.chain)).unwrap();
	let burn_batch = NodePolicy::new(children.clone(), xonly(&f.s), keys.clone(), f.schedule.sweep(false, true), None).unwrap();
	let burnt = vec![burn_batch.sweepable(fake_outpoint("burn batch"), value), burn_lowest.sweepable(fake_outpoint("burn lowest"), value)];
	let sw = sweep_tx(&f.schedule, at_r, &burnt, &[], &fee_coin_source(f, "fee coin", 9_000, 900)).unwrap();
	assert_eq!(sw.tx.output[0], explicit(f.x, value, Script::from(vec![0x6a])));
	assert_eq!(sw.tx.output[1], explicit(f.x, value, Script::from(vec![0x6a])));
	let sigs: Vec<_> = (0..3).map(|i| sign_digest(&f.s, &sw.sighash(i, f.genesis).unwrap(), &[0; 32])).collect();
	book.pass("builder/burn-only sweep of the batch output and a lowest node", &spend_of(sw.finish(&sigs).unwrap(), Some(3)));

	// A margin larger than the fee: the fee is paid from it and the rest goes
	// to the broadcaster's change, after the outputs the signers committed
	// to, which the collaborative path still verifies.
	let old = f.leaf(&f.a, "split old leaf");
	let m = arca_covenant::connector_asset(elements::Txid::from_byte_array(label32("split round")), 2);
	let margin = 40_000;
	let ff = Forfeit::new(old, (f.x, LEAF), LeafId(label32("split leaf id")), label32("split h"), m, f.delay, margin).unwrap();
	let pair = Pair { operator: sig(&f.s, &ff.message().digest), owner: sig(&f.a, &ff.message().digest) };
	let split = FeeSource::Split { fee: FEE, change: f.operator_spk() };
	let u = ff.tx(fake_outpoint("split old leaf"), &pair, &split).unwrap();
	assert_eq!(u.tx.output.len(), 3);
	assert_eq!(u.tx.output[0], ff.output().txout(), "the committed output first");
	assert_eq!(u.tx.output[1], explicit(f.x, margin - FEE, f.operator_spk()), "the rest of the margin to the change");
	assert_eq!(u.tx.output[2], fee(f.x, FEE), "then the fee");
	book.pass("builder/forfeit whose margin pays the fee and the rest to change", &spend_of(u, None));
	let whole = ff.tx(fake_outpoint("split old leaf"), &pair, &FeeSource::Split { fee: margin, change: f.operator_spk() }).unwrap();
	assert_eq!(whole.tx.output, vec![ff.output().txout(), fee(f.x, margin)], "a fee of the whole margin leaves no change");
	book.pass("builder/forfeit split with the whole margin as the fee", &spend_of(whole, None));
	for bad in [0, margin + 1] {
		assert_eq!(ff.tx(fake_outpoint("split old leaf"), &pair, &FeeSource::Split { fee: bad, change: f.operator_spk() }).unwrap_err(),
			SpendError::Fee(UnrollError::SplitFee { fee: bad, margin }));
	}
	assert_eq!(f.schedule.release_tx(0, token0, &split).unwrap_err(), SpendError::NeedsFeeCoin("the token"));

	// What the builder refuses.
	let other = ClockSchedule::new(asset("T2"), xonly(&f.s), f.w, f.schedule.expiries().to_vec()).unwrap();
	assert_eq!(sweep_tx(&other, at_r, &swept, &to, &FeeSource::Reserve).unwrap_err(), SpendError::OtherBatch(0));
	assert_eq!(sweep_tx(&f.schedule, at_r, &[], &to, &FeeSource::Reserve).unwrap_err(), SpendError::NothingToSweep);
	let mixed = vec![swept[0].clone(), burnt[1].clone()];
	assert_eq!(sweep_tx(&f.schedule, at_r, &mixed, &to, &FeeSource::Reserve).unwrap_err(), SpendError::MixedBurn);
	assert_eq!(sweep_tx(&f.schedule, at_r, &burnt, &to, &fee_coin_source(f, "c", 9_000, 900)).unwrap_err(), SpendError::BurnOutputs);
	assert_eq!(sweep_tx(&f.schedule, at_r, &burnt, &[], &FeeSource::Reserve).unwrap_err(), SpendError::NeedsFeeCoin("a burn-only sweep"));
	let mut wrong_tap = swept[1].clone();
	wrong_tap.tap = batch.taproot();
	assert_eq!(sweep_tx(&f.schedule, at_r, &[wrong_tap], &to, &FeeSource::Reserve).unwrap_err(), SpendError::NotSweepable(0));
}

// ---------------------------------------------------------------------------
// Claims in one transaction
// ---------------------------------------------------------------------------

/// Three forfeits of one round claimed in one transaction against one atom
/// of its connector asset, every claim naming that atom's input.
fn claim_batch_cases(f: &F, book: &mut Book) {
	let m = arca_covenant::connector_asset(elements::Txid::from_byte_array(label32("batch round")), 2);
	let m2 = arca_covenant::connector_asset(elements::Txid::from_byte_array(label32("another round")), 2);
	let make = |i: usize, conn: AssetId| {
		let owner = keypair(&format!("batch owner {}", i));
		let leaf = f.leaf(&owner, &format!("batch old leaf {}", i));
		let pre = label32(&format!("batch preimage {}", i));
		(Forfeit::new(leaf, (f.x, LEAF), LeafId(label32(&format!("batch leaf id {}", i))), sha256(&pre), conn, f.delay, FEE).unwrap(), pre)
	};
	let fs: Vec<(Forfeit, [u8; 32])> = (0..3).map(|i| make(i, m)).collect();
	let ops: Vec<OutPoint> = (0..3).map(|i| fake_outpoint(&format!("batch forfeit {}", i))).collect();
	let atom = (fake_outpoint("batch atom"), explicit(m, 1, op_true().script_pubkey()));
	let set: Vec<(&Forfeit, OutPoint)> = fs.iter().zip(&ops).map(|((f, _), op)| (f, *op)).collect();
	let to = vec![ExplicitOutput::new(f.x, 3 * (LEAF - FEE) - FEE, f.operator_spk())];
	let c = batch_claim_tx(&set, atom.clone(), &to, f.operator_spk(), &FeeSource::Reserve).unwrap();
	assert_eq!(c.connector_input(), 3);
	assert_eq!(c.tx.output[1], explicit(m, 1, f.operator_spk()), "the atom goes back");
	let preimages: Vec<[u8; 32]> = fs.iter().map(|(_, p)| *p).collect();
	let sigs = |c: &ClaimTx, key: &Keypair| -> Vec<Signature> { (0..3).map(|i| sign_digest(key, &c.sighash(i, f.genesis).unwrap(), &[0; 32])).collect() };
	let finish = |c: &ClaimTx, s: Vec<Signature>, p: &[[u8; 32]]| {
		let mut sp = spend_of(c.clone().finish(&s, p).unwrap(), None);
		sp.witness(3, op_true_witness());
		sp
	};
	book.pass("claim batch/three forfeits of one round, one atom of M at input 3", &finish(&c, sigs(&c, &f.s), &preimages));
	let mut wrong = preimages.clone();
	wrong[1] = label32("not the preimage");
	book.fail("claim batch/neg a wrong preimage on the second claim", &finish(&c, sigs(&c, &f.s), &wrong), 1, EQUALVERIFY);
	let mut swapped = sigs(&c, &f.s);
	swapped.swap(0, 1);
	book.fail("claim batch/neg the first claim's signature on the second input", &finish(&c, swapped, &preimages), 0, BAD_SIG);
	let mut sp = finish(&c, sigs(&c, &f.s), &preimages);
	let n = sp.tx.input[2].witness.script_witness.len();
	sp.tx.input[2].witness.script_witness[n - 3] = arca_covenant::script::scriptnum(0);
	book.fail("claim batch/neg a claim naming a forfeit input as M's", &sp, 2, EQUALVERIFY);
	// A forfeit of another round, with this round's atom: refused by the
	// builder, and by the script when built by hand.
	let (other, other_pre) = make(3, m2);
	let mixed: Vec<(&Forfeit, OutPoint)> = vec![(&fs[0].0, ops[0]), (&other, fake_outpoint("other forfeit"))];
	assert_eq!(batch_claim_tx(&mixed, atom.clone(), &to, f.operator_spk(), &FeeSource::Reserve).unwrap_err(), SpendError::OtherConnector(1));
	let mut by_hand = c.clone();
	by_hand.tx.input[1].previous_output = fake_outpoint("other forfeit");
	by_hand.prevouts[1] = other.output().txout();
	let mut s2 = Spend::new(0).fake_input("f0", by_hand.prevouts[0].clone(), 0xffff_ffff).fake_input("other", other.output().txout(), 0xffff_ffff)
		.fake_input("atom", atom.1.clone(), 0xffff_ffff).outputs(vec![explicit(f.x, 2 * (LEAF - FEE) - FEE, f.operator_spk()),
			explicit(m, 1, f.operator_spk()), fee(f.x, FEE)]);
	let s0 = s2.sign(&f.s, 0, &fs[0].0.policy.claim_script(), f.genesis);
	let s1 = s2.sign(&f.s, 1, &other.policy.claim_script(), f.genesis);
	s2.witness(0, fs[0].0.policy.taproot().witness(&fs[0].0.policy.claim_script(), ForfeitPolicy::claim_items(&s0, &fs[0].1, 2)));
	s2.witness(1, other.policy.taproot().witness(&other.policy.claim_script(), ForfeitPolicy::claim_items(&s1, &other_pre, 2)));
	s2.witness(2, op_true_witness());
	book.fail("claim batch/neg a forfeit of another round claimed with this round's atom", &s2, 1, EQUALVERIFY);
	assert!(matches!(c.clone().finish(&sigs(&c, &f.s)[..2], &preimages), Err(SpendError::ClaimItems { sigs: 2, preimages: 3, forfeits: 3 })));
	assert_eq!(batch_claim_tx(&[], atom, &to, f.operator_spk(), &FeeSource::Reserve).unwrap_err(), SpendError::NothingToClaim);
}

// ---------------------------------------------------------------------------
// htlc-1
// ---------------------------------------------------------------------------

fn htlc_cases(f: &F, book: &mut Book) {
	let preimage = label32("payment");
	let timeout = MedianTime::from_consensus(f.created.to_consensus_u32() + 2 * 86_400).unwrap();
	let salts = HtlcSalts { claim: label32("hc"), claim_both: label32("hb"), refund_both: label32("hr") };
	let mk = |direction| HtlcPolicy {
		owner: xonly(&f.a), operator: xonly(&f.s), direction, payment_hash: sha256(&preimage), timeout, salts, chain: f.chain,
	};
	let send = mk(HtlcDirection::Send);
	let coin = explicit(f.x, LEAF, send.script_pubkey());
	let to = ExplicitOutput::new(f.x, LEAF - FEE, f.operator_spk());
	let tx = |h: &HtlcPolicy, lock: u32, seq: u32, outs: Vec<TxOut>| {
		let c = explicit(f.x, LEAF, h.script_pubkey());
		Spend::new(lock).fake_input("htlc", c, seq).outputs(outs)
	};
	let paid = |o: &ExplicitOutput| vec![o.txout(), fee(f.x, LEAF - o.value)];
	let m_claim = send.message(HtlcPath::Claim, f.x, LEAF, &to).unwrap();
	let m_both = send.message(HtlcPath::ClaimBoth, f.x, LEAF, &to).unwrap();

	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_witness(&sig(&f.s, &m_claim.digest), &preimage));
	book.pass("htlc/claim by the operator with the preimage", &s);
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_witness(&sig(&f.s, &m_claim.digest), &label32("wrong")));
	book.fail("htlc/neg claim with a wrong preimage", &s, 0, EQUALVERIFY);
	let other = ExplicitOutput::new(f.x, LEAF - FEE, f.leaf(&f.a, "elsewhere").script_pubkey());
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&other));
	s.witness(0, send.claim_witness(&sig(&f.s, &m_claim.digest), &preimage));
	book.fail("htlc/neg claim into an output not committed", &s, 0, BAD_SIG);
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_witness(&sig(&f.a, &m_claim.digest), &preimage));
	book.fail("htlc/neg claim signed by the owner", &s, 0, BAD_SIG);
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_both_witness(&sig(&f.s, &m_both.digest), &sig(&f.a, &m_both.digest), &preimage));
	book.pass("htlc/claim with the preimage and both signatures", &s);
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_both_witness(&sig(&f.s, &m_both.digest), &sig(&f.a, &m_both.digest), &label32("wrong")));
	book.fail("htlc/neg claim_both with a wrong preimage", &s, 0, EQUALVERIFY);
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	let mut w = send.claim_both_witness(&sig(&f.s, &m_both.digest), &sig(&f.a, &m_both.digest), &preimage);
	w[1] = vec![];
	s.witness(0, w);
	book.fail("htlc/neg claim_both without the owner", &s, 0, "OP_CHECKSIGVERIFY");
	// The claim signature does not fit the both-signature path (another salt).
	let mut s = tx(&send, 0, 0xffff_ffff, paid(&to));
	s.witness(0, send.claim_both_witness(&sig(&f.s, &m_claim.digest), &sig(&f.a, &m_claim.digest), &preimage));
	book.fail("htlc/neg claim_both with signatures made for the claim path", &s, 0, BAD_SIG);

	let back = ExplicitOutput::new(f.x, LEAF - FEE, f.leaf(&f.a, "back").script_pubkey());
	let lt = timeout.to_consensus_u32();
	let refund = |lock: u32, key: &Keypair| {
		let mut s = tx(&send, lock, 0xffff_fffe, paid(&back));
		let sg = s.sign(key, 0, &send.script(HtlcPath::Refund), f.genesis);
		s.witness(0, send.refund_witness(&sg));
		s
	};
	book.pass("htlc/refund by the owner after the timeout", &refund(lt, &f.a));
	book.fail("htlc/neg refund one second before the timeout", &refund(lt - 1, &f.a), 0, LOCKTIME);
	book.fail("htlc/neg refund signed by the operator", &refund(lt, &f.s), 0, BAD_SIG);
	let m_rb = send.message(HtlcPath::RefundBoth, f.x, LEAF, &back).unwrap();
	let refund_both = |lock: u32| {
		let mut s = tx(&send, lock, 0xffff_fffe, paid(&back));
		s.witness(0, send.refund_both_witness(&sig(&f.s, &m_rb.digest), &sig(&f.a, &m_rb.digest)));
		s
	};
	book.pass("htlc/refund with both signatures after the timeout", &refund_both(lt));
	book.fail("htlc/neg refund_both one second before the timeout", &refund_both(lt - 1), 0, LOCKTIME);

	// A payment into the tree: the owner claims, the operator refunds.
	let recv = mk(HtlcDirection::Receive);
	let mine = ExplicitOutput::new(f.x, LEAF - FEE, f.leaf(&f.a, "received").script_pubkey());
	let m = recv.message(HtlcPath::Claim, f.x, LEAF, &mine).unwrap();
	let mut s = tx(&recv, 0, 0xffff_ffff, paid(&mine));
	s.witness(0, recv.claim_witness(&sig(&f.a, &m.digest), &preimage));
	book.pass("htlc/receive: the owner claims with the preimage", &s);
	let mut s = tx(&recv, 0, 0xffff_ffff, paid(&mine));
	s.witness(0, recv.claim_witness(&sig(&f.s, &m.digest), &preimage));
	book.fail("htlc/neg receive: the operator cannot claim", &s, 0, BAD_SIG);
	let mut s = tx(&recv, lt, 0xffff_fffe, paid(&to));
	let sg = s.sign(&f.s, 0, &recv.script(HtlcPath::Refund), f.genesis);
	s.witness(0, recv.refund_witness(&sg));
	book.pass("htlc/receive: the operator refunds after the timeout", &s);
	let _ = coin;
}

#[test]
fn every_path_against_the_node_interpreter() {
	let f = F::new();
	let mut book = Book::new(f.genesis);
	leaf_cases(&f, &mut book);
	gate_cases(&f, &mut book);
	sweep_cases(&f, &mut book);
	reclaim_cases(&f, &mut book);
	entry_forfeit_cases(&f, &mut book);
	checkpoint_swap_cases(&f, &mut book);
	burn_cases(&f, &mut book);
	htlc_cases(&f, &mut book);
	builder_cases(&f, &mut book);
	claim_batch_cases(&f, &mut book);
	book.print();
	assert!(book.refused >= 100, "only {} negative cases", book.refused);
}

#[test]
fn record_of_an_explicit_child() {
	let f = F::new();
	let c = Child::new(f.x, 5, [3; 32]);
	assert_eq!(c.record(), record(f.x, 5, &c.script_pubkey()));
}
