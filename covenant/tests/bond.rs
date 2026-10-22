//! The equivocation bond on anchored regtest: a slash by two operator
//! signatures under one leaf salt burns the bond in a block; the notice and
//! the withdrawal after its delay; and every way around them, refused by the
//! mempool and again when forced into a block, the block refused for the
//! mempool's reason.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxOut};

use arca_covenant::bond::{self, rebind_signed_in, BondPolicy, Evidence, Form, Signed};
use arca_covenant::issuer::burn_script;
use arca_covenant::spend::collab_tx;
use arca_covenant::{ExplicitOutput, FeeSource, Pair, Rebindable, RelativeTime};
use common::net::*;
use common::*;

const BOND: u64 = 1_000_000_000;
const SLASH_FEE: u64 = 2_000;

struct Bonds {
	net: Net,
	s: Keypair,
	w: Keypair,
	policy: BondPolicy,
}

impl Bonds {
	fn start() -> Bonds {
		let net = Net::start();
		let s = keypair("bond S");
		let w = keypair("bond W");
		let policy = BondPolicy::new(net.chain, xonly(&s), xonly(&w), RelativeTime::from_units(4).unwrap()).unwrap();
		Bonds { net, s, w, policy }
	}

	/// A bond coin of `value` of `asset`, posted.
	fn post(&mut self, asset: AssetId, value: u64) -> Coin {
		self.net.fund(vec![explicit(asset, value, self.policy.script_pubkey())]).remove(0)
	}

	/// A coin of X that pays a fee.
	fn x_coin(&mut self) -> Coin {
		let x = self.net.x;
		self.net.fund(vec![explicit(x, 20_000, op_true_spk())]).remove(0)
	}

	fn by(&self, c: &Coin, fee: u64) -> FeeSource {
		FeeSource::Coin { outpoint: c.outpoint, coin: c.txout.clone(), fee, change: op_true_spk() }
	}

	/// The slash of `coins` on `e`, its fee from `fee_coin`.
	fn slash(&self, coins: &[&Coin], e: &Evidence, fee_coin: &Coin) -> Transaction {
		let cs: Vec<(OutPoint, TxOut)> = coins.iter().map(|c| (c.outpoint, c.txout.clone())).collect();
		let mut u = self.policy.slash_tx(&cs, e, &self.by(fee_coin, SLASH_FEE)).unwrap();
		let n = u.tx.input.len();
		u.tx.input[n - 1].witness.script_witness = op_true_witness();
		u.tx
	}

	/// The notice of `coin`, signed by `key`.
	fn notice(&self, coin: &Coin, key: &Keypair, fee_coin: &Coin) -> Transaction {
		let (a, v) = (coin.txout.asset.explicit().unwrap(), coin.txout.value.explicit().unwrap());
		let k = self.policy.notice_tx(coin.outpoint, a, v, &self.by(fee_coin, SLASH_FEE)).unwrap();
		let sig = sig(key, &k.sighash(self.net.genesis).unwrap());
		let mut u = k.finish(vec![sig.as_ref().to_vec()]);
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	}

	/// The withdrawal of `noticed` to an OP_TRUE output, signed by `key`, with
	/// input 0's sequence `seq`.
	fn withdraw(&self, noticed: &Coin, key: &Keypair, fee_coin: &Coin, seq: Option<u32>) -> Transaction {
		let (a, v) = (noticed.txout.asset.explicit().unwrap(), noticed.txout.value.explicit().unwrap());
		let out = ExplicitOutput::new(a, v, op_true_spk());
		let mut k = self.policy.withdraw_tx(noticed.outpoint, a, v, &[out], &self.by(fee_coin, SLASH_FEE)).unwrap();
		if let Some(s) = seq {
			k.tx.input[0].sequence = elements::Sequence(s);
		}
		let sig = sig(key, &k.sighash(self.net.genesis).unwrap());
		let mut u = k.finish(vec![sig.as_ref().to_vec()]);
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	}
}

/// S's signature over a message of `form` under `salt` whose rest is `rest`:
/// what a signer that breaks the once-per-salt rule hands out.
fn signs(p: &BondPolicy, key: &Keypair, form: Form, salt: &[u8; 32], rest: &[u8], aux: u8) -> Signed {
	let d = bond::digest(&p.chain, form, salt, rest);
	Signed { form, rest: rest.to_vec(), signature: arca_covenant::sign::sign_digest(key, &d, &[aux; 32]) }
}

fn with_items(tx: &Transaction, input: usize, p: &BondPolicy, noticed: bool, items: Vec<Vec<u8>>) -> Transaction {
	let tap = if noticed { p.notice_taproot() } else { p.taproot() };
	let mut t = tx.clone();
	t.input[input].witness.script_witness = tap.witness(&p.slash_script(), items);
	t
}

#[test]
fn the_equivocation_bond() {
	let mut b = Bonds::start();
	let (x, y) = (b.net.x, b.net.y);
	let p = b.policy;
	println!("SLASH {} bytes, NOTICE {} bytes, WITHDRAW {} bytes", p.slash_script().len(), p.notice_script().len(),
		p.withdraw_script().len());
	println!("bond script {}", hex(p.script_pubkey().as_bytes()));

	// ---------------------------------------------------------------
	// A leaf A owns under salt σ, on the chain. A and the operator pay it
	// to Bob (the message Bob holds, out of round), and S, breaking the
	// once-per-salt rule, also co-signs a spend of the same leaf to A.
	// That second spend confirms: Bob's coin is gone.
	// ---------------------------------------------------------------
	let a = keypair("bond leaf owner A");
	let leaf = b.net.leaf(&a, &b.s, "bond leaf salt");
	let salt = leaf.salt;
	let value = 500_000;
	let l = b.net.fund(vec![explicit(x, value, leaf.script_pubkey())]).remove(0);
	let bob_spk = elements::script::Builder::new().push_int(1).push_slice(&label32("Bob's checkpoint")).into_script();
	let to_bob = [ExplicitOutput::new(x, value - 1_000, bob_spk)];
	let to_a = [ExplicitOutput::new(x, value - 1_000, op_true_spk())];
	let m_bob = leaf.message(x, value, &to_bob).unwrap();
	let m_a = leaf.message(x, value, &to_a).unwrap();
	let pair = |m: &arca_covenant::CsfsMessage| Pair { operator: sig(&b.s, &m.digest), owner: sig(&a, &m.digest) };
	let bob_holds = Signed { form: Form::Rebind, rest: bond::rebind_rest(&m_bob.preimage).unwrap(), signature: pair(&m_bob).operator };
	assert!(p.verify(&salt, &bob_holds));
	let mut spend = collab_tx(&leaf, l.outpoint, x, value, &to_a, &pair(&m_a), &FeeSource::Reserve).unwrap();
	let conflict = b.net.pass("the conflicting spend of A's leaf, co-signed a second time", &spend.tx);
	spend.tx = b.net.rt.client().raw_transaction(&conflict).unwrap();
	// A watcher reads S's second signature from the chain.
	let from_chain = rebind_signed_in(&p.chain, &salt, &spend.tx, 0, &l.txout).expect("a collaborative spend under σ");
	assert!(p.verify(&salt, &from_chain), "S's signature as the chain carries it");
	assert_eq!(rebind_signed_in(&p.chain, &[9; 32], &spend.tx, 0, &l.txout), None, "another salt's K is not in its script");
	let evidence = Evidence { salt, a: bob_holds.clone(), b: from_chain.clone() };
	assert_eq!(p.check(&evidence), Ok(()));

	// ---------------------------------------------------------------
	// The bond, posted in X; its control, a slash that burns it whole.
	// ---------------------------------------------------------------
	let b1 = b.post(x, BOND);
	let fee1 = b.x_coin();
	let control = b.slash(&[&b1], &evidence, &fee1);

	// One signature twice: Bob's signature in both slots.
	let twice = Evidence { salt, a: bob_holds.clone(), b: Signed { signature: bob_holds.signature, ..from_chain.clone() } };
	b.net.refuse("slash: one signature twice", &with_items(&control, 0, &p, false, BondPolicy::slash_items(&twice).unwrap()),
		"Invalid Schnorr signature");
	// Two signatures over one digest.
	let again = signs(&p, &b.s, Form::Rebind, &salt, &bob_holds.rest, 7);
	assert_ne!(again.signature, bob_holds.signature);
	let one_digest = Evidence { salt, a: bob_holds.clone(), b: again };
	b.net.refuse("slash: two signatures over the same digest", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&one_digest).unwrap()), "Script failed an OP_VERIFY operation");
	// Two digests under different salts, the slash naming the first's.
	let other_leaf = b.net.leaf(&a, &b.s, "bond another salt");
	// Its message commits to other outputs: two salts, two rests.
	let m_other = other_leaf.message(x, value, &to_a).unwrap();
	let other = Signed { form: Form::Rebind, rest: bond::rebind_rest(&m_other.preimage).unwrap(), signature: sig(&b.s, &m_other.digest) };
	assert!(p.verify(&other_leaf.salt, &other));
	let two_salts = Evidence { salt, a: bob_holds.clone(), b: other.clone() };
	b.net.refuse("slash: two digests under two salts", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&two_salts).unwrap()), "Invalid Schnorr signature");
	let two_salts_other = Evidence { salt: other_leaf.salt, a: other, b: bob_holds.clone() };
	b.net.refuse("slash: two digests under two salts, naming the second's", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&two_salts_other).unwrap()), "Invalid Schnorr signature");
	// Signatures by another key over two digests under σ.
	let t = keypair("a stranger");
	let stranger = Evidence { salt, a: signs(&p, &t, Form::Rebind, &salt, &bob_holds.rest, 0),
		b: signs(&p, &t, Form::Rebind, &salt, &from_chain.rest, 0) };
	b.net.refuse("slash: two digests under σ signed by another key", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&stranger).unwrap()), "Invalid Schnorr signature");
	let half_stranger = Evidence { salt, a: bob_holds.clone(), b: stranger.b.clone() };
	b.net.refuse("slash: the second by another key", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&half_stranger).unwrap()), "Invalid Schnorr signature");
	// The second signature missing.
	let mut items = BondPolicy::slash_items(&evidence).unwrap();
	items[0] = vec![];
	b.net.refuse("slash: the second signature empty", &with_items(&control, 0, &p, false, items),
		"Script evaluated without error but finished with a false/empty top stack element");
	// The salt not 32 bytes: σ with a byte more, the rests one byte shorter.
	let mut items = BondPolicy::slash_items(&evidence).unwrap();
	let mut long_salt = salt.to_vec();
	long_salt.push(items[8][0]);
	items[10] = long_salt;
	items[8] = items[8][1..].to_vec();
	b.net.refuse("slash: a 33-byte salt", &with_items(&control, 0, &p, false, items), "Script failed an OP_EQUALVERIFY operation");
	// A form byte that is not minimal; a rebind message read as a fill.
	let mut items = BondPolicy::slash_items(&evidence).unwrap();
	items[9] = vec![2];
	b.net.refuse("slash: a form byte of 2", &with_items(&control, 0, &p, false, items),
		"OP_IF/NOTIF argument must be minimal in tapscript");
	let as_fill = Evidence { salt, a: Signed { form: Form::Fill, ..bob_holds.clone() }, b: from_chain.clone() };
	b.net.refuse("slash: a rebind message read as a fill", &with_items(&control, 0, &p, false,
		BondPolicy::slash_items(&as_fill).unwrap()), "Invalid Schnorr signature");

	// The burn: one atom short (it goes to the change), to another script,
	// at another index, in another asset.
	let mut short = control.clone();
	short.output[0].value = elements::confidential::Value::Explicit(BOND - 1);
	let change = short.output.iter().position(|o| o.script_pubkey == op_true_spk()).unwrap();
	short.output[change].value = elements::confidential::Value::Explicit(short.output[change].value.explicit().unwrap() + 1);
	b.net.refuse("slash: the burn one atom short", &short, "Script failed an OP_EQUALVERIFY operation");
	let mut elsewhere = control.clone();
	elsewhere.output[0].script_pubkey = op_true_spk();
	b.net.refuse("slash: the bond to a script, not burned", &elsewhere, "Script failed an OP_EQUALVERIFY operation");
	let mut data_burn = control.clone();
	data_burn.output[0].script_pubkey = Script::from(vec![0x6a, 0x01, 0x00]);
	b.net.refuse("slash: the burn an OP_RETURN with data", &data_burn, "Script failed an OP_EQUALVERIFY operation");
	let mut moved = control.clone();
	moved.output.swap(0, change);
	b.net.refuse("slash: the burn at another index", &moved, "Script failed an OP_EQUALVERIFY operation");
	let yc = b.net.fund(vec![explicit(y, BOND, op_true_spk())]).remove(0);
	let mut other_asset = control.clone();
	other_asset.input.push(elements::TxIn { previous_output: yc.outpoint, sequence: elements::Sequence(0xffff_ffff), ..Default::default() });
	other_asset.input[2].witness.script_witness = op_true_witness();
	other_asset.output[0] = explicit(y, BOND, burn_script());
	other_asset.output.push(explicit(x, BOND, op_true_spk()));
	b.net.refuse("slash: the burn in another asset", &other_asset, "Script failed an OP_EQUALVERIFY operation");

	// The control: Bob's evidence and the chain's burn the bond whole.
	let slashed = b.net.pass("slash: two digests under one salt burn the bond", &control);
	let tx = b.net.rt.client().raw_transaction(&slashed).unwrap();
	assert_eq!(arca_covenant::issuer::burned(&tx, x), BOND);
	assert_eq!(tx.output[0].script_pubkey, burn_script());
	let w = &tx.input[0].witness.script_witness;
	println!("slash witness: {} items, {} bytes ({} of them the script, {} the control block)", w.len(),
		w.iter().map(|i| i.len()).sum::<usize>(), w[w.len() - 2].len(), w[w.len() - 1].len());

	// ---------------------------------------------------------------
	// Two bond coins in one slash: sharing one burn is refused; each
	// burned at its own index is taken.
	// ---------------------------------------------------------------
	let c1 = b.post(x, BOND);
	let c2 = b.post(x, BOND);
	let fee2 = b.x_coin();
	let both = b.slash(&[&c1, &c2], &evidence, &fee2);
	let mut shared = both.clone();
	shared.output[0].value = elements::confidential::Value::Explicit(2 * BOND);
	shared.output.remove(1);
	b.net.refuse("slash: two bond coins sharing one burn", &shared, "Script failed an OP_EQUALVERIFY operation");
	b.net.pass("slash: two bond coins, each burned at its own index", &both);

	// ---------------------------------------------------------------
	// Messages of the most outputs, a fill beside a collaborative spend,
	// and two fills, under one salt: a bond in Y, which no producer takes
	// for fees, slashed with the fee in X.
	// ---------------------------------------------------------------
	let wide_outs: Vec<ExplicitOutput> = (0..4).map(|i| ExplicitOutput::new(x, 100_000 + i, op_true_spk())).collect();
	let wide = leaf.message(x, value, &wide_outs).unwrap();
	let wide = Signed { form: Form::Rebind, rest: bond::rebind_rest(&wide.preimage).unwrap(), signature: sig(&b.s, &wide.digest) };
	assert_eq!(wide.rest.len(), 171);
	let fill_rest: Vec<u8> = (0..169u32).map(|i| (i * 7) as u8).collect();
	let fill = signs(&p, &b.s, Form::Fill, &salt, &fill_rest, 0);
	let fill2 = signs(&p, &b.s, Form::Fill, &salt, &fill_rest[..137], 0);
	let by = b.post(y, BOND);
	let fee3 = b.x_coin();
	let fill_and_wide = Evidence { salt, a: wide.clone(), b: fill.clone() };
	b.net.pass("slash: a fill and a four-output spend under one salt, a bond in Y, its fee in X",
		&b.slash(&[&by], &fill_and_wide, &fee3));
	let bz = b.post(x, BOND);
	let fee4 = b.x_coin();
	b.net.pass("slash: two fills under one salt", &b.slash(&[&bz], &Evidence { salt, a: fill, b: fill2 }, &fee4));

	// ---------------------------------------------------------------
	// The notice and the withdrawal.
	// ---------------------------------------------------------------
	let bn = b.post(x, BOND);
	let fee5 = b.x_coin();
	let notice = b.notice(&bn, &b.w, &fee5);
	// W signs each changed transaction itself: the covenant, not the
	// signature, refuses it.
	let (genesis, wk) = (b.net.genesis, b.w);
	let prev = vec![bn.txout.clone(), fee5.txout.clone()];
	let resign = |mut t: Transaction| {
		let d = arca_covenant::sign::script_spend_sighash(&t, 0, &prev, &p.notice_script(), genesis).unwrap();
		t.input[0].witness.script_witness[0] = sig(&wk, &d).as_ref().to_vec();
		t
	};
	let mut to_w = notice.clone();
	to_w.output[0].script_pubkey = op_true_spk();
	b.net.refuse("notice: the bond to another script, signed by W", &resign(to_w), "Script failed an OP_EQUALVERIFY operation");
	let mut notice_short = notice.clone();
	notice_short.output[0].value = elements::confidential::Value::Explicit(BOND - 1);
	let nc = notice_short.output.iter().position(|o| o.script_pubkey == op_true_spk()).unwrap();
	notice_short.output[nc].value = elements::confidential::Value::Explicit(notice_short.output[nc].value.explicit().unwrap() + 1);
	b.net.refuse("notice: one atom short of the whole bond", &resign(notice_short), "Script failed an OP_EQUALVERIFY operation");
	b.net.refuse("notice: signed by S, the hot key", &b.notice(&bn, &b.s, &fee5), "Invalid Schnorr signature");
	// A withdrawal before its notice: the bond has no WITHDRAW leaf.
	let fee6 = b.x_coin();
	let mut early = b.withdraw(&Coin { outpoint: bn.outpoint, txout: explicit(x, BOND, p.notice_script_pubkey()) }, &b.w, &fee6, None);
	early.input[0].sequence = elements::Sequence(0xffff_fffe);
	b.net.refuse("withdraw: the bond itself, before any notice", &early, "Witness program hash mismatch");
	let noticed_txid = b.net.pass("notice: the bond whole to the notice output, signed by W", &notice);
	let noticed = coin_of(noticed_txid, 0, &notice);
	assert_eq!(p.state_of(&noticed.txout.script_pubkey), Some(arca_covenant::BondState::Noticed));
	// Before the delay has run.
	b.net.refuse("withdraw: at once after the notice", &b.withdraw(&noticed, &b.w, &fee6, None), "non-BIP68-final");
	b.net.wait_csv(&noticed_txid, p.notice);
	// After it: a sequence below the delay, one in blocks, a key not W.
	b.net.refuse("withdraw: a sequence one unit short of the delay",
		&b.withdraw(&noticed, &b.w, &fee6, Some(p.notice.to_sequence() - 1)), "Locktime requirement not satisfied");
	b.net.refuse("withdraw: a delay in blocks", &b.withdraw(&noticed, &b.w, &fee6, Some(4)), "Locktime requirement not satisfied");
	b.net.refuse("withdraw: signed by S", &b.withdraw(&noticed, &b.s, &fee6, None), "Invalid Schnorr signature");
	// A bond in notice is still slashed; then nothing is left to withdraw.
	let bn2 = b.post(x, BOND);
	let fee7 = b.x_coin();
	let notice2 = b.notice(&bn2, &b.w, &fee7);
	let n2 = b.net.pass("notice: a second bond", &notice2);
	let fee8 = b.x_coin();
	let in_notice = coin_of(n2, 0, &notice2);
	b.net.refuse("slash in notice: by another key", &with_items(&b.slash(&[&in_notice], &evidence, &fee8), 0, &p, true,
		BondPolicy::slash_items(&stranger).unwrap()), "Invalid Schnorr signature");
	b.net.pass("slash: a bond in notice, burned whole", &b.slash(&[&in_notice], &evidence, &fee8));
	// The first bond's withdrawal, after its notice and its delay.
	b.net.pass("withdraw: after the notice and its delay, signed by W", &b.withdraw(&noticed, &b.w, &fee6, None));

	b.net.print();
}

/// A conflicting spend whose witness ends with an annex (BIP341): the
/// mempool refuses it (`bad-witness-nonstandard`), a block producer mines it,
/// and its signatures, built over messages that commit to no annex, stay
/// valid. It is the same transaction as the spend without it, the same txid.
/// A watcher reads S's signature from it as from the plain spend, and the
/// slash burns the bond.
#[test]
fn an_annexed_conflicting_spend_is_evidence_as_the_plain_one() {
	let mut b = Bonds::start();
	let x = b.net.x;
	let p = b.policy;
	let a = keypair("annex bond leaf owner");
	let leaf = b.net.leaf(&a, &b.s, "annex bond leaf salt");
	let salt = leaf.salt;
	let value = 500_000;
	let l = b.net.fund(vec![explicit(x, value, leaf.script_pubkey())]).remove(0);
	let bob_spk = elements::script::Builder::new().push_int(1).push_slice(&label32("annex Bob's checkpoint")).into_script();
	let to_bob = [ExplicitOutput::new(x, value - 1_000, bob_spk)];
	let to_a = [ExplicitOutput::new(x, value - 1_000, op_true_spk())];
	let m_bob = leaf.message(x, value, &to_bob).unwrap();
	let m_a = leaf.message(x, value, &to_a).unwrap();
	let pair = |m: &arca_covenant::CsfsMessage| Pair { operator: sig(&b.s, &m.digest), owner: sig(&a, &m.digest) };
	let bob_holds = Signed { form: Form::Rebind, rest: bond::rebind_rest(&m_bob.preimage).unwrap(), signature: pair(&m_bob).operator };
	let plain = collab_tx(&leaf, l.outpoint, x, value, &to_a, &pair(&m_a), &FeeSource::Reserve).unwrap().tx;
	let mut annexed = plain.clone();
	annexed.input[0].witness.script_witness.push(vec![0x50, 0xa4, 0x07]);
	assert_eq!(annexed.txid(), plain.txid(), "the annex is witness data: the txid is the plain spend's");
	assert_ne!(annexed.wtxid(), plain.wtxid());
	let id = b.net.mine_policy_refused("the conflicting spend of A's leaf, an annex on its witness", &annexed, "bad-witness-nonstandard");
	let mined = b.net.rt.client().raw_transaction(&id).unwrap();
	let w = &mined.input[0].witness.script_witness;
	assert_eq!(w.len(), 6, "the block carries the annex");
	assert_eq!(w[5], vec![0x50, 0xa4, 0x07]);
	println!("mined {} with a {}-item witness, the last {}", id, w.len(), hex(&w[5]));
	let seen = rebind_signed_in(&p.chain, &salt, &mined, 0, &l.txout);
	println!("the watcher reads from it: {:?}", seen.as_ref().map(|s| hex(s.signature.as_ref())));
	let seen = seen.expect("S's signature on the annexed spend is read as on the plain one");
	assert_eq!(Some(seen.clone()), rebind_signed_in(&p.chain, &salt, &plain, 0, &l.txout), "the same evidence as the plain spend's");
	assert!(p.verify(&salt, &seen));
	let evidence = Evidence { salt, a: bob_holds, b: seen };
	assert_eq!(p.check(&evidence), Ok(()));
	let bond = b.post(x, BOND);
	let fee = b.x_coin();
	let slashed = b.net.pass("slash: Bob's message and the annexed spend's burn the bond", &b.slash(&[&bond], &evidence, &fee));
	assert_eq!(arca_covenant::issuer::burned(&b.net.rt.client().raw_transaction(&slashed).unwrap(), x), BOND);
	b.net.print();
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}
