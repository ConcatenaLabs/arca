//! The Rust builders against the golden vectors.
//!
//! `regtest/vectors/arca.json` is exported by the regtest suite from its own,
//! independent builders. Every output is rebuilt here from the inputs the
//! vector names and must match byte for byte: each script leaf, control block,
//! merkle root, output key and scriptPubKey. Every sample spend is then
//! re-signed here, and the signature hash or message, the signatures and the
//! whole witness must match too; the transaction carrying the witness built
//! here must verify with the node's interpreter.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::encode::deserialize;
use elements::hashes::Hash;
use elements::hex::{FromHex, ToHex};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{AssetId, BlockHash, Script, Transaction, TxOut, Txid};
use serde_json::Value;

use arca_consensus::Verifier;
use arca_covenant::htlc::HtlcPath;
use arca_covenant::script::{record, sha256};
use arca_covenant::sign::{script_spend_sighash, sign_digest};
use arca_covenant::*;

const VECTORS: &str = include_str!("../../regtest/vectors/arca.json");
const ZERO_AUX: [u8; 32] = [0; 32];

fn hex(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap_or_else(|| panic!("not a hex string: {}", v))).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
	hex(v).try_into().unwrap()
}

fn key(v: &Value) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&hex(v)).unwrap()
}

fn asset(v: &Value) -> AssetId {
	AssetId::from_byte_array(h32(v))
}

fn rel(v: &Value) -> RelativeTime {
	RelativeTime::from_sequence(v.as_u64().unwrap() as u32).unwrap()
}

fn time(v: &Value) -> MedianTime {
	MedianTime::from_consensus(v.as_u64().unwrap() as u32).unwrap()
}

struct Ctx {
	v: Value,
	chain: Chain,
	genesis: BlockHash,
	keys: BTreeMap<String, Keypair>,
	schedule: ClockSchedule,
}

impl Ctx {
	fn load() -> Ctx {
		let v: Value = serde_json::from_str(VECTORS).unwrap();
		let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()).unwrap();
		assert_eq!(genesis.to_byte_array(), h32(&v["inputs"]["genesis_hash"]["internal"]));
		let chain = Chain::new(genesis);
		assert_eq!(chain.tag(), h32(&v["inputs"]["chain_tag"]));
		let secp = Secp256k1::new();
		let mut keys = BTreeMap::new();
		for (label, k) in v["inputs"]["keys"].as_object().unwrap() {
			// The test keys are derived from their labels.
			let derived = sha256(format!("Arca test vector key/{}", label).as_bytes());
			assert_eq!(derived, h32(&k["secret"]), "key {} is not derived from its label", label);
			let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&derived).unwrap());
			assert_eq!(kp.x_only_public_key().0, key(&k["xonly"]));
			keys.insert(label.clone(), kp);
		}
		let inp = &v["inputs"];
		let expiries = inp["expiries"].as_array().unwrap().iter().map(time).collect();
		let schedule = ClockSchedule::new(
			asset(&inp["assets"]["T"]),
			keys["S"].x_only_public_key().0,
			rel(&inp["notice"]),
			expiries,
		).unwrap();
		Ctx { v, chain, genesis, keys, schedule }
	}

	fn kp(&self, label: &str) -> &Keypair {
		&self.keys[label]
	}

	fn x(&self, label: &str) -> XOnlyPublicKey {
		self.keys[label].x_only_public_key().0
	}

	fn label_of(&self, xonly: &XOnlyPublicKey) -> &str {
		self.keys.iter().find(|(_, k)| &k.x_only_public_key().0 == xonly).map(|(l, _)| l.as_str()).unwrap()
	}

	fn output(&self, name: &str) -> &Value {
		&self.v["outputs"][name]
	}

	fn sweep_of(&self, p: &Value, burn: bool) -> Sweep {
		let s = Sweep {
			token: asset(&p["token"]),
			r_program: h32(&p["r_program"]),
			operator: key(&p["operator"]),
			notice: if p["notice"].is_null() { None } else { Some(rel(&p["notice"])) },
			burn,
		};
		assert_eq!(s.token, self.schedule.token);
		assert_eq!(s.r_program, self.schedule.r().program());
		s
	}

	fn node(&self, name: &str, burn: bool) -> NodePolicy {
		let p = &self.output(name)["params"];
		let children = p["children"].as_array().unwrap().iter()
			.map(|c| Child::new(asset(&c["asset"]), c["value"].as_u64().unwrap(), h32(&c["program"])))
			.collect();
		let members: Vec<XOnlyPublicKey> = p["members"].as_array().unwrap().iter().map(key).collect();
		assert_eq!(members[0], self.x("S"), "the operator leads the member list");
		let reclaim = if p["kind"].as_str().unwrap().starts_with("lowest") { Some(self.chain) } else { None };
		let node = NodePolicy::new(children, members[0], members[1..].to_vec(), self.sweep_of(p, burn), reclaim)
			.unwrap();
		let m = node.members();
		assert_eq!(m.root(), h32(&p["member_root"]));
		assert_eq!(m.depth() as u64, p["member_depth"].as_u64().unwrap());
		let padded: Vec<XOnlyPublicKey> = p["members_padded"].as_array().unwrap().iter().map(key).collect();
		assert_eq!(m.keys(), &padded[..]);
		assert_eq!(node.children_hash(), h32(&p["children_hash"]));
		if let Some(rm) = node.release_message() {
			assert_eq!(rm.digest, h32(&p["release_message"]));
		}
		node
	}

	fn leaf(&self) -> LeafPolicy {
		let p = &self.output("leaf")["params"];
		let leaf = LeafPolicy {
			owner: key(&p["owner"]),
			operator: key(&p["operator"]),
			salt: h32(&p["salt"]),
			chain: self.chain,
			exit_delay: rel(&p["exit_delay"]),
		};
		assert_eq!(leaf.leaf_constant(), h32(&p["K"]));
		leaf
	}

	fn entry(&self, name: &str, burn: bool) -> EntryPolicy {
		let p = &self.output(name)["params"];
		EntryPolicy {
			unlock_hash: h32(&p["unlock_hash"]),
			asset: asset(&p["asset"]),
			value: p["value"].as_u64().unwrap(),
			leaf_program: h32(&p["leaf_program"]),
			sweep: self.sweep_of(p, burn),
		}
	}

	fn forfeit(&self) -> ForfeitPolicy {
		let p = &self.output("forfeit")["params"];
		let round = Txid::from_str(p["connector"]["round_txid"].as_str().unwrap()).unwrap();
		let vout = p["connector"]["vout"].as_u64().unwrap() as u32;
		let connector = arca_covenant::connector_asset(round, vout);
		assert_eq!(connector, AssetId::from_byte_array(h32(&p["connector"]["asset"])), "the connector asset from the round's outpoint");
		ForfeitPolicy {
			unlock_hash: h32(&p["unlock_hash"]),
			owner: key(&p["owner"]),
			operator: key(&p["operator"]),
			refund_delay: rel(&p["refund_delay"]),
			leaf_id: arca_covenant::LeafId(h32(&p["leaf_id"])),
			connector,
		}
	}

	fn checkpoint(&self) -> CheckpointPolicy {
		let p = &self.output("checkpoint")["params"];
		let cp = CheckpointPolicy {
			owner: key(&p["owner"]),
			operator: key(&p["operator"]),
			salt: h32(&p["salt"]),
			chain: self.chain,
			sweep: self.sweep_of(p, false),
		};
		assert_eq!(cp.leaf_constant(), h32(&p["K"]));
		cp
	}

	fn htlc(&self, name: &str) -> HtlcPolicy {
		let p = &self.output(name)["params"];
		let owner = key(&p["owner"]);
		let direction = if key(&p["claimer"]) == owner { HtlcDirection::Receive } else { HtlcDirection::Send };
		let h = HtlcPolicy {
			owner,
			operator: key(&p["operator"]),
			direction,
			payment_hash: h32(&p["payment_hash"]),
			timeout: time(&p["timeout"]),
			salts: HtlcSalts {
				claim: h32(&p["salts"]["claim"]),
				claim_both: h32(&p["salts"]["claim_both"]),
				refund_both: h32(&p["salts"]["refund_both"]),
			},
			chain: self.chain,
		};
		assert_eq!(h.claimer(), key(&p["claimer"]));
		assert_eq!(h.refunder(), key(&p["refunder"]));
		for (path, name) in [(HtlcPath::Claim, "claim"), (HtlcPath::ClaimBoth, "claim_both"), (HtlcPath::RefundBoth, "refund_both")] {
			assert_eq!(h.leaf_constant(path).unwrap(), h32(&p["K"][name]));
		}
		h
	}

	/// The Rust output for a vector output, with its leaves by name.
	fn built(&self, name: &str) -> (TapOutput, BTreeMap<&'static str, Script>) {
		let node_leaves = |n: &NodePolicy| {
			let mut m = BTreeMap::from([("unroll", n.unroll_script()), ("sweep", n.sweep_script())]);
			if let Some(r) = n.reclaim_script() {
				m.insert("reclaim", r);
			}
			(n.taproot(), m)
		};
		match name {
			"leaf" => {
				let l = self.leaf();
				(l.taproot(), BTreeMap::from([("collab", l.collab_script()), ("exit", l.exit_script())]))
			},
			"r" => (self.schedule.r(), BTreeMap::from([("spend", self.schedule.r_script())])),
			c if c.starts_with("clock") => {
				let j: usize = c[5..].parse().unwrap();
				let clock = self.schedule.clocks().swap_remove(j);
				let mut m = BTreeMap::from([("release", clock.release.clone())]);
				if let Some(r) = &clock.roll {
					m.insert("roll", r.clone());
				}
				(clock.output, m)
			},
			"entry" | "entry_burn" => {
				let e = self.entry(name, name.ends_with("burn"));
				(e.taproot(), BTreeMap::from([("unlock", e.unlock_script()), ("sweep", e.sweep_script())]))
			},
			"lowest_node" | "inner_node" | "batch_output" => node_leaves(&self.node(name, false)),
			"lowest_node_burn" | "batch_output_burn" => node_leaves(&self.node(name, true)),
			"forfeit" => {
				let f = self.forfeit();
				(f.taproot(), BTreeMap::from([("claim", f.claim_script()), ("refund", f.refund_script())]))
			},
			"checkpoint" => {
				let c = self.checkpoint();
				(c.taproot(), BTreeMap::from([("collab", c.collab_script()), ("sweep", c.sweep_script())]))
			},
			"htlc" | "htlc_receive" => {
				let h = self.htlc(name);
				(h.taproot(), BTreeMap::from([
					("claim", h.script(HtlcPath::Claim)),
					("claim_both", h.script(HtlcPath::ClaimBoth)),
					("refund", h.script(HtlcPath::Refund)),
					("refund_both", h.script(HtlcPath::RefundBoth)),
				]))
			},
			other => panic!("no builder for vector output {}", other),
		}
	}
}

#[test]
fn every_output_matches_its_vector() {
	let ctx = Ctx::load();
	let outputs = ctx.v["outputs"].as_object().unwrap();
	assert_eq!(outputs.len(), 16);
	for (name, o) in outputs {
		let (tap, leaves) = ctx.built(name);
		let expected = o["leaves"].as_object().unwrap();
		assert_eq!(leaves.len(), expected.len(), "{}: leaf count", name);
		for (leaf_name, l) in expected {
			let script = &leaves[leaf_name.as_str()];
			assert_eq!(script.to_hex(), l["script"].as_str().unwrap(), "{}/{}: script", name, leaf_name);
			assert_eq!(script.len() as u64, l["bytes"].as_u64().unwrap());
			assert_eq!(tap.control_block(script).unwrap(), hex(&l["control_block"]), "{}/{}: control block", name, leaf_name);
			assert_eq!(arca_covenant::taptree::leaf_hash(script).to_byte_array(), h32(&l["leaf_hash"]));
		}
		assert_eq!(tap.merkle_root().unwrap(), h32(&o["merkle_root"]), "{}: merkle root", name);
		assert_eq!(tap.output_key().serialize(), h32(&o["output_key"]), "{}: output key", name);
		assert_eq!(tap.script_pubkey().to_hex(), o["script_pubkey"].as_str().unwrap(), "{}: scriptPubKey", name);
	}
}

#[test]
fn every_record_matches_its_vector() {
	let ctx = Ctx::load();
	for r in ctx.v["records"].as_array().unwrap() {
		let spk = Script::from(hex(&r["script_pubkey"]));
		assert_eq!(record(asset(&r["asset"]), r["value"].as_u64().unwrap(), &spk), hex(&r["record"]),
			"record: {}", r["name"]);
	}
}

fn sigs(s: &Value) -> BTreeMap<String, Signature> {
	match s["signatures"].as_object() {
		Some(m) => m.iter().map(|(k, v)| (k.clone(), Signature::from_slice(&hex(v)).unwrap())).collect(),
		None => BTreeMap::new(), // the entry's unlock is signed by nobody
	}
}

#[test]
fn every_spend_matches_its_vector_and_verifies() {
	let ctx = Ctx::load();
	let verifier = Verifier::consensus(ctx.genesis);
	let spends = ctx.v["spends"].as_array().unwrap();
	assert_eq!(spends.len(), 28);
	for s in spends {
		let name = s["name"].as_str().unwrap();
		let output = s["output"].as_str().unwrap();
		let leaf = s["leaf"].as_str().unwrap();
		let mut tx: Transaction = deserialize(&hex(&s["tx"])).unwrap();
		let prevouts: Vec<TxOut> = s["prevouts"].as_array().unwrap().iter().map(|p| deserialize(&hex(p)).unwrap()).collect();
		let idx = s["input_index"].as_u64().unwrap() as usize;
		let expected_sigs = sigs(s);
		let (_, leaves) = ctx.built(output);
		let script = leaves[leaf].clone();

		// A signature over the transaction, for the paths that end in OP_CHECKSIG.
		let checksig = |label: &str| -> Signature {
			let sh = script_spend_sighash(&tx, idx, &prevouts, &script, ctx.genesis).unwrap();
			assert_eq!(sh, h32(&s["sighash"]), "{}: sighash", name);
			let sig = sign_digest(ctx.kp(label), &sh, &ZERO_AUX);
			assert_eq!(sig, expected_sigs[label], "{}: signature by {}", name, label);
			sig
		};
		// A signature over a CSFS message.
		let csfs = |msg: &CsfsMessage, label: &str| -> Signature {
			assert_eq!(msg.digest, h32(&s["digest"]), "{}: digest", name);
			assert_eq!(msg.preimage, hex(&s["message"]), "{}: message", name);
			let sig = sign_digest(ctx.kp(label), &msg.digest, &ZERO_AUX);
			assert_eq!(sig, expected_sigs[label], "{}: signature by {}", name, label);
			sig
		};
		let spent = &prevouts[idx];
		let (asset_in, value_in) = (spent.asset.explicit().unwrap(), spent.value.explicit().unwrap());
		let committed = |m: usize| -> Vec<ExplicitOutput> {
			tx.output[..m].iter().map(|o| ExplicitOutput::from_txout(o).unwrap()).collect()
		};

		let witness: Vec<Vec<u8>> = match (output, leaf) {
			(n, "unroll") => {
				let node = ctx.node(n, false);
				let t = time(&s["t"]);
				assert_eq!(t.script_bytes(), hex(&s["t_bytes"]));
				let signer = s["signer"].as_str().unwrap();
				let sig = csfs(&node.unroll_authorisation(t), signer);
				node.unroll_witness(&sig, t, &ctx.x(signer)).unwrap()
			},
			(n, "sweep") if n.contains("node") || n.starts_with("batch") => {
				let node = ctx.node(n, n.ends_with("burn"));
				node.sweep_witness(&checksig("S"), s["k"].as_u64().unwrap() as u32)
			},
			("entry", "sweep") => ctx.entry("entry", false).sweep_witness(&checksig("S"), s["k"].as_u64().unwrap() as u32),
			("checkpoint", "sweep") => ctx.checkpoint().sweep_witness(&checksig("S"), s["k"].as_u64().unwrap() as u32),
			("entry", "unlock") => ctx.entry("entry", false).unlock_witness(&h32(&s["preimage"])),
			(n, "reclaim") => {
				let node = ctx.node(n, false);
				let rm = node.release_message().unwrap();
				assert_eq!(rm.preimage, hex(&s["release_message"]));
				assert_eq!(rm.digest, h32(&s["release_digest"]));
				let owner_sigs: Vec<Signature> = node.owners().iter().map(|o| {
					let label = ctx.label_of(o);
					let sig = sign_digest(ctx.kp(label), &rm.digest, &ZERO_AUX);
					assert_eq!(sig, expected_sigs[label], "{}: release signature by {}", name, label);
					sig
				}).collect();
				node.reclaim_witness(&checksig("S"), &owner_sigs).unwrap()
			},
			(c, path) if c.starts_with("clock") => {
				let j: usize = c[5..].parse().unwrap();
				let clock = ctx.schedule.clocks().swap_remove(j);
				let script = if path == "roll" { clock.roll.clone().unwrap() } else { clock.release.clone() };
				clock.output.witness(&script, Clock::witness_items(&checksig("S")))
			},
			("r", "spend") => ctx.schedule.r().witness(&ctx.schedule.r_script(), ClockSchedule::r_witness_items(&checksig("S"))),
			("leaf", "exit") => ctx.leaf().exit_witness(&checksig(ctx.label_of(&ctx.leaf().owner))),
			("leaf", "collab") | ("checkpoint", "collab") => {
				let m = s["m"].as_u64().unwrap() as usize;
				let outs = committed(m);
				let msg = if output == "leaf" {
					ctx.leaf().collab_message(asset_in, value_in, &outs).unwrap()
				} else {
					ctx.checkpoint().collab_message(asset_in, value_in, &outs).unwrap()
				};
				let owner = ctx.label_of(&ctx.leaf().owner).to_string();
				let (ss, sa) = (csfs(&msg, "S"), csfs(&msg, &owner));
				if output == "leaf" {
					ctx.leaf().collab_witness(&ss, &sa, m as u8)
				} else {
					ctx.checkpoint().collab_witness(&ss, &sa, m as u8)
				}
			},
			("forfeit", "claim") => ctx.forfeit().claim_witness(&checksig("S"), &h32(&s["preimage"]),
				s["connector_input"].as_u64().unwrap() as u32),
			("forfeit", "refund") => {
				let owner = ctx.label_of(&ctx.forfeit().owner).to_string();
				ctx.forfeit().refund_witness(&checksig(&owner))
			},
			("htlc", path) => {
				let h = ctx.htlc("htlc");
				let owner = ctx.label_of(&h.owner).to_string();
				let out = committed(1).remove(0);
				match path {
					"claim" => {
						let msg = h.message(HtlcPath::Claim, asset_in, value_in, &out).unwrap();
						h.claim_witness(&csfs(&msg, "S"), &h32(&s["preimage"]))
					},
					"claim_both" => {
						let msg = h.message(HtlcPath::ClaimBoth, asset_in, value_in, &out).unwrap();
						h.claim_both_witness(&csfs(&msg, "S"), &csfs(&msg, &owner), &h32(&s["preimage"]))
					},
					"refund_both" => {
						let msg = h.message(HtlcPath::RefundBoth, asset_in, value_in, &out).unwrap();
						h.refund_both_witness(&csfs(&msg, "S"), &csfs(&msg, &owner))
					},
					"refund" => h.refund_witness(&checksig(&owner)),
					p => panic!("unknown htlc path {}", p),
				}
			},
			other => panic!("{}: no witness builder for {:?}", name, other),
		};
		let expected: Vec<Vec<u8>> = s["witness"].as_array().unwrap().iter().map(hex).collect();
		assert_eq!(witness, expected, "{}: witness", name);

		// The transaction with the witness built here verifies, every input.
		tx.input[idx].witness.script_witness = witness;
		verifier.verify_tx(&prevouts, &tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
	}
}
