//! The chain types and the node client against an anchored regtest chain.
//!
//! Needs `SEQUENTIAD_EXEC`.

use std::path::PathBuf;
use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::hex::{FromHex, ToHex};
use elements::schnorr::TapTweak;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{Address, AddressParams, LockTime, SchnorrSighashType};
use serde_json::{json, Value as Json};

use sequentia_ext::regtest::{Regtest, OP_TRUE_DESCRIPTOR};
use sequentia_ext::{
	explicit_txout, fee_txout, AssetAmount, AssetId, Block, BlockHeaderExt, OutPoint, Script,
	Transaction, TxIn, TxOutExt,
};

fn workdir(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()))
}

#[test]
fn regtest_node_client() {
	let chain = Regtest::from_env(&workdir("sequentia-ext"), &[]);
	let rpc = chain.client();
	let secp = Secp256k1::new();

	// Chain identity.
	let info = rpc.blockchain_info().unwrap();
	assert_eq!(info.chain, "elementsregtest");
	let genesis = rpc.genesis_hash().unwrap();
	assert_eq!(genesis, rpc.block_hash(0).unwrap());
	let genesis_block = rpc.block(&genesis).unwrap();
	assert_eq!(genesis_block.block_hash(), genesis);
	println!("genesis hash: {}", genesis);

	// The fee whitelist, keyed by asset id.
	let raw_rates: Json = rpc.call("getfeeexchangerates", &[]).unwrap();
	let rates = rpc.fee_exchange_rates().unwrap();
	println!("fee whitelist: node says {}, resolved {:?}", raw_rates, rates);
	assert_eq!(rates.len(), raw_rates.as_object().unwrap().len());
	assert!(!rates.is_empty());

	// The genesis block's free coins sit at an OP_TRUE output.
	let (free, free_vout) = genesis_block.txdata.iter().find_map(|tx| {
		tx.output.iter().position(|o| o.script_pubkey.as_bytes() == [0x51]).map(|i| (tx.clone(), i))
	}).expect("no OP_TRUE output in the genesis block");
	let free_out = free.output[free_vout].clone();
	let funds = free_out.asset_amount().expect("free coins are explicit");
	assert!(rates.contains_key(&funds.asset), "the seeded fee asset is the free coins' asset");

	// Pay a key-path taproot output of our own key, in a block built directly
	// (a bare OP_TRUE spend is valid, not standard).
	let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x42; 32]).unwrap());
	let tweaked = key.tap_tweak(&secp, None);
	let (output_key, _) = tweaked.public_parts();
	let addr = Address::p2tr_tweaked(output_key, None, &AddressParams::ELEMENTS);
	let fund_value = 10_000_000;
	let fund = Transaction {
		version: 2, lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(free.txid(), free_vout as u32), ..Default::default() }],
		output: vec![
			explicit_txout(AssetAmount::new(funds.asset, fund_value), addr.script_pubkey()),
			explicit_txout(AssetAmount::new(funds.asset, funds.amount - fund_value - 10_000), Script::from(vec![0x51])),
			fee_txout(AssetAmount::new(funds.asset, 10_000)),
		],
	};
	rpc.generate_block(OP_TRUE_DESCRIPTOR, &[&fund]).unwrap();
	assert!(rpc.confirmations(&fund.txid()).unwrap() >= 1);

	// An issuance, built by the node: createrawtransaction + rawissueasset,
	// with a denomination other than the default 8.
	let fee = 3_000u64;
	let raw: String = rpc.call("createrawtransaction", &[
		json!([{"txid": fund.txid().to_string(), "vout": 0}]),
		json!([
			{addr.to_string(): (fund_value - fee) as f64 / 1e8, "asset": funds.asset.to_string()},
			{"fee": fee as f64 / 1e8, "fee_asset": funds.asset.to_string()},
		]),
	]).unwrap();
	let issued: Json = rpc.call("rawissueasset", &[json!(raw), json!([{
		"asset_amount": 5, "asset_address": addr.to_string(),
		"blind": false, "denomination": 2,
	}])]).unwrap();
	let unsigned_hex = issued[0]["hex"].as_str().unwrap();
	let new_asset = AssetId::from_str(issued[0]["asset"].as_str().unwrap()).unwrap();
	let unsigned_bytes = Vec::<u8>::from_hex(unsigned_hex).unwrap();
	let mut tx: Transaction = deserialize(&unsigned_bytes).unwrap();
	assert_eq!(serialize(&tx), unsigned_bytes, "the node's unsigned issuance re-encodes byte for byte");
	let issuance = tx.input[0].asset_issuance;
	assert_eq!(issuance.denomination, 2);
	assert_eq!(issuance.amount.explicit(), Some(500_000_000));
	let entropy = elements::issuance::AssetId::generate_asset_entropy(
		tx.input[0].previous_output, elements::issuance::ContractHash::from_byte_array(issuance.asset_entropy));
	assert_eq!(AssetId::from_entropy(entropy), new_asset);
	println!("issuance: asset {}, denomination {}", new_asset, issuance.denomination);

	// Sign the key path and broadcast.
	let prevouts = [fund.output[0].clone()];
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0, &Prevouts::All(&prevouts), SchnorrSighashType::Default, genesis).unwrap();
	let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &tweaked.to_inner());
	tx.input[0].witness.script_witness = vec![sig.as_ref().to_vec()];
	let accept = rpc.test_mempool_accept(&[&tx]).unwrap();
	assert!(accept[0].allowed, "{:?}", accept[0]);
	let txid = rpc.send_raw_transaction(&tx).unwrap();
	assert_eq!(txid, tx.txid());
	let mined = rpc.generate_to_descriptor(1, OP_TRUE_DESCRIPTOR).unwrap();
	assert!(rpc.confirmations(&txid).unwrap() >= 1);
	println!("broadcast {} and mined it in {}", txid, mined[0]);

	// The transaction as the node stores it: byte for byte.
	let stored = rpc.raw_transaction_bytes(&txid).unwrap();
	assert_eq!(stored, serialize(&tx));
	let decoded: Transaction = deserialize(&stored).unwrap();
	assert_eq!(serialize(&decoded), stored);
	assert_eq!(decoded.input[0].asset_issuance.denomination, 2);
	assert_eq!(rpc.raw_transaction(&txid).unwrap(), tx);

	// The block holding it: byte for byte, with its anchor.
	let block_bytes = rpc.block_bytes(&mined[0]).unwrap();
	let block: Block = deserialize(&block_bytes).unwrap();
	assert_eq!(serialize(&block), block_bytes);
	assert_eq!(block.block_hash(), mined[0]);
	assert!(block.txdata.iter().any(|t| t.txid() == txid));
	let header = rpc.block_header(&mined[0]).unwrap();
	assert_eq!(header, block.header);
	let verbose: Json = rpc.call("getblockheader", &[json!(mined[0].to_string())]).unwrap();
	let anchor = header.bitcoin_anchor();
	assert_eq!(anchor.height as u64, verbose["anchorheight"].as_u64().unwrap());
	assert_eq!(anchor.block_hash.to_string(), verbose["anchorhash"].as_str().unwrap());
	assert_eq!(chain.parent.client().block_hash(anchor.height as u64).unwrap().to_string(),
		anchor.block_hash.to_string(), "the anchor is a block of the parent chain");
	println!("block {} ({} bytes, {} txs) anchored to parent block {} at height {}",
		mined[0], block_bytes.len(), block.txdata.len(), anchor.block_hash, anchor.height);
	let _ = block_bytes.to_hex();

	// A refused call reports the node's error.
	match rpc.send_raw_transaction(&tx) {
		Err(sequentia_ext::rpc::Error::Rpc { code, message }) => println!("rebroadcast refused: {} ({})", message, code),
		other => panic!("rebroadcast of a mined transaction: {:?}", other),
	}
}

/// The proof-of-stake chain: every block the committee produces is certified,
/// its anchor follows the parent's tip, a block produced takes the mempool,
/// and a restart without the mempool keeps the chain and empties the mempool.
#[test]
fn regtest_pos_chain() {
	let mut chain = Regtest::start_pos(
		std::path::Path::new(&std::env::var_os("SEQUENTIAD_EXEC").expect("SEQUENTIAD_EXEC")),
		&workdir("sequentia-ext-pos"), &[],
	).unwrap();
	let h1 = chain.produce_block().unwrap();
	// No block without the committee.
	let e = chain.client().generate_to_descriptor(1, OP_TRUE_DESCRIPTOR).unwrap_err();
	assert!(e.to_string().contains("bad-posvrf"), "{}", e);
	println!("a block without the committee: {}", e);
	let header: Json = chain.client().call("getblockheader", &[json!(h1.to_string())]).unwrap();
	assert_eq!(header["height"], 1);
	assert_eq!(header["poscertified"], true);
	let a1 = header["anchorheight"].as_u64().unwrap();

	chain.mine_parent(2).unwrap();
	let made = chain.anchor_to_parent_tip().unwrap();
	let tip = chain.client().block_header(made.last().unwrap()).unwrap();
	assert_eq!(tip.bitcoin_anchor().height as u64, a1 + 2);
	println!("block 1 anchored at {}; tip anchored at {} after {} block(s)", a1, a1 + 2, made.len());

	// The genesis block's free coins, at a bare OP_TRUE, move through the
	// mempool into the next block.
	let genesis = chain.client().genesis_hash().unwrap();
	let block = chain.client().block(&genesis).unwrap();
	let (txid, vout, out) = block.txdata.iter().flat_map(|tx| {
		tx.output.iter().enumerate().map(move |(i, o)| (tx.txid(), i as u32, o.clone()))
	}).find(|(_, _, o)| o.script_pubkey.as_bytes() == [0x51]).unwrap();
	let amount = out.asset_amount().unwrap();
	let tx = Transaction {
		version: 2, lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(txid, vout), ..Default::default() }],
		output: vec![
			explicit_txout(AssetAmount::new(amount.asset, amount.amount - 10_000), Script::from(vec![0x51])),
			fee_txout(AssetAmount::new(amount.asset, 10_000)),
		],
	};
	let spent = chain.client().send_raw_transaction(&tx).unwrap();
	let h = chain.produce_block().unwrap();
	assert!(chain.client().block(&h).unwrap().txdata.iter().any(|t| t.txid() == spent));

	// A transaction left in the mempool is gone after a restart without it.
	let tx2 = Transaction {
		version: 2, lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(spent, 0), ..Default::default() }],
		output: vec![
			explicit_txout(AssetAmount::new(amount.asset, amount.amount - 20_000), Script::from(vec![0x51])),
			fee_txout(AssetAmount::new(amount.asset, 10_000)),
		],
	};
	let waiting = chain.client().send_raw_transaction(&tx2).unwrap();
	let height = chain.client().block_count().unwrap();
	chain.node.restart(&["-persistmempool=0"]).unwrap();
	assert_eq!(chain.client().block_count().unwrap(), height);
	let mempool: Vec<String> = chain.client().call("getrawmempool", &[]).unwrap();
	assert!(!mempool.contains(&waiting.to_string()), "the mempool kept {}", waiting);
	assert_eq!(chain.client().send_raw_transaction(&tx2).unwrap(), waiting);
}

/// An anchor-driven reorganisation: the parent chain orphans the block a
/// Sequentia block is anchored to, and the node disconnects that block and
/// every block above it, certified or not, returns their transactions to the
/// mempool, and builds on the parent's new chain.
#[test]
fn regtest_pos_anchor_reorg() {
	let chain = Regtest::start_pos(
		std::path::Path::new(&std::env::var_os("SEQUENTIAD_EXEC").expect("SEQUENTIAD_EXEC")),
		&workdir("sequentia-ext-anchor-reorg"), &[],
	).unwrap();
	chain.produce_block().unwrap();
	let genesis = chain.client().genesis_hash().unwrap();
	let block = chain.client().block(&genesis).unwrap();
	let (txid, vout, out) = block.txdata.iter().flat_map(|tx| {
		tx.output.iter().enumerate().map(move |(i, o)| (tx.txid(), i as u32, o.clone()))
	}).find(|(_, _, o)| o.script_pubkey.as_bytes() == [0x51]).unwrap();
	let amount = out.asset_amount().unwrap();

	// A parent block of its own for the block that will hold the spend.
	chain.mine_parent(1).unwrap();
	let anchored = chain.anchor_to_parent_tip().unwrap();
	let a = chain.client().block_header(anchored.last().unwrap()).unwrap().bitcoin_anchor();
	let tx = Transaction {
		version: 2, lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(txid, vout), ..Default::default() }],
		output: vec![
			explicit_txout(AssetAmount::new(amount.asset, amount.amount - 10_000), Script::from(vec![0x51])),
			fee_txout(AssetAmount::new(amount.asset, 10_000)),
		],
	};
	let spent = chain.client().send_raw_transaction(&tx).unwrap();
	let holder = chain.produce_block().unwrap();
	let h_holder = chain.client().block_header(&holder).unwrap();
	assert_eq!(h_holder.bitcoin_anchor().height, a.height, "the block holding the spend is anchored to the parent's tip");
	// Buried two parent blocks, so it was final before the reorganisation.
	chain.mine_parent(2).unwrap();
	chain.anchor_to_parent_tip().unwrap();
	let height = chain.client().block_count().unwrap();
	let v: Json = chain.client().call("getrawtransaction", &[json!(spent.to_string()), json!(true)]).unwrap();
	assert_eq!(v["blockhash"], json!(holder.to_string()));

	let orphaned = chain.orphan_parent_from(a.height as u64).unwrap();
	assert_eq!(orphaned[0], a.block_hash);
	let after = chain.client().block_count().unwrap();
	let mempool: Vec<String> = chain.client().call("getrawmempool", &[]).unwrap();
	println!("parent blocks {}..{} orphaned; Sequentia tip {} -> {}; the spend back in the mempool: {}",
		a.height, a.height as usize + orphaned.len() - 1, height, after, mempool.contains(&spent.to_string()));
	assert!(after < h_holder.height as u64, "the block anchored to the orphaned parent block was disconnected");
	assert!(mempool.contains(&spent.to_string()), "the spend returned to the mempool");
	let h = chain.produce_block().unwrap();
	assert_ne!(h, holder);
	assert!(chain.client().block(&h).unwrap().txdata.iter().any(|t| t.txid() == spent), "the spend confirms again");
	let header = chain.client().block_header(&h).unwrap();
	let at: Json = chain.parent.client().call("getblockheader", &[json!(header.bitcoin_anchor().block_hash.to_string())]).unwrap();
	assert!(at["confirmations"].as_i64().unwrap() >= 0, "the new block is anchored in the parent's new chain");
}
