//! The wallet's copies of the server's digests, the call authentication and
//! the participation id, agree with the server's own for the same parts.

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use elements::{AssetId, BlockHash};

use arca_covenant::{Chain, LeafId, MedianTime, RelativeTime, Template};
use bark::arca::client::{auth_digest, participation_id, Wanted};
use server::participations::OutputRequest;

fn key(label: &str) -> Keypair {
	let s = sha256::Hash::hash(label.as_bytes());
	Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(s.as_byte_array()).unwrap())
}

/// The wallet knows every code the server refuses a request with: a 4xx
/// with a code it does not know would be taken for an answer that says
/// nothing, and the request sent again, where the server said it will not
/// take it. It knows no code the server never answers with, and it takes
/// none of those that say nothing of what was done (a 5xx, or a request to
/// slow down) for a refusal.
#[test]
fn the_wallet_knows_every_refusal_the_server_answers_with() {
	use bark::arca::client::REFUSALS;
	use server::api::REFUSAL_CODES;
	for code in REFUSAL_CODES {
		let status = server::http::status_of(code).as_u16();
		let refusal = (400..500).contains(&status) && *code != "rate_limited";
		assert_eq!(REFUSALS.contains(code), refusal, "the server answers {} with {}; the wallet's REFUSALS {} it", code, status,
			if refusal { "lacks" } else { "has" });
	}
	for code in REFUSALS {
		assert!(REFUSAL_CODES.contains(code), "the wallet knows {}, which the server never answers with", code);
	}
	println!("the wallet takes {} of the server's {} codes for refusals", REFUSALS.len(), REFUSAL_CODES.len());
}

#[test]
fn the_wallets_digests_are_the_servers() {
	let chain = Chain::new(BlockHash::from_str("3ce8ab6c8f9836c0cebca304f3cbed3e824e6c53f4cacd2822f6f8441eed1a3e").unwrap());
	let k = key("owner").x_only_public_key().0;
	for call in ["mailbox_read", "leaf_data"] {
		assert_eq!(auth_digest(&chain, call, &[7; 32], &k), server::auth::auth_digest(&chain, call, &[7; 32], &k));
	}
	let s = key("operator").x_only_public_key().0;
	let a = AssetId::from_slice(&[0x28; 32]).unwrap();
	let d = RelativeTime::from_units(253).unwrap();
	let ids = [LeafId([1; 32]), LeafId([2; 32])];
	for (fees, nb) in [(vec![], None), (vec![(a, 17u64)], Some(MedianTime::from_consensus(1_800_000_000).unwrap()))] {
		let mine = participation_id(&chain, &s, &ids, &[Wanted::Leaf { asset: a, value: 5_000, template: Template::Vtxo1, owner: k,
			owner_nonce: [3; 32], exit_delay: d }], &fees, nb);
		let theirs = server::participations::participation_id(&chain, &s, &ids, &[OutputRequest::Leaf { asset: a, value: 5_000,
			template: Template::Vtxo1, owner: k, owner_nonce: [3; 32], exit_delay: d }], &fees, nb);
		assert_eq!(mine, theirs);
	}
}
