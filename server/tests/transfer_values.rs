//! A coin's id and its checkpoints' values (review R7e, F6). A coin made by
//! a transfer is named by its inputs' ids, their checkpoints' programs and
//! the outputs, not by the checkpoints' values: the same transfer with
//! other checkpoint values would make coins of the same ids. The operator
//! co-signs one checkpoint value for a coin, so at most one such record of
//! a coin ever carries its signatures: the same transfer asked again with
//! another checkpoint value is refused, and the signer's record holds one
//! spend under the coin's salt.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use arca_covenant::sign::sign_digest;
use arca_covenant::{ExplicitOutput, TransferPlan};
use common::client::{new_leaf, random32, transfer_body};
use common::flow::Coin;
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start};

#[tokio::test(flavor = "multi_thread")]
async fn one_transfer_with_other_checkpoint_values_is_refused() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("V A");
	let (held, tx) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held, bases: vec![tx] };
	let v = ca.valid(&r);
	let (b_leaf, _) = new_leaf(&keypair("V B"));
	let (a2_leaf, _) = new_leaf(&keypair("V A2"));
	let kept = v.value - 2_000;
	let outputs = [(x, 600_000, b_leaf), (x, kept - 600_000 - 2_000, a2_leaf)];
	let entries_before = r.signer_entries().await.len();
	let first = r.http.post("cosign_transfer", &transfer_body(&[(&ca.held, v.clone(), kept)], &outputs, xonly(&r.s), r.chain)).ok();
	println!("V the transfer, checkpoint value {}: {}", kept, first["transfer_id"]);
	// The same inputs and outputs, another checkpoint value: the coins it
	// makes would carry the same ids.
	let again = r.http.post("cosign_transfer", &transfer_body(&[(&ca.held, v.clone(), kept - 1)], &outputs, xonly(&r.s), r.chain));
	let (code, message) = again.refusal();
	println!("V the same transfer, checkpoint value {}: {} {}: {}", kept - 1, again.status, code, message);
	assert!(again.status >= 400 && again.json["transfer_id"].is_null(), "{}", again.json);
	let entries = r.signer_entries().await;
	let salt = v.leaf.salt;
	let under: Vec<_> = entries.iter().filter(|e| e.salt == salt).collect();
	println!("V the signer's record: {} entries before, {} after; {} under the coin's salt", entries_before, entries.len(), under.len());
	assert_eq!(under.len(), 1, "one spend under the coin's salt");
	// The signer itself, asked for the other value's checkpoint with the
	// owner's signature over it (as a server whose database lost the first
	// transfer would ask), refuses: one spend under a salt.
	let plan = TransferPlan {
		inputs: vec![(v.clone(), kept - 1)],
		outputs: outputs.iter().map(|(a, val, l)| ExplicitOutput::new(*a, *val, l.policy(xonly(&r.s), r.chain).script_pubkey())).collect(),
	};
	let sig = sign_digest(&a, &plan.checkpoint_message(0).unwrap().digest, &random32());
	let cp_out = ExplicitOutput::new(v.asset, kept - 1, v.checkpoint().script_pubkey());
	let client = server::signer::SignerClient::new(&r.signer.socket);
	let refused = client.rebind(&xonly(&a), &sig, &salt, v.asset, v.value, &[cp_out]).await;
	let why = refused.err().map(|e| e.to_string()).unwrap_or_default();
	println!("V the signer, asked for the checkpoint at value {}: {}", kept - 1, why);
	assert!(why.contains("already_signed"), "{}", why);
	assert_eq!(r.signer_entries().await.iter().filter(|e| e.salt == salt).count(), 1);
}
