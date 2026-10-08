//! The server's components on an anchored proof-of-stake regtest chain, with
//! a purse holding asset X (served, listed for fees) and asset Y (neither).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use elements::secp256k1_zkp::Keypair;
use elements::AssetId;
use tokio::sync::broadcast;

use arca_covenant::Chain;
use sequentia_ext::regtest::Regtest;
use server::boards::Boards;
use server::chain::{ChainEvent, ChainSource, FinalityConfig, FinalityService, NodeSource};
use server::nursery::Nursery;
use server::params::{AssetParams, Params};

use super::db::TestDb;
use super::keys::keypair;
use super::node::{self, Purse};

pub const MIN_LEAF: u64 = 1_000;

pub struct Stack {
	pub db: TestDb,
	pub rt: Regtest,
	pub purse: Purse,
	pub x: AssetId,
	pub y: AssetId,
	pub s: Keypair,
	pub chain: Chain,
	pub params: Arc<Params>,
	pub finality: Arc<FinalityService>,
	pub nursery: Arc<Nursery>,
	pub boards: Arc<Boards>,
	rx: broadcast::Receiver<ChainEvent>,
}

impl Stack {
	pub async fn start() -> Stack {
		let db = TestDb::new().await;
		let rt = tokio::task::block_in_place(node::start);
		let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
		let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
		let y = tokio::task::block_in_place(|| purse.issue(&rt, "asset Y", 100_000_000_000));
		node::list_fee_asset(&rt, x, 100_000_000);
		let s = keypair("operator");
		let chain = Chain::new(rt.client().genesis_hash().unwrap());
		let params = Arc::new(Params::new(chain, s.x_only_public_key().0,
			BTreeMap::from([(x, AssetParams { min_leaf: MIN_LEAF, ..Default::default() })])));
		let source = Arc::new(NodeSource::new(rt.client().clone()));
		let finality = FinalityService::new(db.store.clone(), source as Arc<dyn ChainSource>, FinalityConfig::spec()).await.unwrap();
		let rx = finality.subscribe();
		let nursery = Nursery::new(db.store.clone(), finality.clone(), None, Duration::ZERO);
		let boards = Boards::new(db.store.clone(), finality.clone(), nursery.clone(), params.clone(), Duration::from_secs(6 * 3600));
		let mut stack = Stack { db, rt, purse, x, y, s, chain, params, finality, nursery, boards, rx };
		stack.follow().await;
		stack
	}

	/// Syncs the finality service and hands each event, in order, to the
	/// nursery and the boards, as their tasks would.
	pub async fn follow(&mut self) -> Vec<ChainEvent> {
		self.finality.sync().await.unwrap();
		let mut seen = vec![];
		while let Ok(e) = self.rx.try_recv() {
			match &e {
				ChainEvent::Synced { .. } => {
					self.nursery.pass().await.unwrap();
					self.boards.pass().await.unwrap();
				},
				other => {
					self.nursery.on_chain_event(other).await.unwrap();
					self.boards.on_chain_event(other).await.unwrap();
				},
			}
			seen.push(e);
		}
		seen
	}

	pub async fn produce(&mut self) {
		tokio::task::block_in_place(|| self.rt.produce_block()).unwrap();
		self.follow().await;
	}

	/// Buries everything in the chain two Bitcoin blocks deep.
	pub async fn bury(&mut self) {
		tokio::task::block_in_place(|| node::bury(&self.rt));
		self.follow().await;
	}
}
