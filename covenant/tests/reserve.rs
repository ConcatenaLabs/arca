//! The reserves of a batch: sized by one function for the builder and for a
//! wallet's check, and judged by a wallet whose floor moved since the build.
//!
//! The operator builds every reserve at four times its relay floor in the
//! batch asset when it builds the round; a wallet checks the new leaf later,
//! often at another node, at the floor it reads then. Trees of one to sixteen
//! leaves in each of three assets of very different floors are built, and every
//! node and entry on every leaf's path is sized again from the record alone;
//! then the record is checked at floors above the build's.

mod common;

use elements::hashes::Hash;
use elements::AssetId;

use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;
use common::*;
use common::net::delay;
use common::round::spec;

const NOW: u32 = 1_700_000_000;
const DAY: u32 = 86_400;

fn tree(batch_asset: AssetId, floor: u64, n: usize, delegated: bool) -> Tree {
	let s = xonly(&keypair("S"));
	let schedule = ClockSchedule::new_unchecked(asset("reserve token"), s, delay(),
		vec![MedianTime::from_consensus(NOW + 28 * DAY).unwrap(), MedianTime::from_consensus(NOW + 56 * DAY).unwrap()]).unwrap();
	let leaves: Vec<LeafSpec> = (0..n).map(|i| {
		let label = format!("reserve {} {} {}", batch_asset, n, i);
		spec(&keypair(&label), &label, 10_000_000, label32(&format!("{} unlock", label)))
	}).collect();
	Tree::build(TreeParams {
		asset: batch_asset, chain: Chain::new(elements::BlockHash::from_byte_array(label32("reserve chain"))), schedule, burn: false,
		delegated_reclaim: delegated, radix: 4, reserve: ReserveRule::FeeRate { floor_per_kvb: floor, multiple: 4 }, min_leaf: 1,
	}, &leaves).unwrap()
}

fn policy(t: &Tree, floor_per_kvb: u64, multiple: u64) -> WalletPolicy {
	WalletPolicy {
		min_reserve: ReserveFloor::FeeRate { floor_per_kvb, multiple },
		..WalletPolicy::new(t.params().chain, t.params().schedule.operator, MedianTime::from_consensus(NOW).unwrap())
	}
}

/// Three assets as the testnet values them: one at the reference unit's
/// floor, one ten times cheaper, one worth a hundred times more.
fn assets() -> [(AssetId, u64); 3] {
	[(asset("reserve A"), 100), (asset("reserve B"), 571), (asset("reserve C"), 1)]
}

#[test]
fn the_builder_and_the_wallets_check_size_every_reserve_alike() {
	let mut checked = 0;
	for (asset, floor) in assets() {
		for n in 1..=16 {
			for delegated in [false, true] {
				let t = tree(asset, floor, n, delegated);
				for i in 0..n {
					let record = t.record(i);
					let branch = record.branch().unwrap();
					for (level, node) in branch.nodes.iter().enumerate() {
						assert_eq!(node.reserve, node.fee_rate_reserve(floor, 4), "{} leaves, leaf {}, level {}", n, i, level);
						checked += 1;
					}
					assert_eq!(record.entry_reserve, branch.entry_fee_rate_reserve(floor, 4), "{} leaves, leaf {}: the entry", n, i);
					// At the build's own floor, the operator's multiple and the
					// wallet's both accept.
					assert_eq!(policy(&t, floor, 4).check(&record), Ok(()));
					assert_eq!(policy(&t, floor, 1).check(&record), Ok(()));
				}
			}
		}
	}
	println!("{} node reserves sized alike by the builder and the check", checked);
}

#[test]
fn a_floor_that_rose_since_the_build_is_judged_by_what_the_reserves_pay_now() {
	for (asset, floor) in assets() {
		let mut old_refusals = 0;
		for n in 1..=16 {
			let t = tree(asset, floor, n, true);
			for i in 0..n {
				let record = t.record(i);
				// The floor up by about one percent, as on the testnet between
				// a round's build and a wallet's check (571 to 575).
				let moved = floor + floor.div_ceil(100);
				// Four times the floor now: what the wallet asked. One atom of
				// rise is enough for it to refuse an honest tree.
				if policy(&t, moved, 4).check(&record).is_err() {
					old_refusals += 1;
				}
				// Once the floor now: accepted up to four times the build's.
				for f in [floor, moved, 2 * floor, 4 * floor] {
					assert_eq!(policy(&t, f, 1).check(&record), Ok(()), "{} leaves, leaf {}, built at {}, checked at {}", n, i, floor, f);
				}
				// Far past what the reserves pay (a fall of the asset's rate
				// to a twentieth): refused, naming the reserve.
				match policy(&t, 20 * floor, 1).check(&record) {
					Err(RecordError::NodeReserve { .. } | RecordError::EntryReserve { .. }) => {},
					other => panic!("{} leaves, leaf {}, built at {}, checked at {}: {:?}", n, i, floor, 20 * floor, other),
				}
			}
		}
		// At a floor of 1 a one-atom rise doubles it, and at 571 the refusal
		// is the testnet's: the rule of four times a fresh reading refuses.
		assert!(old_refusals > 0, "asset at floor {}: the old rule refused nothing", floor);
		println!("floor {}: the rule of four times the floor now refused {} of 136 honest leaves after a rise of one percent", floor,
			old_refusals);
	}
}
