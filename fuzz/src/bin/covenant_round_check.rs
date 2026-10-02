//! `arca-covenant`: see `bark_fuzz::covenant::round_check`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_round_check", data, bark_fuzz::covenant::round_check);
		});
	}
}
