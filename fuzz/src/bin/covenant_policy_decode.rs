//! `arca-covenant`: see `bark_fuzz::covenant::policy_decode`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_policy_decode", data, bark_fuzz::covenant::policy_decode);
		});
	}
}
