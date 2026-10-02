//! `arca-covenant`: see `bark_fuzz::covenant::witness_parse`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_witness_parse", data, bark_fuzz::covenant::witness_parse);
		});
	}
}
