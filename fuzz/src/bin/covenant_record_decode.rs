//! `arca-covenant`: see `bark_fuzz::covenant::record_decode`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_record_decode", data, bark_fuzz::covenant::record_decode);
		});
	}
}
