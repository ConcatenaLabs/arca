//! `arca-covenant`: see `bark_fuzz::covenant::record_json`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_record_json", data, bark_fuzz::covenant::record_json);
		});
	}
}
