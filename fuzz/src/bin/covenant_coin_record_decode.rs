//! `arca-covenant`: see `bark_fuzz::covenant::coin_record_decode`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_coin_record_decode", data, bark_fuzz::covenant::coin_record_decode);
		});
	}
}
