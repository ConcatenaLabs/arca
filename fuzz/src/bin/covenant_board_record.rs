//! `arca-covenant`: see `bark_fuzz::covenant::board_record`.

use honggfuzz::fuzz;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("covenant_board_record", data, bark_fuzz::covenant::board_record);
		});
	}
}
