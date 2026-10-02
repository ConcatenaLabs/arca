//! The `arca-covenant` fuzz bodies under libFuzzer, on a stable toolchain.
//!
//! The first byte picks the body and the rest is its input; with
//! `ARCA_FUZZ_BODY` set to `policy`, `witness`, `round`, `record` or
//! `record_json`, every input goes to that body whole. A panic is a crash: unlike the honggfuzz targets, nothing
//! here is contained. See README.md for the build and run commands.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn body() -> Option<u8> {
	static BODY: OnceLock<Option<u8>> = OnceLock::new();
	*BODY.get_or_init(|| match std::env::var("ARCA_FUZZ_BODY").as_deref() {
		Ok("policy") => Some(0),
		Ok("witness") => Some(1),
		Ok("round") => Some(2),
		Ok("record") => Some(3),
		Ok("record_json") => Some(4),
		Ok(other) => panic!("ARCA_FUZZ_BODY must be policy, witness, round, record or record_json, not {:?}", other),
		Err(_) => None,
	})
}

fuzz_target!(|data: &[u8]| {
	let (which, input) = match body() {
		Some(b) => (b, data),
		None => match data.split_first() {
			Some((&b, rest)) => (b % 5, rest),
			None => return,
		},
	};
	match which {
		0 => bark_fuzz::covenant::policy_decode(input),
		1 => bark_fuzz::covenant::witness_parse(input),
		2 => bark_fuzz::covenant::round_check(input),
		3 => bark_fuzz::covenant::record_decode(input),
		_ => bark_fuzz::covenant::record_json(input),
	}
});
