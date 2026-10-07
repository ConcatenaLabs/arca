//! Every refusal code the server answers with is in `server::api::REFUSAL_CODES`,
//! read from the source itself: each `code()` of the server's refusals and
//! each refusal the HTTP layer makes on its own. A code added without the
//! list fails here, and the wallet's own test compares the list with what it
//! knows (`bark-cli/tests/arca_digests.rs`).

use std::collections::BTreeSet;

/// The quoted words in `text`.
fn literals(text: &str) -> BTreeSet<String> {
	let mut out = BTreeSet::new();
	let mut rest = text;
	while let Some(i) = rest.find('"') {
		let after = &rest[i + 1..];
		let Some(j) = after.find('"') else { break };
		let word = &after[..j];
		if !word.is_empty() && word.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') {
			out.insert(word.to_string());
		}
		rest = &after[j + 1..];
	}
	out
}

/// The codes in the bodies of every `fn code(&self) -> &'static str` of
/// `source`.
fn codes_of(source: &str) -> BTreeSet<String> {
	let mut out = BTreeSet::new();
	let mut rest = source;
	while let Some(i) = rest.find("fn code(&self) -> &'static str {") {
		let body = &rest[i..];
		let end = body.find("\n\t}\n").expect("the function ends");
		out.extend(literals(&body[..end]));
		rest = &body[end..];
	}
	out
}

#[test]
fn every_refusal_code_is_listed() {
	let mut found = BTreeSet::new();
	for src in [
		include_str!("../src/boards.rs"), include_str!("../src/cosign.rs"), include_str!("../src/forfeits.rs"),
		include_str!("../src/participations.rs"),
	] {
		found.extend(codes_of(src));
	}
	let http = include_str!("../src/http.rs");
	let mut rest = http;
	while let Some(i) = rest.find("Refusal::new(StatusCode::") {
		let after = &rest[i..];
		let line = &after[..after.find(')').unwrap_or(after.len())];
		found.extend(literals(line));
		rest = &after[1..];
	}
	found.insert("malformed".into());
	let listed: BTreeSet<String> = server::api::REFUSAL_CODES.iter().map(|c| c.to_string()).collect();
	let missing: Vec<&String> = found.difference(&listed).collect();
	let stale: Vec<&String> = listed.difference(&found).collect();
	println!("{} refusal codes in the source, {} listed", found.len(), listed.len());
	assert!(missing.is_empty(), "codes the server answers with that REFUSAL_CODES lacks: {:?}", missing);
	assert!(stale.is_empty(), "codes REFUSAL_CODES lists that nothing answers with: {:?}", stale);
	// A refusal the request was not taken for is a 4xx; the rest say nothing
	// of what was done.
	for code in server::api::REFUSAL_CODES {
		let status = server::http::status_of(code).as_u16();
		let retry = ["internal", "signer_unavailable", "signer_replaced", "not_synced", "rate_limited"].contains(code);
		assert_eq!((400..500).contains(&status) && *code != "rate_limited", !retry, "{} is answered {}", code, status);
	}
}
