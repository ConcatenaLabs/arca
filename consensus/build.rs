//! Compiles the C shim in `src/shim.cpp` against the headers of a Sequentia
//! node source tree and links it with that tree's consensus library, so the
//! verifier runs the node's own script interpreter.
//!
//! `SEQUENTIA_DIR` names the node checkout. It must have been configured and
//! must contain a built consensus library: `src/.libs/libelementsconsensus.a`
//! and `src/secp256k1/.libs/libsecp256k1.a` (`make -C src libelementsconsensus.la`).

use std::env;
use std::path::PathBuf;

fn main() {
	println!("cargo:rerun-if-env-changed=SEQUENTIA_DIR");
	println!("cargo:rerun-if-changed=src/shim.cpp");

	let dir = env::var_os("SEQUENTIA_DIR").map(PathBuf::from).unwrap_or_else(|| panic!(
		"SEQUENTIA_DIR is not set. arca-consensus links the Sequentia node's consensus \
		library: set SEQUENTIA_DIR to a configured node checkout in which \
		`make -C src libelementsconsensus.la` has run (see consensus/README.md)."
	));
	let src = dir.join("src");
	let consensus = src.join(".libs").join("libelementsconsensus.a");
	let secp = src.join("secp256k1").join(".libs").join("libsecp256k1.a");
	for lib in [&consensus, &secp] {
		if !lib.exists() {
			panic!("{} does not exist: build the node's consensus library first \
				(`make -C src libelementsconsensus.la` in {})", lib.display(), dir.display());
		}
		println!("cargo:rerun-if-changed={}", lib.display());
	}

	let mut build = cc::Build::new();
	build.cpp(true)
		.std("c++17")
		.file("src/shim.cpp")
		.include(&src)
		.include(src.join("secp256k1").join("include"))
		.warnings(false);
	// The node's own objects were compiled with its generated configuration;
	// the shim sees the same one so that no header takes a different branch.
	if src.join("config").join("bitcoin-config.h").exists() {
		build.include(src.join("config")).define("HAVE_CONFIG_H", None);
	}
	build.compile("arca_consensus_shim");

	// Link copies under names of our own. rust-secp256k1 also builds a
	// `libsecp256k1.a` (with prefixed symbols) and puts its directory on the
	// search path first, so `-lsecp256k1` would find that one.
	let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
	std::fs::copy(&consensus, out.join("libsequentia_elementsconsensus.a")).unwrap();
	std::fs::copy(&secp, out.join("libsequentia_secp256k1.a")).unwrap();
	println!("cargo:rustc-link-search=native={}", out.display());
	println!("cargo:rustc-link-lib=static=sequentia_elementsconsensus");
	println!("cargo:rustc-link-lib=static=sequentia_secp256k1");
}
