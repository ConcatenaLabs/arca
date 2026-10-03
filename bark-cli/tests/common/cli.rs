//! The `arca` binary, run as a user runs it: one process per command, its
//! JSON read back.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

pub struct Arca {
	pub name: String,
	pub dir: PathBuf,
}

impl Arca {
	pub fn new(name: &str) -> Arca {
		let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("arca-cli-wallet-{}-{}", std::process::id(), name));
		let _ = std::fs::remove_dir_all(&dir);
		Arca { name: name.into(), dir }
	}

	/// Runs `arca` with `args`: whether it succeeded, and its JSON.
	pub fn run(&self, args: &[&str]) -> (bool, Value) {
		let out = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca"))
			.arg("--datadir").arg(&self.dir).args(args).output().expect("run arca"));
		let json: Value = serde_json::from_slice(&out.stdout)
			.unwrap_or_else(|e| panic!("{} {:?}: not JSON ({}): {}\n{}", self.name, args, e, String::from_utf8_lossy(&out.stdout),
				String::from_utf8_lossy(&out.stderr)));
		let stderr = String::from_utf8_lossy(&out.stderr);
		if !stderr.trim().is_empty() {
			println!("  [{} stderr] {}", self.name, stderr.trim());
		}
		(out.status.success(), json)
	}

	/// Runs `arca`, which must succeed; prints and returns its JSON.
	pub fn ok(&self, args: &[&str]) -> Value {
		let (ok, v) = self.run(args);
		let shown: Vec<&str> = args.iter().map(|a| if a.len() > 40 { &a[..40] } else { a }).collect();
		assert!(ok, "{} arca {:?} failed: {}", self.name, shown, v);
		println!("{} $ arca {}\n{}", self.name, shown.join(" "), serde_json::to_string(&v).unwrap());
		v
	}

	/// Runs `arca`, which must refuse with a message holding `why`; prints the
	/// refusal and returns its message.
	pub fn refused(&self, args: &[&str], why: &str) -> String {
		let (ok, v) = self.run(args);
		let shown: Vec<&str> = args.iter().map(|a| if a.len() > 40 { &a[..40] } else { a }).collect();
		assert!(!ok, "{} arca {:?} succeeded, and should have been refused ({}): {}", self.name, shown, why, v);
		let msg = v["error"]["message"].as_str().unwrap_or("").to_string();
		assert!(msg.contains(why), "{} arca {:?}: refused for another reason than {:?}: {}", self.name, shown, why, msg);
		println!("{} $ arca {}\n  REFUSED: {}", self.name, shown.join(" "), msg);
		msg
	}
}
