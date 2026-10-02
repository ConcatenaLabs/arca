//! A throwaway Sequentia regtest node for the agreement tests.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// A `sequentiad` on a fresh `elementsregtest` chain in its own data
/// directory, stopped and deleted on drop.
pub struct Node {
	child: Child,
	dir: PathBuf,
	url: String,
}

#[derive(Debug)]
pub struct RpcError {
	pub code: i64,
	pub message: String,
}

fn free_port() -> u16 {
	TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Node {
	/// Starts the node named by `SEQUENTIAD_EXEC`, with `extra` arguments.
	pub fn start(name: &str, extra: &[&str]) -> Node {
		let exe = std::env::var("SEQUENTIAD_EXEC").expect(
			"SEQUENTIAD_EXEC must name a sequentiad binary; these tests run against a regtest node",
		);
		let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
			.join(format!("{}-{}", name, std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let rpc_port = free_port();
		let mut args = vec![
			"-chain=elementsregtest".to_string(),
			format!("-datadir={}", dir.display()),
			format!("-rpcport={}", rpc_port),
			format!("-port={}", free_port()),
			"-listen=0".into(), "-server".into(), "-printtoconsole=0".into(),
			"-rpcuser=arca".into(), "-rpcpassword=arca".into(),
			"-disablewallet".into(), "-txindex=1".into(),
			// the prototype's chain: free coins at an OP_TRUE output in the
			// genesis block, transparent addresses, fees in any accepted asset
			"-initialfreecoins=2100000000000000".into(),
			"-con_default_blinded_addresses=0".into(),
			"-validatepegin=0".into(),
			"-con_parent_chain_signblockscript=51".into(),
			"-con_any_asset_fees=1".into(),
			// Simplicity is off on a custom chain unless activated
			"-evbparams=simplicity:-1:::".into(),
		];
		args.extend(extra.iter().map(|s| s.to_string()));
		let child = Command::new(&exe).args(&args)
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().unwrap_or_else(|e| panic!("cannot start {}: {}", exe, e));
		let node = Node { child, dir, url: format!("http://127.0.0.1:{}/", rpc_port) };
		let start = Instant::now();
		loop {
			match node.call("getblockchaininfo", json!([])) {
				Ok(_) => break,
				Err(_) if start.elapsed() < Duration::from_secs(60) => {
					std::thread::sleep(Duration::from_millis(200));
				},
				Err(e) => panic!("node did not answer within 60 s: {:?}", e),
			}
		}
		node
	}

	pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
		let body = json!({"jsonrpc": "1.0", "id": "arca", "method": method, "params": params});
		let resp = minreq::post(&self.url)
			.with_header("Authorization", "Basic YXJjYTphcmNh") // arca:arca
			.with_header("Content-Type", "application/json")
			.with_body(body.to_string())
			.with_timeout(120)
			.send()
			.map_err(|e| RpcError { code: -1, message: format!("transport: {}", e) })?;
		let v: Value = serde_json::from_str(resp.as_str().unwrap_or(""))
			.map_err(|e| RpcError { code: -1, message: format!("HTTP {}: {}", resp.status_code, e) })?;
		if !v["error"].is_null() {
			return Err(RpcError {
				code: v["error"]["code"].as_i64().unwrap_or(0),
				message: v["error"]["message"].as_str().unwrap_or("").to_string(),
			});
		}
		Ok(v["result"].clone())
	}

	pub fn rpc(&self, method: &str, params: Value) -> Value {
		self.call(method, params.clone())
			.unwrap_or_else(|e| panic!("{} {} failed: {:?}", method, params, e))
	}
}

impl Drop for Node {
	fn drop(&mut self) {
		let _ = self.call("stop", json!([]));
		let start = Instant::now();
		while start.elapsed() < Duration::from_secs(30) {
			if let Ok(Some(_)) = self.child.try_wait() {
				break;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}
