//! A proxy between a wallet and the server that can rewrite any answer the
//! server gives, or hold a call unanswered: an operator lying to one wallet,
//! or gone mid-call. It logs every call as the wallet saw it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// A change made to every published tree passing through.
pub type Tamper = fn(&mut Value);

/// Called with the call's path, the request's body, the server's status and
/// its answer; may rewrite the answer, and return another status.
pub type Rewrite = Arc<dyn Fn(&str, &Value, u16, &mut Value) -> Option<u16> + Send + Sync>;

/// One call: its path, the request, the status and the answer the wallet saw
/// (status 0 for a call held unanswered).
pub type Logged = (String, Value, u16, Value);

#[derive(Clone)]
pub struct Proxy {
	pub url: String,
	rewrite: Arc<Mutex<Option<Rewrite>>>,
	log: Arc<Mutex<Vec<Logged>>>,
	/// Paths whose requests are held unanswered past the wallet's timeout and
	/// never forwarded.
	hold: Arc<Mutex<Vec<String>>>,
}

fn serve(mut s: TcpStream, target: &str, p: &Proxy) -> std::io::Result<()> {
	let mut r = BufReader::new(s.try_clone()?);
	let mut line = String::new();
	r.read_line(&mut line)?;
	let mut parts = line.split_whitespace();
	let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
	let mut len = 0usize;
	loop {
		let mut h = String::new();
		r.read_line(&mut h)?;
		if h.trim().is_empty() {
			break;
		}
		if let Some((k, v)) = h.split_once(':') {
			if k.eq_ignore_ascii_case("content-length") {
				len = v.trim().parse().unwrap_or(0);
			}
		}
	}
	let mut body = vec![0u8; len];
	r.read_exact(&mut body)?;
	let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
	if p.hold.lock().unwrap().contains(&path) {
		p.log.lock().unwrap().push((path.clone(), req, 0, Value::Null));
		std::thread::sleep(Duration::from_secs(75));
		return Ok(());
	}
	let url = format!("{}{}", target, path);
	let resp = if method == "GET" { minreq::get(url).send() } else {
		minreq::post(url).with_header("Content-Type", "application/json").with_body(body).send()
	};
	let (mut status, text) = match resp {
		Ok(r) => (r.status_code as u16, r.as_str().unwrap_or("").to_string()),
		Err(e) => (502, json!({"error": {"code": "proxy", "message": e.to_string()}}).to_string()),
	};
	let mut v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
	let f = p.rewrite.lock().unwrap().clone();
	if let Some(f) = f {
		if let Some(st) = f(&path, &req, status, &mut v) {
			status = st;
		}
	}
	p.log.lock().unwrap().push((path.clone(), req, status, v.clone()));
	let text = v.to_string();
	write!(s, "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, text.len(), text)?;
	s.flush()
}

impl Proxy {
	pub fn start(target: &str) -> Proxy {
		let l = TcpListener::bind("127.0.0.1:0").unwrap();
		let p = Proxy {
			url: format!("http://{}", l.local_addr().unwrap()),
			rewrite: Arc::new(Mutex::new(None)),
			log: Arc::new(Mutex::new(vec![])),
			hold: Arc::new(Mutex::new(vec![])),
		};
		let (q, target) = (p.clone(), target.to_string());
		std::thread::spawn(move || {
			for s in l.incoming().flatten() {
				let (q, target) = (q.clone(), target.clone());
				std::thread::spawn(move || {
					let _ = serve(s, &target, &q);
				});
			}
		});
		p
	}

	/// Rewrites every published tree with `t`, or nothing.
	pub fn set(&self, t: Option<Tamper>) {
		self.rewrite(t.map(|t| -> Rewrite {
			Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
				if path == "/v1/tree" && status == 200 {
					t(v);
				}
				None
			})
		}));
	}

	/// Rewrites answers with `f`, or nothing.
	pub fn rewrite(&self, f: Option<Rewrite>) {
		*self.rewrite.lock().unwrap() = f;
	}

	/// Holds every call to `path` unanswered from now on.
	pub fn hold(&self, path: &str) {
		self.hold.lock().unwrap().push(path.to_string());
	}

	/// Every call so far.
	pub fn calls(&self) -> Vec<Logged> {
		self.log.lock().unwrap().clone()
	}

	/// How many calls to `path` the wallet made.
	pub fn count(&self, path: &str) -> usize {
		self.log.lock().unwrap().iter().filter(|(p, ..)| p == path).count()
	}

	/// The last call to `path`: its request, status and answer.
	pub fn last(&self, path: &str) -> Option<(Value, u16, Value)> {
		self.log.lock().unwrap().iter().rev().find(|(p, ..)| p == path).map(|(_, q, s, a)| (q.clone(), *s, a.clone()))
	}
}
