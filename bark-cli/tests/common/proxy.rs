//! A proxy between a wallet and the server that can rewrite what the server
//! publishes: an operator lying to one wallet.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::Value;

/// A change made to every published tree passing through.
pub type Tamper = fn(&mut Value);

pub struct Proxy {
	pub url: String,
	pub tamper: Arc<Mutex<Option<Tamper>>>,
}

fn serve(mut s: TcpStream, target: &str, tamper: &Arc<Mutex<Option<Tamper>>>) -> std::io::Result<()> {
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
	let url = format!("{}{}", target, path);
	let resp = if method == "GET" { minreq::get(url).send() } else {
		minreq::post(url).with_header("Content-Type", "application/json").with_body(body).send()
	};
	let (status, mut text) = match resp {
		Ok(r) => (r.status_code, r.as_str().unwrap_or("").to_string()),
		Err(e) => (502, format!("{{\"error\":{{\"code\":\"proxy\",\"message\":\"{}\"}}}}", e)),
	};
	if path == "/v1/tree" && status == 200 {
		if let Some(t) = *tamper.lock().unwrap() {
			let mut v: Value = serde_json::from_str(&text).unwrap();
			t(&mut v);
			text = v.to_string();
		}
	}
	write!(s, "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, text.len(), text)?;
	s.flush()
}

impl Proxy {
	pub fn start(target: &str) -> Proxy {
		let l = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}", l.local_addr().unwrap());
		let tamper: Arc<Mutex<Option<Tamper>>> = Arc::new(Mutex::new(None));
		let (t, target) = (tamper.clone(), target.to_string());
		std::thread::spawn(move || {
			for s in l.incoming().flatten() {
				let _ = serve(s, &target, &t);
			}
		});
		Proxy { url, tamper }
	}

	pub fn set(&self, t: Option<Tamper>) {
		*self.tamper.lock().unwrap() = t;
	}
}
