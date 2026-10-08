//! What the protocol's client code needs from the machine it runs on: one HTTP
//! request at a time, and a pause.
//!
//! A native program needs nothing here: the node client speaks HTTP with
//! `minreq` (the default `minreq` feature) and a pause is the thread's sleep.
//! A program built for `wasm32` in a browser has neither, so it registers its
//! own once, before the first call, with [`set_platform`]: a web wallet's
//! worker sends each request as a synchronous `XMLHttpRequest`, which a
//! dedicated worker may block on. The calls stay blocking either way, so the
//! wallet's code is the same on both.

use std::sync::OnceLock;
use std::time::Duration;

/// One HTTP request.
pub struct Request<'a> {
	/// `GET` or `POST`.
	pub method: &'a str,
	pub url: &'a str,
	pub headers: Vec<(&'a str, String)>,
	pub body: Option<&'a str>,
	/// How long the request may take, in seconds.
	pub timeout_secs: u64,
}

/// What came back: the HTTP status and the body as text.
pub struct Response {
	pub status: i32,
	pub body: String,
}

/// The machine's HTTP and its pause, as a program registers them.
pub trait Platform: Send + Sync {
	/// Sends `request` and waits for the whole answer. An error is a request
	/// that got no HTTP answer at all (no connection, a timeout, a refusal by
	/// the browser), in words.
	fn http(&self, request: &Request) -> Result<Response, String>;
	/// Waits `d` before returning.
	fn sleep(&self, d: Duration);
}

static PLATFORM: OnceLock<Box<dyn Platform>> = OnceLock::new();

/// Registers the platform. Only the first registration counts; a later one is
/// refused, so nothing can swap the transport under a running wallet.
pub fn set_platform(p: Box<dyn Platform>) -> Result<(), &'static str> {
	PLATFORM.set(p).map_err(|_| "a platform is registered already")
}

/// Sends `request` through the registered platform; without one, the request
/// is refused, never sent another way.
pub fn http(request: &Request) -> Result<Response, String> {
	match PLATFORM.get() {
		Some(p) => p.http(request),
		None => Err("no HTTP transport is registered (sequentia_ext::platform::set_platform)".into()),
	}
}

/// Waits `d`: through the registered platform, or the thread's sleep when
/// none is registered.
pub fn sleep(d: Duration) {
	match PLATFORM.get() {
		Some(p) => p.sleep(d),
		None => std::thread::sleep(d),
	}
}
