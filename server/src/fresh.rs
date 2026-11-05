//! A value read from something that can be slow (the node, the signer, the
//! database), kept for readers that must not wait on it: `info`, which every
//! wallet, maker and tool reads before it acts.
//!
//! A reader is handed the value held at once. When it is older than the
//! reader allows, that reader is also handed the turn to read it again, in
//! the background, and the next readers are handed the same value until the
//! new one is put. Only the first reader, before anything was read, waits on
//! the read. So a node that takes seconds to answer, or a table held by a
//! long write, makes the value older, never the reader slower.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a read handed out may run before another reader is handed the
/// turn again: a read that hangs, or a task that ended without putting
/// anything, does not freeze the value for good.
pub const READ_GIVE_UP: Duration = Duration::from_secs(60);

/// A value kept for readers that must not wait on its read.
pub struct Fresh<T> {
	state: Mutex<State<T>>,
}

struct State<T> {
	/// The value, and when it was read.
	value: Option<(Instant, T)>,
	/// When a reader was handed the turn to read it again, while that read
	/// runs.
	reading: Option<Instant>,
}

/// What a reader is handed ([`Fresh::turn`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Turn<T> {
	/// The value, read within the age asked.
	Fresh(T),
	/// The value, older than asked: this reader reads it again, in the
	/// background, and puts what it read ([`Fresh::put`]).
	Stale(T),
	/// The value, older than asked, while another reader reads it again.
	Reading(T),
	/// Nothing was read yet, or the value was dropped: this reader reads it
	/// and puts it.
	Empty,
}

impl<T: Clone> Default for Fresh<T> {
	fn default() -> Self {
		Fresh::new()
	}
}

impl<T: Clone> Fresh<T> {
	pub fn new() -> Fresh<T> {
		Fresh { state: Mutex::new(State { value: None, reading: None }) }
	}

	fn state(&self) -> std::sync::MutexGuard<'_, State<T>> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// What a reader that allows a value up to `max_age` old is handed.
	pub fn turn(&self, max_age: Duration) -> Turn<T> {
		let mut s = self.state();
		let Some((at, v)) = s.value.as_ref() else { return Turn::Empty };
		if at.elapsed() < max_age {
			return Turn::Fresh(v.clone());
		}
		let v = v.clone();
		match s.reading {
			Some(since) if since.elapsed() < READ_GIVE_UP => Turn::Reading(v),
			_ => {
				s.reading = Some(Instant::now());
				Turn::Stale(v)
			},
		}
	}

	/// The value held, whatever its age, without a turn to read it.
	pub fn peek(&self) -> Option<T> {
		self.state().value.as_ref().map(|(_, v)| v.clone())
	}

	/// Keeps `v`, read now, and ends the read handed out.
	pub fn put(&self, v: T) {
		let mut s = self.state();
		s.value = Some((Instant::now(), v));
		s.reading = None;
	}

	/// Drops the value: the next reader reads it ([`Turn::Empty`]).
	pub fn clear(&self) {
		let mut s = self.state();
		s.value = None;
		s.reading = None;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_stale_value_is_read_again_by_one_reader_alone() {
		let f: Fresh<u32> = Fresh::new();
		assert_eq!(f.turn(Duration::from_secs(5)), Turn::Empty, "nothing read yet");
		f.put(1);
		assert_eq!(f.turn(Duration::from_secs(5)), Turn::Fresh(1));
		assert_eq!(f.turn(Duration::ZERO), Turn::Stale(1), "the first reader past the age reads it again");
		assert_eq!(f.turn(Duration::ZERO), Turn::Reading(1), "the next ones are handed the same value meanwhile");
		f.put(2);
		assert_eq!(f.turn(Duration::from_secs(5)), Turn::Fresh(2));
		assert_eq!(f.turn(Duration::ZERO), Turn::Stale(2), "a new turn once the read is put");
		assert_eq!(f.peek(), Some(2));
		f.clear();
		assert_eq!(f.turn(Duration::ZERO), Turn::Empty, "a dropped value is read by the next reader");
		assert_eq!(f.peek(), None);
	}
}
