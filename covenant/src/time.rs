//! Time-based locks.
//!
//! Sequentia reorganises whenever its Bitcoin anchor does, and a height-based
//! lock drifts against wall-clock time after a rollback, so every lock in Arca
//! is time based: an absolute lock is a median-time value for
//! `OP_CHECKLOCKTIMEVERIFY`, a relative one a count of 512-second units for
//! `OP_CHECKSEQUENCEVERIFY`.

use crate::script::scriptnum;

/// The smallest `nLockTime` that is read as a time rather than a height.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// The BIP68 flag that makes a relative lock count time, in 512-second units.
pub const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;

/// The BIP68 flag that disables a relative lock.
pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;

/// Why a value is not a time lock this protocol accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
	#[error("{0} is a block height, not a median time (times start at 500000000)")]
	Height(u32),
	#[error("a relative delay of zero locks nothing")]
	ZeroDelay,
	#[error("{0} seconds is longer than the longest relative delay (65535 units of 512 seconds)")]
	TooLong(u64),
	#[error("sequence {0:#x} is not a time-based relative lock")]
	NotTimeBased(u32),
}

/// An absolute lock: a median-time value, in seconds since the epoch.
///
/// In a script it is a minimally encoded script number (four bytes until
/// 2038, five after); a transaction that satisfies it sets `nLockTime` to at
/// least this value and a non-final sequence on the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MedianTime(u32);

impl MedianTime {
	/// The latest median time there is.
	pub const MAX: MedianTime = MedianTime(u32::MAX);

	/// A median time; a value below the lock-time threshold is a height and is
	/// refused.
	pub fn from_consensus(t: u32) -> Result<MedianTime, TimeError> {
		if t < LOCKTIME_THRESHOLD {
			return Err(TimeError::Height(t));
		}
		Ok(MedianTime(t))
	}

	/// The value as `nLockTime` holds it.
	pub fn to_consensus_u32(self) -> u32 {
		self.0
	}

	/// The bytes of the script number: what a script pushes, and what the
	/// unroll authorisation hashes.
	pub fn script_bytes(self) -> Vec<u8> {
		scriptnum(self.0 as i64)
	}
}

/// A relative lock in 512-second units, as `OP_CHECKSEQUENCEVERIFY` and the
/// input's sequence carry it (`units | 1 << 22`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeTime(u16);

impl RelativeTime {
	/// The shortest relative lock of at least `seconds`.
	pub fn from_seconds_ceil(seconds: u64) -> Result<RelativeTime, TimeError> {
		let units = seconds.div_ceil(512);
		if units == 0 {
			return Err(TimeError::ZeroDelay);
		}
		let units = u16::try_from(units).map_err(|_| TimeError::TooLong(seconds))?;
		Ok(RelativeTime(units))
	}

	/// A relative lock of `units` of 512 seconds.
	pub fn from_units(units: u16) -> Result<RelativeTime, TimeError> {
		if units == 0 {
			return Err(TimeError::ZeroDelay);
		}
		Ok(RelativeTime(units))
	}

	/// The lock a sequence number or CSV operand encodes. Only the time flag
	/// and the unit count may be set.
	pub fn from_sequence(sequence: u32) -> Result<RelativeTime, TimeError> {
		if sequence & !(SEQUENCE_TYPE_FLAG | 0xffff) != 0 || sequence & SEQUENCE_TYPE_FLAG == 0 {
			return Err(TimeError::NotTimeBased(sequence));
		}
		RelativeTime::from_units((sequence & 0xffff) as u16)
	}

	/// The number of 512-second units.
	pub fn units(self) -> u16 {
		self.0
	}

	/// The length of the lock in seconds.
	pub fn seconds(self) -> u64 {
		u64::from(self.0) * 512
	}

	/// The CSV operand, and the sequence an input sets to satisfy it.
	pub fn to_sequence(self) -> u32 {
		SEQUENCE_TYPE_FLAG | u32::from(self.0)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn thirty_six_hours() {
		// The specification's exit delay and notice: 0x4000fe, a 3-byte push.
		let w = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
		assert_eq!(w.to_sequence(), 0x4000fe);
		assert_eq!(scriptnum(w.to_sequence() as i64), vec![0xfe, 0x00, 0x40]);
		assert_eq!(RelativeTime::from_sequence(0x4000fe), Ok(w));
	}

	#[test]
	fn refusals() {
		assert_eq!(MedianTime::from_consensus(499_999_999), Err(TimeError::Height(499_999_999)));
		assert_eq!(RelativeTime::from_seconds_ceil(0), Err(TimeError::ZeroDelay));
		assert!(RelativeTime::from_seconds_ceil(65535 * 512).is_ok());
		assert!(RelativeTime::from_seconds_ceil(65535 * 512 + 1).is_err());
		assert!(RelativeTime::from_sequence(144).is_err()); // a height-based lock
		assert!(RelativeTime::from_sequence(SEQUENCE_DISABLE_FLAG | SEQUENCE_TYPE_FLAG | 5).is_err());
		assert!(RelativeTime::from_sequence(SEQUENCE_TYPE_FLAG).is_err());
	}

	#[test]
	fn script_number_of_a_time() {
		// 1790974888 pushes as a8 1b c0 6a (T18's first expiry).
		assert_eq!(MedianTime::from_consensus(1790974888).unwrap().script_bytes(), vec![0xa8, 0x1b, 0xc0, 0x6a]);
		// After 2038 the top bit is set and a fifth byte keeps the number positive.
		assert_eq!(MedianTime::from_consensus(0x8000_0000).unwrap().script_bytes(), vec![0, 0, 0, 0x80, 0]);
	}
}
