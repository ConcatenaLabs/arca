//! Authentication challenges: issued at random, used once, expiring.

use std::time::Duration;

use rand::RngCore;

use super::{Store, StoreError};

/// Why a challenge was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
	#[error("the challenge was not issued by this server")]
	Unknown,
	#[error("the challenge has expired")]
	Expired,
	#[error("the challenge has already been used")]
	Used,
}

impl Store {
	/// A fresh challenge valid for `ttl`.
	pub async fn issue_challenge(&self, ttl: Duration) -> Result<[u8; 32], StoreError> {
		let conn = self.conn().await?;
		let mut c = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut c);
		let secs = ttl.as_secs_f64();
		conn.execute(
			"INSERT INTO auth_challenge (challenge, expires_at) VALUES ($1, now() + make_interval(secs => $2))",
			&[&&c[..], &secs],
		).await?;
		Ok(c)
	}

	/// Uses `challenge`: it must have been issued, not yet used, and not
	/// expired. A challenge is used once whatever the outcome of the request
	/// it authenticates.
	pub async fn use_challenge(&self, challenge: &[u8; 32]) -> Result<Result<(), ChallengeError>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(
			"UPDATE auth_challenge SET used_at = now()
			 WHERE challenge = $1 AND used_at IS NULL AND expires_at > now()
			 RETURNING challenge",
			&[&&challenge[..]],
		).await?;
		if row.is_some() {
			return Ok(Ok(()));
		}
		let row = conn.query_opt(
			"SELECT used_at IS NOT NULL, expires_at <= now() FROM auth_challenge WHERE challenge = $1",
			&[&&challenge[..]],
		).await?;
		Ok(Err(match row {
			None => ChallengeError::Unknown,
			Some(r) if r.get::<_, bool>(0) => ChallengeError::Used,
			Some(_) => ChallengeError::Expired,
		}))
	}
}
