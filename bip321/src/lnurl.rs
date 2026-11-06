//! LNURL (LUD-01) as a `lightning=` value.
//!
//! BIP 321 defines `lightning=` for BOLT 11 invoices, but Lightning wallets
//! also write an LNURL there: the bech32 encoding (human-readable part
//! `lnurl`) of an `https` URL, typically a LNURL-pay endpoint that lets the
//! payer choose the amount. Such a value is not an invoice, so it is kept as
//! its own payment instruction rather than failing the whole URI.

use std::fmt;
use std::str::FromStr;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::Bech32;

/// The human-readable part of an LNURL.
const LNURL_HRP: &str = "lnurl";

/// An LNURL carried in a `lightning=` parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lnurl {
	/// The bech32 form, in lower case.
	encoded: String,
	/// The URL it encodes.
	url: String,
}

impl Lnurl {
	/// The bech32 form (`lnurl1…`), in lower case.
	pub fn encoded(&self) -> &str {
		&self.encoded
	}

	/// The URL the LNURL encodes.
	pub fn url(&self) -> &str {
		&self.url
	}
}

/// Why a string is not an LNURL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LnurlParseError {
	/// Not bech32 with a valid checksum.
	#[error("not bech32: {0}")]
	Bech32(String),
	/// The human-readable part is not `lnurl`.
	#[error("human-readable part is not lnurl")]
	Hrp,
	/// The payload is not a UTF-8 http(s) URL.
	#[error("payload is not an http(s) URL")]
	NotUrl,
}

impl FromStr for Lnurl {
	type Err = LnurlParseError;

	/// Parses `lnurl1…` in either case, with or without a `lightning:`
	/// prefix.
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let s = s.trim();
		let s = match s.get(..10) {
			Some(p) if p.eq_ignore_ascii_case("lightning:") => &s[10..],
			_ => s,
		};
		let checked = CheckedHrpstring::new::<Bech32>(s)
			.map_err(|e| LnurlParseError::Bech32(e.to_string()))?;
		if !checked.hrp().as_str().eq_ignore_ascii_case(LNURL_HRP) {
			return Err(LnurlParseError::Hrp);
		}
		let url = String::from_utf8(checked.byte_iter().collect())
			.map_err(|_| LnurlParseError::NotUrl)?;
		let lower = url.get(..8).map(|p| p.to_ascii_lowercase()).unwrap_or_default();
		if !lower.starts_with("https://") && !lower.starts_with("http://") {
			return Err(LnurlParseError::NotUrl);
		}
		Ok(Lnurl { encoded: s.to_ascii_lowercase(), url })
	}
}

impl fmt::Display for Lnurl {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.encoded)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	/// LUD-01's own example.
	const LUD01: &str = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";

	#[test]
	fn lud01_example() {
		let l = Lnurl::from_str(LUD01).unwrap();
		assert_eq!(l.url(), "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df");
		assert_eq!(l.encoded(), LUD01.to_ascii_lowercase());
		assert_eq!(Lnurl::from_str(&LUD01.to_ascii_lowercase()).unwrap(), l);
		assert_eq!(Lnurl::from_str(&format!("lightning:{}", LUD01)).unwrap(), l);
		assert_eq!(Lnurl::from_str(&format!("LIGHTNING:{}", LUD01)).unwrap(), l);
	}

	#[test]
	fn refuses_what_is_not_an_lnurl() {
		// A broken checksum.
		let mut broken = LUD01.to_string();
		broken.pop();
		broken.push('Q');
		assert!(matches!(Lnurl::from_str(&broken), Err(LnurlParseError::Bech32(_))));
		// Another human-readable part.
		assert!(matches!(
			Lnurl::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
			Err(LnurlParseError::Hrp),
		));
		assert!(Lnurl::from_str("notaninvoice").is_err());
	}
}
