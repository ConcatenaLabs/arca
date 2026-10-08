//! The one change the server makes to a BOLT11 invoice: its payment hash.
//!
//! An invoice paid into the tree is locked to a hash the receiving wallet
//! chose, whose preimage the operator does not know. A node makes invoices
//! only for preimages it holds, so the operator has its node make one for
//! the payment (amount, asset, description, expiry, final lock time, payment
//! secret, route hints and features, as it makes them for any invoice),
//! swaps in the wallet's hash here, and has the node sign the result
//! (`signinvoice`). Every other field is kept as the node wrote it.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BOLT11's tag of the payment hash, `p`.
const TAG_PAYMENT_HASH: u8 = 1;

/// The length of a signature, in five-bit groups: 65 bytes.
const SIGNATURE_GROUPS: usize = 104;

fn polymod(values: &[u8]) -> u32 {
	const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	let mut chk: u32 = 1;
	for v in values {
		let b = chk >> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
		for (i, g) in GEN.iter().enumerate() {
			if (b >> i) & 1 == 1 {
				chk ^= g;
			}
		}
	}
	chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
	let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
	v.push(0);
	v.extend(hrp.bytes().map(|b| b & 31));
	v
}

/// `bytes` as five-bit groups, the last one padded with zero bits.
fn to_groups(bytes: &[u8]) -> Vec<u8> {
	let mut out = vec![];
	let (mut acc, mut bits) = (0u32, 0u32);
	for b in bytes {
		acc = (acc << 8) | *b as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			out.push(((acc >> bits) & 31) as u8);
		}
	}
	if bits > 0 {
		out.push(((acc << (5 - bits)) & 31) as u8);
	}
	out
}

/// `invoice` with its payment hash replaced by `hash`, and every other field
/// as it was. Its signature no longer holds: the node that made it signs it
/// again (`signinvoice`).
pub fn with_payment_hash(invoice: &str, hash: &[u8; 32]) -> Result<String, String> {
	let s = invoice.trim().to_lowercase();
	let sep = s.rfind('1').ok_or("no separator")?;
	let (hrp, data) = (&s[..sep], &s[sep + 1..]);
	if !hrp.starts_with("ln") {
		return Err("not a Lightning invoice".into());
	}
	let mut groups = vec![];
	for c in data.bytes() {
		groups.push(CHARSET.iter().position(|x| *x == c).ok_or("a character outside bech32")? as u8);
	}
	let mut check = hrp_expand(hrp);
	check.extend(&groups);
	if groups.len() < 7 + SIGNATURE_GROUPS + 6 || polymod(&check) != 1 {
		return Err("its checksum does not hold".into());
	}
	let body = &groups[..groups.len() - 6];
	let sig_at = body.len() - SIGNATURE_GROUPS;
	let mut out = body[..7].to_vec();
	let mut at = 7;
	let mut found = 0;
	while at < sig_at {
		if at + 3 > sig_at {
			return Err("a tagged field runs into the signature".into());
		}
		let (tag, len) = (body[at], (body[at + 1] as usize) * 32 + body[at + 2] as usize);
		if at + 3 + len > sig_at {
			return Err("a tagged field runs into the signature".into());
		}
		if tag == TAG_PAYMENT_HASH {
			if len != 52 {
				return Err(format!("a payment hash of {} groups", len));
			}
			out.extend([TAG_PAYMENT_HASH, 1, 20]);
			out.extend(to_groups(hash));
			found += 1;
		} else {
			out.extend(&body[at..at + 3 + len]);
		}
		at += 3 + len;
	}
	if found != 1 {
		return Err(format!("{} payment hashes", found));
	}
	out.extend(&body[sig_at..]);
	let mut check = hrp_expand(hrp);
	check.extend(&out);
	check.extend([0u8; 6]);
	let m = polymod(&check) ^ 1;
	let mut encoded = String::with_capacity(hrp.len() + 1 + out.len() + 6);
	encoded.push_str(hrp);
	encoded.push('1');
	for g in &out {
		encoded.push(CHARSET[*g as usize] as char);
	}
	for i in 0..6 {
		encoded.push(CHARSET[((m >> (5 * (5 - i))) & 31) as usize] as char);
	}
	Ok(encoded)
}

#[cfg(test)]
mod test {
	use super::*;

	// Written by SeqLN (sequentia-regtest) for 5,000,000 msat of the policy
	// asset, with SeqLN's asset field `a`; its payment hash is
	// 45729a42…bb2a.
	const INVOICE: &str = "lnsqrt50u1p4vwja6sp5242tp6uz86q5tcxnex99rft2nzphn3dtlctpldfzjhgnfxad50espp5g4ef5sse9090jqmp0duq6ccw7n2ecsqn39ayxxgrhs\
		ere94mhv4qdqzvsap5f5d3wl8x0sjzv0y23a6kkn34yhkpd7ja6gj7xv7p6tfa8ll9u4lsxqyjw5qcqz959qxpqysgq9tu6neufvd7zqn67f540x45knxd89r6tz\
		j99vkast6x26tzqprvqdcyw4gjpyymyvucle4dw6uugv3e8p08us4a2h2jqy6pj2wuuu4qqmas8tg";

	fn hash_of(inv: &str) -> String {
		// The `pp5` field: tag p, length 52, then the hash's 52 groups.
		let at = inv.find("pp5").unwrap() + 3;
		inv[at..at + 52].to_string()
	}

	#[test]
	fn the_hash_is_swapped_and_nothing_else() {
		let h = [0x5a; 32];
		let out = with_payment_hash(INVOICE, &h).unwrap();
		assert_eq!(out.len(), INVOICE.len());
		assert_eq!(hash_of(&out), to_groups(&h).iter().map(|g| CHARSET[*g as usize] as char).collect::<String>());
		// Everything but the hash's groups and the checksum is as it was.
		let (at, n) = (INVOICE.find("pp5").unwrap() + 3, INVOICE.len());
		assert_eq!(&out[..at], &INVOICE[..at]);
		assert_eq!(&out[at + 52..n - 6], &INVOICE[at + 52..n - 6]);
		// Swapped back, it is the invoice the node wrote, checksum and all.
		let original: [u8; 32] = [
			0x45, 0x72, 0x9a, 0x42, 0x19, 0x2b, 0xca, 0xf9, 0x03, 0x61, 0x7b, 0x78, 0x0d, 0x63, 0x0e, 0xf4,
			0xd5, 0x9c, 0x40, 0x13, 0x89, 0x7a, 0x43, 0x19, 0x03, 0xbc, 0x32, 0x3c, 0x96, 0xbb, 0xbb, 0x2a,
		];
		assert_eq!(with_payment_hash(&out, &original).unwrap(), INVOICE);
		assert!(with_payment_hash("lnsqrt1qqqq", &h).is_err());
		let mut bad = INVOICE.to_string();
		bad.replace_range(30..31, if &INVOICE[30..31] == "q" { "p" } else { "q" });
		assert!(with_payment_hash(&bad, &h).is_err(), "a broken checksum is refused");
	}
}
