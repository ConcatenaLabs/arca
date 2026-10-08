//! Paying and being paid out of round: receive requests, transfers, the
//! mailbox, and the in-tree swap of two assets between two wallets.

use std::collections::BTreeSet;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Script};
use serde_json::{json, Value};

use arca_covenant::spend::{margin_for, FeeSource};
use arca_covenant::{CoinRecord, ExplicitOutput, NewLeaf, Pair, RelativeTime, TransferPlan, ValidCoin, ValidInput, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::store::CoinRow;
use super::wallet::{amount, kind_of, owner_of, sign, Assessed, CoinDates, Wallet};
use super::{random32, Error};

/// How many times the floor a pre-signed transaction's margin holds: the
/// specification's cover for a fourfold rise in the fee floor. It is the
/// operator's least margin (`info.fees.margin_multiple`).
pub const MARGIN_MULTIPLE: u64 = 4;

/// The least time between accepting a swap and the exit deadline of the
/// coins it gives the wallet, unless the user takes it anyway: two days.
pub const SWAP_DEADLINE_MARGIN: u32 = 2 * 86_400;

/// How many times the operator's least margin the wallet leaves, within the
/// operator's most: room for the operator's floor to rise between the
/// wallet reading it and the operator co-signing.
pub const MARGIN_HEADROOM: u64 = 2;

/// The margins a transfer leaves, as the operator bounds them: its node's
/// floor in the asset now (`None` where it does not accept the asset for
/// fees: a margin of one atom), the least margin's multiple of it, and the
/// most margin's multiple of the least. Read from the operator's `info`,
/// never from the wallet's own node, whose view of the open fee market may
/// differ from the operator's.
#[derive(Debug, Clone, Copy)]
pub struct Margins {
	pub floor: Option<u64>,
	pub multiple: u64,
	pub max_multiple: u64,
}

impl Margins {
	/// The operator's margins in `asset`, from its `info`.
	pub fn of(info: &Value, asset: AssetId) -> Result<Margins, Error> {
		let fees = &info["fees"];
		let floors = fees["floors"].as_array().ok_or_else(|| Error::Unreachable(
			"the operator publishes no fee floor now (its node did not answer it): no margin can be priced; try again".into()))?;
		let row = floors.iter().find(|f| f["asset"].as_str() == Some(&asset.to_string()))
			.ok_or_else(|| Error::Refused(format!("the operator publishes no fee floor in asset {}", asset)))?;
		let floor = match &row["floor_per_kvb"] {
			Value::Null => None,
			v => Some(amount(v, "floor_per_kvb")?),
		};
		let multiple = fees["margin_multiple"].as_u64().filter(|m| *m > 0).unwrap_or(MARGIN_MULTIPLE);
		let max_multiple = fees["max_margin_multiple"].as_u64().filter(|m| *m > 0).unwrap_or(1);
		Ok(Margins { floor, multiple, max_multiple })
	}

	/// The margin the wallet leaves on a transaction of `vsize` vbytes: the
	/// operator's least times [`MARGIN_HEADROOM`], within its most.
	pub fn margin(&self, vsize: usize) -> u64 {
		let least = match self.floor {
			Some(f) => margin_for(vsize, f, self.multiple).max(1),
			None => 1,
		};
		least.saturating_mul(MARGIN_HEADROOM.min(self.max_multiple))
	}
}

/// A script of a leaf's size, to size an output whose leaf is not known yet:
/// every leaf pays a taproot output, and the operator prices a margin from
/// the transaction's real size.
fn leaf_probe() -> Script {
	let mut b = vec![0x51, 0x20];
	b.extend([0u8; 32]);
	Script::from(b)
}

/// What each text the wallet hands out holds, by which another wallet knows
/// it, whatever its prefix ([`super::wallet::Spelling`]).
const REQUEST_KIND: &str = "arca_request";
const OFFER_KIND: &str = "arca_swap_offer";
const ACCEPT_KIND: &str = "arca_swap_accept";

fn encode(prefix: &str, v: &Value) -> String {
	format!("{}{}", prefix, hex(v.to_string().as_bytes()))
}

/// The text `s` the wallet was handed, `what` (a receive request, an offer,
/// an acceptance): a prefix, any word and a colon, as the wallet that made
/// it spells it, then the hex of its JSON, which names its `kind`.
fn decode(kind: &str, s: &str, what: &str) -> Result<Value, Error> {
	let (prefix, h) = s.trim().split_once(':').ok_or_else(|| Error::Parse(format!("{}: it has no prefix", what)))?;
	if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
		return Err(Error::Parse(format!("{}: its prefix {:?} is not a word", what, prefix)));
	}
	let bytes = unhex(h)?;
	let v: Value = serde_json::from_slice(&bytes).map_err(|e| Error::Parse(format!("{}: {}", what, e)))?;
	if v.get(kind).is_none() {
		return Err(Error::Parse(format!("{}: the text is not one", what)));
	}
	Ok(v)
}

fn xonly(s: &str) -> Result<XOnlyPublicKey, Error> {
	XOnlyPublicKey::from_str(s).map_err(|e| Error::Parse(format!("key {:?}: {}", s, e)))
}

fn asset_of(v: &Value, what: &str) -> Result<AssetId, Error> {
	AssetId::from_str(v.as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("{}: {}", what, e)))
}

/// One output of a transfer: its asset and value, its leaf, the mailbox it
/// is posted to, and, for a payment to a receive request, when that request
/// lapses (`until`), which the server checks too: it records no payment to a
/// request past its lapse.
#[derive(Debug, Clone)]
pub(crate) struct Out {
	pub asset: AssetId,
	pub value: u64,
	pub leaf: NewLeaf,
	pub mailbox: XOnlyPublicKey,
	pub until: Option<u32>,
}

impl Out {
	fn json(&self) -> Value {
		let mut v = json!({
			"asset": self.asset.to_string(), "value": self.value.to_string(), "owner": hex(&self.leaf.owner.serialize()),
			"owner_nonce": hex(&self.leaf.owner_nonce), "creator_nonce": hex(&self.leaf.creator_nonce),
			"exit_delay_units": self.leaf.exit_delay.units(), "mailbox": hex(&self.mailbox.serialize()),
		});
		if let Some(u) = self.until {
			v["until"] = json!(u);
		}
		v
	}

	fn from_json(v: &Value) -> Result<Out, Error> {
		Ok(Out {
			asset: asset_of(&v["asset"], "an output's asset")?,
			value: amount(&v["value"], "an output's value")?,
			leaf: NewLeaf {
				owner: XOnlyPublicKey::from_slice(&unhex(v["owner"].as_str().unwrap_or(""))?).map_err(|e| Error::Parse(e.to_string()))?,
				owner_nonce: unhex32(v["owner_nonce"].as_str().unwrap_or(""))?,
				creator_nonce: unhex32(v["creator_nonce"].as_str().unwrap_or(""))?,
				exit_delay: RelativeTime::from_units(v["exit_delay_units"].as_u64().unwrap_or(0) as u16)
					.map_err(|e| Error::Parse(e.to_string()))?,
			},
			mailbox: XOnlyPublicKey::from_slice(&unhex(v["mailbox"].as_str().unwrap_or(""))?).map_err(|e| Error::Parse(e.to_string()))?,
			until: v["until"].as_u64().map(|u| u32::try_from(u).map_err(|_| Error::Parse(format!("an output's lapse {}", u)))).transpose()?,
		})
	}

	fn explicit(&self, w: &Wallet) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.leaf.policy(w.operator, w.genesis).script_pubkey())
	}
}

/// One coin given up in a transfer, with what its checkpoint keeps.
pub(crate) struct In {
	pub row: CoinRow,
	pub coin: ValidCoin,
	pub checkpoint_value: u64,
}

/// The earliest first expiry among the batches `record` rests on, as its
/// record names them; `None` for a coin resting on boards alone.
pub(crate) fn first_expiry(record: &CoinRecord) -> Option<u32> {
	match record {
		CoinRecord::Leaf { record, .. } => record.schedule.expiries().first().map(|e| e.to_consensus_u32()),
		CoinRecord::Board(_) => None,
		CoinRecord::Transfer(t) => t.inputs.iter().filter_map(|i| first_expiry(&i.coin)).min(),
	}
}

/// What the wallet says of a coin whose forfeit the operator's signer holds.
const FORFEIT_HELD_NOTE: &str = "given up: the operator's signer holds a forfeit of this coin, signed in a refresh that did not \
	complete, so it co-signs no spend of it; the coin is the wallet's on the chain, and sync takes it home from home_from ({exit} \
	takes it now)";

/// The salt under which the operator's signer holds a forfeit, when `e` is
/// its refusal of a spend for that reason (`double_spend`, naming the
/// forfeit).
fn forfeit_held(e: &Error) -> Option<[u8; 32]> {
	let Error::Server { code, message, .. } = e else { return None };
	if code != "double_spend" || !message.contains("already co-signed the forfeit") {
		return None;
	}
	let salt = message.split("under salt ").nth(1)?.split_whitespace().next()?;
	unhex32(salt).ok()
}

fn dummy_sig() -> Signature {
	Signature::from_slice(&[1u8; 64]).expect("64 bytes")
}

impl Wallet {
	// -----------------------------------------------------------------------
	// Receive requests
	// -----------------------------------------------------------------------

	/// A single-use receive request: a fresh owner nonce and the key it gives,
	/// the wallet's mailbox, the exit delay the wallet asks for, and when it
	/// lapses (`until`, a median time, [`super::wallet::REQUEST_HOLDS`] after
	/// it was handed out): a sender pays it only before then, and the
	/// wallet's schedule holds at a day until then while it is unpaid. The
	/// nonce, and both dates, are stored before the request is shown, and a
	/// second coin to it is refused.
	pub fn receive(&mut self, asset: Option<AssetId>, value: Option<u64>) -> Result<Value, Error> {
		if let Some((at, why)) = self.rolled_back()? {
			return Err(Error::Refused(format!("the operator's signer's record was rolled back or replaced past entry {} ({}): the wallet \
				asks for no payment through this operator", at, why)));
		}
		let nonce = random32();
		let key = self.keys.leaf_xonly(&nonce)?;
		// When it was handed out, by the chain's clock, and when it lapses.
		let now = self.now()?.to_consensus_u32();
		let until = now.saturating_add(super::wallet::REQUEST_HOLDS);
		self.store.atomically(|s| {
			s.put_nonce(&nonce, &key.serialize(), "receive")?;
			let pending: Vec<String> = s.nonces()?.iter().filter(|n| n.purpose == "receive" && n.state == "pending")
				.map(|n| hex(&n.nonce)).collect();
			for (k, t) in [(super::wallet::RECEIVE_ASKED, now), (super::wallet::RECEIVE_UNTIL, until)] {
				let mut m: std::collections::BTreeMap<String, u32> = s.meta(k)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
				m.retain(|n, _| pending.contains(n));
				m.insert(hex(&nonce), t);
				s.set_meta(k, &serde_json::to_string(&m).expect("a map"))?;
			}
			Ok(())
		})?;
		let mut req = json!({
			(REQUEST_KIND): 1, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"owner": hex(&key.serialize()), "owner_nonce": hex(&nonce),
			"mailbox": hex(&self.keys.mailbox()?.x_only_public_key().0.serialize()),
			"exit_delay_units": self.cfg.exit_delay_units, "until": until,
		});
		if let Some(a) = asset {
			req["asset"] = json!(a.to_string());
		}
		if let Some(v) = value {
			req["value"] = json!(v.to_string());
		}
		Ok(json!({"request": encode(&self.spelling.request, &req), "details": req}))
	}

	fn check_chain(&self, v: &Value, what: &str) -> Result<(), Error> {
		if v["genesis_hash"].as_str() != Some(&self.genesis.genesis_hash().to_string()) {
			return Err(Error::Refused(format!("the {} is for the chain of genesis {}, not this wallet's", what, v["genesis_hash"])));
		}
		if v["operator"].as_str() != Some(&self.operator.to_string()) {
			return Err(Error::Refused(format!("the {} is for operator {}, not this wallet's", what, v["operator"])));
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Transfers
	// -----------------------------------------------------------------------

	/// A fresh leaf of the wallet's own, its nonce stored.
	fn own_leaf(&self, purpose: &str) -> Result<NewLeaf, Error> {
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), purpose)?;
		Ok(NewLeaf { owner, owner_nonce: nonce, creator_nonce: random32(), exit_delay: self.exit_delay() })
	}

	/// The live coins of `asset`, furthest from their exit date first (D58:
	/// what a receiver gets has the longest life the wallet can give it), the
	/// largest first among those of one date, each resolved; a coin past its
	/// exit deadline is not paid on (the operator co-signs no spend of it,
	/// and `sync` takes it on the chain).
	fn spendable(&self, asset: AssetId) -> Result<Vec<In>, Error> {
		let mut out = vec![];
		let now = self.now()?.to_consensus_u32() as u64;
		for row in self.store.coins_in("live")?.into_iter().filter(|c| c.asset == asset.to_string()) {
			if row.expiry != u32::MAX && now + WalletPolicy::EXIT_DEADLINE as u64 >= row.expiry as u64 {
				continue;
			}
			let (_, a) = self.held(&row)?;
			if !a.all_final() {
				continue;
			}
			let v = a.valid.value;
			out.push(In { row, coin: a.valid, checkpoint_value: v });
		}
		out.sort_by_key(|i| (std::cmp::Reverse(i.row.expiry), std::cmp::Reverse(i.coin.value)));
		Ok(out)
	}

	/// The checkpoint margin of `coin`, and the reassignment's of `inputs`
	/// into `outputs`, each as the operator bounds them ([`Margins`]).
	fn checkpoint_margin(&self, coin: &ValidCoin, m: &Margins) -> Result<u64, Error> {
		let vi = ValidInput {
			coin: coin.clone(), checkpoint: coin.checkpoint(), checkpoint_value: coin.value,
			checkpoint_pair: Pair { operator: dummy_sig(), owner: dummy_sig() }, reassignment_pair: Pair { operator: dummy_sig(), owner: dummy_sig() },
		};
		let tx = vi.checkpoint_tx(OutPoint::default(), &FeeSource::Reserve).map_err(|e| Error::Refused(e.to_string()))?.tx;
		Ok(m.margin(tx.vsize()))
	}

	fn reassignment_margin(&self, inputs: &[&ValidCoin], outputs: &[ExplicitOutput], m: &Margins) -> Result<u64, Error> {
		let vis: Vec<ValidInput> = inputs.iter().map(|c| ValidInput {
			coin: (*c).clone(), checkpoint: c.checkpoint(), checkpoint_value: c.value,
			checkpoint_pair: Pair { operator: dummy_sig(), owner: dummy_sig() }, reassignment_pair: Pair { operator: dummy_sig(), owner: dummy_sig() },
		}).collect();
		// Sized with outputs of one atom each of the inputs' asset, so they
		// fit any inputs: an explicit output's size does not depend on either.
		let asset = inputs.first().map(|c| c.asset).ok_or_else(|| Error::Refused("a transfer with no input".into()))?;
		let small: Vec<ExplicitOutput> = outputs.iter().map(|o| ExplicitOutput::new(asset, 1, o.script_pubkey.clone())).collect();
		let cps: Vec<OutPoint> = (0..vis.len()).map(|i| OutPoint::new(elements::Txid::all_zeros(), i as u32)).collect();
		let tx = arca_covenant::transfer::reassignment_tx(&vis, &small, &cps, &FeeSource::Reserve)
			.map_err(|e| Error::Refused(e.to_string()))?.tx;
		Ok(m.margin(tx.vsize()))
	}

	/// Refuses margins above the wallet's own bound: together, at most
	/// [`super::DEFAULT_MAX_FEE_PPM`] of the coins they come out of. The
	/// margins are taken out of the coins given up, priced from the floor the
	/// operator publishes, so that floor never takes the wallet past its own
	/// bound.
	fn margins_within_bound(&self, inputs: &[In], margin: u64, asset: AssetId) -> Result<(), Error> {
		let value: u64 = inputs.iter().map(|i| i.coin.value).sum();
		let margins: u64 = inputs.iter().map(|i| i.coin.value - i.checkpoint_value).sum::<u64>() + margin;
		if !super::round::fee_within(margins, value, super::DEFAULT_MAX_FEE_PPM) {
			return Err(Error::Refused(format!("the operator's floor in asset {} asks margins of {} on coins of {}, above the \
				wallet's bound of {} ppm: nothing is signed", asset, margins, value, super::DEFAULT_MAX_FEE_PPM)));
		}
		Ok(())
	}

	/// Chooses coins of `asset` to pay `paid` (outputs of `asset` the wallet
	/// pays, plus `extra` atoms more), each input's checkpoint keeping its
	/// value less its margin; returns the inputs, the reassignment's margin
	/// when `pays_margin`, and the change.
	#[allow(clippy::too_many_arguments)]
	fn choose(&self, info: &Value, asset: AssetId, paid: u64, others: &[ExplicitOutput], pays_margin: bool, min_leaf: u64,
		other_inputs: usize) -> Result<(Vec<In>, u64, u64), Error>
	{
		let margins = Margins::of(info, asset)?;
		let candidates = self.spendable(asset)?;
		let total_live: u64 = candidates.iter().map(|c| c.coin.value).sum();
		let mut chosen: Vec<In> = vec![];
		// The reassignment's margin with every coin chosen so far.
		let mut margin = 0;
		for c in candidates {
			let m = self.checkpoint_margin(&c.coin, &margins)?;
			chosen.push(In { checkpoint_value: c.coin.value - m.min(c.coin.value - 1), ..c });
			let kept: u64 = chosen.iter().map(|i| i.checkpoint_value).sum();
			// Size the reassignment with a change output, which it may need.
			let change_probe = ExplicitOutput::new(asset, 1, leaf_probe());
			let mut outs = others.to_vec();
			outs.push(change_probe);
			// Inputs another owner adds (a swap's other side) are sized as
			// copies of the first.
			let mut all: Vec<&ValidCoin> = chosen.iter().map(|i| &i.coin).collect();
			for _ in 0..other_inputs {
				all.push(&chosen[0].coin);
			}
			margin = if pays_margin { self.reassignment_margin(&all, &outs, &margins)? } else { 0 };
			if kept >= paid + margin {
				let change = kept - paid - margin;
				if change > 0 && change < min_leaf {
					if chosen.len() < arca_covenant::transfer::MAX_INPUTS {
						continue;
					}
				} else {
					self.margins_within_bound(&chosen, margin, asset)?;
					return Ok((chosen, margin, change));
				}
			}
		}
		let kept: u64 = chosen.iter().map(|i| i.checkpoint_value).sum();
		if kept >= paid + margin {
			return Err(Error::Refused(format!("the change would be below the operator's smallest leaf in asset {} ({} atoms): \
				pay a little less, or that much more", asset, min_leaf)));
		}
		Err(Error::Refused(format!("the wallet holds {} of asset {} in live coins, and paying {} takes {} with the margins its \
			transactions leave for their fees", total_live, asset, paid, paid + total_live.saturating_sub(kept) + margin)))
	}

	/// Pays `value` of `asset` to the receive request `request`, out of round:
	/// coins of that asset, each into a checkpoint, and the reassignment into
	/// the receiver's leaf and the wallet's change, with the margins left for
	/// their fees in the asset moved. The server co-signs and posts the coins
	/// to the mailboxes. No asset is a default: the request or the caller
	/// names it. A request past its lapse (`until`) is refused before
	/// anything is built or signed.
	pub fn send(&mut self, request: &str, value: Option<u64>, asset: Option<AssetId>) -> Result<Value, Error> {
		let req = decode(REQUEST_KIND, request, "the receive request")?;
		self.check_chain(&req, "receive request")?;
		// A receiver waits for a payment to its request until the request
		// lapses, and reads one paid later only if it happens to sync: a
		// request past its lapse is paid by nobody. One handed out before
		// requests carried their lapse names none, and its receiver waits
		// for it until it is paid or forgotten.
		let until = match req.get("until") {
			Some(u) => Some(u.as_u64().and_then(|t| u32::try_from(t).ok())
				.ok_or_else(|| Error::Parse(format!("the receive request's lapse {}: not a median time", u)))?),
			None => None,
		};
		if let Some(until) = until {
			let now = self.now()?.to_consensus_u32();
			if now >= until {
				return Err(Error::Refused(format!("the request lapsed at {} (a median time; the chain's is {}): ask the receiver for a \
					new one", until, now)));
			}
		}
		let req_asset = req.get("asset").map(|a| asset_of(a, "the request's asset")).transpose()?;
		let asset = match (asset, req_asset) {
			(Some(a), Some(r)) if a != r => return Err(Error::Refused(format!("the request asks for asset {}, not {}", r, a))),
			(Some(a), _) | (None, Some(a)) => a,
			(None, None) => return Err(Error::Refused("name the asset to send (--asset): no asset is a default".into())),
		};
		let value = match (value, req.get("value")) {
			(Some(v), _) => v,
			(None, Some(v)) => amount(v, "the request's value")?,
			(None, None) => return Err(Error::Refused("name the amount to send".into())),
		};
		let info = self.server_info()?;
		let min = Self::min_leaf(&info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("{} is below the operator's smallest leaf in asset {}, {}", value, asset, min)));
		}
		let to = Out {
			asset, value,
			leaf: NewLeaf {
				owner: xonly(req["owner"].as_str().unwrap_or(""))?,
				owner_nonce: unhex32(req["owner_nonce"].as_str().unwrap_or(""))?,
				// Drawn fresh for this leaf: two payments to one request make
				// two leaves, never one output two pairs commit to.
				creator_nonce: random32(),
				exit_delay: RelativeTime::from_units(req["exit_delay_units"].as_u64().unwrap_or(0) as u16)
					.map_err(|e| Error::Parse(e.to_string()))?,
			},
			mailbox: xonly(req["mailbox"].as_str().unwrap_or(""))?,
			// The server records no payment to the request past its lapse,
			// whenever this payment reaches it (a post held, and sent again).
			until,
		};
		let to_out = to.explicit(self);
		let (inputs, margin, change) = self.choose(&info, asset, value, std::slice::from_ref(&to_out), true, min, 0)?;
		let mut outs = vec![to];
		if change > 0 {
			let leaf = self.own_leaf("change")?;
			outs.push(Out { asset, value: change, leaf, mailbox: self.keys.mailbox()?.x_only_public_key().0, until: None });
		}
		let answer = self.transfer(&inputs, &outs, &[])?;
		Ok(json!({
			"sent": {"asset": asset.to_string(), "value": value.to_string(), "to": to_out_owner(&outs[0])},
			"inputs": inputs.iter().map(|i| i.row.leaf_id.clone()).collect::<Vec<_>>(),
			"margins": {"asset": asset.to_string(), "checkpoints": inputs.iter().map(|i| (i.coin.value - i.checkpoint_value).to_string()).collect::<Vec<_>>(),
				"reassignment": margin.to_string()},
			"change": if change > 0 { json!(change.to_string()) } else { Value::Null },
			"transfer": answer,
		}))
	}

	/// Signs `mine` (the wallet's inputs among `inputs` at their index), asks
	/// the server to co-sign the whole transfer, and takes the answer. `theirs`
	/// carries the signatures of inputs another owner signed, by index.
	fn transfer(&mut self, inputs: &[In], outs: &[Out], theirs: &[(usize, Signature, Signature)]) -> Result<Value, Error> {
		// Nothing is signed for the operator without a witness of its
		// signer's record, whatever entry point led here.
		self.witnessed_now()?;
		let plan = TransferPlan {
			inputs: inputs.iter().map(|i| (i.coin.clone(), i.checkpoint_value)).collect(),
			outputs: outs.iter().map(|o| o.explicit(self)).collect(),
		};
		let mut ins = vec![];
		let mut mine = vec![];
		for (k, i) in inputs.iter().enumerate() {
			let (cp, re) = match theirs.iter().find(|(j, _, _)| *j == k) {
				Some((_, cp, re)) => (*cp, *re),
				None => {
					let key = self.keys.leaf(&i.row.owner_nonce)?;
					mine.push(i.row.leaf_id.clone());
					let cp = sign(&key, &plan.checkpoint_message(k).map_err(|e| Error::Refused(e.to_string()))?.digest);
					let re = sign(&key, &plan.reassignment_message(k).map_err(|e| Error::Refused(e.to_string()))?.digest);
					(cp, re)
				},
			};
			ins.push(json!({"leaf_id": i.coin.id.to_string(), "checkpoint_value": i.checkpoint_value.to_string(),
				"checkpoint_sig": hex(cp.as_ref()), "reassignment_sig": hex(re.as_ref())}));
		}
		let body = json!({"inputs": ins, "outputs": outs.iter().map(|o| { let mut j = o.json(); j["mailbox"] = json!(hex(&o.mailbox.serialize())); j }).collect::<Vec<_>>()});
		let id = self.store.atomically(|s| {
			let id = s.put_transfer(&body.to_string(), &serde_json::to_string(&mine).expect("strings"))?;
			for l in &mine {
				s.set_coin_state(l, "sending", &format!("transfer request {}", id))?;
			}
			Ok(id)
		})?;
		self.post_transfer(id, &body, &mine)
	}

	/// Posts transfer request `id` and takes the answer: the inputs spent, the
	/// wallet's own new coins validated and kept. Only a refusal (a 4xx with
	/// one of the server's refusal codes) puts the inputs back; anything else,
	/// a 5xx or a timeout after the server may have co-signed among them,
	/// leaves the request standing, to be posted again, the same bytes, by
	/// `sync`: the server answers a request repeated byte for byte as it did
	/// the first time.
	fn post_transfer(&mut self, id: i64, body: &Value, mine: &[String]) -> Result<Value, Error> {
		match self.server.post("cosign_transfer", body) {
			// A co-signature whose head is not held outside the operator's
			// machine as the wallet requires is taken as no answer: the
			// request stands, and is posted again.
			Ok(answer) if self.held_outside(&answer["signer_record"]).is_err() => {
				let why = self.held_outside(&answer["signer_record"]).err().unwrap_or_default();
				Err(Error::Unreachable(format!("the operator co-signed transfer request {} without the acknowledgements of its keepers: {}; \
					the wallet takes no coin of it, and the request stands, to be posted again", id, why)))
			},
			Ok(answer) => {
				let transfer_id = answer["transfer_id"].as_str().unwrap_or("").to_string();
				let mut kept = vec![];
				for o in answer["outputs"].as_array().cloned().unwrap_or_default() {
					let bytes = unhex(o["record"].as_str().unwrap_or(""))?;
					let record = CoinRecord::from_bytes(&bytes).map_err(|e| Error::Refused(e.to_string()))?;
					let (_, nonce) = owner_of(&record);
					if self.store.nonce(&nonce)?.is_some() {
						match self.accept_coin(&bytes, o["leaf_id"].as_str().unwrap_or(""), "transfer answer") {
							Ok(v) => {
								if let Err(e) = self.keep_coin_head(v["leaf_id"].as_str().unwrap_or(""), &answer["signer_record"]) {
									self.store.refused(&format!("the head of transfer {}", transfer_id), &e.to_string())?;
								}
								kept.push(v)
							},
							Err(e) => kept.push(json!({"leaf_id": o["leaf_id"], "refused": e.to_string()})),
						}
					} else {
						// Not ours: still, the operator must have signed it. Its
						// dates are its receiver's to judge, so it is checked as
						// of its expiry once that has passed (an answer read
						// again, the request posted again past it).
						let txs = self.base_txs(&record)?;
						record.resolve(&txs, &self.followed_policy(first_expiry(&record).unwrap_or(u32::MAX), self.now()?))
							.map_err(|e| Error::Refused(format!("the server's record of output {}: {}", o["leaf_id"], e)))?;
					}
				}
				self.store.atomically(|s| {
					for l in mine {
						s.set_coin_spent(l, &format!("transfer {}", transfer_id))?;
					}
					s.set_transfer(id, "done", &answer.to_string())
				})?;
				Ok(json!({"transfer_id": transfer_id, "outputs": answer["outputs"].as_array().map(|a| a.iter().map(|o| o["leaf_id"].clone()).collect::<Vec<_>>()),
					"kept": kept}))
			},
			Err(e @ Error::Server { .. }) => {
				// A coin whose forfeit the operator's signer holds (given up in a
				// refresh that the operator let go) can never be paid on: it is
				// shown as given up, and goes home on the chain.
				let forfeited = forfeit_held(&e).and_then(|salt| mine.iter().find(|l| {
					self.store.coin(l).ok().flatten().is_some_and(|c| c.salt == salt)
				}).cloned());
				let held_note = self.spelling.say(FORFEIT_HELD_NOTE);
				self.store.atomically(|s| {
					for l in mine {
						if Some(l) == forfeited.as_ref() {
							s.set_coin_state(l, "forfeited", &held_note)?;
						} else {
							s.set_coin_state(l, "live", "")?;
						}
					}
					s.set_transfer(id, "refused", &e.to_string())?;
					s.refused(&format!("transfer request {}", id), &e.to_string())
				})?;
				Err(e)
			},
			Err(e) => Err(e),
		}
	}

	/// Posts again every transfer request the server has not answered.
	pub(crate) fn retry_transfers(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (id, body, inputs) in self.store.transfers_in("requested")? {
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			let mine: Vec<String> = serde_json::from_str(&inputs).map_err(|e| Error::Store(e.to_string()))?;
			out.push(match self.post_transfer(id, &body, &mine) {
				Ok(v) => v,
				Err(e) => json!({"transfer_request": id, "error": e.to_string()}),
			});
		}
		Ok(out)
	}

	// -----------------------------------------------------------------------
	// Receiving
	// -----------------------------------------------------------------------

	/// Checks a coin record paid to the wallet and keeps it, or refuses it with
	/// its reason: the key and nonce must be ones the wallet drew and is
	/// waiting on; the record must validate back to its rounds and boards under
	/// the wallet's receipt policy (every pair, preimage and authorisation,
	/// the bounds on every leaf of the lineage, the depth limit); no leaf or
	/// checkpoint of its lineage may be on the chain; every board it rests on
	/// must be unspent; and its salt must be one the wallet has never held a
	/// coin under. A coin past its batch's exit deadline is kept and exited
	/// at once, whatever of its lineage is on the chain, and so is one a day
	/// or less from its exit date (D57), whose sender may already be taking
	/// their shared lineage home. Past its batch's expiry it is checked as of
	/// that expiry, and kept and exited at once while the chain still holds
	/// its path; it is refused once a sweep that cut that path is final (D58),
	/// and kept while that sweep is not final yet, its note naming the sweep.
	pub(crate) fn accept_coin(&mut self, bytes: &[u8], claimed: &str, source: &str) -> Result<Value, Error> {
		self.accept_coin_as(bytes, claimed, source, false)
	}

	/// [`Self::accept_coin`], and with `home`, for a wallet whose operator's
	/// signer is stopped: the coin is checked as ever, kept even where its
	/// lineage or a board it rests on is on the chain already, and taken on
	/// the chain at once, since the operator co-signs nothing more and
	/// exiting it is its holder's only chance.
	/// What a coin the wallet already holds, arriving again as `bytes` (its
	/// record, checked), is: the same record, held; or another record of the
	/// same coin, which every check passed, so validly signed: since a coin's
	/// id commits to its outputs, both pay the same outputs and the wallet's
	/// coin is safe, but the operator co-signed two checkpoint values for one
	/// coin, which it never should. That is kept with the wallet's refusals as
	/// evidence, the second record with it, and reported. `None` for a coin
	/// the wallet does not hold.
	pub(crate) fn held_again(&self, id: &str, bytes: &[u8]) -> Result<Option<Value>, Error> {
		let Some(c) = self.store.coin(id)? else { return Ok(None) };
		// Each in its canonical encoding.
		let held = CoinRecord::from_bytes(&c.record).ok().and_then(|r| r.to_bytes().ok());
		if c.record.is_empty() || c.record == bytes || held.as_deref() == Some(bytes) {
			return Ok(Some(json!({"leaf_id": id, "already_held": c.state})));
		}
		let why = format!("a second record of coin {}, every check of it passed, carries other checkpoint values than the record the \
			wallet holds: the operator co-signed two checkpoint values for one coin. Both pay the same outputs, so the coin is safe; the \
			second record is kept here as evidence: {}", id, hex(bytes));
		self.store.refused(&format!("evidence: coin {}", id), &why)?;
		Ok(Some(json!({"leaf_id": id, "already_held": c.state, "evidence": why})))
	}

	fn accept_coin_as(&mut self, bytes: &[u8], claimed: &str, source: &str, home: bool) -> Result<Value, Error> {
		let record = CoinRecord::from_bytes(bytes).map_err(|e| Error::Refused(format!("the record does not decode: {}", e)))?;
		let (owner, nonce) = owner_of(&record);
		let row = match self.store.nonce(&nonce)? {
			Some(row) => row,
			// A restore takes a coin paid to a key of the mnemonic that the
			// lost store had drawn; one key, one coin, as ever.
			None if self.adopting.get() && self.keys.leaf_xonly(&nonce)? == owner => {
				self.store.put_nonce(&nonce, &owner.serialize(), "restored")?;
				self.store.nonce(&nonce)?.ok_or_else(|| Error::Store("a nonce just kept is gone".into()))?
			},
			None => return Err(Error::Refused(format!("a coin for owner nonce {}, which this wallet never drew", hex(&nonce)))),
		};
		if row.owner_key != owner.serialize() || self.keys.leaf_xonly(&nonce)? != owner {
			return Err(Error::Refused("the record's owner key is not the key this wallet derives from its nonce".into()));
		}
		let now = self.now()?;
		let policy = self.receipt_policy(now);
		// A coin resting on a batch past its exit deadline (a payment the
		// server recorded before it and completed when it was asked again, or
		// one read late) is still the wallet's, co-signed and checked:
		// refusing it would undo nothing. It is kept, and taken on the chain
		// at once, since the operator co-signs no spend of it and takes it
		// into no round, and the batch's expiry is near. Past the expiry
		// itself (D58) it is checked as of its expiry, as an exit checks a
		// coin held, and kept and taken on the chain at once while the chain
		// still holds its path: the operator sweeps a batch only once its
		// token has waited the notice. It is refused once the sweep that cut
		// its path is final.
		let (a, late, expired): (Assessed, bool, bool) = match self.assess(&record, &policy, Some((&owner, &nonce))) {
			Ok(a) => (a, false, false),
			Err(e) => match self.assess(&record, &WalletPolicy { horizon: 0, ..policy }, Some((&owner, &nonce))) {
				Ok(a) => (a, true, false),
				Err(_) => {
					let as_of = first_expiry(&record).filter(|t| *t < now.to_consensus_u32())
						.and_then(|t| arca_covenant::MedianTime::from_consensus(t).ok());
					let Some(as_of) = as_of else { return Err(e) };
					match self.assess(&record, &WalletPolicy { horizon: 0, ..self.receipt_policy(as_of) }, Some((&owner, &nonce))) {
						Ok(a) => (a, true, true),
						Err(_) => return Err(e),
					}
				},
			},
		};
		// A sweep the exit would find is looked for here too: once it is
		// final the coin is gone, and refused, counted nowhere; while it is
		// not, a rollback could still undo it, so the coin is kept and taken
		// on the chain at once, and says so.
		let mut sweeping = None;
		if expired {
			if let Some((why, by)) = self.swept(&a.valid)? {
				let finality = self.chain.finality(&by)?;
				if finality.is_final() {
					return Err(Error::Refused(format!("the coin arrives past its batch's expiry, and its path is gone: {}; that spend \
						is final", why)));
				}
				sweeping = Some((by, finality.word()));
			}
		}
		let id = a.valid.id.to_string();
		if !claimed.is_empty() && claimed != id {
			return Err(Error::Refused(format!("the server names the coin {}, its record makes it {}", claimed, id)));
		}
		if let Some(v) = self.held_again(&id, &record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?)? {
			return Ok(v);
		}
		if row.state != "pending" {
			return Err(Error::Refused(format!("a second coin for the single-use key {} (it already holds {})",
				owner, row.leaf_id.unwrap_or_default())));
		}
		if let Some(c) = self.store.coin_by_salt(&a.valid.leaf.salt)? {
			return Err(Error::Refused(format!("the coin's salt is that of coin {} the wallet has held: its old pairs would spend it", c.leaf_id)));
		}
		// D57: a coin a day or less from its exit date, or past it, goes on
		// the chain at once from wherever its lineage is: whoever shares that
		// lineage (its sender's change) may already be taking it home, and
		// refusing the coin would leave its output on the chain to no one.
		let due = CoinDates::of(self.service_expiry(&record, &a)?)
			.is_some_and(|d| now.to_consensus_u32() >= d.home_from);
		let boards_spent = a.valid.check_boards(|op| self.chain.unspent(op).unwrap_or(false)).err();
		if let Some(e) = &boards_spent {
			if !home && !late && !due {
				return Err(Error::Refused(e.to_string()));
			}
		}
		// A coin resting on a board carries the board's dates. One that
		// arrives past its exit deadline (a payment the server recorded
		// before it and completed when it was asked again) is still the
		// wallet's, co-signed and checked: refusing it would undo nothing.
		// It is kept, and shown as a coin the operator co-signs no spend of
		// and takes into no refresh: `sync` takes it on the chain.
		let board_expiry = self.board_expiry(&record, &a.bases)?;
		let past_deadline = board_expiry.is_some_and(|e| now.to_consensus_u32() as u64 + WalletPolicy::EXIT_DEADLINE as u64 >= e as u64);
		let lineage: BTreeSet<Script> = a.valid.lineage().into_iter().map(|o| o.output.script_pubkey).collect();
		let seen = self.chain.scripts_seen(&lineage, a.lowest_height())?;
		// A coin held off the chain must have nothing of its lineage there,
		// or the owner of that step could spend it under the receiver. A
		// coin taken on the chain at once goes on from wherever its lineage
		// is (an exit of a coin sharing it, say), and its exit answers that
		// step first: refusing it would only lose it.
		let on_chain = a.valid.check_lineage(|s| seen.contains(s)).err();
		if let Some(e) = &on_chain {
			if !late && !home && !due {
				return Err(Error::Refused(e.to_string()));
			}
		}
		let (state, mut note) = if a.all_final() { ("live", String::new()) } else { ("pending", format!("waiting: {}", a.waiting())) };
		// A coin received out of round from an operator with no keeper rests
		// on the operator's machine alone until it is refreshed.
		if matches!(record, CoinRecord::Transfer(_)) && self.keepers()?.0.is_empty() {
			note = if note.is_empty() { super::wallet::NO_KEEPER.to_string() } else { format!("{}; {}", note, super::wallet::NO_KEEPER) };
		}
		if past_deadline {
			let e = board_expiry.expect("past a deadline");
			let why = format!("it rests on a board past its exit deadline (the board's service ends at median time {}): the operator \
				co-signs no spend of it and takes it into no refresh, so sync takes it on the chain", e);
			note = if note.is_empty() { why } else { format!("{}; {}", note, why) };
		}
		if late {
			let why = if let Some((by, word)) = &sweeping {
				format!("it arrives past its batch's expiry (median time {}), and the operator's sweep {} has spent the batch output its \
					path rests on; that sweep is not final yet ({}): the coin is lost once it is, and the wallet keeps the coin and takes \
					it on the chain at once should a rollback undo the sweep", a.valid.expiry.to_consensus_u32(), by, word)
			} else if expired {
				format!("it arrives past its batch's expiry (median time {}), its path still on the chain: the operator may sweep the \
					batch once its notice has run, so the wallet takes it on the chain at once{}", a.valid.expiry.to_consensus_u32(),
					on_chain.as_ref().map(|e| format!(", going on from its lineage on the chain ({})", e)).unwrap_or_default())
			} else {
				format!("it rests on a batch past its exit deadline (the batch expires at median time {}): the operator co-signs \
					no spend of it and takes it into no round, so the wallet takes it on the chain at once{}", a.valid.expiry.to_consensus_u32(),
					on_chain.as_ref().map(|e| format!(", going on from its lineage on the chain ({})", e)).unwrap_or_default())
			};
			note = if note.is_empty() { why } else { format!("{}; {}", note, why) };
		}
		let coin = self.row(&record, &a, state, &note)?;
		// The wallet's own coins this transfer spent (a swap's side).
		let spent: Vec<String> = match &record {
			CoinRecord::Transfer(t) => t.inputs.iter().filter_map(|i| {
				let (_, n) = owner_of(&i.coin);
				self.store.nonce(&n).ok().flatten().and_then(|r| r.leaf_id)
			}).collect(),
			_ => vec![],
		};
		self.store.atomically(|s| {
			s.put_coin(&coin)?;
			s.use_nonce(&nonce, &id)?;
			for l in &spent {
				if let Some(c) = s.coin(l)? {
					if c.state != "spent" {
						s.set_coin_spent(l, &format!("transfer creating {}", id))?;
					}
				}
			}
			Ok(())
		})?;
		let mut out = json!({"leaf_id": id, "kind": kind_of(&record), "asset": a.valid.asset.to_string(), "value": a.valid.value.to_string(),
			"hops": a.valid.hops, "state": state, "note": note, "from": source});
		// D57: a coin whose exit needs a fee coin the wallet does not hold
		// says so when it is taken, as on every listing.
		if let Some(f) = self.exit_fee(&coin, &mut None)? {
			out["exit_fee"] = f;
		}
		if super::wallet::rests_on_board(&record) {
			out["board"] = match board_expiry {
				Some(e) if past_deadline => json!({"exit_deadline": e.saturating_sub(WalletPolicy::EXIT_DEADLINE), "expiry": e,
					"note": "the coin rests on a board past its exit deadline: it cannot be paid on or refreshed, and sync takes it on the \
					chain; it can be exited at any time"}),
				Some(e) => json!({"exit_deadline": e.saturating_sub(WalletPolicy::EXIT_DEADLINE), "expiry": e,
					"note": "the coin rests on a board, which carries the dates of a batch made when it confirmed: pay it on or refresh it \
					before its exit deadline (sync refreshes it in the two days before, and takes it on the chain from a day before unless \
					refreshed); from the expiry the operator may bring the coin on the chain"}),
				None => json!({"note": "the coin rests on a board not yet in a block: it carries the dates of a batch made when the board \
					confirms, shown once it does"}),
			};
		}
		if home && !late {
			let why = format!("the operator's signer is stopped and co-signs nothing more: the wallet takes the coin on the chain at once{}{}",
				on_chain.as_ref().map(|e| format!(", going on from its lineage on the chain ({})", e)).unwrap_or_default(),
				boards_spent.as_ref().map(|e| format!("; {}", e)).unwrap_or_default());
			self.store.set_coin_state(&id, &coin.state, &why)?;
			out["note"] = json!(why);
			out["exit"] = self.exit(&id, None).unwrap_or_else(|e| json!({"error": e.to_string(),
				"note": "exit the coin, naming an asset the wallet holds on the chain for the fees (--fee-asset)"}));
			if let Some(c) = self.store.coin(&id)? {
				out["state"] = json!(c.state);
			}
		}
		if due && !late && !home {
			let why = format!("it arrives a day or less from its exit date{}: the wallet takes it on the chain at once{}{}",
				CoinDates::of(coin.expiry).map(|d| format!(" (median time {})", d.exit_by)).unwrap_or_default(),
				on_chain.as_ref().map(|e| format!(", going on from its lineage on the chain ({})", e)).unwrap_or_default(),
				boards_spent.as_ref().map(|e| format!("; {}", e)).unwrap_or_default());
			self.store.set_coin_state(&id, &coin.state, &why)?;
			out["note"] = json!(why);
			out["exit"] = self.exit(&id, None).unwrap_or_else(|e| json!({"error": e.to_string()}));
			if let Some(c) = self.store.coin(&id)? {
				out["state"] = json!(c.state);
			}
		}
		if late {
			let e = a.valid.expiry.to_consensus_u32();
			out["batch"] = json!({"expiry": e, "exit_deadline": e.saturating_sub(WalletPolicy::EXIT_DEADLINE),
				"note": match (&sweeping, expired) {
					(Some((by, word)), _) => format!("the coin arrives past its batch's expiry, and the operator's sweep {} of the batch has \
						spent the output its path rests on; that sweep is not final yet ({}): the coin is lost once it is, and comes home \
						only should a rollback undo it", by, word),
					(None, true) => "the coin arrives past its batch's expiry, its path still on the chain: it cannot be paid on or \
						refreshed, and is exited at once, before the operator's sweep".to_string(),
					(None, false) => "the coin rests on a batch past its exit deadline: it cannot be paid on or refreshed, and is exited at \
						once".to_string(),
				}});
			out["exit"] = self.exit(&id, None).unwrap_or_else(|e| json!({"error": e.to_string(),
				"note": if sweeping.is_some() {
					"the operator's sweep has cut the coin's path: there is nothing to exit while it stands, and sync looks again"
				} else {
					"exit the coin before its batch expires, naming an asset the wallet holds on the chain for the fees (--fee-asset)"
				}}));
			if let Some(c) = self.store.coin(&id)? {
				out["state"] = json!(c.state);
			}
		}
		Ok(out)
	}

	/// Reads the wallet's mailbox, and the mailbox of every key of a receive
	/// request still waiting, and validates every coin in them. Each coin is
	/// kept or refused with its reason; one refused for a passing reason
	/// (what it rests on not on the chain now, the node or the server not
	/// answering) is kept aside and checked again on every read until it is
	/// kept or refused for good. The cursor moves past all of them but one
	/// whose head of the operator's signer's record comes without the
	/// acknowledgements of the keepers the wallet pinned: that coin is not
	/// taken, and its message is read again on the next read.
	pub fn mailbox(&mut self) -> Result<Value, Error> {
		let witness = self.witness()?;
		// After a stop, the mailbox and the coins kept for a retry are still
		// read, each coin checked as ever and taken on the chain at once: the
		// operator co-signs nothing more, so exiting is its holder's only
		// chance, and refusing it would gain nothing.
		let home = self.rolled_back()?;
		let mut keys = vec![self.keys.mailbox()?];
		for n in self.store.nonces()? {
			if n.purpose == "receive" && n.state == "pending" {
				keys.push(self.keys.leaf(&n.nonce)?);
			}
		}
		let mut accepted = vec![];
		let mut refused = vec![];
		let mut waiting = vec![];
		// Coins read again that the wallet holds already (the messages after
		// one that waits are read again with it): never reported as taken.
		let mut held = vec![];
		for (leaf, bytes, head) in self.store.kept_for_retry()? {
			let head_v: Value = head.as_deref().and_then(|h| serde_json::from_str(h).ok()).unwrap_or(Value::Null);
			if let (Err(why), None) = (self.held_outside(&head_v), &home) {
				self.store.keep_for_retry(&leaf, &bytes, &why, None)?;
				waiting.push(json!({"leaf_id": leaf, "reason": why}));
				continue;
			}
			match self.accept_coin_as(&bytes, &leaf, "mailbox", home.is_some()) {
				Ok(v) => {
					self.store.drop_retry(&leaf)?;
					let head: Value = head.as_deref().and_then(|h| serde_json::from_str(h).ok()).unwrap_or(Value::Null);
					if let Err(e) = self.keep_coin_head(&leaf, &head) {
						self.store.refused(&format!("the head of mailbox coin {}", leaf), &e.to_string())?;
					}
					if v["already_held"].is_null() { accepted.push(v) } else { held.push(v) }
				},
				Err(e) if passing(&e) => {
					self.store.keep_for_retry(&leaf, &bytes, &e.to_string(), None)?;
					waiting.push(json!({"leaf_id": leaf, "reason": e.to_string()}));
				},
				Err(e) => {
					self.store.drop_retry(&leaf)?;
					self.store.refused(&format!("mailbox coin {}", leaf), &e.to_string())?;
					refused.push(json!({"leaf_id": leaf, "reason": e.to_string()}));
				},
			}
		}
		for key in keys {
			let k = key.x_only_public_key().0.serialize();
			let mut read_again: Option<i64> = None;
			loop {
				let after = self.store.cursor(&k)?;
				let v = self.server.mailbox_read(&key, &self.genesis, after, 100)?;
				let msgs = v["messages"].as_array().cloned().unwrap_or_default();
				if msgs.is_empty() {
					break;
				}
				for m in &msgs {
					let cursor: i64 = m["cursor"].as_str().unwrap_or("0").parse().unwrap_or(0);
					let leaf = m["leaf_id"].as_str().unwrap_or("").to_string();
					let bytes = unhex(m["record"].as_str().unwrap_or("")).unwrap_or_default();
					// A coin is taken only once the head it rests on is held
					// outside the operator's machine as the wallet requires;
					// until then it waits, and its message is read again from
					// the server, which hands the head on with what it holds.
					if let (Err(why), None) = (self.held_outside(&m["signer_record"]), &home) {
						waiting.push(json!({"leaf_id": leaf, "reason": why}));
						read_again = Some(read_again.map_or(cursor - 1, |c: i64| c.min(cursor - 1)));
						self.store.set_cursor(&k, cursor)?;
						continue;
					}
					match self.accept_coin_as(&bytes, &leaf, "mailbox", home.is_some()) {
						Ok(v) => {
							if let Err(e) = self.keep_coin_head(&leaf, &m["signer_record"]) {
								self.store.refused(&format!("the head of mailbox coin {}", leaf), &e.to_string())?;
							}
							if v["already_held"].is_null() { accepted.push(v) } else { held.push(v) }
						},
						Err(e) if passing(&e) => {
							let head = (!m["signer_record"].is_null()).then(|| m["signer_record"].to_string());
							self.store.keep_for_retry(&leaf, &bytes, &e.to_string(), head.as_deref())?;
							waiting.push(json!({"leaf_id": leaf, "reason": e.to_string()}));
						},
						Err(e) => {
							self.store.refused(&format!("mailbox coin {}", leaf), &e.to_string())?;
							refused.push(json!({"leaf_id": leaf, "reason": e.to_string()}));
						},
					}
					self.store.set_cursor(&k, cursor)?;
				}
			}
			if let Some(c) = read_again {
				self.store.set_cursor(&k, c)?;
			}
		}
		let mut out = json!({"accepted": accepted, "refused": refused, "waiting": waiting});
		if !held.is_empty() {
			out["already_held"] = json!(held);
		}
		if let Some((at, why)) = home {
			out["witness"] = witness;
			out["note"] = json!(format!("the operator's signer's record was rolled back past entry {} ({}): the operator co-signs \
				nothing more, so the wallet takes every coin it is sent on the chain at once", at, why));
		}
		Ok(out)
	}

	// -----------------------------------------------------------------------
	// The swap
	// -----------------------------------------------------------------------

	/// Offers `give` of `give_asset` for `want` of `want_asset`, in one
	/// reassignment both wallets sign: the offer names the maker's coins (their
	/// records, so the taker can check them), what each checkpoint keeps, the
	/// leaf the maker wants and its change. The maker pays the reassignment's
	/// margin, in the asset it gives; the coins are held back until the swap
	/// completes or is cancelled.
	pub fn swap_offer(&mut self, give_asset: AssetId, give: u64, want_asset: AssetId, want: u64) -> Result<Value, Error> {
		if give_asset == want_asset {
			return Err(Error::Refused("a swap exchanges two assets".into()));
		}
		let info = self.server_info()?;
		let min_give = Self::min_leaf(&info, give_asset)?;
		let min_want = Self::min_leaf(&info, want_asset)?;
		if give < min_give || want < min_want {
			return Err(Error::Refused("each side of a swap is at least the operator's smallest leaf in its asset".into()));
		}
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let want_leaf = self.own_leaf("swap")?;
		let wanted = Out { asset: want_asset, value: want, leaf: want_leaf, mailbox, until: None };
		// The taker's leaf of `give`, and its change, are not known yet: size
		// with probes of the same shape.
		let probe = |a: AssetId| ExplicitOutput::new(a, 1, leaf_probe());
		let others = vec![wanted.explicit(self), probe(give_asset), probe(want_asset)];
		let (inputs, margin, change) = self.choose(&info, give_asset, give, &others, true, min_give, 1)?;
		let mut outs = vec![wanted];
		if change > 0 {
			outs.push(Out { asset: give_asset, value: change, leaf: self.own_leaf("change")?, mailbox, until: None });
		}
		let offer = json!({
			(OFFER_KIND): 1, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"give": {"asset": give_asset.to_string(), "value": give.to_string()},
			"want": {"asset": want_asset.to_string(), "value": want.to_string()},
			"margin": margin.to_string(),
			"inputs": inputs.iter().map(|i| json!({"leaf_id": i.coin.id.to_string(), "record": hex(&i.row.record),
				"checkpoint_value": i.checkpoint_value.to_string()})).collect::<Vec<_>>(),
			"outputs": outs.iter().map(Out::json).collect::<Vec<_>>(),
		});
		let id = hex(&sha256::Hash::hash(offer.to_string().as_bytes()).to_byte_array());
		self.store.atomically(|s| {
			s.put_swap(&id, "maker", &offer.to_string())?;
			for i in &inputs {
				s.set_coin_state(&i.row.leaf_id, "offered", &format!("swap {}", id))?;
			}
			Ok(())
		})?;
		Ok(json!({"swap": id, "offer": encode(&self.spelling.offer, &offer), "details": offer}))
	}

	/// Checks an offer's coins as a receiver checks a coin, and their values.
	fn offer_inputs(&self, offer: &Value) -> Result<Vec<In>, Error> {
		let now = self.now()?;
		let mut out = vec![];
		for i in offer["inputs"].as_array().cloned().unwrap_or_default() {
			let bytes = unhex(i["record"].as_str().unwrap_or(""))?;
			let record = CoinRecord::from_bytes(&bytes).map_err(|e| Error::Refused(format!("an offered coin: {}", e)))?;
			let a = self.assess(&record, &self.receipt_policy(now), None)?;
			if a.valid.id.to_string() != i["leaf_id"].as_str().unwrap_or("") {
				return Err(Error::Refused("an offered coin's id is not its record's".into()));
			}
			if !a.all_final() {
				return Err(Error::Refused(format!("an offered coin is not final: {}", a.waiting())));
			}
			a.valid.check_boards(|op| self.chain.unspent(op).unwrap_or(false)).map_err(|e| Error::Refused(e.to_string()))?;
			let cp = amount(&i["checkpoint_value"], "checkpoint_value")?;
			if cp == 0 || cp > a.valid.value {
				return Err(Error::Refused("an offered checkpoint keeps nothing, or more than its coin".into()));
			}
			// Its dates: the earliest first expiry of the batches it rests
			// on, or a board's service expiry, whichever comes first.
			let expiry = self.service_expiry(&record, &a)?;
			let row = CoinRow {
				leaf_id: a.valid.id.to_string(), owner_nonce: owner_of(&record).1, kind: kind_of(&record).into(),
				asset: a.valid.asset.to_string(), value: a.valid.value, record: bytes, salt: a.valid.leaf.salt, state: "theirs".into(),
				note: String::new(), expiry, bases: vec![], spent_by: None,
			};
			out.push(In { row, coin: a.valid, checkpoint_value: cp });
		}
		Ok(out)
	}

	/// Takes an offer: checks the maker's coins and that they fund what the
	/// maker gives, adds the wallet's coins of the asset wanted and the leaf it
	/// gets, signs its own inputs over the full output set, and returns the
	/// acceptance for the maker to complete. Every coin the swap makes rests
	/// on every coin it spends, so the coins the wallet gets carry the
	/// earliest dates among them (a batch's first expiry, or a board's
	/// service expiry): they are shown, and the swap is refused when their
	/// exit deadline is less than [`SWAP_DEADLINE_MARGIN`] away, unless
	/// `near_deadline` says to take it anyway.
	pub fn swap_accept(&mut self, offer_text: &str, near_deadline: bool) -> Result<Value, Error> {
		let offer = decode(OFFER_KIND, offer_text, "the offer")?;
		self.check_chain(&offer, "offer")?;
		let id = hex(&sha256::Hash::hash(offer.to_string().as_bytes()).to_byte_array());
		let give_asset = asset_of(&offer["give"]["asset"], "give")?;
		let give = amount(&offer["give"]["value"], "give")?;
		let want_asset = asset_of(&offer["want"]["asset"], "want")?;
		let want = amount(&offer["want"]["value"], "want")?;
		let margin = amount(&offer["margin"], "margin")?;
		let theirs = self.offer_inputs(&offer)?;
		let maker_outs: Vec<Out> = offer["outputs"].as_array().cloned().unwrap_or_default().iter().map(Out::from_json).collect::<Result<_, _>>()?;
		if theirs.is_empty() || theirs.iter().any(|i| i.coin.asset != give_asset) {
			return Err(Error::Refused("the offered coins are not all of the asset offered".into()));
		}
		if maker_outs.first().map(|o| (o.asset, o.value)) != Some((want_asset, want)) {
			return Err(Error::Refused("the offer's first output is not what it says it wants".into()));
		}
		let maker_change: u64 = maker_outs.iter().skip(1).filter(|o| o.asset == give_asset).map(|o| o.value).sum();
		let kept: u64 = theirs.iter().map(|i| i.checkpoint_value).sum();
		if kept != give + maker_change + margin {
			return Err(Error::Refused(format!("the offered coins keep {} of asset {}; the offer gives {}, keeps {} as change \
				and {} as margin", kept, give_asset, give, maker_change, margin)));
		}
		let info = self.server_info()?;
		let min_want = Self::min_leaf(&info, want_asset)?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let mut outs = maker_outs.clone();
		outs.push(Out { asset: give_asset, value: give, leaf: self.own_leaf("swap")?, mailbox, until: None });
		let mut others: Vec<ExplicitOutput> = outs.iter().map(|o| o.explicit(self)).collect();
		others.push(ExplicitOutput::new(want_asset, 1, leaf_probe()));
		let (mine, _, change) = self.choose(&info, want_asset, want, &others, false, min_want, 0)?;
		if change > 0 {
			outs.push(Out { asset: want_asset, value: change, leaf: self.own_leaf("change")?, mailbox, until: None });
		}
		if outs.len() > arca_covenant::leaf::MAX_OUTPUTS as usize {
			return Err(Error::Refused(format!("the swap would make {} outputs; a reassignment makes at most {}", outs.len(),
				arca_covenant::leaf::MAX_OUTPUTS)));
		}
		// The dates of the coins the wallet gets: the earliest of every coin
		// spent, the maker's and its own.
		let dates = self.swap_dates(theirs.iter().chain(mine.iter()), near_deadline)?;
		let n = theirs.len();
		let mut inputs = theirs;
		inputs.extend(mine);
		let plan = TransferPlan {
			inputs: inputs.iter().map(|i| (i.coin.clone(), i.checkpoint_value)).collect(),
			outputs: outs.iter().map(|o| o.explicit(self)).collect(),
		};
		let mut sigs = vec![];
		for (k, i) in inputs.iter().enumerate().skip(n) {
			let key = self.keys.leaf(&i.row.owner_nonce)?;
			let cp = sign(&key, &plan.checkpoint_message(k).map_err(|e| Error::Refused(e.to_string()))?.digest);
			let re = sign(&key, &plan.reassignment_message(k).map_err(|e| Error::Refused(e.to_string()))?.digest);
			sigs.push(json!({"input": k, "checkpoint_sig": hex(cp.as_ref()), "reassignment_sig": hex(re.as_ref())}));
		}
		let accept = json!({
			(ACCEPT_KIND): 1, "swap": id,
			"inputs": inputs.iter().map(|i| json!({"leaf_id": i.coin.id.to_string(), "record": hex(&i.row.record),
				"checkpoint_value": i.checkpoint_value.to_string()})).collect::<Vec<_>>(),
			"outputs": outs.iter().map(Out::json).collect::<Vec<_>>(),
			"signatures": sigs,
		});
		self.store.atomically(|s| {
			s.put_swap(&id, "taker", &offer.to_string())?;
			s.set_swap(&id, "accepted", Some(&accept.to_string()))?;
			for i in inputs.iter().skip(n) {
				s.set_coin_state(&i.row.leaf_id, "offered", &format!("swap {}", id))?;
			}
			Ok(())
		})?;
		let mut gets = vec![json!({"asset": give_asset.to_string(), "value": give.to_string(), "dates": dates})];
		if change > 0 {
			gets.push(json!({"asset": want_asset.to_string(), "value": change.to_string(), "change": true, "dates": dates}));
		}
		Ok(json!({"swap": id, "accept": encode(&self.spelling.accept, &accept), "gets": {"asset": give_asset.to_string(), "value": give.to_string()},
			"gives": {"asset": want_asset.to_string(), "value": want.to_string()}, "coins": gets, "dates": dates}))
	}

	/// The dates of the coins a swap spending `inputs` gives the wallet, as
	/// shown before anything is signed: every coin the swap makes rests on
	/// every coin it spends, so they carry the earliest dates among them (a
	/// batch's first expiry, a board's service expiry). Refused when their
	/// exit deadline is less than [`SWAP_DEADLINE_MARGIN`] away, unless
	/// `near_deadline` says to take it anyway.
	fn swap_dates<'a>(&self, inputs: impl Iterator<Item = &'a In> + Clone, near_deadline: bool) -> Result<Value, Error> {
		let now = self.now()?.to_consensus_u32() as u64;
		let expiry = inputs.clone().map(|i| i.row.expiry).min().unwrap_or(u32::MAX);
		let on_board = inputs.clone().any(|i| CoinRecord::from_bytes(&i.row.record).is_ok_and(|r| super::wallet::rests_on_board(&r)));
		let deadline = (expiry != u32::MAX).then(|| expiry.saturating_sub(WalletPolicy::EXIT_DEADLINE));
		let dates = json!({"expiry": (expiry != u32::MAX).then_some(expiry), "exit_deadline": deadline, "rests_on_board": on_board,
			"seconds_to_exit_deadline": deadline.map(|d| (d as u64).saturating_sub(now))});
		if let Some(d) = deadline {
			if (d as u64) < now + SWAP_DEADLINE_MARGIN as u64 && !near_deadline {
				return Err(Error::Refused(format!("the coins this swap gives the wallet rest on coins whose earliest exit deadline is at \
					median time {} ({} s from now): they could be paid on for less than {} s, and after it the operator takes them only \
					into a refresh; take the swap anyway with --accept-near-deadline", d, (d as u64).saturating_sub(now),
					SWAP_DEADLINE_MARGIN)));
			}
		}
		Ok(dates)
	}

	/// Completes a swap the wallet offered: checks that the acceptance keeps
	/// the maker's inputs and outputs exactly as offered, that every other
	/// coin in it is good, signs the maker's inputs over the full output set,
	/// and has the server co-sign. The maker's coins move only into a
	/// transaction that creates every output the maker signed for. The coins
	/// the swap gives the maker rest on every coin it spends, the taker's
	/// included: their dates are shown, and checked as [`Wallet::swap_accept`]
	/// checks the taker's, before the maker signs anything.
	pub fn swap_complete(&mut self, accept_text: &str, near_deadline: bool) -> Result<Value, Error> {
		let accept = decode(ACCEPT_KIND, accept_text, "the acceptance")?;
		let id = accept["swap"].as_str().unwrap_or("").to_string();
		let (role, offer, _, state) = self.store.swap(&id)?.ok_or_else(|| Error::Refused(format!("no swap {} offered by this wallet", id)))?;
		if role != "maker" || state != "open" {
			return Err(Error::Refused(format!("swap {} is not an open offer of this wallet's (it is {} {})", id, role, state)));
		}
		let offer: Value = serde_json::from_str(&offer).map_err(|e| Error::Store(e.to_string()))?;
		let offered_in = offer["inputs"].as_array().cloned().unwrap_or_default();
		let offered_out = offer["outputs"].as_array().cloned().unwrap_or_default();
		let acc_in = accept["inputs"].as_array().cloned().unwrap_or_default();
		let acc_out = accept["outputs"].as_array().cloned().unwrap_or_default();
		if acc_in.len() < offered_in.len() || acc_in[..offered_in.len()] != offered_in[..] {
			return Err(Error::Refused("the acceptance does not keep the offered coins and checkpoints as offered".into()));
		}
		if acc_out.len() < offered_out.len() || acc_out[..offered_out.len()] != offered_out[..] {
			return Err(Error::Refused("the acceptance does not keep the outputs offered, at their places".into()));
		}
		let give_asset = asset_of(&offer["give"]["asset"], "give")?;
		let give = amount(&offer["give"]["value"], "give")?;
		let outs: Vec<Out> = acc_out.iter().map(Out::from_json).collect::<Result<_, _>>()?;
		if !outs.iter().skip(offered_out.len()).any(|o| o.asset == give_asset && o.value == give) {
			return Err(Error::Refused("the acceptance has no leaf for the taker of what the offer gives".into()));
		}
		let n = offered_in.len();
		let mut inputs = vec![];
		for (k, i) in acc_in.iter().enumerate() {
			let leaf_id = i["leaf_id"].as_str().unwrap_or("").to_string();
			if k < n {
				let row = self.store.coin(&leaf_id)?.ok_or_else(|| Error::Refused(format!("coin {} is not the wallet's", leaf_id)))?;
				if row.state != "offered" {
					return Err(Error::Refused(format!("coin {} is {} now, not held for the swap", leaf_id, row.state)));
				}
				let (_, a) = self.held(&row)?;
				inputs.push(In { row, coin: a.valid, checkpoint_value: amount(&i["checkpoint_value"], "checkpoint_value")? });
			}
		}
		let taker = self.offer_inputs(&json!({"inputs": acc_in[n..]}))?;
		inputs.extend(taker);
		// The dates of the coins the wallet gets: the earliest of every coin
		// spent, its own and the taker's.
		let dates = self.swap_dates(inputs.iter(), near_deadline)?;
		let mut theirs = vec![];
		for s in accept["signatures"].as_array().cloned().unwrap_or_default() {
			let k = s["input"].as_u64().unwrap_or(0) as usize;
			if k < n {
				return Err(Error::Refused("the acceptance signs for the maker's inputs".into()));
			}
			let cp = Signature::from_slice(&unhex(s["checkpoint_sig"].as_str().unwrap_or(""))?).map_err(|e| Error::Parse(e.to_string()))?;
			let re = Signature::from_slice(&unhex(s["reassignment_sig"].as_str().unwrap_or(""))?).map_err(|e| Error::Parse(e.to_string()))?;
			theirs.push((k, cp, re));
		}
		if theirs.len() != inputs.len() - n {
			return Err(Error::Refused("the acceptance does not sign every one of the taker's inputs".into()));
		}
		// Coins of the taker's are not the wallet's to mark: only the maker's
		// are put to `sending`.
		let answer = self.transfer(&inputs, &outs, &theirs)?;
		self.store.set_swap(&id, "done", None)?;
		Ok(json!({"swap": id, "transfer": answer, "dates": dates}))
	}

	/// Cancels a swap the wallet offered or accepted and has not seen
	/// completed. An offer has nothing of the wallet's signed in it: its coins
	/// are spendable again. An acceptance has: the maker holds the wallet's
	/// signatures over the swap and can complete it while the wallet's coins
	/// in it are unspent, so the wallet spends them, through the server, to a
	/// fresh leaf of its own, after which the acceptance can never complete.
	/// If that cannot be done now, the answer says the acceptance still
	/// stands, and the coins stay held for the swap.
	pub fn swap_cancel(&mut self, id: &str) -> Result<Value, Error> {
		let (role, _, _, state) = self.store.swap(id)?.ok_or_else(|| Error::Refused(format!("no swap {}", id)))?;
		if state == "done" {
			return Err(Error::Refused(format!("swap {} is done", id)));
		}
		let held: Vec<CoinRow> = self.store.coins_in("offered")?.into_iter().filter(|c| c.note == format!("swap {}", id)).collect();
		if role == "taker" && state == "accepted" && !held.is_empty() {
			let ids: Vec<String> = held.iter().map(|c| c.leaf_id.clone()).collect();
			return match self.respend_to_self(held) {
				Ok(answer) => {
					self.store.set_swap(id, "cancelled", None)?;
					Ok(json!({"swap": id, "cancelled": true, "respent": ids, "transfer": answer,
						"note": "the coins signed into the acceptance moved to a fresh leaf of the wallet's own: the acceptance can never complete"}))
				},
				Err(Error::Server { code, message, .. }) if code == "double_spend" => {
					Ok(json!({"swap": id, "cancelled": false, "error": message,
						"note": "the coins signed into the acceptance are already spent, most likely by the maker completing the swap: \
						read the mailbox for what the swap pays the wallet"}))
				},
				Err(e) => {
					for l in &ids {
						if self.store.coin(l)?.is_some_and(|c| c.state == "live") {
							self.store.set_coin_state(l, "offered", &format!("swap {}", id))?;
						}
					}
					Ok(json!({"swap": id, "cancelled": false, "acceptance_stands": true, "error": e.to_string(),
						"note": "the acceptance still stands: the maker can complete it while the coins signed into it are unspent; run \
						swap cancel again, or exit the coins"}))
				},
			};
		}
		let mut freed = vec![];
		for c in held {
			self.store.set_coin_state(&c.leaf_id, "live", "")?;
			freed.push(c.leaf_id);
		}
		self.store.set_swap(id, "cancelled", None)?;
		Ok(json!({"swap": id, "cancelled": true, "freed": freed}))
	}

	/// Spends `rows`, coins of one asset, to one fresh leaf of the wallet's
	/// own, through the server, with the margins a transfer leaves.
	fn respend_to_self(&mut self, rows: Vec<CoinRow>) -> Result<Value, Error> {
		let asset = AssetId::from_str(&rows[0].asset).map_err(|e| Error::Store(e.to_string()))?;
		let margins = Margins::of(&self.server_info()?, asset)?;
		let mut inputs = vec![];
		for row in rows {
			let (_, a) = self.held(&row)?;
			let m = self.checkpoint_margin(&a.valid, &margins)?;
			inputs.push(In { checkpoint_value: a.valid.value - m.min(a.valid.value - 1), row, coin: a.valid });
		}
		let leaf = self.own_leaf("cancel")?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let probe = Out { asset, value: 1, leaf: leaf.clone(), mailbox, until: None };
		let all: Vec<&ValidCoin> = inputs.iter().map(|i| &i.coin).collect();
		let margin = self.reassignment_margin(&all, &[probe.explicit(self)], &margins)?;
		let kept: u64 = inputs.iter().map(|i| i.checkpoint_value).sum();
		let value = kept.checked_sub(margin).filter(|v| *v > 0)
			.ok_or_else(|| Error::Refused("the coins do not cover the margins of a transfer to the wallet itself".into()))?;
		self.transfer(&inputs, &[Out { asset, value, leaf, mailbox, until: None }], &[])
	}
}

/// Whether a coin refused with `e` may be accepted later: what it rests on
/// is not on the chain now, or the node, the server or the store did not
/// answer.
fn passing(e: &Error) -> bool {
	matches!(e, Error::Missing(_) | Error::Node(_) | Error::Unreachable(_) | Error::Store(_) | Error::Io(_))
}

fn to_out_owner(o: &Out) -> String {
	o.leaf.owner.to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The signer's refusal of a spend for a forfeit it holds names the salt
	/// of the coin the wallet then shows as given up; a refusal for a spend,
	/// or any other refusal, names none.
	#[test]
	fn a_refusal_for_a_held_forfeit_names_the_coins_salt() {
		let salt = [0x5a; 32];
		let refusal = |code: &str, what: &str| Error::Server {
			call: "cosign_transfer".into(), status: 409, code: code.into(),
			message: format!("the signer: the signer refused: already_signed: S has already co-signed {} {} under salt {} (entry 1, for \
				the leaf of {}); the signer co-signs one spend under a salt", what, hex(&[1; 32]), hex(&salt), hex(&[2; 32])),
		};
		assert_eq!(forfeit_held(&refusal("double_spend", "the forfeit")), Some(salt));
		assert_eq!(forfeit_held(&refusal("double_spend", "the spend")), None);
		assert_eq!(forfeit_held(&refusal("in_use", "the forfeit")), None);
		assert_eq!(forfeit_held(&Error::Refused("already co-signed the forfeit under salt 00".into())), None);
	}

	/// W2.1's finding: what the library says names no command of the command
	/// line (`arca sync`, `arca exit`, `arca address`): a client without one
	/// shows it as it is. Every line of the library's code, comments and
	/// tests aside, is read for one.
	#[test]
	fn the_library_says_the_act_not_the_command() {
		let command = format!("`{} ", "arca");
		let mut found = vec![];
		for (file, text) in [("wallet.rs", include_str!("wallet.rs")), ("pay.rs", include_str!("pay.rs")), ("exit.rs", include_str!("exit.rs")),
			("round.rs", include_str!("round.rs")), ("chain.rs", include_str!("chain.rs")), ("store.rs", include_str!("store.rs"))]
		{
			let code = text.split("#[cfg(test)]").next().unwrap_or("");
			for (n, l) in code.lines().enumerate() {
				if !l.trim_start().starts_with("//") && l.contains(&command) {
					found.push(format!("{}:{}: {}", file, n + 1, l.trim()));
				}
			}
		}
		println!("lines of the library's code naming a command of the command line: {}", found.len());
		for l in &found {
			println!("  {}", l);
		}
		assert!(found.is_empty(), "{} line(s)", found.len());
	}

	/// A spelling with no command line says the act; the command line's says
	/// its commands, as the wallet always did; every slot of every note is
	/// filled either way.
	#[test]
	fn a_spelling_names_the_command_line_or_the_act() {
		use super::super::wallet::{Spelling, SYNC_NOTE, HOME_NOTE, UNREACHABLE_NOTE, REFUSED_NOTE, EXPIRED_NOTE, FEE_COIN_MISSING};
		let (neutral, cli) = (Spelling::default(), Spelling::command_line("arca"));
		for note in [SYNC_NOTE, HOME_NOTE, UNREACHABLE_NOTE, REFUSED_NOTE, EXPIRED_NOTE, FEE_COIN_MISSING, FORFEIT_HELD_NOTE] {
			for s in [&neutral, &cli] {
				assert!(!s.say(note).contains('{'), "a slot left: {}", s.say(note));
			}
			assert!(!neutral.say(note).contains("arca"), "{}", neutral.say(note));
		}
		println!("SYNC_NOTE, no command line: {}", neutral.say(SYNC_NOTE));
		println!("SYNC_NOTE, the command line: {}", cli.say(SYNC_NOTE));
		println!("FEE_COIN_MISSING, no command line: {}", neutral.say(FEE_COIN_MISSING));
		assert!(neutral.say(SYNC_NOTE).ends_with("Run sync at least once a day while the wallet holds a coin off the chain or waits for a \
			payment, whatever next_sync_at says; an exit takes the coin now"));
		assert!(cli.say(SYNC_NOTE).ends_with("Run `arca sync` at least once a day while the wallet holds a coin off the chain or waits \
			for a payment, whatever next_sync_at says; `arca exit` takes the coin now"));
		assert!(neutral.say(FEE_COIN_MISSING).contains("(send one to the wallet's address)"));
		assert!(cli.say(FEE_COIN_MISSING).contains("(send one to an address of `arca address`)"));
		assert!(neutral.say(FORFEIT_HELD_NOTE).ends_with("(an exit takes it now)"));
		assert_eq!((neutral.request.as_str(), neutral.offer.as_str(), neutral.accept.as_str()), ("request:", "swap-offer:", "swap-accept:"));
		assert_eq!((cli.request.as_str(), cli.offer.as_str(), cli.accept.as_str()), ("arca:", "arca-offer:", "arca-accept:"));
	}

	/// A text the wallet is handed is read whatever its prefix, and known by
	/// what it holds: a request made under any spelling, an older wallet's
	/// included, is a request; an offer is not one, nor a text without a
	/// prefix.
	#[test]
	fn a_text_is_read_whatever_its_prefix_and_known_by_what_it_holds() {
		let request = json!({(REQUEST_KIND): 1, "owner": "00"});
		let offer = json!({(OFFER_KIND): 1});
		for prefix in ["arca:", "request:", "leaf-pay:"] {
			assert_eq!(decode(REQUEST_KIND, &encode(prefix, &request), "the receive request").unwrap(), request);
		}
		let e = decode(REQUEST_KIND, &encode("request:", &offer), "the receive request").unwrap_err();
		assert!(e.to_string().contains("the receive request: the text is not one"), "{}", e);
		let e = decode(REQUEST_KIND, &hex(request.to_string().as_bytes()), "the receive request").unwrap_err();
		assert!(e.to_string().contains("it has no prefix"), "{}", e);
		let e = decode(REQUEST_KIND, &encode("a b:", &request), "the receive request").unwrap_err();
		assert!(e.to_string().contains("is not a word"), "{}", e);
	}
}
