use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint, Psbt, ScriptBuf, Transaction, Txid};
use log::{debug, info, warn};

use ark::VtxoId;
use ark::board::BoardBuilder;
use ark::fees::validate_and_subtract_fee;
use ark::musig;
use ark::tree::signed::cosign_taproot;
use bitcoin_ext::{BlockHeight, TxStatus};
use server_rpc::{protos, MAX_NB_BOARD_FUNDING_INPUTS};
use server_rpc::protos::VtxoSpendState;

use crate::{Wallet, WalletVtxo};
use crate::actions::DriveMode;
use crate::actions::board::{Board, Progress, board_action_id};
use crate::movement::update::MovementUpdate;
use crate::persist::models::PendingBoard;
use crate::subsystem::{BoardMovement, Subsystem};
use crate::vtxo::VtxoStateKind;

impl Wallet {
	/// Board a [ark::Vtxo] with the given amount.
	///
	/// NB we will spend a little more onchain to cover fees.
	///
	/// Returns an error if no onchain wallet is configured.
	pub async fn board_amount(&self, amount: Amount) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(Some(amount), user_keypair).await
	}

	/// Board a [ark::Vtxo] with all the funds in your onchain wallet.
	///
	/// Returns an error if no onchain wallet is configured.
	pub async fn board_all(&self) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(None, user_keypair).await
	}

	pub async fn pending_boards(&self) -> anyhow::Result<Vec<PendingBoard>> {
		self.boards_in_progress().await?
			.into_iter()
			.map(|b| Ok(PendingBoard {
				funding_tx: b.funding()?.clone(),
				vtxos: vec![b.vtxo_id],
				amount: b.amount,
				movement_id: b.movement_id,
			}))
			.collect()
	}

	/// Returns every in-progress board checkpoint.
	pub(crate) async fn boards_in_progress(&self) -> anyhow::Result<Vec<Board>> {
		Ok(self.inner.db.get_all_wallet_action_checkpoints().await?
			.into_iter()
			.filter_map(|cp| cp.into_board())
			.collect())
	}

	/// Queries the database for any VTXO that is an unregistered board whose funding
	/// transaction has reached the chain. There is a lag time between when a board is
	/// created and when it becomes spendable.
	///
	/// A board bark does not broadcast itself is left out until its funding
	/// transaction shows up: nothing has moved on-chain yet, and the party holding the
	/// signatures may never send it.
	///
	/// See [ark::ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub async fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let boards = self.boards_in_progress().await?;

		let mut vtxos = Vec::with_capacity(boards.len());
		for board in boards {
			// A board still in `Broadcasting` has not been seen on the network, so
			// nothing has moved and its vtxo may not even be stored yet.
			if matches!(board.progress, Progress::Broadcasting { .. }) {
				continue;
			}
			let vtxo_id = board.vtxo_id;
			let vtxo = self.get_vtxo_by_id(vtxo_id).await?;
			// We can silently filter out exited VTXOs, next time we sync they will be dropped from
			// the pending list. A spent one means the funding tx was double-spent and the board
			// action is being torn down, which will likewise drop it from the pending list.
			match vtxo.state.kind() {
				VtxoStateKind::Locked => vtxos.push(vtxo),
				VtxoStateKind::Exited | VtxoStateKind::Spent => continue,
				VtxoStateKind::Spendable => {
					warn!("Pending board VTXO {} has unexpected state: {:?}", vtxo_id, vtxo.state);
					debug_assert!(false, "all pending board vtxos should be locked, spent or exited");
				}
			}
		}

		Ok(vtxos)
	}

	/// Drives every in-progress board forward by one step or to its next park.
	///
	/// Each board is a [`Board`] wallet action that broadcasts the funding tx,
	/// waits for [ark::ArkInfo::required_board_confirmations], registers with the
	/// server, and salvages via exit near expiry. See [`crate::actions::board`].
	pub async fn sync_pending_boards(&self) -> anyhow::Result<()> {
		let pending = self.boards_in_progress().await?;
		if pending.is_empty() {
			return Ok(());
		}

		info!("Syncing {} pending boards", pending.len());
		for board in pending {
			let id = board.id();
			if let Err(e) = self.drive_action(board, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync board {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	async fn board(
		&self,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<PendingBoard> {
		let onchain = self.inner.onchain.as_ref()
			.ok_or_else(|| anyhow!("no onchain wallet configured; cannot board"))?;

		let (addr, expiry_height) = self.board_funding_address(&user_keypair).await?;
		let fee_rate = self.inner.chain.fee_rates().await.regular;

		let signed_psbt = {
			let mut wallet = onchain.write().await;
			let board_psbt = if let Some(amount) = amount {
				wallet.prepare_tx(&[(addr, amount)], fee_rate).await?
			} else {
				wallet.prepare_drain_tx(addr, fee_rate).await?
			};

			if board_psbt.inputs.len() > MAX_NB_BOARD_FUNDING_INPUTS {
				bail!("We need {} inputs to board, exceeding the limit of {}",
					board_psbt.inputs.len(), MAX_NB_BOARD_FUNDING_INPUTS,
				);
			}

			wallet.finish_psbt(board_psbt).await?
		};

		self.board_psbt(signed_psbt, user_keypair, expiry_height).await
	}

	/// Returns the funding address for a board with the given keypair.
	///
	/// The caller can use this address to build a funding transaction, then pass it
	/// to [Wallet::board_psbt] to complete the board setup.
	pub async fn board_funding_address(
		&self,
		user_keypair: &Keypair,
	) -> anyhow::Result<(Address, BlockHeight)> {
		let (_, ark_info) = self.require_server().await?;
		let properties = self.inner.db.read_properties().await?.context("Missing config")?;
		let current_height = self.inner.chain.tip().await?;

		let expiry_height = current_height + ark_info.vtxo_lifetime as BlockHeight;
		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		);

		let addr = bitcoin::Address::from_script(
			&builder.funding_script_pubkey(),
			properties.network,
		)?;

		Ok((addr, expiry_height))
	}

	#[deprecated(note = "use board_psbt instead")]
	pub async fn board_tx(
		&self,
		board_psbt: Psbt,
		user_keypair: Keypair,
		expiry_height: BlockHeight,
	) -> anyhow::Result<PendingBoard> {
		self.board_psbt(board_psbt, user_keypair, expiry_height).await
	}

	/// Board a [ark::Vtxo] from a funding PSBT.
	///
	/// The PSBT must pay to the address returned by [Wallet::board_funding_address].
	/// It may have been built anywhere: the board output is found by matching the
	/// [BoardBuilder] funding script-pubkey, so it may sit at any index alongside
	/// any other outputs.
	///
	/// Broadcasting follows from the PSBT rather than being chosen by the caller. A
	/// finalised PSBT bark broadcasts itself; an unfinalised one leaves the missing
	/// signatures, and so the broadcast, with another party, and bark waits for the
	/// transaction to appear.
	///
	/// The vtxo commits to `psbt.unsigned_tx.compute_txid()` and bark watches for
	/// nothing else, so a transaction paying the same board output under a different
	/// txid — added input, fee bump, payjoin sender falling back to its original —
	/// goes unnoticed: the board waits forever while the funds land in an output no
	/// vtxo tracks. The other party must therefore report any change, and the caller
	/// call this again with the updated PSBT and the same `user_keypair` and
	/// `expiry_height`; the abandoned board stays pending until its vtxo expires.
	///
	/// A receiver contributing its own input, signed `SIGHASH_ALL`, would bind the
	/// sender to the boarded transaction
	///
	/// Inputs that are not natively segwit gain a scriptSig when finalised, changing
	/// the txid, so a PSBT carrying one cannot be boarded here.
	pub async fn board_psbt(
		&self,
		board_psbt: Psbt,
		user_keypair: Keypair,
		expiry_height: BlockHeight,
	) -> anyhow::Result<PendingBoard> {
		let (mut srv, ark_info) = self.require_server().await?;

		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		);

		// The server caps funding inputs. `board` checks this for txs we build; a
		// tx built elsewhere has to be checked here too.
		ensure!(board_psbt.unsigned_tx.input.len() <= MAX_NB_BOARD_FUNDING_INPUTS,
			"funding tx has {} inputs, exceeding the limit of {}",
			board_psbt.unsigned_tx.input.len(), MAX_NB_BOARD_FUNDING_INPUTS,
		);

		// Locate the board output by script-pubkey rather than a fixed vout: a tx
		// built elsewhere orders its outputs freely. Ours puts it at vout 0. Paying
		// the script twice is refused rather than resolved to the first match, which
		// would board one output and leave the other tracked by nothing.
		let expected_script = builder.funding_script_pubkey();
		let mut board_outputs = board_psbt.unsigned_tx.output.iter().enumerate()
			.filter(|(_, o)| o.script_pubkey == expected_script);
		let (vout, board_output) = board_outputs.next()
			.context("PSBT output does not pay to the expected board funding address")?;
		ensure!(board_outputs.next().is_none(),
			"PSBT pays to the board funding address more than once",
		);
		let vout = vout as u32;

		let amount = board_output.value;
		ensure!(amount >= ark_info.min_board_amount,
			"board amount of {amount} is less than minimum board amount required by server ({})",
			ark_info.min_board_amount,
		);
		let fee = ark_info.fees.board.calculate(amount).context("fee overflowed")?;
		validate_and_subtract_fee(amount, fee)?;

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), vout);
		let builder = builder
			.set_funding_details(amount, fee, utxo)
			.context("error setting funding details for board")?
			.generate_user_nonces();

		let cosign_resp = srv.client.request_board_cosign(protos::BoardCosignRequest {
			amount: amount.to_sat(),
			utxo: bitcoin::consensus::serialize(&utxo), //TODO(stevenroose) change to own
			expiry_height,
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
			funding_tx: bitcoin::consensus::serialize(&board_psbt.unsigned_tx),
		}).await.context("error requesting board cosign")?
			.into_inner().try_into().context("invalid cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
				"invalid board cosignature received from server",
			);

		// Cosign and vtxo construction need the user keypair (and the funding
		// PSBT came from the on-chain wallet), neither of which the action can
		// reach. Do them here, then hand the rest of the lifecycle (store +
		// broadcast + confirm + register) to a crash-safe wallet action.
		let vtxo = builder.build_vtxo(&cosign_resp, &user_keypair)?;

		let onchain_fee = board_psbt.fee()?;
		let movement_id = self.inner.movements.new_movement_with_update(
			Subsystem::BOARD,
			BoardMovement::Board.to_string(),
			MovementUpdate::new()
				.intended_balance(amount.to_signed()?)
				.effective_balance(vtxo.amount().to_signed()?)
				.fee(fee)
				.produced_vtxo(&vtxo)
				.metadata(BoardMovement::metadata(utxo, onchain_fee)),
		).await?;

		let vtxo_id = vtxo.id();
		// The board amount net of the board fee, i.e. the vtxo value. This is
		// what `PendingBoard` has always reported (not the gross funding output).
		let vtxo_amount = vtxo.amount();

		// `Broadcasting` broadcasts only a finalised proposal, so boards bark won't
		// send start here too. `funding_tx` is never written: it exists to read
		// checkpoints from before `funding_psbt`, which a bark that predates it cannot
		// read in turn.
		let board = Board {
			id: board_action_id(utxo),
			funding_tx: None,
			funding_psbt: Some(board_psbt),
			vtxo_id,
			amount: vtxo_amount,
			movement_id,
			progress: Progress::Broadcasting { signed_vtxo: vtxo },
		};

		// Persist the checkpoint before any vtxo lock so a crash between here and
		// `drive_action` leaves something to resume (the action stores the vtxo
		// and broadcasts), rather than an orphaned lock.
		self.inner.db.upsert_wallet_action_checkpoint(&board.id, &board.clone().into()).await?;

		let pending = PendingBoard {
			funding_tx: board.funding()?.clone(),
			vtxos: vec![vtxo_id],
			amount: vtxo_amount,
			movement_id,
		};

		// The checkpoint above is durable, so the board is accepted: sync will
		// drive it to completion. The initial drive is best-effort, so don't
		// propagate its error (a retry would fund a duplicate board).
		match self.drive_action(board, DriveMode::UntilParkOrDone).await {
			Ok(()) => info!("Board accepted"),
			Err(e) => warn!("Initial board drive failed, sync will retry: {:#}", e),
		}
		Ok(pending)
	}
}

/// How far back from the block that confirms a funding transaction a board's
/// address may have been drawn: the chain's tip when the address was drawn
/// fixes the board's expiry (that tip plus the server's coin lifetime), and a
/// holder may sign the funding later than it drew the address. Two days of
/// Bitcoin blocks.
pub const BOARD_SEARCH_BLOCKS: BlockHeight = 288;

/// How many unrevealed vtxo keys past the last one this store revealed a board
/// search tries: a board's key is the store's next key when its address was
/// drawn, and a lost store may have drawn several since the last one another
/// store of the phrase learned of.
pub const BOARD_SEARCH_KEYS: u32 = 100;

/// The outputs a board search matched to no board, by wallet and by the
/// number of keys it tried: a wallet that catches up every few minutes
/// searches each output once while it runs, and again once it tries more keys.
static SEARCHED: Mutex<Option<HashMap<(bitcoin::bip32::Fingerprint, u32), HashSet<OutPoint>>>> = Mutex::new(None);

/// A board funding output found on the chain by [Wallet::recover_boards].
#[derive(Debug, Clone)]
pub struct FoundBoard {
	pub funding: OutPoint,
	pub amount: Amount,
	pub key_index: u32,
	pub expiry_height: BlockHeight,
	/// The coin, once the wallet holds it (adopted or recovered).
	pub vtxo: Option<VtxoId>,
	/// `adopted` (cosigned again and followed to its registration),
	/// `recovered` (registered before, taken from the server), or why it was
	/// left: `spent` (in the ark or on the chain), `expired`, or the error.
	pub outcome: String,
}

impl Wallet {
	/// Finds, among `txs`, the funding of boards of this phrase that no store
	/// of it registered, and takes each in.
	///
	/// A board's coin is posted to the phrase's recovery mailbox only once the
	/// store that made it registers it, after its funding's confirmations, so
	/// a store lost in between leaves a coin nothing else of the phrase can
	/// find from the server. Its funding is on the chain, paid by the coins of
	/// whoever funded it: given the transactions those coins made (a
	/// dual-chain wallet's own Bitcoin account), this rebuilds each board
	/// script from the phrase's vtxo keys and the expiries the board could
	/// have had (the tip when its address was drawn, [BOARD_SEARCH_BLOCKS]
	/// back from its confirmation, plus the server's coin lifetime), and for
	/// each unspent output that matches one, asks the server to cosign it
	/// again and follows it to its registration as [Wallet::board_psbt] does.
	/// A board the server already registered is taken from the server
	/// instead, and one the server says is spent is left.
	///
	/// Outputs of coins the store already holds are skipped, and so is an
	/// output this program already searched with the same keys, so the call
	/// is cheap to repeat. A board made under another server coin lifetime
	/// than the current one is not found.
	pub async fn recover_boards(
		&self,
		txs: impl IntoIterator<Item = Transaction>,
	) -> anyhow::Result<Vec<FoundBoard>> {
		let (_, ark_info) = self.require_server().await?;
		let tip = self.inner.chain.tip().await?;

		// Funding outputs this store already knows.
		let mut known = HashSet::<OutPoint>::new();
		for v in self.inner.db.get_all_vtxos().await? {
			known.insert(v.vtxo.chain_anchor());
		}
		for b in self.boards_in_progress().await? {
			if let Ok(txid) = b.funding_txid() {
				if let Ok(tx) = b.funding() {
					for vout in 0..tx.output.len() {
						known.insert(OutPoint::new(txid, vout as u32));
					}
				}
			}
		}

		// The keys to try: every one revealed and [BOARD_SEARCH_KEYS] past
		// the last.
		let last = self.inner.db.get_last_vtxo_key_index().await?;
		let top = last.map(|i| i.saturating_add(1)).unwrap_or(0).saturating_add(BOARD_SEARCH_KEYS);
		let cache_key = (self.fingerprint(), top);
		let searched = SEARCHED.lock().unwrap().as_ref().and_then(|m| m.get(&cache_key).cloned()).unwrap_or_default();

		// Candidate outputs: taproot, at least the server's least board.
		let mut seen = HashSet::<Txid>::new();
		let mut candidates = Vec::<(Transaction, u32)>::new();
		for tx in txs {
			let txid = tx.compute_txid();
			if !seen.insert(txid) {
				continue;
			}
			for (vout, out) in tx.output.iter().enumerate() {
				let op = OutPoint::new(txid, vout as u32);
				if out.script_pubkey.is_p2tr() && out.value >= ark_info.min_board_amount && !known.contains(&op)
					&& !searched.contains(&op)
				{
					candidates.push((tx.clone(), vout as u32));
				}
			}
		}
		if candidates.is_empty() {
			return Ok(vec![]);
		}

		// Each key combined with the server's.
		let keys = (0..top).map(|i| {
			let pk = self.inner.seed.derive_vtxo_keypair(i).public_key();
			let agg = musig::combine_keys([pk, ark_info.server_pubkey]).x_only_public_key().0;
			(i, pk, agg)
		}).collect::<Vec<_>>();
		let lifetime = ark_info.vtxo_lifetime as BlockHeight;

		let mut out = vec![];
		for (tx, vout) in candidates {
			let txid = tx.compute_txid();
			let op = OutPoint::new(txid, vout);
			let spk = &tx.output[vout as usize].script_pubkey;
			// The tip the board's address was drawn at is before the block
			// that confirms it; one still in the mempool, before the next.
			let confirmed = match self.inner.chain.tx_status(txid).await {
				Ok(TxStatus::Confirmed(b)) => b.height,
				Ok(TxStatus::Mempool) => tip.saturating_add(1),
				_ => continue,
			};
			let Some((index, expiry)) = match_board_script(spk, &keys, ark_info.server_pubkey,
				confirmed, lifetime) else {
				SEARCHED.lock().unwrap().get_or_insert_with(HashMap::new).entry(cache_key).or_default().insert(op);
				continue;
			};
			let amount = tx.output[vout as usize].value;
			let mut found = FoundBoard {
				funding: op, amount, key_index: index, expiry_height: expiry, vtxo: None, outcome: String::new(),
			};
			found.outcome = match self.take_found_board(&tx, vout, index, expiry, tip, &ark_info).await {
				Ok((outcome, vtxo)) => {
					found.vtxo = vtxo;
					outcome
				},
				Err(e) => format!("{:#}", e),
			};
			info!("Board funding {} of {} (key {}, expiry {}) found on the chain: {}",
				op, amount, index, expiry, found.outcome);
			out.push(found);
		}
		Ok(out)
	}

	async fn take_found_board(
		&self,
		tx: &Transaction,
		vout: u32,
		index: u32,
		expiry: BlockHeight,
		tip: BlockHeight,
		ark_info: &ark::ArkInfo,
	) -> anyhow::Result<(String, Option<VtxoId>)> {
		let txid = tx.compute_txid();
		let op = OutPoint::new(txid, vout);
		if expiry <= tip {
			return Ok(("expired".into(), None));
		}
		if self.inner.chain.outpoint_spent_confirmed(op).await? {
			return Ok(("spent".into(), None));
		}

		// Reveal the key, and every one below it: the wallet issues keys in
		// sequence.
		let keypair = self.inner.seed.derive_vtxo_keypair(index);
		let first = self.inner.db.get_last_vtxo_key_index().await?.map(|i| i + 1).unwrap_or(0);
		for i in first..=index {
			let pk = self.inner.seed.derive_vtxo_keypair(i).public_key();
			self.inner.db.store_vtxo_key(i, pk).await?;
		}

		// The coin's id is fixed by the funding and the board's terms, so the
		// server can say whether it knows it before anything is signed.
		let amount = tx.output[vout as usize].value;
		let fee = ark_info.fees.board.calculate(amount).context("fee overflowed")?;
		let builder = BoardBuilder::new(keypair.public_key(), expiry, ark_info.server_pubkey, ark_info.vtxo_exit_delta)
			.set_funding_details(amount, fee, op)
			.context("error setting funding details for board")?;
		let vtxo_id = VtxoId::from(OutPoint::new(builder.exit_tx().compute_txid(), 0));
		match self.fetch_vtxo_spend_state(vtxo_id, &keypair).await {
			Ok(VtxoSpendState::Spendable) => {
				let r = self.recover_vtxos([vtxo_id], None).await?;
				if r.recovered().ids().any(|i| i == vtxo_id) {
					return Ok(("recovered".into(), Some(vtxo_id)));
				}
				return Ok((format!("registered, not recovered: {:?}", r), None));
			},
			Ok(VtxoSpendState::Spent) => return Ok(("spent".into(), None)),
			Ok(VtxoSpendState::Unregistered) | Ok(VtxoSpendState::Unspecified) | Err(_) => {},
			Ok(other) => return Ok((format!("left: the server says {:?}", other), None)),
		}

		// The funding as a proposal: its signatures are already on the chain.
		let mut unsigned = tx.clone();
		for i in unsigned.input.iter_mut() {
			i.script_sig = ScriptBuf::new();
			i.witness = bitcoin::Witness::new();
		}
		let mut psbt = Psbt::from_unsigned_tx(unsigned).context("funding tx as a PSBT")?;
		for (i, inp) in tx.input.iter().enumerate() {
			let prev = self.inner.chain.get_tx(&inp.previous_output.txid).await?
				.with_context(|| format!("funding input {} not found", inp.previous_output))?;
			let utxo = prev.output.get(inp.previous_output.vout as usize).cloned()
				.with_context(|| format!("funding input {} has no such output", inp.previous_output))?;
			psbt.inputs[i].witness_utxo = Some(utxo);
		}
		let pending = self.board_psbt(psbt, keypair, expiry).await?;
		if pending.vtxos.first() != Some(&vtxo_id) {
			warn!("Board {} adopted as {:?}, not the {} computed", op, pending.vtxos, vtxo_id);
		}
		Ok(("adopted".into(), pending.vtxos.first().copied()))
	}
}

/// The vtxo key index and expiry whose board script is `spk`, trying the
/// expiries a board confirmed at `confirmed` can have, the likeliest first.
fn match_board_script(
	spk: &ScriptBuf,
	keys: &[(u32, PublicKey, bitcoin::XOnlyPublicKey)],
	server_pubkey: PublicKey,
	confirmed: BlockHeight,
	lifetime: BlockHeight,
) -> Option<(u32, BlockHeight)> {
	let latest = confirmed.saturating_sub(1);
	for back in 0..=BOARD_SEARCH_BLOCKS {
		let Some(drawn) = latest.checked_sub(back) else { break };
		let expiry = drawn.saturating_add(lifetime);
		for (index, _, agg) in keys {
			if &ScriptBuf::new_p2tr_tweaked(cosign_taproot(*agg, server_pubkey, expiry).output_key()) == spk {
				debug!("Board script matched key {} expiry {}", index, expiry);
				return Some((*index, expiry));
			}
		}
	}
	None
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use bitcoin::Network;

	use super::*;

	fn keys(n: u32, server: PublicKey) -> Vec<(u32, PublicKey, bitcoin::XOnlyPublicKey)> {
		let m = bip39::Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
		let seed = crate::WalletSeed::new_from_mnemonic(Network::Regtest, &m);
		(0..n).map(|i| {
			let pk = seed.derive_vtxo_keypair(i).public_key();
			(i, pk, musig::combine_keys([pk, server]).x_only_public_key().0)
		}).collect()
	}

	/// A board's script names its key and expiry back: the board drawn at the
	/// tip before its confirmation, and one drawn a day earlier; a script no
	/// key of the phrase made matches nothing, after the whole search.
	#[test]
	fn a_board_script_is_found_from_the_phrase_alone() {
		let server = bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[7u8; 32]).unwrap().public_key();
		let keys = keys(BOARD_SEARCH_KEYS + 1, server);
		let lifetime = 4032;
		let script = |i: usize, expiry: BlockHeight| ScriptBuf::new_p2tr_tweaked(cosign_taproot(keys[i].2, server, expiry).output_key());

		// Drawn at 158402, confirmed at 158403.
		assert_eq!(match_board_script(&script(3, 158_402 + lifetime), &keys, server, 158_403, lifetime), Some((3, 158_402 + lifetime)));
		// Drawn a day before its confirmation, under the last key tried.
		let last = BOARD_SEARCH_KEYS as usize;
		assert_eq!(match_board_script(&script(last, 158_258 + lifetime), &keys, server, 158_403, lifetime),
			Some((last as u32, 158_258 + lifetime)));
		// Drawn before the window: not found.
		assert_eq!(match_board_script(&script(3, 158_402 - BOARD_SEARCH_BLOCKS - 1 + lifetime), &keys, server, 158_403, lifetime), None);

		let other = bitcoin::secp256k1::Keypair::from_seckey_slice(&ark::SECP, &[9u8; 32]).unwrap().public_key();
		let foreign = ScriptBuf::new_p2tr_tweaked(cosign_taproot(musig::combine_keys([other, server]).x_only_public_key().0,
			server, 158_402 + lifetime).output_key());
		let t = std::time::Instant::now();
		assert_eq!(match_board_script(&foreign, &keys, server, 158_403, lifetime), None);
		println!("a whole search ({} keys, {} expiries): {:?}", keys.len(), BOARD_SEARCH_BLOCKS + 1, t.elapsed());
	}
}
