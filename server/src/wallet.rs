//! The operator's on-chain wallet, on the Sequentia Wallet Kit.
//!
//! The wallet's keys come from a BIP39 mnemonic through the kit's software
//! signer (`lwk_signer::SwSigner`), at `m/84'/1'/0'/<chain>/<index>`: chain 0
//! for the scripts it hands out to be paid, chain 1 for change. Each is a
//! P2WPKH script, unblinded. The kit signs every input of the transactions
//! the wallet builds, through its PSET signer.
//!
//! The wallet finds its coins as the finality service connects blocks: every
//! explicit output paying one of its scripts, per asset, and none that hides
//! its asset or value (those are recorded as refused: the server is
//! transparent at its boundary). A coin whose block is disconnected is not in
//! the chain again until its transaction is; the wallet spends a coin only once
//! the finality service says its transaction is final, unless told otherwise.
//!
//! Every transaction the wallet builds is built by hand and names its fee
//! asset. There is no default and no fallback: an asset the node does not
//! accept for fees now is refused, and so is one the wallet holds too little
//! of. The fee is in the fee asset's own atoms, priced from the node's relay
//! floor and its exchange rate for that asset, at the moment of building. No
//! asset is assumed, the policy asset included: a wallet that holds none of
//! it builds every transaction in whatever accepted asset it holds.
//!
//! A round-shaped transaction carries the round's connector output
//! ([`arca_covenant::ConnectorPolicy`]) right after the outputs it pays.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use elements::bitcoin::bip32::{DerivationPath, Fingerprint};
use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash};
use lwk_common::Signer as _;
use lwk_signer::SwSigner;
use tokio::sync::Mutex;

use arca_covenant::{ConnectorPolicy, ExplicitOutput};
use sequentia_ext::{explicit_txout, fee_txout, AssetAmount};

use crate::chain::{ChainError, Finality, FinalityService};
use crate::store::{Store, StoreError, WalletCoin};

/// The wallet's derivation chains.
pub const RECEIVE: u8 = 0;
pub const CHANGE: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error(transparent)]
	Chain(#[from] ChainError),
	#[error("the wallet's keys: {0}")]
	Keys(String),
	#[error("asset {0} is not accepted for fees by the node now; the wallet pays fees in no other asset than the one named")]
	FeeAssetNotAccepted(AssetId),
	#[error("the wallet holds {have} of asset {asset} that it can spend, and needs {need}")]
	Insufficient { asset: AssetId, need: u64, have: u64 },
	#[error("a transaction pays nothing")]
	Empty,
	#[error("an output of {0} atoms: every output carries value")]
	ZeroOutput(AssetId),
	#[error("the kit's signer signed {signed} of {inputs} inputs")]
	Signing { signed: u32, inputs: usize },
	#[error("another transaction took a coin this one chose; build it again")]
	Raced,
	#[error("the finality service: {0}")]
	Finality(String),
}

/// How spendable a coin must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendFrom {
	/// Its transaction is final: certified, and the anchor buried.
	Final,
	/// Its transaction is in a block of the active chain.
	Confirmed,
}

#[derive(Debug, Clone)]
pub struct WalletConfig {
	/// The BIP39 mnemonic the wallet's keys come from.
	pub mnemonic: String,
	/// The multiple of the node's relay floor the wallet pays.
	pub fee_multiple: u64,
	pub spend_from: SpendFrom,
}

/// What to build.
#[derive(Debug, Clone)]
pub struct BuildRequest {
	/// The outputs to pay, at indices `0..n`.
	pub outputs: Vec<ExplicitOutput>,
	/// For a round-shaped transaction: the connector output, holding this
	/// amount, at index `n`.
	pub connector: Option<AssetAmount>,
	/// The asset the fee is paid in. Named every time.
	pub fee_asset: AssetId,
}

/// A transaction the wallet built and signed, not yet broadcast.
#[derive(Debug, Clone)]
pub struct Built {
	pub tx: Transaction,
	pub fee: AssetAmount,
	/// The connector output's index, in a round-shaped transaction.
	pub connector_vout: Option<u32>,
	/// The coins it spends.
	pub spent: Vec<OutPoint>,
}

/// See the [module documentation](self).
pub struct Wallet {
	store: Store,
	finality: Arc<FinalityService>,
	signer: SwSigner,
	fingerprint: Fingerprint,
	/// The operator key `S`, which the connector output names.
	operator: XOnlyPublicKey,
	config: WalletConfig,
	/// One build at a time, so two never choose the same coin.
	building: Mutex<()>,
}

/// The size, in bytes, of a P2WPKH witness with a low-R signature: what the
/// fee is sized for before the transaction is signed.
const DUMMY_SIG: usize = 72;

impl Wallet {
	pub fn new(store: Store, finality: Arc<FinalityService>, operator: XOnlyPublicKey, config: WalletConfig)
		-> Result<Wallet, WalletError>
	{
		let signer = SwSigner::new(&config.mnemonic, false).map_err(|e| WalletError::Keys(e.to_string()))?;
		let fingerprint = signer.fingerprint();
		Ok(Wallet { store, finality, signer, fingerprint, operator, config, building: Mutex::new(()) })
	}

	fn path(chain: u8, index: u32) -> DerivationPath {
		DerivationPath::from_str(&format!("m/84h/1h/0h/{}/{}", chain, index)).expect("a valid path")
	}

	/// The public key at `chain`/`index`.
	fn public_key(&self, chain: u8, index: u32) -> Result<elements::bitcoin::PublicKey, WalletError> {
		let xprv = self.signer.derive_xprv(&Self::path(chain, index)).map_err(|e| WalletError::Keys(e.to_string()))?;
		let secp = elements::bitcoin::secp256k1::Secp256k1::new();
		Ok(elements::bitcoin::PublicKey::new(xprv.private_key.public_key(&secp)))
	}

	fn script(pk: &elements::bitcoin::PublicKey) -> Script {
		Script::new_v0_wpkh(&WPubkeyHash::hash(&pk.to_bytes()))
	}

	/// A new script of the wallet's on `chain`, recorded so the scan finds
	/// what pays it.
	async fn new_script(&self, chain: u8) -> Result<Script, WalletError> {
		let index = self.store.next_wallet_index(chain).await?;
		let script = Self::script(&self.public_key(chain, index)?);
		self.store.add_wallet_key(chain, index, script.as_bytes()).await?;
		Ok(script)
	}

	/// A script to pay the wallet: an explicit output to it becomes a coin.
	pub async fn receive_script(&self) -> Result<Script, WalletError> {
		self.new_script(RECEIVE).await
	}

	/// Whether a coin is spendable under the configuration.
	async fn spendable(&self, c: &WalletCoin) -> Result<bool, WalletError> {
		if !c.in_chain || c.spent_by.is_some() {
			return Ok(false);
		}
		let status = self.finality.status(&Txid::from_byte_array(c.txid)).await
			.map_err(|e| WalletError::Finality(e.to_string()))?;
		Ok(match self.config.spend_from {
			SpendFrom::Final => status.is_final(),
			SpendFrom::Confirmed => status.in_chain(),
		})
	}

	/// What the wallet can spend now, per asset.
	pub async fn balance(&self) -> Result<BTreeMap<AssetId, u64>, WalletError> {
		let mut b = BTreeMap::new();
		for c in self.store.wallet_coins(None).await? {
			if self.spendable(&c).await? {
				*b.entry(AssetId::from_byte_array(c.asset)).or_insert(0) += c.value;
			}
		}
		Ok(b)
	}

	/// The fee for `vsize` vbytes in `asset`'s own atoms, from the node's relay
	/// floor and its rate for `asset` now; the asset must be accepted.
	async fn fee_for(&self, asset: AssetId, vsize: u64) -> Result<u64, WalletError> {
		let rates = self.finality.call(|c| c.fee_rates()).await?;
		let rate = match rates.get(&asset) {
			Some(r) if *r > 0 => *r as u128,
			_ => return Err(WalletError::FeeAssetNotAccepted(asset)),
		};
		let floor = self.finality.call(|c| c.relay_floor_per_kvb()).await? as u128;
		// The node values a fee of `a` atoms at a × rate / 10^8 reference
		// units and wants floor × vsize / 1000 of them.
		let value = (floor * vsize as u128).div_ceil(1000);
		let atoms = (value * 100_000_000).div_ceil(rate) * self.config.fee_multiple.max(1) as u128;
		Ok(atoms.max(1) as u64)
	}

	/// Builds and signs the transaction `req` asks for: see the [module
	/// documentation](self). The coins it spends are marked spent by it before
	/// it is returned; a transaction that is never broadcast must have them
	/// released ([`Wallet::release`]).
	pub async fn build(&self, req: &BuildRequest) -> Result<Built, WalletError> {
		if req.outputs.is_empty() && req.connector.is_none() {
			return Err(WalletError::Empty);
		}
		for o in &req.outputs {
			if o.value == 0 {
				return Err(WalletError::ZeroOutput(o.asset));
			}
		}
		// Refuse an asset the node does not accept before anything else.
		self.fee_for(req.fee_asset, 1).await?;

		let _one = self.building.lock().await;
		let mut outputs: Vec<TxOut> = req.outputs.iter().map(|o| o.txout()).collect();
		let connector_vout = req.connector.map(|c| {
			outputs.push(ConnectorPolicy { operator: self.operator }.output(c.asset, c.amount).txout());
			(outputs.len() - 1) as u32
		});

		// What each asset must cover, the fee aside.
		let mut need: BTreeMap<AssetId, u64> = BTreeMap::new();
		for o in &outputs {
			let a = o.asset.explicit().expect("explicit");
			*need.entry(a).or_insert(0) += o.value.explicit().expect("explicit");
		}
		need.entry(req.fee_asset).or_insert(0);

		// The spendable coins of every asset involved.
		let mut available: BTreeMap<AssetId, Vec<WalletCoin>> = BTreeMap::new();
		for a in need.keys() {
			let mut coins = vec![];
			for c in self.store.wallet_coins(Some(&a.into_inner().to_byte_array())).await? {
				if self.spendable(&c).await? {
					coins.push(c);
				}
			}
			available.insert(*a, coins);
		}

		// Choose coins and size the fee until they agree. A fee is never
		// zero, so the fee asset always gives at least one coin.
		let mut fee = self.fee_for(req.fee_asset, 1).await?;
		let mut change_scripts: BTreeMap<AssetId, Script> = BTreeMap::new();
		loop {
			let mut chosen: Vec<WalletCoin> = vec![];
			for (a, amount) in &need {
				let want = amount + if *a == req.fee_asset { fee } else { 0 };
				let coins = &available[a];
				let mut sum = 0u64;
				for c in coins {
					if sum >= want {
						break;
					}
					sum += c.value;
					chosen.push(c.clone());
				}
				if sum < want {
					return Err(WalletError::Insufficient { asset: *a, need: want, have: coins.iter().map(|c| c.value).sum() });
				}
			}
			let (tx, paid) = self.assemble(&chosen, &outputs, req.fee_asset, fee, &mut change_scripts).await?;
			let vsize = Self::signed_vsize(&tx);
			let needed = self.fee_for(req.fee_asset, vsize).await?;
			if needed <= paid {
				let mut tx = tx;
				self.sign(&mut tx, &chosen).await?;
				let txid = tx.txid();
				let spent: Vec<([u8; 32], u32)> = chosen.iter().map(|c| (c.txid, c.vout)).collect();
				if !self.store.spend_wallet_coins(&spent, &txid.to_byte_array()).await? {
					return Err(WalletError::Raced);
				}
				let fee = paid;
				return Ok(Built {
					tx,
					fee: AssetAmount::new(req.fee_asset, fee),
					connector_vout,
					spent: chosen.iter().map(|c| OutPoint::new(Txid::from_byte_array(c.txid), c.vout)).collect(),
				});
			}
			fee = needed;
		}
	}

	/// The unsigned transaction: `coins` in, `outputs`, then change per
	/// asset to the wallet's change scripts, then the fee output. Change in
	/// the fee asset smaller than the fee goes to the fee rather than make
	/// an output too small to relay. Returns the fee it pays.
	async fn assemble(&self, coins: &[WalletCoin], outputs: &[TxOut], fee_asset: AssetId, fee: u64,
		change_scripts: &mut BTreeMap<AssetId, Script>) -> Result<(Transaction, u64), WalletError>
	{
		let mut held: BTreeMap<AssetId, u64> = BTreeMap::new();
		for c in coins {
			*held.entry(AssetId::from_byte_array(c.asset)).or_insert(0) += c.value;
		}
		for o in outputs {
			let a = o.asset.explicit().expect("explicit");
			*held.get_mut(&a).expect("chosen for every asset") -= o.value.explicit().expect("explicit");
		}
		*held.get_mut(&fee_asset).expect("chosen for the fee asset") -= fee;
		let mut paid = fee;
		let mut all = outputs.to_vec();
		for (a, left) in held {
			if a == fee_asset && left < fee {
				paid += left;
				continue;
			}
			if left > 0 {
				let script = match change_scripts.get(&a) {
					Some(s) => s.clone(),
					None => {
						let s = self.new_script(CHANGE).await?;
						change_scripts.insert(a, s.clone());
						s
					},
				};
				all.push(explicit_txout(AssetAmount::new(a, left), script));
			}
		}
		all.push(fee_txout(AssetAmount::new(fee_asset, paid)));
		let tx = Transaction {
			version: 2,
			lock_time: LockTime::ZERO,
			input: coins.iter().map(|c| TxIn {
				previous_output: OutPoint::new(Txid::from_byte_array(c.txid), c.vout),
				sequence: Sequence::MAX,
				..Default::default()
			}).collect(),
			output: all,
		};
		Ok((tx, paid))
	}

	/// The virtual size `tx` will have once every input carries its
	/// signature and key.
	fn signed_vsize(tx: &Transaction) -> u64 {
		let mut t = tx.clone();
		for i in &mut t.input {
			i.witness.script_witness = vec![vec![0; DUMMY_SIG], vec![0; 33]];
		}
		(t.weight() as u64).div_ceil(4)
	}

	/// Signs every input through the kit's PSET signer.
	async fn sign(&self, tx: &mut Transaction, coins: &[WalletCoin]) -> Result<(), WalletError> {
		let mut pset = PartiallySignedTransaction::from_tx(tx.clone());
		let mut keys = vec![];
		for (i, c) in coins.iter().enumerate() {
			let pk = self.public_key(c.chain, c.index)?;
			let input = &mut pset.inputs_mut()[i];
			input.witness_utxo = Some(explicit_txout(
				AssetAmount::new(AssetId::from_byte_array(c.asset), c.value), Script::from(c.script_pubkey.clone()),
			));
			input.bip32_derivation.insert(pk, (self.fingerprint, Self::path(c.chain, c.index)));
			keys.push(pk);
		}
		let signed = self.signer.sign(&mut pset).map_err(|e| WalletError::Keys(e.to_string()))?;
		if signed as usize != coins.len() {
			return Err(WalletError::Signing { signed, inputs: coins.len() });
		}
		for (i, pk) in keys.iter().enumerate() {
			let sig = pset.inputs()[i].partial_sigs.get(pk).cloned()
				.ok_or(WalletError::Signing { signed, inputs: coins.len() })?;
			tx.input[i].witness.script_witness = vec![sig, pk.to_bytes()];
		}
		Ok(())
	}

	/// Frees the coins a built transaction took, once it will never be
	/// broadcast or can never confirm.
	pub async fn release(&self, txid: &Txid) -> Result<u64, WalletError> {
		Ok(self.store.release_wallet_coins(&txid.to_byte_array()).await?)
	}

	/// Where a coin's transaction stands, for reports.
	pub async fn coin_finality(&self, c: &WalletCoin) -> Result<Finality, WalletError> {
		self.finality.status(&Txid::from_byte_array(c.txid)).await.map_err(|e| WalletError::Finality(e.to_string()))
	}
}
