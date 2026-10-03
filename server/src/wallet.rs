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
//! ([`arca_covenant::ConnectorPolicy`]) right after the outputs it pays. A
//! round transaction ([`Wallet::build_round`]) also issues each batch's sweep
//! token, one explicit atom with no reissuance token, from one of the
//! wallet's own coins per batch.
//!
//! The watcher builds transactions the wallet did not build (a forfeit, a
//! claim, a release, a sweep), and a coin of the wallet may pay their fee
//! ([`Wallet::with_fee_coin`]) or hold a round's connector asset. The wallet
//! signs its own input of such a transaction itself
//! ([`Wallet::sign_input`]), with the key the kit derives, over the
//! transaction's segwit v0 signature hash as rust-elements computes it from the
//! transaction itself: the kit's PSET signer re-encodes an input's issuance
//! (its index and denomination) before it signs, which would sign another
//! transaction than one that issues a connector asset.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use elements::bitcoin::bip32::{DerivationPath, Fingerprint};
use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{confidential, AssetId, AssetIssuance, ContractHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash};
use lwk_common::Signer as _;
use lwk_signer::SwSigner;
use tokio::sync::Mutex;

use arca_covenant::spend::FeeSource;
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
	#[error("a round of {need} batches needs {need} spendable coins to issue their tokens; the wallet has {have}")]
	TooFewCoins { need: usize, have: usize },
	#[error("the round's outputs: {0}")]
	Round(String),
	#[error("the transaction a fee coin pays for: {0}")]
	Build(String),
	#[error("no asset of {0} is both accepted for fees by the node now and held by the wallet in a coin that covers the fee")]
	NoFeeCoin(String),
	#[error("input {0} does not spend the coin it is signed for")]
	WrongInput(usize),
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

/// The sweep token a wallet coin issues in a round: the asset its outpoint
/// issues with a zero contract hash.
pub fn token_of(c: &WalletCoin) -> AssetId {
	AssetId::new_issuance(OutPoint::new(Txid::from_byte_array(c.txid), c.vout), ContractHash::from_byte_array([0; 32]))
}

/// The denomination a sweep token is issued with. It is not part of what a
/// wallet checks of the token, and the kit's PSET signs every issuance as 8.
pub const TOKEN_DENOMINATION: u8 = 8;

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
		// Refuse an asset the node does not accept before anything else.
		self.fee_for(req.fee_asset, 1).await?;
		let _one = self.building.lock().await;
		self.build_locked(&req.outputs, req.connector, req.fee_asset, &[]).await
	}

	/// Builds and signs a round transaction that creates `batches` batches.
	/// The wallet chooses one of its spendable coins per batch, each of which
	/// issues one explicit atom of a new asset, with a zero contract hash and
	/// no reissuance token: that batch's sweep token, whose id follows from the
	/// coin's outpoint. `make` is given the tokens, in that order, and returns
	/// the outputs to pay (each token exactly once, as one atom) and whatever
	/// else it made of them; the connector output follows those outputs, then
	/// change per asset, then the one fee output, in `fee_asset`. The issuing
	/// coins are the first inputs, in the order of the tokens. The lock time is
	/// 0 and every input final, so the transaction can always return to the
	/// mempool unchanged after a rollback.
	pub async fn build_round<R, F>(&self, batches: usize, fee_asset: AssetId, connector: AssetAmount, make: F)
		-> Result<(Built, R), WalletError>
	where
		F: FnOnce(&[AssetId]) -> Result<(Vec<ExplicitOutput>, R), String>,
	{
		self.fee_for(fee_asset, 1).await?;
		let _one = self.building.lock().await;
		// A connector asset's atom is the watcher's, for its claims and
		// reclaims: it never issues a token.
		let connectors = self.store.connector_assets().await?;
		let mut coins = vec![];
		for c in self.store.wallet_coins(None).await? {
			if !connectors.contains(&c.asset) && self.spendable(&c).await? {
				coins.push(c);
			}
		}
		if coins.len() < batches {
			return Err(WalletError::TooFewCoins { need: batches, have: coins.len() });
		}
		// The fee asset's coins first, the largest first: an issuing coin's
		// value goes on to pay the round like any other.
		let fee = fee_asset.into_inner().to_byte_array();
		coins.sort_by(|a, b| (b.asset == fee).cmp(&(a.asset == fee)).then(b.value.cmp(&a.value)).then(a.txid.cmp(&b.txid)).then(a.vout.cmp(&b.vout)));
		let issuers: Vec<WalletCoin> = coins.into_iter().take(batches).collect();
		let tokens: Vec<AssetId> = issuers.iter().map(token_of).collect();
		let (outputs, made) = make(&tokens).map_err(WalletError::Round)?;
		for t in &tokens {
			let held: Vec<&ExplicitOutput> = outputs.iter().filter(|o| o.asset == *t).collect();
			if held.len() != 1 || held[0].value != 1 {
				return Err(WalletError::Round(format!("the token {} must be paid once, as one atom", t)));
			}
		}
		let built = self.build_locked(&outputs, Some(connector), fee_asset, &issuers).await?;
		Ok((built, made))
	}

	/// Builds and signs, the build lock held: `issuers` are the first inputs,
	/// each issuing one atom of its token ([`token_of`]).
	async fn build_locked(&self, outputs_req: &[ExplicitOutput], connector: Option<AssetAmount>, fee_asset: AssetId,
		issuers: &[WalletCoin]) -> Result<Built, WalletError>
	{
		for o in outputs_req {
			if o.value == 0 {
				return Err(WalletError::ZeroOutput(o.asset));
			}
		}
		let issued: Vec<AssetId> = issuers.iter().map(token_of).collect();
		let mut outputs: Vec<TxOut> = outputs_req.iter().map(|o| o.txout()).collect();
		let connector_vout = connector.map(|c| {
			outputs.push(ConnectorPolicy { operator: self.operator }.output(c.asset, c.amount).txout());
			(outputs.len() - 1) as u32
		});

		// What each asset must cover, the fee aside; the tokens the issuing
		// inputs create cover themselves.
		let mut need: BTreeMap<AssetId, u64> = BTreeMap::new();
		for o in &outputs {
			let a = o.asset.explicit().expect("explicit");
			if !issued.contains(&a) {
				*need.entry(a).or_insert(0) += o.value.explicit().expect("explicit");
			}
		}
		need.entry(fee_asset).or_insert(0);

		// The spendable coins of every asset involved, the issuers apart.
		let taken: Vec<([u8; 32], u32)> = issuers.iter().map(|c| (c.txid, c.vout)).collect();
		let mut available: BTreeMap<AssetId, Vec<WalletCoin>> = BTreeMap::new();
		for a in need.keys() {
			let mut coins = vec![];
			for c in self.store.wallet_coins(Some(&a.into_inner().to_byte_array())).await? {
				if !taken.contains(&(c.txid, c.vout)) && self.spendable(&c).await? {
					coins.push(c);
				}
			}
			available.insert(*a, coins);
		}

		// Choose coins and size the fee until they agree. A fee is never
		// zero, so the fee asset always gives at least one coin.
		let mut fee = self.fee_for(fee_asset, 1).await?;
		let mut change_scripts: BTreeMap<AssetId, Script> = BTreeMap::new();
		loop {
			let mut chosen: Vec<WalletCoin> = issuers.to_vec();
			for (a, amount) in &need {
				let want = amount + if *a == fee_asset { fee } else { 0 };
				let mut sum: u64 = issuers.iter().filter(|c| AssetId::from_byte_array(c.asset) == *a).map(|c| c.value).sum();
				let coins = &available[a];
				for c in coins {
					if sum >= want {
						break;
					}
					sum += c.value;
					chosen.push(c.clone());
				}
				if sum < want {
					let have = sum.max(coins.iter().map(|c| c.value).sum());
					return Err(WalletError::Insufficient { asset: *a, need: want, have });
				}
			}
			let (tx, paid) = self.assemble(&chosen, issuers.len(), &outputs, fee_asset, fee, &mut change_scripts).await?;
			let vsize = Self::signed_vsize(&tx);
			let needed = self.fee_for(fee_asset, vsize).await?;
			if needed <= paid {
				let mut tx = tx;
				self.sign(&mut tx, &chosen).await?;
				let txid = tx.txid();
				let spent: Vec<([u8; 32], u32)> = chosen.iter().map(|c| (c.txid, c.vout)).collect();
				if !self.store.spend_wallet_coins(&spent, &txid.to_byte_array()).await? {
					return Err(WalletError::Raced);
				}
				return Ok(Built {
					tx,
					fee: AssetAmount::new(fee_asset, paid),
					connector_vout,
					spent: chosen.iter().map(|c| OutPoint::new(Txid::from_byte_array(c.txid), c.vout)).collect(),
				});
			}
			fee = needed;
		}
	}

	/// The unsigned transaction: `coins` in, the first `issuing` of them each
	/// issuing one atom of its token, `outputs`, then change per asset to the
	/// wallet's change scripts, then the fee output. Change in the fee asset
	/// smaller than the fee goes to the fee rather than make an output too
	/// small to relay. Returns the fee it pays.
	async fn assemble(&self, coins: &[WalletCoin], issuing: usize, outputs: &[TxOut], fee_asset: AssetId, fee: u64,
		change_scripts: &mut BTreeMap<AssetId, Script>) -> Result<(Transaction, u64), WalletError>
	{
		let mut held: BTreeMap<AssetId, u64> = BTreeMap::new();
		for c in coins {
			*held.entry(AssetId::from_byte_array(c.asset)).or_insert(0) += c.value;
		}
		for c in &coins[..issuing] {
			*held.entry(token_of(c)).or_insert(0) += 1;
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
			input: coins.iter().enumerate().map(|(i, c)| {
				let mut input = TxIn {
					previous_output: OutPoint::new(Txid::from_byte_array(c.txid), c.vout),
					sequence: Sequence::MAX,
					..Default::default()
				};
				if i < issuing {
					input.asset_issuance = AssetIssuance {
						asset_blinding_nonce: ZERO_TWEAK,
						asset_entropy: [0; 32],
						amount: confidential::Value::Explicit(1),
						inflation_keys: confidential::Value::Null,
						// The kit's PSET carries no denomination and signs an
						// issuance as denomination 8; the transaction must say
						// the same, or the signature covers another hash.
						denomination: TOKEN_DENOMINATION,
					};
				}
				input
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
		// The kit's PSET keeps an input's issuance flag in its output index
		// (bit 31), and the transaction it extracts to sign then names
		// another outpoint than the one spent. The index is the outpoint's.
		for (i, input) in tx.input.iter().enumerate() {
			if input.has_issuance() {
				pset.inputs_mut()[i].previous_output_index = input.previous_output.vout;
			}
		}
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

	/// The fee for `vsize` vbytes in `asset`'s own atoms, now: the node's
	/// relay floor at its rate for `asset`, times the wallet's multiple.
	/// Refuses an asset the node does not accept for fees now.
	pub async fn fee_in(&self, asset: AssetId, vsize: u64) -> Result<u64, WalletError> {
		self.fee_for(asset, vsize).await
	}

	/// Builds, with `build`, a transaction whose fee a coin of the wallet's
	/// pays: the first asset of `assets` the node accepts for fees now in
	/// which the wallet holds a spendable coin of at least twice the fee
	/// (its largest), with the change to a new change script. `build` is
	/// given the fee source and returns what it built, its txid and the
	/// virtual size it will have once signed; the fee is sized again from
	/// that size until it covers it. The coin is marked spent by that txid
	/// before this returns; a transaction never broadcast must have it
	/// released ([`Wallet::release`]). Returns what `build` made, the coin
	/// and the fee.
	pub async fn with_fee_coin<T, F>(&self, assets: &[AssetId], mut build: F) -> Result<(T, WalletCoin, AssetAmount), WalletError>
	where
		F: FnMut(&FeeSource) -> Result<(T, Txid, u64), String>,
	{
		let _one = self.building.lock().await;
		for asset in assets {
			let mut fee = match self.fee_for(*asset, 400).await {
				Ok(f) => f,
				Err(WalletError::FeeAssetNotAccepted(_)) => continue,
				Err(e) => return Err(e),
			};
			let mut coins = vec![];
			for c in self.store.wallet_coins(Some(&asset.into_inner().to_byte_array())).await? {
				if self.spendable(&c).await? {
					coins.push(c);
				}
			}
			coins.sort_by(|a, b| b.value.cmp(&a.value).then(a.txid.cmp(&b.txid)).then(a.vout.cmp(&b.vout)));
			let coin = match coins.into_iter().next() {
				Some(c) => c,
				None => continue,
			};
			let change = self.new_script(CHANGE).await?;
			for _ in 0..5 {
				if coin.value < fee.saturating_mul(2) {
					break;
				}
				let source = FeeSource::Coin {
					outpoint: OutPoint::new(Txid::from_byte_array(coin.txid), coin.vout),
					coin: explicit_txout(AssetAmount::new(*asset, coin.value), Script::from(coin.script_pubkey.clone())),
					fee,
					change: change.clone(),
				};
				let (made, txid, vsize) = build(&source).map_err(WalletError::Build)?;
				let need = self.fee_for(*asset, vsize).await?;
				if need <= fee {
					if !self.store.spend_wallet_coins(&[(coin.txid, coin.vout)], &txid.to_byte_array()).await? {
						return Err(WalletError::Raced);
					}
					return Ok((made, coin, AssetAmount::new(*asset, fee)));
				}
				fee = need;
			}
		}
		Err(WalletError::NoFeeCoin(assets.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")))
	}

	/// The wallet's coins of `asset` in a block of the active chain and not
	/// spent, final or not: where the watcher finds a round's connector atom.
	pub async fn coins_in_chain(&self, asset: AssetId) -> Result<Vec<WalletCoin>, WalletError> {
		Ok(self.store.wallet_coins(Some(&asset.into_inner().to_byte_array())).await?
			.into_iter().filter(|c| c.in_chain && c.spent_by.is_none()).collect())
	}

	/// Marks `coins` spent by `txid`, the watcher's transaction that spends
	/// them; refuses a coin another transaction took.
	pub async fn take(&self, coins: &[&WalletCoin], txid: &Txid) -> Result<(), WalletError> {
		let _one = self.building.lock().await;
		let ids: Vec<([u8; 32], u32)> = coins.iter().map(|c| (c.txid, c.vout)).collect();
		if !self.store.spend_wallet_coins(&ids, &txid.to_byte_array()).await? {
			return Err(WalletError::Raced);
		}
		Ok(())
	}

	/// Signs input `index` of `tx`, which spends the wallet's `coin`, a
	/// P2WPKH output: see the [module documentation](self). The signature
	/// commits to every input and output, so it is made once nothing else
	/// will change but the other inputs' witnesses.
	pub fn sign_input(&self, tx: &mut Transaction, index: usize, coin: &WalletCoin) -> Result<(), WalletError> {
		use elements::bitcoin::secp256k1::{Message, Secp256k1};
		use elements::sighash::SighashCache;
		let input = tx.input.get(index).ok_or(WalletError::WrongInput(index))?;
		if input.previous_output != OutPoint::new(Txid::from_byte_array(coin.txid), coin.vout) {
			return Err(WalletError::WrongInput(index));
		}
		let pk = self.public_key(coin.chain, coin.index)?;
		if Self::script(&pk).as_bytes() != coin.script_pubkey.as_slice() {
			return Err(WalletError::Keys(format!("coin {}:{} is not at the key the wallet derives for it", Txid::from_byte_array(coin.txid), coin.vout)));
		}
		let xprv = self.signer.derive_xprv(&Self::path(coin.chain, coin.index)).map_err(|e| WalletError::Keys(e.to_string()))?;
		let code = Script::new_p2pkh(&elements::PubkeyHash::hash(&pk.to_bytes()));
		let sighash = SighashCache::new(&*tx).segwitv0_sighash(index, &code, confidential::Value::Explicit(coin.value),
			elements::EcdsaSighashType::All);
		let sig = Secp256k1::new().sign_ecdsa_low_r(&Message::from_digest(sighash.to_byte_array()), &xprv.private_key);
		let mut der = sig.serialize_der().to_vec();
		der.push(elements::EcdsaSighashType::All as u8);
		tx.input[index].witness.script_witness = vec![der, pk.to_bytes()];
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
