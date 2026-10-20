//! `arca`: the Arca wallet on the command line.
//!
//! A dual-chain wallet. Its Sequentia side holds Arca coins (leaves of
//! covenant-tree batches, boards, coins paid out of round) against an Arca
//! server, with the node as its chain source; every coin is validated before it
//! is kept. Its Bitcoin side is Bark's own wallet for Bitcoin arks, run by
//! `arca bitcoin …` in the same data directory (`bitcoin.rs`).
//!
//! Every command prints JSON. A refusal prints `{"error": {"kind", "message"}}`
//! with its reason and exits with status 1.

mod bitcoin;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use bark::arca::elements::AssetId;
use bark::arca::{Config, Spelling, Wallet};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

fn default_datadir() -> String {
	home::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".arca").display().to_string()
}

#[derive(Parser)]
#[command(name = "arca", about = "The Arca wallet: Arca coins on Sequentia, and Bitcoin arks through Bark")]
struct Cli {
	/// The wallet's directory: its mnemonic and its database.
	#[arg(long, env = "ARCA_DATADIR", global = true, default_value_t = default_datadir())]
	datadir: String,

	/// How long, in seconds, `sync` keeps trying to reach the operator, with
	/// back-off, before it takes it for unreachable: one failed witness
	/// decides nothing.
	#[arg(long, global = true, default_value_t = bark::arca::WITNESS_PATIENCE.as_secs())]
	witness_patience: u64,

	#[command(subcommand)]
	command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
	/// Creates a wallet: a new mnemonic (or the one given), the node's chain,
	/// and the server's operator key, pinned. `join --from-registry KEY`
	/// joins the operator the registry lists under that key instead of a
	/// server named by address.
	#[command(visible_alias = "join")]
	Create {
		/// The Arca server's base URL.
		#[arg(long, required_unless_present = "from_registry", conflicts_with = "from_registry")]
		server: Option<String>,
		/// The operator key of an operator the registry lists: the wallet
		/// reads its record, checks the operator's signature over it, takes
		/// the server's address from it, and is created only when that server
		/// shows the record's key, chain and keepers.
		#[arg(long, requires = "registry")]
		from_registry: Option<String>,
		/// The registry's base URL (`https://host/registry`).
		#[arg(long, env = "ARCA_REGISTRY")]
		registry: Option<String>,
		/// The node's JSON-RPC URL. The node must run with -txindex and
		/// -validateanchor.
		#[arg(long)]
		node_url: String,
		#[arg(long)]
		node_user: Option<String>,
		/// A file holding the node's RPC password, read once; the password is
		/// also taken from the environment variable ARCA_NODE_PASSWORD. It is
		/// never a command-line argument, which other users of the machine
		/// can read, and the wallet keeps it in a file of its directory only
		/// its owner can read.
		#[arg(long)]
		node_password_file: Option<PathBuf>,
		/// The node's cookie file, instead of a user and password.
		#[arg(long)]
		node_cookie: Option<String>,
		/// Restore from this mnemonic instead of drawing a new one: the wallet
		/// is created, then restored from what the server serves to its
		/// mailbox key, every record checked (`restore`).
		#[arg(long, conflicts_with = "mnemonic_file")]
		mnemonic: Option<String>,
		/// The same, the mnemonic read once from this file, or from the
		/// standard input when it is `-` (a pipe or a socket alike): a
		/// program that runs `arca` keeps it off the command line, which
		/// other users of the machine can read.
		#[arg(long)]
		mnemonic_file: Option<PathBuf>,
		/// The account of the leaf keys, m/6'/account'/….
		#[arg(long, default_value_t = 0)]
		account: u32,
		/// The exit delay to ask for on the wallet's own leaves, in 512-second
		/// units (default 36 hours).
		#[arg(long)]
		exit_delay_units: Option<u16>,
		/// The shortest exit delay the wallet accepts on any leaf, its lineage
		/// included (default 36 hours).
		#[arg(long)]
		min_exit_delay_units: Option<u16>,
		/// The longest (default 48 hours).
		#[arg(long)]
		max_exit_delay_units: Option<u16>,
	},
	/// The operators the registry lists, each record's signature checked
	/// here; needs no wallet.
	Operators {
		/// The registry's base URL (`https://host/registry`).
		#[arg(long, env = "ARCA_REGISTRY")]
		registry: String,
		/// Only the operators of the chain of this genesis hash.
		#[arg(long)]
		genesis: Option<String>,
	},
	/// The wallet, its chain, its operator and what the server publishes.
	Info,
	/// A new on-chain Sequentia address of the wallet's.
	Address,
	/// What the wallet holds, per asset: Arca coins by state, on-chain coins,
	/// and the Bitcoin side.
	Balance {
		/// Leaves the Bitcoin side out, Bark not run: for a program that
		/// reads it on its own, one Bark run at a time (Bark lets one
		/// process at a time open its wallet). BTC's row is still first,
		/// with no total.
		#[arg(long)]
		without_bitcoin: bool,
	},
	/// Every coin the wallet holds or held.
	Coins,
	/// One coin's record.
	Record { leaf_id: String },
	/// Boards `amount` of `asset` from the wallet's on-chain coins.
	Board {
		asset: String,
		amount: u64,
		/// The asset to pay the board transaction's fee in; the boarded asset
		/// unless named.
		#[arg(long)]
		fee_asset: Option<String>,
		/// Only says what the board would pay now (its fee, its size, the
		/// coins it spends), signing and asking nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The fee shown to the user, as `--quote` answered it (its `fee`):
		/// the board goes ahead only on this very fee, and is refused before
		/// anything is registered or signed when it changed.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Where each board stands.
	Boards,
	/// A single-use receive request: a fresh key and owner nonce, and the
	/// wallet's mailbox.
	Receive {
		#[arg(long)]
		asset: Option<String>,
		#[arg(long)]
		amount: Option<u64>,
	},
	/// Stops waiting for a payment to an unpaid receive request, by the key
	/// it names (`owner`, as `sync`'s `schedule.receive_requests` lists
	/// it): it no longer holds the schedule at a day. A coin paid to it is
	/// still read, by any later sync.
	ForgetRequest { owner: String },
	/// Pays a receive request out of round; one past its lapse is refused.
	Send {
		request: String,
		#[arg(long)]
		amount: Option<u64>,
		/// The asset to send, when the request does not name it.
		#[arg(long)]
		asset: Option<String>,
	},
	/// Reads the mailbox and validates every coin in it.
	Mailbox,
	/// Payments over Lightning, through the operator's node in each asset.
	#[command(subcommand)]
	Lightning(LightningCmd),
	/// Restores the wallet from its mnemonic: every leaf the server serves to
	/// its mailbox key, each checked against the chain, the published tree
	/// and its owner's own signatures, then the mailbox and a sync. Run
	/// again, it takes only what the wallet does not hold.
	Restore,
	/// The refresh fee of each coin a participation would give up (every
	/// live coin when none is named), priced by its asset's schedule, before
	/// anything is signed: what `participate --shown` takes.
	Quote {
		#[arg(long = "leaf")]
		leaves: Vec<String>,
		#[arg(long)]
		max_fee_ppm: Option<u64>,
	},
	/// Takes part in the next round with the coins named (every live coin
	/// when none is), for one new leaf per asset.
	#[command(alias = "refresh")]
	Participate {
		#[arg(long = "leaf")]
		leaves: Vec<String>,
		/// The earliest median time of a round it may run in.
		#[arg(long)]
		not_before: Option<u32>,
		/// The most the operator's refresh fee may take of a coin, in
		/// millionths, for this command: by default 10,000, and nothing in a
		/// coin's free window.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// The fees shown to the user, as `quote` answered them (its
		/// `coins`): the participation goes ahead only on these very fees,
		/// and is refused before anything is signed when they changed.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Every participation the wallet made, from its own store: where it
	/// stands, its round, the coins it gave up and its new leaves.
	Participations,
	/// Re-checks every coin against the chain, retries what the server never
	/// answered, reads the mailbox and moves every participation on.
	Sync,
	/// When `sync` must next run, and the dates of every coin held off the
	/// chain, asking nothing of the operator: for a program that runs `sync`
	/// on a timer.
	Schedule,
	/// Re-checks every coin against the chain as it is now.
	Recheck,
	/// Takes a coin on-chain from its record alone and claims it after its
	/// exit delay. Run again to go on.
	Exit {
		leaf_id: String,
		/// The asset to pay fees in where the coin's own reserves cannot.
		#[arg(long)]
		fee_asset: Option<String>,
		/// Only says what this run would broadcast (each transaction's size
		/// and fee) and the claim's fee now, broadcasting nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The fees shown to the user, as `--quote` answered them (its
		/// `unroll`): the path is broadcast only on these very fees, and
		/// nothing is broadcast when they changed.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Takes an on-chain order in the operator's round: a fill of an order
	/// resting on the chain under SeqDEX's fill covenant, paid with the
	/// wallet's coins of the asset it is paid in, for a leaf of what it fills.
	/// `sync` hands over the forfeits once the round is built and takes the
	/// leaf once it is final.
	Take {
		/// The order as the relay serves it: its `CovenantTerms` JSON (or an
		/// offer whose settlement is one), `@FILE` to read it from a file, or
		/// `-` to read it from standard input.
		order: String,
		/// How much of the asset the order sells to take, in its atoms; all
		/// of it when not named.
		#[arg(long)]
		amount: Option<u64>,
		/// The most the operator's fee may take of the price, in millionths:
		/// 10,000 unless raised.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// Only says what the take would cost (the fill, the price, the fee,
		/// what the coins given up hold), signing and asking nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The take shown to the user, as `--quote` answered it: the take
		/// goes ahead only on that very fill, price and fee.
		#[arg(long)]
		shown: Option<String>,
	},
	/// An in-tree swap of two assets with another wallet.
	#[command(subcommand)]
	Swap(SwapCmd),
	/// Every refusal the wallet made, with its reason.
	Refusals,
	/// The Bitcoin side: Bark's wallet for Bitcoin arks, in `<datadir>/bitcoin`.
	/// `bitcoin create` makes it from this wallet's own mnemonic (see
	/// `arca bitcoin create --help`); everything else after `bitcoin` goes to
	/// Bark as given.
	Bitcoin {
		#[arg(trailing_var_arg = true, allow_hyphen_values = true)]
		args: Vec<String>,
	},
}

#[derive(Subcommand)]
enum SwapCmd {
	/// Offers `give` of one asset for `want` of another.
	Offer {
		#[arg(long)]
		give_asset: String,
		#[arg(long)]
		give: u64,
		#[arg(long)]
		want_asset: String,
		#[arg(long)]
		want: u64,
	},
	/// Takes an offer, signing the wallet's side. The coins the swap gives
	/// the wallet carry the earliest dates of every coin it spends, which are
	/// shown; it is refused when their exit deadline is less than two days
	/// away.
	Accept {
		offer: String,
		/// Takes the swap even when the coins it gives the wallet reach their
		/// exit deadline within two days.
		#[arg(long)]
		accept_near_deadline: bool,
	},
	/// Completes the wallet's offer with an acceptance. The coins the swap
	/// gives the wallet carry the earliest dates of every coin it spends,
	/// the taker's included, which are shown; it is refused when their exit
	/// deadline is less than two days away.
	Complete {
		accept: String,
		/// Completes the swap even when the coins it gives the wallet reach
		/// their exit deadline within two days.
		#[arg(long)]
		accept_near_deadline: bool,
	},
	/// Cancels an offer or acceptance not completed.
	Cancel { swap: String },
}

fn asset(s: &str) -> Result<AssetId, bark::arca::Error> {
	AssetId::from_str(s).map_err(|e| bark::arca::Error::Parse(format!("asset {:?}: {}", s, e)))
}

/// Whether `a` names native BTC rather than a Sequentia asset.
fn is_btc(a: &str) -> bool {
	a.eq_ignore_ascii_case("btc")
}

/// `arca bitcoin create`: the Bitcoin ark wallet, made from this wallet's
/// own mnemonic, which reaches Bark in a request body and never on a command
/// line. A new wallet scans Bitcoin from now; give `--birthday-height` to
/// restore one whose mnemonic held bitcoin before.
#[derive(Parser)]
#[command(name = "arca bitcoin create")]
struct BitcoinCreate {
	/// Bitcoin's testnet4, the network the Sequentia testnet anchors to.
	#[arg(long, group = "network")]
	testnet4: bool,
	#[arg(long, group = "network")]
	mainnet: bool,
	#[arg(long, group = "network")]
	signet: bool,
	#[arg(long, group = "network")]
	mutinynet: bool,
	#[arg(long, group = "network")]
	regtest: bool,
	/// The Bitcoin ark's server (Bark's `captaind`).
	#[arg(long)]
	ark: String,
	/// A Bitcoin Core node's RPC URL, version 29 or later, as the chain
	/// source.
	#[arg(long, conflicts_with = "esplora", required_unless_present = "esplora")]
	bitcoind: Option<String>,
	/// Its cookie file.
	#[arg(long, conflicts_with = "bitcoind_user")]
	bitcoind_cookie: Option<String>,
	/// Its RPC user; the password is taken from ARCA_BITCOIND_PASSWORD,
	/// never from the command line.
	#[arg(long)]
	bitcoind_user: Option<String>,
	/// An Esplora server, as the chain source.
	#[arg(long)]
	esplora: Option<String>,
	/// The height to scan Bitcoin from (default: the node's tip, or all of
	/// it through Esplora).
	#[arg(long)]
	birthday_height: Option<u32>,
}

fn bitcoin(datadir: &Path, args: &[String]) -> Result<Value, bark::arca::Error> {
	if args.first().map(|a| a.as_str()) == Some("create") {
		let c = BitcoinCreate::try_parse_from(std::iter::once("arca bitcoin create".to_string()).chain(args[1..].iter().cloned()))
			.map_err(|e| bark::arca::Error::Parse(e.to_string()))?;
		let network = [("testnet4", c.testnet4), ("mainnet", c.mainnet), ("signet", c.signet), ("mutinynet", c.mutinynet),
			("regtest", c.regtest)].into_iter().find(|(_, on)| *on).map(|(n, _)| n.to_string())
			.ok_or_else(|| bark::arca::Error::Parse("name the Bitcoin network: --testnet4, --mainnet, --signet, --mutinynet or \
				--regtest".into()))?;
		return bitcoin::create(datadir, bitcoin::CreateOpts {
			network, ark: c.ark, bitcoind: c.bitcoind, bitcoind_cookie: c.bitcoind_cookie, bitcoind_user: c.bitcoind_user,
			bitcoind_password: std::env::var("ARCA_BITCOIND_PASSWORD").ok(), esplora: c.esplora, birthday_height: c.birthday_height,
		});
	}
	bitcoin::board_guard(datadir, args)?;
	let status = Command::new(bitcoin::bark_exe()).arg("--datadir").arg(bitcoin::dir(datadir)).args(args).status()
		.map_err(|e| bark::arca::Error::Io(format!("cannot run Bark ({}): {}", bitcoin::bark_exe().display(), e)))?;
	std::process::exit(status.code().unwrap_or(1));
}

/// One row per holding: BTC first, always, 0 included, as every Sequentia
/// wallet shows it; then each Sequentia asset the wallet holds anything of,
/// on-chain or in Arca, with nothing set apart, and its value in the
/// reference unit where the wallet's node has a rate for it. An asset with
/// nothing in it has no row. The headline is the balance's `total`.
fn rows(b: &Value) -> Value {
	let mut rows = vec![match bitcoin::total_sat(&b["bitcoin"]) {
		Some(btc) => json!({"asset": "BTC", "total": btc.to_string(), "unit": "sat"}),
		None if b["bitcoin"]["left_out"] == json!(true) => json!({"asset": "BTC", "total": null, "unit": "sat",
			"note": b["bitcoin"]["note"].clone()}),
		None => json!({"asset": "BTC", "total": null, "unit": "sat", "note": format!("the Bitcoin side could not be read: {}",
			b["bitcoin"]["error"].as_str().unwrap_or(""))}),
	}];
	let mut per: std::collections::BTreeMap<String, u128> = std::collections::BTreeMap::new();
	for (a, states) in b["arca"].as_object().into_iter().flatten() {
		for (_, v) in states.as_object().into_iter().flatten() {
			*per.entry(a.clone()).or_default() += v.as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
		}
	}
	for (a, v) in b["sequentia_onchain"].as_object().into_iter().flatten() {
		*per.entry(a.clone()).or_default() += v.as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
	}
	for (a, total) in per {
		if total > 0 {
			let mut row = json!({"asset": a, "total": total.to_string(), "unit": "atom"});
			if let Some(v) = b["total"]["values"].get(&a) {
				row["value"] = v.clone();
			}
			rows.push(row);
		}
	}
	Value::Array(rows)
}

#[derive(Subcommand)]
enum LightningCmd {
	/// Pays a BOLT11 invoice out of the wallet's coins of the asset it names:
	/// they go into an htlc-1 leaf the operator claims with the preimage once
	/// it has paid, and the change. An invoice in no asset, or in another
	/// asset than `--asset`, is refused before anything is signed. A Bitcoin
	/// invoice is paid in native BTC through Bark's Lightning leg on the
	/// wallet's Bitcoin ark wallet (`bitcoin create`), never from a Sequentia
	/// leaf, and the outcome read back from Bark.
	Pay {
		invoice: String,
		/// The asset of the coins to pay with: it must be the invoice's.
		#[arg(long)]
		asset: Option<String>,
		/// Raises the wallet's bound on the operator's fee for this payment,
		/// in parts per million of what it pays.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// How long to wait for the operator to say how the payment went, in
		/// seconds; `sync` follows it after that.
		#[arg(long, default_value_t = 60)]
		wait: u64,
	},
	/// Every payment over Lightning the wallet made, with where it stands.
	Payments,
	/// An invoice for `amount` of `asset`, under a payment hash only the
	/// wallet can open, paid into a leaf of the wallet's own in the asset's
	/// next round; `sync` claims the leaf once the wallet holds it, which
	/// settles the payment. The operator's fee comes out of the amount.
	/// `btc` for native BTC: an invoice for `amount` satoshis through Bark's
	/// Lightning leg on the wallet's Bitcoin ark wallet, which `claim` must
	/// then claim while the payer pays.
	Receive {
		asset: String,
		amount: u64,
		#[arg(long)]
		description: Option<String>,
		/// Raises the wallet's bound on the operator's fee for this payment,
		/// in parts per million of the amount.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
	},
	/// Claims a payment to a Bitcoin invoice of the wallet's (`receive
	/// btc`): waits up to `--wait` seconds for the payer's payment and claims
	/// it at once, as Bark's server requires. Answers `claimed`, `waiting`
	/// (claim again while the payer may still pay), or `reissued` with a
	/// fresh invoice of the same amount for the payer to pay instead, when
	/// the server refused the claim as too close to the payment's expiry.
	Claim {
		invoice: String,
		#[arg(long, default_value_t = 300)]
		wait: u64,
	},
	/// Every payment the wallet asked to receive over Lightning, with where
	/// it stands.
	Receives,
}

fn run(cli: Cli) -> Result<Value, bark::arca::Error> {
	let datadir = PathBuf::from(&cli.datadir);
	if let Cmd::Bitcoin { args } = &cli.command {
		return bitcoin(&datadir, args);
	}
	// The Bitcoin side of Lightning is Bark's, on the Bitcoin ark wallet: it
	// needs nothing of the Arca wallet's store or operator.
	match &cli.command {
		Cmd::Lightning(LightningCmd::Pay { invoice, asset: a, .. }) => {
			let currency = bark::arca::lightning::parse_invoice(invoice).ok().map(|i| i.currency);
			if let Some((net, false)) = currency.as_deref().and_then(bark::arca::lightning::network_of) {
				if let Some(a) = a.as_deref().filter(|a| !is_btc(a)) {
					return Err(bark::arca::Error::Refused(format!("the invoice is a Bitcoin invoice ({}), paid in native BTC: coins of asset \
						{} never pay it; nothing is signed", net, a)));
				}
				return bitcoin::pay(&datadir, invoice);
			}
		},
		Cmd::Lightning(LightningCmd::Receive { asset: a, amount, description, .. }) if is_btc(a) =>
			return bitcoin::invoice(&datadir, *amount, description.as_deref()),
		Cmd::Lightning(LightningCmd::Claim { invoice, wait }) => {
			let currency = bark::arca::lightning::parse_invoice(invoice)?.currency;
			if !matches!(bark::arca::lightning::network_of(&currency), Some((_, false))) {
				return Err(bark::arca::Error::Refused(format!("`claim` takes a Bitcoin invoice of the wallet's (`receive btc`); this one \
					is in currency {:?}. A Sequentia receive is claimed by `sync`", currency)));
			}
			return bitcoin::claim(&datadir, invoice, std::time::Duration::from_secs(*wait));
		},
		_ => {},
	}
	if let Cmd::Operators { registry, genesis } = &cli.command {
		return bark::arca::command::operators(registry, genesis.as_deref());
	}
	if let Cmd::Create { server, from_registry, registry, node_url, node_user, node_password_file, node_cookie, mnemonic, mnemonic_file,
		account, exit_delay_units, min_exit_delay_units, max_exit_delay_units } = cli.command
	{
		// `-` reads the standard input itself: a path such as /dev/stdin
		// cannot be opened when the input is a socket, which is what
		// Node.js gives a child process.
		let mnemonic = match mnemonic_file {
			Some(f) if f.as_os_str() == "-" => {
				let mut s = String::new();
				std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
					.map_err(|e| bark::arca::Error::Io(format!("the standard input: {}", e)))?;
				Some(s.split_whitespace().collect::<Vec<_>>().join(" "))
			},
			Some(f) => Some(std::fs::read_to_string(&f).map_err(|e| bark::arca::Error::Io(format!("{}: {}", f.display(), e)))?
				.split_whitespace().collect::<Vec<_>>().join(" ")),
			None => mnemonic,
		};
		// From the registry: the record's signature checked here, the server's
		// address taken from it, and what the server must show to be pinned.
		let (server, joined) = match (server, from_registry) {
			(Some(s), None) => (s, None),
			(None, Some(key)) => {
				let r = bark::arca::registry::RegistryClient::new(registry.as_deref().unwrap_or(""))?;
				let (record, listing) = r.operator(&key)?;
				let expect = bark::arca::registry::Expected::of(&record)?;
				(record["api"].as_str().unwrap_or("").to_string(), Some((expect, listing)))
			},
			_ => return Err(bark::arca::Error::Parse("name the server (--server) or the registry's operator (--from-registry)".into())),
		};
		let mut cfg = Config::spec_delays(&server, &node_url);
		let listing = joined.map(|(e, l)| {
			cfg.expect = Some(e);
			l
		});
		cfg.node_user = node_user;
		cfg.node_password = match node_password_file {
			Some(f) => Some(std::fs::read_to_string(&f).map_err(|e| bark::arca::Error::Io(format!("{}: {}", f.display(), e)))?
				.trim_end_matches(['\r', '\n']).to_string()),
			None => std::env::var("ARCA_NODE_PASSWORD").ok(),
		};
		cfg.node_cookie = node_cookie;
		cfg.account = account;
		if let Some(d) = exit_delay_units {
			cfg.exit_delay_units = d;
		}
		if let Some(d) = min_exit_delay_units {
			cfg.min_exit_delay_units = d;
		}
		if let Some(d) = max_exit_delay_units {
			cfg.max_exit_delay_units = d;
		}
		let restoring = mnemonic.is_some();
		let mut w = Wallet::create(&datadir, mnemonic.as_deref(), cfg)?;
		w.spell(Spelling::command_line("arca"));
		w.witness_patience = std::time::Duration::from_secs(cli.witness_patience);
		let mut info = w.info()?;
		info["mnemonic_file"] = json!(w.mnemonic_path().display().to_string());
		let check = format!("compare the operator key {} with the one the operator publishes through a channel you trust: the wallet \
			has pinned it, and refuses any server that names another", info["operator"].as_str().unwrap_or(""));
		eprintln!("arca: {}", check);
		info["operator_key_check"] = json!(check);
		if let Some(l) = listing {
			info["registry"] = l;
		}
		// A mnemonic given may have held coins: they are restored from what
		// the server serves to the wallet's mailbox key, every record checked.
		if restoring {
			info["restore"] = w.restore().unwrap_or_else(|e| json!({"error": {"kind": e.kind(), "message": e.to_string(),
				"note": "nothing was restored: run `arca restore` once the cause is gone"}}));
		}
		return Ok(info);
	}
	let mut w = Wallet::open(&datadir)?;
	// What the wallet says names this command line's commands (`arca sync`),
	// and its texts carry its prefixes (`arca:`).
	w.spell(Spelling::command_line("arca"));
	w.witness_patience = std::time::Duration::from_secs(cli.witness_patience);
	// The witness of the operator's signer's record runs on every start, so
	// every wallet that is online witnesses it: a rollback of the record
	// takes the coins resting on what it lost on the chain at once.
	// Commands that stay on this machine and the node (and an exit, which
	// needs nothing of the operator) do not wait on the server. The library
	// witnesses again in every entry point that takes a coin or signs a
	// spend through the operator, and refuses while no witness succeeds.
	if !matches!(cli.command, Cmd::Address | Cmd::Balance { .. } | Cmd::Coins | Cmd::Record { .. } | Cmd::Refusals | Cmd::Participations
		| Cmd::Exit { .. } | Cmd::Schedule)
	{
		match w.witness() {
			Ok(v) if !v["rolled_back"].is_null() => eprintln!("arca: the witness on start: {}", v),
			Ok(_) => {},
			Err(e) => eprintln!("arca: the witness on start could not run ({}): the wallet takes no coin and signs no spend through the \
				operator until a witness succeeds", e),
		}
	}
	// The re-check runs on every start: a rollback since the last command
	// un-credits what it took out before anything is spent or shown.
	let startup = match &cli.command {
		Cmd::Recheck | Cmd::Sync | Cmd::Schedule => None,
		_ => match w.recheck() {
			Ok(v) => Some(v),
			Err(e) => {
				eprintln!("arca: the re-check on start could not run: {}", e);
				None
			},
		},
	};
	if let Some(v) = &startup {
		if v["reorganised"] == json!(true) || v["changes"].as_array().is_some_and(|a| !a.is_empty()) {
			eprintln!("arca: re-check on start: {}", v);
		}
	}
	match cli.command {
		Cmd::Create { .. } | Cmd::Bitcoin { .. } | Cmd::Operators { .. } => unreachable!("handled above"),
		Cmd::Info => w.info(),
		Cmd::Address => w.address(),
		Cmd::Balance { without_bitcoin } => {
			let mut b = w.balance()?;
			b["bitcoin"] = if without_bitcoin {
				json!({"left_out": true, "note": "the Bitcoin side is left out (--without-bitcoin): read it with `arca bitcoin balance` \
					and `arca bitcoin onchain balance`"})
			} else {
				bitcoin::balance(&datadir)
			};
			b["rows"] = rows(&b);
			Ok(b)
		},
		Cmd::Coins => w.coins(),
		Cmd::Record { leaf_id } => w.record(&leaf_id),
		Cmd::Board { asset: a, amount, fee_asset, quote: true, .. } => w.board_quote(asset(&a)?, amount, fee_asset.as_deref().map(asset).transpose()?),
		Cmd::Board { asset: a, amount, fee_asset, quote: false, shown } => {
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the fee shown: {}", e)))).transpose()?;
			w.board_shown(asset(&a)?, amount, fee_asset.as_deref().map(asset).transpose()?, shown.as_ref())
		},
		Cmd::Boards => w.boards(),
		Cmd::Receive { asset: a, amount } => w.receive(a.as_deref().map(asset).transpose()?, amount),
		Cmd::ForgetRequest { owner } => w.forget_request(&owner),
		Cmd::Send { request, amount, asset: a } => w.send(&request, amount, a.as_deref().map(asset).transpose()?),
		Cmd::Mailbox => w.mailbox(),
		Cmd::Lightning(LightningCmd::Pay { invoice, asset: a, max_fee_ppm, wait }) => {
			let mut v = w.lightning_pay(&invoice, a.as_deref().map(asset).transpose()?, max_fee_ppm)?;
			let hash = v["paying"]["payment_hash"].as_str().unwrap_or("").to_string();
			v["payment"] = w.lightning_follow(&hash, std::time::Duration::from_secs(wait))?;
			Ok(v)
		},
		Cmd::Lightning(LightningCmd::Payments) => w.lightning_payments(),
		Cmd::Lightning(LightningCmd::Receive { asset: a, amount, description, max_fee_ppm }) =>
			w.lightning_receive(asset(&a)?, amount, description.as_deref(), max_fee_ppm),
		Cmd::Lightning(LightningCmd::Receives) => w.lightning_receives(),
		Cmd::Lightning(LightningCmd::Claim { .. }) => unreachable!("handled above"),
		Cmd::Restore => w.restore(),
		Cmd::Quote { leaves, max_fee_ppm } => Ok(json!({"coins": w.refresh_quote(&leaves, max_fee_ppm)?.coins()})),
		Cmd::Participate { leaves, not_before, max_fee_ppm, shown } => {
			// The fee is shown before anything is signed.
			let quote = w.refresh_quote(&leaves, max_fee_ppm)?;
			// A program that showed the fees (`quote`) goes ahead only on
			// the very fees it showed.
			if let Some(shown) = shown {
				let shown: Value = serde_json::from_str(&shown)
					.map_err(|e| bark::arca::Error::Parse(format!("the fees shown: {}", e)))?;
				let now = json!(quote.coins());
				if shown != now {
					return Err(bark::arca::Error::Refused(format!("the refresh fees changed since they were shown; they are now {}", now)));
				}
			}
			for c in quote.coins() {
				eprintln!("arca: refresh fee for coin {}: {} of asset {} ({} ppm of its {}; the wallet's bound {} ppm)", c["leaf_id"].as_str().unwrap_or(""),
					c["fee"].as_str().unwrap_or(""), c["asset"].as_str().unwrap_or(""), c["ppm"], c["value"].as_str().unwrap_or(""), c["bound_ppm"]);
			}
			w.participate(quote, not_before)
		},
		Cmd::Sync => w.sync(),
		Cmd::Schedule => w.sync_schedule(),
		Cmd::Recheck => w.recheck(),
		Cmd::Exit { leaf_id, fee_asset, quote: true, .. } => w.exit_quote(&leaf_id, fee_asset.as_deref().map(asset).transpose()?),
		Cmd::Exit { leaf_id, fee_asset, quote: false, shown } => {
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the fees shown: {}", e)))).transpose()?;
			w.exit_shown(&leaf_id, fee_asset.as_deref().map(asset).transpose()?, shown.as_ref())
		},
		Cmd::Take { order, amount, max_fee_ppm, quote, shown } => {
			let order = read_order(&order)?;
			if quote {
				w.take_quote(&order, amount, max_fee_ppm)
			} else {
				let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
					.map_err(|e| bark::arca::Error::Parse(format!("the take shown: {}", e)))).transpose()?;
				w.take(&order, amount, max_fee_ppm, shown.as_ref())
			}
		},
		Cmd::Swap(SwapCmd::Offer { give_asset, give, want_asset, want }) => w.swap_offer(asset(&give_asset)?, give, asset(&want_asset)?, want),
		Cmd::Swap(SwapCmd::Accept { offer, accept_near_deadline }) => w.swap_accept(&offer, accept_near_deadline),
		Cmd::Swap(SwapCmd::Complete { accept, accept_near_deadline }) => w.swap_complete(&accept, accept_near_deadline),
		Cmd::Swap(SwapCmd::Cancel { swap }) => w.swap_cancel(&swap),
		Cmd::Refusals => w.refusals(),
		Cmd::Participations => w.participations(),
	}
}

/// The order a take names: the JSON itself, `@FILE`, or `-` for standard
/// input.
fn read_order(arg: &str) -> Result<String, bark::arca::Error> {
	if arg == "-" {
		let mut s = String::new();
		std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| bark::arca::Error::Io(format!("the order: {}", e)))?;
		return Ok(s);
	}
	match arg.strip_prefix('@') {
		Some(path) => std::fs::read_to_string(path).map_err(|e| bark::arca::Error::Io(format!("the order {}: {}", path, e))),
		None => Ok(arg.to_string()),
	}
}

fn main() {
	let cli = Cli::parse();
	match run(cli) {
		Ok(v) => println!("{}", serde_json::to_string_pretty(&v).expect("JSON")),
		Err(e) => {
			let mut out = json!({"error": {"kind": e.kind(), "message": e.to_string()}});
			if let bark::arca::Error::Server { code, status, .. } = &e {
				out["error"]["code"] = json!(code);
				out["error"]["status"] = json!(status);
			}
			println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
			eprintln!("arca: {}", e);
			std::process::exit(1);
		},
	}
}
