//! `arca`: the Arca wallet on the command line.
//!
//! A dual-chain wallet. Its Sequentia side holds Arca coins (leaves of
//! covenant-tree batches, boards, coins paid out of round) against an Arca
//! server, with the node as its chain source; every coin is validated before it
//! is kept. Its Bitcoin side is Bark's own wallet for Bitcoin arks, run by
//! `arca bitcoin …` in the same data directory.
//!
//! Every command prints JSON. A refusal prints `{"error": {"kind", "message"}}`
//! with its reason and exits with status 1.

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
	/// and the server's operator key, pinned.
	Create {
		/// The Arca server's base URL.
		#[arg(long)]
		server: String,
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
		#[arg(long)]
		mnemonic: Option<String>,
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
	/// The wallet, its chain, its operator and what the server publishes.
	Info,
	/// A new on-chain Sequentia address of the wallet's.
	Address,
	/// What the wallet holds, per asset: Arca coins by state, on-chain coins,
	/// and the Bitcoin side.
	Balance,
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
	},
	/// Every participation the wallet made, from its own store: where it
	/// stands, its round, the coins it gave up and its new leaves.
	Participations,
	/// Re-checks every coin against the chain, retries what the server never
	/// answered, reads the mailbox and moves every participation on.
	Sync,
	/// Re-checks every coin against the chain as it is now.
	Recheck,
	/// Takes a coin on-chain from its record alone and claims it after its
	/// exit delay. Run again to go on.
	Exit {
		leaf_id: String,
		/// The asset to pay fees in where the coin's own reserves cannot.
		#[arg(long)]
		fee_asset: Option<String>,
	},
	/// An in-tree swap of two assets with another wallet.
	#[command(subcommand)]
	Swap(SwapCmd),
	/// Every refusal the wallet made, with its reason.
	Refusals,
	/// The Bitcoin side: Bark's wallet for Bitcoin arks, in `<datadir>/bitcoin`.
	/// Everything after `bitcoin` goes to Bark.
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

/// Bark's binary, beside this one.
fn bark_exe() -> PathBuf {
	std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("bark"))).unwrap_or_else(|| PathBuf::from("bark"))
}

fn bitcoin(datadir: &Path, args: &[String]) -> Result<Value, bark::arca::Error> {
	let dir = datadir.join("bitcoin");
	let status = Command::new(bark_exe()).arg("--datadir").arg(&dir).args(args).status()
		.map_err(|e| bark::arca::Error::Io(format!("cannot run Bark ({}): {}", bark_exe().display(), e)))?;
	std::process::exit(status.code().unwrap_or(1));
}

/// The Bitcoin side's balance, from Bark, or why there is none.
fn bitcoin_balance(datadir: &Path) -> Value {
	let dir = datadir.join("bitcoin");
	if !dir.exists() {
		return json!({"wallet": null, "note": "no Bitcoin ark wallet yet: create one with `arca bitcoin create …`"});
	}
	match Command::new(bark_exe()).arg("--datadir").arg(&dir).arg("--quiet").arg("balance").output() {
		Ok(o) if o.status.success() => serde_json::from_slice(&o.stdout).unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&o.stdout)})),
		Ok(o) => json!({"error": String::from_utf8_lossy(&o.stderr)}),
		Err(e) => json!({"error": e.to_string()}),
	}
}

/// One row per holding: BTC first, always, 0 included, as every Sequentia
/// wallet shows it; then each Sequentia asset the wallet holds anything of,
/// on-chain or in Arca, with nothing set apart, and its value in the
/// reference unit where the wallet's node has a rate for it. An asset with
/// nothing in it has no row. The headline is the balance's `total`.
fn rows(b: &Value) -> Value {
	let btc: u64 = b["bitcoin"].as_object().map(|o| o.iter()
		.filter(|(k, _)| k.ends_with("_sat"))
		.filter_map(|(_, v)| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
		.sum()).unwrap_or(0);
	let mut rows = vec![json!({"asset": "BTC", "total": btc.to_string(), "unit": "sat"})];
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
	/// it has paid, and the change. A Bitcoin invoice, one in no asset, or
	/// one in another asset than `--asset` is refused before anything is
	/// signed.
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
}

fn run(cli: Cli) -> Result<Value, bark::arca::Error> {
	let datadir = PathBuf::from(&cli.datadir);
	if let Cmd::Bitcoin { args } = &cli.command {
		return bitcoin(&datadir, args);
	}
	if let Cmd::Create { server, node_url, node_user, node_password_file, node_cookie, mnemonic, account, exit_delay_units,
		min_exit_delay_units, max_exit_delay_units } = cli.command
	{
		let mut cfg = Config::spec_delays(&server, &node_url);
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
	if !matches!(cli.command, Cmd::Address | Cmd::Balance | Cmd::Coins | Cmd::Record { .. } | Cmd::Refusals | Cmd::Participations
		| Cmd::Exit { .. })
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
		Cmd::Recheck | Cmd::Sync => None,
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
		Cmd::Create { .. } | Cmd::Bitcoin { .. } => unreachable!("handled above"),
		Cmd::Info => w.info(),
		Cmd::Address => w.address(),
		Cmd::Balance => {
			let mut b = w.balance()?;
			b["bitcoin"] = bitcoin_balance(&datadir);
			b["rows"] = rows(&b);
			Ok(b)
		},
		Cmd::Coins => w.coins(),
		Cmd::Record { leaf_id } => w.record(&leaf_id),
		Cmd::Board { asset: a, amount, fee_asset } => w.board(asset(&a)?, amount, fee_asset.as_deref().map(asset).transpose()?),
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
		Cmd::Restore => w.restore(),
		Cmd::Participate { leaves, not_before, max_fee_ppm } => {
			// The fee is shown before anything is signed.
			let quote = w.refresh_quote(&leaves, max_fee_ppm)?;
			for c in quote.coins() {
				eprintln!("arca: refresh fee for coin {}: {} of asset {} ({} ppm of its {}; the wallet's bound {} ppm)", c["leaf_id"].as_str().unwrap_or(""),
					c["fee"].as_str().unwrap_or(""), c["asset"].as_str().unwrap_or(""), c["ppm"], c["value"].as_str().unwrap_or(""), c["bound_ppm"]);
			}
			w.participate(quote, not_before)
		},
		Cmd::Sync => w.sync(),
		Cmd::Recheck => w.recheck(),
		Cmd::Exit { leaf_id, fee_asset } => w.exit(&leaf_id, fee_asset.as_deref().map(asset).transpose()?),
		Cmd::Swap(SwapCmd::Offer { give_asset, give, want_asset, want }) => w.swap_offer(asset(&give_asset)?, give, asset(&want_asset)?, want),
		Cmd::Swap(SwapCmd::Accept { offer, accept_near_deadline }) => w.swap_accept(&offer, accept_near_deadline),
		Cmd::Swap(SwapCmd::Complete { accept, accept_near_deadline }) => w.swap_complete(&accept, accept_near_deadline),
		Cmd::Swap(SwapCmd::Cancel { swap }) => w.swap_cancel(&swap),
		Cmd::Refusals => w.refusals(),
		Cmd::Participations => w.participations(),
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
