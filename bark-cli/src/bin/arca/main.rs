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
	/// What the operator minted and burned of an issuer-operated asset, and
	/// what is live in its batches, each transaction read again from the
	/// wallet's own node.
	Supply { asset: String },
	/// A new on-chain Sequentia address of the wallet's.
	Address,
	/// The wallet's OpenAMP account key (`m/5/0`): the key a SeqPal ID is,
	/// which a payer may name for this wallet as for an address key.
	OpenampKey,
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
	/// answered, reads the mailbox and moves every participation on. Every
	/// exit step whose date has come (a received leaf's home date, an exit's
	/// next step) is taken first, before the operator is asked anything.
	Sync {
		/// Takes only the exit steps whose date has come, asking the operator
		/// nothing: for a program woken by the schedule's `next_exit_at`.
		#[arg(long)]
		exits_only: bool,
	},
	/// When `sync` must next run (`next_sync_at`), when the next exit step
	/// is due (`next_exit_at`, which `sync --exits-only` takes), and the
	/// dates of every coin held off the chain, asking nothing of the
	/// operator: for a program that runs `sync` on a timer.
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
	/// Orders on the chain under SeqDEX's fill covenant: placed from the
	/// wallet's leaves, filled in the operator's round, refunded once their
	/// time has passed.
	#[command(subcommand)]
	Order(OrderCmd),
	/// Every order the wallet placed, as the chain shows it now: where it
	/// rests (and its terms as SeqDEX's relay serves them), each fill and
	/// what it credited, and the credits at its key. Asks the node only.
	Orders,
	/// Pays many holders in one round (a claim tree): each line of `list`
	/// (a file, or `-` for standard input) names a holder's key and an amount
	/// of `asset`, `KEY AMOUNT`; a key is 64 hex digits (x-only), 66 (a
	/// compressed public key) or a taproot address. Each holder takes its
	/// leaf up with `arca claim`; what no holder takes up by the deadline
	/// goes back to `--return`, by default a new on-chain address of this
	/// wallet's, once the operator's sweep of it is final. `sync` hands over
	/// the forfeits once the round is final.
	Distribute {
		list: String,
		#[arg(long)]
		asset: String,
		/// The address what no holder takes up is paid back to.
		#[arg(long = "return")]
		return_address: Option<String>,
		/// Only says what the distribution would cost (the operator's fee,
		/// the coins it gives up), signing and asking nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The fee shown to the user, as `--quote` answered it (its `fee`):
		/// the distribution goes ahead only on this very fee.
		#[arg(long)]
		shown: Option<u64>,
	},
	/// Every distribution this wallet made, as the operator shows it: each
	/// claim's state, the deadline and what went back.
	Distributions,
	/// Pre-signs an offline refresh of each coin named (by default every live
	/// coin of a round that no plan names): the operator refreshes it in later
	/// rounds while the wallet stays closed, one step per expiry, until the
	/// date the plan names. Each step runs in its coin's free window, where a
	/// refresh costs nothing. A coin a plan names is paid out of round only
	/// once given up in a round (`plan-release`), which ends its plan.
	Plan {
		/// The coins, by leaf id.
		coins: Vec<String>,
		/// How many expiries the wallet will be away for: one step each, 1 to 6.
		#[arg(long, default_value_t = 2)]
		expiries: usize,
		/// Only says what each plan would cost and until when it would cover
		/// its coin, signing and keeping nothing.
		#[arg(long)]
		quote: bool,
		/// The most a step may cost, in millionths of the coin; a step costs
		/// nothing unless this is given.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
	},
	/// Every offline-refresh plan this wallet made: its coin, each step's
	/// state and leaf, until when it covers the coin at the earliest, and the
	/// date the wallet must sync by.
	Plans,
	/// Cancels the steps of an offline-refresh plan that have not started.
	PlanCancel {
		plan: String,
	},
	/// Gives up planned coins in the next round for a leaf of the wallet's
	/// own, named by no plan, which is then paid out of round like any
	/// coin; each coin's plan ends once that round is final and the forfeit
	/// handed over (at sync), and stands should the round never complete.
	PlanRelease {
		/// The coins: each the current coin of an open or stopped plan.
		#[arg(required = true)]
		coins: Vec<String>,
		/// The most the refresh may cost, in millionths of each coin (the
		/// wallet's refresh bound by default).
		#[arg(long)]
		max_fee_ppm: Option<u64>,
	},
	/// What a wallet does by itself at a sync: takes up every open claim,
	/// cancels each plan whose coin has moved, and plans each coin whose
	/// first step could run within ten days (a coin of no round is
	/// refreshed in a round first).
	Care {
		/// How many receive addresses to look for claims under, from the
		/// first; by default every one handed out and 20 more.
		#[arg(long)]
		scan: Option<u32>,
		/// How many expiries each new plan covers: one step each.
		#[arg(long, default_value_t = 2)]
		expiries: usize,
		/// The most a step may cost, in millionths of the coin (2,000 unless
		/// given).
		#[arg(long)]
		max_fee_ppm: Option<u64>,
	},
	/// The claims paid to this wallet, found by asking the operator under its
	/// OpenAMP account key and each address key: their distribution, value,
	/// state and deadline.
	Claims {
		/// How many receive addresses to ask under, from the first; by
		/// default every one handed out and 20 more.
		#[arg(long)]
		scan: Option<u32>,
	},
	/// Takes up the open claims paid to this wallet's OpenAMP account key and
	/// its on-chain addresses (those named, as `DISTRIBUTION:INDEX` or by leaf id, or every one):
	/// each is checked, kept, and paid out of round to a fresh leaf of the
	/// wallet's own.
	Claim {
		claims: Vec<String>,
		#[arg(long)]
		scan: Option<u32>,
	},
	/// An in-tree swap of two assets with another wallet.
	#[command(subcommand)]
	Swap(SwapCmd),
	/// A swap of native BTC in a Bitcoin ark for an asset in this operator's
	/// tree, with another wallet of the operator, under one payment hash:
	/// the asset through the operator, the BTC through Bark.
	#[command(subcommand, name = "btc-swap")]
	BtcSwap(BtcSwapCmd),
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
enum OrderCmd {
	/// Places an order on the chain from the wallet's leaves: sells
	/// `--amount` of `--sell` for `--for` at `--rate-num` atoms of it for
	/// every `--rate-den` atoms sold, by offboarding exactly that amount into
	/// the address SeqDEX's fill covenant makes for those terms. The fee
	/// (each coin's refresh fee, the offboard's fee and its unlock margin) is
	/// shown before anything is signed (`--quote`, then `--shown`). Waits for
	/// the operator's round, hands over the forfeits, and answers where the
	/// order rests, with its terms as SeqDEX's relay serves them; the maker
	/// may then go offline. Fills credit the order's own key, which `board`
	/// spends.
	Place {
		/// The asset the order sells.
		#[arg(long)]
		sell: String,
		/// How much of it, in its atoms: exactly what the order holds.
		#[arg(long)]
		amount: u64,
		/// The asset it is paid in.
		#[arg(long = "for")]
		want: String,
		#[arg(long)]
		rate_num: u64,
		#[arg(long)]
		rate_den: u64,
		/// The least a fill takes and a remainder holds; the whole amount
		/// when not named.
		#[arg(long)]
		min_lot: Option<u64>,
		/// The median time from which the maker may refund it.
		#[arg(long, required_unless_present = "expires_in_hours", conflicts_with = "expires_in_hours")]
		expires: Option<u32>,
		/// The same, as hours from the chain's median time now.
		#[arg(long)]
		expires_in_hours: Option<u32>,
		/// The 32-byte version 1 program every fill credits, in hex, in
		/// place of the order's own key: a plain key's, never an Arca
		/// script's, which the wallet refuses.
		#[arg(long)]
		maker_prog: Option<String>,
		/// The most the fee may take of the amount, in millionths: 10,000
		/// unless raised.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// Only says what placing the order would cost (the coins, the fee,
		/// the change), signing and asking nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The quote shown to the user, as `--quote` answered it: the order
		/// is placed only on that very fee and those coins.
		#[arg(long)]
		shown: Option<String>,
		/// How long to wait, in seconds, for the order to rest on the chain,
		/// final, syncing meanwhile; 0 answers once the operator has the
		/// participation, and `sync` and `orders` take it on.
		#[arg(long, default_value_t = 3600)]
		wait: u64,
	},
	/// Fills an order resting on the chain under SeqDEX's fill covenant in
	/// the operator's round: `take`, by the name the order's side goes by.
	Fill {
		/// The order as the relay serves it: its `CovenantTerms` JSON (or an
		/// offer whose settlement is one), `@FILE`, or `-` for standard input.
		order: String,
		/// How much of the asset the order sells to take, in its atoms; all
		/// of it when not named.
		#[arg(long)]
		amount: Option<u64>,
		/// The most the operator's fee may take of the price, in millionths:
		/// 10,000 unless raised.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// Only says what the fill would cost, signing and asking nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The fill shown to the user, as `--quote` answered it.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Rests an order in the tree, as a leaf of its own (`order-2`): takers
	/// fill it there while the wallet is away, each fill under the
	/// operator's signature and held by the leaf's program to these terms.
	/// It gives up leaves of `--sell` for one leaf of exactly `--amount` of
	/// it, paying their refresh fees (shown before anything is signed with
	/// `--quote`, then `--shown`). Once the operator's round is final, `sync`
	/// hands over the forfeits and publishes the order; each `sync` after
	/// takes up the credits its fills pay and what rests. Brought on the
	/// chain, the order lands after the exit delay as SeqDEX's own order for
	/// the same terms, filled on the chain by anyone and refundable by the
	/// order key from `--expires`.
	Rest {
		/// The asset the order sells.
		#[arg(long)]
		sell: String,
		/// How much of it, in its atoms: exactly what the order holds.
		#[arg(long)]
		amount: u64,
		/// The asset it is paid in.
		#[arg(long = "for")]
		want: String,
		#[arg(long)]
		rate_num: u64,
		#[arg(long)]
		rate_den: u64,
		/// The least a fill takes and a remainder holds; the whole amount
		/// when not named.
		#[arg(long)]
		min_lot: Option<u64>,
		/// The median time from which its landed order may be refunded; the
		/// operator co-signs no fill within its order margin of it.
		#[arg(long, required_unless_present = "expires_in_hours", conflicts_with = "expires_in_hours")]
		expires: Option<u32>,
		/// The same, as hours from the chain's median time now.
		#[arg(long)]
		expires_in_hours: Option<u32>,
		/// The most the fee may take of the amount, in millionths: 10,000
		/// unless raised.
		#[arg(long)]
		max_fee_ppm: Option<u64>,
		/// Only says what resting the order would cost, signing and asking
		/// nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The quote shown to the user, as `--quote` answered it.
		#[arg(long)]
		shown: Option<String>,
	},
	/// The orders the wallet rests in the tree, as the operator shows them
	/// (where each rests, what is left, its fills) with the credits the
	/// wallet holds of each; and any other resting orders named by their ids.
	Resting { orders: Vec<String> },
	/// Fills another maker's order resting in the tree, by its id: the
	/// wallet checks the coin it rests at against its round, and pays with
	/// its own coins of the asset the order is paid in that expire no earlier.
	FillResting {
		order: String,
		/// How much of the asset the order sells to take, in its atoms; all
		/// of what rests when not named.
		#[arg(long)]
		amount: Option<u64>,
		/// Only says what the fill would take, pay and cost, and the coin the
		/// order rests at now, signing nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The quote shown to the user, as `--quote` answered it: the fill is
		/// of the order as it was served then, and goes ahead only on what
		/// the quote showed.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Cancels an order the wallet rests in the tree: what rests of it comes
	/// back to a leaf of the wallet's own.
	CancelResting {
		order: String,
		/// Only says what the cancel would give back and cost, signing nothing.
		#[arg(long, conflicts_with = "shown")]
		quote: bool,
		/// The quote shown to the user, as `--quote` answered it.
		#[arg(long)]
		shown: Option<String>,
	},
	/// Takes back what an order holds where it rests, by its REFUND, once
	/// the chain's median time has passed its expiry: to an address of the
	/// wallet's.
	Refund {
		/// The order, as `order place` and `orders` name it.
		order: String,
		/// The asset to pay the fee in where the node does not take the
		/// order's own asset for fees.
		#[arg(long)]
		fee_asset: Option<String>,
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

#[derive(Subcommand)]
enum BtcSwapCmd {
	/// Offers a swap: `--give btc` gives `--sats` of BTC for `--atoms` of
	/// `--asset`; `--give asset` gives the atoms for the BTC, and makes now
	/// the Bitcoin invoice the taker will pay. Shows what the wallet gives
	/// and gets, with every fee; nothing is locked. The offer lapses after
	/// `--lapse-seconds`, or with the invoice.
	Offer {
		#[arg(long)]
		give: String,
		#[arg(long)]
		asset: String,
		#[arg(long)]
		atoms: u64,
		#[arg(long)]
		sats: u64,
		#[arg(long, default_value_t = 1800)]
		lapse_seconds: u64,
	},
	/// What taking an offer would give and get, with every fee; asks for,
	/// makes and locks nothing.
	Read { offer: String },
	/// Takes an offer: as the one who gets the asset, asks the operator to
	/// receive it under the hash of the maker's Bitcoin invoice; as the one
	/// who gets the BTC, makes the Bitcoin invoice the maker will pay.
	/// Nothing is locked. Prints the take, for the maker to complete.
	Take { offer: String },
	/// Completes the wallet's offer with the taker's take.
	Complete { take: String },
	/// Moves the wallet's swaps on (or the one named), running Bark as each
	/// needs: the lock of the asset, the claim of the BTC while the payer
	/// pays (in slices of `--claim-slice` seconds), the payment of the BTC
	/// once the asset leaf is held and final, the claim of that leaf with the
	/// preimage. Goes on for `--wait` seconds; one pass when 0.
	Follow {
		swap: Option<String>,
		#[arg(long, default_value_t = 0)]
		wait: u64,
		#[arg(long, default_value_t = 20)]
		claim_slice: u64,
	},
	/// Every swap the wallet takes part in, with where it stands, and the
	/// legs a restore found of swaps whose record it lost.
	List,
	/// Cancels a swap the wallet has locked nothing of yet.
	Cancel { swap: String },
}

/// `arca btc-swap …`: the Sequentia side is the library's
/// ([`bark::arca::btc_swap`]); this runs Bark for the Bitcoin side and hands
/// it what Bark said.
fn btc_swap(w: &mut Wallet, datadir: &Path, c: BtcSwapCmd) -> Result<Value, bark::arca::Error> {
	let gets_btc = |offer: &str, w: &mut Wallet, ark: &Value| -> Result<bool, bark::arca::Error> {
		Ok(w.btc_swap_read(offer, &json!({"ark_info": ark}))?["role"] == "P")
	};
	match c {
		BtcSwapCmd::Offer { give, asset: a, atoms, sats, lapse_seconds } => {
			let ark = bitcoin::ark_info(datadir)?;
			let p = give != "btc";
			let fee = bitcoin::lightning_fee(datadir, if p { "receive" } else { "pay" }, sats)?;
			let mut b = json!({"ark_info": ark, "fee": fee});
			// The giver of the asset makes the Bitcoin invoice now; an offer
			// refused cancels it.
			let made = if p && give == "asset" {
				let inv = bitcoin::invoice(datadir, sats, Some("btc swap"))?["invoice"].as_str().unwrap_or("").to_string();
				b["invoice"] = json!(inv);
				Some(inv)
			} else { None };
			w.btc_swap_offer(&give, asset(&a)?, atoms, sats, lapse_seconds, &b).inspect_err(|_| {
				if let Some(i) = &made {
					let _ = bitcoin::cancel_receive(datadir, i);
				}
			})
		},
		BtcSwapCmd::Read { offer } => {
			let ark = bitcoin::ark_info(datadir)?;
			let p = gets_btc(&offer, w, &ark)?;
			let v = w.btc_swap_read(&offer, &json!({"ark_info": ark}))?;
			let fee = bitcoin::lightning_fee(datadir, if p { "receive" } else { "pay" }, v["sats"].as_str().and_then(|s| s.parse().ok())
				.unwrap_or(0))?;
			w.btc_swap_read(&offer, &json!({"ark_info": ark, "fee": fee}))
		},
		BtcSwapCmd::Take { offer } => {
			let ark = bitcoin::ark_info(datadir)?;
			let p = gets_btc(&offer, w, &ark)?;
			let sats: u64 = w.btc_swap_read(&offer, &json!({"ark_info": ark}))?["sats"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
			let fee = bitcoin::lightning_fee(datadir, if p { "receive" } else { "pay" }, sats)?;
			let mut b = json!({"ark_info": ark, "fee": fee});
			let made = if p {
				let inv = bitcoin::invoice(datadir, sats, Some("btc swap"))?["invoice"].as_str().unwrap_or("").to_string();
				b["invoice"] = json!(inv);
				Some(inv)
			} else { None };
			w.btc_swap_take(&offer, &b).inspect_err(|_| {
				if let Some(i) = &made {
					let _ = bitcoin::cancel_receive(datadir, i);
				}
			})
		},
		BtcSwapCmd::Complete { take } => {
			let ark = bitcoin::ark_info(datadir)?;
			w.btc_swap_complete(&take, &json!({"ark_info": ark}))
		},
		BtcSwapCmd::Follow { swap, wait, claim_slice } => {
			// A `bark` a stopped run left behind finishes first.
			let ark = bitcoin::ark_info_waiting(datadir, std::time::Duration::from_secs(wait.max(120)))?;
			let until = std::time::Instant::now() + std::time::Duration::from_secs(wait);
			let mut ran = vec![];
			loop {
				let steps = w.btc_swap_follow(swap.as_deref(), &json!({"ark_info": ark}))?;
				let mut acted = false;
				for s in &steps {
					let (Some(id), Some(b)) = (s["swap"].as_str(), s.get("bitcoin")) else { continue };
					let inv = b["invoice"].as_str().unwrap_or("");
					let left = until.saturating_duration_since(std::time::Instant::now()).as_secs();
					let result = match b["action"].as_str() {
						Some("claim") => bitcoin::claim_for_swap(datadir, inv, std::time::Duration::from_secs(claim_slice.min(left).max(5))),
						Some("pay") => bitcoin::pay_for_swap(datadir, inv),
						Some("pay_status") => bitcoin::pay_status_for_swap(datadir, inv),
						Some("cancel_receive") => bitcoin::cancel_receive(datadir, inv),
						_ => continue,
					};
					acted |= result["state"] != "waiting" && result["state"] != "pending";
					let after = w.btc_swap_bitcoin(id, &result)?;
					ran.push(json!({"swap": id, "bitcoin": result, "after": after}));
				}
				let done = steps.iter().all(|s| s.get("bitcoin").is_none());
				if std::time::Instant::now() >= until || (done && wait == 0) {
					return Ok(json!({"swaps": steps, "bitcoin": ran}));
				}
				if !acted {
					std::thread::sleep(std::time::Duration::from_secs(2));
				}
			}
		},
		BtcSwapCmd::List => w.btc_swaps(),
		BtcSwapCmd::Cancel { swap } => {
			let mut v = w.btc_swap_cancel(&swap)?;
			if let Some(i) = v["bitcoin"]["invoice"].as_str().map(String::from) {
				v["bitcoin"]["result"] = bitcoin::cancel_receive(datadir, &i);
			}
			Ok(v)
		},
	}
}

fn asset(s: &str) -> Result<AssetId, bark::arca::Error> {
	AssetId::from_str(s).map_err(|e| bark::arca::Error::Parse(format!("asset {:?}: {}", s, e)))
}

/// Thirty-two bytes from their hex.
fn unhex32(s: &str) -> Result<[u8; 32], bark::arca::Error> {
	bark::arca::chain::unhex32(s.trim())
}

fn hex_of(b: &[u8]) -> String {
	bark::arca::chain::hex(b)
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
/// reference unit where the wallet's node has a rate for it: what the
/// library's balance counts of it (`held`, which counts a coin whose exit's
/// claim is out once, as the claim's output on the chain). An asset with
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
	for (a, v) in b["held"].as_object().into_iter().flatten() {
		*per.entry(a.clone()).or_default() += v.as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
	}
	// A library from before `held` counted its rows here, by state.
	for (a, states) in b["arca"].as_object().into_iter().flatten().filter(|_| b["held"].is_null()) {
		// A leaf awaiting the preimage of a hash the wallet did not make is
		// shown apart and counted in no row.
		for (_, v) in states.as_object().into_iter().flatten().filter(|(s, _)| *s != "awaiting_preimage") {
			*per.entry(a.clone()).or_default() += v.as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
		}
	}
	for (a, v) in b["sequentia_onchain"].as_object().into_iter().flatten().filter(|_| b["held"].is_null()) {
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
		/// The htlc-1 leaf's timeout, a median time of the chain: within the
		/// operator's window for a payment's timeout (its `timeout_seconds` to
		/// twice that past the chain's median time), refused before anything
		/// is signed otherwise. A little past the operator's least unless
		/// given. An invoice of the operator's own, for a payment into its
		/// tree, is paid inside the operator, and its receiver's leaf times
		/// out the operator's `internal_gap_seconds` before this one.
		#[arg(long)]
		timeout: Option<u32>,
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
		/// Receives under this payment hash (hex), one the wallet did not
		/// make and whose preimage reaches it later (`lightning preimage`, or
		/// the operator's status once the operator knows it). Until the
		/// wallet holds the preimage its leaf is held apart, counted in no
		/// balance (`awaiting_preimage`). Not for `btc`: Bark makes every
		/// invoice's preimage itself.
		#[arg(long)]
		hash: Option<String>,
	},
	/// Hands the wallet the preimage (hex) of a payment it receives under a
	/// hash it did not make (`receive --hash`): kept once it opens the hash,
	/// and the leaf claimed with it by the next `sync`.
	Preimage {
		hash: String,
		preimage: String,
	},
	/// The operator's payment into its tree under a payment hash, as it
	/// serves it to anyone holding the hash: its invoice, its state, the
	/// receiver leaf's exit delay, what holds it, and the preimage once the
	/// operator knows it.
	Lookup {
		hash: String,
	},
	/// Hands the operator the preimage (hex) of a payment into its tree:
	/// the payment is claimed with it once its leaf is its owner's, a
	/// payment held inside the operator is decided by it, and the operator
	/// serves it from then on. The preimage is public once posted.
	PostPreimage {
		hash: String,
		preimage: String,
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
		Cmd::Lightning(LightningCmd::Receive { asset: a, hash: Some(_), .. }) if is_btc(a) =>
			return Err(bark::arca::Error::Refused("a BTC invoice is Bark's, and Bark makes every invoice's preimage itself: it takes no \
				payment hash".into())),
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
				"note": "the restore stopped at this error: what it took before it is kept (`arca coins`, `arca participations`), and \
				`arca restore` takes the rest once the cause is gone"}}));
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
	// `sync` takes the exit steps whose date has come before it asks the
	// operator anything, and witnesses itself, patiently.
	if !matches!(cli.command, Cmd::Address | Cmd::OpenampKey | Cmd::Balance { .. } | Cmd::Coins | Cmd::Record { .. } | Cmd::Refusals | Cmd::Participations
		| Cmd::Exit { .. } | Cmd::Schedule | Cmd::Sync { .. } | Cmd::Orders | Cmd::Order(OrderCmd::Refund { .. }) | Cmd::Claims { .. }
		| Cmd::Distributions | Cmd::Plans)
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
		Cmd::Recheck | Cmd::Sync { .. } | Cmd::Schedule => None,
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
		Cmd::Supply { asset: a } => w.supply(asset(&a)?),
		Cmd::Address => w.address(),
		Cmd::OpenampKey => w.openamp_key().map(|k| serde_json::json!({"key": k.to_string(), "path": "m/5/0"})),
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
		Cmd::Lightning(LightningCmd::Pay { invoice, asset: a, max_fee_ppm, timeout, wait }) => {
			let mut v = w.lightning_pay_until(&invoice, a.as_deref().map(asset).transpose()?, max_fee_ppm, timeout)?;
			let hash = v["paying"]["payment_hash"].as_str().unwrap_or("").to_string();
			v["payment"] = w.lightning_follow(&hash, std::time::Duration::from_secs(wait))?;
			Ok(v)
		},
		Cmd::Lightning(LightningCmd::Payments) => w.lightning_payments(),
		Cmd::Lightning(LightningCmd::Receive { asset: a, amount, description, max_fee_ppm, hash }) => {
			let hash = hash.as_deref().map(unhex32).transpose()?;
			w.lightning_receive_under(asset(&a)?, amount, description.as_deref(), max_fee_ppm, hash)
		},
		Cmd::Lightning(LightningCmd::Preimage { hash, preimage }) => w.lightning_receive_preimage(&hash.to_lowercase(), &unhex32(&preimage)?),
		Cmd::Lightning(LightningCmd::Lookup { hash }) => w.lightning_lookup(&hex_of(&unhex32(&hash)?)),
		Cmd::Lightning(LightningCmd::PostPreimage { hash, preimage }) => w.lightning_post_preimage(&hash.to_lowercase(), &unhex32(&preimage)?),
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
		Cmd::Sync { exits_only: false } => w.sync(),
		Cmd::Sync { exits_only: true } => w.sync_exits(),
		Cmd::Schedule => w.sync_schedule(),
		Cmd::Recheck => w.recheck(),
		Cmd::Exit { leaf_id, fee_asset, quote: true, .. } => w.exit_quote(&leaf_id, fee_asset.as_deref().map(asset).transpose()?),
		Cmd::Exit { leaf_id, fee_asset, quote: false, shown } => {
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the fees shown: {}", e)))).transpose()?;
			w.exit_shown(&leaf_id, fee_asset.as_deref().map(asset).transpose()?, shown.as_ref())
		},
		Cmd::Take { order, amount, max_fee_ppm, quote, shown } | Cmd::Order(OrderCmd::Fill { order, amount, max_fee_ppm, quote, shown }) => {
			let order = read_order(&order)?;
			if quote {
				w.take_quote(&order, amount, max_fee_ppm)
			} else {
				let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
					.map_err(|e| bark::arca::Error::Parse(format!("the take shown: {}", e)))).transpose()?;
				w.take(&order, amount, max_fee_ppm, shown.as_ref())
			}
		},
		Cmd::Order(OrderCmd::Place { sell, amount, want, rate_num, rate_den, min_lot, expires, expires_in_hours, maker_prog, max_fee_ppm,
			quote, shown, wait }) =>
		{
			let expiry = match (expires, expires_in_hours) {
				(Some(t), _) => t,
				(None, Some(h)) => w.expiry_in(h.saturating_mul(3600))?,
				(None, None) => unreachable!("clap requires one"),
			};
			let ask = bark::arca::order::ask_of(&json!({"sell": sell, "amount": amount, "want": want, "rate_num": rate_num,
				"rate_den": rate_den, "min_lot": min_lot, "expiry": expiry, "maker_prog": maker_prog}))?;
			if quote {
				return w.order_quote(&ask, max_fee_ppm);
			}
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the order shown: {}", e)))).transpose()?;
			let placed = w.order_place(&ask, max_fee_ppm, shown.as_ref())?;
			wait_for_order(&mut w, placed, wait)
		},
		Cmd::Order(OrderCmd::Refund { order, fee_asset }) => w.order_refund(&order, fee_asset.as_deref().map(asset).transpose()?),
		Cmd::Order(OrderCmd::Rest { sell, amount, want, rate_num, rate_den, min_lot, expires, expires_in_hours, max_fee_ppm, quote,
			shown }) =>
		{
			let expiry = match (expires, expires_in_hours) {
				(Some(t), _) => t,
				(None, Some(h)) => w.expiry_in(h.saturating_mul(3600))?,
				(None, None) => unreachable!("clap requires one"),
			};
			let ask = bark::arca::resting::RestAsk { sell: asset(&sell)?, amount, want: asset(&want)?, rate_num, rate_den,
				min_lot: min_lot.unwrap_or(amount), expiry };
			if quote {
				return w.order_rest_quote(&ask, max_fee_ppm);
			}
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the order shown: {}", e)))).transpose()?;
			w.order_rest(&ask, max_fee_ppm, shown.as_ref())
		},
		Cmd::Order(OrderCmd::Resting { orders }) => w.resting_orders(&orders),
		Cmd::Order(OrderCmd::FillResting { order, amount, quote, shown }) => {
			if quote {
				return w.order_fill_resting_quote(&order, amount);
			}
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the fill shown: {}", e)))).transpose()?;
			w.order_fill_resting(&order, amount, shown.as_ref())
		},
		Cmd::Order(OrderCmd::CancelResting { order, quote, shown }) => {
			if quote {
				return w.order_cancel_resting_quote(&order);
			}
			let shown = shown.map(|s| serde_json::from_str::<Value>(&s)
				.map_err(|e| bark::arca::Error::Parse(format!("the cancel shown: {}", e)))).transpose()?;
			w.order_cancel_resting(&order, shown.as_ref())
		},
		Cmd::Orders => w.orders(),
		Cmd::Swap(SwapCmd::Offer { give_asset, give, want_asset, want }) => w.swap_offer(asset(&give_asset)?, give, asset(&want_asset)?, want),
		Cmd::Swap(SwapCmd::Accept { offer, accept_near_deadline }) => w.swap_accept(&offer, accept_near_deadline),
		Cmd::Swap(SwapCmd::Complete { accept, accept_near_deadline }) => w.swap_complete(&accept, accept_near_deadline),
		Cmd::Swap(SwapCmd::Cancel { swap }) => w.swap_cancel(&swap),
		Cmd::BtcSwap(c) => btc_swap(&mut w, &datadir, c),
		Cmd::Refusals => w.refusals(),
		Cmd::Participations => w.participations(),
		Cmd::Distribute { list, asset: a, return_address, quote, shown } => {
			let mut claims = vec![];
			for (key, amount) in read_claims(&list)? {
				claims.push((w.named(&key)?, amount));
			}
			if quote {
				w.distribute_quote(asset(&a)?, &claims)
			} else {
				let return_to = return_address.as_deref().map(|r| w.script_of(r)).transpose()?;
				w.distribute(asset(&a)?, &claims, return_to, shown)
			}
		},
		Cmd::Distributions => w.distributions(),
		Cmd::Plan { coins, expiries, quote, max_fee_ppm } => if quote {
			w.plan_quote(&coins, expiries, max_fee_ppm)
		} else {
			w.plan(&coins, expiries, max_fee_ppm)
		},
		Cmd::Plans => w.plans(),
		Cmd::PlanCancel { plan } => w.plan_cancel(&plan),
		Cmd::PlanRelease { coins, max_fee_ppm } => w.plan_release(&coins, max_fee_ppm),
		Cmd::Care { scan, expiries, max_fee_ppm } => w.care(scan, expiries, max_fee_ppm),
		Cmd::Claims { scan } => w.claims(scan),
		Cmd::Claim { claims, scan } => w.claim(&claims, scan),
	}
}

/// The claims of a distribution's list: a file, or `-` for standard input,
/// each line `KEY AMOUNT` (a comma between them is taken too), blank lines
/// and lines from `#` on left out.
fn read_claims(list: &str) -> Result<Vec<(String, u64)>, bark::arca::Error> {
	let text = if list == "-" {
		let mut s = String::new();
		std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| bark::arca::Error::Io(e.to_string()))?;
		s
	} else {
		std::fs::read_to_string(list).map_err(|e| bark::arca::Error::Io(format!("{}: {}", list, e)))?
	};
	let mut out = vec![];
	for (n, line) in text.lines().enumerate() {
		let line = line.split('#').next().unwrap_or("").trim();
		if line.is_empty() {
			continue;
		}
		let parts: Vec<&str> = line.split(|c: char| c.is_whitespace() || c == ',').filter(|p| !p.is_empty()).collect();
		let [key, amount] = parts[..] else {
			return Err(bark::arca::Error::Parse(format!("line {} of the list: {:?} is not KEY AMOUNT", n + 1, line)));
		};
		let amount = amount.parse::<u64>().map_err(|_| bark::arca::Error::Parse(format!("line {} of the list: {:?} is no amount in \
			atoms", n + 1, amount)))?;
		out.push((key.to_string(), amount));
	}
	Ok(out)
}

/// Waits up to `wait` seconds for the order `placed` names to rest on the
/// chain, final, syncing every few seconds meanwhile (the forfeits go over
/// once its round is final): answers the placement with where it rests, or
/// where it stands when the wait ends.
fn wait_for_order(w: &mut Wallet, placed: Value, wait: u64) -> Result<Value, bark::arca::Error> {
	if wait == 0 {
		return Ok(placed);
	}
	let id = placed["order"].as_str().unwrap_or("").to_string();
	let until = std::time::Instant::now() + std::time::Duration::from_secs(wait);
	loop {
		std::thread::sleep(std::time::Duration::from_secs(2));
		if let Err(e) = w.sync() {
			eprintln!("arca: a sync while waiting for order {}: {}", id, e);
		}
		let orders = w.orders()?;
		let now = orders.as_array().and_then(|a| a.iter().find(|o| o["order"] == json!(id))).cloned().unwrap_or(Value::Null);
		let mut out = placed.clone();
		out["placed"] = now.clone();
		if now["state"] == "not_placed" {
			return Err(bark::arca::Error::Refused(format!("order {} was not placed: {}", id, now["note"].as_str().unwrap_or(""))));
		}
		if now["state"] == "resting" && now["final"] == json!(true) {
			return Ok(out);
		}
		if std::time::Instant::now() >= until {
			out["note"] = json!(format!("still {} after {} s: `arca sync` takes it on, and `arca orders` says where it rests",
				now["state"].as_str().unwrap_or("waiting"), wait));
			return Ok(out);
		}
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
