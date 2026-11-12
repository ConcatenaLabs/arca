# arca-wallet-wasm

The Arca wallet (`bark::arca`, the library the `arca` command line runs) built
for a browser. A web wallet loads this crate's package in a dedicated worker and
drives the wallet through one class, `ArcaWallet`, with the command line's
commands and the command line's JSON. Nothing of the wallet is written again
here: every script, record, check, store write, fee and refusal is the
library's.

## What the browser gives the library

The library is blocking. It reaches its node and the Arca server with one HTTP
request at a time and waits for each answer, it pauses between tries of an
operator that does not answer, and it keeps its state in SQLite. In a browser:

- **HTTP** is a synchronous `XMLHttpRequest`, which only a dedicated worker may
  block on. This crate registers it with `sequentia_ext::platform::set_platform`
  before anything else runs; the library builds without a transport of its own
  (the `arca-core` feature of `arca-wallet`), so every request goes through it.
  A server or node on another origin than the page must answer CORS.
- **The node** is any `sequentiad` with `-txindex` and `-validateanchor`, and
  the library makes these JSON-RPC calls of it and no other:
  `getblockchaininfo`, `getblockhash`, `getblockheader`, `getblock` (verbosity
  0, the raw block), `getrawtransaction`, `gettxout`, `getrawmempool` (txids
  only), `getmempoolentry`, `getmempoolinfo`, `scantxoutset` (`start`, with
  `raw()` descriptors), `decodescript`, `getanchorstatus`,
  `getfeeexchangerates` with `dumpassetlabels` (the node keys its rates by
  label), and `sendrawtransaction`, the one that writes. Reads that do not
  depend on each other go together in one JSON-RPC batch where the node or
  its proxy takes one; a proxy that refuses batches is asked one call at a
  time, and tried with a batch again every ten minutes. A proxy that is busy,
  restarting or out of time refuses nothing: that batch's reads are made one
  at a time and the next batch is sent as before. A page
  holds no node credential worth having, so a site serves its wallets a proxy
  that allows exactly these calls, adds the node's credential itself and
  limits each caller, and the wallet is created with `node_url` alone.
  `scantxoutset` reads the whole UTXO set, whatever number of scripts it
  looks for. A scan carries every script the wallet looks for at once (up to
  20,000) where the node's route takes them, as a node's own RPC does; a
  proxy that refuses a scan of more than 256 descriptors is asked in parts of
  256 from its first refusal on. The
  wallet scans once for each
  window of on-chain scripts and each output it looks for when the chain has
  moved since its last command (a few, among some fifty calls, for a wallet of
  twenty coins after a new block), and not at all while it has not (see What
  is checked when): a limit that lets a caller make a few dozen in a row, then
  about one a second, keeps the wallet working. The node runs one scan at a
  time for all its clients: a scan it refuses as busy with another's waits on
  the pause and is asked again, for two minutes at most, and the refusal is
  never kept as the chain's answer.
- **The pause** between two tries (a node or proxy that answers busy or "too
  many calls", an operator that does not answer) is the host's to give. A worker
  blocked in the library has nothing else to do, but a pause that watches the
  clock keeps a processor core busy for the whole of it, and a long restore
  behind a rate-limited proxy pauses for minutes. So the host hands the library
  a wait of its own with `setPause(wait)`: `wait(ms)` blocks the thread for up to
  `ms` milliseconds without using the processor, and returns. The library calls
  it for each pause and watches the clock only for what it left over, so a wait
  that returns early, throws or is never given still makes a whole pause, at the
  cost of a busy core. How the host waits is its own choice, and the library
  names no address for it:
  - under Node, or in a page that is cross-origin isolated, `Atomics.wait` on a
    `SharedArrayBuffer`;
  - in any other page, a synchronous request to a server of its own origin that
    holds the request open for the pause and then answers (the web wallet asks
    its node proxy's `/hold`).

  `pause(ms)` makes one pause as the library does, for a host to check its wait.
- **The store** is the same SQLite schema, on SQLite's OPFS storage
  (`opfs-sahpool`, from `sqlite-wasm-vfs`), which `installStore` installs as the
  default before a wallet is opened. SQLite commits every write to disk before the
  next statement runs, so what the wallet writes before it broadcasts or hands
  anything over survives a closed tab, as with the native file. The storage
  admits one worker at a time: a second tab's `installStore` fails while the first
  holds it. There is one store per mnemonic, named after the wallet's mailbox key.
  The store keeps no mnemonic: the page hands it over on every open, and an open
  with another mnemonic than the store's is refused.

The store holds what the mnemonic cannot rebuild on its own (which coins were
spent off the chain, the forfeits signed, the heads of the operator's signer's
record), as `arca`'s directory does. A wallet whose store is gone (a site's
data cleared, another browser) is created again from its mnemonic with
`ArcaWallet.create` and restored with `run('restore')`, which rebuilds what
the server and the chain hold of it, every record checked, as `arca create
--mnemonic` does (`bark-cli/README.md`, Restoring from the mnemonic). It
returns once the coins that make the balance are checked; the coins given up
for good, the wallet's history, are checked after it, in slices:
`run('restore_history', {budget_ms})` checks coins for about that long (past
it only by the coin it was checking, at least one) and answers how many are
`left` and how long it ran (`ms`); each `sync` runs a slice of about a second.
A page runs slices while nobody asks the wallet for anything, one after the
other, so a person's ask waits for one slice at most, never for the whole
history. While they are left, `balance` carries `history: {"loading": true,
"left": N}`: a page shows its activity as still loading until it is gone. The restore leaves
the watchtowers' deposits owed (`deposits.owed`): the page runs `deposits` as
soon as `restore` returns, and a `sync` makes them first while they are owed.
`restore {at_once: true}` checks everything before it returns instead.

## Why a workspace of its own

The native build links SQLite through `rusqlite` 0.31, whose SQLite has no
`wasm32-unknown-unknown` build; `rusqlite` 0.40 links one (`sqlite-wasm-rs`).
Both declare `links = "sqlite3"`, so they cannot share a lockfile. This
workspace has its own, and `rusqlite-shim/` takes the name and version 0.31
inside it alone (`[patch.crates-io]`), re-exporting 0.40, so the wallet's store
compiles from its own source unchanged. The root workspace excludes this
directory.

## The API

```js
import init, { installStore, setPause, ArcaWallet, arcaWalletExists } from './pkg/leaf_wallet.js'

await init()
await installStore('.leaf-wallet')               // in a dedicated worker, once
setPause((ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms))  // where the host may
if (!arcaWalletExists(mnemonic)) {
  const w = ArcaWallet.create(mnemonic, JSON.stringify({
    server: 'https://host/operator', node_url: 'https://host/node',
    node_user: 'u', node_password: 'p',             // when the node needs them
    exit_delay_units: 253, min_exit_delay_units: 253, max_exit_delay_units: 338,  // optional
  }))
}
const w = ArcaWallet.open(mnemonic, nodePassword)
```

In place of `server`, `from_registry: '<operator key>', registry:
'https://host/registry'` joins the operator the Sequentia registry lists
under that key: the library reads its record, checks the operator's
signature over it, takes the server's address from it, and creates the
wallet only when that server shows the record's operator key, chain and
keepers (`bark::arca::registry`). The registry must be reachable through the
page's transport, as the server and node are.

```js
const { result, start } = JSON.parse(w.run('board', JSON.stringify({ asset, amount: '2000000' })))
```

`run(command, args)` is the library's `bark::arca::command::run`, which every
program that embeds the library calls, and takes the command line's commands, each with its
arguments in `command::COMMANDS` (`bark/src/arca/command.rs`): `info`, `address`, `openamp_key`,
`balance`, `coins {held?, brief?}`, `record {leaf_id}`, `board_quote {asset, amount, fee_asset?}`,
`board {asset, amount, fee_asset?, shown?}`, `boards`, `receive {asset?,
amount?, channels?}` (`channels: false` names none of the wallet's channels), `forget_request {owner}`, `send {request, amount?, asset?, route?}`,
`mailbox`, `restore {at_once?}`, `restore_history {budget_ms?}`, `quote {leaves?, max_fee_ppm?, piece?, pieces?}`, `participate {leaves?,
not_before?, max_fee_ppm?, piece?, pieces?, shown}`, `participations`, `settle_quote {asset,
value, expiry}`, `sync {catch_up?, deposits?}`, `deposits`, `hand_over_forfeits`, `schedule`,
`recheck`, `exit_quote {leaf_id, fee_asset?}`, `exit {leaf_id, fee_asset?,
shown?}`, `speed_up {txid, fee_asset?, rate?, max_fee?}`, `refresh_received
{max_fee_ppm?, leaves?}` (`leaves`: those coins alone), `refresh_needed {idle_seconds?}` (whether what the wallet received out
of round should be refreshed now, and by which rule: `arriving`, `depth`, `exposure`, `expiry`, `idle`, `shape`),
`settle_first {coins? | asset?, max_fee_ppm?}` (puts through the next round the coins a `settle_first` refusal names, giving up
nothing twice: `settling`, `waiting`, `done`, `left`, `ready` once the coins their round made can be spent, and while not,
`final_in_seconds`, the most it should still take, `usual_in_seconds`, what it usually takes, and `waiting_for`, the step it
waits for; a `settle_first` refusal carries the same three),
`instant_limit {value}` (the wallet's instant limit, atoms of the reference unit, or `"off"`),
`coin_places` (each coin's place, `settled`, `proceeds`, `counted` or `arriving`, the totals by asset,
what is spendable now, and the limit),
`withdraw_participation {participation}`, `refusals`; a payment to an address on the chain from leaves
(`offboard_quote {asset, amount | coins | value + expiry, address | script, max_fee_ppm?}`, `offboard
{asset, amount | coins, address | script, fee_asset?, max_fee_ppm?, shown?}`,
`offboards`; `coins` moves the whole of the named coins and no other, with no change, a coin settled first
still named by its old id, and `value` with `expiry` prices that move for a coin before the wallet
holds it, the round it goes through first counted when it would arrive past the instant limit: `fee.amount` is
then the whole fee, `fee.settle` its part, and `max_fee_ppm` bounds the settle and the move each on its own); a take of an on-chain order and an order placed from
leaves (`take_quote`, `take`, `order_quote`, `order_place`, `orders`,
`order_refund`); an order resting in the tree (`order_rest_quote`,
`order_rest`, `order_resting {orders?, brief?}`, `order_fill_resting_quote {order,
amount?}`, `order_fill_resting {order, amount?, shown?}`,
`order_cancel_resting_quote {order}`, `order_cancel_resting {order, shown?}`); the in-tree swap (`swap_offer {give_asset, give, want_asset,
want}`, `swap_read {offer}`, `swap_accept {offer, shown?}`, `swap_complete
{accept}`, `swap_cancel {swap}`, `swaps {swaps?}`); the swap of BTC in a Bitcoin
ark (`btc_swap_*`); payments over Lightning in and out of the tree
(`lightning_pay_quote {invoice, asset?, max_fee_ppm?}`, `lightning_pay {invoice,
asset?, max_fee_ppm?, timeout?, shown?}`, `lightning_payments`,
`lightning_receive_quote {asset, amount, max_fee_ppm?}`, `lightning_receive
{asset, amount, description?, max_fee_ppm?, hash?}`,
`lightning_receive_preimage {hash, preimage}`, `lightning_receive_ready {hash,
need_seconds}`, `lightning_receives`, `lightning_lookup {hash}`,
`lightning_post_preimage {hash, preimage}`); the offline-refresh plans (`plan_quote`, `plan`,
`plans`, `plan_cancel`, `plan_release {leaves, max_fee_ppm?}`), which a page shows only in developer mode; the operator's equivocation bond (`bond`, `bond_evidence`,
`watch_bond {evidence?, fee_asset?}`, the CLI README's "Watching the operator's bond"), whose check `receive` and the swaps run by
themselves; `supervised_check {txid, vout}`, the check of a whole published batch of a supervised asset (see the CLI README's section on
holding a supervised asset), which a page shows only in developer mode, while each coin of a supervised asset carries its
`landing` and `frozen` in `coins` in either mode; `supply {asset}`, the operator's supply report for an asset
it serves issuer-operated, each mint and burn read again from the wallet's node, and each coin's `batch_profile` and `hops` (reassignments since a round) in `coins`
(`issuer-operated` when its batch's sweep can only burn, `open` when it pays the operator), both of which a page shows only in
developer mode; the channel leaves (`channels`, each with `final`, `channel_open {leaves?, capacity, keep?, max_fee_ppm?}`,
`channel_sync {leaf_id?}` (every live channel when none is named), `channel_pay {leaf_id, to, amount}`, `channel_fold {leaf_id}`,
`channel_exit {leaf_id, fee_asset?}`, `channel_code {address?}`, the CLI README's "Channel leaves"), whose payments are final for
the receiver at once: `send {request, amount?, asset?, route?}` takes a receive request or a channel code and pays over the
wallet's channel into the receiver's when it can, otherwise a request to its leaf, refusing a code with its address named for a
payment on the chain, and `route` in its answer says which; `exit` of a channel coin is `channel_exit`; `leaf_template {template?}`, the template the wallet's own new leaves
take (`vtxo-1` or `vtxo-2`, the CLI README's `leaf-template`); and `care {scan?, expiries?, max_fee_ppm?, plan_within?, channels?}`, which a page runs by itself after a sync in either mode (with `channels`, first reading each channel, folding its credit, and opening one in each asset the operator makes them of from half of the wallet's leaves of it, answered under `channels`): it takes up every open claim under the wallet's receive keys, cancels each plan whose coin has moved, and plans each coin whose first step could run within `plan_within` seconds (ten days unless named; `4294967295` plans every leaf of a round at once) but a coin of a supervised asset or a `vtxo-2` coin, which `sync` refreshes, refreshing a coin of no round in a round first once within ten days (see the CLI README's offline refresh section for the gap the default reach leaves). A page that plans every leaf of a round pays from a planned coin through `plan_release`: a payment, take, swap, order or fill that the unplanned coins cannot cover and the planned ones can is refused with `kind` `planned`, naming the `asset` and the coins to `release`; the page releases them, runs `sync` until their round is final and the new leaf held, and asks again. Its answer is `{"result", "start", "cost"}`:
the command's JSON, what the start of the command found, the witness of the
operator's signer's record (unless the command stays on the machine and the
node) and the re-check of every coin against the chain (unless the command is
`recheck`, `sync`, `hand_over_forfeits` or `schedule`), as `arca` runs them on every start, and what
each cost (`cost.start` and `cost.command`, each `{ms, node, operator}`: the
milliseconds and the requests made of the node and of the operator; a part that
asked the node more than fifty reads one at a time adds `alone`, those reads by
method; `cost.operator_ms` is the milliseconds the command waited for the
operator's answers; the re-check's own parts are under `start.recheck.ms`, and
a `sync` answers what each of its steps cost under `cost_by_step`, with `alone`
the same way, and for a step over a second `operator_ms` and `operator_calls`,
`[count, ms]` by call). A refusal carries the same `cost` beside its `error`:
what the command cost before it was refused, so a page that logs a slow command
names one refused after a long time, and what it waited on, as well.

A program that holds many coins asks for what it needs. `coins` with `"held":
true` lists only the coins the wallet holds, leaving out those it spent, exited
or lost, which a wallet that trades all day counts by the thousand and which are
then not read at all. With `"brief": true` each coin is listed as the store
holds it (`leaf_id`, `kind`, `asset`, `value`, `state`, `standing`, `expiry`,
`exit_deadline`, `spent_by`, `template`) and nothing else is read: no dates,
notes, freezes or exit fees, whose reads of the chain (the exit fee of a board
reads every on-chain script the wallet ever drew) a program that counts its
coins many times a minute does not need. `order_resting` with `"brief": true`
lists the wallet's own resting orders as its store holds them (`order`,
`rested_by`, `state`, `amount`) and asks the operator only of the `orders`
named: a maker that rests orders all day has thousands of its own, long filled
or cancelled, and follows the few still resting by their ids. `swaps` with
`"swaps": [id, …]` reads only those swaps, each by its id, rather than every
offer the wallet ever made with its coins' records. `sync` with `"catch_up": false` leaves out the catch-up
between stores of one mnemonic: a program that is the only store of its mnemonic
(a service wallet on one machine) has no other store to catch up with, and the
catch-up reads every coin ever served to its mailbox key to find that out. With
`"deposits": false` it leaves out the watchtowers' step too, which the program
runs next as the command `deposits`: a program that answers others from the
wallet then finds it free between the two. A
command that only reads, run as one of a burst, answers from the look at the
chain another made within three seconds when asked with `"shared_view": true`.

An in-tree swap passes two texts between two wallets. The maker's `swap_offer`
holds its coins and signs nothing, and answers what it gives, gets and pays (the
reassignment's margin and its checkpoints' margins). The taker's `swap_read`
checks the offer as `swap_accept` does and answers what it gives, gets and pays
(with an instant limit set, from the coin of exactly what it gives that the
wallet pays itself first, whose margins it counts, also apart as
`pays.shapes`),
and the `hops` of what the swap makes (reassignments since a round, against the
operator's `depth_limit`), signing, holding and storing nothing; `swap_accept`
with `shown` (that answer)
signs only on those terms. The maker's `swap_complete` signs its side and has the
operator co-sign; one the operator refuses withdraws the offer and is refused
with kind `swap_refused`, naming the `swap`, the `coin` the operator named and
`whose` it is (`maker` or `taker`). `swaps` lists each swap with where it
stands. A spend the operator refuses because a coin of the wallet's is spent
already, by another store of the same mnemonic (a second device), or a
participation (a refresh) it refuses `in_use` because such a store gave one of its
coins up already, has the wallet read what its other stores did at once, so it stops counting that coin
and holds what replaced it. While the other store's round is not final yet,
that read finds nothing: the coin is then held out of every spend (every `sync`
catches up while one is held out), and a spend it would have paid waits for it
as `settle_first`. The hold is the operator's word with an age: it ends once the
operator serves the coin live again (the other store's participation withdrawn
or voided, its round dropped), once a catch-up settles it, and at the latest when
the wait `settle_first` stated for it has passed, so a false refusal costs at most
that one wait. While held, the coin counts in `balance` (as `spent_elsewhere`)
and not in what `coin_places` calls spendable (`spent_elsewhere_until` on its
line), and its exit is never barred; a `swap_cancel` that meets such a coin cancels the
acceptance without a respend. A `swap_cancel` whose respend went unanswered
never calls the acceptance cancelled until the operator has answered it: the
next one posts the respend again and answers `cancelled`, `done`, or, while
the operator cannot be reached, `cancelled: false` with `unknown: true`.

`quote` is the refresh fee, coin by coin, that `participate` would pay; the page
shows it, and `participate` goes ahead only when `shown` equals the fees it
quotes again, so nothing is signed on a fee the user did not see.
`settle_quote` prices that refresh for a coin the wallet does not hold yet, from
its asset, value and expiry (a swap's coin, its expiry from `swap_read`'s
dates): what settling it in the operator's next round costs now. The fee only
falls as time passes, so the `quote` of the coin once held is at most it.
`take_quote` answers what a take leaves the wallet in all (`spends`): the price,
the operator's fee, and the margins of a payment to itself (`pays_itself`, with its change and the change's expiry)
when no coin holds exactly the price and the fee. A payment
over Lightning works the same way: `lightning_pay_quote` answers what paying an
invoice leaves the wallet in all (`spends`: the amount, the operator's fee and
the margins of the coins it spends), the coins it spends (`gives`) and the
change it leaves (`change`), and `lightning_pay` with `shown` set to
that answer pays only on it. `lightning_receive_quote` answers what a receive's
leaf will hold once claimed (`claimed`: the amount less the operator's fee and
the margins of the claim), asking the operator nothing. Both quotes carry the
operator's limit on one payment over its node in the asset (`max_payment`, in
atoms, null when it publishes none), the figure `info` shows under
`server_info.assets[].lightning.max_payment` (`send`, `receive`): the operator
refuses a payment out of the tree above it, and makes no invoice above it, so a
wallet pays on the chain instead. `lightning_receive` above it is refused
before the operator is asked. A receive under a hash
the wallet did not make (`lightning_receive` with `hash`, its preimage someone
else's) is claimed only once `lightning_receive_preimage` hands the preimage
over; `lightning_receive_ready` says when its leaf is held for good enough to
pay that preimage's price: validated, its round final, and its home date at
least `need_seconds` away (the time the other side may take to reveal the
preimage, and the wallet to claim with it). `sync` moves every payment and
receive on. A board and
an exit work the same way: `board_quote` is the board's fee (`fee: {asset,
amount}`), size and coins, and `board` with `shown` set to that `fee` goes ahead
only on it; `exit_quote` is each transaction an exit would broadcast now, with
its size, its fee and what pays it, their fees by asset (`unroll`) and the
claim's fee now, and `exit` with `shown` set to that `unroll`
broadcasts only on those fees. A quote signs, asks and broadcasts nothing, and a
`shown` that no longer holds is refused before anything is written or
broadcast. `schedule` is
`Wallet::sync_schedule`: when `sync` must run next and why. A page runs `sync`
when it is due. `hand_over_forfeits` hands over the forfeits of every round
the operator holds for them before broadcasting it, and does nothing else (the
CLI README's `hand-over-forfeits`): a held round is dropped, and the
participation voided, when they have not come within the operator's window
(`info.fills.forfeit_window_seconds`), so a program whose `sync` runs longer
or comes less often than that runs it on a short timer of its own.

A refusal is thrown as the JSON `arca` prints, `{"error": {"kind",
"message"}}`, with the server's `code` and `status` when the server refused
(and `swap`, `coin` and `whose` for a `swap_refused`; `asset` and `fee` for a
`shaped` refusal: a trade refused after the wallet paid itself the coin it
gives, which left that fee; the coin is kept, and the trade priced again
trades from it).

The page shows what the library says as it says it. With no command line,
the library names the act rather than a command ("run sync", "an exit takes
it now", "send one to the wallet's address"), and prefixes the texts it hands
out `request:`, `swap-offer:` and `swap-accept:`. It reads a text whatever its
prefix, the command line's `arca:…` included.

## What is checked when

The wallet runs every check the Arca specification names, at the moments it
names them; a page keeps one wallet open across commands, and the library
spends nothing it does not have to on reading the chain again.

- **At the start of every command:** the re-check of every coin the wallet
  holds against the chain (`start.recheck`, except for `recheck`, `sync` and
  `schedule`, which run it themselves, and `hand_over_forfeits`, which signs
  only forfeits of coins already given up, against a round it validates): each coin's round or board read where
  the chain holds it now, a round that another transaction replaced checked
  again with the five checks and the wallet's bounds (a failure takes the coin
  on the chain at once), every round and board's finality, each coin's dates,
  and its lineage looked for on the chain and in the mempool. Then the witness
  of the operator's signer's record (`start.witness`), unless the command stays
  on the machine and the node; a witness stands for ten seconds. A command
  given `"recheck": "coins"` among its arguments runs only the part of the
  re-check that concerns the coins (each coin against the chain and its
  lineage watch), leaving the following of its participations' rounds (a round
  that can never return, a re-run whose round stands), which gives coins back
  and guards no spend, to the next `sync` or `recheck`: a program that answers
  others from the wallet, such as a maker's firm offer, asks for it on its
  answer path and runs `sync` on a timer.
- **In every command that reads the operator's terms** (each quote, payment,
  refresh, take, board and swap): the operator's `info`, its key, chain and
  keepers against those the wallet pinned when it was created. An operator
  showing another key is refused there, before anything is signed; a coin's
  records are checked against the pinned key in any case. A command that asks
  the operator nothing (`coins`, `balance`) answers from the wallet's own
  store and the chain.
- **Before every signature:** the command's own checks, on the chain as it is
  then: a payment pays only from coins whose rounds and boards are final now,
  a take reads its order unspent and final, a swap reads the other side's
  coins as a receiver does; fees in what the node accepts now.
- **When a coin is received:** the five checks and the bounds on every leaf of
  its lineage, then it is kept; until then it is not counted.

**How the chain is read.** What the node answers is fixed by three things: the
tip of its active chain, its view of its anchors (`getanchorstatus`), and the
transactions in its mempool. Any reorganisation, of any depth, an anchor-driven
one included, changes the tip; a parent chain the node no longer follows
changes the anchor status; a broadcast, a replacement or an eviction changes
the mempool. The library looks at those three (one request where the node
takes a batch, three calls where it does not) at the start of every command,
after each request to the operator (who may broadcast), after each pause and
each broadcast of its own, and at least once a second. While
they stand it answers each read of the chain from what the node said in that
view; when any changes it drops those answers and reads again. A
transaction's bytes by its id and a block's or a header's by its hash are kept
across views, since no view changes them. What the node values at broadcast
(its fee whitelist, its rates, its relay floor) can change while the view
stands, and is read again in every command. So a command between tip changes
makes a handful of calls; the first after a new block reads, once each, every
base transaction and block the wallet's coins rest on, in two batches where
the node takes them (some fifty single calls for twenty coins where it does
not). The checks themselves run as often as before. The command line reads
the chain the same way, within the one command each of its processes runs.

**What is computed once.** Checking a coin's record against the transactions
it rests on is a pure function of the record, those transactions and the
wallet's policy (which holds the chain's median time): the wallet keeps its
answer for the same three, and works it out again when any of them differs.

## Building

Needs the `wasm32-unknown-unknown` target, `wasm-pack`, and `protoc` (the
wallet crate compiles Bark's gRPC protocol).

    rustup target add wasm32-unknown-unknown
    cd wallet-wasm
    wasm-pack build --target web --release --out-name leaf_wallet

The package is `pkg/leaf_wallet.js` with `pkg/leaf_wallet_bg.wasm`. The web
wallet carries a copy in its `leaves/pkg/`.

The `leaf-wallet-pkg` workflow builds the same package on every change to `master`
that reaches the wallet, with every build-machine path remapped (as the web wallet's
`tooling/build-leaf-wallet.sh` does), and keeps it for 90 days as the artifact
`leaf-wallet-pkg-<commit>`, with its `SHA256SUMS`:

    gh run download -R ConcatenaLabs/arca -n leaf-wallet-pkg-<commit> -D <dir>

`.cargo/config.toml` builds libsecp256k1 with its 32-bit-limb field
(`USE_FORCE_WIDEMUL_INT64`): wasm32 has no 64-by-64-bit multiply, and the
64-bit-limb field spends most of a coin's check in that multiply's emulation.
Both are libsecp256k1's own field implementations.

## Testing against an operator

`bark-cli/tests/arca_operator_for_browsers.rs` keeps a whole Arca server running
on an anchored regtest chain for a wallet outside the test, with a control
address to fund scripts, produce and bury blocks, build rounds and move the
chain's median time. The web wallet's `tooling/leaves-drive.mjs` drives this
package in a headless browser against it, with the `arca` binary as the
counterparty.
