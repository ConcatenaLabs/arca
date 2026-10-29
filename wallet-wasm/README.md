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
  its proxy takes one; a proxy that refuses a batch is asked one call at a
  time from then on. A page
  holds no node credential worth having, so a site serves its wallets a proxy
  that allows exactly these calls, adds the node's credential itself and
  limits each caller, and the wallet is created with `node_url` alone.
  `scantxoutset` reads the whole UTXO set. The wallet scans once for each
  window of on-chain scripts and each output it looks for when the chain has
  moved since its last command (a few, among some fifty calls, for a wallet of
  twenty coins after a new block), and not at all while it has not (see What
  is checked when): a limit that lets a caller make a few dozen in a row, then
  about one a second, keeps the wallet working. The node runs one scan at a
  time for all its clients: a scan it refuses as busy with another's waits on
  the pause and is asked again, for two minutes at most, and the refusal is
  never kept as the chain's answer.
- **The pause** waits on the clock: a worker blocked in the library has nothing
  else to do, and `Atomics.wait` needs a cross-origin-isolated page.
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
--mnemonic` does (`bark-cli/README.md`, Restoring from the mnemonic).

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
import init, { installStore, ArcaWallet, arcaWalletExists } from './pkg/leaf_wallet.js'

await init()
await installStore('.leaf-wallet')               // in a dedicated worker, once
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
`balance`, `coins`, `record {leaf_id}`, `board_quote {asset, amount, fee_asset?}`,
`board {asset, amount, fee_asset?, shown?}`, `boards`, `receive {asset?,
amount?}`, `forget_request {owner}`, `send {request, amount?, asset?, route?}`,
`mailbox`, `restore`, `quote {leaves?, max_fee_ppm?}`, `participate {leaves?,
not_before?, max_fee_ppm?, shown}`, `participations`, `settle_quote {asset,
value, expiry}`, `sync`, `schedule`,
`recheck`, `exit_quote {leaf_id, fee_asset?}`, `exit {leaf_id, fee_asset?,
shown?}`, `refusals`; a payment to an address on the chain from leaves
(`offboard_quote {asset, amount, address | script, max_fee_ppm?}`, `offboard
{asset, amount, address | script, fee_asset?, max_fee_ppm?, shown?}`,
`offboards`); a take of an on-chain order and an order placed from
leaves (`take_quote`, `take`, `order_quote`, `order_place`, `orders`,
`order_refund`); an order resting in the tree (`order_rest_quote`,
`order_rest`, `order_resting {orders?}`, `order_fill_resting_quote {order,
amount?}`, `order_fill_resting {order, amount?, shown?}`,
`order_cancel_resting_quote {order}`, `order_cancel_resting {order, shown?}`); the in-tree swap (`swap_offer {give_asset, give, want_asset,
want}`, `swap_read {offer}`, `swap_accept {offer, shown?}`, `swap_complete
{accept}`, `swap_cancel {swap}`, `swaps`); the swap of BTC in a Bitcoin
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
it serves issuer-operated, each mint and burn read again from the wallet's node, and each coin's `batch_profile` in `coins`
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
`recheck`, `sync` or `schedule`), as `arca` runs them on every start, and what
each cost (`cost.start` and `cost.command`, each `{ms, node, operator}`: the
milliseconds and the requests made of the node and of the operator; the
re-check's own parts are under `start.recheck.ms`).

An in-tree swap passes two texts between two wallets. The maker's `swap_offer`
holds its coins and signs nothing, and answers what it gives, gets and pays (the
reassignment's margin and its checkpoints' margins). The taker's `swap_read`
checks the offer as `swap_accept` does and answers what it gives, gets and pays,
signing, holding and storing nothing; `swap_accept` with `shown` (that answer)
signs only on those terms. The maker's `swap_complete` signs its side and has the
operator co-sign; `swaps` lists each swap with where it stands.

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
the margins of the claim), asking the operator nothing. A receive under a hash
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
claim's fee at the floor now, and `exit` with `shown` set to that `unroll`
broadcasts only on those fees. A quote signs, asks and broadcasts nothing, and a
`shown` that no longer holds is refused before anything is written or
broadcast. `schedule` is
`Wallet::sync_schedule`: when `sync` must run next and why. A page runs `sync`
when it is due.

A refusal is thrown as the JSON `arca` prints, `{"error": {"kind",
"message"}}`, with the server's `code` and `status` when the server refused.

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
  `schedule`, which run it themselves): each coin's round or board read where
  the chain holds it now, a round that another transaction replaced checked
  again with the five checks and the wallet's bounds (a failure takes the coin
  on the chain at once), every round and board's finality, each coin's dates,
  and its lineage looked for on the chain and in the mempool. Then the witness
  of the operator's signer's record (`start.witness`), unless the command stays
  on the machine and the node; a witness stands for ten seconds.
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
