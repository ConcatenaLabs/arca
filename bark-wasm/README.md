# arca-bark-wasm

Bark's wallet for Bitcoin arks (`bark::Wallet`, on Bitcoin) built for a
browser. A web wallet loads this crate's package in a dedicated worker and
drives the wallet through one class, `BtcArk`, with commands by name and JSON
in and out. Nothing of the wallet is written again here: every coin, fee,
signature and refusal is the wallet's or its server's.

## One phrase

The wallet is made from the web wallet's own phrase, under Bark's own key path,
so the phrase restores it anywhere Bark runs (the Arca client's Bitcoin side
is the same wallet). A wallet made anew from a phrase that held coins in the
ark takes back what the server's recovery mailbox kept for it. A store made
before, on a second device, learns what the phrase's other wallets did since
with `catch_up`: the coins they made or received (a board once its wallet has
registered it), and which of its own coins they spent.

Boarding takes the funding from whoever holds the coins: `board_address`
answers the address under a fresh key of the wallet's, the holder builds the
funding transaction, and `board_psbt` takes it unsigned. The server cosigns the
board first; only then does the holder sign and send the funding, and the
wallet registers the board once the funding has the server's confirmations. A
web wallet therefore boards straight from its own Bitcoin address, in one
transaction.

## What the browser gives the wallet

- **The ark server** over gRPC-web (`tonic-web-wasm-client`): a server on
  another origin than the page must answer CORS.
- **The chain** from an Esplora server.
- **The store** in IndexedDB, one database per wallet fingerprint, and the
  browser's locks (`navigator.locks`), which keep two tabs from driving one
  wallet at once.
- **The daemon** runs in the worker while the page is open: it claims Lightning
  payments the server holds for the wallet, takes in what is sent to it in the
  ark, follows boards to the chain and refreshes coins in the server's rounds.

## Renewal with the page closed

`schedule_refreshes` hands the server, for every coin that has none yet, a
delegated refresh scheduled for 72 blocks before the coin's expiry (Bark's
refresh threshold, if that is more): the server runs it in its first round from
that height, with the page closed, and the wallet takes the new coin in at its
next sync, after the old coin's expiry too. Coins sharing an expiry go in one
refresh, for one base fee. A coin spent before its refresh runs drops it on the
server, and the next call schedules one for what replaced it. While a refresh
is scheduled, `refresh` and the daemon leave that coin to the server, until six
blocks past its height. A page calls it when it opens and after each sync,
after `tower_plan`, with `except` set to that plan's `no_refresh`: a coin a
Bitcoin ark watchtower covers gets no delegated refresh (see below).

## Leaving the ark alone

A coin's exit is already signed, so the wallet takes a coin to the chain
without the server: it broadcasts every transaction from the round down to the
coin, then, once the coin's exit delta has passed, claims it to the holder's
own Bitcoin address (`m/84'/coin'/0'/0/0` unless another is named). Each of
those transactions pays no fee itself and carries an anchor a child spends to
pay it. The children are paid from the phrase's own BIP84 account, the coins a
dual-chain wallet holds at its shared address: the wallet is opened with that
account as its onchain wallet, so nothing else needs funding. A child spends
only confirmed coins, so the address needs confirmed BTC for the whole walk,
and the walk advances one level per block at best.

An exit costs Bitcoin fees for every transaction above the coin. A coin is
worth its exit when what reaches the address is more than 330 sat after every
fee; `exit_estimate` prices each coin alone, and `exit_start` refuses one that
is not worth it, in words.

`exit_auto` is default mode's rule, the same in every wallet: when the server
refused the wallet's last renewal (or the caller says it refused, with
`ark_refused`) or cannot be reached now, it takes out every coin worth its exit
within `margin` blocks of its expiry (144 by default, a day); otherwise it
starts nothing. In every case it moves exits already under way on and claims
what has finished. A page calls it after each sync; developer mode offers
`exit_estimate` and `exit_start` as a button.

## Watchtowers for coins away

A holder who goes away past a coin's expiry would otherwise rely on the
operator not to sweep it. `tower_plan` answers what to send the Bitcoin ark
watchtowers the program names (each one's `GET /v1/info`, read by the
program):

- `deposit`: for every coin worth rescuing, a deposit for each watchtower that
  watches the coin's ark, does not hold it yet, and whose own BTC can still pay
  for its rescue. Its claim (signed now by the coin's key) pays the phrase's
  first BIP84 address, less the rescue fee. One rate decides both whether the
  coin is worth it (at least 20 times its rescue cost) and that fee: the
  highest of the day's fast rate, the watchtower's least rate and the rate it
  charges today. Each deposit names it (`rate_sat_vb`, `rescue_fee`).
- `withdraw`: a withdrawal for each deposit the program lists whose coin the
  wallet no longer holds: spent in the ark, or its own exit claimed. A coin
  whose exit the wallet has started keeps its deposits until then, so a
  wallet closed mid-exit leaves the rest of the exit to its watchtowers.
- `covered`: the coins a watchtower has accepted and can pay for, and by which
  watchtowers. A watchtower whose `info` says it is short of BTC for the
  deposits it holds covers nothing. `uncovered` lists every other coin worth
  rescuing, each with why (no watchtower watches its ark, none can pay for it,
  its deposits are not accepted yet, its refresh is scheduled with the ark);
  `not_worth` the coins too small at every watchtower's rate, with that rate.
- `refresh_due`: the coins within 288 blocks (two days) of expiry, which the
  program refreshes while the wallet is open, so a holder who opened it
  recently is never rescued; `rescuing`: the covered coins a watchtower may
  already be bringing on chain (past `expiry − margin`), which the program
  leaves to it.
- `no_refresh`: the coins covered or just planned for a deposit. The program
  passes them to `schedule_refreshes` as `except`.

A coin gets a watchtower or a delegated refresh, never both. A watchtower
cannot tell a refreshed coin from an abandoned one, so it would bring the old
coin on chain, at the holder's cost, while the refreshed one waits in the ark;
and the server cannot cancel a scheduled refresh. So a coin that already has a
refresh scheduled is left to it (no deposit, and its deposits withdrawn), and a
covered coin gets none.

The program posts each `body` to `<tower>/v1/deposit` or `<tower>/v1/withdraw`
and keeps the `tower`, `vtxo` and `claim_txid` of each deposit a tower took, to
pass back as `deposited`. Default mode shows none of this; developer mode shows
`covered`, `uncovered` and `not_worth`, with the rate.

What a watchtower does not do is written in
[the CLI's README](../bark-cli/README.md#what-a-bitcoin-ark-watchtower-does-not-do).

## Commands

`BtcArk.open(network, mnemonic, server, esplora)`, then `run(command, json)`.
Amounts are whole sats (strings or numbers), hashes and preimages hex.

| Command | Takes | Answers |
| --- | --- | --- |
| `info` | | network, server key, least board, largest coin, board confirmations, coin lifetime, exit delta, `max_route_delay` (the longest lock a Lightning payment out may take) |
| `balance` | | `spendable`, `pending_lightning_send`, `claimable_lightning_receive`, `pending_in_round`, `pending_board`, `pending_exit`, `total` |
| `address` | | a new Ark address |
| `board_address` | `sats`? | `address`, `key_index`, `expiry_height`, `min_sat`, `max_sat`, `fee` |
| `board_psbt` | `psbt` (hex), `key_index`, `expiry_height` | `funding_txid`, `amount`, `vtxos` |
| `send`, `send_fee` | `address` (Ark), `sats` | `sent`, `fee` |
| `pay` | `invoice`, `max_fee_sats`?, `max_delay`?, `wait`? | `state` (`complete` with `preimage`, `pending`, `failed` with `reason`) |
| `pay_status` | `hash`, `drive`? | `state` (`complete`, `pending`, `none`) |
| `pay_fee` | `sats` | `fee`, `gross`, `max_route_delay` |
| `invoice` | `sats`, `description`? | `invoice`, `payment_hash`, `expires_at` |
| `receive_status` | `hash`, `claim`?, `wait`? | `state` (`paid` with `preimage`, `waiting`, `unknown`) |
| `receive_fee` | `sats` | `fee`, `net` |
| `offboard`, `offboard_fee` | `address` (Bitcoin), `sats` or `all` | `txid` / `fee` |
| `refresh` | | `refreshed` (coins whose refresh is scheduled are left to the server) |
| `schedule_refreshes` | `except`? (coin ids: `tower_plan`'s `no_refresh`) | `scheduled`: each refresh scheduled now, its `height`, `vtxos` (ids) and `amount` |
| `sync` | | |
| `catch_up` | | `recovered` (ids), `recovered_sat`, `spent_elsewhere` (ids), `failed` (ids), `complete` |
| `history` | | the wallet's movements |
| `coins` | | `tip`, each coin's `id`, `amount`, `expiry_height`, `refresh_height` (its scheduled refresh, or null), `state` |
| `exit_estimate` | `vtxos`? (ids) | `tip`, `address` (where a claim goes), `fee_rate` (sat/vB), `funding_confirmed`, each coin's `id`, `amount`, `expiry_height`, `blocks_left`, `cost`, `worth`, `why_not`; `worth`: the worthwhile coins together, their `fees`, `claim_fee`, `cost`, `transactions`, `fundable` |
| `exit_start` | `vtxos`? (ids; every worthwhile coin when absent) | `started` (ids), `amount`, `fees`, `claim_fee`, `cost`, `transactions`, `exits` |
| `exit_progress` | `address`? | `exits` (each `id`, `state`, `claimable_height`, `error`), `claimed` (`txid`, `address`, `amount`, `coins`, or null), `pending`, `claimable_at` |
| `exit_claim` | `address`? | `txid`, `address`, `amount`, `coins` |
| `exit_status` | | `exits`: every exit, live or finished, with its `state` |
| `tower_plan` | `towers` (each `url`, `info`), `deposited`? (each `tower`, `vtxo`, `claim_txid`), `fast_rate`? (sat/vB) | `deposit` (each `tower`, `vtxo`, `claim_txid`, `rate_sat_vb`, `rescue_fee`, `body`) and `withdraw` (each `tower`, `vtxo`, `claim_txid`, `body`), `covered` (each `vtxo`, `amount`, `expiry_height`, `rescued_from`, `towers`, `exiting`), `uncovered` (each `vtxo`, `amount`, `reason`), `not_worth` (each `vtxo`, `amount`, `rate_sat_vb`, `rescue_cost`), `refresh_due`, `rescuing`, `no_refresh` (coin ids), `skipped` (with `reason`), `holder_address`, `fast_rate`, `tip` |
| `exit_auto` | `address`?, `ark_refused`?, `margin`? | `action` (`none`, `started`, `cannot_start` with `reason`, the coins' `amount` and, when the address holds too little for the fees, `needed` and `available`), `ark` (`answering`, `refused`, `unreachable`), `not_worth` (coins due but not worth their exit), `started`, `progress` |

An exit's states are `starting`, `on_its_way`, `waiting_out_its_delay`,
`claimable`, `claiming`, `claimed`, `spent_elsewhere` and `canceled`.

`pay` refuses before anything moves when the fee would pass `max_fee_sats` or
the server's longest lock would pass `max_delay`.

A program that links the wallet natively runs the same commands: build with
the `native` feature, open the wallet with `arca_bark_wasm::open` and call
`arca_bark_wasm::run`. A program that opens `bark::Wallet` itself calls
`arca_bark_wasm::exit::attach_funding` on its `OpenWalletArgs` first, so its
exits can pay their fees. `examples/regtest_drive.rs` does so against the regtest
ark of `contrib/bitcoin-ark-regtest`, one command a run, the wallet closed
between runs (`funding_address` answers the phrase's first BIP84 address, to
fund an exit's fees from, and `board_funding` `{"sats"}` boards from those
coins). With `NETWORK` and `ESPLORA` in place of `BITCOIND` and `COOKIE` it
drives a wallet on any Bitcoin ark, the chain read from Esplora:

    ARK=… BITCOIND=… COOKIE=… MNEMONIC="…" [FEERATE=5] \
    cargo run --features native --example regtest_drive -- DATADIR COMMAND [JSON]

## Build

    cargo build --release --target wasm32-unknown-unknown
    wasm-pack build --target web --release --out-name bark_wasm

A workspace of its own, outside the root one: it is built for `wasm32` with
the wallet's browser features, which the root workspace's native build does
not take. Its tests: `cargo test --features native --lib`.
