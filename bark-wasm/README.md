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
blocks past its height. A page calls it when it opens and after each sync.

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
| `schedule_refreshes` | | `scheduled`: each refresh scheduled now, its `height`, `vtxos` (ids) and `amount` |
| `sync` | | |
| `catch_up` | | `recovered` (ids), `recovered_sat`, `spent_elsewhere` (ids), `failed` (ids), `complete` |
| `history` | | the wallet's movements |
| `coins` | | `tip`, each coin's `id`, `amount`, `expiry_height`, `refresh_height` (its scheduled refresh, or null), `state` |

`pay` refuses before anything moves when the fee would pass `max_fee_sats` or
the server's longest lock would pass `max_delay`.

A program that links the wallet natively runs the same commands: build with
the `native` feature, open the wallet with `arca_bark_wasm::open` and call
`arca_bark_wasm::run`. `examples/regtest_drive.rs` does so against the regtest
ark of `contrib/bitcoin-ark-regtest`, one command a run, the wallet closed
between runs:

    ARK=… BITCOIND=… COOKIE=… MNEMONIC="…" \
    cargo run --features native --example regtest_drive -- DATADIR COMMAND [JSON]

## Build

    cargo build --release --target wasm32-unknown-unknown
    wasm-pack build --target web --release --out-name bark_wasm

A workspace of its own, outside the root one: it is built for `wasm32` with
the wallet's browser features, which the root workspace's native build does
not take. Its tests: `cargo test --features native --lib`.
