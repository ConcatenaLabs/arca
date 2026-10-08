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
const { result, start } = JSON.parse(w.run('board', JSON.stringify({ asset, amount: '2000000' })))
```

`run(command, args)` takes the command line's commands: `info`, `address`,
`balance`, `coins`, `record {leaf_id}`, `board {asset, amount, fee_asset?}`,
`boards`, `receive {asset?, amount?}`, `forget_request {owner}`, `send
{request, amount?, asset?}`, `mailbox`, `restore`, `quote {leaves?, max_fee_ppm?}`,
`participate {leaves?, not_before?, max_fee_ppm?, shown}`, `participations`,
`sync`, `schedule`, `recheck`, `exit {leaf_id, fee_asset?}` and `refusals`. Its answer is `{"result", "start"}`: the
command's JSON, and what the start of the command found, the witness of the
operator's signer's record (unless the command stays on the machine and the
node) and the re-check of every coin against the chain (unless the command is
`recheck`, `sync` or `schedule`), as `arca` runs them on every start.

`quote` is the refresh fee, coin by coin, that `participate` would pay; the page
shows it, and `participate` goes ahead only when `shown` equals the fees it
quotes again, so nothing is signed on a fee the user did not see. `schedule` is
`Wallet::sync_schedule`: when `sync` must run next and why. A page runs `sync`
when it is due.

A refusal is thrown as the JSON `arca` prints, `{"error": {"kind",
"message"}}`, with the server's `code` and `status` when the server refused.

The page shows what the library says as it says it. With no command line,
the library names the act rather than a command ("run sync", "an exit takes
it now", "send one to the wallet's address"), and prefixes the texts it hands
out `request:`, `swap-offer:` and `swap-accept:`. It reads a text whatever its
prefix, the command line's `arca:…` included.

## Building

Needs the `wasm32-unknown-unknown` target, `wasm-pack`, and `protoc` (the
wallet crate compiles Bark's gRPC protocol).

    rustup target add wasm32-unknown-unknown
    cd wallet-wasm
    wasm-pack build --target web --release --out-name leaf_wallet

The package is `pkg/leaf_wallet.js` with `pkg/leaf_wallet_bg.wasm`. The web
wallet carries a copy in its `leaves/pkg/`.

## Testing against an operator

`bark-cli/tests/arca_operator_for_browsers.rs` keeps a whole Arca server running
on an anchored regtest chain for a wallet outside the test, with a control
address to fund scripts, produce and bury blocks, build rounds and move the
chain's median time. The web wallet's `tooling/leaves-drive.mjs` drives this
package in a headless browser against it, with the `arca` binary as the
counterparty.
