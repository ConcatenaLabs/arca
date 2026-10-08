# Arca

Arca is an Ark protocol for [Sequentia](https://github.com/ConcatenaLabs/Sequentia),
a Bitcoin sidechain for asset tokenization and disintermediated exchanges. An
operator commits many users' balances to one on-chain output, a batch, whose
covenant tree of introspection scripts pins every child output. Each user holds a
leaf of that tree (a VTXO while off-chain), pays and receives off-chain with the
operator's co-signature, and can always leave unilaterally by publishing the path
from the batch to their leaf and claiming it after the exit delay. A batch carries
one asset, and every asset issued on Sequentia can have batches of its own.

A batch expires 28 days after its round, and after a public notice the operator
may then sweep what is left in it, so a holder moves each leaf into a new batch
before then: a refresh. The holder submits a participation once, naming the leaves
it gives up and the leaves it wants, and the operator runs it in the next round
without the holder online. The operator takes a leaf in a participation only up to
its exit deadline, three days before its batch's expiry, and a refresh is free in
the two days before that deadline. Once the round is final the holder hands over a
forfeit of each old leaf, bound to that round, and receives the preimage that
completes its new leaves; it has a day to do so, after which the participation
expires and the old leaves are the holder's again. Finally the holder signs a
release of the lowest node above each old leaf, naming the new round's connector
asset, so that the operator can reclaim the node before the batch expires. Forfeit
and release alike are void if the new round leaves the chain: neither can be used
without an asset that only that round can issue. A coin resting on a round, a
leaf of it or a coin paid out of one, is as final as that round: while the round
is out of the chain the coin is worth nothing, and it is good again if the round
returns.

The operator's server watches the chain for what follows. A holder who brings a
leaf it gave up back on-chain is answered, before the leaf's exit delay runs out,
by that leaf's forfeit or by the checkpoint and reassignment it signed. A board
given up in a round comes back to the operator by its forfeit; an expired batch
is released and, after the notice, swept; a node every owner has released is
reclaimed before the batch expires. An offboard is paid to its destination once
its owner hands over its forfeit, and reclaimed by the operator after a delay if
the owner never does. Everything it publishes is broadcast again unchanged after
any rollback, an anchor-driven one included.

This repository is a fork of [Bark](https://gitlab.com/ark-bitcoin/bark), the Ark
implementation by Second, taken at its `0.7.1` release with the full upstream
history. Bark's tags (`bark-0.7.1`, `lib-0.7.1`, `server-0.7.1`) mark the fork
point. Bark's MIT licence and its copyright notice are kept in [LICENSE](LICENSE).

## Crates

The crates keep the directory and library names they have upstream, so code taken
from Bark applies with few edits; only the package names carry the `arca-` prefix.

| Directory | Package | Library | What it holds |
|---|---|---|---|
| `lib/` | `arca-lib` | `ark` | Protocol primitives: the VTXO type and its encoding, policies and clauses, the transaction tree, arkoor, board, offboard, forfeits, attestations, fees |
| `bitcoin-ext/` | `arca-bitcoin-ext` | `bitcoin_ext` | Height and delta types, fee and dust helpers, node RPC extension traits |
| `bark/` | `arca-wallet` | `bark` | The client wallet library: Bark's wallet for Bitcoin arks (rounds, arkoor, board and offboard, exits, Lightning, persistence), and the Arca wallet on Sequentia (`bark::arca`, the `arca` feature): its chain source, its SQLite store, its keys, its client of the Arca server, and every operation of the `arca` command line |
| `bark-cli/` | `arca-cli` | `bark_cli` | The `arca` command-line wallet, dual-chain: Arca coins on Sequentia, and Bitcoin arks through Bark's `bark` wallet and `barkd` daemon ([bark-cli/README.md](bark-cli/README.md)) |
| `bark-json/`, `bark-rest/`, `bark-rest-client/` | `arca-json`, `arca-rest`, `arca-rest-client` | `bark_json`, `bark_rest`, `bark_rest_client` | JSON types, the daemon's REST server and its generated client |
| `bark-common/`, `bark-runtime/` | `arca-common`, `arca-runtime` | `bark_common`, `bark_runtime` | Helpers shared by the wallet and the server; the async runtime abstraction |
| `server/` | `arca-server` | `server` | The operator's server on Sequentia: its state in PostgreSQL, the finality service, the on-chain wallet on the Sequentia Wallet Kit, the nursery, boards, transfer co-signing, rounds with their participations, published trees, forfeits and releases, the watcher that acts on the chain for the operator (answers to stale exits, claims, the release and sweep of expired batches, reclaims, offboards), the Lightning gateway's nodes (one SeqLN node per asset served over Lightning, one Lightning node on Bitcoin), and the JSON interface (`arcad`), the signer holding the operator key (`arca-signer`), and the keeper that holds the signer's record's heads on another machine (`arca-keeper`) ([server/README.md](server/README.md)) |
| `server-rpc/` | `arca-server-rpc` | `server_rpc` | The gRPC protocol of Bark's server, which the Bark wallet speaks |
| `sequentia-ext/` | `arca-sequentia-ext` | `sequentia_ext` | Sequentia chain types (anchored block headers, issuances with a denomination, asset-tagged amounts), a JSON-RPC client for `sequentiad`, and a regtest harness ([sequentia-ext/README.md](sequentia-ext/README.md)) |
| `covenant/` | `arca-covenant` | `arca_covenant` | Arca's covenant scripts on Sequentia: the tree node, the sweep behind the token, the clock, the leaf (`vtxo-1`, and `htlc-1`, whose exit is a hash-locked pair), the entry, the forfeit, the checkpoint, with their messages, witnesses, encodings and the client's checks on a round; the leaf record, its id and its validation; the tree builder and the unroll; the board, the forfeit and its connector asset, the release and the reclaim, the offboard, and the transactions that spend a leaf off the tree ([covenant/README.md](covenant/README.md)) |
| `consensus/` | `arca-consensus` | `arca_consensus` | Script verification under Sequentia's consensus rules for tests, through the node's own interpreter ([consensus/README.md](consensus/README.md)) |
| `wallet-wasm/` | `arca-wallet-wasm` | `arca_wallet_wasm` | The Arca wallet built for a browser's dedicated worker: the same library, with the worker's HTTP, its pause, and SQLite on the browser's private file system (a separate workspace) ([wallet-wasm/README.md](wallet-wasm/README.md)) |
| `bip321/` | `bip321` | `bip321` | Payment URI parser |
| `fuzz/` | `arca-fuzz` | | Fuzz targets for the decoders (a separate workspace) |

[doc/operator-procedure.md](doc/operator-procedure.md) is the procedure an operator that holds other people's
coins follows: how it is made, what is never done, how its storage is kept and restored, and what its holders
are told.

## Building and testing

You need a stable Rust toolchain. The library's unit tests check every transaction
they build for consensus validity through `bitcoinkernel`, which compiles Bitcoin
Core's kernel with CMake and needs the Boost headers (Debian and Ubuntu:
`apt install cmake libboost-dev`).

    cargo build -p arca-lib
    cargo test -p arca-lib --lib

The wallet crates (`arca-wallet`, `arca-cli`) compile Bark's gRPC protocol and
also need `protoc` (`apt install protobuf-compiler`).

The [justfile](justfile) holds the remaining recipes (`just check`, `just unit`).

`arca-consensus` links the Sequentia node's consensus library, which the tests of
`arca-covenant` verify through as well, and the tests of all three crates run
`sequentiad` on a regtest chain: set
`SEQUENTIA_DIR` to a node checkout with that library built and `SEQUENTIAD_EXEC`
to a node binary, as [consensus/README.md](consensus/README.md) describes.

    cargo test -p arca-consensus -p arca-sequentia-ext -p arca-covenant

The server's tests also need a PostgreSQL server, named by `ARCA_TEST_POSTGRES`
([server/README.md](server/README.md)).

[regtest/](regtest/README.md) is the regtest suite: Python tests that build every
Arca script independently of the Rust code and spend it on a Sequentia regtest
chain, with each negative case forced into a block. It exports the golden
vectors (`regtest/vectors/arca.json`) that the Rust builders must reproduce byte
for byte. It needs a node binary and a node source tree:

    SEQUENTIAD_EXEC=/path/to/sequentiad SEQUENTIA_DIR=/path/to/Sequentia regtest/run

Continuous integration on GitHub Actions runs on every pull request and on every
push to `master`: [lib.yml](.github/workflows/lib.yml) builds `arca-lib` and runs
its unit tests, and [node.yml](.github/workflows/node.yml) runs `arca-consensus`,
`arca-sequentia-ext` and `arca-covenant`, checks that the golden vectors
regenerate, and runs the regtest suite, all against the newest node build.
[server.yml](.github/workflows/server.yml) runs the server's tests, the
end-to-end ones with the signer process and the minimal client included,
against a PostgreSQL service and the newest node build.
[client.yml](.github/workflows/client.yml) runs the `arca` wallet's
scenarios against a whole server, the same PostgreSQL service and the newest
node build.
[covenant.yml](.github/workflows/covenant.yml) checks that `arca-covenant`
builds with the Rust version the Sequentia Wallet Kit pins, which is the
`rust-version` in `covenant/Cargo.toml`.
[wallet-wasm.yml](.github/workflows/wallet-wasm.yml) builds the wallet for a
browser (`wallet-wasm/`, its own workspace and lockfile) for
`wasm32-unknown-unknown`.
[lightning.yml](.github/workflows/lightning.yml) builds SeqLN at the commit it
pins and runs the server's Lightning tests against SeqLN nodes on the chain
SeqLN's `sequentia-regtest` network assumes, with Bitcoin Core for the
operator's Lightning node on Bitcoin.

## Security

See [SECURITY.md](SECURITY.md).

## Licence

MIT, see [LICENSE](LICENSE).
