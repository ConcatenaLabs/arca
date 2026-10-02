# Arca

Arca is an Ark protocol for [Sequentia](https://github.com/ConcatenaLabs/Sequentia),
the Bitcoin sidechain for asset tokenization and disintermediated exchanges. An
operator commits many users' balances to one on-chain output, a batch, whose
covenant tree of introspection scripts pins every child output. Each user holds a
leaf of that tree (a VTXO while off-chain), pays and receives off-chain with the
operator's co-signature, and can always leave unilaterally by publishing the path
from the batch to their leaf and claiming it after the exit delay. A batch carries
one asset, and every asset issued on Sequentia can have batches of its own.

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
| `bark/` | `arca-wallet` | `bark` | The client wallet library: rounds, arkoor, board and offboard, exits, Lightning, persistence |
| `bark-cli/` | `arca-cli` | `bark_cli` | The `bark` command-line wallet and the `barkd` daemon |
| `bark-json/`, `bark-rest/`, `bark-rest-client/` | `arca-json`, `arca-rest`, `arca-rest-client` | `bark_json`, `bark_rest`, `bark_rest_client` | JSON types, the daemon's REST server and its generated client |
| `bark-common/`, `bark-runtime/` | `arca-common`, `arca-runtime` | `bark_common`, `bark_runtime` | Helpers shared by the wallet and the server; the async runtime abstraction |
| `server/` | `arca-server` | `server` | The operator's server (`captaind`) and the watcher (`watchmand`) |
| `server-rpc/`, `server-log/`, `cln-rpc/` | `arca-server-rpc`, `arca-server-log`, `arca-cln-rpc` | `server_rpc`, `server_log`, `cln_rpc` | The gRPC protocol, structured log messages, the Core Lightning client |
| `testing/` | `arca-testing` | `ark_testing` | The integration harness and its test suites |
| `bip321/` | `bip321` | `bip321` | Payment URI parser |
| `fuzz/` | `arca-fuzz` | | Fuzz targets for the decoders (a separate workspace) |

## Building and testing

You need a stable Rust toolchain. The library's unit tests check every transaction
they build for consensus validity through `bitcoinkernel`, which compiles Bitcoin
Core's kernel with CMake and needs the Boost headers (Debian and Ubuntu:
`apt install cmake libboost-dev`).

    cargo build -p arca-lib
    cargo test -p arca-lib --lib

The [justfile](justfile) holds the remaining recipes (`just check`, `just unit`,
`just int`). The integration tests drive real daemons and expect the environment
that the Nix flake (`nix develop`) provides.

Continuous integration on GitHub Actions builds `arca-lib` and runs its unit tests
on every pull request and on every push to `master`
([.github/workflows/lib.yml](.github/workflows/lib.yml)).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

MIT, see [LICENSE](LICENSE).
