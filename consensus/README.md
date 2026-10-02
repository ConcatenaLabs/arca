# arca-consensus

Script verification under Sequentia's consensus rules, for tests. A test that
builds a transaction asks this crate whether the node would accept the spend of
one of its inputs:

```rust
use arca_consensus::Verifier;

let verifier = Verifier::consensus(genesis_hash);
verifier.verify_input(&spent_outputs, input_index, &tx)?;
```

The verdict comes from the node's own script interpreter. The crate compiles a
small C shim (`src/shim.cpp`) against a Sequentia node source tree and links the
node's consensus library, so it covers everything the interpreter does:
tapscript at leaf version `0xc4` with the Elements introspection opcodes,
`OP_CHECKSIGFROMSTACK`, `OP_CAT` and the streaming SHA256 opcodes, the time locks,
and Simplicity at leaf version `0xbe`. Signature hashes commit to the chain's
genesis block hash, which is why a `Verifier` is made for one chain.

- `Verifier::consensus` applies the rules a block enforces.
- `Verifier::standard` applies the node's mempool script checks: its standard
  flags, then the block rules.
- `Verifier::with_flags` applies exactly the flags given.

It checks the script of an input and nothing else. Whether the inputs exist and
are unspent, the value balance, fees, the transaction's own lock time and the
relative locks of BIP68 are checked by the node, not here; a test that depends on
them runs its transaction against a node.

## Building

The build needs a Sequentia node checkout with its consensus library built.
`SEQUENTIA_DIR` names it:

    git clone https://github.com/ConcatenaLabs/Sequentia
    cd Sequentia
    ./autogen.sh
    ./configure --without-daemon --without-utils --disable-wallet --disable-tests \
      --disable-bench --disable-fuzz-binary --with-gui=no --without-miniupnpc \
      --without-natpmp --disable-zmq --with-libs
    make -j"$(nproc)" -C src libelementsconsensus.la
    export SEQUENTIA_DIR=$PWD

A full node build works as well: it contains the same library. The build stops
with an explanation when `SEQUENTIA_DIR` is unset or the library is missing.

## Testing

    cargo test -p arca-consensus

The unit tests need only the library. `tests/node_agreement.rs` also runs
`sequentiad`, named by `SEQUENTIAD_EXEC`, on a fresh anchored regtest chain
(`arca-sequentia-ext`'s regtest harness). It builds
known-good and known-bad spends from the regtest prototype's scripts (the tree
node's unroll, the rebindable two-party path through `OP_CHECKSIGFROMSTACK`, the
hash-locked forfeit claim, the CLTV sweep, the CSV exit, and a Simplicity
relative lock) and asserts for each that the verifier, the node's
`testmempoolaccept` and the node's block validation (`generateblock`) reach the
same verdict, and that the verifier names the same script error as the node.
`-- --nocapture` prints the table.

The `node` workflow (`.github/workflows/node.yml`) runs both against the newest
node `master` commit whose build passed: it downloads that build's `sequentiad` and
builds the consensus library from the same commit.
