# Regtest suite and golden vectors

Arca's scripts are proven here on a real Sequentia node. Each test builds a
construction with plain Python, spends it on a fresh `elementsregtest` chain, and
records every size, script and error string the node reports. The suite is the
independent reference the Rust implementation is checked against: it shares no
code with it, and the golden vectors it exports are what the Rust builders must
reproduce byte for byte.

## Running it

You need a `sequentiad` binary and a Sequentia source tree (for the node's
functional test framework in `test/functional`; the tree need not be built):

    SEQUENTIAD_EXEC=/path/to/sequentiad SEQUENTIA_DIR=/path/to/Sequentia regtest/run

`run` starts one node per test, four tests at a time (`-j N` to change that),
and prints a line per test. Name tests to run only those (`regtest/run t18 t21`).
Logs, result files and the data of failed tests go under `regtest/out/`
(`--out DIR` to put them elsewhere, `--keep` to keep the data of passing tests
too). The exit status is non-zero if any test fails.

A test passes when every spend it expects to confirm is accepted by
`testmempoolaccept`, broadcast and mined, and every negative case is refused by
`sendrawtransaction` and again when forced into a block with `generateblock`,
and the block is refused for the mempool's reason. Relay policy can hide a
consensus flaw, so no negative case rests on the mempool alone, and a negative
case refused for an unrelated reason would be a test that cannot fail. The node
runs with `-par=1`, checking scripts inline, so a block refused for a script
names the failure, as the mempool does; a lock not yet reached reads
`bad-txns-nonfinal` in a block. A few spends that relay policy refuses but consensus accepts are mined on
purpose with `generateblock`, to show what a block producer could do.

Each test writes `regtest/out/results/<test>.json`: for every transaction its
virtual size, weight and witness size; for every script its opcodes, hex and
length; for every negative case the mempool's error and the block error.

## The tests

The library `arklib.py` holds the chain bootstrap, the transaction helpers and
the constructions T0 to T15 measure; `arklib3.py` holds the frozen constructions.

| Test | What it establishes |
|---|---|
| T0 | The node facts the constructions rely on: the witness stack item limit, zero-value and one-atom outputs, the dust floor of an issued asset, what the introspection opcodes push, the 520-byte `OP_CAT` limit |
| T1 | The tree node's UNROLL pins asset, value and script of each child, in the plain and compact forms at radix 2 and 4 and the streaming form at radix 8; the time-locked sweep |
| T1c | A record that appends the witness version raw is not injective (a forged unroll is mined against it); the injective record with `version + 2` refuses it |
| T2 | A leaf with collaborative, exit and sweep paths, each spent |
| T3 | A full unroll of a 16-leaf tree with exits, fees from the in-tree reserve, and fees from an outside coin once the batch asset is delisted |
| T3b | How many chained node transactions enter the mempool from one root |
| T4 | A membership gate on the unroll: a signature from any key under the node, proven by a Merkle path |
| T5 | The hash-locked entry and the forfeit: the operator takes the old leaf only by publishing the preimage that releases the new one; the abort path. T5 runs the forfeit's claim without the leaf id and the connector asset; the claim as built is in the vectors and `covenant/tests/offchain.rs` |
| T6 | A rebindable signature through `OP_CHECKSIGFROMSTACK`: one signature spends the leaf at any outpoint |
| T7 | The burn-only sweep: the value can only be destroyed, at the input's own index |
| T8 | A supervised asset in a tree under pause and targeted freeze; the forced single-owner landing |
| T9 | The tree survives `invalidateblock` and a replaced round transaction |
| T10 | The rebindable two-party path over the committed outputs, for one to four outputs |
| T11 | A swap of two leaves in two assets in one transaction |
| T12 | The checkpoint and reassignment chain, signed before the tree exists, with reserve and outside fees |
| T13 | The gate with an authorisation signed in advance and usable by anyone who holds it |
| T14 | A node with a pinned fee output, which cannot relay once its asset is delisted |
| T15 | The `htlc-1` leaf's four paths |
| T16 | The rebindable message bound to the spent coin's asset and amount and to the chain's genesis hash, with the folded 32-byte constant |
| T17 | A gate that takes an unchecked key from the witness is spendable with a one-byte signature (mined); the hardened gate and the timed authorisation |
| T18 | The token-gated sweep and its clock; the attacks consensus accepts and the client checks that catch them |
| T19 | The reclaim of a lowest node by all its owners and the operator |
| T20 | The notice on the sweep token: no node of any age is swept earlier than the notice after the release |
| T21 | Every frozen construction together in a 16-leaf tree in an asset that is not the policy asset |

The node runs on a custom chain with the arguments in `ArkBase.ark_params`
(`arklib.py`): transparent addresses, fees in any accepted asset, and an issued
asset that is not the policy asset as the batch asset. Every lock is time based:
expiries and authorisation times are median-time values for
`OP_CHECKLOCKTIMEVERIFY`, and delays are `OP_CHECKSEQUENCEVERIFY` operands in
512-second units. Median time is moved with `setmocktime`.

## Golden vectors

`vectors/arca.json` holds every frozen Arca script with what determines it, and a
sample spend of every path:

- for each taproot output (the leaf, `R`, the clock steps, the hash-locked entry,
  the lowest, inner and batch nodes with the operator's sweep and with the
  burn-only sweep, the forfeit output (bound to the leaf it gives up and to its
  round's connector output), the round's connector output (spent only by the
  operator's issuance of that asset), the board output (`board-1`: the leaf's
  collaborative path and the owner's conversion), the checkpoint output and
  `htlc-1` in both
  directions): its inputs (keys, hashes, salts, the genesis hash, `T`, `R`, `W`,
  times, children), each script leaf with its opcodes, depth, leaf hash and
  control block, the merkle root, the output key and the scriptPubKey;
- for each spend: a transaction, the outputs it spends, the signature hash or the
  signed message and its digest, the test keys' signatures and the witness;
- the injective record of several kinds of output.

`vectors/records.json` holds the leaf record's vectors, written by
`records.py`: the reference for the tree rules, the record's binary and JSON
forms and the leaf id, which its docstring states in full. For each of seven
batches (one leaf; five; sixteen; seventeen with burn-only sweeps; ten at radix
3; seven at radix 6 with no reserves; sixty-four) it holds the inputs, the
shape of the tree (the child count of every node), the batch output, a round
transaction that issues the batch's token and funds it, and each exported
leaf's salt, position, leaf id and record in both forms. It also holds
encodings a reader must refuse, each with the kind of reason.

`vectors/transactions.json` holds the off-chain transactions' vectors, written
by `offchain.py`, the reference for their shapes, which its docstring states in
full: the board, its record in both forms with refusal vectors, the owner's
conversion, the exit of the converted leaf, and one pair spending the board
output and the converted leaf alike; the forfeit, the round's connector output and the operator's issuance
of its connector asset, the claim and the refund; the offboard output, its unlock and its reclaim; and a transfer
chain three hops deep from two batches (one hop a swap of two owners' coins in
two assets) and a coin paid out of round from the board: the rounds and the
board, every checkpoint and reassignment, and every receiver's coin record with
its id and the creator nonce its sender drew for its leaf. It also holds a coin
record a receiver must refuse, resting on one leaf that two reassignments
promised (the second sender repeating the first's creator nonce), and the same
coin with the second sender's own creator nonce, which it accepts. Each
transaction is given whole, witnesses included, with the outputs it spends and,
for a signature, the signature hash and the test key's signature, once with the
spent output's margin as the fee and once with a fee coin attached.

`vectors.py` writes every file from the suite's builders and the node framework's
taproot code; no node runs. Every input comes from a fixed label and every
signature uses zero auxiliary randomness, so the output is the same on every run:

    SEQUENTIA_DIR=/path/to/Sequentia regtest/vectors.py           # rewrite the files in vectors/
    SEQUENTIA_DIR=/path/to/Sequentia regtest/vectors.py --check   # fail if any would change

The keys are test keys, `SHA256("Arca test vector key/" + label)` reduced modulo
the group order; they hold nothing. `consensus/tests/vectors.rs` verifies every
sample spend, every input, with the node's own interpreter, and
`covenant/tests/vectors.rs` rebuilds every output and every witness with the Rust
builders and compares them byte for byte; `covenant/tests/record.rs` decodes,
re-encodes and validates every record; `covenant/tests/transactions.rs` rebuilds
every off-chain transaction byte for byte and verifies it.

## In CI

The `regtest-suite` job of [node.yml](../.github/workflows/node.yml) runs
`vectors.py --check`, which regenerates both vector files, and the whole suite against the newest node build, with the
functional test framework from the same node commit. The logs and result files
are kept as the job's artifact.
