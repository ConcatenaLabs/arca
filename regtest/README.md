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
names the failure, as the mempool does; the harness compares the failure and
not the label before it, which a node prints as
`mandatory-script-verify-flag-failed` or, where its block flags include one
that relay policy also sets, `mempool-script-verify-flag-failed`, as the
mempool's reads. A lock not yet reached reads
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
| T15 | The `htlc-1` leaf: the operator's claim with the preimage and the owner's refund after the timeout out of the tree, the owner's claim and the operator's refund into it, each refused before its relative delay, and past the timeout in the block that creates the output; the collaborative path at once |
| T16 | The rebindable message bound to the spent coin's asset and amount and to the chain's genesis hash, with the folded 32-byte constant |
| T17 | A gate that takes an unchecked key from the witness is spendable with a one-byte signature (mined); the hardened gate and the timed authorisation |
| T18 | The token-gated sweep and its clock; the attacks consensus accepts and the client checks that catch them |
| T19 | The reclaim of a lowest node by all its owners and the operator, each owner's release naming the connector asset `M` of the round of its new leaf, issued for real from a connector output: confirmed with an atom of `M` (and with an atom of each of two rounds), refused without it, with another round's `M`, with another asset, with three releases of four and with releases over the message that named no round |
| T20 | The notice on the sweep token: no node of any age is swept earlier than the notice after the release |
| T21 | Every frozen construction together in a 16-leaf tree in an asset that is not the policy asset |
| T22 | The operator's equivocation bond (`bond.py`): a payment and a second spend of one leaf, both co-signed by the operator, burn the bond whole; refused beside it one signature twice, two signatures over one digest, two salts, another key and a burn short; a fill beside a payment under one salt burns another; the notice keeps the bond whole and is W's alone; the withdrawal waits the notice's delay |
| T23 | `landing-1`, the leaf of a supervised asset: the collaborative path over its prefix `K ‖ P`, which binds the landing program, refused over the plain constant and over another landing's prefix; the landing refused before its delay, to another key's P2WPKH, to a taproot output, in another asset and one atom below the value less the allowance; under a pause, with the leaf's own script named in a freeze, the landing confirms, the landed coin is refused by the pause and by a freeze of its address, and spent once the freeze is lifted |
| T24 | `channel-1`, a leaf with a balance for each of owner and operator (`channel.py`): an update moves the coin to a newer state at once, both signing the state's number and program; refused to an equal or older state, over another state's program, keeping one atom less, into another asset, with either signature from another key, with 33-byte and 9-byte witness items; an older state's settle on a newer output, the newer settle paying the older balances, short by one atom, swapped, to another channel's credit output, and before its delay; the collaborative path spends a state output. The credit output's claim pays the owner what the operator's cumulative note credits less what was paid, capped at the state's `s + F`; refused above the signed amount, one atom over, with a note already paid, with another channel's note, with a 33-byte amount or signature, with the rest short or elsewhere; a stale state's claim takes the operator's whole balance; the provider path after the window, refused before it; the unroll gate above a channel leaf refuses a 33-byte member key |
| T25 | RECLAIM-D, the reclaim of a lowest node whose coins moved out of round: for each owner a tree whose inner nodes are delegations (a coin's key signs `SHA256("Arca/delegate" ‖ genesis_hash ‖ K_1 ‖ … ‖ K_m)`, the owner keys of every output of the reassignment it moved into) and whose leaves are releases naming the round of each holder's new coin, checked in at most 32 steps; confirmed for a coin paid twice, a swap and a direct release together, for every owner releasing directly, and for six owners using all 32 steps; refused with a delegation by another key, with a successor substituted, for another chain, with a release signature in its place, with a release naming a round not in the chain, without an atom of `M`, with `M` read from another asset, with one owner's tree twice, with three trees for four owners, with one successor's release standing for two, with a successor missing, with a successor's release of another node, with two keys split 33 and 31 bytes over the same 64 bytes (which a block takes once the 32-byte key check is removed: `OP_CHECKSIGFROMSTACK` passes any signature for a key of another length), with another node's `P` or another chain's `Q` below the steps, with an item below the operator's signature, and without the operator's signature or with another key's. A release by a key that has already delegated confirms with the operator's signature: the chain cannot tell it from its holder's, so the operator refuses it |
| T26 | A batch without a sweep (`t26_no_sweep.py`): no token, no clock, the batch output `[UNROLL]`, lowest nodes `[UNROLL, [RECLAIM, RECLAIM-D]]` (and `[UNROLL, RECLAIM]`), entries `[unlock]`, checkpoints `[collab]`. A round built for eight is built again for seven when one never signs its forfeit; every forfeit is signed against the built round's connector asset before broadcast and claimed after it, and a forfeit for the round built away can never be claimed and is refunded. Every removed sweep leaf (batch output, lowest nodes, entries, checkpoint) is refused in a block with a real token at `R` beside it, with its twin's control block and as a lone leaf (`Witness program hash mismatch`), and the same leaf sweeps each twin that has it. The operator's recovery: an unroll by its own authorisation, RECLAIM-D (refused with an absent owner's release missing or forged), RECLAIM, a forfeit claimed; a dormant owner's entry opens only into its leaf, and that owner and a dormant receiver of an out-of-round payment take their coins home with their own keys, never the operator's |
| T27 | `claim-1`, a distribution's claim leaf (`t27_claim_lapse.py`): `[collab, [exit, lapse]]`, the lapse paying the output at its own input's index to the return script (`SHA256(program ‖ version + 2)` pinned), in the leaf's asset, at least the value less the allowance, once the median time has passed the deadline and the leaf has waited its exit delay, with no signature. Refused: the lapse before the deadline (`bad-txns-nonfinal`), with a lock time below it and with a sequence below the exit delay (`Locktime requirement not satisfied`), to another script, in another asset, two lapses sharing one output and one paying the return script at another index (`Script failed an OP_EQUALVERIFY operation`), one atom below the value less the allowance (`false/empty top stack element`), a leaf confirmed after the deadline lapsed at once (`bad-txns-nonfinal`), the collaborative path over another salt. Confirmed: the holder's claim before the deadline, its exit started an exit delay before it, the lapse with its fee from the allowance, two lapses in one transaction (one to a P2PKH return), a lapse with a fee coin of another asset paying the whole value back, a lapse carrying an annex (mined; relay refuses it, nothing it pins changes), a leaf confirmed after the deadline answered at once by its pair; and the race, a leaf confirmed less than an exit delay before the deadline open to the exit and the lapse at the same moment |

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
  `htlc-1` in both directions, `landing-1`, `claim-1`): its inputs (keys, hashes, salts, the genesis hash, `T`, `R`, `W`,
  times, children), each script leaf with its opcodes, depth, leaf hash and
  control block, the merkle root, the output key and the scriptPubKey;
- for each spend: a transaction, the outputs it spends, the signature hash or the
  signed message and its digest, the test keys' signatures and the witness;
- the injective record of several kinds of output.

`vectors/records.json` holds the leaf record's vectors, written by
`records.py`: the reference for the tree rules, the record's binary and JSON
forms and the leaf id, which its docstring states in full. For each of seven
batches (one leaf; five; sixteen; seventeen with burn-only sweeps; ten at radix
3; seven at radix 6 with no reserves; sixty-four) and an eighth of five whose
second and fourth leaves are `htlc-1`, one whose first and fourth are
`order-2`, one whose second and fifth are `order-3`, one of a supervised asset whose five leaves are all
`landing-1`, one whose second and fifth leaves are `channel-1` (the
fifth with no opening balance for the operator), one whose second and third are `vtxo-2`, one of seventeen with
RECLAIM-D on every lowest node, and the batches without a sweep (seventeen
with RECLAIM-D; five whose second and third are `vtxo-2`; five whose second
and fourth are `claim-1`) and one with a sweep whose first and fifth are
`claim-1`, it holds the inputs, the
shape of the tree (the child count of every node), the batch output, a round
transaction that issues the batch's token and funds it, and each exported
leaf's salt, position, leaf id and record in both forms. It also holds
encodings a reader must refuse, each with the kind of reason.

`vectors/transactions.json` holds the off-chain transactions' vectors, written
by `offchain.py`, the reference for their shapes, which its docstring states in
full: the board, its record in both forms with refusal vectors, the owner's
conversion, the exit of the converted leaf, and one pair spending the board
output and the converted leaf alike; a board of a supervised asset, whose
record (format 3) carries the landing program and allowance, its conversion
into a `landing-1` leaf and that leaf's landing; the forfeit, the round's connector output and the operator's issuance
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

`vectors/order.json` holds the `order-2` leaf's vectors, and under `order_3`
the same order's as an `order-3` leaf, written by
`order.py`, which derives them on its own: the tree mixes tapscript leaves, a
Simplicity leaf and a hidden data leaf, which the node framework's taproot code
cannot express, so it builds the tagged hashes itself. It holds an order's
terms and keys, its parameters, the collaborative, landing and fill leaves with
their control blocks, the merkle root and scriptPubKey; the same for the
remainder after one fill; the credit leaf that fill pays; the SeqDEX order it
lands as; and the operator's digest over a fill's outputs with its signature.
The Simplicity commitment roots are sequentia-contracts': `arca/order-3`
and `seqdex/order` version 2 for an `order-3` leaf, `arca/order-2` and
`seqdex/order` version 1 for an `order-2` leaf.

`vectors/collab2.json` holds the `vtxo-2` leaf's vectors, written by
`collab2.py`, which derives them on its own from the tagged hashes, as
`order.py` does: a leaf and its checkpoint, each a Simplicity leaf
(`arca/collab-2`, named by sequentia-contracts' commitment root), a hidden data
leaf over the owner's key, the operator's key and the salt, and a tapscript
leaf (the exit, or the checkpoint's sweep), with their control blocks, merkle
roots and scriptPubKeys; and a spend of each, the leaf alone into its
checkpoint and the checkpoint at index 1 of a swap: the bytes both keys sign
(the coin's index, the inputs named by asset, amount and script, the
outputs), the digest, both signatures and the Simplicity witness.

`vectors/bond.json` holds the equivocation bond's vectors, written by
`bond.py`: its keys and notice delay, its three scripts, the bond's and the
notice output's scriptPubKeys, merkle roots and control blocks, and a slash's
evidence: two messages the operator signed under one leaf salt (a payment and
a second spend of the same leaf), and a fill beside the first, each with its
rest, digest and signature, and the witness items the slash takes for each
pair.

`vectors/channel.json` holds the `channel-1` leaf's vectors, written by
`channel.py`: one channel's keys, salt, value, capacity, exit delay and credit
window, its state and credit constants, its outputs at three states (each
one's collaborative, update and settle leaves, scriptPubKey, merkle root and
control blocks, and its credit output's claim and provider leaves), each
state's message with both signatures, and two credit notes with the
operator's signatures.

`vectors/accumulator.json` holds the accumulator batch's vectors, written by
`accumulator.py`, which derives them on its own from the batch's rules: six
leaves behind the entries a tree would pay them through, each slot's record,
the Merkle-sum root and the batch's weight, the state's data leaf, the batch
output's merkle root, scriptPubKey and control block, and two exits, by an
owner and then by the operator, each with its path, digest, signature, witness
value and the state it leaves; and every leaf's record and coin record in
binary form, with its leaf id, and records a reader must refuse. The
Simplicity commitment root is sequentia-contracts' (`arca/accumulator-1`).

`vectors/reclaim_d.json` holds RECLAIM-D's vectors, written by `reclaim_d.py`
from T25's constructions: a lowest node of four owners with RECLAIM and
RECLAIM-D (its scripts, scriptPubKey and control blocks), the release and
delegation prefixes and messages, and the items below RECLAIM-D for a coin
paid twice, a swap and a direct release, with every signature.

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
every off-chain transaction byte for byte and verifies it; `covenant/tests/order_vectors.rs` rebuilds every `order-2` and `order-3` vector and verifies the fill signature; `covenant/tests/accumulator_vectors.rs` rebuilds every accumulator vector, checks each exit's signature, and encodes and decodes every record and coin record.

## In CI

The `regtest-suite` job of [node.yml](../.github/workflows/node.yml) runs
`vectors.py --check`, which regenerates every vector file, and the whole suite against the newest node build, with the
functional test framework from the same node commit. The logs and result files
are kept as the job's artifact.
