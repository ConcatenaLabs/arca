# arca-covenant

Arca's covenant scripts on Sequentia, as Rust: every script the Arca
specification freezes, the taproot outputs that carry them, the messages their
signatures cover, the witnesses that spend them, and the checks a wallet runs on
a round before it accepts a leaf.

Every output is a taproot output whose internal key is the BIP341 NUMS point, so
it has no key path, with tapscript leaves at leaf version `0xc4` hashed with the
Elements tags. Amounts are explicit and always name their asset. Every lock is
time based: `MedianTime` for `OP_CHECKLOCKTIMEVERIFY`, `RelativeTime` (512-second
units) for `OP_CHECKSEQUENCEVERIFY`; a height is refused.

## What it builds

| Module | Output | Leaves |
|---|---|---|
| `node` | A tree node: the batch output, an inner node, a lowest node | UNROLL behind the membership gate with a timed authorisation; the sweep; RECLAIM on a lowest node |
| `sweep` | The sweep path of every output above a leaf | The token check (`T` at `R` in input `k`), the notice `W` on every output but the batch output, burn-only for an issuer-operated batch |
| `clock` | `R` and the clock chain from a published schedule `(T, S, W, E_0 … E_K)` | ROLL, RELEASE; `R` is `<W> CSV DROP <S> CHECKSIG` |
| `leaf` | The leaf (`vtxo-1`) | The rebindable collaborative path for 1 to 4 committed outputs, and the exit |
| `entry` | The hash-locked entry | Unlock into the owner's leaf with the preimage; the sweep with notice |
| `forfeit` | The forfeit output | The operator's claim with the preimage; the owner's refund after the delay |
| `checkpoint` | The checkpoint output | The collaborative path with the checkpoint's own salt; the sweep with notice |
| `htlc` | `htlc-1`, for a payment out of the tree or into it | Claim, claim with both signatures, refund after the timeout, refund with both signatures |

`record` holds the leaf record, `record_json` its JSON form (the `json`
feature, on by default), `tree` the builder that turns the leaves of one asset
into a batch, and `unroll` the transactions that take a leaf on-chain; all
described below.

`message` holds the three messages `OP_CHECKSIGFROMSTACK` verifies (the
rebindable message bound to the spent coin and the chain, the unroll
authorisation, the release), `sign` the Elements taproot signature hash and BIP340
signing, `checks` the five client checks (`check_round` returns the check that
failed), `encode` a canonical binary encoding of every policy and of the clock
schedule, and `witness` the reading of witnesses found on-chain (the preimage a
claim revealed, an unroll authorisation).

A typical use: build a policy, take its `script_pubkey()` for the output, sign
its message or the transaction's signature hash, and put the witness it returns
on the input.

```rust
use arca_covenant::{LeafPolicy, ExplicitOutput};
use arca_covenant::sign::sign_digest;

let msg = leaf.collab_message(asset, value, &outputs)?;   // what owner and operator sign
let w = leaf.collab_witness(&sign_digest(&operator, &msg.digest, &aux), &sign_digest(&owner, &msg.digest, &aux), outputs.len() as u8);
tx.input[i].witness.script_witness = w;
```

## The leaf record

A `LeafRecord` is what the holder of a leaf keeps: everything needed to check
the leaf against the chain and to take it on-chain alone, and nothing secret.
It names the leaf's template and version (`vtxo-1`), the owner's key, the two
nonces the salt is built from, the exit delay, the asset and value, the entry in
front of the leaf (its unlock hash and reserve), the batch's chain, token and
clock schedule
`(T, S, W, E_0 … E_K)` (`R` is rebuilt from `W` and `S`), whether its sweeps
are burn-only, and the path from the batch output down to the leaf. Each level
of the path holds the index of the child on the leaf's path, the node's reserve
and its other children; above the lowest node it holds the owner's proof in the
node's member tree, and at the lowest node the other owners, whose keys that
node's RECLAIM names.

```rust
use arca_covenant::{LeafRecord, WalletPolicy};

let record = LeafRecord::from_bytes(&bytes)?;          // or LeafRecord::from_json_str(text)?
let policy = WalletPolicy::new(chain, operator, now);  // the wallet's chain, the operator it was told, now
let valid = record.validate(&round_tx, &policy, &leaf_key, &leaf_nonce)?;
let id = valid.leaf_id;                                // what the server keys the leaf by
let round = valid.round_txid;                          // the round it was checked against
let branch = valid.branch;                             // every output from the batch output down
```

**One key, one leaf.** A leaf's owner key signs for that leaf only: every leaf
instance, every receive included, has a key of its own. Where one key held two
leaves, the operator could take one, by building a new leaf from a salt the owner
had signed under, by one release filling two slots of a RECLAIM, or by merging
two forfeits. The builder refuses a key on two leaves of a batch, and a record
whose lowest level names its own key in another slot is refused.

**A salt from both sides.** A leaf's salt is
`SHA256("Arca/salt" ‖ owner_nonce ‖ operator_nonce)`. The owner's wallet picks
`owner_nonce` at random for every leaf it asks for (or publishes it in a receive
request), never from a counter, which a restore would repeat; the operator adds
its own. The record carries both nonces and rebuilds the salt from them.
`validate` takes the key and the nonce the wallet expects for this leaf and
refuses a record not built from them, so a wallet that never repeats a nonce is
never given a leaf script it has signed for before.

**The wallet's policy.** `validate` is the check a wallet runs before it accepts
a leaf. It refuses a record outside the wallet's `WalletPolicy`: another chain,
an operator key other than the one the wallet was told, a notice `W` below the
wallet's minimum, a first expiry `E_0` sooner than the wallet's horizon after
now, or an exit delay out of bounds. `WalletPolicy::new` takes the
specification's parameters: `W` at least 36 hours, `E_0` at least 27 days after
now (a batch expires 28 days after its round; the day between is for the round
to become final), an exit delay of 36 to 48 hours. Then it rebuilds every script
on the path, requires the round to pay exactly one output equal to the batch
output it rebuilds (asset, value and script), so the leaf is where the record
says, and runs the five client checks on the token and its clock, every sweep
below the batch output carrying the notice. A wallet accepts a leaf only after
that, and only once the round is final.

`valid.round_txid` names the round the leaf was checked against. After a
rollback that disconnects it, another transaction can pay the same batch output,
even spending the same issuing coin, and may fail the checks: the wallet checks
again whichever transaction now pays its batch output, and unrolls at once if
that fails, `W` after the replacement being the time it has.
`validate_round` is the same check without the owner's key and nonce, for a
leaf the wallet does not own; `validate_batch_output` checks the path against
one output and leaves out the clock, which only the round shows, and the
policy.

The leaf id is never an outpoint. It is the BIP340 tagged hash, tag
`Arca/leaf-id`, of the batch output's witness program, the number of levels, the
index on the path at each level from the batch output down (one byte each), and
the leaf's witness program.

Both forms are versioned and canonical: a reader refuses an unknown format
version, an unknown template or template version, and anything that does not
encode back to the same record. The binary layout is in the `record` module's
documentation. The JSON form has the same fields; its canonical text has its keys
sorted and no whitespace, asset ids, the token and the genesis hash are in
display order, and amounts are decimal strings. Its reader also refuses a
repeated key, which two readers could otherwise resolve differently.

## Building a tree

`Tree::build` takes the leaves of one asset and the batch's parameters: the
asset, the chain, the token and clock schedule (whose `S` is the operator's
key), whether the sweeps are burn-only, the radix (3 to 6) and the reserve rule.
It follows the specification's rules for building a tree: leaves left to right,
each behind its hash-locked entry; entries grouped into lowest nodes and nodes
into the level above until one is left; scripts bottom-up; the reserve at every
node and every entry; member lists of the operator and the owners under the
node, padded with the operator; RECLAIM on the lowest nodes; no leaf script and
no operator nonce twice.

At every level the children are spread as evenly as possible over the fewest
nodes that hold them: `n` children go to `k = ⌈n / r⌉` nodes, the first
`n mod k` holding one child more than the rest. Every node then holds 2 to `r`
children, so the owners in one batch pay about the same to exit; the only node
with one child is a batch of one leaf. At radix 4, five leaves make lowest nodes
of 3 and 2 under the batch output, and seventeen make lowest nodes of 4, 4, 3, 3
and 3, then nodes of 3 and 2, then the batch output. Radix 2 is refused: an odd
number of children on a level would need a node of one child. `tree::spread`
gives the grouping.

```rust
use arca_covenant::{LeafSpec, ReserveRule, Tree, TreeParams};

let tree = Tree::build(TreeParams {
	asset, chain, schedule, burn: false, radix: 4,
	reserve: ReserveRule::FeeRate { floor_per_kvb, multiple: 4 },
	min_leaf: floor_per_kvb,
}, &leaves)?;
let batch = tree.batch_output();                  // the round pays this
let clock0 = tree.clock0_script_pubkey();         // and the token's atom here
let records = tree.records();                     // one per leaf, for its owner
```

`ReserveRule::FeeRate` is the specification's rule: each output holds
`multiple` times the relay floor for its own spend, sized from that
transaction built with a full-length witness. `ReserveRule::Fixed` puts the same
reserve on every node and on every entry.

## Unrolling a leaf

A leaf goes on-chain from its record alone. `Branch::unroll` builds the node
transactions from the batch output down, each spending the child its parent
created, and `Branch::entry_tx` the unlock of the entry into the leaf with the
preimage. Each takes a `FeeSource`: the output's own reserve as the fee, or a
coin of the broadcaster's in any accepted asset, attached as a second input,
which pays the fee in its own asset while the reserve goes to an ordinary
output. An attached coin changes every transaction's id, which no witness
depends on. The owner authorises each node with a signature over
`BranchNode::unroll_authorisation(t)`; another member signs the same message
and supplies its own member proof.

```rust
let branch = record.validate(&round, &policy, &leaf_key, &leaf_nonce)?.branch;
let auths: Vec<_> = branch.nodes.iter()
	.map(|n| n.owner_auth(sign(&n.unroll_authorisation(t).digest), t, owner))
	.collect();
let txs = branch.unroll(batch_outpoint, &auths, &vec![FeeSource::Reserve; auths.len()])?;
let entry = branch.entry_tx(branch.entry_outpoint(&txs).unwrap(), &preimage, &FeeSource::Reserve)?;
```

## Building

The crate depends on `elements`, `thiserror` and, for the JSON form, `serde` and
`serde_json`, so a wallet can take it alone. The Sequentia Wallet Kit does, for
wasm as well, with the Rust it pins: the crate builds with the `rust-version`
in its `Cargo.toml` and uses no newer standard-library API.

## Testing

The tests verify through the node's own interpreter (`arca-consensus`), so they
need `SEQUENTIA_DIR` set to a node checkout with its consensus library built
([consensus/README.md](../consensus/README.md)). The regtest test also needs
`SEQUENTIAD_EXEC`.

    cargo test -p arca-covenant -- --nocapture

- `tests/vectors.rs`: every output in the regtest suite's golden vectors
  (`regtest/vectors/arca.json`) is rebuilt here and must match byte for byte,
  every leaf, control block and output key; every sample spend is re-signed and
  its signature hash or message, signatures and witness must match, and the
  transaction with the witness built here must verify.
- `tests/consensus.rs`: every path of every policy, spent by a transaction built
  here, verifies under the block rules and the mempool's script checks, and each
  negative case is refused by the block rules with the node's error. `--nocapture`
  prints the table.
- `tests/checks.rs`: the five client checks accept an honest round and refuse
  each attack that consensus accepts, naming the check.
- `tests/encode.rs`: the encodings round-trip and refuse malformed bytes; the
  witness readers recover what the builders wrote.
- `tests/record.rs`: every leaf record in the regtest suite's record vectors
  (`regtest/vectors/records.json`) decodes from both forms, encodes back to the
  same bytes and the same JSON text, gives the same leaf id and validates
  against the round transaction that funds its batch; the refusal vectors are
  refused for the reason they name; every single-field mutation of a valid
  record, and every one-byte change of its binary form, is refused.
- `tests/tree.rs`: the builder rebuilds every batch and record in the record
  vectors byte for byte, the shape of every node included; for every leaf
  count from 1 to 100 at radix 4 (and 1 to 40 at radix 3, 5 and 6) no node
  but a one-leaf batch has one child, the nodes of a level differ by at most
  one child, and one leaf's exit differs from another's by less than one node,
  alone or as its share of a full exit; every leaf's record validates against
  the round, every node transaction of every branch and every entry's unlock
  verifies under the block rules and the mempool's checks, with the reserve as
  the fee and with a fee coin attached, and a child changed by one atom makes
  its node fail; the fee-rate reserves cover each spend; a 1,024-leaf batch's
  node sizes match the specification's table; a record whose salt is not built
  from the owner nonce it names, or from the wallet's nonce, is refused.
- `tests/regtest.rs`: on an anchored regtest chain, the checkpoint and
  reassignment chain, the forfeit and the entry it releases, `htlc-1`, the swap of
  two leaves in two assets, the entry's sweep behind the token and the notice, and
  the burn-only sweep; and a 17-leaf and a 64-leaf batch built by the tree
  builder, every record checked against the confirmed round and three leaves in
  different subtrees unrolled from their records, unlocked and exited: every
  spend confirms, and every negative case is refused by the mempool and again
  when forced into a block with `generateblock`, the block for the same reason
  (the node runs with `-par=1`, so a block refused by a script names the
  failure). It also funds the review's attacks, turned around: a batch whose
  key holds two leaves and a leaf built from a salt the owner signed under
  before; validation refuses each owner's record against the confirmed round.

The decoders and readers, the record's two among them, are fuzz targets in
[fuzz/](../fuzz/README.md).

## Relay policy to plan around

The node's relay policy allows one data-carrying OP_RETURN output per
transaction (`multi-op-return`), but a bare OP_RETURN, the burn-only sweep's
output, carries no data and does not count, so one sweep can burn several nodes,
each at its own index. A node whose policy still counts every OP_RETURN refuses
that transaction; a block producer can mine it all the same. Every sweep returns
the token to `R`, where it waits `W` again before the next. A witness item
that is not minimally encoded (the sweep's `k`, say) is refused by the mempool and
accepted in a block; it changes the witness, not what the spend does.
