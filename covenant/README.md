# arca-covenant

Arca's covenant scripts on Sequentia, as Rust: every script the Arca
specification freezes, the taproot outputs that carry them, the messages their
signatures cover, the witnesses that spend them, and the checks a wallet runs on
a round before it accepts a leaf.

Every output is a taproot output whose internal key is the BIP341 NUMS point, so
it has no key path, with tapscript leaves at leaf version `0xc4` hashed with the
Elements tags. Amounts are explicit and always name their asset. Every lock is
time based: `MedianTime` for `OP_CHECKLOCKTIMEVERIFY`, `RelativeTime` (512-second
units) for `OP_CHECKSEQUENCEVERIFY`; a height is refused. The one script here
that is not Arca's, SeqDEX's fill covenant (`fill`), is read as SeqDEX builds
it: its REFUND lock may be a height, and Arca only reads it. The `order-3` leaf
(`order`) carries one Simplicity leaf (`0xbe`), the fill program
`arca/order-3`, and a hidden data leaf beside its tapscript leaves; it lands as
`seqdex/order` version 2. Both programs refuse an annex, which nothing a fill
carries signs. An `order-2` leaf is the same with `arca/order-2` and
`seqdex/order` version 1, which take one; it is read and filled for the orders
resting under it, and new orders rest as `order-3` (`SeqdexVersion`). The
pruned programs come from sequentia-contracts (`order_programs`), so the spends
are built with no compiler.
A `vtxo-2` leaf and its checkpoint (`collab`) carry the
Simplicity program `arca/collab-2` and a hidden data leaf in place of the
tapscript collaborative path; its one pruned program comes from
sequentia-contracts too.
An accumulator batch (`accumulator`) holds its leaves as a fixed root of leaf
records and a bitmap of the leaves that have left, under the Simplicity
program `arca/accumulator-1`, or `arca/accumulator-2` for a batch without a
sweep, whose pruned forms also come from sequentia-contracts
(`accumulator_programs`).

## What it builds

| Module | Output | Leaves |
|---|---|---|
| `node` | A tree node: the batch output, an inner node, a lowest node | UNROLL behind the membership gate with a timed authorisation; the sweep, except in a batch without one; RECLAIM on a lowest node, each owner's release naming its own round's connector asset, read from an input; on a lowest node built with it, RECLAIM-D, which takes each owner's slot released by the current holders of the coins resting on it, through the delegations their senders signed (`ReleaseTree`, 32 steps) |
| `sweep` | The sweep path of every output above a leaf | The token check (`T` at `R` in input `k`), the notice `W` on every output but the batch output, burn-only for an issuer-operated batch |
| `clock` | `R` and the clock chain from a published schedule `(T, S, W, E_0 … E_K)`; the schedule of a batch without a sweep (`ClockSchedule::never`), which names only `S` | ROLL, RELEASE; `R` is `<W> CSV DROP <S> CHECKSIG` |
| `leaf` | The leaf (`vtxo-1`; `vtxo-2` when `v2` is set) | The rebindable collaborative path for 1 to 4 committed outputs, and the exit; for `vtxo-2`, `arca/collab-2` and its data leaf in place of the tapscript path, the same exit |
| `collab` | `vtxo-2`'s collaborative path, for a leaf and for the checkpoint a `vtxo-2` coin moves into (`Collab2`) | `[[arca/collab-2, data], exit]` (or `sweep`): both keys sign `SHA256(K ‖ k ‖ n ‖ I ‖ m ‖ O)`, `K` the salt's own constant, `k` the coin's input index, `I` the `n` inputs the signers name by asset, amount and script (`utxo_hash`, never the outpoint), `O` the `m` outputs committed to by their whole `output_hash`; `n` 1 to 16, `m` 1 to 4, `k < n`. So a pair fits one index of one shape of transaction: it never spends a second coin of its script in the same transaction, two pairs over the same outputs made for coins spent alone never fit one transaction, and a swap leg moves only beside the other leg. What follows `K` is 70 bytes, which the bond slashes as any collaborative message. The spend carries no annex, which the digest does not cover. The pruned program is one constant (`COLLAB_PROGRAM`, 1,158 bytes) for every spend; a spend is 556 vB where `vtxo-1`'s is 280, its exit 219 vB as `vtxo-1`'s |
| `entry` | The hash-locked entry | Unlock into the owner's leaf with the preimage; the sweep with notice, except in a batch without one |
| `forfeit` | The forfeit output, bound to the leaf given up and to its round | The operator's claim with the preimage and the round's connector asset; the owner's refund after the delay |
| `forfeit` | The round's connector output (`ConnectorPolicy`) | The operator's issuance of the round's connector asset: its signature, and exactly one explicit atom with no reissuance token issued on that input |
| `checkpoint` | The checkpoint output | The collaborative path with the checkpoint's own salt; the sweep with notice, except for a coin of a batch without one |
| `htlc` | `htlc-1`: a leaf whose exit is a hash-locked pair, for a payment out of the tree over Lightning or into it | The leaf's collaborative path; a claim with the preimage after a relative delay; a refund after the timeout and a relative delay. The operator's delay is the shorter: out of the tree the operator claims and the owner refunds, into it the owner claims and the operator refunds |
| `landing` | `landing-1`: the leaf of a supervised asset, whose issuer can freeze holdings by consensus rule | The leaf's collaborative path, its script pushing `K ‖ P` (`K` the salt's own, `P = hash160(L)` the landing program), so its message is `SHA256(K ‖ P ‖ …)` and a pair made for one landing spends only a leaf that lands there, while a double-sign under its salt is evidence to the equivocation bond as for any coin; the landing, which after the exit delay pays output 0 to P2WPKH of the owner's landing key `L`, explicitly in the leaf's asset, holding at least the value less the fee allowance (`LandingTerms`; 119 bytes with a 512-second delay), where a freeze of the asset binds; `landing_tx` builds it. `check_explicit` is the profile's rule for a transaction that moves a supervised asset: every output explicit |
| `enclave` | `enclave-1`: the leaf of a restricted asset (an OpenAMP asset, whose every move needs its issuer's policy key), held only in its holders' enclaves | The leaf's collaborative path, its script pushing `K ‖ D` (`D = HASH160(Q)`, `Q` the holder's enclave program), so a pair made for one holder spends only a leaf that exits to that holder's enclave; the exit, which after the delay pays output 0 `OP_1 <Q>` explicitly in the leaf's asset, holding exactly its value (130 bytes with a 36-hour delay), the fee from a coin attached (`enclave_exit_tx`); where the asset elected clawback, the enclave's own claw leaf `<Ki> CHECKSIGVERIFY <Kp> CHECKSIG`, at once (`claw_tx`). The owner key is the holder's enclave key for the owner nonce (`enclave_key`: `lift_x(H) + t·G`, `t = SHA256(T ‖ T ‖ H ‖ n)`, `T = SHA256("Arca/enclave-key")`). `Enclave` builds the holder's enclave as openampd does; `policy_cosign_digest` is what the policy key signs beside the operator |
| `board` | The board output (`board-1`) | The leaf's own collaborative path; the owner's conversion into the leaf of the board's value (a `landing-1` leaf for a board of a supervised asset; an `enclave-1` leaf for one of a restricted asset, whose board carries the asset's claw leaf too where it elected clawback) |
| `offboard` | The offboard output a round pays: the destination's value and the margin its unlock takes as its fee (`unlock_margin`, the operator's price and the wallet's alike) | Unlock into the owner's destination, at the input's own index, with the preimage; the operator's reclaim after a delay |
| `fill` | An on-chain order a round fills: SeqDEX's fill covenant (`FillOrder`), read from its terms as the relay serves them, and a holder's take of it (`Take`, its id the attestation of every coin it gives up) | FILL, which needs no signature: for the covenant at input `k`, the maker's credit at output `2k` (the price in the asset it is paid in, to the maker's program) and the order resting again at `2k+1` with its identical script after a partial fill; REFUND, the maker's after the order's lock (`refund_tx`: its lock time the order's `expiry_locktime`) |
| `order` | `order-3` (and `order-2`): an order resting in the tree, which the operator fills with the maker offline (`OrderPolicy`), and SeqDEX's own order it lands as (`SeqdexOrder`, `seqdex/order`) | The leaf's collaborative path (`[collab, land]` beside `[fill, data]`); the landing, one exit delay after the leaf reaches the chain, into `seqdex/order` for the same terms with no signature; the fill (`arca/order-2`, Simplicity), the operator's signature over the fill's outputs (`fill_digest`) with, for the coin at input `k`, the maker's credit at `2k` to a `vtxo-1` leaf of the next credit key (`credit_leaf`) and the remainder at `2k+1` under the next salt with the credit keys moved up (`next`); at most four fills along one lineage. `plan` and `check` mirror the program; `landing_tx` builds the landing, a fee coin paying; `publish_digest` is what the leaf's key signs to publish the order to its operator |
| `plan` | No output of its own: offline refresh's plan, a chain of refresh steps the operator applies without the holder (`Plan`, its id what the holder's keys sign, `PlanStep`), and each step's refund (`Refund`), which stands in for the forfeit the holder cannot sign before the step's round exists | None of its own: the refund spends the coin given up and the step's new leaf together, each by the `vtxo-1` collaborative path, into the holder's `v(i)` at output 0 and the rest to the operator at output 1, so every use of either half pays the holder |
| `accumulator` | An accumulator batch output (`AccumulatorPolicy`): up to 1,024 leaves of one asset as a fixed Merkle-sum root of slot records (`Slot`: the owner key, the SHA256 of the leaf's entry's scriptPubKey, the entry's value and the reserve of the slot's exit), the operator's key and a bitmap of the slots that have left, in a hidden data leaf beside the program | EXIT (`arca/accumulator-1`, Simplicity): one slot out in one transaction, under the owner's or the operator's signature over `exit_digest` (chain, root, record and a not-before time, no outpoint and no bitmap) with the lock time at or after that time; the slot's entry at `2k`, the rest at `2k+1` under the same state with the slot's bit set (`exit_tx`; `check` mirrors the program); SWEEP, the tree's batch-output sweep behind the token. Without a sweep (`arca/accumulator-2`, `TapBranch(X2, D)`): the same EXIT, and RELEASE of 1 to 14 slots in one transaction, each under its owner's signature over `release_digest` (chain, root, record and the connector asset `M` of the round that made the owner's new coin, read from an input) and the operator's over `payout_digest` (chain, state, index and every output), the rest at `2k+1` with the bits set (`release_tx`, `AccumulatorRelease` for the owner's release; `check_release` mirrors the program). `read_spend` and `follow` read the state from the exits and releases on the chain |
| `limiter` | No output of Arca's: the mint limiter of sequentia-contracts (`templates/mint_limiter`), which holds an issuer-operated asset's reissuance token (`LimiterParams`, read from the instance file the limiter's tool writes, and `LimiterState`) | None of Arca's: the coin's script in each state (`script_pubkey`, rebuilt from the template's root and the data leaf, equal to the template's address vectors), the state a mint leads to by the program's own rule (`mint`, `room`), what a spend of the coin did (`follow`: a mint, the brake applied or lifted, the recovery), and the reissuance a round's input 0 carries (`reissuance`). The limiter's tool signs and satisfies a mint (`mint-limiter sign`) |
| `issuer` | No output of its own: an issuer-operated batch's burn (`burn`, a bare `OP_RETURN` of explicit asset and value) and the supply a transaction moves (`issued`, `burned`, `reissuing_inputs`) | None |
| `bond` | The operator's equivocation bond (`BondPolicy`: the chain, `S`, the withdrawal key `W`, the notice delay `D`), and the notice output a withdrawal waits in | SLASH, in both outputs: the salt, two messages `S` signed under it (each a form, `Rebind` for a collaborative path's message `SHA256(K ‖ rest)` or `Fill` for an `order-2` fill's `SHA256(F ‖ salt ‖ rest)`, its rest in three chunks of at most 80 bytes, and `S`'s signature), the digests computed in the script and required to differ, and the output at the input's own index a bare `OP_RETURN` of its whole amount, so a slash pays no one; NOTICE, `W`'s signature, the bond whole to the notice output; WITHDRAW, on the notice output, `W`'s signature `D` after the notice confirmed. `slash_tx`, `notice_tx` and `withdraw_tx` build the three spends, a fee coin paying; `check` judges evidence as SLASH will; `rebind_signed_in` reads `S`'s signature and its message from a collaborative spend found on the chain, and `collab2_signed_in` from a `vtxo-2` spend given the outputs its named inputs spend; `cosigned_by` lists every message `S` signed that a coin's lineage rests on, each under its salt, which a holder hands a watcher |
| `channel` | `channel-1`'s outputs: the channel output of each state (`ChannelPolicy`, `State`: the number, the owner's and the operator's balances, the credit already folded into the owner's), the leaf in the tree being the output of state 0, and the credit output the operator's balance settles into | The leaf's collaborative path under the salt's `K`, the same in every state, so a pair made for the coin spends it in any state; UPDATE(n), a state `m > n` signed by owner and operator over `SHA256(Q ‖ le8(m) ‖ P)` (`state_message`), `Q` the salt's state constant and `P` the program of the output at the input's own index, which keeps the input's asset and value; SETTLE(n), after the exit delay, exactly the owner's balance to `OP_1 <A>` and the operator's to the state's credit output, a zero balance's half left out. The credit output's CLAIM pays the owner, at the input's own index, what the operator's cumulative note (`note_message`, `SHA256(N ‖ le8(c))`) credits beyond what was paid, capped at the state's `s + F`, the rest returning to the same script; PROVIDER, `S`'s after the window. A `channel-1` leaf's `LeafPolicy` carries its terms (`ChannelTerms`: the value, the operator's opening balance, the credit window) and `channel_policy` gives its channel. `collab_tx` (the coin's pair at any state), `update_tx`, `settle_tx`, `claim_tx` and `provider_tx` build the spends, a fee coin paying; `claim_amounts` computes a claim as the script does. `read_spend` reads how a spend found on the chain left a state's output (`ChannelSpend`: an update and the number it moved to, a settle, or the collaborative path) by the leaf script it ran, through `witness::without_annex`: nothing a channel signs covers an annex, so whoever relays or mines an update, a settle or a claim can add one, the same spend with the same outputs; a witness that is no spend of that output's leaves is refused |
| `claim` | The claim key a holder's leaf in a claim tree is owned by, `A' = lift_x(A) + t·G` with `t = SHA256(T ‖ T ‖ A ‖ n)` and `T = SHA256("Arca/claim-key")`, for the key `A` a payer names and the nonce `n` it draws (`claim_key`; `claim_keypair` signs for it from the named key's pair); the distribution a payer submits (`Distribution`, its id the attestation of every coin it gives up, with a deadline and a fee allowance when its claims lapse, `DistributionLapse`); and `claim-1`, the claim leaf that lapses ([Claim leaves that lapse](#claim-leaves-that-lapse)) | A distribution without a deadline pays `vtxo-1` leaves under claim keys. `claim-1`: `[collab, [exit, lapse]]`, `vtxo-1`'s collaborative path and exit under the claim key, and LAPSE, which once the median time has passed the deadline `D` (`OP_CHECKLOCKTIMEVERIFY`) and the leaf has waited its exit delay (`OP_CHECKSEQUENCEVERIFY`) pays the output at its own input's index to the distribution's return script (`script_pin`: `SHA256(program ‖ version + 2)`), explicitly in the leaf's asset, holding at least the value less the allowance, with no signature (`LapseTerms`; 105 bytes with a 36-hour delay; `lapse_tx` builds it, the allowance or a fee coin paying). `vest-1`, a vesting distribution's claim leaf: `claim-1` with `<V> OP_CHECKLOCKTIMEVERIFY OP_DROP` in front of the collaborative path and the exit, its collaborative constant `K ‖ V` ([Claim leaves that vest](#claim-leaves-that-vest)) |

`batch` holds a batch of either kind (`Batch`: a tree or an accumulator
batch, built from the same parameters and leaves) and the operator's rule for
choosing between them (`BatchKind::choose`: an accumulator batch when the
share of leaves expected to leave on their own costs less from one output,
never for a batch with a resting order or a channel, or a burn-only one).
`record` holds the leaf record, `record_json` its JSON form (the `json`
feature, on by default), `tree` the builder that turns the leaves of one asset
into a batch, `unroll` the transactions that take a leaf on-chain, `board`
the board and its record, `spend` the transactions that spend a leaf off the
tree (forfeits, exits, the offboard's unlock and reclaim), `release` the
release an owner signs for the lowest node above a coin it gave up, and
the delegation a coin's key signs when the coin moves out of round,
`transfer` the out-of-round transfer and the coin record a receiver validates,
and `clock` and `sweep` the operator's release or roll of the token and the
sweep of an expired batch; all described below.

`message` holds the four messages `OP_CHECKSIGFROMSTACK` verifies (the
rebindable message bound to the spent coin and the chain, the unroll
authorisation, the release bound to the round of the owner's new leaf, the
delegation of a coin's release to the keys of the outputs it moved into), `sign` the Elements taproot signature hash and BIP340
signing, `checks` the five client checks (`check_round` returns the check that
failed; `check_reissue` is the fifth's clause on the batch's profile: a round
whose input reissues the batch's asset passes only when every sweep path above
the leaf is burn-only, and `LeafRecord::validate_round` runs it after the
others), `encode` a canonical binary encoding of every policy and of the clock
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
It names the leaf's template and version (`vtxo-1`; `htlc-1` with its
payment hash, timeout, direction and operator delay; `order-3` or `order-2` with its
order's terms: the asset it is paid in, the price and lot, the landed order's
maker script hash, REFUND time and key, and the four credit keys;
`landing-1` with its landing program and fee allowance; `enclave-1` with its
holder's key, the asset's policy key and its clawback key, though no batch holds
an `enclave-1` leaf: it rests on a board or comes from a reassignment; or
`channel-1` with the operator's opening balance and the credit window;
`claim-1` with its distribution's deadline, the lapse's fee allowance and the
return script; `vest-1` with the same and its vest time; or
`vtxo-2`, a `vtxo-1` leaf whose collaborative path is `arca/collab-2`), the owner's key, the two
nonces the salt is built from, the exit delay, the asset and value, the entry in
front of the leaf (its unlock hash and reserve), the batch's chain, token and
clock schedule
`(T, S, W, E_0 … E_K)` (`R` is rebuilt from `W` and `S`), whether its sweeps
are burn-only, whether its lowest node carries RECLAIM-D, and the path from
the batch output down to the leaf. Each level
of the path holds the index of the child on the leaf's path, the node's reserve
and its other children; above the lowest node it holds the owner's proof in the
node's member tree, and at the lowest node the other owners, whose keys that
node's RECLAIM names. A record of a batch without a sweep is format version 3:
the same fields without the token, the notice, the burn flag and the expiries
([Batches without a sweep](#batches-without-a-sweep)).

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
`SHA256("Arca/salt" ‖ owner_nonce ‖ creator_nonce)`. The owner's wallet picks
`owner_nonce` at random for every leaf it asks for (or publishes it in a receive
request), never from a counter, which a restore would repeat; the leaf's creator
adds the second nonce. For a leaf of a round, and for a board, the creator is
the operator, and the leaf record and the board record call it the operator
nonce. For a leaf a reassignment creates, the creator is the sender (below).
The record carries both nonces and rebuilds the salt from them. `validate`
takes the key and the nonce the wallet expects for this leaf and refuses a
record not built from them, so a wallet that never repeats a nonce is never
given a leaf script it has signed for before.

**The wallet's policy.** `validate` is the check a wallet runs before it accepts
a leaf. It refuses a record outside the wallet's `WalletPolicy`: another chain,
an operator key other than the one the wallet was told, a notice `W` below the
wallet's minimum, a first expiry `E_0` sooner than the wallet's horizon after
now, an exit delay out of bounds, a path deeper than `max_levels`, a node of one
child anywhere but in a batch of one leaf, and a reserve on a node of the path
or on the entry below `min_reserve`. Each bound keeps the leaf's exit what the
builder would make it: a record of sixteen one-child levels with no reserves
matches a round as well as an honest one does, and its exit costs sixteen node
transactions paid from the owner's own coins. `WalletPolicy::new` takes the
specification's parameters: `W` at least 36 hours, `E_0` at least 27 days after
now (a batch expires 28 days after its round; the day between is for the round
to become final), an exit delay of 36 to 48 hours, at most five levels (1,024
leaves at radix 4; a wallet sets the depth of the largest batch its operator
advertises), and a reserve of at least one atom. `ReserveFloor::FeeRate` is the
specification's reserve rule at the wallet's own floor, in the batch asset's
atoms: each node and the entry must hold what `ReserveRule::FeeRate` gives them.
Then it rebuilds every script on the path, requires the round to pay exactly one
output equal to the batch output it rebuilds (asset, value and script), so the
leaf is where the record says, and runs the five client checks on the token and
its clock, every sweep below the batch output carrying the notice. A wallet
accepts a leaf only after that, and only once the round is final.

A leaf of a batch without a sweep never expires, so it meets every notice and
horizon. `WalletPolicy::no_sweep(chain, operator, now)` is the policy of a
wallet that accepts only such batches: no first-expiry horizon, every other
bound `new`'s, and a record of a batch with a sweep refused
(`RecordError::SweepRefused`). The Arca wallet on the main chain (`sequentia`)
takes it; on any other chain it takes `new`, which accepts both kinds.

The 27-day horizon is for accepting a leaf from a round. A leaf the wallet
already holds, and a coin it receives out of round, need only a first expiry
past the exit deadline, three days after now: `policy.receipt()` is that policy.
Under the acceptance horizon an honest leaf would be refused from the second day
of its batch.

`valid.round_txid` names the round the leaf was checked against. After a
rollback the operator broadcasts that round again unchanged, so it returns with
the same txid. `record.recheck(&valid, &round, &policy)` checks the leaf against
whatever transaction the chain now has paying its batch output, under the
receipt policy: `Recheck::Same` when it is the round the leaf was accepted from,
`Recheck::NewRound` when another transaction pays the same batch output. That
one is a new round: every forfeit signed for the old round names a connector
asset that can never be issued, so a leaf given up for it is still its owner's,
and nothing signed for the old round carries over. An error means the leaf is
not where the record says or no longer meets the policy; when its batch output is
on-chain the wallet unrolls at once, `W` after any release being the time it has.
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
let clock0 = tree.clock0_script_pubkey();         // and the token's atom here (None without a sweep)
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

## Expiry: the release and the sweep

The operator recovers an expired batch in two steps, each behind its
signature `S`. The token rests at a clock until the clock's expiry `E`;
`ClockSchedule::place` reads which clock, or `R`, from the script of the output
holding it. `ClockSchedule::release_tx` moves it from clock `j` to `R` at
output 0, with lock time `E_j` and a non-final input, so it confirms only once
the chain's median time has passed `E_j`; `roll_tx` moves it to the next clock
instead, extending the batch without touching the tree. The token holds one
atom and nothing for a fee, so both take a fee coin.

Once the token has waited `W` at `R`, `sweep_tx` builds one wave: the outputs
it takes (`Sweepable`: the batch output, a node, an entry or a checkpoint,
each with the taproot it was built as) by their sweep leaves at inputs
`0..n`, the token at input `n`, which every sweep's `k` names, the outputs the
operator pays, and the token back at `R` for the next wave. Each input carries
its own notice as its sequence, so an output that went on-chain late is swept
only `W` after its own confirmation. What the swept outputs hold beyond the
outputs paid is the fee, in the batch asset, or a fee coin pays. A burn-only
sweep pays every input whole to an `OP_RETURN` at its own index, and takes a
fee coin. The operator signs each input's signature hash.

The sweep takes whatever is left in the batch, and the scripts do not say
whose it was. A leaf on the chain is no longer in it: its exit pays its owner
and nothing sweeps it. So a coin is kept from the sweep by bringing it on the
chain during the notice, which anyone holding its coin record can do: the
record carries its owner's unroll authorisations and its entry's preimage
(and, for a coin paid out of round, the pairs of every step), each of which
spends only into the outputs it pins. A wallet hands its record to
watchtowers, sealed so that each reads it only once its batch is released or
a leaf of its lineage is on the chain, its own batch leaf's authorisations
signed for a time an hour before the batch's first expiry so that they unroll
nothing sooner; the
operator, a member of every node, does the same from its own records
([Coins are taken on the chain before the sweep](../server/README.md#coins-are-taken-on-the-chain-before-the-sweep)).
The holder then relies on any one of them acting within the notice, paid
from the path's reserves. What a sweep takes from a holder all the same is
the operator's to repay by its policy: Arca's server repays it as a new leaf
in the asset's next round, less the late-refresh fee, once the holder's
wallet claims it, and publishes that it does
([Swept coins are repaid](../server/README.md#swept-coins-are-repaid)).

A batch run by its asset's issuer is burn-only: the round that makes it
reissues its value through the asset's mint limiter (`limiter`), and its sweep
destroys whatever it takes, so the units minted for a refresh exist only while
their batch lives. Every other way the operator takes a unit of such an asset
(a forfeit's claim, a reclaim, a reclaimed offboard, a reserve or margin left
over) is the operator's to burn too: those scripts pin no output, so the
transaction pays `issuer::burn` and takes its fee from a coin of another
asset, `FeeSource::Burning` burning whatever margin its inputs leave.

```rust
let fee = FeeSource::Coin { outpoint, coin, fee: atoms, change };
let release = schedule.release_tx(0, token_at_clock0, &fee)?;   // at or after E_0
let sig = sig_over(release.sighash(genesis)?);
let release = release.finish(Clock::witness_items(&sig));
let swept = [root.sweepable(batch_outpoint, batch_value).unwrap()];   // after W at R
let to = [ExplicitOutput::new(asset, batch_value - fee_atoms, operator_script)];
let sw = sweep_tx(&schedule, token_at_r, &swept, &to, &FeeSource::Reserve)?;
let sigs = (0..sw.leaves.len()).map(|i| Ok(sig_over(sw.sighash(i, genesis)?))).collect::<Result<Vec<_>, Error>>()?;
let tx = sw.finish(&sigs)?;
```

### Batches without a sweep

A batch built with `ClockSchedule::never(S)` has no token and no clock, and no
output above its leaves carries a sweep leaf. Its round issues nothing and pays
no token (`Tree::clock0_script_pubkey` is `None`). The batch output and an
inner node are `[UNROLL]`, a lowest node `[UNROLL, RECLAIM]` or `[UNROLL,
[RECLAIM, RECLAIM-D]]`, an entry `[unlock]`, and the checkpoint of one of its
coins `[collab]` (`[arca/collab-2, data]` for a `vtxo-2` coin); the leaf is the
leaf of any batch. A sweep path is `None` wherever it would have been
(`NodePolicy::sweep`, `EntryPolicy::sweep`, `CheckpointPolicy::sweep`,
`ValidCoin::sweep`), and a coin of the batch, or one paid on from it, never
expires (`ValidCoin::expiry` is `transfer::NEVER`, as for a board).

Nothing then takes a holder's coin: a node can only be unrolled into its pinned
children, a lowest node taken back only with its owners' releases, and an entry
only opened into its owner's leaf. The operator recovers what it fronted as it
does for a board: by RECLAIM or RECLAIM-D where every owner under a lowest node
has moved on, and otherwise by unrolling the node with its own authorisation
(it is a member of every node), claiming the forfeits of the owners who gave
their coins up and opening an absent owner's entry, so that coin lands on the
chain as its owner's leaf. A refresh into such a batch takes every forfeit
before its round is broadcast: a leaf whose owner never hands over its forfeit
would otherwise hold the operator's value for good. A forfeit names the
connector asset `M` of its round, which the round's txid fixes, so the wallet
validates its new leaf against the built transaction and signs
(`Forfeit::for_refresh`, `Release::for_refresh`) before it is broadcast.

An accumulator batch built with the never schedule is `arca/accumulator-2`
([The accumulator batch without a sweep](#the-accumulator-batch-without-a-sweep)):
no token, no clock and no sweep leaf on the batch output or an entry. The
operator takes back the slots whose owners moved on by RELEASE, and otherwise
takes a slot out by its own exit authorisation, which pays the owner's entry,
then claims the forfeit or opens the entry into the owner's leaf, as for a
tree.

## Claim leaves that lapse

A distribution pays many holders in one round, each a leaf owned by the claim
key of a key the payer names (`claim`). A distribution that names a deadline
`D` (`DistributionLapse`, in its id) pays `claim-1` leaves, whose LAPSE pays
back to the payer's return script what a holder did not take up by `D`, a term
between payer and payee on the payer's own money, as a cheque lapses. In a
batch without a sweep nothing else would ever bring an unclaimed leaf back: it
would stay its absent holder's for good.

```text
collab:  vtxo-1's collaborative path under the leaf's salt
exit:    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A'> OP_CHECKSIG
lapse:   <D> OP_CHECKLOCKTIMEVERIFY OP_DROP <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
         output[k].script: SHA256(program ‖ version + 2) == pin        k = this input's index
         output[k].asset == the leaf's asset, explicit
         output[k].value >= the leaf's value less the allowance
```

- **Nobody signs a lapse.** Once the leaf is on the chain, `D` has passed and
  the exit delay has run, the payer, the operator's watcher or anyone else can
  lapse it, and it pays only the return script, in the leaf's asset. An annex
  or a fee coin added to it changes nothing it pins, and whatever of the
  allowance the fee leaves goes where the lapser puts it.
- **Its own index.** Each lapse pins the output at its input's index, so the
  claim leaves of one distribution, with one return script and one minimum,
  lapse together in one transaction, each to its own output, and one output
  never stands for two.
- **The exit delay protects a holder who took the claim up.** A holder takes
  its claim up out of round, by the collaborative path, before `D`, and holds
  a coin resting on the claim leaf. If the leaf reaches the chain after `D`,
  the lapse still waits the exit delay from the leaf's confirmation, and the
  holder (or a watchtower, or the operator holding the coin's forfeit)
  publishes its pair in that time, as it answers an exit.
- **The holder's exit and the lapse.** Both wait the exit delay from the
  leaf's confirmation, and the lapse also waits for `D`. A holder whose leaf
  confirms at least an exit delay before `D` exits before the lapse opens; one
  whose leaf confirms later meets the lapse at the same moment, and the first
  spend to confirm takes the coin. So a wallet takes a claim up well before
  `D`, which needs no chain, or starts its exit an exit delay and a margin
  before `D`.
- **Fees.** The allowance pays the fee in the leaf's asset where the node
  takes it (`FeeSource::Split`); where it does not, as for an asset that is
  delisted, a coin of any accepted asset pays the fee and the return script
  gets the whole value (`FeeSource::Coin`). `FeeSource::Reserve` makes the
  whole allowance the fee. `lapse_allowance(floor, multiple)` prices an
  allowance at a multiple of a relay floor for a lapse of `LAPSE_VSIZE`
  (220) vbytes; a lapse into the return script and the fee output measures
  215.
- **Assets.** A `claim-1` leaf's exit pays the claim key by a script path, and
  its lapse any return script, so neither lands where a freeze binds: a
  server takes no distribution of a supervised or a restricted asset, as for
  `vtxo-1` claim leaves. No accumulator batch holds a `claim-1` leaf.

The record keeps the lapse (`Lapse`: the deadline, the allowance, the return
script), template `claim-1` (id 8, version 1); `CoinRecord::lapse` gives it for
the claim leaf itself, and nothing for a coin paid on from one. `Tree::build`
takes it in `LeafSpec::claim`.

```rust
let lapse = distribution.claim_lapse().unwrap();     // what every claim leaf's record keeps
let tx = valid.branch.leaf.lapse_tx(at, value, &lapse.return_script, &FeeSource::Split { fee, change })?.tx;
```

### Claim leaves that vest

A distribution whose lapse names a vest time `V` before `D`
(`DistributionLapse::vest`, the last field of its id) pays `vest-1` leaves,
for allocations that their holders may not move before `V`, as a token sale
locks what it sells:

```text
collab:  <V> OP_CHECKLOCKTIMEVERIFY OP_DROP   vtxo-1's collaborative path over K ‖ V
exit:    <V> OP_CHECKLOCKTIMEVERIFY OP_DROP <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A'> OP_CHECKSIG
lapse:   claim-1's, after D
```

as `[collab, [exit, lapse]]`, in a batch without a sweep that holds only
`vest-1` leaves of one `V` (`TreeError::VestBatch` otherwise), whose lowest
nodes carry `[UNROLL, RECLAIM]` with RECLAIM (and RECLAIM-D) behind the same
`<V> OP_CHECKLOCKTIMEVERIFY OP_DROP` (`NodePolicy::with_reclaim_lock`).

- **Nothing moves the value before `V`.** The batch output and the inner
  nodes only unroll into their pinned children, the entry only opens into its
  leaf, and the leaf's collaborative path, its exit and its lowest node's
  RECLAIM all check `V`. Owner and operator together cannot move it either:
  a refresh, an out-of-round transfer and a reclaim each take a transaction
  that is not final before `V`. What no script can stop is a holder signing
  away, before `V`, a spend that confirms only after it, as with any time
  lock; so an operator co-signs no spend of a `vest-1` leaf before `V`, and
  no off-chain coin rests on one before it vests.
- **A pair names `V`.** The collaborative message starts with `K ‖ V` (`V`
  as u32), so a pair made for a vesting leaf spends no other leaf, and a pair
  over `vtxo-1`'s `K` spends no vesting leaf.
- **Without a sweep, and why.** A sweep would take an unvested leaf back at
  the batch's expiry, and a leaf repaid after a sweep is a new coin that has
  not vested anything. The builder and the record refuse `vest-1` in a batch
  with a sweep.
- **The lapse.** What a holder has not taken up by `D` goes back to the
  payer as with `claim-1`. A holder takes its claim up between `V` and `D`;
  `D` comes after `V` (`LapseError::Vest`, `ClaimError::VestAfterDeadline`).
- **Spends carry `V`.** `LeafPolicy::lock_time` is `V`; `collab_tx` (and so
  every forfeit and checkpoint of the leaf) and `exit_tx` set it with a
  non-final input, as `NodePolicy::reclaim_tx` does for a locked RECLAIM.

The record is template `vest-1` (id 9, version 1, format 3 only): `claim-1`'s
fields and then `V`; its JSON form adds `"vest"` to `claim`. The policy
encoding is type 16, and a node's reclaim flag 2 carries `V`.
Measured on a regtest node (`tests/vest.rs`): the exit 229 vB, the
collaborative spend 283 vB, the lapse 215 vB, a reclaim of a lowest node of
three with one connector 451 vB; the round paying one hundred holders 264 vB,
one batch output; a hundred leaves are four levels deep at radix 4.

## Off-chain transactions

Every spend outside the unroll has one shape (`spend`): input 0 spends an
Arca output, outputs `0..m` are the ones its path pins or its signers committed
to, and the rest is open for the fee. What the spent coins hold beyond those
outputs is the margin, per asset. `FeeSource::Reserve` makes the margin the fee,
in the coin's own asset; `FeeSource::Coin` attaches a coin of the broadcaster's
in any accepted asset, which pays the fee, and the margin goes to its change. A
rebindable spend (`collab_tx`, for a leaf or a checkpoint) is signed by owner
and operator as a `Pair` over the outputs alone, before the coin is on-chain. A
spend whose path ends in `<key> OP_CHECKSIG` (`KeySpend`: an exit, a forfeit's
claim or refund, an offboard's reclaim) is signed once built.

**The forfeit.** A refresh or an offboard gives up an old leaf against an
unlock hash `h`. The owner and the operator sign the old leaf's move into the
forfeit output in advance, leaving a margin for the fee. The forfeit's claim
needs the preimage of `h`, the operator's signature, and an input holding the
round's connector asset `M`; it names the id of the leaf given up, so every
forfeit output is unique to its leaf and two forfeits of one participation can
never share one. `M` is the asset that spending the round's connector output
`(round_txid, c)` would issue (`connector_asset`): the owner computes it from
the confirmed round, the operator issues one atom only when it needs to claim
and reuses it for every claim of that round. If the round is not in the chain,
`(round_txid, c)` does not exist, `M` can never be issued and no forfeit of that
round can be claimed. The claim reads input `k`'s asset and nothing else of it,
so several claims can name one `k`: `batch_claim_tx` claims every forfeit of a
round in one transaction, the forfeits at inputs `0..n` and one atom of `M` at
input `n`, which goes back to the operator. The operator signs each claim input
over the whole transaction, so no signature serves another input or another
claim, and a forfeit of another round cannot join: its claim finds this round's
`M` at `k`, not its own.

The connector output has a script of its own (`ConnectorPolicy`): the
operator's signature, then `OP_INSPECTINPUTISSUANCE` on its own input requiring
a new issuance with a zero contract hash of exactly one explicit atom and no
reissuance token. So nobody, the operator included, can spend it without issuing
`M`, which would strand every claim of the round. The owner signs only a
forfeit built by `Forfeit::for_refresh` (or `Forfeit::for_offboard`; for a new
leaf of an accumulator batch, `ValidAccumulatorLeaf::forfeit_for`), which
takes `h` from the new leaf it validated and `M` from that round, and refuses a
round other than the one the leaf was validated against, an output `c` that is
not the operator's connector, and an old leaf under another operator.
`Forfeit::new` takes `h` and `M` as given: it is how the server, which chose
them, rebuilds the forfeit to verify the pair.

After a rollback the operator broadcasts the identical round again: it has
`nLockTime` 0 and spends only the operator's coins, so it returns with the same
txid and its claims follow. A round with another txid that paid the same batch
output would void every forfeit of the old one while its new leaves stayed good:
each refreshed owner would keep the old coin and the new leaf. So a round with
another txid is always a new round, with a new tree and new unlock hashes, whose
participations run again, and a round that carries refreshes takes no input of a
third party (a covenant fill, say), which could be spent elsewhere and force a
replacement; fills go in their own round transactions, which carry only the
takes that fill them and are broadcast only once the operator holds every
take's forfeits, signed against the round's txid before it goes out. A round
that cannot
return leaves each owner who gave up a leaf for it a forfeit that no claim can
answer and that ends in the owner's refund. An owner holding that forfeit
whole, which happens only when the operator published it, and the preimage of
a re-run would refund the old coin and keep the new leaf too. So a coin whose
forfeit for the lost round the operator published is never taken into a
re-run, the operator never publishes a forfeit for a round once it is lost,
and any other re-run completes as an ordinary participation, its forfeit for
the new round taken and its preimage released against it. The operator
co-signs no other off-chain spend of a leaf given up for the lost round.

```rust
let valid = new_record.validate(&round, &policy, &new_key, &new_nonce)?;   // the new leaf, in this round
let f = Forfeit::for_refresh(old_leaf, (asset, value), old_leaf_id, &valid, &round, c, refund_delay, margin)?;
let digest = f.message().digest;                       // owner and operator each sign it
f.verify(&pair)?;                                      // the server's check
let forfeit_tx = f.tx(old_leaf_coin, &pair, &FeeSource::Reserve)?;
let issue = ConnectorPolicy { operator }.issuance(connector_coin, (asset, value), m_to, &[], &FeeSource::Reserve)?;
let issue = issue.finish(vec![sig_over(issue.sighash(genesis)?)]);           // the operator, when it must claim
let claim = f.claim(forfeit_coin, (m_coin, m_txout), &outputs, m_back_to, &FeeSource::Reserve)?;
let claim = claim.finish(ForfeitPolicy::claim_items(&sig_over(claim.sighash(genesis)?), &preimage, Forfeit::CONNECTOR_INPUT));
```

**The release.** Once every owner under a lowest node has moved on, the
operator need not wait for the batch to expire: each owner signs a release of
the node, and the operator spends it by its RECLAIM leaf. The release is
`SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)`, `H` the node's children hash
and `M` the connector asset of the round that made the owner's new leaf (or
paid its offboard). RECLAIM pushes `"Arca/release" ‖ genesis_hash ‖ H` and, for
each owner in turn, reads `M` from the input the witness names, explicitly, and
checks the owner's signature over the hash of the two. So a reclaim confirms
only with an atom of each named `M` among its inputs, `M` exists only while its
round is in the chain, and a release is void with the round it names: a reclaim
that confirmed is disconnected with that round and cannot return without it.
Owners who refreshed in different rounds each name their own; owners of one
round share one input. The operator reuses one atom of each `M` across that
round's claims and reclaims, paying it back to itself each time. A wallet signs
only a release built by `Release::for_refresh` (or `Release::for_offboard`;
`Release::for_accumulator_refresh` for a new leaf of an accumulator batch),
which takes `H` from the old leaf it holds and `M` from the round its new leaf
was validated against, and refuses another round, an output that is not the
operator's connector and an old leaf under another operator; it signs once it
holds the new leaf's preimage and that round is final. A reclaim of four owners
with one atom of `M` is 485 vB.

```rust
let r = Release::for_refresh(&old_valid, &new_valid, &round, c)?;   // H from the old leaf, M from the round
let sig = sign_digest(&old_key, &r.message().digest, &aux);       // the owner's release
r.verify(&sig)?;                                                   // the server's check
let lowest = old_valid.branch.nodes.last().unwrap();
let ks = lowest.reclaim_tx(node_coin, &[(m_coin, m_txout)], &outputs, m_back_to, &FeeSource::Reserve)?;
let k = node::connector_index(&ks.prevouts, r.connector).unwrap();    // the input RECLAIM reads M from
let tx = ks.finish(node::reclaim_items(&sig_over(ks.sighash(genesis)?), &releases_in_owner_order, owners)?);
```

**Release delegation.** A batch leaf paid on out of round can be released
only by whoever holds the coins it became, and its owner no longer does. A
batch built with `delegated_reclaim` puts RECLAIM-D beside RECLAIM on every
lowest node, at `[UNROLL, [SWEEP, [RECLAIM, RECLAIM-D]]]` (UNROLL's control
block stays 65 bytes, SWEEP's is 97, the two reclaims' 129). When a coin moves
into a reassignment, its key signs a delegation to the owner keys of every
output, in output order: `SHA256("Arca/delegate" ‖ genesis_hash ‖ K_1 ‖ … ‖
K_m)` (`Delegation::for_reassignment`, which refuses outputs that are not the
leaves named for them). RECLAIM-D then takes, for each owner of the node, a
tree (`ReleaseTree`): the owner's own release, or its delegation and a tree
for each key it names, every leaf of every tree a release over the node's
`P ‖ M`, `M` the connector asset of the round of that holder's new coin, read
from an input as RECLAIM reads it. A holder signs its releases with
`Release::for_holder`, one for each lowest node with RECLAIM-D its coin rests
on (`ValidCoin::release_nodes`), once it holds its new leaf's preimage and
that round is final (`Release::for_holder_offboard` when it takes the coin off
the tree by an offboard instead). So the node is released only when every coin resting on
it has a successor in a round in the chain, and returns at the next round
after its holders refresh, however many times its coins moved.

An in-tree fill of a resting order is a reassignment too. Its outputs are the
maker's credit, for a partial fill the order resting again, then the taker's
leaves (`OrderPolicy::fill_leaves` gives the maker's two), and every coin it
spends delegates to all of them (`Delegation::for_fill`): each taker coin
when the taker signs the fill, and the order's coin later, since its maker is
away when it is filled and the operator's signature alone fills it. The
maker signs once it holds a coin the fill made, from that coin's record and
the taker's leaves the operator names (`Delegation::for_filled_order`, which
refuses leaves that are not the fill's outputs). The order resting again
carries the order coin's own key, and a delegation or a release names a key,
never a coin: whatever that key signed later would fill the order coin's
slot in place of its delegation into the fill, and the node could go while
the first fill's credit and taker leaves still rest on it. So only the
order's first coin signs. The order resting again (`ValidCoin::is_rest`)
signs no release and no delegation, into a later fill or a cancel alike
(`Delegation::for_reassignment` and `Delegation::for_filled_order` refuse
it), and the operator neither keeps nor follows one. Every tree that runs
through it then stays open, so the nodes under the order's coin and under
the taker coins of a fill that left a remainder come back at their batches'
expiry.
A delegation that named its coin would keep that liveness, but the message
is built by RECLAIM-D's script, so it would take a new leaf version.

The `htlc-1` leaf of a Lightning payment out of the tree is the operator's
once the payment is paid, and its owner key is the sender's. The sender
releases each lowest node with RECLAIM-D it rests on once it holds the
payment's preimage, naming a round the operator names
(`Release::for_paid_send`, which refuses a leaf of a receive and a preimage
of another hash), and never before: the release ends its refund.

A delegation names every output, so no co-receiver (a payer's change, a
swap's other side) can release a slot without the others; and it adds no one
a coin must trust, since the coin's senders, with the operator, could already
spend the coins it came from twice. The chain cannot know whether a key has
delegated: a release by a key that already did confirms as its holder's
would, so the operator, whose signature every reclaim needs, refuses a
release from any key whose coin has moved on. The script checks every key is
32 bytes: `OP_CHECKSIGFROMSTACK` passes any signature for a key of another
length, so two keys of 33 and 31 bytes over the 64 a delegation signed would
release a node nobody under it released. The leaf runs 32 steps, one per
release or delegation, summed over every owner's tree; a node whose trees
need more waits for its batch's expiry. A record reader that does not know
RECLAIM-D refuses such a batch's leaves (the record's flag), so an operator
builds batches with it only for wallets that read it. Measured on the node:
the leaf is 1,868 bytes at four owners; a reclaim with a coin paid twice, a
swap and a direct release (12 steps) is 1,170 vB, four direct releases through
RECLAIM-D 951 vB, the same through RECLAIM 481 vB, and six owners using all 32
steps 1,691 vB.

```rust
let d = Delegation::for_reassignment(&my_coin, &plan.outputs, &leaves)?;  // the sender, at the transfer
let sig = sign_digest(&my_key, &d.message().digest, &aux);
d.verify(&sig)?;                                                       // the operator's check
let df = Delegation::for_fill(&taker_coin.leaf, &order_policy, &fill_outputs, &taker_leaves)?;  // a taker, at a fill
let dm = Delegation::for_filled_order(&credit_coin, &taker_leaves)?;   // the maker, later, from its credit
let rs = Release::for_holder(&coin, &new_valid, &round, c)?;           // the holder, after its refresh
let rp = Release::for_paid_send(&htlc_coin, &preimage, &round, c)?;    // a sender, once its payment is paid
let trees = vec![ReleaseTree::Delegation { key: a0, sig: d0, to: vec![
	ReleaseTree::Release { key: b, sig: rb, connector_input: 1 },
	ReleaseTree::Release { key: a0_change, sig: rc, connector_input: 1 },
]}, /* one per owner */];
let ks = lowest.reclaim_delegated_tx(node_coin, &[(m_coin, m_txout)], &outputs, m_back_to, &FeeSource::Reserve)?;
let tx = ks.finish(lowest.reclaim_delegated_items(chain, &sig_over(ks.sighash(genesis)?), &trees)?);
```

**The board.** The owner brings its own coins into Arca with a board
(`board-1`): it pays them to a board output (`BoardRecord::tx`) and keeps a
`BoardRecord`: the key, the two nonces of the salt (one given by the operator)
and the exit delay of the leaf the board converts into, its asset, value, chain
and operator. The board output has two script leaves: the leaf's own
collaborative path, and the conversion, which needs the owner's signature and
pays the standard leaf of the board's whole value at output 0
(`BoardPolicy::conversion`; its fee comes from a coin attached, in any accepted
asset). The owner alone takes a board only by converting it, and the leaf's
exit delay then runs from the conversion, so every unilateral exit gives the
full notice and nobody else can start it. Because the board's collaborative
leaf is the leaf's own and the board holds the leaf's value, one pair over the
leaf spends the coin in either form: a board's forfeit, or a checkpoint of it,
is signed in advance as for any leaf. The operator hands over a refreshed
board's preimage on the pair alone, publishes the forfeit from the board output
(`Forfeit::board_tx`) whenever it wants the value, and answers a conversion by
publishing it on the leaf within the delay. A board may also be paid out of
round. The record has a binary and a JSON form like the leaf record's, and
`validate` checks it against the board transaction under the wallet's policy
(chain, operator, exit delay). A board's leaf id is that of a batch with no
levels whose batch output is the board output. The board's own conversion costs
370 vB with a fee coin; the operator credits a board once its transaction is
final.

**No off-chain spend of a leaf that is on-chain.** Any Arca leaf on-chain past
its exit delay, a batch leaf someone unrolled, a reassignment's output someone
published or a board someone converted, can be exited by its owner at once, so
no off-chain spend of it is safe. The operator refuses to
co-sign a spend of a leaf that is on-chain, and a receiver refuses a coin when
any leaf or checkpoint in its lineage is on-chain (below).

**The offboard.** A round pays an `OffboardPolicy` output, whose unlock moves
it, with the preimage of `h`, to the owner's destination (any script, asset and
value explicit) at the unlocking input's own index, so that two offboards to
one destination can never be paid by one output; anyone holding the preimage
can broadcast it and choose how the fee is paid. The owner checks the round with
`find` and forfeits its leaf against `h`; the operator's claim of that forfeit
publishes the preimage. The operator reclaims the output after its delay, which
must be longer than unrolling the old leaf, its exit delay, the forfeit's refund
delay and a margin to broadcast the unlock together: a wallet starts its exit as
soon as the preimage fails to arrive.

## Out-of-round transfers

A transfer is two linked transactions. Each input coin moves, by its
collaborative path, into a checkpoint output, and the reassignment moves the
checkpoints into the new leaves (1 to 4 committed outputs). Where the coin
rests on a batch with RECLAIM-D, its key also signs a delegation of its
release to the outputs' owner keys ([Release delegation](#off-chain-transactions)). For each input, its
owner and the operator sign two pairs in advance: the checkpoint pair, over the
checkpoint output, and the reassignment pair, over the outputs. A reassignment
may take several coins of several owners in several assets, the in-tree swap:
each owner signs the same output set. The checkpoint's salt is
`SHA256("Arca/checkpoint" ‖ the coin's leaf salt)`, so neither step can be
skipped or reordered, and the checkpoint sweeps with the notice of the batch the
coin descends from.

```rust
let receiver_leaf = NewLeaf { owner, owner_nonce, creator_nonce: random(), exit_delay };  // the request, and the sender's nonce
let plan = TransferPlan { inputs: vec![(coin, checkpoint_value)], outputs };
plan.admit(&mut seen)?;                               // the operator's rule, before it co-signs
let cp = plan.checkpoint_message(0)?.digest;          // owner and operator sign both
let re = plan.reassignment_message(0)?.digest;
let record = CoinRecord::Transfer(Box::new(Transfer {
	inputs: vec![TransferInput { coin: my_record, checkpoint_value, checkpoint: cp_pair, reassignment: re_pair }],
	outputs: plan.outputs.clone(), index: 0, leaf: receiver_leaf,
}));
```

**Every output a pair commits to carries something unique to the inputs it
spends.** A pair names outputs, never inputs: two pairs whose committed outputs
agree at every index both commit to (the same outputs, or one set the first
outputs of the other) are satisfied by one transaction, which spends the coins
of both, creates the outputs once, and leaves the value of one side to whoever
broadcasts it. Each pair is sound on its own, so no signer can see it. So each
kind of output carries what makes it unique: a forfeit output the id of the
leaf it gives up, a checkpoint the salt of the coin it holds, and every output
a reassignment creates something the sender draws fresh, for a leaf its
creator nonce (an `htlc-1` output, its salts). The sender's wallet draws a
fresh random nonce for every leaf it creates, the receiver's and its own
change alike, never from a counter and never from the receive request; two
payments to one receive request then create two leaves, where with the request
alone they would commit to one output and one sender's coin would go to the
broadcaster. The receiver checks its own key and nonce as for any leaf, and
the leaf is rebuilt from both nonces.

Two checks hold the rule where a sender breaks it. The operator co-signs a
reassignment only after `TransferPlan::admit` against every reassignment it has
co-signed (`SeenReassignments`, kept by the hash of output 0, which any two
such reassignments share): it refuses one whose outputs agree with another's at
every index both commit to, and admits the same reassignment again. And
`CoinRecord::validate` refuses a record in which two coins share a salt: a leaf
promised by two reassignments may exist on-chain only once, and a coin that
rests on it twice could be brought on-chain only in part. `validate` cannot see
the coins a wallet holds or has held, so the wallet keeps every salt it has held
a coin under and refuses a coin whose salt (`coin.leaf.salt`) is one of them.
Two records at one leaf are one coin, and a leaf rebuilt at a salt its owner has
signed under is spent by the owner's old pairs, at the same asset and value:
the sender chooses the creator nonce, so it could rebuild such a leaf. A second
honest payment never meets that refusal, since its sender drew another creator
nonce.

A `CoinRecord` is what the holder of a coin keeps, and what a receiver gets from
the mailbox: for a leaf of a batch, its leaf record with its entry's preimage
and its owner's unroll authorisations, so anyone holding the record can bring it
on-chain; for a leaf of an accumulator batch, its `AccumulatorRecord` with its
entry's preimage and its owner's exit authorisation, to the same end; for a
board, its board record (the board is on-chain already, and a
checkpoint of it spends the board output itself, `board_checkpoint_tx`); for a
coin a reassignment created, the reassignment's inputs (each a
coin record, with its checkpoint's value and both pairs), its outputs, the
coin's index and its leaf. The binary form is versioned and canonical, and the
layout is in the `transfer` module's documentation.

`CoinRecord::validate(rounds, policy, key, nonce)` is the receiver's check,
from the record and the transactions its bases came from alone: every batch leaf
validates against its round, and every board against its board transaction,
under the receiver's policy, every preimage and authorisation
is good and usable now, every pair verifies, no reassignment creates more than
its checkpoints hold, every leaf in the lineage (whoever owns it) has an exit
delay within the policy's bounds, the coin's output is the leaf the record names
for the receiver's key and nonce and the sender's creator nonce, no coin is
spent by two reassignments or at two inputs of one anywhere in the record (two
coins descending from one reassignment, such as two payments from one payer,
both carry its spends, which one transaction brings on-chain), no two coins
share a salt, and the chain is at most
five reassignments from a round. A receiver passes
`policy.receipt()`: a coin from a reassignment is safe only until the earliest
first expiry among the batches it descends from (`expiry`), and the receipt
policy asks that every one of them lie past the exit deadline. The valid coin
builds every transaction that brings it on-chain: the unroll and entry of each
batch leaf, each `checkpoint_tx`, each `reassignment_tx`.

The record cannot show what is on-chain. `coin.lineage()` lists every leaf and
checkpoint the coin descends from, and `coin.check_lineage(on_chain)` refuses the
coin if an index of the chain reports any of them on-chain; a wallet without such
an index relies on the operator's refusal to co-sign a spend of an on-chain leaf.
A board must instead still be there: `coin.boards()` lists the boards the coin
rests on, and `coin.check_boards(unspent)` refuses it when one is spent, by its
conversion or by a forfeit. A board has no batch and no expiry: a coin from
boards alone never expires (`expiry` is `MedianTime::MAX`), and a checkpoint of a
board's leaf carries the frozen sweep for a token no issuance creates
(`board_sweep`), so only its collaborative path spends it.

Against the sender alone the receiver is then safe: every leaf of the lineage is
off-chain and has an exit delay of at least the policy's minimum, so when the
sender's leaf reaches the chain, the receiver publishes the checkpoint and the
reassignment within that delay, or a watchtower holding the receiver's record
does while the receiver is away. It answers at once: a rollback that disconnects
its answer does not restart the delay of the leaf it answered. Against the sender
and the operator together it is not safe, before a round: that is the trust the
specification calls operator-confirmed.

## The accumulator batch

An accumulator batch (`accumulator`) replaces a tree's node levels for a batch
of up to 1,024 leaves. `Accumulator::build` takes the leaves of one asset and
the batch's parameters (`AccumulatorParams`: a tree's, but for the radix) and
puts each leaf behind its hash-locked entry under the tree's rules (one key per
leaf, no operator nonce twice, no leaf script twice, the leaf's value bounds);
slot `j` holds leaf `j`. The batch output is
`P2TR(NUMS, TapBranch(TapBranch(X, D), SWEEP))`: `X` the program, `D` the
data leaf of the root, the operator's key and the bitmap, `SWEEP` the sweep a
tree's batch output carries. A slot's record is
`SHA256(0x00 ‖ j ‖ owner ‖ SHA256(entry scriptPubKey) ‖ entry value ‖ exit
reserve)` and weighs the entry's value and the reserve; an inner node is
`SHA256(0x01 ‖ h_l ‖ w_l ‖ h_r ‖ w_r)`; the root's weight is what the batch
output holds. `ReserveRule::Fixed { node, entry }` puts `node` on every slot's
exit; `ReserveRule::FeeRate` sizes it from the exit itself.

An exit of slot `j` from the batch output at input `k` needs the slot's record
on its path to the root, every weight on the path the sum of its children,
its bit clear, and the signature of the slot's owner, or of the operator (the
operator's path is the tree's gate, where the operator is a member of every
node), over `exit_digest`: the chain, the root, the record and a time `t`,
with the transaction's lock time at or after `t`. It names no outpoint and no
bitmap, so it holds for every state of the batch: an owner signs it when the
leaf is accepted and hands it to a watcher or a receiver, as it does the
unroll authorisations of a tree leaf. The exit pays the slot's entry at `2k`,
the very output a tree's lowest node pays, and the rest at `2k+1` under the
same state with the slot's bit set; the slot's reserve pays the fee, or a coin
attached does. From the entry on, the leaf is a tree leaf's: the entry's
unlock with the preimage, the exit delay, and every signature made for the
leaf. Because the root never changes, every other holder's record and
authorisation stay valid through every exit, and because every weight on an
exit's path is checked, a record under a node whose weight is not the sum of
its children can never leave, so the batch always holds enough for every
record that can.

```rust
use arca_covenant::accumulator::{Accumulator, AccumulatorParams, ExitAuth};

let acc = Accumulator::build(params, &leaves)?;
let batch = acc.batch_output();                          // the round pays this
let record = acc.record(i);                              // for leaf i's owner
let valid = record.validate(&round, &policy, &leaf_key, &leaf_nonce)?;
let auth = ExitAuth { by_operator: false, time: t, signature: sign(&valid.exit_digest(t)) };
let exit = valid.exit_tx(&state, batch_outpoint, held, &auth, &FeeSource::Reserve)?;   // state: the batch's latest
let entry = valid.entry_tx(OutPoint::new(exit.tx.txid(), 0), &preimage, &FeeSource::Reserve)?;
```

`AccumulatorRecord::validate` is the wallet's check before it accepts a leaf in
an accumulator batch: the record is for its key and nonce, within its policy
(chain, operator, notice, first expiry, exit delay, and the reserves of the
entry and of the slot's exit), and the round pays exactly one output equal to
the batch output the record rebuilds (asset, the root's weight, and the script
with every bit clear), with the five checks on the token and its clock. Every
exit publishes the whole state it spends, so `read_exit` reads the bitmap of a
batch from its latest exit, and `follow` replays a batch's exits from its
round; a builder checks the state it spends against the batch output's script.

A holder keeps such a leaf as `CoinRecord::Accumulator`: the record, the
entry's preimage and its own exit authorisation (signature and time), so the
record alone takes the leaf out. Its binary form is tag 6 of the coin record
(`AccumulatorRecord::to_bytes`, layout in the `accumulator` module), and
`CoinRecord::validate` checks it as the wallet does a leaf of its own, then the
preimage against the entry's unlock hash and the authorisation as the owner's,
good now (`ValidOrigin::Accumulator`).

The exit's input carries no annex: the authorisation does not name one, so the
program refuses one rather than let whoever holds the authorisation add
weight to the exit (its cost is a constant well inside its witness's budget,
so it never needs the budget an annex buys). `read_exit` strips an annex all
the same.

Exits are serial: each spends the batch output and re-creates it, so the
mempool takes 25 exits of one batch from one unconfirmed chain, and a block
takes them together. An exit is 979 vB with its
fee from the slot's reserve, against 2,854 vB for the five node transactions of
a 1,024-leaf tree; the entry's unlock (234 vB) and the leaf's exit follow in
both (`covenant/tests/accumulator.rs`).

### The accumulator batch without a sweep

A batch built with `ClockSchedule::never(S)` is `arca/accumulator-2`:
`P2TR(NUMS, TapBranch(X2, D))`, the same state, records and tree, and no
sweep (`AccumulatorPolicy::sweep` is `None`). Its EXIT is the one above, the
same authorisation. Its RELEASE takes back, in one transaction, the slots
`j_1 < … < j_n` whose owners gave them up, `n` from 1 to 14
(`RELEASE_PLACES`, the most whose cost the witness pays for with no annex):

- each slot's record on its path to `ROOT`, its bit clear, and its owner's
  signature over `release_digest`, `SHA256(SHA256("Arca/accumulator-release")
  ‖ genesis ‖ ROOT ‖ rec_j ‖ M)`, `M` the explicit asset of the input the slot
  names: the connector asset of the round that made the owner's new coin;
- the operator's signature over `payout_digest`,
  `SHA256(SHA256("Arca/accumulator-release-outputs") ‖ genesis ‖ D ‖ k ‖
  outputs_hash)`, `D` the state the coin holds and `outputs_hash` the chain's
  commitment to every output (`accumulator::outputs_hash`);
- the rest at `2k+1` under the same state with the slots' bits set, holding
  the input less every released weight. Output `2k` and what the slots held
  are the operator's; for an issuer-operated asset the operator pays them to a
  burn.

`M` exists only while its round is in the chain, so a release is void with
that round, as a tree's release is. A release names one slot of one batch for
one round on one chain, and no outpoint or bitmap, so releases signed at
different times ride one transaction; a slot's bit, once set, refuses it
again. Nothing else spends the batch: no path moves a slot its owner has
neither taken out nor released.

A wallet signs its slot's release with `AccumulatorRelease::for_refresh`,
`for_accumulator_refresh` or `for_offboard`, which take the slot from the old
leaf it validated and `M` from the round its new coin was validated against,
and refuse a batch with a sweep; it signs once it holds the new coin's preimage
and that round is final. The operator gathers releases and spends them with
`AccumulatorPolicy::release_tx`: the batch output at input 0, an atom of each
round's `M` after it, paid back to itself, its payout at output 0, then the
operator's signature over `ReleaseSpend::digest` (`finish`).

```rust
use arca_covenant::accumulator::{AccumulatorRelease, Released};

let r = AccumulatorRelease::for_refresh(&old_valid, &new_valid, &round, c)?;   // the slot from the old leaf, M from the round
let sig = sign_digest(&old_key, &r.digest(), &aux);                         // the owner's release
r.verify(&sig)?;                                                            // the server's check
let slots = [Released { exit: old_valid.exit.clone(), connector: r.connector, signature: sig }];
let rs = state.release_tx(&chain, batch_coin, (asset, held), &slots, &[(m_coin, m_txout)], &[payout], m_back_to, &FeeSource::Reserve)?;
let tx = rs.finish(&sign_digest(&operator, &rs.digest(&chain), &aux));      // then the M atom's own witness
```

Such a record is format version 4 (no token, notice, burn or expiry; a tree
leaf record is version 2 or 3, so the first byte tells the kinds apart), and
`WalletPolicy::no_sweep` takes it while it refuses an `arca/accumulator-1`
record. Measured on regtest (`covenant/tests/accumulator_release.rs`): an
exit is 1,072 vB with its fee from the slot's reserve; a release of one slot
1,305 vB, of 14 slots 3,317 vB, and of the last nine slots, leaving no rest,
2,320 vB, each with one or two atoms of `M` beside it.

## In-tree fills of a resting order

An `order-3` leaf (`order`), or an `order-2` leaf, is filled off the chain by a transaction that
spends the order's coin by its fill path, under the operator's signature over
the fill's outputs, and each of the taker's coins through a checkpoint, as a
transfer does. The outputs (2 to 4, all committed by every signature) are the
maker's credit at 0, for a partial fill the order resting again at 1, then the
taker's leaves. Every coin it makes has a `CoinRecord::Fill`: the order coin's
own record, the operator's signature, whether the fill is partial, the taker's
inputs with their checkpoint values and pairs, the outputs, the coin's index,
and which coin it is (`FillLeaf`): the maker's credit or the order resting
again, whose leaves follow from the order's terms and which name only the nonce
the maker derived the owner key from, or a taker's new leaf.

```rust
let op = order_coin.leaf.order_policy().unwrap();      // the coin a round made, or a fill's remainder
let plan = op.plan(order_coin.value, filled)?;          // the credit at its price, the order resting again
let digest = op.fill_digest(order_coin.value, &outputs)?; // what the operator signs, outputs 0..m
let credit = CoinRecord::Fill(Box::new(FillCoin {
	fill: OrderFill { order: order_record, signature, partial: true, inputs: vec![taker_input], outputs },
	index: 0, leaf: FillLeaf::Credit { owner_nonce },
}));
```

`CoinRecord::validate` checks a fill as the program does (`OrderPolicy::check_signature`
and `judge`: the operator's signature over the outputs, the credit to the
order's next credit leaf at its price, the remainder under the next salt, the
lot), each taker's pairs, that no asset leaves the fill in more than its inputs
hold, and the coin at its index; a fill coin is one hop deeper than the deepest
coin it spends, and its expiry the earliest of theirs. `ValidCoin::fill_tx`
builds the fill from the record, the order coin's outpoint and the taker's
checkpoints. A fill's binary form is tag 4 of the coin record: the order coin,
the signature, a partial flag, the inputs and outputs as a reassignment's, the
index, and the coin's kind (0 the credit and 1 the remainder, each with its
owner nonce; 2 a taker's leaf, as a reassignment's leaf).

## Offline refresh

A coin of a batch without a sweep never expires, so it needs no plan; a plan
names no batch, and an operator takes none for such a coin.

A holder who will be away past a coin's expiry pre-signs a plan (`plan`):
step `i` gives up the holder's coin `L(i-1)` for a new leaf `L(i)` the
operator puts in a later round, and `L(0)` is the coin the plan starts from.
A forfeit names its round's connector asset and cannot be signed before the
round exists, so each step's forfeit is replaced by a refund: `L(i-1)` and
`L(i)` spent together, each by its collaborative path, into `v(i)` at the
holder's own address `Q(i)` (output 0) and the rest less a margin to the
operator (output 1).

```rust
use arca_covenant::plan::{key_proof_digest, Plan};

plan.check()?;                                       // steps, values, keys, nonces, addresses
let id = plan.id();                                  // L(0)'s owner signs it; each A(i) signs key_proof_digest(&id)
let refund = plan.refund(i).unwrap();
let old = refund.old_message()?;                     // A(i-1)'s half, and S's when it is used
let new = refund.new_message()?;                     // A(i)'s half, and S's
let tx = refund.tx(old_coin, new_coin, &old_pair, &new_pair, &FeeSource::Reserve)?;
```

A half binds what the collaborative message binds: the chain, the leaf's
salt, the coin's asset and amount, and the two outputs; no outpoint, round or
time. Every use of either half creates output 0, so whatever the operator does
with a refund the holder ends holding `v(i)`: the refund cannot be mined
without a coin of `L(i)`'s script beside `L(i-1)`, and a copy of `L(i)` the
operator funds itself pays the holder as the real one does. The halves stay
valid while the coin's script is unspent, so a coin a plan names is given up
in a round for a leaf no plan names before it is paid out of round: with a
half, the operator alone could otherwise void a reassignment of it.

## Building

The crate depends on `elements`, `thiserror` and, for the JSON form, `serde` and
`serde_json`, so a wallet can take it alone. The Sequentia Wallet Kit does, for
wasm as well, with the Rust it pins: the crate builds with the `rust-version`
in its `Cargo.toml` and uses no newer standard-library API.

The crate has one binary, `arca-enclave`, for a restricted asset's policy
server (OpenAMP's `openampd`, which names it with `-arcaenclave`):
`cargo install --path covenant --bin arca-enclave`. It reads one JSON request
on stdin and answers one JSON object on stdout, exit 1 with `{"error": ...}`
for a refusal. `arca-enclave board {"record"}` answers a board record's board
output and leaf scripts, its holder, policy key, clawback key, operator,
chain, salt, value and claw control blocks; `arca-enclave transfer` takes the
chain, the operator, the asset's policy and clawback keys, each input coin's
record with its checkpoint's value, and each new leaf's asset, value, holder,
nonces and exit delay, and answers each input's salt, holder and value with
the two digests its owner and the operator sign (into its checkpoint, and from
it into the outputs) and each new leaf's salt, holder, script and claw control
block. Every input must be an `enclave-1` coin of that operator, chain and
asset resting on a board, and every output an `enclave-1` leaf of theirs. The
policy server signs those digests, after the asset's rules, under the tag
`policy_cosign_digest` names; the operator's signer signs a message of a
restricted asset only beside that signature.

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
  negative case is refused by the block rules with the node's error; so are the
  release, the roll and a sweep of every kind of output built by
  `release_tx`, `roll_tx` and `sweep_tx`. `--nocapture` prints the table.
- `tests/fill.rs`: SeqDEX's fill covenant equals SeqDEX's golden vector
  (`daemon/pkg/covenant/leaf_test.go`); with `SEQOB_COVENANT_EXEC` naming
  SeqDEX's `seqob-covenant` (built from `daemon/cmd/seqob-covenant`), a set of
  orders derives the same scripts and plans the same fills, at `k` beyond 0,
  as that tool does; the relay's JSON form of an order reads back; and on
  round-shaped transactions (covenant inputs first, credits at `2k`, remainders
  at `2k+1`, the batch after them) the node's interpreter and
  `FillOrder::check` agree on every case, each negative refused with the node's
  error; and the id a take of an order is attested by covers every part of
  it, and is the body its documentation spells under its own tag.
  `--nocapture` prints the table.
- `tests/order_refund.rs`: on an anchored regtest chain, an order placed as a
  wallet holding only leaves places one: an offboard output holding the
  order's amount and its unlock margin, unlocked with that margin as the fee
  into the order's address, where the order rests at output 0 holding exactly
  its amount; then its maker's REFUND built by `refund_tx`, forced into a
  block and refused before its time (its lock time at the expiry, and below
  it) and with the operator's signature, and mined at its time.
  `--nocapture` prints the table.
- `tests/checks.rs`: the five client checks accept an honest round and refuse
  each attack that consensus accepts, naming the check; and a round that
  reissues the batch's asset passes check 5 only when every sweep path above
  the leaf is burn-only, while a round funded from coins, or reissuing another
  asset, passes with either sweep.
- `tests/encode.rs`: the encodings round-trip and refuse malformed bytes; the
  witness readers recover what the builders wrote.
- `tests/record.rs`: every leaf record in the regtest suite's record vectors
  (`regtest/vectors/records.json`) decodes from both forms, encodes back to the
  same bytes and the same JSON text, gives the same leaf id and validates
  against the round transaction that funds its batch, under a reserve floor
  of the batch's own reserves (the batch with no reserves is refused under the
  default floor); the refusal vectors are refused for the reason they name;
  every single-field mutation of a valid record, and every one-byte change of
  its binary form, is refused. The wallet's policy refuses each thing it
  bounds: the chain, the operator, the notice, the horizon, the exit delay, the
  depth, a node of one child, the node and entry reserves at a fixed floor and
  at a fee-rate floor; and the receipt policy accepts a held leaf from the day
  after its round until three days before its first expiry, where the
  acceptance horizon refuses it from the second day.
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
- `tests/transactions.rs`: every transaction in the regtest suite's
  off-chain vectors (`regtest/vectors/transactions.json`) is rebuilt here byte
  for byte, witnesses included, and re-signed with the test keys: the board, the
  owner's conversion and the converted leaf's exit, one pair spending the board
  output and the converted leaf alike, the forfeit, the connector output and the operator's issuance of
  the connector asset, the forfeit's claim and refund, the offboard's unlock and
  reclaim, each with the margin as the fee and
  with a fee coin, and the three-hop chain's checkpoints and reassignments; every
  input verifies under the block rules and the mempool's checks. The board record
  decodes from both forms and its refusal vectors are refused; every coin record
  in the chain, and a coin paid out of round from the board, decodes, encodes
  back, validates for its receiver, gives the reference's coin id and carries
  its sender's creator nonce; the coin resting on one leaf that two
  reassignments promised is refused for the salt they share.
- `tests/transfer.rs`: a chain three hops deep, one hop a two-asset swap,
  received from the last receiver's record alone, validated against the two
  rounds, and every transaction that brings it on-chain built from the record
  and verified; each kind of bad record refused (another key or nonce, a changed
  output, swapped pairs, a checkpoint worth more than its coin, a coin spent twice
  in the record, one leaf promised by two reassignments and both spent, a coin
  paid back into the leaf it came from, an authorisation by another key or not
  yet usable, a wrong preimage, a missing round, the horizon, batch leaves of
  another operator, six hops); two coins of one reassignment (a payment and
  the payer's change) spent together, accepted, with that reassignment built
  once to bring the coin on-chain, while a coin spent by two reassignments
  or at both inputs of one is refused; the operator's rule admitting the chain's three
  reassignments and refusing another with the same outputs, with only the first
  of them, or with one more after them, in either order, while admitting the
  same reassignment again and one whose outputs part at output 1; the receipt
  policy accepting the coin until three days before the
  earliest first expiry in its lineage; a coin refused for a leaf up its lineage
  whose exit delay is outside the bounds, too short or too long; the lineage
  listing every leaf and checkpoint the coin descends from, and the coin refused
  when any of them is on-chain; and every one-byte change of the record refused.
- `tests/lineage.rs`: on an anchored regtest chain, what a receiver refuses and
  what accepting it would have cost. A coin through a leaf of a 512-second exit
  delay is refused; its owner alone brings that leaf on-chain and exits it, and
  the checkpoint the receiver would hold is refused in a block. A leaf
  transferred after it reached the chain and its delay passed validates under
  the receipt policy, and the lineage check against the node's unspent outputs
  refuses it; the sender exits at once and the receiver's checkpoint is refused.
  A record of sixteen one-child levels with no reserves, paid by a confirmed
  round, is refused for its depth and its one-child nodes, and a one-leaf batch
  with no reserves for its reserve. A board paid out of round: the receiver
  validates the coin against the board transaction, finds the board unspent and
  brings the coin on-chain from the board output itself; a board converted after
  a payment makes the receipt check refuse the coin, and the receiver holding it
  answers with the checkpoint on the converted leaf.
- `tests/offchain.rs`: on an anchored regtest chain, a board and its refresh
  into a round: the preimage handed over on the forfeit pair alone; the
  conversion signed by the operator, unsigned, one atom short or into another
  script refused, the owner's own conversion confirmed, its exit refused before
  the delay and, once the operator has answered with the forfeit on the
  converted leaf, after it; the connector asset issued, the claim, the new batch
  unrolled from its record, its entry unlocked with the preimage learned from
  the chain, the new leaf exited; a second board never converted, its forfeit
  published straight from the board output and claimed; one atom of the
  connector serving two claims, two forfeits of one participation refused one
  output, and the offboard's unlock, its merge refused, and its reclaim; the round's connector output spent with no issuance, issuing
  two atoms, issuing with a reissuance token, issuing another asset under a
  contract hash, or signed by another key, each refused, and its issuance of
  `M` confirmed; every negative case refused by the mempool and in a block,
  for its reason. Then the three-hop chain on chain: the last receiver validates it from its record and
  the confirmed rounds, brings it on-chain from the record, with fee coins
  wherever the asset is not accepted for fees, and exits; a reassignment's pair
  cannot skip the checkpoint, a checkpoint's pair cannot spend the checkpoint,
  the swap's outputs cannot be paid from one input's value alone (the values do
  not balance; the pairs do not name the other input, so a third party funding
  that side would make it confirm), and the first sender's exit fails once the
  receiver has published the checkpoint.
- `tests/merge.rs`: on an anchored regtest chain, two reassignments merged into
  one transaction. Two senders pay one receive request, each drawing the
  creator nonce of the leaf it creates: the operator admits both, the receiver
  holds two leaves, and the transaction that spends both checkpoints into one
  sender's outputs is refused (`Invalid Schnorr signature`, on the other
  sender's input), by the mempool and in a block; each reassignment confirms on
  its own. A sender that repeats another's creator nonce: the operator's rule
  refuses its plan, for the same outputs and for one set the first outputs of
  the other; the pairs made anyway merge, the leaf is created once and the
  broadcaster takes a sender's whole checkpoint, in both shapes; a receiver
  refuses the coin that rests on the one leaf twice, and after the merge only
  one of its two checkpoints can be made. A sender that rebuilds a leaf the
  receiver has already paid on, with the first sender's creator nonce: the
  record validates, and the receiver's old pairs move the second payment to
  the earlier payee, which is why a wallet refuses a coin at a salt it has
  held.
- `tests/rollback.rs`: on an anchored regtest chain, what each party holds after
  a rollback (`invalidateblock` standing in for an anchor rollback). A round
  broadcast again returns with its txid, the re-check finds the same round, `M`
  is issued and the forfeit claimed: the operator ends with the old coin, the
  owner with the new leaf. A replacement with another txid paying the same batch
  output is a new round to the re-check, and the wallet will not carry its
  forfeit over; `M` of the old round cannot be issued and the new round's does
  not satisfy the claim, so the owner ends with the old coin and the new leaf.
  A round whose third party's input is spent elsewhere cannot return; the new
  round has a new tree and new unlock hashes: with the new forfeit published
  first, the old forfeit has no coin left and the operator claims; with the
  preimage released to an owner holding the old forfeit whole (one the
  operator published), the owner publishes it, refunds it and keeps the new
  leaf, which is why such a coin is never taken into a re-run.
  A forfeit disconnected late in its refund delay restarts it. A receiver's
  checkpoint disconnected while the replacing chain runs past the sender's exit
  delay: the leaf's delay does not restart, and a producer mines the sender's
  exit. A board's forfeit seen in one block and disconnected: the owner has no
  exit from the board itself, its conversion starts the leaf's delay, and the
  same pair's forfeit takes the converted leaf.
- `tests/plan_refund.rs`: on an anchored regtest chain, offline refresh's
  refund, every pair made from the plan alone before any step's round
  existed: the operator unrolls a step's new leaf with its own unroll
  authorisations, opens its entry with the plan's preimage and spends the
  coin given up and the new leaf together, the margin or an outside fee coin
  paying, output 0 paying the holder; thirteen negative cases (an output
  changed, swapped or one atom off, the halves of two steps mixed, a half made
  for another salt, chain or amount, the operator's signature in both slots, a
  slot left empty) each refused by the mempool and in a block; a step whose
  round is replaced leaves the refund unminable and the coin given up the
  holder's, and the step run again under the same leaf makes it good; and the
  spends consensus accepts with either half alone, or with a copy of the new
  leaf the operator funds, each pay the holder output 0.
- `tests/no_sweep.rs`: on an anchored regtest chain, a batch without a sweep:
  its records (format version 3) and the wallet policy that refuses a batch
  with a sweep; a refresh into another such batch whose forfeits and releases
  are signed against the built round before it is broadcast; the operator's
  recovery by unrolling with its own authorisation, RECLAIM-D, a forfeit's
  claim and a dormant owner's entry opened into its own leaf, which only that
  owner takes home; and each removed sweep (batch output, lowest nodes, an
  entry, a checkpoint) refused in a block with `Witness program hash mismatch`.
- `tests/accumulator_release.rs`: on an anchored regtest chain, an
  accumulator batch without a sweep (`arca/accumulator-2`): its records
  (format version 4) and the wallet policy that takes them and refuses
  `arca/accumulator-1`; owners refreshing into a round that is rolled back and
  replaced, and into another; releases of one slot and of 14 slots of two
  rounds, each paying the operator exactly what the slots weighed, exits by an
  owner and by the operator between them, and the release of the last nine,
  which leaves no rest; every spend read back by `follow`. Refused in a block:
  a release signed by a stranger, by another slot's owner and by the operator
  for the owner, an owner's release under another batch's root, a release for
  the rolled-back round with its atom and with the replacement's, a slot twice
  and slots out of order, a slot already released, 15 slots (the program has
  14 places: `Trailing bytes after final byte of witness`), the rest under another
  root, another operator key or with the slot's bit clear, the operator taking
  one atom more, the operator's signature missing or over another payout, an
  annex, and the removed sweep leaf with a real token at `R` beside it (by its
  twin's control block and as a lone leaf, while the same leaf, token and
  signature sweep the twin that has it).
- `tests/reclaim.rs`: on an anchored regtest chain, the reclaim of a lowest
  node whose owners refreshed into new rounds, each release built with
  `Release::for_refresh`. The reclaim with an atom of `M` confirms; without it,
  with another round's `M`, with another asset, with the batch asset or the
  node itself at the index, with three releases of four, with releases over the
  message that named no round, with a release by another key and with the
  operator's signature by another key, it is refused. Owners of two rounds are
  reclaimed with one atom of each, and refused when an index names the wrong
  round or one round's atom is missing; one atom of `M` serves a forfeit's
  claim and two reclaims. The owners' round disconnected and replaced by another
  with a new txid: its `M` can no longer be issued, the reclaim with the
  releases is refused with the replacement's `M` and with none, and an owner
  takes its old leaf alone. A reclaim already confirmed goes with its round: the
  round's block disconnected and the round replaced, the reclaim cannot return,
  the node is unspent again and an owner exits its old leaf. A release for an
  offboard (`Release::for_offboard`) names the round that pays the offboard,
  refuses another operator's offboard, a round that does not pay it and an
  output that is not the connector, and the one-owner node is reclaimed with
  that round's `M` and not another's. Every negative case is refused by the
  mempool and in a block, for its reason. RECLAIM-D on a batch built with it:
  owner 0's coin paid twice with change, owner 1's kept, owners 2 and 3
  swapped, each sender's delegation from `Delegation::for_reassignment` (which
  refuses its outputs' leaves out of order or short), the six holders
  refreshed into one round and their releases from `Release::for_holder`
  (which refuses another round); the node reclaimed with one atom of `M`, and
  refused with a delegation signed by another key, with a stranger in a
  successor's place, with a release naming a round not in the chain, without
  an atom, with one owner's tree in two slots, with three trees for four
  owners, with a successor missing, and through the compact RECLAIM. A
  release by a key that has delegated is accepted by `testmempoolaccept`: the
  chain cannot tell it from its holder's, and the operator refuses it.
- `tests/reclaim_d_vectors.rs`: RECLAIM-D against `regtest/vectors/reclaim_d.json`
  (the leaf, its step, the node's scriptPubKey and control blocks, the
  release and delegation prefixes, messages and signatures, and the items
  below the leaf for a coin paid twice, a swap and a direct release), byte for
  byte.
- `tests/issuer.rs`: what a transaction issues and burns of an asset (a bare
  `OP_RETURN` alone counts as a burn), and a fee coin that burns the margin
  its inputs leave while its own change goes back.
- `tests/limiter.rs`: the mint limiter's coin rebuilt for each of the
  template's eight address vectors, an instance file read as the limiter's
  tool writes it, the program's rule for the state a mint leads to, and the
  following of a mint, the brake, its release and the recovery.
- `tests/landing.rs`: on an anchored regtest chain, a supervised asset issued
  under the supervision descriptor with the pause capability, and `landing-1`
  leaves of it. The collaborative path signed over the plain constant, and
  over another landing's, and the landing before its delay, to another key's
  P2WPKH, to a taproot output, in another asset and one atom below the value
  less the allowance: each refused by the mempool and in a block, for its
  reason. Under a pause, with the leaf's own script named in a freeze, the
  landing confirms (`isassetfrozen` says frozen for that tree script, whose
  script-path spends no freeze reaches); the landed coin is refused under the
  pause and under a freeze of its address (`bad-txns-asset-frozen`) and spent
  once that is lifted. A round of the asset with a blinded output is refused in
  a block (`bad-txns-supervised-blinded`) beside the same round all explicit,
  whose `landing-1` leaves' records validate against it, and the same blinding
  in a round of an open asset confirms.
- `tests/vtxo2.rs`: on an anchored regtest chain with Simplicity, `vtxo-2`.
  Each attack a `vtxo-1` pair allows is run against a `vtxo-1` leaf, where it
  is mined, and against a `vtxo-2` leaf, where the mempool and a block refuse
  it: one pair spending two coins of one script in one transaction, the second
  to the broadcaster; two pairs over one output, each made for a coin alone,
  both leaves in one transaction; a swap leg spent with a third party's coin in
  place of the other leg (and beside the other leg's script one atom larger);
  a blinding key put on a committed output; an annex on a co-signed spend
  (relay refuses it on `vtxo-1`, a block takes it). Beside them the swap with both
  legs, and what `vtxo-2` still allows (a coin funded twice spent alone, into
  the same outputs, a second time); the operator alone, the signatures
  swapped, a pair under another salt and a `vtxo-1` pair under the same `K`,
  refused; the exit before its delay refused and after it mined; and the bond
  burned with a `vtxo-2` co-signature read from the chain beside a second one
  under its salt, and not on one digest signed twice. Then a round of
  `vtxo-2` and `vtxo-1` leaves in one batch: a `vtxo-2` coin paid out of round
  into a `vtxo-2` leaf through its checkpoint and reassignment; a swap of a
  `vtxo-2` coin and a `vtxo-1` coin in one reassignment, its `vtxo-2` leg
  refused with a stranger's coin in place of the other; a `vtxo-2` coin and a
  `vtxo-1` coin each refreshed into a `vtxo-2` leaf (the forfeits, the
  connector's issuance, the claims, the new leaves brought with the published
  preimages); every `vtxo-2` leaf exited.
- `tests/collab_vectors.rs`: the `vtxo-2` leaf and checkpoint, their spends'
  signed bytes, digests, signatures and Simplicity witnesses, against
  `regtest/vectors/collab2.json`.
- `tests/enclave.rs`: the enclave built byte for byte as openampd's golden
  vectors (`tests/openamp_enclave_vectors.json`, with and without clawback);
  the board record format 4, its JSON and the policy encoding round-trip; and,
  on an anchored regtest chain, an `enclave-1` board of a restricted asset.
  The collaborative path signed over the plain constant and over another
  holder's `K ‖ D`; the exit before its delay, to another holder's enclave, to
  a script that is no enclave, one atom short, in another asset, and signed by
  the holder's registered key in place of its leaf key; the landed enclave
  coin spent without the policy key; the clawback without the policy key; and
  the clawback of a board and of a leaf of an asset that elected none
  (`Witness program hash mismatch`): each refused by the mempool and in a
  block, for its reason. Beside them confirm the collaborative spend into
  another holder's leaf, its exit into that holder's enclave, the landed coin
  spent by its enclave's own transfer leaf, two conversions and a clawback of
  a board and of a leaf into the issuer's enclave.
- `tests/enclave_tool.rs`: `arca-enclave`, the tool a restricted asset's
  policy server runs, answers the board's scripts and terms, and for a
  transfer of a board coin, and of a coin two hops from it, the very digests
  `TransferPlan` builds; it refuses another operator, another policy key, a
  missing clawback key, a `vtxo-1` board or coin, and an unknown command.
- `tests/claim.rs`: on an anchored regtest chain, a batch of four claim
  leaves, each owned by the claim key of an address key (two of each parity)
  and its nonce. Each record validates for its claim key and not for the named
  key. The unroll authorised by the named key standing in for the claim key,
  by the named key as a member and by the payer's key; the exit signed by the
  named key and by the payer's key; and the collaborative path signed by the
  named key and by the payer's key, each with the operator's signature: every
  one refused by the mempool and in a block, for its reason. The same
  transactions signed by the claim key confirm. Then a batch without a sweep
  of three `claim-1` leaves: each record is format 3 and reads back from both
  forms, validates for its claim key under the no-sweep policy, and its coin
  record names its lapse. Before the deadline the lapse is refused
  (`non-final`) and the holder's exit confirms; after it the lapse to another
  script (`Script failed an OP_EQUALVERIFY operation`) and one atom short of
  the value less the allowance (`Script evaluated without error but finished
  with a false/empty top stack element`) are refused, and the lapse
  `lapse_tx` builds, its fee from the allowance, confirms; a leaf brought on
  the chain after the deadline is refused its lapse at once
  (`non-BIP68-final`), and lapses with a fee coin once its exit delay has
  run, the whole value to the return script.
- `tests/vest.rs`: on an anchored regtest chain, a batch without a sweep of
  six `vest-1` leaves under claim keys. The builder refuses `vest-1` beside
  `claim-1` or `vtxo-1`, two vest times, a batch with a sweep and a vest time
  at the deadline; each record is format 3, template id 9, reads back from
  both forms and validates, and a record naming another vest time does not
  match the round. Before `V`, with the leaf on the chain past its exit
  delay, the exit, the collaborative spend signed by owner and operator, and
  the RECLAIM of the other lowest node with every owner's release are each
  refused `non-final` (in a block `bad-txns-nonfinal`) and, with lock time 0,
  `Locktime requirement not satisfied`. After `V` a pair over `vtxo-1`'s
  message is refused (`Invalid Schnorr signature`); the exit, a collaborative
  spend and the RECLAIM confirm; an unclaimed leaf's lapse is refused until
  `D` and then confirms. A second test pays a hundred holders from one batch
  output and takes one leaf out alone after `V`.
- `tests/regtest.rs`: on an anchored regtest chain, the checkpoint and
  reassignment chain, the forfeit and the entry it releases, `htlc-1`, the swap of
  two leaves in two assets, the entry's sweep behind the token and the notice, and
  the burn-only sweep, each clock move and sweep built by `release_tx`, `roll_tx`
  and `sweep_tx`; an issuer-operated batch: an asset issued with an explicit
  reissuance token, a round that reissues exactly its burn-only batch's value
  (every leaf's record validates), the same round funding a batch whose sweep
  pays the operator (the chain takes it; every leaf's record is refused by
  check 5), and that batch's sweep refused in a block before its notice, paying
  a script instead of the burn, one atom short, in another asset and at
  another index, beside the burn the operator makes after the notice; the
  asset's supply, read from every block, back at its level less what the open
  batch still holds; and a 17-leaf and a 64-leaf batch built by the tree
  builder, every record checked against the confirmed round and three leaves in
  different subtrees unrolled from their records, unlocked and exited: every
  spend confirms, and every negative case is refused by the mempool and again
  when forced into a block with `generateblock`, the block for the same reason
  (the node runs with `-par=1`, so a block refused by a script names the
  failure, under the consensus label `mandatory-script-verify-flag-failed`). It also funds the review's attacks, turned around: a batch whose
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
