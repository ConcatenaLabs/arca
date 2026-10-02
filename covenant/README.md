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
- `tests/regtest.rs`: on an anchored regtest chain, the checkpoint and
  reassignment chain, the forfeit and the entry it releases, `htlc-1`, the swap of
  two leaves in two assets, the entry's sweep behind the token and the notice, and
  the burn-only sweep: every spend confirms, and every negative case is refused by
  the mempool and again when forced into a block with `generateblock`.

The decoders and readers are fuzz targets in [fuzz/](../fuzz/README.md).

## Relay policy to plan around

Two OP_RETURN outputs in one transaction are not standard (`multi-op-return`),
so a burn-only sweep relays one node per transaction, and each one waits `W` at
`R` for the token. A block producer can still mine several in one. A witness item
that is not minimally encoded (the sweep's `k`, say) is refused by the mempool and
accepted in a block; it changes the witness, not what the spend does.
