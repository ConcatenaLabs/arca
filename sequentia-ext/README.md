# arca-sequentia-ext

Sequentia chain types and a JSON-RPC client for `sequentiad`.

## Chain types

Sequentia encodes transactions and blocks as Elements does, with two
differences: an asset issuance carries a denomination byte after its inflation
keys, and every block header carries the Bitcoin block it is anchored to (height
and hash, after the block height). The types come from the `rust-elements` that
[SWK](https://github.com/ConcatenaLabs/SWK) vendors with its `sequentia` feature,
which encodes both. The workspace depends on it once, in the root `Cargo.toml`,
pinned by commit; this crate re-exports it as `sequentia_ext::elements` along with
the types the protocol uses (`Transaction`, `TxOut`, `AssetId`, `Block`,
`BlockHeader`, `AssetIssuance`, ...).

Because the feature changes the header encoding, a header without an anchor (an
upstream Elements chain, or a custom chain started without
`-con_bitcoin_anchor=1`) does not decode with these types.

On top of them:

- `AssetAmount`: an amount that always names its asset. Sequentia has no
  privileged asset outside staking, so a bare number of atoms is never enough.
- `explicit_txout`, `fee_txout` and `TxOutExt`: transparent outputs, the default
  on Sequentia, and their asset and value.
- `BlockHeaderExt::bitcoin_anchor`: the header's anchor as a `BitcoinAnchor`.

## Node client

`rpc::Client` is a blocking JSON-RPC client. Blocks, headers and transactions
come back as their raw serialisation and are decoded here, so what the client
returns is byte for byte what the node holds. Typed calls cover the chain
(`blockchain_info`, `block_count`, `block_hash`, `genesis_hash`, `block`,
`block_bytes`, `block_header`), transactions (`raw_transaction`,
`raw_transaction_bytes`, `confirmations`, `send_raw_transaction`,
`test_mempool_accept`), the fee whitelist (`fee_exchange_rates`, keyed by asset id
with the node's labels resolved) and regtest mining (`generate_to_descriptor`,
`generate_block`). Anything else goes through `Client::call`.

The fee whitelist is the node's own and changes over time: an asset in it now may
be gone tomorrow, and another node may list different assets.

## Regtest harness

With the `regtest` feature, `regtest::Regtest::start` runs a throwaway anchored
chain from one `sequentiad` binary: a Bitcoin-mode regtest node as the parent,
and a Sequentia custom chain (`elementsregtest`) whose headers carry anchors from
it, as every live Sequentia chain does. The genesis block pays the initial free
coins to a bare `OP_TRUE` output, and Simplicity is active from genesis. Both
nodes stop, and their data is deleted, when the value is dropped.
`Regtest::from_env` takes the binary from `SEQUENTIAD_EXEC`.

`Regtest::start_pos` (or `pos_from_env`) runs the same chain under proof of
stake, as the live chains run: a committee of three test stakers certifies
every block, `produce_block` builds one from the mempool, and the node takes
its anchor from the parent's tip as soon as it sees it. Such a chain takes no
block from `generateblock`, so everything reaches a block through the mempool;
the node runs with `-acceptnonstdtxn` so the genesis block's free coins, at a
bare `OP_TRUE`, can be spent. `mine_parent` mines parent blocks and
`anchor_to_parent_tip` produces blocks until the tip is anchored to the
parent's tip, which is how a test buries an anchor. `Daemon::restart` stops a
node and starts it again on its data; with `-persistmempool=0` it comes back
with an empty mempool.

## Testing

    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-sequentia-ext

`tests/regtest.rs` runs against the regtest harness. `regtest_pos_chain`
checks the proof-of-stake chain: certified blocks, an anchor following the
parent, the free coins spent through the mempool, and a restart that empties
the mempool and keeps the chain. `regtest_node_client` reads the chain's
genesis hash and fee whitelist, has the node build a transaction with an asset
issuance of denomination 2 (`createrawtransaction`, `rawissueasset`), decodes it
and re-encodes it byte for byte, signs and broadcasts it, and decodes the block
that mines it, again byte for byte, with its Bitcoin anchor checked against the
parent chain.
