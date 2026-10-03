# arca-server

The Arca operator's server on Sequentia. It holds the operator's side of Arca:
the durable state of every leaf, board and transfer the operator has taken part
in, kept in PostgreSQL.

The scripts, records and their validation come from
[`arca-covenant`](../covenant/README.md); the server uses them and builds no
script of its own.

## State

The server keeps everything in one PostgreSQL database, whose schema is
[`schema/V1__arca.sql`](schema/V1__arca.sql). `Store::connect` builds it from
nothing on an empty database and brings an older one up to date: the schema is
a list of numbered migrations, applied in order, each once, under a lock.

What the database holds, and the rules it enforces itself so that no two
requests can race past them:

- **Leaves, keyed by leaf id.** Every coin the server knows (a board, a leaf
  of a batch, an output of a transfer) is a row keyed by its leaf id, never by
  an outpoint, with its coin record, from which its lineage and every
  transaction that brings it on-chain follow. A key owns one leaf.
- **Arca scripts.** Every leaf, board and checkpoint script the server has
  created or co-signed into appears once: a leaf script is never funded twice,
  across batches, boards and transfers alike.
- **Operator nonces.** The operator's half of every leaf's salt is 32 random
  bytes, recorded as issued before it is handed out and taken by one leaf at
  most. A nonce that was never issued, or was already taken, is refused.
- **Transfers.** A leaf is the input of one transfer at most, recorded before
  any signature leaves the server.
- **The chain as the server saw it**, rounds and their connector outputs,
  participations and forfeits, mailboxes, authentication challenges, the
  on-chain wallet's coins and the server's own transactions.

Back up the database: it holds what the chain does not, such as which leaves
were spent off-chain and the records receivers collect from their mailboxes.

## Finality

The server never counts confirmations. One component, the finality service
(`chain::finality`), follows the node's active chain block by block into the
database and gives the one answer to "is this final" for any transaction
something in the server relies on:

| State | Meaning |
|---|---|
| not in the chain | not in a block of the active chain (perhaps in the mempool) |
| unsettled | in a block the committee has not certified |
| settled | in a certified block, its anchor buried fewer Bitcoin blocks than the rule |
| final | certified, and its anchor buried `anchor_depth` Bitcoin blocks (2) |

A block counts as certified when the node reports the committee's certificate
for it or for any block above it. The anchor's burial is the anchor height of
the tip less the anchor height of the block, as SeqLN counts it, so many
Sequentia blocks on one Bitcoin block bury nothing. Nothing becomes final
while the node reports its tip's anchor as anything but `ok`.

Sequentia reorganises whenever its Bitcoin anchor does, with no depth limit,
so the service disconnects, tip first, every block the node no longer holds,
however deep and whether or not it was final, and publishes each change: a
disconnection names every watched transaction the block held, so whatever
relied on one is checked again. A rollback that happens while the server is
stopped is found on its first pass. The service also records, for good, every
output it sees paying an Arca script the server knows and every spend of an
outpoint it watches, in blocks and in the mempool.

The node must run with `-txindex` and `-validateanchor`. The service refuses a
node that does not validate its anchors, since that node has no notion of
finality, and refuses to leave certification out on a chain whose node reports
certificates.

## Testing

The tests run against a real PostgreSQL server. `ARCA_TEST_POSTGRES` names it,
with a database to connect to for administration; each test creates a database
of its own there, builds the schema in it and drops it at the end. The tests
that need a chain run `sequentiad` (named by `SEQUENTIAD_EXEC`) on an anchored
proof-of-stake regtest chain (`sequentia_ext::regtest::Regtest::start_pos`),
where a committee certifies every block; the cases a live chain will not
produce on demand (a block without its certificate, a certificate arriving
late, a stale anchor, a rollback below where the service started) run against
a chain held in memory.

    ARCA_TEST_POSTGRES=postgres://user@127.0.0.1:5432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-server

The user needs the right to create databases. A throwaway server in user
space is enough:

    initdb -D /tmp/arca-pg -U arca --auth=trust
    pg_ctl -D /tmp/arca-pg -o "-p 55432 -k /tmp" start
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres cargo test -p arca-server
