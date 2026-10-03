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

## Testing

The tests run against a real PostgreSQL server. `ARCA_TEST_POSTGRES` names it,
with a database to connect to for administration; each test creates a database
of its own there, builds the schema in it and drops it at the end.

    ARCA_TEST_POSTGRES=postgres://user@127.0.0.1:5432/postgres cargo test -p arca-server

The user needs the right to create databases. A throwaway server in user
space is enough:

    initdb -D /tmp/arca-pg -U arca --auth=trust
    pg_ctl -D /tmp/arca-pg -o "-p 55432 -k /tmp" start
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres cargo test -p arca-server
