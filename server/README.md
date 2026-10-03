# arca-server

The Arca operator's server on Sequentia. It holds the operator's side of Arca:
it hands out the operator's half of every leaf's salt, registers boards and
credits them once final, co-signs out-of-round transfers and delivers them to
their receivers' mailboxes, re-serves a key's leaves, and keeps its own
on-chain wallet and the transactions it relies on broadcast. Its state is in
PostgreSQL; what is final comes from one finality service; the operator key
lives in a separate signer process. Wallets speak JSON over HTTP to `arcad`.

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

## Published parameters

The operator publishes its chain (the genesis hash), its key `S`, the bounds on
every leaf's exit delay (36 to 48 hours by default), the assets it serves with
the smallest leaf it takes in each, and the depth limit (5 reassignments from
a round or a board). Every record and coin the server checks is checked under
these, with the receipt horizon a receiver uses: a coin's first expiry past
the exit deadline.

## Boards

An owner brings its own coins in with a board (`board-1`). It asks the server
for an operator nonce, builds its board record with it (its key, a nonce of
its own, the exit delay, asset and value), pays its coins to the board output,
and registers the record with the board transaction. The server refuses a
record for another chain or another operator key, an exit delay out of
bounds, an asset it does not serve, a value below its smallest leaf, a
transaction that does not pay the board output exactly once, a nonce it never
issued or already gave a leaf, a key that already owns a leaf, a script it
already knows, and another transaction for a board already registered. A
refused board leaves nothing behind.

A registered board goes into the nursery and is credited, its leaf becoming
the owner's to spend off-chain, only once the finality service calls its
transaction final. A rollback that takes a credited board out uncredits it at
once; the nursery broadcasts the same transaction again and the board is
credited again when final again. A board whose transaction can no longer
confirm is lost.

## Out-of-round transfers

A sender gives up coins the server knows, by leaf id, each with the value its
checkpoint keeps and its owner's signatures over the checkpoint and the
reassignment, for one to four new leaves, each named by its receiver's key and
nonce, an operator nonce from the server, an exit delay, an asset and a value.
The server co-signs only when every rule holds:

- each input is live (a board once credited) and spent by nothing else: a
  second spend of a leaf is refused, which is the whole of the double-spend
  protection before a round;
- nothing of the coin's lineage, its own leaf included, has been seen paid on
  the chain, in a block or in the mempool, and every board it rests on is
  credited and unspent: an Arca leaf on the chain past its exit delay can be
  exited by its owner at once, so the server co-signs no off-chain spend of
  it, a converted board included;
- the new coins are at most five reassignments from a round or a board;
- each new leaf is within the published bounds: an asset served, a value
  within its bounds, an exit delay within the bounds, an operator nonce the
  server issued and never gave another leaf, a key that owns no other leaf, a
  script never seen;
- every checkpoint keeps between one atom and the whole coin, the outputs take
  no more of any asset than the checkpoints keep, and each owner signature
  verifies.

The transfer is then recorded, inputs spent, before the operator key signs
anything, so the server never signs a spend it has not durably recorded and
two spends racing for one leaf leave exactly one standing. Each new coin's
record is checked by the server as a receiver would check it, stored, and
posted to the receiver's mailbox (the leaf's key, unless the output names
another). A request repeated byte for byte gets the same answer; one that
found the signer unreachable completes when repeated. Transfers are free.

The same record of spends answers the round's question, before it accepts an
owner's release of a leaf's lowest node, whether the leaf has an open
out-of-round reassignment (`Cosigner::check_release`).

## The interface

JSON over HTTP, every call under `/v1/`, so the server sits behind one
same-origin path of a reverse proxy that terminates TLS. Every request body is
bounded (64 KiB by default) before it is read: a larger one is refused with
413, whatever it holds. Every refusal is
`{"error": {"code": …, "message": …}}` with a stable code. Amounts are decimal
strings, asset ids and the genesis hash in display order, keys, nonces,
signatures, leaf ids and records lower-case hex; records travel in their
canonical binary form. Every object refuses a field it does not know.

| Call | Does |
|---|---|
| `GET info` | The operator key, genesis hash, assets served with their smallest leaf, exit-delay bounds, depth limit, the finality rule, the template list and its version, the fee schedule, the request limit |
| `POST operator_nonce` | A fresh operator nonce for one new leaf |
| `POST challenge` | A challenge to authenticate with, good once, for a short while |
| `POST register_board` | Registers a board record with its transaction |
| `POST board_status` | A board's state (`pending`, `credited`, `lost`) and its transaction's finality |
| `POST cosign_transfer` | Co-signs an out-of-round transfer and delivers its coins |
| `POST mailbox_read` | The coin records in a key's mailbox after a cursor |
| `POST leaf_data` | The leaves a key owns, with their records |

`mailbox_read` and `leaf_data` need a proof of the key: a challenge from
`challenge`, signed with BIP340 over the tagged hash
`SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key)` with
`T = SHA256("Arca/auth")`. The tag keeps it apart from everything else a leaf
key signs, the genesis hash to one chain, the call to one request, the
challenge to one use. There is no bearer token. `cosign_transfer` is
authenticated by the owners' signatures over the transfer itself.

## The signer

The operator key `S` lives in `arca-signer`, a process of its own; the server
never holds it. It loads the key from a file only its owner can read (it
refuses one others can), listens on a Unix socket of mode 0600, and answers two
requests: its public key, and `S`'s signature over the rebindable message of a
collaborative path, which it builds itself from the parts (the salt, the coin's
asset and value, one to four committed outputs) on its own chain. It signs no
digest it is handed, no transaction, no unroll authorisation and no release.
The server checks each signature it gets back against the message it built.

## Running

    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --socket /run/arca/signer.sock
    arcad /etc/arca/arcad.toml

[`arcad.example.toml`](arcad.example.toml) lists every setting: the listen
address, the database, the signer's socket, the wallet's mnemonic file, the
node's RPC, the finality rule, the exit-delay bounds, and the assets served
with their smallest leaf. The node must run with `-txindex` and
`-validateanchor`.

## The on-chain wallet

The operator's wallet is built on the Sequentia Wallet Kit: its keys come from
a BIP39 mnemonic through the kit's software signer, at
`m/84'/1'/0'/<chain>/<index>` (chain 0 for scripts handed out to be paid,
chain 1 for change), each an unblinded P2WPKH script, and the kit's PSET
signer signs every input.

- **Coins per asset, explicit only.** The wallet finds its coins as the
  finality service connects blocks: each explicit output paying one of its
  scripts is a coin of that asset. An output paying it that hides its asset or
  value, or carries a nonce, is refused and recorded as refused: the server is
  transparent at its boundary. A coin whose block is disconnected is out of
  the chain until its transaction returns.
- **Final coins only**, by default: the wallet spends a coin once the finality
  service says its transaction is final.
- **A named fee asset, no fallback.** Every transaction is built by hand and
  names its fee asset. The fee is in that asset's own atoms, priced from the
  node's relay floor and the node's exchange rate for the asset at the moment
  of building, times a configured multiple. An asset the node does not accept
  for fees now is refused, and so is one the wallet holds too little of; the
  wallet never pays in another asset instead, and assumes none, the policy
  asset included. A wallet holding no policy asset at all builds and pays in
  whatever accepted asset it holds.
- **Round-shaped transactions** carry the round's connector output, whose only
  spend is the issuance of the round's connector asset
  (`arca_covenant::ConnectorPolicy`), right after the outputs they pay, then
  change per asset, then the one fee output.

## The nursery

The nursery keeps every transaction the server relies on broadcast until the
finality service calls it final: the server's own (a round, a wallet
transaction, each with its fee asset named) and those it relies on without
having built them (a board). A transaction enters byte for byte and is only
ever broadcast again as those bytes: the nursery never builds a replacement,
so a round returns with its txid and every forfeit signed for it still holds,
and a board returns as its owner signed it.

When a rollback disconnects a block holding one of them, final or not, it goes
back to pending and is broadcast again at once, oldest first, so a parent
precedes its child. On each pass a transaction the finality service calls
final is marked final (and stays watched, since a rollback can take it out
again), one not in the chain is broadcast again, and one whose input a final
transaction of another txid has spent is marked lost, freeing the wallet coins
it held: it can no longer confirm, and what depends on it learns so.

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
