# arca-server

The Arca operator's server on Sequentia. It holds the operator's side of Arca:
it hands out the second nonce of the salt of every leaf it creates, registers
boards and credits them once final, co-signs out-of-round transfers and delivers them to
their receivers' mailboxes, takes participations in rounds, re-serves a key's
leaves, keeps its own on-chain wallet and the transactions it relies on
broadcast, and watches the chain to act for the operator there: it answers a
stale exit, claims forfeits, releases and sweeps expired batches, reclaims
emptied nodes and settles offboards. Its state is in
PostgreSQL; what is final comes from one finality service; the operator key
lives in a separate signer process. Wallets speak JSON over HTTP to `arcad`.

The scripts, records and their validation come from
[`arca-covenant`](../covenant/README.md); the server uses them and builds no
script of its own.

## State

The server keeps everything in one PostgreSQL database, whose schema is
[`schema/V1__arca.sql`](schema/V1__arca.sql) and the migrations after it
([`schema/V2__watcher.sql`](schema/V2__watcher.sql),
[`schema/V3__operator_scripts.sql`](schema/V3__operator_scripts.sql),
[`schema/V4__participation_waiting.sql`](schema/V4__participation_waiting.sql),
[`schema/V5__leaf_salt.sql`](schema/V5__leaf_salt.sql),
[`schema/V6__signer_head.sql`](schema/V6__signer_head.sql),
[`schema/V7__signer_messages.sql`](schema/V7__signer_messages.sql),
[`schema/V8__stateless_challenges.sql`](schema/V8__stateless_challenges.sql),
[`schema/V9__wanted_keys_freed.sql`](schema/V9__wanted_keys_freed.sql),
[`schema/V10__round_signer_head.sql`](schema/V10__round_signer_head.sql),
[`schema/V11__signed_record_heads.sql`](schema/V11__signed_record_heads.sql),
[`schema/V12__challenge_key.sql`](schema/V12__challenge_key.sql),
[`schema/V13__reruns_are_ordinary.sql`](schema/V13__reruns_are_ordinary.sql),
[`schema/V14__keeper_acks.sql`](schema/V14__keeper_acks.sql),
[`schema/V15__rerun_ties.sql`](schema/V15__rerun_ties.sql)). `Store::connect` builds it
from nothing on an empty database and brings an older one up to date: the
migrations are applied in order, each once, under a lock.

What the database holds, and the rules it enforces itself so that no two
requests can race past them:

- **Leaves, keyed by leaf id.** Every coin the server knows (a board, a leaf
  of a batch, an output of a transfer) is a row keyed by its leaf id, never by
  an outpoint, with its coin record, from which its lineage and every
  transaction that brings it on-chain follow. A key owns one leaf; a leaf of
  a participation that expired, never credited, owns none.
- **Arca scripts.** Every leaf, board and checkpoint script the server has
  created or co-signed into appears once: a leaf script is never funded twice,
  across batches, boards and transfers alike. The operator's connector script,
  which every round pays, is recorded beside them, so the chain is watched for
  it.
- **Operator nonces.** A leaf's salt is built from two nonces, its owner's and
  its creator's. For a leaf the operator creates (a board, a leaf of a round)
  the creator's is the operator's: 32 random bytes, recorded as issued before
  it is handed out and taken by one leaf at most. A nonce that was never
  issued, or was already taken, is refused. A leaf a reassignment creates
  takes its sender's creator nonce instead.
- **Salts.** A leaf's salt is unique on a server. Every salt the server has
  seen is kept for good: on a board, a leaf of a batch or an output of a
  transfer, or promised to a leaf a participation wants (one for each
  attempt, from the operator nonce drawn for it). A board or a transfer
  whose new leaf would take a salt the server has seen is refused (`salt`),
  and a participation's leaf is promised a salt no other leaf has. A
  transfer's sender chooses both nonces of its new leaves' salts, and the
  public tree shows every batch leaf's, so without this a holder could name
  another holder's salt for a leaf of its own.
- **Transfers and participations.** A leaf is given up as the input of one
  transfer, recorded before any signature leaves the server, or of one
  participation at a time, recorded when it is accepted. A participation that
  never runs, or whose forfeits never come, gives back each coin for which no
  forfeit was signed; that coin can then be given up again.
- **Reassignments.** Every reassignment the server co-signed, kept by the hash
  of its output 0's record with its inputs and outputs: the merge rule below
  reads them, so it survives a restart.
- **Rounds**, each kept whole with its batches, every leaf the tree builder
  took for each, its offboard outputs and its connector output: what the
  server publishes and what it broadcasts again after a rollback.
- **The chain as the server saw it**, participations and forfeits,
  mailboxes, the on-chain wallet's coins and the
  server's own transactions.
- **Every node and entry of every batch**, by script, so the outputs a holder
  unrolls are seen, and **everything the watcher published**, with what it
  acts for and the outpoints it spends.

### Keeping the database

The database holds what the chain does not: which leaves were spent off-chain,
the rounds the server built with their preimages, the records receivers
collect from their mailboxes. It must never lose a commit, and never go back
to an older state:

- Run PostgreSQL with its durability settings on (`fsync`,
  `synchronous_commit` and `full_page_writes`, the defaults), and keep every
  commit off the machine as it happens: a synchronous standby
  (`synchronous_standby_names`, with `synchronous_commit = on` or
  `remote_apply`), or continuous WAL archiving (`archive_mode`,
  `archive_command`) with base backups. A nightly dump alone loses whatever
  came after it.
- A restore is to the latest commit: promote the standby, or recover the base
  backup with every archived WAL segment to the end. Never restore to an
  earlier point, and never start the server on a copy taken earlier.
- The signer's record (`arca-signer --record`) is never restored with the
  database or from any older copy; it lives on its own durable storage (one
  that loses no write, such as a mirror) and only grows. It is what keeps `S`
  from co-signing a second spend of a coin whatever the database says, so a
  database that has lost a transfer gets a refusal (`double_spend`) where it
  would co-sign the second spend. A record lost or rolled back would open
  that hole again, so the signer notices both: it does not start where its
  record is missing, and the database remembers the latest entry it was
  given, so a record cut back or replaced by an older copy signs nothing
  (`record_behind`) and the server does not start against it. A record that
  is lost cannot be replaced by a new one: the operator stops co-signing.
- A record and a database rolled back together (a snapshot of the whole
  machine restored) pass every check the server makes of itself, so the
  record is held outside the machine: by keepers on other machines, which
  hold every head before the signer answers it and which the signer asks
  before it signs anything after a start ([The keepers](#the-keepers)), and
  by the wallets that witness it; a proven rollback stops the signer
  ([The signed head, witnessed](#the-signed-head-witnessed)). Keep each
  keeper's heads file off the signer's machine and out of its snapshots.
- The server records every message it asks the signer to sign before it
  asks, in the same transaction as what the signature is for (a transfer,
  a forfeit), and refuses to start on a database that does not know an
  entry of the signer's record after the latest it was given: such a
  database is older than what the signer has signed (a copy taken before a
  transfer, or mid-round before the forfeits came, which nothing on the
  chain shows yet). It names each entry: its number, the spend or forfeit,
  the leaf's owner key and salt.
- The server refuses to start on a database that does not know what the
  chain shows of the operator's: a transaction paying the operator's
  connector script that is no round it knows (a round it built and forgot,
  whose batches it would never release or sweep and whose participations
  would run again), or a board spent by its collaborative path by a
  transaction it neither built nor co-signed. It names each one. A database
  that fails this check is older than the chain; restore it to its latest
  commit rather than start it.

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
outpoint it watches, in blocks and in the mempool, and every output paying a
node or an entry of a batch the server built.

The node must run with `-txindex` and `-validateanchor`. The service refuses a
node that does not validate its anchors, since that node has no notion of
finality, and refuses to leave certification out on a chain whose node reports
certificates.

## Published parameters

The operator publishes its chain (the genesis hash), its key `S`, the bounds on
every leaf's exit delay (36 to 48 hours by default), the assets it serves with
the smallest leaf it takes in each, the depth limit (5 reassignments from
a round or a board) and its fee schedule. Every record and coin the server checks is checked under
these, with the receipt horizon a receiver uses: a coin's first expiry past
the exit deadline.

## Boards

An owner brings its own coins in with a board (`board-1`). It asks the server
for an operator nonce, builds its board record with it (its key, a nonce of
its own, the exit delay, asset and value), pays its coins to the board output,
and registers the record with the board transaction. The server refuses a
record for another chain or another operator key, an exit delay out of
bounds, an asset it does not serve, a value below its smallest leaf, a
transaction that does not pay the board output exactly once, a salt it has
seen before (`salt`), a nonce it never issued or already gave a leaf, a key
that already owns a leaf or is the operator's own `S` (`operator_key`), a
script it already knows, and another transaction for a board already
registered. The
node must then take the board transaction: it is in a block or the mempool
already, or `testmempoolaccept` allows it. One the node refuses (an input that
does not exist, say) is refused with `not_accepted` and the node's reason, so
a board nobody can pay never reaches the database or the nursery. A refused
board leaves nothing behind, its nonce included.

A registered board goes into the nursery and is credited, its leaf becoming
the owner's to spend off-chain, only once the finality service calls its
transaction final.

A board, and every coin resting on it, carries the dates of a batch made
when the board confirmed: its service expiry is 28 days after the median
time of the block that holds its transaction, and its exit deadline three
days before that (`board_status`, `info.boards`). Up to the exit deadline the
server co-signs spends of a coin resting on the board; after it, it takes the
coin only into a refresh, up to a day before the expiry. Past its expiry a
coin resting on the board is the owner's to take on-chain, and the operator
may bring its lineage on the chain to collect a coin of it that was given up
(see the watcher). A rollback that moves the board's transaction to another
block moves its dates with it. A rollback that takes a credited board out uncredits it at
once; the nursery broadcasts the same transaction again and the board is
credited again when final again. A board whose transaction can no longer
confirm is lost, and so is one never credited whose transaction is still in
no block a set time after it was registered (`board_unconfirmed_seconds`, six
hours by default): its transaction lost its parent, say. The nursery then
stops broadcasting it.

## Out-of-round transfers

A sender gives up coins the server knows, by leaf id, each with the value its
checkpoint keeps and its owner's signatures over the checkpoint and the
reassignment, for one to four new leaves, each named by its receiver's key and
nonce, a creator nonce the sender draws fresh for that leaf, an exit delay, an
asset and a value. The server co-signs only when every rule holds:

- each input is live (a board once credited) and spent by nothing else: a
  second spend of a leaf is refused, which is the whole of the double-spend
  protection before a round;
- each input resting on a board is before the board's exit deadline
  (`invalid_coin` after it: the coin is taken only into a refresh);
- nothing of the coin's lineage, its own leaf included, has been seen paid on
  the chain, in a block or in the mempool, and every board it rests on is
  credited and unspent: an Arca leaf on the chain past its exit delay can be
  exited by its owner at once, so the server co-signs no off-chain spend of
  it, a converted board included;
- the new coins are at most five reassignments from a round or a board;
- each new leaf is within the published bounds: an asset served, a value
  within its bounds, an exit delay within the bounds, a key that owns no other
  leaf and is not the operator's `S` (`operator_key`), a script never seen,
  and a salt no other output of the transfer has and the server has never
  seen on a leaf or promised to one (`salt`): the sender chooses both nonces
  of a new leaf's salt;
- no transaction could satisfy both it and a reassignment the server
  co-signed before: their committed outputs do not agree at every index both
  commit to (the same outputs, or one set the first outputs of the other).
  Such a transaction would spend both sides' checkpoints, create the outputs
  once and give one side's value to whoever broadcast it. The rule is
  `arca-covenant`'s (`TransferPlan::admit`), run against every reassignment
  recorded with the same output 0, under a lock on that output, so two
  requests racing cannot both pass;
- every checkpoint keeps between one atom and the whole coin, the outputs take
  no more of any asset than the checkpoints keep, and each owner signature
  verifies;
- the margins are bounded (`margin`): each checkpoint, and the reassignment in
  at least one asset, leaves the least margin that pays its fee, four times
  the node's floor for the transaction in an asset the node accepts for fees
  now, or one atom in one it does not; and no margin is more than
  `max_margin_multiple` (25 by default) times its least. A margin of nothing
  would make every answer a coin of the operator's, and a margin far above
  the fee a fee the node refuses. Both bounds are published (`info`), with the
  node's floor in every asset served now (`fees.floors`, read from the node at
  most every five seconds; `null` for an asset it does not accept), so a
  wallet prices its margins as the operator bounds them, whatever its own
  node makes of the asset.

The transfer is then recorded, inputs spent, before the operator key signs
anything, so the server never signs a spend it has not durably recorded and
two spends racing for one leaf leave exactly one standing. Each new coin's
record is checked by the server as a receiver would check it, stored, and
posted to the receiver's mailbox (the leaf's key, unless the output names
another). A request repeated byte for byte gets the same answer; one that
found the signer unreachable completes when repeated, whatever has changed
since it was recorded: its margins are judged as they were then, against
the floor of that moment, and the dates of the boards and batches its coins
rest on, which it was within then, refuse it only once a batch has expired.
Transfers are free.

The same record of spends answers the question `release_leaves` asks before
it takes an owner's release of a leaf's lowest node: whether the leaf has an
open out-of-round reassignment (`Cosigner::check_release`).

## Participations

An owner takes part in a round with one request, and is never asked for
anything while the round runs: the participation names the coins it gives up,
each with an attestation (its owner key's BIP340 signature over the
participation's id), the outputs it wants for them, the fee it pays in each
asset, and optionally the earliest median time of a round it may run in, at
most seven days ahead. An output wanted is a leaf (its template, `vtxo-1`, its
owner key and nonce, its exit delay, asset and value, and its key proof: the
owner key's BIP340 signature over `SHA256(T ‖ T ‖ id)`,
`T = SHA256("Arca/participation-key")`, so a participation wants a leaf only
under a key it holds) or an offboard (an asset, a value and the on-chain
script to pay). The server accepts it only when:

- every coin given up passes the same check as a transfer's input: known,
  live, given up nowhere else, its record valid, every board it rests on
  credited and unspent, nothing of its lineage on the chain, and its first
  expiry at least three days ahead: a coin is taken only up to its exit
  deadline. A coin resting on a board is taken past the board's exit
  deadline, until a day before the board's expiry: after the deadline a
  refresh is the one way it is taken. Its attestation verifies, and an
  earliest round time asked for lies before the last time every coin is
  taken;
- every leaf wanted is within the published bounds, under a key that owns no
  leaf, that no other participation standing wants and that is not the
  operator's `S` (`operator_key`), and its key proof verifies
  (`bad_attestation`); every offboard pays a served
  asset within its bounds to a script that is not an Arca script;
- per asset, the coins given up hold exactly what the outputs take plus the
  fee, and the fee covers the schedule.

It then chooses the participation's unlock hash and keeps its preimage,
draws an operator nonce of its own for every leaf wanted (taken at once, so
never handed out again), prices each forfeit's margin and each offboard
output's margin from the node's floor in that asset, and records everything in
one database transaction, the coins given up becoming spent by the
participation. The same request again is the same participation and gets its
status, with or without its key proofs: they sign the id, which does not
cover them, and are required only of a participation the server does not
hold yet.

The participation's id is
`SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body)`, `T = SHA256("Arca/participation")`,
where the body is the request without its attestations and key proofs: the leaf ids given up,
each output (kind, asset, value, then a leaf's template id and version, owner
key, owner nonce and exit delay, or an offboard's script), each fee and the
earliest round time (the layout is in `participations.rs`). The tag keeps the
attestation apart from everything else a leaf key signs, the genesis hash and
`S` to one chain and one operator.

The fee schedule is published by `info`. Transfers are free. A refresh, or an
offboard, costs nothing in the free window, the two days before a coin's exit
deadline (from five days before its first expiry to three days before it, when
the server stops taking it), and rises with the time left beyond the window to
`refresh_ppm` parts per million of the coin's value for a coin 23 days or more
beyond it; a coin resting on a board counts from the board's service expiry
when that comes first (see Boards). An
offboard adds `offboard_ppm` of what it pays out and the margin its on-chain
output holds for its unlock.

Each forfeit carries the refund delay the server publishes with the
participation (the longest exit delay), and leaves uncommitted the margin the
server priced: four times the node's floor for the forfeit transaction, in the
coin's asset, or one atom when the node does not accept that asset for fees.
An offboard's output may be reclaimed by the operator after a delay longer than
unrolling the coin given up, its exit delay, the refund delay and a margin.

## Rounds

At each round (every `round_interval_seconds` while participations wait) the
runner gathers the pending participations whose earliest round time has
come, checks each coin they give up again, and builds one tree per asset with
`arca-covenant`'s builder: balanced at radix 4, every node gated, RECLAIM on
the lowest nodes, each leaf behind its participation's hash-locked entry, the
reserve at four times the node's floor in the batch asset. A batch in an asset
the node does not accept for fees carries a reserve of one atom on every node
and every entry, so whoever unrolls it attaches a fee coin in an asset that is
accepted. A coin is checked again under a horizon of one day before its first
expiry: a participation accepted before its exit deadline still runs if a
round takes it by then, and one with a coin past that can never run and is
voided, its coins given back. A batch holds at most 1,024 leaves; a participation runs whole in one
round, its leaves in several assets included. The participations are taken
against what the operator's wallet can spend of each asset now: per asset,
what the round pays on their behalf (each batch output, leaves and reserves
as the builder makes it, and each offboard output) must fit, and the round's
own fee and connector after it. A participation that does not fit waits,
in order, and the ones after it still run if they fit: one asset the
operator is short of delays no participation in another. A participation
that waits says why in its status (`waiting`), and runs once the wallet can
fund it. Each batch has its own sweep
token, one explicit atom with no reissuance token, issued by one of the
operator's coins, and a clock schedule of three steps, 28, 56 and 84 days
after the round's median time, with a notice of 36 hours.

The round transaction pays each batch output followed by its token's atom at
the batch's first clock, then every offboard output, then the connector
output, then change per asset and the one fee output. It spends the
operator's coins only: a round that carries forfeits takes no input of a
third party, which could be spent elsewhere and keep the round from
returning after a rollback. Its lock time is 0 and every input final, and it
is kept byte for byte, so the nursery broadcasts it again unchanged and it
returns with its txid, every forfeit signed for it still good. Its fee is
paid in one asset: the first of its own batches' assets, in the order of
`fee_assets`, that the node accepts for fees now, else the first asset of
`fee_assets` it accepts; never another, and never one the node refuses.

Before it records anything the runner checks its work as a wallet would:
every leaf's record validates against the transaction under the acceptance
policy (the five checks on the token and its clock among them), the connector
output is the operator's, each offboard output is paid once, the lock time is
0, and the node would accept the transaction now. Then the round, its
batches, each leaf (a pending coin until its owner hands over its forfeits)
and every participation's move to `issued` are recorded in one database
transaction, and the round goes to the nursery. A participation one of whose
keys has come to own a leaf meanwhile cannot run; it is voided and the coins
it gave up are given back.

Every batch is published by `tree`: the round, the batch output, its token's
output and the round's connector output, the asset, the schedule in
`arca-covenant`'s canonical encoding, burn-only or not, the radix, the
reserve rule and the smallest leaf, every leaf as the builder took it
(template, owner key and nonce, operator nonce, exit delay, value, unlock
hash), and the latest entry of the signer's record, with its running hash,
when the round was built (`signer_record`). From that alone a wallet, an explorer or any mirror rebuilds every
script of the tree with `Tree::build` and checks the leaf it cares about
against the round transaction with `LeafRecord::validate`.

### Rollbacks

A round the chain loses goes back to the nursery's care. When a rollback
disconnects it, its new leaves are uncredited at once: a leaf whose round is
not final is not live, and no coin resting on one is co-signed. The nursery
broadcasts the round again byte for byte, so it returns with its txid, every
forfeit signed for it still good, and its leaves are credited again once it is
final again.

A round out of the chain whose input another transaction took, final, is
lost (the nursery finds the conflict) and is retired, in one database
transaction: the round is lost, its new leaves not yet spent are lost, and
every participation it ran runs again in a later round, under a new unlock
hash and with a new operator nonce for each leaf it wants (its keys and owner
nonces as before, so its owner's wallet recognises the new leaves), the
attempt it leaves recorded. A round with another txid is always a new round
with new hashes: nothing signed for the old one carries over. The coins those
participations gave up stay given up, so the operator co-signs no other
off-chain spend of them, and any release of their lowest nodes given for the
lost round is retired: it names the lost round's connector asset, which is
not issued while the round is out of the chain.

A lost round can still return: finality is modulo Bitcoin, so the parent
chain can take out the transaction that took its input, however deep, and
anyone holding the round can send it again. A round that runs a lost round's
participations again therefore spends a coin of the operator's that cannot
exist while the lost round is in the chain: an input of the lost round that
is still unspent, or, where there is none, an output of a transaction that
took one (or of a transaction of the operator's descending from it). Whatever
the parent chain does, at most one of the two rounds is in the chain. The
round records each lost round it replaces and the coin that keeps them apart
(`round_rerun`). A re-run runs only with such a coin for every lost round its
participation was in; where none of the operator's exists, the participation
is voided and its status says so (`void_reason`), and its coins are its
owner's on the chain. A round's inputs are the operator's choice, not a
format: no script or transaction format changes for this.

A round held as lost that is final in the chain again is restored, in one
database transaction: the round is final; every round that ran its
participations again and is not in the chain, which can now never confirm
beside it, is retired; and each participation the round ran is back as it
stood in it, under its unlock hash and operator nonces, its new leaves
credited, its releases good again, and every forfeit naming the round
followed by the nursery again, so the watcher publishes and claims them as
for any final round. Nothing runs a third time for a participation whose
first round stands; a participation a retired round ran that was never in the
restored one runs again as after any lost round. A participation a coin of
which was taken back on the chain while the round was out (its forfeit for
the round refunded) is not brought back: its leaves of the round are never
credited (`expired`), and the operator sweeps them with their batch. A coin
resting on a round is as final as that round.

A coin with a forfeit for an earlier round in the watcher's log, or whose
output the server has seen spent, is never taken into a re-run: such a
forfeit may still confirm, from any mempool that saw it, and is its owner's
to refund once its delay has run while the round is out, since no claim of
it can be made then. The participation is voided and its status says why
(`void_reason`); its coins stay given up (the signer co-signs no spend under
a salt it signed a forfeit under), so each is its owner's on the chain, by
that forfeit's refund or by its exit, unless the round returns first and the
watcher claims the forfeit. Any other re-run completes as an ordinary
participation: its forfeit for the new round is taken and checked, the
preimage released against it, and the coin left like any forfeited coin (a
board lineage to the board's dates, a batch leaf to its batch's expiry,
either answered at once if its owner exits). Nothing goes on the chain for a
re-run that an ordinary participation would not put there.

The server publishes no forfeit naming a lost round, by any path. The
watcher's log records the round each forfeit names and refuses one naming a
round retired, under that round's row lock, so a forfeit is logged before its
round is lost or never; the watcher publishes none whose round transaction
cannot confirm as the chain stands (lost, retired or not yet, or a re-run of
a lost round that is final again); and the nursery gives up every such
forfeit it holds before it could broadcast it again, on a pass, after a
disconnection or at a restart, until the round is restored.

The nursery does not call a round lost when its input's own transaction is
reorganised away and never returns: such a round stays broadcast, its
participations issued and its leaves uncredited.

## The forfeit swap

Once its round is final, an owner validates each new leaf from the published
tree, then hands over with `forfeit_leaves` the forfeit of every coin its
participation gave up, built with `Forfeit::for_refresh` from that validated
leaf and round and the refund delay and margin of the participation's status,
together with its unroll authorisations for every node above each new leaf.
The server takes it only for a participation in a round it calls final, and
only when:

- the forfeits are exactly the coins given up, one each;
- each verifies against the forfeit the server builds itself from what it
  chose: the participation's unlock hash, the connector asset of its round's
  connector output (which exists only while that round is in the chain), the
  coin's own leaf id, and the published refund delay and margin. A forfeit for
  another hash, another round's connector, another coin, or with another delay
  or margin, does not verify;
- each coin given up still passes the coin check: nothing of its lineage on
  the chain, its boards credited and unspent, its expiry not past;
- the authorisations are one set per new leaf, and each new leaf's full coin
  record (its record, the preimage, the authorisations) validates against the
  round as a receiver checks a coin.

The forfeits are then recorded with their owners' halves, each new leaf's
coin record filled in, together with the messages the signer is to sign, in
one database transaction: a forfeit the signer may have signed is never one
the database has not heard of. The signer then signs the operator's half of
each forfeit, which the server checks and stores: it is never returned to
anyone, and leaves the server only inside a forfeit the operator publishes.
An owner therefore never holds a forfeit it could publish itself. Then, in
one database transaction, the participation is released and its new leaves
credited; only then does the preimage go back. A forfeit left without the
operator's half (the server stopped before the signer's answer was stored)
is given it at start and every minute after; the signer signs again what it
signed, and a forfeit is its owner's consent, so completing it takes
nothing from anyone. The same request again gets
the same preimage, whatever the chain has seen of the coins given up
meanwhile. A participation run again after a lost round completes the same
way, with its forfeits for the new round.

A new leaf is live, and can be paid on out of round, once its participation
is released and its round final; a coin resting on a leaf of a round that is
not final is not co-signed (`round_not_final`).

The forfeits are due within a day of the round being found final. A
participation whose forfeits have not come by then expires: its new leaves
are never credited (their preimage never goes out, and the operator sweeps
them with their batch at expiry), and each coin it gave up for which no
forfeit was signed is given back, live again and free to be given up again. A
coin under a forfeit signed for an earlier, lost round stays given up. A forfeit step that reaches the server after the expiry, even one in
flight when it ran, is refused (`not_in_round`) and stores nothing. A round
that stops being final and becomes final again starts the day again.

`release_leaves` then takes the owner's release of the lowest node of each
coin it gave up: the owner's signature, with the coin's own key, over
`SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)`, `H` the node's children hash
and `M` the connector asset of the participation's round
(`arca_covenant::Release`), and, if the wallet names it, that `M`
(`connector_asset`). RECLAIM needs an atom of `M` among its inputs, and `M`
exists only while that round is in the chain, so a release is void with its
round. A release naming another `M` is refused (`wrong_round`), and one whose
signature is over another message (`bad_signature`): the server checks every
release over its round's own `M`, named or not. It is also refused for a coin with an
open out-of-round reassignment, whatever else holds; for a coin not given up
in the participation named; before the participation's preimage went out;
while its round is not final; and for a board or a coin a reassignment made,
which have no lowest node. Each release is kept with its round and `M`. Once
every owner under a lowest node has released it, the operator may reclaim the
node before expiry, with one atom of each `M` its owners' releases name.

## The watcher

The watcher (`watcher`) is everything the operator does on the chain after a
round. It follows the finality service: on each of its passes it answers
stale exits and claims forfeits, and after each new block, or at least every
`recovery_interval_seconds`, it does the rest, always in the order of the
deadlines: answers to stale exits (the exit delay), then claims (the refund
delay), then new forfeits and the rest, which have none. It never builds a second spend
of an outpoint while a spend of its own is in the nursery and not lost, so
each step is taken once, and every transaction it publishes goes to the nursery,
which broadcasts it again unchanged after a rollback of any depth. Each step
reads only what may still need it: an output a final transaction of the
watcher's spends is not looked at again until a rollback takes that
transaction out, a batch is not looked at for its expiry before its first
one, nor for a reclaim before an owner under it has released.

- **Stale exits.** A coin the server holds as given up, by a participation
  whose forfeit it stored or by a transfer it co-signed, whose leaf is seen on
  the chain unspent, in a block or the mempool, is answered at once: by its
  forfeit, or by its checkpoint; and a reassignment is published once every
  checkpoint it spends is on the chain. A board given up and then converted
  is the same case: its leaf appears. The answer confirms within the leaf's
  exit delay, after which its owner's exit finds the leaf spent.
- **Boards given up in a round.** No batch sweeps a board, so once the round
  it was given up for is final the watcher publishes its forfeit from the
  board output itself, and claims it. Every forfeit's refund clock starts when it
  confirms, and a round may give up thousands of boards, so the watcher
  publishes them no faster than it can claim them: a new one goes out only
  while the watcher's own transactions waiting for a block stay within
  `block_share_vbytes` (45,000 by default, about half a block), and only if
  its claim can follow within its refund delay at `block_interval_seconds`
  apart. The rest wait for the next pass, and each pass says how many wait.
  The round's atom of its connector asset is issued with its first board
  forfeit, so it is held by the time the forfeits confirm. A coin of a
  transfer given up in a final round whose lineage rests on boards alone is
  swept by no batch either: the watcher publishes each board's checkpoint
  from the board output, and the answers to stale exits carry it through
  each reassignment to the coin's forfeit. That lineage is shared: each
  reassignment on it made other coins too (a sender's change, say), which
  land on the chain with it, and so do the coins those were spent into. So
  the watcher publishes it at once only when none of them is a coin another
  holder may still hold off-chain (live, pending, or given up with no
  forfeit the operator can claim); otherwise it waits until the latest
  service expiry among those coins, a date each of their holders was shown.
  Before then only an exit puts the lineage on the chain, and the answers to
  stale exits take it on. A coin resting on a batch leaf is left to that
  batch's sweep.
- **Claims.** The forfeits the watcher published that are in a block are
  claimed, every one of a round in one transaction (up to `max_claim_inputs`,
  200 by default), each with the preimage of its unlock hash, against one
  atom of the round's connector asset `M` that every claim in it names. The
  watcher issues that atom from the round's connector output when it holds
  none, to the wallet, and every claim pays it back to the wallet for the
  next. A claim acts for its round (its log entry names `M`) and takes each
  forfeit as an input; it pays what the forfeits hold to the wallet, less the
  fee in the first of their assets the node accepts, or a wallet coin pays.
- **Offboards.** A released participation's offboard output is unlocked to its
  destination with the preimage, which its owner already holds, so the owner
  need do nothing more. One whose participation expired or was voided, its
  preimage never out, is reclaimed by the operator once its reclaim delay has
  passed since it confirmed. An offboard whose preimage went out is never
  reclaimed. A stale exit of the coin it gave up is answered as any other.
- **Expiry.** At the expiry of the clock that holds a batch's token, the
  release moves the token to `R`. Once it has waited the notice there, each
  sweep takes every output of the batch still unspent whose own notice has
  passed (the batch output, a node or an entry someone unrolled, a checkpoint
  of a coin from the batch), at most `max_sweep_inputs` at a time, and returns
  the token to `R`. A leaf on the chain is its owner's and is never swept.
  The server builds no burn-only batch and sweeps none.
- **Reclaim.** A lowest node every owner of which has released it is
  reclaimed with an atom of each connector asset the releases name. With
  `reclaim_early`, a node all of whose lowest nodes are released is unrolled
  first, by a released owner's authorisation, until the lowest nodes are on
  the chain, so a fully refreshed batch comes back before it expires; the
  watcher never unrolls a node with an owner who has not released.

A fee is paid from the value a transaction takes, or from the margin its
signers left, when the node accepts that asset for fees now and it covers the
node's floor. A margin of more than twice the fee the wallet pays for the
transaction pays that fee and the rest goes to the wallet, after the outputs
the signers committed to: paid whole, a large margin would be a fee the node
refuses (`max-fee-exceeded`). Otherwise a coin of the wallet's pays, in the
first asset of `fee_assets` the node accepts, and the margin goes to the
wallet's change. No
asset is assumed, the policy asset included. The watcher spends the change of
its own transactions the nursery still holds as pending, in a block or not,
as long as fewer than twenty of its transactions waiting for a block lie
under it; a round spends only final coins. A step the wallet cannot pay for
waits, and is logged.

A board forfeit in an asset the node does not accept for fees takes a wallet
coin for its fee, and so does its claim. The watcher publishes one only while
the fee pool (what it can pay fees with in the first accepted fee asset)
covers, twice over, the claims of the forfeits already waiting and this
forfeit with its claim; the rest are held back, and the pass logs that the
pool cannot cover what is outstanding. The operator's metrics
(`metrics_listen`, `GET /metrics` in the text format Prometheus reads) give
the pool and what is outstanding per fee asset
(`arca_watcher_fee_pool`, `arca_watcher_fee_outstanding`) and the board
forfeits held back for block space or for the pool
(`arca_watcher_forfeits_held`).

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
| `GET info` | The operator key, genesis hash, assets served with their smallest leaf, exit-delay bounds, depth limit, the finality rule, the template list and its version, the fee schedule with its free window and the bounds on a transfer's margins (`margin_multiple`, `max_margin_multiple`) and the node's floor in each asset served (`floors`), a participation's exit deadline and forfeit deadline, a board's dates (`boards`: its service lifetime, exit deadline and last refresh time), the signer's record's latest entry, running hash and the signer's signature over them, with the keepers' acknowledgements of it (`signer_record`, absent while the signer does not answer or is stopped), the keepers' keys and how many must hold a head (`keepers`), the request limit |
| `POST operator_nonce` | A fresh operator nonce, for a board, good for an hour by default |
| `POST challenge` | A challenge to authenticate with, good for a short while, stored nowhere |
| `POST register_board` | Registers a board record with its transaction |
| `POST board_status` | A board's state (`pending`, `credited`, `lost`), its transaction's finality and, once that is in a block, its dates (`exit_deadline`, `expiry`) |
| `POST cosign_transfer` | Co-signs an out-of-round transfer and delivers its coins, with the signed head of the signer's record its last signature was recorded at (`signer_record`) |
| `POST submit_participation` | Accepts a participation in a round |
| `POST participation_status` | A participation's state (`pending`, `issued`, `released`, `void`, `expired`), its unlock hash, its forfeits' refund delay and margins, its round and where each of its outputs is in it, while it is pending why the last round did not take it (`waiting`), once void why it never runs (`void_reason`), and once void or expired whether each coin it gave up is its owner's again off the chain (`returned`) |
| `POST tree` | The published tree of a batch, by its round's txid and output, with the signer's record's latest entry when its round was built, signed |
| `POST forfeit_leaves` | Takes a participation's forfeits and its new leaves' unroll authorisations, and returns its preimage |
| `POST release_leaves` | Takes an owner's release of the lowest node of each coin it gave up, each naming the connector asset of the participation's round |
| `POST mailbox_read` | The coin records in a key's mailbox after a cursor, each a transfer made with the signed head of the signer's record that transfer was recorded at |
| `POST leaf_data` | The leaves a key owns (`pending`, `live`, `spent`, `lost`, `expired`), with their records; a round's leaf is served with an empty record until its participation's preimage went out |
| `POST witness` | Takes the heads of the signer's record a wallet holds (at most 32, each `{entry, hash, signature}`) and a nonce the wallet draws fresh for the call, hands them to the signer, and answers the running hash the record holds at each entry, each signed, its latest entry, signed (`head`), the record's end signed together with the nonce (`end`), and whether the signer is stopped (`stopped`), with its proof (`proof`: the signed head that stopped it and, when the record holds another there, that head, signed) |

`mailbox_read` and `leaf_data` need a proof of the key: a challenge from
`challenge`, signed with BIP340 over the tagged hash
`SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key ‖ SHA256(request))`
with `T = SHA256("Arca/auth")`, where `request` is what the read asks besides
its proof: for `mailbox_read` its cursor (eight bytes) and page size (four),
little-endian; for `leaf_data` nothing. The tag keeps it apart from
everything else a leaf key signs, the genesis hash to one chain, the call and
the request to one read, the challenge to a short while. A challenge is
stored nowhere: it is the time it was issued, 12 random bytes, and a keyed
check over both (HMAC-SHA256 under a key drawn once and kept in the
database, so every server on one database takes the others' challenges, and
its own across a restart), taken within its lifetime
(`challenge_ttl_seconds`, two minutes by default); a proof used again within
it repeats only the very read it was signed for, so whoever sees one (a
proxy, a log) learns nothing more than that read. There is no bearer token. `cosign_transfer` is
authenticated by the owners' signatures over the transfer itself, and
`submit_participation` by each owner's attestation over the participation;
`participation_status` needs only the participation's id, which is a hash
of its request, and `tree` is public. `forfeit_leaves` and `release_leaves`
are authenticated by the owners' signatures over the forfeits and releases
themselves.

The one call that writes a row for anyone who asks, `operator_nonce`, is
handed to each source at a bounded rate (`[limits]`: one a second with bursts
of ten by default), so one caller asking as fast as it can leaves every other
its share, and over every source together within a high bound (250 a second,
bursts of 10,000), which bounds the rows nonces hold without a budget a few
sources could use up; a request past either is refused with 429
`rate_limited`. The overall bound is a ceiling every caller shares: it is
what bounds the rows, since a nonce's row is what makes it single use, and a
caller holding more sources than the overall rate (more than 250 IPv4
addresses or IPv6 /48s, at the defaults) can take every overall token while
it keeps asking, after which boarding waits for the bucket to refill. A
`witness`, which reads the signer's record under its lock and carries up to
34 of the signer's signatures, has a budget of its own, apart from the
nonces' (`witness_per_second` and `witness_burst` overall,
`witness_source_per_second` and `witness_source_burst` for each source; 500
a second with bursts of 5,000, and 5 a second with bursts of 60, at the
defaults): a wallet makes one each command, and a caller that uses up the
nonces leaves every wallet its witness. A witness names at most 32 heads, of
which at most four without the signer's valid signature; the server and the
signer each check every signature before anything is looked up, and refuse a
call naming more (`malformed`), so only the signer's own heads cost a read of
the record. A `challenge` writes no row and is not limited. A source is
an IPv4 address, or an IPv6 /48. A request from a trusted proxy
(`trusted_proxies`, loopback by default, for a proxy on the same machine) is
counted against the nearest address in its `X-Forwarded-For` that is not a
trusted proxy; any other request against the address that connected,
whatever header it carries. Each entry of the header is read on its own (an
address, with or without a port), so one that does not read costs the others
nothing; when the nearest entry that is not a trusted proxy does not read,
the request is counted against the proxy, not against what a client wrote
before it. A nonce no board took within its lifetime (`nonce_ttl_seconds`)
is deleted, so what the call holds in the database is bounded by the overall
rate times the lifetime. A board naming a deleted nonce is refused
(`nonce_unknown`): a wallet registers its board right after it takes the
nonce.

## The signer

The operator key `S` lives in `arca-signer`, a process of its own; the server
never holds it. It loads the key from a file only its owner can read (it
refuses one others can), listens on a Unix socket of mode 0600, and answers
three requests: its public key; `S`'s signature over the rebindable message of
a collaborative path, which it builds itself from the parts (the salt, the
coin's asset and value, one to four committed outputs, and for a forfeit the
forfeit's own parts) on its own chain, for the leaf of an owner key the
request names together with that owner's own signature over the same
message, which the signer checks; and
`S`'s signature over the spend of one input of a transaction by one tapscript
leaf, whose signature hash it computes itself from the transaction and the
outputs every input spends, on its own chain. It signs a spend only by a leaf
that names `S` with `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` (the operator's own
paths: a clock's release, `R`, a sweep, a reclaim, a forfeit's claim, the
connector's issuance, an offboard's reclaim) and of a taproot output. It signs
no digest it is handed, no unroll authorisation and no release, and nothing
by a path that checks `S` with `OP_CHECKSIGFROMSTACK`. The server checks each
signature it gets back against the message or signature hash it built.

The signer is the one-spend authority. Before it returns a rebindable
signature it appends the owner key, the salt, the kind and the message's
digest to its record, an append-only file it alone writes, and syncs it to
disk; it reads the record line by line when it starts, checking every line,
and refuses to start on a line it cannot read. It keeps at hand only what a
lookup needs, the first bytes of each entry's salt and where its line
starts, and reads the entries under a salt back from the file when a request
names it: a record of four million entries opens in about ten seconds in
under 70 MB. Each entry names its leaf: its owner key together with its
salt (a leaf's, a board's, a checkpoint's, whose owner is its coin's), and
needs that owner's own signature over the message, so an entry under a key is
always its holder's doing. The rule is kept per salt: `S`'s signature commits
to the salt and not to the owner key, so a signature given for one leaf is
valid on every coin of the same salt, asset and value. Under each salt it
signs one spend, a message into anything but a forfeit output, or forfeits,
one for each round's connector asset: a forfeit request names the forfeit's
parts, and the signer rebuilds the forfeit output from them and checks it is
the one output committed to. The same message again is signed again, so a
request repeated after a signer outage completes; a spend when any entry
under the salt carries another message, a forfeit after a spend, and a second
forfeit for one round are refused (`already_signed`), whatever the database
holds. The server refuses a second leaf under a salt it has seen, so two
leaves share a salt only where its database has forgotten one; there the
first to spend takes the salt and the other's holder is refused, and can
exit, while a second signature, which would also spend the first coin, is
never given. The server answers such a
refusal with `double_spend`, and logs that its database has lost a spend.

The record cannot be lost, cut back, torn or shared without the signer
noticing:

- **Lost.** The signer starts only on its record. One is made once, for a new
  operator key, by `arca-signer --create-record`, which refuses a path where a
  record is; a signer pointed at a path where there is none does not start,
  so a lost record is never silently replaced by an empty one, which would
  sign again what was signed before.
- **Cut back or replaced.** The record's first line names its format, the
  operator key and the chain, and a record of another key or chain does not
  start. Every entry carries its number and a running hash over everything
  before it, so an edited line stops the start. The server's database
  remembers the latest entry the signer gave it, and every rebind request
  names it: a record that ends before it has been cut back, or replaced by an
  older copy (`record_behind`), and one that holds another entry there is
  another record (`record_differs`). Either way the signer signs nothing more
  until it runs on its whole record, the server answers `signer_unavailable`,
  and the server does not start against such a record, naming both entries.
- **Torn.** A write that fails (a full disk) is undone at once, so the line it
  cut short is never followed by another; a last line cut short by a crash
  was never answered, and is removed when the record is opened, with a line
  in the signer's log. A crash between a line's write and its sync can leave
  a whole line the disk does not hold yet: the record is synced when it is
  opened, before it answers anything, so no head is signed for an entry that
  is not on disk.
- **Shared.** The signer locks its record while it runs, so a second signer
  on the same file does not start; a copy written by another signer is
  another record, caught by the entry the database knows.

The record grows with every message signed, and protects nothing once the
coins its entries are for can no longer be spent off-chain. It can be
compacted, with the signer stopped: `arcad <config> expired-salts` lists the
salts of every leaf whose coin rests on batches alone, all past their last
expiry, and of their checkpoints (a board's covenant never expires, so a coin
resting on one is never listed), and `arca-signer --compact-into <new file>
--drop-salts <list>` writes a new record without the entries under those
salts. The new record's first line names the old record's latest entry and
running hash, from which its own entries go on, so the entry the server's
database knows is still the record's; it carries every other entry's line
over verbatim, and for every entry it drops a line with that entry's number
and running hash (about 70 bytes an entry, on disk), with a hash over all of
them in that first line, which the signer checks at start. So the record
answers the running hash at every one of its entries for its whole life. The
operator then puts the new file in the record's place and starts the signer
on it.

### The signed head, witnessed

Every head of the record the signer hands out, an entry and its running
hash, is signed with `S` over `SHA256(T ‖ T ‖ genesis ‖ entry ‖ hash)`,
`T = SHA256("Arca/record-head")`, the genesis hash in internal byte order and
the entry eight bytes little-endian; only for an entry on disk. `info`
carries the latest, every published tree the one the database knew when its
round was built, and every transfer's answer and its coins' mailbox records
the one its last signature was recorded at. A wallet keeps each head it is
shown with that signature, and on every contact (each command that reaches
the server, `sync`, the mailbox and the re-check on start among them) makes
one `witness` call: it hands over the highest head it holds, the heads its
coins were recorded at, and as many more as fit, with a nonce it draws fresh
for the call, and gets back the running hash the record holds at each entry,
each signed as a head, the record's latest entry, signed, and the record's
end signed together with the nonce, over `SHA256(T ‖ T ‖ genesis ‖ entry ‖
hash ‖ nonce)`, `T = SHA256("Arca/record-end")`. Another hash the signer
signed at an entry the wallet holds signed is two heads `S` signed at one
entry, and an end signed with the call's nonce before such an entry is the
record's end now, not an older head replayed: each is a rollback, and the
signer's own proof of it. Since the wallet asks for its own highest entry by
number every time, a rolled-back record that has signed past it again is
caught as well. The wallet acts on nothing else: the server (and anything
between it and the wallet) passes the signer's signatures on, and an answer
without them, or a latest entry in `info` below what the wallet holds, is an
unreachable server, which the wallet asks again and refuses nothing for.

A head that carries `S`'s valid signature and that the record does not hold
(an entry past its end, or another hash at that entry) is proof the record
was rolled back or replaced: the signer signed it. The server hands every
head it is given to the signer, which checks the signature itself, writes
the proof beside its record (`<record>.stopped`), and from then on signs no
rebindable message and no head, across restarts. It still signs the spends
of the operator's own paths (a claim, a sweep), which the record does not
govern. The server still starts on a stopped signer and answers every
wallet's witness with the stop and its proof: the head that stopped it, as it
was handed over, and the head the record holds at that entry, signed, or,
where it holds none, the record's end signed with the asker's nonce before
it. So one wallet that was online in between protects every holder, and no
wallet takes a stop on the server's word. A head without `S`'s valid signature, altered, of
another chain, or one the record holds, stops nothing; neither does a head
from before a compaction, whose hash the compacted record keeps.

A stop means the record's guarantee is void for every entry after the point
it fell back to: `S` may have co-signed a second spend of a coin a transfer
after that point made. Each wallet finds the highest entry it holds that the
record still agrees with, takes on the chain at once every coin it holds
that a transfer recorded after it made (a coin whose entry it was never
given counts as after), and goes no further with the operator: it still
reads its mailbox and takes every coin in it on the chain at once, and takes
every other coin it holds off the chain there by that coin's exit deadline.
The operator does not clear the
stop to carry on: it resumes only with a new signer key and a new record,
which is a new operator to every wallet. `arca-signer --clear-stopped`
removes the proof, with the signer stopped, after printing it.

### The keepers

Wallets are not always online, so a record and a database restored together
(a snapshot of the whole machine) could co-sign a second spend of a coin
paid in the lost window before any wallet witnesses. The keepers close that
window: the signer answers an entry only once its signed head is held
outside its machine.

A keeper is `arca-keeper`, a small program of its own, run on another
machine than the signer. It holds the operator key `S` (public), the
chain's genesis hash and a key of its own, and keeps an append-only file of
the heads of `S`'s record it was given, each synced before it answers. It
takes a head only with `S`'s valid signature, and only when it extends what
it holds: an entry after its latest, or an entry it holds with the same
running hash. A head that contradicts what it holds is refused and answered
with the signed head it holds at that entry, or with its latest when it
never held that entry. It answers "your latest" on request. Every answer is
signed by the keeper's key over the asker's nonce, fresh for each request:
an acknowledgement is the keeper's signature over `SHA256(T ‖ T ‖ genesis ‖
S ‖ entry ‖ hash ‖ nonce)`, `T = SHA256("Arca/keeper-ack")`, and an answer
naming its latest head over `SHA256(T ‖ T ‖ genesis ‖ S ‖ nonce ‖ 0x01 ‖
entry ‖ hash)` (`‖ 0x00` alone when it holds none), `T =
SHA256("Arca/keeper-latest")`. Nobody on the path can make an
acknowledgement or replay an older latest. Its heads file, like the
record, is made once on purpose (`--create`), locked while it runs, and
synced when it is opened; a last line cut short by a crash is removed.

The signer is configured with its keepers (`--keeper <host:port>=<key>`,
one for each) and how many must hold a head (`--keepers-required`, all of
them by default). After it has written and synced an entry, it hands the
record's latest head, signed, to every keeper, and releases the
co-signature only when the required number have acknowledged it; otherwise
it answers `keepers_unavailable` (the server's `signer_unavailable`), the
entry stays, and the same request again completes once they do. Requests
waiting at once share one hand-over. At start, and before the first
signature after a start, it asks the keepers for their latest: a keeper's
head past the record's end, or with another hash at an entry the record
holds, is the proof of a rollback, and stops the signer as a wallet's head
would; and until enough keepers have answered it signs nothing the record
governs. Enough is the keepers minus the required plus one, so that any set
of keepers that acknowledged a head includes one that answered: with all
of them required, one answer is enough; with one of two required, both
must answer. A keeper restored from an older copy, while the signer was
not, holds heads the record still holds: it stops nothing, takes the
record's latest at the next hand-over, and is whole again.

Every head the signer hands out carries the acknowledgements it has of it,
and they travel with the head wherever a head travels: `info`, the witness
answer, a transfer's answer, a mailbox record, a published tree (the server
keeps them, by head, in its database). `info` names the keepers' keys and
how many are required (`keepers`). A wallet pins them when it is created, as
it pins the operator key, and from then on takes no coin and keeps no head
that lacks the required acknowledgements. A keeper on the signer's own
machine adds under a millisecond to a co-signature, and one 50 ms away each
way about 100 ms: one round trip, over a connection the signer keeps open
to each keeper.

With no keeper configured the signer works without one, and says so when it
starts; `info` names no keeper, and a wallet says so in its own `info` and
on every coin it receives out of round. Such an operator's record rests on
its own machine alone: a restore of that machine, its database and record
together, can let a coin paid out of round be spent twice, until a wallet
holding a later head witnesses. Such an operator is for its own coins.

## Running

    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
        --create-record                    # once, for a new operator key
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --socket /run/arca/signer.sock \
        --record /var/lib/arca/signer.record \
        --keeper keeper-1.example:7341=<keeper 1 key> --keeper keeper-2.example:7341=<keeper 2 key>
    arcad /etc/arca/arcad.toml
    arcad /etc/arca/arcad.toml address     # a receive address of the operator's wallet, to fund it
    arcad /etc/arca/arcad.toml expired-salts > expired.salts           # what the record no longer needs
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
        --compact-into /var/lib/arca/signer.record.new --drop-salts expired.salts   # with the signer stopped
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
        --clear-stopped                    # removes the proof of a rollback, with the signer stopped

Each keeper, on a machine of its own:

    arca-keeper --key-file /etc/arca/keeper.key --pubkey     # its key, for the signer's --keeper
    arca-keeper --key-file /etc/arca/keeper.key --operator <S> --genesis <genesis hash> \
        --heads /var/lib/arca/keeper.heads --create          # once
    arca-keeper --key-file /etc/arca/keeper.key --operator <S> --genesis <genesis hash> \
        --heads /var/lib/arca/keeper.heads --listen 0.0.0.0:7341

The keeper's key file holds its 32-byte secret key as 64 hex characters,
readable by its owner alone. A keeper speaks plain TCP, one JSON object a
line: every answer it gives is signed by its key over the asker's nonce,
and it takes nothing but heads `S` signed, so it needs no TLS. Its heads
file is never restored from an older copy while the signer runs on, and
never together with the signer's machine.

`arcad` stops its tasks and exits on SIGINT, so a service manager is set to
send it that signal (systemd's `KillSignal=SIGINT`).

[`arcad.example.toml`](arcad.example.toml) lists every setting: the listen
address, the database, the signer's socket, the wallet's mnemonic file, the
node's RPC, the finality rule, the exit-delay bounds, the assets served
with their smallest leaf, how often a round is built, the assets a round's
fee is paid in, the fee schedule, the watcher (`[watcher]`: whether it
acts on its own, early reclaims, the most outputs a sweep takes, how often its
recovery work runs), and the limits on what the unauthenticated calls leave
behind (`[limits]`: the rate of nonces, and the witness's own, for each source and overall, the
proxies trusted to name a request's source, a nonce's lifetime,
how long a board may stay out of every block), and where the operator's
metrics are served (`metrics_listen`, a loopback address). The node must run with `-txindex` and `-validateanchor`.

An asset served need not be accepted for fees by the node. A batch in such an
asset carries a reserve of one atom on every node and every entry, on every
operator's server alike: nobody can pay a fee in it, so whoever unrolls the
batch attaches a fee coin in an accepted asset. A batch in an accepted asset
reserves four times the node's floor for each node's unroll. A round's own fee
is always paid in an accepted asset (`fee_assets`).

## The on-chain wallet

The operator's wallet is built on the Sequentia Wallet Kit: its keys come from
a BIP39 mnemonic through the kit's software signer, at
`m/84'/1'/0'/<chain>/<index>` (chain 0 for scripts handed out to be paid,
chain 1 for change), each an unblinded P2WPKH script, and the kit's PSET
signer signs every input.

- **Funding.** `arcad <config> address` hands out a receive address of the
  wallet (chain 0, the next index), records it in the database and prints it
  with its script and index as JSON, then exits. It needs the database, the
  mnemonic file and the node, not the signer, and runs beside the server.
  The server follows the chain from the block it first started at, so an
  operator starts the server once, then hands out an address and pays it: an
  output paying it in any block the server connects after that is a coin.
  The wallet knows the scripts it handed out, and no others: a coin paid to a
  key of the mnemonic it never handed out is not found.
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
- **Coins for the watcher.** The watcher's transactions spend Arca outputs,
  and a coin of the wallet may pay their fee (`Wallet::with_fee_coin`) or hold
  a round's connector asset. The wallet signs its own input of such a
  transaction itself, with the key the kit derives, over the segwit v0
  signature hash rust-elements computes from the transaction. A connector
  asset's atom never issues a round's sweep token.
- **Round-shaped transactions** carry the round's connector output, whose only
  spend is the issuance of the round's connector asset
  (`arca_covenant::ConnectorPolicy`), right after the outputs they pay, then
  change per asset, then the one fee output. A round transaction also issues
  each batch's sweep token from one of the wallet's coins per batch, those
  coins first among its inputs; each token's id follows from that coin's
  outpoint and a zero contract hash. The token is issued with denomination 8,
  which is what the kit's PSET signs an issuance as, and the wallet sets the
  PSET's output index of an issuing input back to the outpoint's own (the kit
  keeps the issuance flag in it).

## The nursery

The nursery keeps every transaction the server relies on broadcast until the
finality service calls it final: the server's own (a round, a wallet
transaction, the watcher's, each with its fee asset named) and those it relies
on without having built them (a board). A transaction enters byte for byte and is only
ever broadcast again as those bytes: the nursery never builds a replacement,
so a round returns with its txid and every forfeit signed for it still holds,
and a board returns as its owner signed it.

When a rollback disconnects a block holding one of them, final or not, it goes
back to pending and is broadcast again at once, oldest first, so a parent
precedes its child. On each pass a transaction the finality service calls
final is marked final (and stays watched, since a rollback can take it out
again), one not in the chain is broadcast again, and one whose input a final
transaction of another txid has spent, whatever first watched that input, is
marked lost, freeing the wallet coins it held: it can no longer confirm, and
what depends on it learns so. So is a transaction of the watcher's the node
refuses for a missing input whose own transaction is in no block of the
followed chain, not in the mempool, and not one the nursery holds as pending:
a claim whose atom's issuance an anchor-driven reorganisation took out and
another spend of the connector replaced, say. Nothing final ever spends an
outpoint that does not exist, so the first rule never catches it; once it is
lost the watcher does its work again.

## Testing

The tests run against a real PostgreSQL server. `ARCA_TEST_POSTGRES` names it,
with a database to connect to for administration; each test creates a database
of its own there, builds the schema in it and drops it at the end. The tests
that need a chain run `sequentiad` (named by `SEQUENTIAD_EXEC`) on an anchored
proof-of-stake regtest chain (`sequentia_ext::regtest::Regtest::start_pos`),
where a committee certifies every block; the cases a live chain will not
produce on demand (a block without its certificate, a certificate arriving
late, a stale anchor, a rollback below where the service started) run against
a chain held in memory. One signer test watches the signer's system calls
with `strace`, which must be on the `PATH`.

    ARCA_TEST_POSTGRES=postgres://user@127.0.0.1:5432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-server

`tests/e2e.rs` runs the server as an operator runs it: `arca-signer` in its own
process holding the operator key, `Server::start` with its tasks and its HTTP
listener, its wallet paid in an issued asset and never the policy asset. A
minimal client (`tests/common/client.rs`), built on `arca-covenant` directly,
drives it over HTTP as a wallet would: it boards, waits for the board to be
credited, makes transfers with each owner's signatures, reads its mailbox with
a signed challenge and validates every coin it receives as a receiver must.
Each of the server's rules is exercised by a refusal, and each refusal is
asserted by its code: a second spend, alone and eight at once; a leaf on the
chain, by a board's conversion seen in the mempool and by a transfer's output
its receiver published; a coin on a board a rollback uncredited; the depth
limit; outputs outside the bounds; a key already owning a leaf; a repeated
output, equal or prefix, alone and after a restart (`salt`), and two at once
(`merge` or `salt`, as the race falls); a bad
signature; an unknown leaf; a board not yet final; the request size bound; and
authentication, a proof replayed with another cursor or page size included. A
challenge is taken across a restart and by a second server on the same
database. A board rolled back, the node restarted with an empty mempool,
is uncredited, broadcast again by the server and credited again; the signer
going away mid-transfer leaves the spend recorded and the same request
completes once it returns; and the server, holding no policy asset, co-signs
and broadcasts a transaction whose fee is in another asset.

`tests/address.rs` runs `arcad <config> address` beside a running server:
each run hands out the next index, the address is the node's for the script
printed, the server's own next script is another, a coin paid to it is the
wallet's and spendable once final, and the index goes on after a restart.

`tests/round_e2e.rs` runs rounds as wallets meet them. Eight participants in
two assets, one giving up coins of both for leaves of both and one leaving half
on-chain, share one round; each validates its leaves from the published trees,
hands over its forfeits and gets its preimage, every new leaf is live, and the
offboard's output is unlocked to its owner's script with the preimage alone.
Then a leaf is unrolled from its published tree and exited by its owner alone:
each node by the owner's own unroll authorisation with its reserve as the fee,
the entry with the preimage, the exit after the exit delay; no signature of the
operator's is made. Once that leaf is on the chain the server refuses to co-sign
a spend of it, and the exit is refused before the delay and when signed by the
operator's key. These run on a proof-of-stake chain, which takes no block its
committee did not make (`generateblock` is refused there), so a refused spend
is refused by the mempool; the covenant's own suite forces each into a block on
a chain that can.

`tests/rounds.rs` turns participations in two assets, X listed for fees and
Y not, into one round: a batch and a token per asset, an offboard, the
connector, nLockTime 0, the operator's coins only, the fee in X, the wallet
holding no policy asset. Once the round is final, each owner validates its
new leaf from the published tree alone, and a published tree with a leaf's
value or unlock hash, the last expiry, the clock's order or the reserve rule
changed is refused. It also builds rounds of 1, 4 and 16 leaves and prints
their sizes.

`tests/margins.rs` refuses transfers whose margins are out of bounds: no
checkpoint margin, no reassignment margin, and either past the cap, in X;
none of either in Y, where one atom each is co-signed. Then R7's P9 with the
cap raised: a board paid out of round with nearly the whole coin left as the
reassignment's margin, then converted; the watcher's checkpoint and
reassignment each pay the fee they need and return the rest to the
operator's wallet, and a block takes the reassignment. `info` publishes the
node's floor in X, and `null` in Y.

`tests/claims.rs` refreshes 16, 200 and 2,000 boards in one round (2,000 is
ignored by default; `-- --ignored` runs it) on a chain of one-minute blocks of
400,000 weight units, the refund delay at its shortest (one unit, 512 s). The
watcher passes once a block, and after each block the test checks every
forfeit in a block whose claim is not: its refund must not be open (the tip's
median time short of the refund delay past that of the block before the
forfeit's), and its owner's refund is refused. Every forfeit is claimed.

`tests/orphan.rs` runs R7's F9: a deep anchor-driven reorganisation (eight
Sequentia blocks) takes out a board's forfeit, the round's atom issuance and
the claim on that atom, and another issuance of the same connector output
takes the first one's place; the forfeit returns, the claim is refused for
its missing input and marked lost, and the watcher claims the forfeit again
with the new atom.

`tests/fee_pool.rs` turns R7's P5 around: eight boards of Y, which the node
does not accept for fees, given up in one round, the wallet holding two coins
of X, a parent block every ten blocks. The watcher publishes all eight
forfeits in one pass, chaining each fee on the change of the one before, and
claims them the next block; no refund. Then a pool too small for eight (fees
at a thousand times the floor): two forfeits go out, six are held back, the
log and the metrics say so, and once the wallet is paid more of X the rest
go out and every one is claimed.

`tests/funding.rs` gives the operator's wallet less of Y than a
participation in Y wants: the round takes the participation in X, the one in
Y waits and says why, and the next round takes it once the wallet is paid
more Y.

`tests/forfeits.rs` runs a refresh end to end: a board, its participation,
the round final, the new leaf validated from the published tree, the forfeit
and the preimage that opens the new leaf's entry, the new leaf live and paid on
out of round, then a second refresh of that batch leaf and the release of its
lowest node, naming the second round's connector asset. Each refusal is
asserted by its code: forfeits before the round and before it is final, for
the wrong unlock hash, the wrong connector (another output, another round),
another coin, another margin, another refund delay or another key, a forfeit
set that is not exact (none, another coin, one twice, one more), no
authorisations, authorisations by another key or not yet usable, a release
before the preimage, by another key, naming another round's connector asset
(`wrong_round`), over the message that named no round, of a board, of a coin
not in the participation, and of a coin with an open reassignment.

`tests/rollback.rs` disconnects a final round: its new leaf is uncredited at
once and a transfer of it refused, a release refused, the round broadcast
again by the server to a node restarted with an empty mempool, final again
with its txid, the leaf credited again and paid on. Then a round that is lost, the
operator's coin it spent taken by another transaction that becomes final and
pays the operator back: the round is retired, its leaves lost, and its participations run
again in a new round under new unlock hashes and operator nonces, as ordinary
participations. The one whose preimage had gone out (giving up a leaf whose
lowest node its owner had released) has its release retired, its old forfeit
does not verify for the new round, and its new forfeit is taken and its new
preimage released against it; no release is taken and no answer carries that
preimage before. The release is void on the chain as well: the lost round's
connector asset cannot be issued, and the node refuses the reclaim of the
released node with the release and the new round's connector asset, or with
none, so the node stays its owner's. The coins given up stay given up. A third,
also released in the lost round, never hands over its forfeit for the new
round: a day after that round is final it expires, and its coin, under a
forfeit signed for the lost round, stays given up, its status saying so. Last,
the owner of the first brings its old coin on the chain after its re-run
completed (its node unrolled by its own authorisation, its entry unlocked):
the watcher answers with its forfeit for the new round, never the lost
round's, and claims it.

`tests/rerun.rs` holds a lost round to its participations' coins. A board
whose forfeit for the lost round the watcher published is never taken into
its re-run: void, saying why, its coin not given back, the server's copy of
that forfeit never broadcast again, no preimage for the re-run; the forfeit,
sent by whoever saw it, confirms and is refunded by its owner once its delay
has run, while the other participation of the round, whose forfeit was never
published, completes in the next round with its preimage. A forfeit for the
lost round the watcher logged and never got onto the chain is given up: not
broadcast on a pass, once the node takes its fee asset again or after a
restart; the log refuses another naming the round; an exit of a coin given up
in it is answered with no forfeit, and that coin, its output spent, is never
taken into its re-run. A sender's change on a board's lineage, and on a batch
leaf's, stays live off the chain after the receiver's re-run completes,
nothing of the lineage published, and the sender pays with it.

`tests/rerun_returns.rs` brings a lost round back, every reorganisation driven
through the parent chain: the round R goes out with its Bitcoin block, another
transaction X takes its input, and its participations run again in Y; then
the parent chain takes X out and R, sent again, confirms in its place. Where Y
spends an input of R that was still unspent, and where it spends X's output
(R's only input taken), the node refuses Y once R is in the chain
(`missing-inputs`), the server restores R and retires Y, A's participation is
back in R, its leaf of R live and its leaf of Y lost (the first unroll of the
one taken, of the other refused), and the watcher claims A's board with its
forfeit for R while its forfeit for Y can never confirm. Where X pays the
operator nothing and R had no other input, the participation is voided,
saying so, and restored when R returns, its board claimed with its forfeit
for R. A participant whose forfeit for R the watcher published while R was
final, voided while R is out, is restored with R and its forfeit claimed with
R's connector asset; one that refunded that forfeit while R was out keeps the
refund, and its leaf of R is never credited.

`tests/watcher.rs` drives the watcher a pass at a time, a block between
passes, except where it runs on its own as the server's task. Refreshed boards
come back to the operator: each forfeit from the board output, one atom of the
round's connector asset, a claim for each; the board's owner can no longer
convert it. A refreshed batch leaf that its owner unrolls and unlocks again (a
stale exit) is answered by its forfeit and claimed, the claim revealing the
preimage of the owner's new leaf; the owner's exit is refused before its delay
and, after it, because the leaf is spent. A board paid out of round and then
converted by its sender is answered, by the watcher's own task while the
conversion is still in the mempool, with the checkpoint and the reassignment;
the sender's exit is refused and the receiver exits the leaf the watcher put
on the chain. A batch of five leaves, part of it unrolled by its owners, is not
released before its expiry, is released at it, is not swept during the notice,
and is then swept in one transaction of exactly what is left of it (a lowest
node and an entry), while the leaf an owner put on the chain exits. A batch
every owner refreshed and released, in two rounds, comes back before it
expires: one unroll of the batch output, a reclaim of each lowest node with an
atom of the connector asset its releases name; nothing is unrolled while two
owners have yet to release. A coin paid out of round from a board and then
refreshed by its receiver waits while the sender's change rests live on the
same lineage: the board shows its dates, and the watcher publishes nothing.
Past the board's exit deadline the change is refused in a transfer
(`invalid_coin`) and taken into a refresh; with no live coin left on the
lineage the watcher publishes, before the board's expiry, the board's
checkpoint, the reassignment and both forfeits, and claims them; once the
claims are final it no longer scans either coin. And an anchor-driven
reorganisation: the parent
chain orphans the block a round and the watcher's answer to a stale exit are
anchored to and every block above; the node disconnects them all, the server
no longer calls the round final, the round and the answers wait in the
mempool and the nursery as pending, and they return with the same txids and
are final again, nothing built a second time; the owner's exit is still
refused. A test waits before it makes a block for every transaction in the
nursery to have gone to the node once: the watcher logs a transaction before
it broadcasts it, so its own task's answer may be in the log a moment before
it is in the mempool.

`tests/refusal_codes.rs` reads every refusal code out of the server's source
(each `code()` of its refusals, each refusal the HTTP layer makes itself) and
compares them with `api::REFUSAL_CODES`, both ways; a code is answered with a
4xx exactly when the request was not taken.

`tests/offboard.rs` runs offboards. In X, which the node accepts for fees, and
in Y, which it does not: nothing is unlocked before the owner's forfeit; then
the watcher unlocks each output to its destination, the margin paying in X and
a coin of X paying for Y, and the boards given up come back, Y's forfeit and
claim paid by coins of X. An offboard whose owner never hands over its forfeit
expires with its participation: the coin is the owner's again, the output is
neither unlocked nor reclaimed early, a reclaim signed before the delay is
refused by the node, and after the delay the watcher reclaims it. An owner who
offboards a batch leaf, is paid on-chain and then brings the leaf back
on-chain is answered by its forfeit and the claim, and its exit is refused.

`tests/expiry.rs` moves the chain's median time on. A participation whose
forfeits have not come a day after its round was found final expires: its
coin is live again and given up again in a new participation, its new leaf is
expired, a good forfeit for it is refused and stores nothing, its new leaf's
key is free again and wanted by the new participation, and a participation of
the same round whose
forfeits came is untouched. On batch leaves of a round whose first expiry is
`E`: six days before `E` a refresh is charged for the day before the free
window, and refused one atom short; four days before it is free and runs; a
round time asked for past the exit deadline is refused; past the exit
deadline a coin is refused; and a participation accepted before the deadline
whose coin passes one day before `E` with no round taking it is voided by the
next round, its coin live again.

`tests/signer.rs` runs `arca-signer` as its own process: its key, a
rebindable message, and the spend of a clock's release whose signature verifies
over the signature hash the library builds; it refuses a raw digest, a stray
field, outputs out of range, an oversized line, a spend by the leaf's
collaborative path or the owner's exit, an input out of range, spent outputs
missing, and an input that spends no taproot output. Its record: a spend
signed again when asked again and a second spend refused; another holder's
leaf under the same salt refused another message once the first leaf spent
under it, and signed the same message; an owner signature by another key,
over another message or for another salt refused and not recorded; forfeits of one coin for two rounds
signed and a second forfeit for one round refused; a spend after forfeits and
a forfeit after a spend refused; forfeit parts that do not make the output
refused and not recorded; the same refusals after a restart; a last line cut
short dropped, and a line that does not read, or a record kept by salt alone,
refusing the start. And the record's integrity: no start where there is no
record, and nothing made there; `--create-record` making one of mode 0600,
and refusing where one is; a second signer on one record not starting; the
record cut back to an older copy refusing the request that names the
database's later entry (`record_behind`), and everything after it; a copy
another signer wrote refusing the database's entry (`record_differs`); a write
past a file size limit undone at once and the next entry whole once there is
room; a line cut short by a crash removed at start, which says so; a whole
line a crash left unsynced read as the head after a restart, with the record
opened, then `fsync`ed, before the first answer is written (watched with
`strace`); an edited line, and a record of another key, refusing the start. Its compaction: no
compaction while a signer holds the record, nor over a file that is there;
the entries under the salts listed dropped, each leaving a line with its
running hash, the rest carried over verbatim, the new record going on from
the old one's latest entry; the signer on it refusing another message under a
salt carried over, signing the same message again as its entry, taking a
dropped salt afresh, answering the running hash at a dropped entry, a head
of it signed before the compaction stopping nothing, accepting the
database's knowledge of an entry compacted away whose hash it kept and
refusing another hash there (`record_differs`), listing its entries; a
carried line changed refusing the start; and a compacted record compacted
again. And the signed head: every rebind's entry and `head` signed by `S`; an
unsigned head, one signed by another key or for another chain, a signature
moved to another hash or entry, garbage, and a head the record holds each
stopping nothing; a record rolled back to an older copy and signing two
entries of another branch, handed the head it lost, stopped, the proof
written beside it, every rebind and `head` refused (`stopped`) across a
restart while the spend of one of the operator's own paths is still signed;
`--clear-stopped` removing the proof, after which it signs again; and a
signed head past the record's end stopping it as well. And the witness's
answer as the signer's own word: every running hash answered signed as a
head, nothing signed past the end, the end signed with the request's nonce
and with no other, an end's signature not a head's nor a head's an end's;
a stopped signer answering with the head that stopped it, as handed over,
and its end before it signed with the nonce, across a restart, and, stopped
on another hash at an entry it holds, with the head it holds there, signed.
And the witness's bounds: on a record of 5,000 entries, 32 heads with
garbage signatures at entries read back from the file refused, with no read
of the record (watched with `strace`), four of them answered, and 32 heads
the signer signed answered, each read back.

`tests/keeper.rs` runs the signer with `arca-keeper` processes, each on a
port of its own: every rebind answered only with the keeper's
acknowledgement, which verifies under its key and not another's, the head
in its file, and `head` carrying it; the keeper down, the entry recorded
and `keepers_unavailable` answered with nothing signed, the same request
completing as the same entry once it is back; a signer's record restored to
entry 2 while the keeper holds entry 4, stopped at start, every rebind
(the second spend of a lost entry's salt among them) refused `stopped`, its
witness showing the keeper's head as the proof; behind a proxy, an
acknowledgement signed by another key, one replayed from an earlier
request, and a latest replayed at a start each refused, nothing signed; a
keeper restored from an older copy stopping nothing and taking the
record's latest; two keepers with one required, one down holding nothing
up, a start with one down signing nothing until it is back; and what a
keeper adds to a co-signature, printed.

`tests/signer_record.rs` runs it with the server: after a payment the
database knows entry 2; the record replaced by its empty copy, the next
payment is answered `signer_unavailable` (`record_behind`) and the server does
not start, naming both entries; with the whole record back the server starts
and the payment, sent again byte for byte, is co-signed. And a batch leaf paid
on out of round, past its batch's last expiry: `expired_salts` lists its salt,
the salt of the coin it paid and both checkpoints', never a board's; the
record compacted with that list, the server starts on it, its database's
entry the compacted record's latest.

`tests/salts.rs` names other leaves' salts. A transfer to a leaf of the
attacker's under a batch leaf's salt read from the public tree, two new leaves
of one transfer under one salt, a board under a transfer output's salt (its
operator nonce unused), and a transfer to a leaf under the salt promised to a
participation not yet in a round are each refused with `salt`, naming it; the
holders whose salts were named then pay and refresh as usual. With one salt
deleted from the database, as one restored from an older copy would have
forgotten it, the attacker's leaf under it is co-signed and spent, and its
holder's own payment is then refused by the signer (`double_spend`): the rule
is the salt's. And the case it guards: an attacker pays from its leaf, its
database forgets the leaf's salt, and it makes a second leaf of its own under
that salt and pays from it: the signer refuses the second spend under the
salt, which would have been a signature valid on the first coin too.

`tests/transfer_values.rs` asks for one transfer twice, the second time with
another checkpoint value: a coin a transfer makes is named by its inputs' ids,
their checkpoints' programs and the outputs, not by the checkpoints' values,
so both would make coins of the same ids. The second is refused (`salt`: its
outputs' salts are known), and the signer, asked directly for the other
value's checkpoint with the owner's signature over it, refuses it too
(`already_signed`): the operator co-signs one checkpoint value for a coin, so
at most one record of a coin ever carries its signatures.

`tests/restore.rs` restores the database from an older copy. A board pays B
and the copy forgets it: the server does not start on it, naming the two
entries of the signer's record the payment made; B's coin validates and its
checkpoint and reassignment are taken by the node, and behind the record's
check the chain's refuses the start too, naming the board's spend. A copy
taken mid-round, the round final and the forfeit not yet handed over, does
not start either, naming the forfeit; the latest state starts. A round
built after the copy makes the server refuse to start on it, naming the
round. Database and signer's record rolled back together past a round
built and forfeited after the copy agree with each other, and the server
still does not start, naming the round the chain holds. A forfeit whose
operator's half was never stored is given it at start, and the signer's
record does not grow. A copy older than twelve
entries is refused naming the first ten, the check stopping there rather
than read the whole of a long record against it.

`tests/limits.rs` bounds what the calls anyone may make leave behind: junk
boards whose transactions the node refuses leave no row and nothing in the
nursery; nonces asked for a thousand times are handed out within the rate and
deleted once expired, and a thousand challenges are each handed out and leave
no row; a board the node took that never confirms is dropped. A stranger
asking about a hundred times a second for each, through the proxy, leaves an
honest wallet asking once a second every one of its twenty, and gets its own
share of nonces and no more; a caller naming a new source in every request,
from no trusted proxy, is counted as the address that connected. Six sources
each asking every 10 ms, each held to its own rate, leave an honest caller
from a seventh every challenge and every nonce it asks for over 30 s. The
witness's budget is its own: with nonces held to one in all, twenty witnesses
from five sources are each answered, and with witnesses held to two in all,
the third is refused while nonces go on.

`tests/participations.rs` takes a participation over HTTP (its status, the
same request again) and refuses, each by its code: a coin given up already,
in a participation and in a transfer; an attestation by another key or for
another participation; amounts one atom off either way and a fee in another
asset; a fee one atom short of the schedule; a key wanted twice, wanted
already, or owning a board; a template a round does not build; an exit
delay, an asset, a leaf value or a round time outside the bounds; an offboard
to an Arca script; an unknown coin, a board not yet final, a stray field, a
coin given twice, and an unknown participation. A
participation naming a key it does not hold (another holder's receive key)
is refused, without a key proof and with one by another key
(`bad_attestation`), and a payer then pays that key; a key wanted by a
participation that expired, or that a round voided because its board coin
passed its last round time, is free again and paid.

The user needs the right to create databases. A throwaway server in user
space is enough:

    initdb -D /tmp/arca-pg -U arca --auth=trust
    pg_ctl -D /tmp/arca-pg -o "-p 55432 -k /tmp" start
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres cargo test -p arca-server
