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
[`schema/V4__participation_waiting.sql`](schema/V4__participation_waiting.sql)). `Store::connect` builds it
from nothing on an empty database and brings an older one up to date: the
migrations are applied in order, each once, under a lock.

What the database holds, and the rules it enforces itself so that no two
requests can race past them:

- **Leaves, keyed by leaf id.** Every coin the server knows (a board, a leaf
  of a batch, an output of a transfer) is a row keyed by its leaf id, never by
  an outpoint, with its coin record, from which its lineage and every
  transaction that brings it on-chain follow. A key owns one leaf.
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
  mailboxes, authentication challenges, the on-chain wallet's coins and the
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
  database or from any older copy; it lives on its own durable storage and
  only grows. It is what keeps `S` from co-signing a second spend of a coin
  whatever the database says, so a database that has lost a transfer gets a
  refusal (`double_spend`) where it would co-sign the second spend. A record
  lost or rolled back opens that hole again, so the signer is not run without
  its record whole.
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
transaction that does not pay the board output exactly once, a nonce it never
issued or already gave a leaf, a key that already owns a leaf or is the
operator's own `S` (`operator_key`), a script it already knows, and another transaction for a board already registered. The
node must then take the board transaction: it is in a block or the mempool
already, or `testmempoolaccept` allows it. One the node refuses (an input that
does not exist, say) is refused with `not_accepted` and the node's reason, so
a board nobody can pay never reaches the database or the nursery. A refused
board leaves nothing behind, its nonce included.

A registered board goes into the nursery and is credited, its leaf becoming
the owner's to spend off-chain, only once the finality service calls its
transaction final. A rollback that takes a credited board out uncredits it at
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
- nothing of the coin's lineage, its own leaf included, has been seen paid on
  the chain, in a block or in the mempool, and every board it rests on is
  credited and unspent: an Arca leaf on the chain past its exit delay can be
  exited by its owner at once, so the server co-signs no off-chain spend of
  it, a converted board included;
- the new coins are at most five reassignments from a round or a board;
- each new leaf is within the published bounds: an asset served, a value
  within its bounds, an exit delay within the bounds, a key that owns no other
  leaf and is not the operator's `S` (`operator_key`), a script never seen;
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
  the fee a fee the node refuses. Both bounds are published (`info`).

The transfer is then recorded, inputs spent, before the operator key signs
anything, so the server never signs a spend it has not durably recorded and
two spends racing for one leaf leave exactly one standing. Each new coin's
record is checked by the server as a receiver would check it, stored, and
posted to the receiver's mailbox (the leaf's key, unless the output names
another). A request repeated byte for byte gets the same answer; one that
found the signer unreachable completes when repeated. Transfers are free.

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
owner key and nonce, its exit delay, asset and value) or an offboard (an asset,
a value and the on-chain script to pay). The server accepts it only when:

- every coin given up passes the same check as a transfer's input: known,
  live, given up nowhere else, its record valid, every board it rests on
  credited and unspent, nothing of its lineage on the chain, and its first
  expiry at least three days ahead: a coin is taken only up to its exit
  deadline. Its attestation verifies, and an earliest round time asked for
  lies before every coin's exit deadline;
- every leaf wanted is within the published bounds, under a key that owns no
  leaf, that no other participation wants and that is not the operator's `S`
  (`operator_key`); every offboard pays a served
  asset within its bounds to a script that is not an Arca script;
- per asset, the coins given up hold exactly what the outputs take plus the
  fee, and the fee covers the schedule.

It then chooses the participation's unlock hash and keeps its preimage,
draws an operator nonce of its own for every leaf wanted (taken at once, so
never handed out again), prices each forfeit's margin and each offboard
output's margin from the node's floor in that asset, and records everything in
one database transaction, the coins given up becoming spent by the
participation. The same request again is the same participation and gets its
status.

The participation's id is
`SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body)`, `T = SHA256("Arca/participation")`,
where the body is the request without its attestations: the leaf ids given up,
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
beyond it; a coin from boards alone never expires and pays the whole of it. An
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
reserve rule and the smallest leaf, and every leaf as the builder took it
(template, owner key and nonce, operator nonce, exit delay, value, unlock
hash). From that alone a wallet, an explorer or any mirror rebuilds every
script of the tree with `Tree::build` and checks the leaf it cares about
against the round transaction with `LeafRecord::validate`.

### Rollbacks

A round the chain loses goes back to the nursery's care. When a rollback
disconnects it, its new leaves are uncredited at once: a leaf whose round is
not final is not live, and no coin resting on one is co-signed. The nursery
broadcasts the round again byte for byte, so it returns with its txid, every
forfeit signed for it still good, and its leaves are credited again once it is
final again.

A round that can never return (the nursery finds an input of it spent by
another transaction that is final) is retired, in one database transaction:
the round is lost, its new leaves not yet spent are lost, and every
participation it ran runs again in a later round, under a new unlock hash and
with a new operator nonce for each leaf it wants (its keys and owner nonces as
before, so its owner's wallet recognises the new leaves), the attempt it
leaves recorded. A round with another txid is always a new round with new
hashes: nothing signed for the old one carries over. A participation whose
preimage had gone out runs again forfeit-first: its forfeit for the new round
is taken, and its new preimage goes out only through the claim of that
forfeit, once published. The coins those participations gave up stay given up,
so the operator co-signs no other off-chain spend of them, and any release of
their lowest nodes given for the lost round is retired: it names the lost
round's connector asset, which can never be issued, so no reclaim can use it.

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

The signer then signs the operator's half of each forfeit, which the server
checks and keeps: it is never returned to anyone, and leaves the server only
inside a forfeit the operator publishes. An owner therefore never holds a
forfeit it could publish itself. In one database transaction the forfeits are stored, each new leaf's
coin record filled in, the participation released and its new leaves
credited; only then does the preimage go back. The same request again gets
the same preimage. A participation that runs again forfeit-first, after a
round it was released in could not return, has its forfeits stored and its
preimage withheld: that preimage goes out only by the claim of the forfeit,
once published, which reveals it on the chain. The watcher publishes it (see
below), and releases the participation once the claims are final; the same
request again then returns the preimage, whatever the chain has seen of the
coins given up meanwhile.

A new leaf is live, and can be paid on out of round, once its participation
is released and its round final; a coin resting on a leaf of a round that is
not final is not co-signed (`round_not_final`).

The forfeits are due within a day of the round being found final. A
participation whose forfeits have not come by then expires: its new leaves
are never credited (their preimage never goes out, and the operator sweeps
them with their batch at expiry), and each coin it gave up for which no
forfeit was signed is given back, live again and free to be given up again. A
coin under a forfeit signed for an earlier round that could not return stays
given up. A forfeit step that reaches the server after the expiry, even one in
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
`recovery_interval_seconds`, it does the rest. It never builds a second spend
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
- **Boards given up in a round.** A board never expires, so once the round it
  was given up for is final the watcher publishes its forfeit from the board
  output itself, and claims it. A coin of a transfer given up in a final round
  whose lineage rests on boards alone never expires either: the watcher
  publishes each board's checkpoint from the board output, and the answers to
  stale exits carry it through each reassignment to the coin's forfeit. A coin
  resting on a batch leaf is left to that batch's sweep.
- **Claims.** Each forfeit the watcher published is claimed with the preimage
  of its unlock hash and an atom of its round's connector asset `M`. The
  watcher issues that atom from the round's connector output when it holds
  none, to the wallet, and every claim pays it back to the wallet for the
  next; claims of one round therefore follow one another, a block apart.
- **Forfeit-first.** A participation run again after a round that could not
  return has its forfeits stored and its preimage withheld. The watcher brings
  each coin it gave up onto the chain from the coin's own record (each node of a
  batch leaf's path by its owner's unroll authorisation, then its entry with
  its preimage; the checkpoint of any board in its lineage), so the answer to
  stale exits publishes its forfeit; it claims the forfeits, which reveals the
  preimage, only once all of them are final, and releases the participation
  once the claims are final.
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
asset is assumed, the policy asset included. A coin that pays a fee is taken
until its change is final, so an operator keeps several coins in each fee
asset; a step the wallet cannot pay for waits, and is logged.

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
| `GET info` | The operator key, genesis hash, assets served with their smallest leaf, exit-delay bounds, depth limit, the finality rule, the template list and its version, the fee schedule with its free window and the bounds on a transfer's margins (`margin_multiple`, `max_margin_multiple`), a participation's exit deadline and forfeit deadline, the request limit |
| `POST operator_nonce` | A fresh operator nonce, for a board, good for an hour by default |
| `POST challenge` | A challenge to authenticate with, good once, for a short while |
| `POST register_board` | Registers a board record with its transaction |
| `POST board_status` | A board's state (`pending`, `credited`, `lost`) and its transaction's finality |
| `POST cosign_transfer` | Co-signs an out-of-round transfer and delivers its coins |
| `POST submit_participation` | Accepts a participation in a round |
| `POST participation_status` | A participation's state (`pending`, `issued`, `released`, `void`, `expired`), its unlock hash, its forfeits' refund delay and margins, its round and where each of its outputs is in it, and while it is pending why the last round did not take it (`waiting`) |
| `POST tree` | The published tree of a batch, by its round's txid and output |
| `POST forfeit_leaves` | Takes a participation's forfeits and its new leaves' unroll authorisations, and returns its preimage |
| `POST release_leaves` | Takes an owner's release of the lowest node of each coin it gave up, each naming the connector asset of the participation's round |
| `POST mailbox_read` | The coin records in a key's mailbox after a cursor |
| `POST leaf_data` | The leaves a key owns (`pending`, `live`, `spent`, `lost`, `expired`), with their records; a round's leaf is served with an empty record until its participation's preimage went out |

`mailbox_read` and `leaf_data` need a proof of the key: a challenge from
`challenge`, signed with BIP340 over the tagged hash
`SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key)` with
`T = SHA256("Arca/auth")`. The tag keeps it apart from everything else a leaf
key signs, the genesis hash to one chain, the call to one request, the
challenge to one use. There is no bearer token. `cosign_transfer` is
authenticated by the owners' signatures over the transfer itself, and
`submit_participation` by each owner's attestation over the participation;
`participation_status` needs only the participation's id, which is a hash
of its request, and `tree` is public. `forfeit_leaves` and `release_leaves`
are authenticated by the owners' signatures over the forfeits and releases
themselves.

The two calls that write a row for anyone who asks, `operator_nonce` and
`challenge`, are each handed out at a bounded rate (`[limits]`: five a second
with bursts of fifty, by default, for the server as a whole); a request past
it is refused with 429 `rate_limited`. A nonce no board took within its
lifetime (`nonce_ttl_seconds`), and a challenge once used or expired, is
deleted, so what these calls hold in the database is bounded by the rate times
the lifetime. A board naming a deleted nonce is refused (`nonce_unknown`): a
wallet registers its board right after it takes the nonce.

## The signer

The operator key `S` lives in `arca-signer`, a process of its own; the server
never holds it. It loads the key from a file only its owner can read (it
refuses one others can), listens on a Unix socket of mode 0600, and answers
three requests: its public key; `S`'s signature over the rebindable message of
a collaborative path, which it builds itself from the parts (the salt, the
coin's asset and value, one to four committed outputs, and for a forfeit the
forfeit's own parts) on its own chain; and
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
signature it appends the salt, the kind and the message's digest to its
record, an append-only file it alone writes, and syncs it to disk; it reads
the record whole when it starts, and refuses to start on a line it cannot
read (a last line cut short by a crash was never answered, and is dropped).
For each salt (a leaf's, a board's, a checkpoint's) it signs one spend, a
message into anything but a forfeit output, or forfeits, one for each round's
connector asset: a forfeit request names the forfeit's parts, and the signer
rebuilds the forfeit output from them and checks it is the one output
committed to. The same message again is signed again, so a request repeated
after a signer outage completes; a second spend, a spend after a forfeit, a
forfeit after a spend, and a second forfeit for one round are refused
(`already_signed`), whatever the database holds. The server answers such a
refusal with `double_spend`, and logs that its database has lost a spend.

## Running

    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --socket /run/arca/signer.sock \
        --record /var/lib/arca/signer.record
    arcad /etc/arca/arcad.toml

[`arcad.example.toml`](arcad.example.toml) lists every setting: the listen
address, the database, the signer's socket, the wallet's mnemonic file, the
node's RPC, the finality rule, the exit-delay bounds, the assets served
with their smallest leaf, how often a round is built, the assets a round's
fee is paid in, the fee schedule, the watcher (`[watcher]`: whether it
acts on its own, early reclaims, the most outputs a sweep takes, how often its
recovery work runs), and the limits on what the unauthenticated calls leave
behind (`[limits]`: the rate of nonces and challenges, a nonce's lifetime,
how long a board may stay out of every block). The node must run with `-txindex` and `-validateanchor`.

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
what depends on it learns so.

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
limit; outputs outside the bounds; a key already owning a leaf; a mergeable
reassignment, equal or prefix, alone, at once and after a restart; a bad
signature; an unknown leaf; a board not yet final; the request size bound; and
authentication. A board rolled back, the node restarted with an empty mempool,
is uncredited, broadcast again by the server and credited again; the signer
going away mid-transfer leaves the spend recorded and the same request
completes once it returns; and the server, holding no policy asset, co-signs
and broadcasts a transaction whose fee is in another asset.

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
operator's wallet, and a block takes the reassignment.

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
with its txid, the leaf credited again and paid on. Then a round that can never
return, the operator's coin it spent taken by another transaction that becomes
final: the round is retired, its leaves lost, and its two participations run
again in a new round under new unlock hashes and operator nonces. The one whose
preimage had gone out (giving up a leaf whose lowest node its owner had
released) runs forfeit-first: its release is retired, its old forfeit does not
verify for the new round, its new forfeit is taken and its preimage withheld.
The release is void on the chain as well: the lost round's connector asset
cannot be issued, and the node refuses the reclaim of the released node with
the release and the new round's connector asset, or with none, so the node
stays its owner's. The other completes as before, and the coins both gave up
stay given up. A third, also released in the lost round, never hands over its
forfeit for the new round: a day after that round is final it expires, and its
coin, under a forfeit pair for the lost round, stays given up. Last, the
watcher completes the forfeit-first run: it unrolls the old coin's node by its
owner's authorisation and unlocks its entry, from the server's own record of
the coin, publishes the forfeit for the new round, claims it once final, which
reveals the new preimage on the chain, and releases the participation once the
claim is final; its new leaf is live, and the same forfeit request returns the
preimage the claim revealed.

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
refreshed by its receiver comes back: the board's checkpoint, the
reassignment, the coin's forfeit and its claim. And an anchor-driven
reorganisation: the parent
chain orphans the block a round and the watcher's answer to a stale exit are
anchored to and every block above; the node disconnects them all, the server
no longer calls the round final, the round and the answers wait in the
mempool and the nursery as pending, and they return with the same txids and
are final again, nothing built a second time; the owner's exit is still
refused.

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
key cannot be wanted again, and a participation of the same round whose
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
signed again when asked again and a second spend refused; forfeits of one
coin for two rounds signed and a second forfeit for one round refused; a spend
after forfeits and a forfeit after a spend refused; forfeit parts that do not
make the output refused and not recorded; the same refusals after a restart;
a last line cut short dropped, and a line that does not read refusing the
start.

`tests/restore.rs` restores the database from an older copy. A board pays B,
the copy forgets it, and the same board's spend to C is refused by the
signer's record (`double_spend`, `already_signed`); B's coin validates and its
checkpoint and reassignment are taken by the node, after which the server
refuses to start, naming the board's spend it has no record of. A round built
after the copy makes the server refuse to start on it, naming the round.

`tests/participations.rs` takes a participation over HTTP (its status, the
same request again) and refuses, each by its code: a coin given up already,
in a participation and in a transfer; an attestation by another key or for
another participation; amounts one atom off either way and a fee in another
asset; a fee one atom short of the schedule; a key wanted twice, wanted
already, or owning a board; a template a round does not build; an exit
delay, an asset, a leaf value or a round time outside the bounds; an offboard
to an Arca script; an unknown coin, a board not yet final, a stray field, a
coin given twice, and an unknown participation.

The user needs the right to create databases. A throwaway server in user
space is enough:

    initdb -D /tmp/arca-pg -U arca --auth=trust
    pg_ctl -D /tmp/arca-pg -o "-p 55432 -k /tmp" start
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres cargo test -p arca-server
