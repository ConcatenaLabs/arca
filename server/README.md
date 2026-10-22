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
[`schema/V15__rerun_ties.sql`](schema/V15__rerun_ties.sql),
[`schema/V16__keepers_pinned.sql`](schema/V16__keepers_pinned.sql),
[`schema/V17__leaf_reserving.sql`](schema/V17__leaf_reserving.sql),
[`schema/V18__lightning_send.sql`](schema/V18__lightning_send.sql),
[`schema/V19__lightning_receive.sql`](schema/V19__lightning_receive.sql),
[`schema/V20__pending_coins.sql`](schema/V20__pending_coins.sql),
[`schema/V21__takes.sql`](schema/V21__takes.sql),
[`schema/V22__round_fills.sql`](schema/V22__round_fills.sql),
[`schema/V23__lightning_internal.sql`](schema/V23__lightning_internal.sql),
[`schema/V24__distributions.sql`](schema/V24__distributions.sql),
[`schema/V25__shared_fills.sql`](schema/V25__shared_fills.sql),
[`schema/V26__plans.sql`](schema/V26__plans.sql),
[`schema/V27__resting_orders.sql`](schema/V27__resting_orders.sql),
[`schema/V28__issuer_operated.sql`](schema/V28__issuer_operated.sql),
[`schema/V29__fill_requests.sql`](schema/V29__fill_requests.sql),
[`schema/V30__order_landings.sql`](schema/V30__order_landings.sql),
[`schema/V31__supervised.sql`](schema/V31__supervised.sql)). `Store::connect` builds it
from nothing on an empty database and brings an older one up to date: the
migrations are applied in order, each once, under a lock.

What the database holds, and the rules it enforces itself so that no two
requests can race past them:

- **Leaves, keyed by leaf id.** Every coin the server knows (a board, a leaf
  of a batch, an output of a transfer) is a row keyed by its leaf id, never by
  an outpoint, with its coin record, from which its lineage and every
  transaction that brings it on-chain follow. A key owns one leaf; a leaf of
  a participation that expired, never credited, owns none.
- **Mailbox bindings.** A wallet draws a fresh owner nonce, and so a fresh
  key, for every leaf it asks for, and a wallet restored from its mnemonic
  knows none of them; it knows its mailbox key, which follows from the
  mnemonic and the account. So each leaf a wallet asks for names that key,
  with the leaf's owner key's signature over the binding (below): the server
  keeps one binding per owner key, the first, and only for a key that owns
  a leaf or that a participation wants, so a stranger writes no row. A
  transfer's output is bound to the mailbox it was posted to. `leaf_data`
  re-serves a leaf to its own key and to the mailbox key it is bound to, and
  every leaf has a cursor, the order the server learned of it in, that the
  re-serving pages by.
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
  The files the signer keeps beside its record live with it, on the same
  storage, and are never restored or edited either: `<record>.acknowledged`
  and `<record>.keepers-seen` ([The keepers](#the-keepers)), and
  `<record>.stopped`, the proof of a rollback.
- A record and a database rolled back together (a snapshot of the whole
  machine restored) pass every check the server makes of itself, so the
  record is held outside the machine: by keepers on other machines, which
  hold every head before the signer answers it and which the signer asks
  before it signs anything after a start ([The keepers](#the-keepers)), and
  by the wallets that witness it; a proven rollback stops the signer
  ([The signed head, witnessed](#the-signed-head-witnessed)). Keep each
  keeper's heads file off the signer's machine and out of its snapshots.
- The server pins the keepers of the signer's record in the database the
  first time it reads them from the signer (`keepers_pinned`), as a wallet
  pins them, and refuses to start against a signer that names another set,
  naming both: that signer runs on another record than the operator's, made
  anew or with its first line edited. While the server runs it reads the
  signer's keepers again at `info` and once a minute: a signer that names
  another set since (swapped under the running server) stops it serving,
  every call answered `signer_replaced` (503) with both sets named, and the
  reason in its log; `info` never shows another set, so no wallet made then
  pins one.
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

Each asset is served on its own: its boards, its batches and rounds, its
pool (the operator's wallet's coins of it) and, when the operator names one,
its rate source. An asset the operator does not
serve is refused at every entry, `out_of_bounds` with its id named: a board
of it, a transfer's output in it or a coin of it given up, and a
participation's leaf, offboard or fee in it. Adding an asset takes its entry
in the configuration and coins of it paid to the operator's wallet, and no
restart: `arcad` takes the assets anew on SIGHUP (see Running).

### The equivocation bond

The operator key `S` co-signs every out-of-round spend, and the signer signs
one message under a coin's salt, ever (see "The signer"). Two different
messages `S` signed under one salt are therefore proof that `S` signed twice,
and the bond is a coin that anyone holding that proof burns
(`arca_covenant::bond`). The slash pays no one: it burns the whole bond with
a bare `OP_RETURN`, and its fee comes from a coin its broadcaster attaches.
A slash needs no key, so any holder or watcher who has the two signatures
can send it.

The bond is posted in any asset the operator chooses, and is withdrawn only
in two steps, both signed by the withdrawal key `W` (never `S`, since the
signer signs whatever path names `S` for the server). First comes a notice,
which moves the bond whole into a second output that still carries the slash.
The withdrawal can confirm only a delay `D` after that notice, by median time.
`D` is at least a coin's lifetime (28 days) plus the longest exit delay plus
a day. That gives the holder of every coin paid out of round before the
notice the time to have it refreshed in a round, or to take it home on the
chain, while the bond still stands. The server refuses to start with a
shorter `D`, and with `W` equal to `S`.

`[bond]` in the configuration holds its terms:

- `withdraw_key`: `W`.
- `notice_units`: `D`, in 512-second units.
- `outpoint`: the bond coin, once it is posted.
- `notice`: the notice output, once a notice is given.

`info.bond` names the bond as the server's node shows it, read again every
ten seconds:

- `state`, one of:
  - `unposted`: no coin is configured;
  - `missing`: the coin is not at the bond's script, explicit;
  - `unconfirmed`: in no block yet;
  - `bonded`: unspent;
  - `noticed`: the configured notice output takes it whole and is unspent;
  - `spent`: anything else, a notice the configuration does not name included.
- The coin: its `outpoint`, `asset` and `value`.
- `reference_value`: the value at the operator's rate for the asset.
- `operator`: `S`, the key the bond binds.
- `withdraw_key`, `notice_units`, and both scripts.
- `final`: whether the coin that stands is final.
- `why`: what the state rests on.
- In notice: `notice` and `withdrawable_at`, the median time from which the
  withdrawal can confirm.

The section is absent when no bond is configured. A wallet trusts none of
this until it has checked the coin on its own node.

The commands that work the bond each print JSON:

    arcad bond-key /etc/arca/bond-withdraw.key        # draws W into a new file (0600); prints its key
    arcad <config> bond-address                       # the bond's address and terms (needs the signer, for S)
    arcad <config> bond-post <node wallet> <asset> <atoms> [<fee asset>]
    arcad <config> bond-notice <key file>
    arcad <config> bond-withdraw <key file> <address>

- `bond-post` pays the bond from a node wallet the operator names. It refuses
  a wallet whose name marks it a treasury, a reserve, a bridge's, an escrow or
  another service's. It pays nothing while the operator key has already
  signed two messages under one salt: a salt under which the signer's record
  holds two different digests, or a leaf the database holds operator-signed
  forfeits of for more than one round (a signer that ran a lost round's
  participation again with a second forfeit, before it kept one message per
  salt, left such pairs). Each pair burns any bond under the key in the hands
  of whoever holds the database or a backup of it, so such an operator posts
  its bond under a new operator key. Nor does it pay while the signer's
  record is a compaction that kept no salt it dropped (`salts_lost`): compact
  it again first (see The signer). The fee is in the bond's own asset unless
  another is named, and never falls back to another. It prints the `outpoint`
  line for `[bond]`; add it and restart `arcad`.
- `bond-notice` and `bond-withdraw` sign with `W`'s key from its file. Their
  fee comes from the operator's on-chain wallet: the bond's asset first, then
  the fee assets, then the served assets.
- `bond-notice` prints the `notice` line for `[bond]`. Until that line is
  added, `info` reads the bond as `spent`.
- `bond-withdraw` is refused by the node until the delay has run.

Keep `W`'s file off the server, with a backup: it alone ends a bond.

### Listing the operator in the registry

Wallets find an operator in the Sequentia registry
([sequentia-registry](https://github.com/ConcatenaLabs/sequentia-registry),
its operator records): a record of the operator key, the chain's genesis, the
API's public address, the assets served with their rate sources and fee
schedules, the keepers, the exit delays and expiry, the template list and a
contact, signed with `S`. The registry lists it only when the signature
verifies and the server's `GET info` says what the record says, and checks it
again on a schedule: a record whose server says something else is marked
`mismatched`, so a changed fee schedule, an asset added or a keeper set
changed takes a new record. A wallet checks the signature itself
(`arca operators`, `arca join --from-registry`).

The record is written from the server's own `info` by the registry's
`tools/operator-record.js`, and signed by the signer, which holds `S`, on its
machine:

    node tools/operator-record.js --info http://127.0.0.1:3535 --api https://example.org/arca \
      --contact-name "Example" --contact-domain example.org > record.json
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis> --sign-operator-record record.json > signed.json
    curl -s -X POST -H 'content-type: application/json' --data @signed.json https://<registry>/operators

`--sign-operator-record` reads the key file and the record and nothing else,
so it runs beside a signer that is serving. It signs only a record that names
`S` and the chain of `--genesis`, under the record's own tag
(`sequentia-registry/arca-operator/v1`, `arca_covenant::operator_record`),
which nothing else `S` signs uses: the signature vouches for that record and
can be taken for no spend, head or witness.

### Exchange rates

The operator's exchange rate for an asset comes from a source it names for
that asset (`[assets.rate]`): `node`, the node's own rate for the asset, the
one it values fees in it at (`-con_any_asset_fees`, read with
`getfeeexchangerates`), where the node lists the asset; `file`, a file the
operator's price process writes; or `command`, a program the server runs. A
file or a command gives one reading, `{"rate": <integer>, "time": <unix
seconds>}` (the rate as a number or a decimal string) or the same two numbers
on one line, the time optional: without it a file's reading is as old as the
file, a command's as its run, and the node's as the server's read; a
reading dated more than five minutes ahead of the server's clock is not taken,
since its age would read nothing until then. A rate is
the node's unit: what 10^8 atoms of the asset are worth in atoms of the
reference unit, the unit the node's fee rates count in, which no asset of the
chain is. The server reads every source at its start, at a reload and every
15 seconds; a source that fails leaves the last rate standing, the failure
beside it. `info` publishes each asset's rate with its source, its time, its
age and how long it is good for (`max_age_seconds`, an hour by default), and
whether it is stale.

The rate sets what the operator sets as a value: an asset's smallest leaf
(`min_leaf_value`) and the fixed parts of its fee schedule
(`refresh_base_value`, `offboard_base_value`) may be values in the reference
unit, each taken in the asset's atoms at its rate, rounded up, and published
in atoms beside it. While an asset's rate is stale, or before its source has given
one, the server takes no new work in that asset: a board or a participation
of it is refused `rate_stale` (503), naming the asset, the source, the rate
and its age, and a wallet posts it again later. Work already taken goes on:
a participation accepted before is answered, built into its round, completed
and released; a coin of the asset is paid on out of round; the watcher
answers exits, claims and sweeps; a smallest leaf set as a value takes the
last rate read. Every other asset goes on as before. An asset that names no
source has no rate, and nothing of it is priced from one.

### The Lightning gateway's nodes

The operator runs one SeqLN node for each asset it serves over Lightning, and
one Lightning node on Bitcoin for native BTC. An asset's node is named beside
the asset's pool, rate and fees, by its JSON-RPC socket (`[assets.lightning]
rpc`); the Bitcoin node, and the Bitcoin ark wallets join with Bark for
native BTC, under `[lightning.bitcoin]`. The server speaks to each node as
`lightning-cli` does, one JSON-RPC request on its socket; SeqLN's gRPC
bindings carry no asset. A payment between a leaf and Lightning goes through
the node of the leaf's asset and no other, so no asset leans on another's
node, and native BTC never enters a Sequentia leaf.

The server checks every node at its start, at a reload and every
`[lightning] poll_seconds` (10 by default): the node answers, runs on a
Sequentia network (Bitcoin for the Bitcoin node), and holds at least one open
channel in its asset; whether it runs SeqLN's hold-invoice plugin
(`contrib/holdinvoice-seq`), which receiving needs, is noted. `info` names
each asset's leg (`assets[].lightning`: `up` with the node's id, network,
open channels, what it can send and receive in the asset's atoms and whether
it receives; or `down` with the reason) and the Bitcoin side
(`lightning.bitcoin`: its node and the ark). A request to move value over
Lightning is refused at every entry, with the reason: in an asset the operator
does not serve, `out_of_bounds`; in one it serves with no node, or whose node
runs no hold-invoice plugin when the request receives, `no_lightning`; and
while the asset's node is down (it does not answer, or its channels are all in
other assets), `lightning_unavailable`, a 503, since the request may be taken
once the node is back. A reload (SIGHUP) takes each asset's node anew; one
whose socket changed is checked at once.

### Paying an invoice out of the tree

A wallet pays a BOLT11 invoice in asset A out of its coins in A
(`lightning_send`). The request is a transfer, signed by each coin's owner as
any transfer is, with the invoice beside it: its coins go, through
checkpoints and a reassignment, into one `htlc-1` leaf
([`arca-covenant`](../covenant/README.md)) of the wallet's own key, locked to
the invoice's payment hash, and the change. The leaf's direction is `send`:
the operator claims it with the preimage once its operator delay has run, and
its owner refunds it once the timeout has passed and then its exit delay.
The operator co-signs only when:

- the invoice names asset A (SeqLN's `a` field), and so does every output and
  every coin given up: a coin in one asset never pays an invoice in another
  (`invoice`), and the payment goes through A's node and no other;
- A's node is up (`no_lightning`, `lightning_unavailable` otherwise) and
  decodes the invoice as a valid BOLT11 invoice of its own network (a
  Bitcoin invoice is paid in native BTC, never from a Sequentia leaf), for
  an amount, unexpired a minute from now (`invoice`);
- the leaf is locked to the invoice's payment hash, its operator delay is the
  operator's (`[lightning] operator_delay_units`), its exit delay at least
  `owner_delay_units`, and its timeout between `send_timeout_seconds` and
  twice that past the chain's median time (`htlc`); the invoice's final lock
  time fits in half the time to that timeout at the chain's block interval
  (`invoice`); the hash is no unlock hash of a participation, whose preimage
  the operator hands out (`htlc`);
- the leaf holds the invoice's amount and the operator's fee for it, to the
  atom (`fee`): the asset's `lightning_ppm` of the amount, rounded up, and its
  `lightning_base`;
- no other transfer pays the same hash (`in_use`): an invoice is paid once;
- and every rule of a transfer holds. A plain `cosign_transfer` makes no
  `htlc-1` leaf (`htlc`).

The operator then records the payment, `paying`, and pays the invoice through
A's node (`pay`), spending on routing at most its fee, with the payment's lock
times within half the time left to the leaf's timeout less
`send_stall_margin_seconds` (six hours unless set, and below
`send_timeout_seconds`), so that the payment resolves before the owner's
refund could open through a stall of the chain up to that long, the chain at
half its pace besides: the leaf times out in median time and the lock times
count blocks, and the first blocks after a stall carry the clock, so the
median time leaps the whole stall in a few blocks. Within that margin of the
leaf's timeout a payment is decided as soon as the node can say: claimed
with the preimage at once, failed without waiting for an earlier `pay` to try
another route, and one not started is failed. The node's answer decides
it: `paid`, with the preimage, which proves the payment and makes the leaf the
operator's; or `failed`, once no part of the payment is pending on the node.
A payment whose answer is not known is asked about again every few seconds,
and paid again only when the node never started it; one whose parts all
failed before a restart is decided only once a `pay` an earlier run started
can no longer try another route (`retry_seconds` and two minutes after its
first part). A paid leaf is never co-signed back to its owner (`htlc`), and
the watcher claims it with the preimage should it come on-chain
(`htlc_claim`), its operator delay passed; off the chain it is the
operator's when the round it rests on expires. A failed payment's leaf is
co-signed back, whole and the fee with it, into a new leaf through its
collaborative path. The leaf's refund path stays the owner's should the
operator do neither. `lightning_send_status` answers a payment by its hash,
with the preimage once paid or the reason once failed (`unknown_payment`, 404,
for a hash no payment is recorded for).

A request repeated byte for byte gets the answer it got, whatever has changed
since (the invoice expired, the fees, the node): a wallet whose answer was
lost asks again, and the operator co-signed it already. `info` publishes each
asset's Lightning fees (`assets[].fees.lightning_ppm`, `lightning_base`) and
the terms of the leaf (`lightning.send`: `operator_delay_units`,
`owner_delay_units`, `timeout_seconds`).

### Receiving into the tree

A wallet asks to receive `amount` of asset A (`lightning_receive`) under a
payment hash it chose, whose preimage only it knows, into an `htlc-1` leaf
of a key of its own, its exit delay longer than the operator's delay; it
signs the request with that key, and names the mailbox key the leaf is to
be served to (`mailbox`, with `mailbox_proof`, the leaf key's signature over
the binding, as a refresh's wanted leaves name it), which the operator binds
the leaf to at once, so `leaf_data` serves the leaf from when it is made, and
the payment itself, with the participation that wants its leaf, until it is
claimed or failed back. The operator refuses a request not signed
by the key (`bad_signature`), in an asset it does not serve (`out_of_bounds`)
or serves with no node or with a node that runs no hold-invoice plugin
(`no_lightning`), under a key that owns a leaf or is asked for already
(`key_reused`), under a hash asked for, paid or used as an unlock hash
(`in_use`), or whose leaf, the operator's fee out (`lightning_ppm` and
`lightning_base`, as a payment), is below the smallest leaf
(`out_of_bounds`). A node makes invoices only for preimages it holds, so the
operator has the asset's node make one for the payment under a preimage of
its own (the amount, the asset in SeqLN's `a` field, the description, the
expiry `invoice_expiry_seconds`, the payment secret, route hints and
features, as the node makes any invoice), deletes it unpaid, swaps the
wallet's hash into it, and has the node sign the result (`signinvoice`). It
registers the hash with the node's hold-invoice plugin and answers the
invoice. The invoice's final lock time is twice the leaf's lock, in blocks at
`block_seconds`; the lock is eight sevenths of the leaf's exit delay and
`receive_window_seconds`, since the wallet keeps an eighth of the lock in
hand before the leaf's timeout (the claim's margin) and the window stays
the wallet's to claim the leaf in: with a 36-hour exit delay and the default
window, 48 hours, about 5,770 blocks. SeqLN accepts lock times
up to 20,160 blocks on a Sequentia network, but its `pay` adds up to 2,016
unless the payer raises it (`maxdelay`), so a payer's node needs `maxdelay`
at least the invoice's final lock time and the route's. A payment from
a leaf of another operator over Lightning is held to half the time to its
own leaf's timeout, so it pays such an invoice only with a
`send_timeout_seconds` of about a week or more. A payment from a leaf of this
operator is settled inside it, with no lock time on any channel (below).

The hold plugin holds the payment when it arrives instead of settling it.
Once the parts held, in A, add up to the amount and are locked for that
long, the operator wants the leaf in A's next round: a participation that
gives up no coin and wants one output, the `htlc-1` leaf of the amount less
the fee (direction `receive`: its owner claims it with the preimage once its
exit delay has run; the operator refunds it once its timeout has passed and
then `operator_delay_units`), funded by the operator's pool against the
payment its node holds. The leaf's timeout is half the time the held parts
are locked for, at the published block interval, so the payment outlives
any claim the owner can make: its exit delay, the window and the wallet's
margin lie before the timeout. A payment locked for less is failed back. The wallet completes the
participation as any other (`forfeit_leaves` with no forfeit and its unroll
authorisations for the leaf) and receives the leaf's record and its
entry's preimage.

Only then does the wallet hand over the payment's preimage
(`lightning_receive_claim`), with a transfer of the leaf into a leaf of its
own. The operator checks the preimage opens the hash (`htlc`), that the leaf
is the owner's (its participation released) and that the time to claim is
not over, records the preimage, has its node settle the payment with it,
and co-signs the transfer; no spend of a received leaf is co-signed
otherwise (`htlc`). The payment is never settled before the wallet holds its
leaf. The wallet hands the preimage over only while it could still take the
leaf home by its claim a margin before the timeout (the larger of three
blocks and an eighth of the leaf's lock, from its round's confirmation to
its timeout); once it has, a claim this server does not co-sign leaves the
leaf a home date at which the wallet takes it home on the chain, and the
wallet takes that step, and every other exit step whose date has come,
before it asks the server anything in a `sync`, and again whenever one
comes while it asks. Its schedule names those dates on their own
(`next_exit_at`), for a sync that asks the server nothing (`sync
--exits-only`): an operator that answers slowly holds back no claim. A
wallet that takes the leaf home on the chain claims it there with
the preimage; the server watches each output of a received leaf seen on the
chain, reads the preimage from its claim (looking for a spend made before
the output was watched on the chain itself) and settles the payment the same
way. A payment is failed back when its invoice expires unpaid or part paid,
when its leaf never comes (the participation void, expired, or not built
while its owner would still have its exit delay and half the window), and
once its timeout and the operator's delay have passed by an hour with no
preimage, and its leaf is not on the chain unspent (where its owner could
still claim it) or the held parts are a dozen blocks from their expiry; the
watcher refunds a leaf of such a payment that reaches the chain
(`htlc_refund`). A participation for a leaf that no round took in time is
voided, and its payment failed back, only if no round has taken it
meanwhile. `lightning_receive_status` answers a payment by its
hash: `open`, `accepted` (with its participation and the leaf's timeout),
`claimed` (and whether the node has settled it) or `cancelled` with the
reason; the leaf's exit delay (`exit_delay_units`); once held, what holds it
(`held_by`: `node`, or `send` with that send leaf's timeout, `send_timeout`);
and the preimage once the operator knows it. `info` publishes the terms
(`lightning.receive`: `operator_delay_units`, `window_seconds`,
`invoice_expiry_seconds`, `block_seconds`, and `internal_gap_seconds`, below).

### A payment between two wallets of this operator

A payment out of the tree (`lightning_send`) whose invoice is exactly the
invoice the operator made for an open payment into its tree is settled
inside the operator. The operator's node in the asset cannot pay its own
invoice: SeqLN's self-payment looks the hash up in the node's own invoice
table, and a receive's hash lives only in the hold-invoice plugin, so the
node answers `Unknown invoice`. Instead the payer's `htlc-1` send leaf is the
held payment. Before it signs anything the operator checks that the receive
is open and that its leaf, which times out a gap before the send leaf (the
receive's `operator_delay_units`, the send's `send_stall_margin_seconds` and
an hour, published as `lightning.receive.internal_gap_seconds`), keeps the receive's least lock, eight sevenths of its exit delay
and the window (`htlc`); an invoice an outside payer's payment already holds
at the node is refused (`in_use`). Then it cancels the hold invoice on the
node, so no outside payer can pay the same invoice, and wants the receiver's
leaf in the asset's next round as for any held payment. The gap leaves the
operator the preimage before the payer's refund can open: the latest a claim
of the receiver's leaf on the chain can reveal it is that leaf's timeout and
the operator's refund delay. The receive decides the send: paid with the
preimage the receiver hands over with its claim, a claim on the chain
reveals, or anyone posts (`lightning_preimage`); failed, and co-signed back
to its owner, when the receive is failed back. The node is never settled for
such a payment, and nothing crosses its channels. `lightning_preimage`
takes a preimage for a payment into the tree whose leaf is its owner's and
whose time to claim is not over, from anyone who has it: the payment is
`claimed` with it, its status serves it, and its owner can still claim the
leaf.

A leaf's timeout is computed at the block interval the operator publishes:
a chain running twice as fast would let a claim on the chain come after the
payment's lock time. A payment held and never claimed keeps its leaf's value
in the operator's batch until the batch expires, or until the operator
takes the leaf on-chain and refunds it, while the payer's money is
returned, and its fee is never charged: whoever asks to receive and never
claims pays nothing for it. The leaves of payments held and not yet claimed
are therefore capped in each asset: together they hold at most
`[lightning] receive_cap_ppm` (a tenth unless set) of the operator's pool in
the asset, the pool counted with their values back in it. A request whose
leaf would take them past the cap is refused (`receive_cap`, 409, naming the
cap), and an invoice asked for within it whose payment would take them past
it once held is failed back with the same reason, so the pool keeps funding
the asset's rounds. The cap and the batch's expiry are what bound an
unclaimed receive.

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
registered. A registration may bind the board to its owner's mailbox key
(`mailbox`, with `mailbox_proof`, the board's owner key's BIP340 signature
over `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ owner ‖ mailbox)`,
`T = SHA256("Arca/mailbox-of")`), so that `leaf_data` serves the board to
that key; a proof that is not the board key's is refused (`bad_signature`)
before anything is registered. The
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
server co-signs spends of a coin resting on the board and takes it into a
refresh, as for a coin resting on a batch; after it, the owner takes the coin
on the chain. Past its expiry a
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
  (`invalid_coin` after it: its owner takes the coin on the chain);
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
two spends racing for one leaf leave exactly one standing. Before the signer
signs anything of it, the server asks the signer what its record holds under
each input's salt. When it holds anything there but this transfer's own
spend (the forfeit of a coin given up in a refresh, or another spend), the
transfer is refused `double_spend`, naming that coin and what the signer
holds, with nothing of it signed: its record is dropped and every input
given back, so the other inputs, a swap's other side's included, stay
payable and refreshable. When the transfer is recorded, each of its outputs
is posted to the receiver's mailbox (the leaf's key, unless the output names
another) as a notice that the coin is pending: its leaf, transfer, asset,
value, owner key and nonce, and the median time from which the transfer can
no longer complete (the earliest expiry of a batch its coins rest on). A
receiver that reads it keeps reading its mailbox until the coin comes,
whatever happens between the record and the signature (the signer not
reached, its keepers not acknowledging); a transfer dropped before it is
signed withdraws its notices there, naming why. A transfer recorded by a
server that posted no notices (an operator moved with a transfer in flight)
gets them at this server's next start: each output with no notice in its
mailbox is posted one, naming the owner key but not its nonce, which the
server never kept for a recorded output; the receiver finds the nonce by the
key. A notice is the operator's
statement, not a payment: the receiver holds for it only while
`transfer_status` shows its transfer recorded with that output, asking when
it reads the notice and at every sync after. Each new coin's
record is checked by the server as a receiver would check it, stored, and
posted to the same mailbox. A request repeated byte for byte gets the same answer; one that
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
participation's id), the outputs it wants for them, the fee it pays, and
optionally the earliest median time of a round it may run in, at
most seven days ahead. An output wanted is a leaf (its template, `vtxo-1`, its
owner key and nonce, its exit delay, asset and value, and its key proof: the
owner key's BIP340 signature over `SHA256(T ‖ T ‖ id)`,
`T = SHA256("Arca/participation-key")`, so a participation wants a leaf only
under a key it holds, and optionally the leaf's binding to its owner's
mailbox key, `mailbox` with `mailbox_proof`, as a board's: not covered by
the id, refused with `bad_signature` when the proof is not the leaf key's)
or an offboard (an asset, a value and the on-chain
script to pay). The server accepts it only when:

- it carries one asset, as the round it runs in does: every coin it gives
  up, every output it wants and every fee it pays is in that asset, which
  the operator serves. One that carries two is refused (`out_of_bounds`,
  naming both): a wallet refreshing coins of several assets submits one
  participation for each;
- every coin given up passes the same check as a transfer's input: known,
  live, given up nowhere else, its record valid, every board it rests on
  credited and unspent, nothing of its lineage on the chain, and its first
  expiry (or the service expiry of a board it rests on, whichever comes
  first) at least three days ahead: a coin is taken only up to its exit
  deadline. Its attestation verifies, and an earliest round time asked for
  lies before every coin's exit deadline;
- every leaf wanted is within the published bounds, under a key that owns no
  leaf, that no other participation standing wants and that is not the
  operator's `S` (`operator_key`), and its key proof verifies
  (`bad_attestation`); every offboard pays a served
  asset within its bounds to a script that is not an Arca script;
- the coins given up hold exactly what the outputs take plus the fee, and
  the fee covers the schedule;
- the signer's record holds nothing under any coin's salt (the server asks
  it, `under`): neither a forfeit, which a coin an older server gave back
  while its forfeit stood in the record carries, nor a spend the database
  lost. Such a coin is refused (`double_spend`, naming the coin and what the
  signer holds): its forfeit for this round would stand beside the other, or
  be refused for good, leaving a participation that is neither released nor
  expired. One taken before this check that stands so is released once the
  watcher claims one of its forfeits, like any other.

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

Each asset has its own fee schedule, charged in that asset and published by
`info` with the asset (`assets[].fees`); an asset that sets none takes
`[fees]`' parts per million, which `info` also publishes at the top of its
`fees`. Transfers are free. A refresh, or an offboard, costs nothing in the
free window, the two days before a coin's exit deadline (from five days before
its first expiry to three days before it, when the server stops taking it),
and rises with the time left beyond the window to `refresh_ppm` parts per
million of the coin's value plus `refresh_base` atoms for each coin given up,
for a coin 23 days or more beyond it; a coin resting on a board counts from
the board's service expiry when that comes first (see Boards). An offboard
adds `offboard_ppm` of what it pays out, `offboard_base` atoms and the margin
its on-chain output holds for its unlock. The fixed parts are set in the
asset's atoms or as a value in the reference unit (`refresh_base_value`,
`offboard_base_value`), taken in atoms at the asset's rate (see Exchange
rates) and published both ways. A fee short of the asset's schedule is
refused (`fee`), naming the asset and its schedule.

Each forfeit carries the refund delay the server publishes with the
participation (the longest exit delay), and leaves uncommitted the margin the
server priced: four times the node's floor for the forfeit transaction, in the
coin's asset, or one atom when the node does not accept that asset for fees.
An offboard's output may be reclaimed by the operator after a delay longer than
unrolling the coin given up, its exit delay, the refund delay and a margin.

### Takes of on-chain orders

A take asks the operator's round to fill an order resting on the chain under
SeqDEX's fill covenant (`arca_covenant::fill`), for a holder who pays for it
with leaves. The order sells one asset (`asset_a`) and is paid in another
(`asset_b`); the take gives up coins in `asset_b` worth the order's price for
the fill and the operator's fee, and wants one leaf, in `asset_a`, of what it
fills. Its round spends the order and pays the maker its credit on the chain,
from the operator's coins of `asset_b`; the coins the take gave up are the
operator's by its forfeits, which the take hands over before that round is
broadcast (see Rounds that fill on-chain orders).

`take_order` names the order as the relay serves it (its `CovenantTerms`, or
an offer whose settlement is one), what it holds (`locked`), the fill
(`filled`), the coins given up, each with its attestation over the take's id,
the leaf wanted with its key proof, the fee, and whether it shares the order
(`share`, which `info.fills.shared` says the server takes). The server takes
it only when:

- the order's terms are ones a resting order can have (an internal key other
  than NUMS is a maker's key path and is refused), and the fill is one the
  order's FILL leaf takes: at least `min_lot`, at most what it holds,
  leaving nothing or at least `min_lot` resting, within the leaf's
  arithmetic (`order`, naming what is wrong);
- the operator's node holds, at the order's outpoint, an explicit output of
  `locked` of `asset_a` paying the script the terms make (`order` otherwise),
  unspent in a block and in its mempool (`order_spent`), in a transaction
  that is final (`order_not_final`: a round spends only what a rollback
  cannot take away);
- its maker cannot refund it within `[fills] order_margin_seconds` (six
  hours unless set; an order locked to a height counted at `[fills]
  block_seconds` a block): such an order is a race a round can lose after
  it is built (`order_expiring`);
- the leaf wanted holds exactly `filled` of `asset_a`, within the published
  bounds, under a key the take proves it holds, as a participation's leaf;
- both assets are served and their rates fresh;
- every coin given up is in `asset_b` and passes the checks a
  participation's coins pass;
- the coins hold exactly the price and the fee, and the fee, in `asset_b`,
  covers that asset's schedule for an offboard of the price: the maker's
  credit is an on-chain output the operator pays, as an offboard is;
- no other pending or issued participation takes the same order
  (`order_taken`, a 409, naming that participation), unless this take and
  every one standing share it: takes that share an order stand together as
  long as all of them together take no more than it holds and leave nothing,
  or at least `min_lot`, resting (`order_taken` again, saying how much is
  left to take). Each take's own fill is still at least `min_lot`. This is
  checked under a lock on the order so two takes racing each other cannot
  both be taken past it, and it makes every set of them one round can run
  together a fill the FILL leaf takes.

Unlike a refresh, a take asks its owner for something once more before its
round runs: its forfeits, once its round is built and before it is
broadcast, since that round pays the maker from the operator's coins (see
Rounds that fill on-chain orders). A take is a participation of its own,
carrying the two assets its nature asks: it is never taken into a refresh round, and its status
(`participation_status`) shows its order (`fill`: the outpoint, both assets,
what it holds, what is filled and what rests again, the price, the maker's
script and the order's; once in a round, the order's input `k`, the credit's
`2k` and the rest's `2k+1`, and what the round fills of the order with every
take of it together: `round_filled`, `round_remainder`, `round_credit` and
`round_takes`). The same request again is answered with its status.

The take's id is `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body)`,
`T = SHA256("Arca/take")`, over the order's outpoint and script (which commits
to every term), what it holds, the fill and its price, the coins given up,
the leaf wanted, the fee and the earliest round time
(`arca_covenant::Take::id` spells the layout). Its tag is its own, so no
attestation of a take is one of a refresh.

### Distributions: claim trees

A distribution pays many holders from one round: a payer gives up its own
coins in one asset and names, for each holder, a key and an amount, and each
holder gets an ordinary `vtxo-1` leaf in that asset's round, which it takes
up when it likes, having never been in contact with the payer or the
operator before. What no holder takes up goes back to the payer once the
batch's sweep is final. It serves a dividend or a coupon, a refund at a
failed closing, a launch allocation, a reward payout.

The payer names each holder by a 32-byte x-only key `A` (an on-chain address
key, a taproot address's program, or any key the holder hands over) and
draws a fresh nonce `n` for it. The holder's leaf is owned by the claim key
`A' = lift_x(A) + t·G`, `t = SHA256(T ‖ T ‖ A ‖ n)`,
`T = SHA256("Arca/claim-key")` (`arca_covenant::claim`), which the server
derives itself, and `n` is the leaf's owner nonce. The holder signs for `A'`
with its secret for `A` plus `t`. The claim key is a key of its own for
every claim, so one address can be paid by any number of distributions while
every leaf keeps a key of its own, and a payer, naming keys and never claim
keys, can take no key a wallet uses for its own leaves.

`distribute` names the coins given up, each with its owner's attestation
over the distribution's id (`arca_covenant::Distribution::id`: a tagged hash
of its own, `Arca/distribution`, with two-byte counts), the asset, the claim
leaves' exit delay, the claims (each a key, a nonce and a value), the return
script, and the fee. The server takes it only when:

- it gives up 1 to 16 coins and names 1 to 1,024 claims, each holding
  something, no key twice (`malformed`); the asset is served and its rate
  fresh, and the fee is in that asset (`out_of_bounds`, `rate_stale`);
- each claim's value is within the asset's bounds and the exit delay within
  the operator's (`out_of_bounds`); no claim key is `S` (`operator_key`) or
  owns a leaf or is wanted by another participation (`key_reused`);
- the return script is a standard address, P2PKH, P2SH, P2WPKH, P2WSH or
  P2TR (`out_of_bounds`), so the payment back relays, and no Arca script the
  server knows (`script_reused`): what nobody takes up is paid to an address
  of the payer's, never into the tree;
- every coin given up passes the checks a participation's coins pass, in the
  distribution's asset, attested over its id (`bad_attestation`), with
  nothing of it in the signer's record (`double_spend`);
- the coins hold exactly the claims and the fee (`unbalanced`), and the fee
  covers the asset's schedule (`fee`): the refresh fee of each coin given
  up, `refresh_base` for each claim leaf, and `offboard_base` once, for the
  payment of the unclaimed leaves back to the payer.

It is recorded as a participation whose outputs are the claim leaves, runs
in the asset's ordinary round, and completes as a refresh does: once the
round is final the payer hands over the forfeit of each coin it gave up
(`forfeit_leaves`, with no unroll authorisations: the payer holds no claim
key, and one handing any over is refused `leaf_set`), and the
distribution's one preimage goes out. A payer that never hands its
forfeits over keeps its coins, and the claim leaves are never opened.

A holder finds its claims with `claims`, naming each of its keys with a
proof of it, and gets, once the distribution is released, each claim's leaf,
round, record, the preimage that opens its entry, its batch's first expiry
and the deadline, the leaf's exit deadline three days before that expiry, by
which the operator co-signs its take-up. The published tree carries every
leaf's owner key and owner nonce too, so a holder can also find a claim in
any copy of a tree by testing its keys. To take a claim up, the holder hands
over its unroll authorisations for the leaf, signed by the claim key
(`claim_leaf`): the server keeps the leaf's full record and credits it,
since signatures that verify under the claim key prove the key. Then it
spends the leaf as any coin is spent, through `cosign_transfer`, into a fresh
leaf of its own. That spend is the claim, in the signer's record under the
leaf's salt like every spend.

`distribution_status` shows the payer each claim's state (`pending` until
the distribution is released, `open`, `claimed`, `returned`), the deadline,
and each payment back with its state. The return itself is the watcher's
(see The watcher).

### Offline refresh: plans

A holder who will stay away past a coin's expiry pre-signs a plan
(`plans`, `arca_covenant::plan`): a chain of 1 to 6 refresh steps the operator
applies in later rounds without it. Step `i` gives up the holder's coin
`L(i-1)` for a new leaf `L(i)`; `L(0)` is the coin the plan starts from, a leaf
of a round (a board or a received coin is refreshed in a round first). Each
step runs as a participation of the server's own making, wanting `L(i)` exactly
as the plan names it (owner key, owner nonce, the operator nonce the quote drew,
exit delay, value) under the plan's unlock hash, whose preimage the holder
handed over and can derive again. It is created no earlier than the start of
`L(i-1)`'s free window, five days before its first expiry, where the schedule
charges nothing, runs in the asset's ordinary round, and may run after
`L(i-1)`'s exit deadline while `L(i-1)`'s batch is not released. Once its round
is final the server releases it without forfeits and credits `L(i)`, whose
full record waits for the holder's unroll authorisations (`plan_leaf`). In
place of the forfeit the holder could not sign before the round existed, the
operator holds the step's refund: the holder's halves over `L(i-1)`'s and
`L(i)`'s collaborative paths, both committing to `v(i)` at the holder's own
address and the rest, less a margin for the refund's fee, at the operator's
script. Every use of either half pays the holder `v(i)`.

A plan is asked for in two calls. `plan_quote` takes the coin, one owner nonce
per step and the exit delay, asked by the coin's owner (its signature over
`SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ coin ‖ n ‖ owner nonces ‖ exit delay units)`,
`T = SHA256("Arca/plan-quote")`); it draws an operator nonce for each step and
names the script the operator's share of every refund pays to, each step's fee
(the refresh fee in the coin's free window: nothing) and the refund's margin.
`submit_plan` takes the plan, the coin's owner's signature over its id, and
for each step the leaf key's signature over the plan's key digest, both refund
halves, the preimage and the leaf key's binding to the wallet's mailbox key.
The server takes a plan only when its coin passes what a refresh's coins pass,
is a leaf of a round and is named by no plan that is open or stopped; each
step's operator nonce is one the quote drew; each step's key owns no leaf and
is wanted by nothing else; each step's salt is new to the server (promised to
the step from then on); every signature verifies, every preimage opens its
hash, every value and exit delay is within bounds, every fee covers the
schedule, every operator script is the quote's, and no holder's address is a
script the server knows as an Arca script. A plan submitted again is answered
with its status.

What the server does with a plan once it holds it:

- A step whose coin is spent otherwise, lost or on the chain is void, and the
  plan stopped: the coin it would have given up is its holder's again. So is a
  step whose round is lost: a step runs only under the leaf its plan names, so
  it is not run again.
- The watcher releases no batch that holds the current coin of a plan that is
  open or stopped, whether its step has run or not: a holder away on a plan
  finds that coin unswept. A plan is over once it is done or its holder
  cancels it (`cancel_plan`, signed by the plan's mailbox key).
- A coin a plan names carries its holder's refund halves for as long as its
  script is unspent; with one, the operator alone could void a reassignment of
  it. So no transfer of such a coin is co-signed (`planned`); its holder
  gives it up in a round first, by a participation of its own, which the
  operator takes for the current coin of an open or stopped plan unless the
  plan's step is in a round. While that participation holds the coin no step
  runs from it; once it is released (its round final, its forfeit handed
  over) the plan ends, the reason naming the participation and round; should
  it never complete, the coin is live again and the plan stands. A coin a step
  made is taken into no
  participation until the coin that step gave up is swept, its sweep final:
  the refund that answers that coin needs the signer's one spend under the new
  coin's salt.
- A coin a step gave up that comes on the chain is answered by the step's
  refund (see the watcher).

### Resting orders

A resting order is an `order-2` leaf (`arca-covenant`'s `order`): an order of
SeqDEX's, selling the leaf's asset at a fixed rate and lot, that takers fill
in the tree while its maker is away, and that lands on the chain as SeqDEX's
own order (`seqdex/order`, for the same terms) if anyone brings it there. Each
fill is co-signed by the operator alone, and the leaf's program holds every
co-signed fill to the order's terms: the maker's credit at output 0, a `vtxo-1`
leaf under the order's next credit key paying at least the price, and for a
part fill the order resting again at output 1 under a new salt, holding the
rest. An order fills at most four times along its lineage, one credit key a
fill.

A maker asks a round for the leaf as for any leaf, its wanted leaf naming the
template `order-2` and the order's terms (`order`: the asset it is paid in,
the rate, the lot, the landed order's maker script hash, REFUND time and
refund key, and four credit keys). The server takes it only when the terms
hold (`order`): the asset it is paid in is one it serves, its four credit keys
are distinct, own no leaf and are not the operator's or the leaf's key, and
its REFUND time is more than the order margin (`fills.order_margin_seconds`)
ahead. Once the round is final and the participation released, the maker
publishes the order (`order_publish`) and can stop: the publication carries
the coin's record as the maker holds it, the nonces its credit keys come from
and the mailbox its credits and remainders go to, signed by the order's leaf
key over `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ order id ‖ the four credit nonces
‖ mailbox)`, `T = SHA256("Arca/order-publish")`.

A taker reads the order (`order_state`): the coin it rests at, what that
holds, the coin's leaf key, salt, exit delay and terms (from which it rebuilds
the coin's script and the fill's outputs), the coin's record (it checks the
coin is in the tree before it signs), and every fill so far. It fills by
giving up coins of the asset the order is paid in, each through a checkpoint
as in a transfer, for a leaf of what it takes and a leaf of its change
(`order_fill`). The operator co-signs only when:

- the coin is the one the order rests at now, live, its lineage off the chain
  and its first expiry past its exit deadline, and the signer holds no other
  spend under its salt;
- it is before the order's REFUND time less the order margin;
- each taker coin passes what a transfer's input passes, is of the asset the
  order is paid in, and expires no earlier than the order's coin, so every
  coin the fill makes ages with the order's lineage;
- the fill takes at least the lot and leaves nothing or at least the lot
  resting, the taker's first leaf holds exactly what it takes and its second
  the change, a checkpoint and the fill each leave a margin that pays their
  fee as a transfer's does (the fill's in the asset paid), the depth limit
  holds, and every signature verifies.

The fill is recorded, the order's coin spent by it and the taker's request
kept with it, before anything is signed. The signer co-signs the taker's checkpoints and their pair over the
fill's outputs, then the fill itself, after judging it by the program's rules,
as the one spend under the order coin's salt. The answer carries each coin the
fill makes with its record; the maker's credit and the order resting again go
to the maker's mailbox, the taker's leaves to the taker's, and the order rests
at the remainder from then on. A fill sent again gets the same answer. A fill
left unsigned (the server stopped, or the signer went away after it signed the
taker's pairs and before the fill) is completed by the server from the request
it kept, at start and every minute after, as when the taker sends it again: the
taker signed its pairs over exactly these outputs, so completing it takes
nothing from anyone, and the order's coin is not held until the taker returns.
One the signer refuses (its record holds another spend of a coin) is dropped,
its coins live again. While a fill is unsigned the order reads `filling`.

The maker cancels by spending the order's coin as any coin: a transfer into a
leaf of its own (`cosign_transfer`), or a refresh. The signer's one spend per
salt keeps a cancel and a fill of one coin apart. A credit's key is public in
the order's terms, so the coins a fill makes for the maker are outside the
one-key rule: a leaf anyone pays to a credit key does not block the fill that
credits it.

## Rounds

A round carries one asset. Each asset the operator serves has rounds of its
own and a pool of its own, the operator's wallet's coins of that asset,
which fund its batches and nothing else. At each round interval (every
`round_interval_seconds` while participations wait) the runner builds a
round for each asset whose participations wait, each its own transaction:
one asset's round that cannot be built (its pool short, the node refusing
it) holds back no other's. For an asset, it gathers that asset's pending
participations whose earliest round time has come, checks each coin they give
up again, and builds the asset's tree with `arca-covenant`'s builder: balanced at radix 4, every node gated, RECLAIM on
the lowest nodes, each leaf behind its participation's hash-locked entry, the
reserve at four times the node's floor in the batch asset. A batch in an asset
the node does not accept for fees carries a reserve of one atom on every node
and every entry, so whoever unrolls it attaches a fee coin in an asset that is
accepted. A coin is checked again under the horizon it was taken under, its
exit deadline, at each round and at every pass over the rounds: a pending
participation with a coin past its exit deadline can never run and is voided
then, whether a round is being built or not, its coins given back; from that
deadline their owner takes them on the chain. A batch holds at most 1,024
leaves; a participation runs whole in one round. The participations are
taken against what the operator's wallet can spend of the asset now: what
the round pays on their behalf (the batch output, leaves and reserves as the
builder makes it, and each offboard output) must fit, and the round's own
fee and connector after it. A participation that does not fit waits, in
order, and the ones after it still run if they fit. A participation that
waits says why in its status (`waiting`), and runs once the wallet can fund
it. A pending participation in an asset the operator no longer serves waits,
saying so; one that carries several assets, which only a server from before
a round carried one asset took, is voided, its coins given back. Each batch
has its own sweep
token, one explicit atom with no reissuance token, issued by one of the
operator's coins, and a clock schedule of three steps, 28, 56 and 84 days
after the round's median time, with a notice of 36 hours.

The round transaction pays the batch output followed by its token's atom at
the batch's first clock, then every offboard output, then the connector
output, then change per asset and the one fee output. A round of refreshes
spends the operator's coins only: it takes no input of a third party, which
could be spent elsewhere and keep the round from returning after a rollback;
only a round of its own that fills on-chain orders spends one (see Rounds
that fill on-chain orders). Its lock time is 0 and every input final, and it
is kept byte for byte, so the nursery broadcasts it again unchanged and it
returns with its txid, every forfeit signed for it still good. Its fee is
paid in one asset: its own, when the node accepts it for fees now and it is
among `fee_assets`, else the first asset of `fee_assets` the node accepts;
never another, and never one the node refuses. A round in an asset the node
does not accept for fees so draws its fee and its connector from the pool
of that fee asset, and waits, saying so, while that pool cannot pay them.
A round spends only final coins, so an operator serving an asset the node
does not accept for fees keeps several final coins of the first fee asset:
a round of that asset built while the other rounds' change is not yet final
otherwise waits for their confirmations.

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
against the round transaction with `LeafRecord::validate`. The tree as the
server built it comes with it, for a reader to compare with what it rebuilds:
every node, level by level from the lowest to the batch output (its value,
the reserve in it, its script and its children), each leaf's id and script,
and where the round stands (`round_state`). Once a leaf's participation's
preimage went out, the tree publishes that preimage beside the leaf
(`preimage`). It opens the leaf's entry, whose only spend pays the leaf's own
script, so it lets nobody move anything but into the leaf; and with it an
owner whose own record is gone takes the leaf on the chain from the published
tree, its mnemonic (which signs its unroll authorisations again) and the
chain. Before the preimage went out the owner's forfeit is not in, and the
preimage stays the operator's. `rounds` lists every round after a cursor,
oldest first, with its transaction, its state and the outputs of its
batches, so a mirror copies every published tree.

### Rounds that fill on-chain orders

A take runs in a round of its own kind, beside the refresh rounds: a fill
round of the asset its order sells, which carries takes and nothing else, so
an input a third party may spend first never stands in a round of refreshes.
The runner builds one for each asset whose takes wait, at most 16 orders and
64 takes a round. Takes that share an order run in one round together: the
round spends the order once, at the input of the first of them, fills it by
the sum of their fills, credits its maker the order's price for that sum
(rounded up once, so never more than the takes' own prices together), and
pays each take a leaf of its own fill in the batch. The FILL leaf reads only
that sum, so the round holds each buyer's share to the order's `min_lot`
itself: a take below it is refused when it is submitted and voided if a
round ever meets one; a take that shares an order with a take that takes it
alone waits for a later round. It is built under the rule every SeqDEX fill
covenant reads:

| Inputs | Outputs |
|---|---|
| `0..n-1`: the orders, each with its FILL leaf and control block as its witness | `2k`: the maker's credit of the order at input `k`, its price in the asset it is paid in, to the maker's program |
| then the operator's coins: the token's issuer, the coins that pay the credits and the reserves, the fee | `2k+1`: the order resting again with its identical script, for a partial fill; for a full fill, an output to the operator in the asset the order is paid in (one atom, or 1,000 where that asset pays the round's fee), never one in the asset the order sells |
| | then the batch and its token, the connector, change per asset, the fee |

The orders' own value pays the takers' leaves; the operator's pool of the
asset pays the batch's reserves, and its pool of each asset an order is paid
in pays that order's credit. A take that does not fit what the wallet can
spend waits, saying why. Before anything is recorded, the runner follows each
order's FILL leaf over the transaction (`arca_covenant::FillOrder::check`)
and asks the node whether it would take it.

Each take's order is checked again when its round is built: one spent by
another transaction (in a block or the node's mempool), or whose maker can
refund it within `[fills] order_margin_seconds`, drops out: its take is voided
with the reason, and the round is built without it. So is one the node finds
spent when the round is put to it. A fill round that goes out of the chain
because another transaction that is final took an order of it is lost like
any round: its takes run again, each order checked again, and the take
whose order was taken is voided. A coin a take gave up whose forfeit it had
handed over for that round stays given up, its owner's on the chain, as for
any participation of a lost round.

A fill round pays its makers on the chain from the operator's coins, and the
operator is paid back only by each take's forfeits. So it is held, built and
unbroadcast, until every take in it has handed over its forfeits, and only
then broadcast. The take's status shows its round with the transaction
without its witnesses (`round.tx`, its txid the round's, which nobody but the
operator can broadcast); the wallet validates its new leaf against it and
signs a forfeit of each coin it gave up, which `forfeit_leaves` takes before
the round is broadcast, recording the owner's half only: the signer is asked
for its half once the node holds the round, in its mempool or a block, so a
round dropped unbroadcast leaves nothing in the signer's record. A take whose
forfeits have not come `[fills] forfeit_window_seconds` (600 unless set) after
its round was built, by the chain's median time, is voided, its coins given
back; the round is dropped unbroadcast, its coins freed, and every take that
did hand its forfeits over runs again in the round built after it. A take's
preimage goes out once its round is final, as any participation's:
`forfeit_leaves` asked again then answers it, and the server releases the
take itself once its forfeits are whole.

A held round goes out only with its orders unspent: anyone may fill an order
on the chain while its round waits for forfeits. At every pass, and once more
before the round is handed to the node, each of its orders is checked again
at the node; one spent meanwhile drops the round unbroadcast, voids that take
with the reason (`order … is spent …; its round … was dropped unbroadcast`),
and runs the others again. When the node refuses a fill round, its order
inputs are looked up at the node, not in the database's index of spends: a
round whose order another transaction took is retired as lost, like any
round another transaction took an input of (its takes run again, the take
whose order was taken is voided, and a coin a take gave up whose forfeit it
had handed over stays given up, its owner's on the chain). A round dropped
unbroadcast is killed on the chain: the server spends one of the round's own
coins back to its wallet at once, in a transaction of its own (its fee in the
round's fee asset while the node accepts it, else in another it accepts), and
tries again at every pass until one is under way, so the dropped round can
never confirm, whoever holds it, and every wallet that signed a forfeit for it
sees it gone. That costs the operator one small transaction's fee for each
round dropped.

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
restored one runs again as after any lost round. A participation one of whose
coins' salts holds another message the signer co-signed (a forfeit for the
round that ran it again while this one was out, given before this round's
forfeit came) is not brought back: the signer co-signs one message under a
salt, ever, so its forfeit for this round can never be signed, its leaves of
the round are never credited and their preimage never goes out, and the coin
is its owner's on the chain, by its exit or that other forfeit's refund. A
participation one of
whose coins was spent on the chain otherwise than by its forfeit for the
round is not brought back: that forfeit refunded while the round was out,
the coin's last output on the chain (its board output, the leaf its
conversion made, or a leaf output its unroll made) spent by its owner's exit,
or by another round's forfeit that came back with the reorganisation (a
forfeit spends its coin alone, so a node puts it back in its mempool, and it
confirms beside the round, while that round's claim of it never can). Its
leaves of the round are never credited (`expired`), it is left void saying
so, and the server serves them nothing; their owner holds their records, so
they are its to take on the chain, and the loss, one coin's worth, is the
operator's. Whatever the owner leaves of them the operator sweeps with their
batch. Both need the parent chain to reorganise past a final transaction. A coin
resting on a round is as final as that round: while the round is lost, every
coin a transfer made out of one of its leaves, at any depth, is lost too, and
it is the holder's again once the round is restored, unless it rests on
another round or a board still lost. A
re-run whose leaf of the lost round was spent before the round was lost (paid
on out of round, or given up in another participation) is not run again, its
status saying so: a second leaf would leave its owner what it spent.

A coin with a forfeit for an earlier round in the watcher's log, or whose
output the server has seen spent, is never taken into a re-run: such a
forfeit may still confirm, from any mempool that saw it, and is its owner's
to refund once its delay has run while the round is out, since no claim of
it can be made then. The participation is voided and its status says why
(`void_reason`); its coins stay given up (the signer co-signs no spend under
a salt it signed a forfeit under), so each is its owner's on the chain, by
that forfeit's refund or by its exit, unless the round returns first and the
watcher claims the forfeit. Nor is a coin under whose salt the signer has
co-signed anything, the lost round's forfeit included: the signer co-signs
one message under a salt, ever, and a forfeit for the re-run would be a
second, which burns the operator's bond ("The equivocation bond"). Such a
participation is voided the same way, its coins their owners' on the chain by
their exits unless the round returns. Any other re-run (its forfeits never
made whole before the round was lost) completes as an ordinary
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

## Issuer-operated assets

An asset's own issuer may run its batches: then the operator funds them by
reissuing the asset in the round that makes them, instead of from its own
coins, and every sweep of them can only burn. The refresh liquidity exists
only while its batch lives, and the asset's supply returns to its level once
the batch is swept, which anyone checks on the chain.

The asset's reissuance token rests in a mint limiter (sequentia-contracts
`templates/mint_limiter`): the whole token, explicitly, at the instance's
address, its operator key the issuer's minting key, which `arca-signer`
holds and arcad never does, and its cold key the issuer's, which can brake
every mint. An asset whose token is not in a limiter is not served this way:
the operator mints on every round with nobody present, and only the
limiter bounds what a stolen minting key makes. The asset is served
issuer-operated by its configuration:

    [[assets]]
    asset = "<asset id>"
    min_leaf = "1000"
    [assets.issuer]
    limiter = "/etc/arca/z-limiter.json"   # the instance file `mint-limiter instance` writes
    entropy = "<the asset's issuance entropy, as issueasset prints it>"
    coin = "<txid>:<vout>"                 # the limiter's coin when the asset was set up
    state = "0,0,0"                        # its MINTED,ELAPSED,ARMED then; 0,0,0 when absent

and the signer started with the same instance and the mnemonic of the
limiter's operator key (`--issuer <instance file>=<mnemonic file>`, a file
only its owner reads, and `--mint-limiter <path>` naming the limiter's tool
when it is not on the `PATH`). The instance must be on the server's chain, a
limiter of the asset whose token is the asset's explicit reissuance token by
that entropy, and its operator key is never `S`. `info` names the limiter
(`assets[].issuer`).

**Rounds.** A round of the asset mints exactly what it pays of it: the
batch output, with its leaves and reserves as the builder makes them, and
each offboard output. The limiter's coin is input 0, carrying the
reissuance, its sequence the coin's age in blocks, and its successor, the
token's whole amount in the next state, is output 0; the batch output and
its token's atom follow, then the offboards, the connector, the change and
the fee, which the operator pays from its fee assets but the asset (a
configuration whose fee assets are all issuer-operated is refused at start
and on reload, as its rounds and sweeps would have nothing to pay in). Every
batch of the asset is burn-only. The server follows the limiter's coin on
the chain from the one its configuration names, through its own rounds and
any other spend of it (the cold key's brake, its release, its recovery), and
a round mints only from a coin whose transaction is final, two blocks old or
more, its brake off, spent by no round of the server's that is in no block
yet (the next round of the asset waits for that one), and only what the
window's allowance has room for: a
participation whose mint does not fit waits, saying how much the limiter
allows now and when its window ends. The signer checks the round before it
signs the mint (`reissue`): input 0 spends the limiter's coin and reissues
the asset, no other input reissues it or spends a coin of it, every output of
the asset is a burn-only batch under `S` or an offboard under `S`, each
rebuilt by the signer from its parts, and together they hold exactly what
input 0 reissues, so nothing of the asset goes to change or a fee; then the
limiter's own tool (`mint-limiter sign`) signs the program's signature hash
over the whole round and satisfies the program, and refuses a mint over the
allowance. The round records its mint (the coin, the states before and
after, the age, the amount). A mint and its batch are one transaction, so a
rollback takes both out together and the nursery broadcasts both again.

**What the operator takes in.** The operator keeps no unit of the asset.
Whatever an operator transaction takes in of it is burned whole in that
transaction, a bare `OP_RETURN` of its explicit amount, and its fee is paid by
a coin of another asset: a board's forfeit and its claim, a forfeit claimed
against a stale exit, a reclaimed node, a reclaimed offboard, the operator's
share of a plan step's refund (a plan quoted in the asset names a burn as
the operator's script), and any margin or reserve such a transaction leaves.
The signer signs no spend that pays a unit of an asset it mints anywhere but
a burn. Fees holders pay in the asset are burned with the coins they gave up,
so its operator earns nothing in it; an issuer that wants no fall in supply
sets the asset's fees to zero. The same holds for an asset that once had a
burn-only batch, whatever it is served as since.

**Not served in the asset**: takes of on-chain orders (a round that fills
them holds the orders at its low inputs and mints nothing), distributions
(their unclaimed value is paid back from the operator's coins), and a
Lightning leg (refused in the configuration).

**The supply.** Anyone reads the asset's supply from the chain: every
issuance of it, each reissuance a spend of the limiter's coin, less every
bare `OP_RETURN` of it. `issuer_supply` lists the operator's part of it,
transaction by transaction, and the value live under its burn-only sweeps,
counting only what the active chain holds.

## Supervised assets

A supervised asset is one whose issuer can freeze holdings by consensus
rule: its supervision descriptor (an operational and a recovery key, and
whether the asset can be paused) is committed in its asset id at issuance,
so it can never be added or removed (the node's
`doc/sequentia/supervised-assets.md`). A freeze names a script, and binds
only a single-owner spend of it (P2WPKH, a taproot key path); a pause
freezes every single-owner holding of the asset. Every Arca output is spent
by a script path, so no freeze ever reaches the tree itself. The operator
serves such an asset so that a frozen holder can neither move nor escape:

**The profile is the chain's.** The server reads `getsupervisedassets` from
its node at start and at every reload, and serves every asset listed there
under this profile, whatever its section says. A section may set the
profile's one setting:

    [[assets]]
    asset = "<asset id>"
    min_leaf = "1000"
    [assets.supervised]
    landing_allowance = "10000"   # atoms; default: four times the node's floor for a landing

and one that names `[assets.supervised]` for an asset the node does not
list, or serves a supervised asset issuer-operated or over Lightning, is
refused at start and on reload. `info` publishes the profile
(`assets[].supervised.landing_allowance`).

**Every leaf is `landing-1`.** A leaf of the asset, in a batch, a board or a
reassignment, is `landing-1` (`arca-covenant`'s `landing`): its exit, the
landing, pays only P2WPKH of the owner's own landing key, explicitly in the
asset, all but the published allowance, and its collaborative constant
commits to that key's program as well. Its owner names the landing when the
leaf is asked for: a participation's wanted leaf, a transfer's output and a
board's record carry `landing` (`{"program", "allowance"}`, the leaf
record's JSON form), with the allowance `info` publishes; any other
template, a missing landing or another allowance is refused
(`out_of_bounds`), and a landing is refused on a leaf of any other asset.
The published tree (`tree`) carries each leaf's landing, so anyone, the
issuer included, rebuilds every leaf of a batch and reads where each lands.
Every output of every round and transfer of the asset is explicit, as
consensus requires of a transaction that moves it. Not served in the asset:
takes of on-chain orders, resting orders (either asset), distributions,
offline-refresh plans and Lightning legs, whose leaves or refunds would pay
a key a freeze cannot follow.

**The operator mirrors freezes.** Before it co-signs anything that spends a
coin of the asset, the server asks its node whether the coin's landing is
frozen (`isassetfrozen` on the landing's P2WPKH, never on an Arca script,
which the node calls frozen once named although its script-path spends
confirm). A coin whose landing is frozen, or whose asset is paused, is
refused with `frozen` (409), checked before anything else about the
request, naming the coin, its landing and why: a transfer, a swap, a
refresh, an offboard, a take, a resting-order fill, a distribution, a plan,
a Lightning payment, and a forfeit handed over for a participation taken
before the freeze; a participation whose coin is frozen when its round is
built is voided with the reason. A freeze binds as soon as its record is in
a block of the node. Its lifting binds only once final: the server keeps a
hold (`supervision_hold`) on every script a freeze record names, and on the
asset's pause, from the block at which the node first shows it free until
that block is certified and its anchor buried, so an anchor reorganisation
that restores the freeze on the chain finds it still held. It reads every
freeze and pause of the assets it serves after each pass over the chain, as
well as at every request, so a freeze that no request met while it lasted is
held to its final lifting too; only one recorded and lifted within a single
pass, or while the server is stopped, goes unseen. Paying a frozen landing is co-signed: the coin arrives frozen, as on
the chain. A frozen holder's coin leaves the tree only by its landing,
unroll and exit by script paths that confirm under any freeze, into its own
key, where the freeze binds; a frozen coin not landed by its batch's exit
deadline is swept with the batch.

**The signer checks on its own.** `arca-signer --supervision-node <url>
--supervision-cookie <file>` reads freezes from a node of its own. A
co-signature for a `landing-1` coin names its landing (the signer request's
`landing`): the signer builds the message with that landing after `K`, as
the coin's script does, and refuses (`frozen`) while its node shows the landing frozen or the asset
paused. A signer started without a node signs nothing for a `landing-1`
coin, so an operator serving a supervised asset runs its signer with one.

## The forfeit swap

Once its round is final, an owner validates each new leaf from the published
tree, then hands over with `forfeit_leaves` the forfeit of every coin its
participation gave up, built with `Forfeit::for_refresh` from that validated
leaf and round and the refund delay and margin of the participation's status,
together with its unroll authorisations for every node above each new leaf.
The server takes it only for a participation in a round it calls final, or
for a take whose round fills on-chain orders and is not broadcast yet (it then
records the owners' halves and nothing more, and returns no preimage: see
Rounds that fill on-chain orders), and only when:

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

The forfeits are taken, and co-signed, until the later of a day after the
round was found final and the exit deadline of the coins the participation
gave up (the earliest of them), so a wallet that asked for a refresh in its
coin's free window completes it at any sync before the coin's exit date.
A forfeit the operator can claim ends in a release, whoever finishes the
step. At every pass over the rounds the server releases, itself, a
participation of a final round one of whose forfeits the watcher has
claimed (the claim puts the preimage out), or every forfeit of which it
holds whole while every coin it gave up is off the chain (the operator can
put the preimage out at will). One whose coin is on the chain waits for the
watcher's answer and its claim: until then the coin's owner may still take
it by its exit once the exit delay has run, and a preimage handed out then
would pay for the coin twice. Its new leaves are
credited as when the owner completes the step, and the owner's step asked
again returns the preimage. So a forfeit whose operator's half came late
(the server's minute task fills it in once the signer and its keepers
answer) leaves its owner the new leaf, even when the owner's coin is on its
way home on the chain and its own step can no longer finish.

A participation not released by its deadline expires, whether its forfeits
never came or came and were never co-signed (the signer away, or its
keepers), with one exception: while some of its forfeits are whole and the
rest recorded without the operator's half, it waits, since the signer may
still sign the rest, and the whole ones can reveal the preimage. When it
expires, its new leaves are never credited (their preimage never goes out,
and the operator sweeps them with their batch at expiry), each of its
forfeits without the operator's half is dropped, never asked of the signer
again, and each coin it gave up for which no forfeit was ever recorded is
given back, live again and free to be given up again. A coin whose forfeit
was recorded stays given up, whole or not: one whole can be claimed, and
one without the operator's half may have reached the signer's record, which
then co-signs no spend of it. So does every coin of a participation one of
whose forfeits is whole, and a coin under a forfeit signed for an earlier,
lost round: its owner's way home is that forfeit's refund or its exit. A
forfeit step that reaches the server after the expiry, even one in flight
when it ran, is refused (`not_in_round`) and stores nothing. A round that
stops being final and becomes final again starts the day again.

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
A transaction that needs the operator's signature takes the wallet coins
that pay its fee before the signer is asked; when the signer gives no
signature (it is stopped, say), those coins go back to the wallet, so a
signer outage holds none of them, and the operator's rounds stay funded
meanwhile.

- **Stale exits.** A coin the server holds as given up, by a participation
  whose forfeit it stored or by a transfer it co-signed, whose leaf is seen on
  the chain unspent, in a block or the mempool, is answered at once: by its
  forfeit, or by its checkpoint; and a reassignment is published once every
  checkpoint it spends is on the chain. A board given up and then converted
  is the same case: its leaf appears. The answer confirms within the leaf's
  exit delay, after which its owner's exit finds the leaf spent. A coin given
  up by a step of an offline-refresh plan is answered by the step's refund:
  the watcher first brings the step's leaf on the chain, one transaction a
  pass, unrolling its path with the operator's own unroll authorisations (the
  operator is a member of every node, and the signer signs them) and opening
  its entry with the plan's preimage, then spends the coin and the leaf
  together, the holder paid the leaf's value at its own address. A resting
  order's coin that a co-signed fill spent is answered by the fill: the
  watcher brings each taker's coin on, one transaction a pass, and
  checkpoints it, then publishes the fill, which spends the order's coin by
  its fill path within the landing delay, so its maker cannot land it; a
  remainder that comes on with it and was filled again is answered the same
  way. A taker's checkpoint on the chain is answered by the fill once the
  order's coin is there too.
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
- **Absent makers' orders.** A resting order whose coin is live at its exit
  deadline (three days before the earliest expiry in its lineage), its maker
  not back to refresh it or take it home, is landed by the operator, so it is
  not swept with its batch: the coin is brought on the chain (its path
  unrolled by the authorisations its record carries; for a coin a fill made,
  the order's first coin and each taker's coin brought on and the fill
  published, as stale exits are answered), and once it has waited its exit
  delay in a block, the landing moves it whole into SeqDEX's order for the
  same terms, its fee from a coin of the wallet's. The order then rests on the
  chain, its maker's to refund or SeqDEX's takers' to fill, and `order_state`
  reads `landed`. A coin the signer holds a spend of is left alone.
- **Expiry.** At the expiry of the clock that holds a batch's token, the
  release moves the token to `R`. Once it has waited the notice there, each
  sweep takes every output of the batch still unspent whose own notice has
  passed (the batch output, a node or an entry someone unrolled, a checkpoint
  of a coin from the batch), at most `max_sweep_inputs` at a time, and returns
  the token to `R`. A leaf on the chain is its owner's and is never swept.
  A burn-only batch's sweep burns each output it takes whole, at its own
  index, several in one transaction, and a coin of another asset pays its
  fee (see Issuer-operated assets). A batch that holds
  the current coin of an offline-refresh plan that is open or stopped is not
  released: the release waits until the plan's step has taken that coin into
  a final round, or the plan is over.
- **Reclaim.** A lowest node every owner of which has released it is
  reclaimed with an atom of each connector asset the releases name. With
  `reclaim_early`, a node all of whose lowest nodes are released is unrolled
  first, by a released owner's authorisation, until the lowest nodes are on
  the chain, so a fully refreshed batch comes back before it expires; the
  watcher never unrolls a node with an owner who has not released.

- **Returns.** A claim leaf of a distribution whose value a final sweep took
  (the batch output, a node above the leaf, or its entry), with no spend of
  it recorded, is a claim nobody took up. The watcher pays every such leaf of
  a distribution to its return script, an explicit output in its asset, in
  one transaction of the operator's wallet, its fee from the operator's own
  coins (the distribution's asset where the node takes it, else the first of
  the operator's fee assets it takes), recorded with the claims it returns
  before the nursery broadcasts it. A leaf whose own output came on the chain
  is its holder's and is never returned. The return is the operator's
  payment, not a script: a payer relies on the operator for it, and checks it
  against `distribution_status`.

A fee is paid from the value a transaction takes, or from the margin its
signers left, when the node accepts that asset for fees now and it covers the
node's floor. A margin of more than twice the fee the wallet pays for the
transaction pays that fee and the rest goes to the wallet, after the outputs
the signers committed to: paid whole, a large margin would be a fee the node
refuses (`max-fee-exceeded`). Otherwise a coin of the wallet's pays: from
the pool of the asset the transaction works in (the batch's, for a token's
release; the coin's, for a claim or an answer) when the node accepts it for
fees and the wallet holds a coin of it, else in the first asset of
`fee_assets` the node accepts; the margin goes to the wallet's change. No
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
| `GET info` | The operator key, genesis hash, assets served in the configuration's order with their smallest leaf (`min_leaf`, in atoms, and `min_leaf_value` when it is set as a value), for an issuer-operated asset its mint limiter (`issuer`: the template, the token, its operator and cold keys, its allowance, window and recovery delay; see Issuer-operated assets), and their rate (`rate`: its source, the rate, its time and age, how long it is good for, whether it is stale, and why its last read failed), exit-delay bounds, depth limit, the finality rule, for a supervised asset its profile (`supervised`: the landing allowance; see Supervised assets), the template list and its version (every leaf template the covenant crate knows: `vtxo-1`, `board-1`, `htlc-1`, `order-2`, `landing-1`), the fee schedule with its free window and the bounds on a transfer's margins (`margin_multiple`, `max_margin_multiple`) and the node's floor in each asset served (`floors`), a participation's exit deadline and forfeit deadline, a board's dates (`boards`: its service lifetime, exit deadline and last refresh time), the signer's record's latest entry, running hash and the signer's signature over them, with the keepers' acknowledgements of it (`signer_record`, absent while the signer does not answer or is stopped), the keepers' keys and how many must hold a head (`keepers`), the request limit, and how takes of on-chain orders are bounded (`fills`: `order_margin_seconds`, `block_seconds`, `forfeit_window_seconds`, and `round_interval_seconds`, the runner's interval, 0 when it builds rounds only when asked, from which a wallet with a take waiting times its wakes) |
| `POST operator_nonce` | A fresh operator nonce, for a board, good for an hour by default |
| `POST challenge` | A challenge to authenticate with, good for a short while, stored nowhere |
| `POST register_board` | Registers a board record with its transaction |
| `POST board_status` | A board's state (`pending`, `credited`, `lost`), its transaction's finality and, once that is in a block, its dates (`exit_deadline`, `expiry`) |
| `POST cosign_transfer` | Co-signs an out-of-round transfer and delivers its coins, with the signed head of the signer's record its last signature was recorded at (`signer_record`). An output that pays a receive request names when the request lapses (`until`, a median time, as the request carries it): once the chain's median time has reached it, the server records no transfer paying it and answers `request_lapsed` (422), naming that time, since its receiver no longer waits for the payment; a transfer recorded before it completes when it is asked again. An output without `until` is taken as before |
| `POST lightning_send` | Pays a BOLT11 invoice out of the tree (see Paying an invoice out of the tree): co-signs the transfer into the payment's `htlc-1` leaf and the change, as `cosign_transfer` answers it (`cosigned`), and answers the payment (`payment`: its hash, asset, amount, fee, `htlc_leaf_id` and state) |
| `POST lightning_send_status` | A payment out of the tree by its payment hash: `paying`, `paid` with its preimage, or `failed` with the reason |
| `POST lightning_receive` | An invoice paid into the tree under the wallet's own payment hash (see Receiving into the tree), and the payment (`open`) |
| `POST lightning_receive_status` | A payment into the tree by its payment hash: `open`, `accepted` with its participation and the leaf's timeout, `claimed` and whether the node has settled it, or `cancelled` with the reason |
| `POST lightning_receive_claim` | Takes the payment's preimage with the transfer of its leaf into a leaf of the owner's: settles the payment and co-signs the transfer, as `cosign_transfer` answers it (`cosigned`), with the payment (`receive`) |
| `POST submit_participation` | Accepts a participation in a round |
| `POST participation_status` | A participation's state (`pending`, `issued`, `released`, `void`, `expired`), its unlock hash, its forfeits' refund delay and margins, its round and where each of its outputs is in it, while it is pending why the last round did not take it (`waiting`), once void why it never runs (`void_reason`), once void or expired whether each coin it gave up is its owner's again off the chain (`returned`), and for a take the order it takes (`fill`, with its input and outputs once in a round) and, while its round is held for the takes' forfeits, the round's transaction without its witnesses (`round.tx`) |
| `POST transfer_status` | How a transfer stands, by its id (`transfer_id`): `recorded` (not yet co-signed), `signed`, or `unknown` (never recorded, or dropped); with `leaf_id`, that output when it is one of the transfer's (`output`: its leaf, owner key, asset and value). Not authenticated: the id names the transfer. A wallet checks a notice that a coin is pending for it by it, when it reads the notice and at every sync while it holds one |
| `POST take_order` | Accepts a take of an on-chain order (see Takes of on-chain orders), answered as `participation_status` answers |
| `POST issuer_supply` | What the operator minted and burned of an issuer-operated asset (see Issuer-operated assets): every round's mint and every burn of the watcher's the active chain holds, each with its txid, kind, amount and finality, their sums and those of the final ones, the value live under its burn-only sweeps (`in_batches`), and the limiter's coin and state, or why it mints nothing now. Not authenticated: everything in it is on the chain |
| `POST distribute` | Accepts a distribution (see Distributions: claim trees), answered as `participation_status` answers |
| `POST distribution_status` | A distribution by its id: its participation's state, round, the claim leaves' first expiry and deadline, each claim's key, claim key, value, leaf and state, and each payment of unclaimed leaves back to the return script, with its state in the nursery |
| `POST claims` | The claims under each of up to 64 keys, each proven under one challenge (the call `claims`, an empty request), newest first: each claim's distribution, nonce, claim key, asset, value, exit delay and state, and once its distribution is released its leaf, round, place in the tree, record, preimage, expiry and deadline |
| `POST claim_leaf` | Takes a holder's unroll authorisations for a claim leaf, signed by its claim key, keeps the leaf's full record and credits the leaf, so its holder can spend it |
| `POST plan_quote` | A quote for an offline-refresh plan from a coin (see Offline refresh: plans): the quote's id, the coin's asset, value and first expiry, the earliest time of step 1's round, the operator's script for every refund, and for each step its operator nonce, fee and refund margin |
| `POST submit_plan` | Accepts a plan, answered as `plan_status` answers |
| `POST plan_status` | A plan by its id: `open`, `done`, `cancelled` or `stopped` (with the reason), and each step: `waiting`, `running`, `done` or `void` (with the reason), the leaf it makes as the plan names it (value, fee, owner key, both nonces, exit delay, unlock hash, the holder's address), the coin it gives up, its participation, its round and the round's state, and its leaf with its place in the tree and, once its round is final, its record. Not authenticated: the id names the plan |
| `POST plans` | Every plan whose leaves are bound to the authenticated key (a wallet's mailbox key), the newest first, each as `plan_status` answers it |
| `POST cancel_plan` | Cancels the steps of a plan that have not started, on the plan's mailbox key's signature over `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ plan id)`, `T = SHA256("Arca/plan-cancel")`; a plan with a step in a round is cancelled once that round decides it |
| `POST plan_leaf` | Takes the holder's unroll authorisations for a leaf a step of its plan made, signed by the leaf's key, and keeps the leaf's full record |
| `POST order_publish` | Publishes a resting order its round made (see Resting orders), answered as `order_state` answers it; a publication sent again gets the order's state |
| `POST order_fill` | Co-signs a fill of a resting order: the transfer's id, the operator's fill signature, its signatures for each taker coin, and each coin the fill makes with its record (the credit, the order resting again, the taker's leaves), with the signed head of the signer's record (`signer_record`) |
| `POST order_state` | Up to 100 resting orders by their ids, each that is published: `resting`, `exhausted` (it fills no more), `filling` (a fill of its coin is recorded and not yet signed; it is signed or dropped), `filled` (a fill of it whole is signed), `cancelled`, `landed` (its coin is on the chain, to land as SeqDEX's order; it takes no fill in the tree), `pending` or `unknown`, the coin it rests at, its asset and value, the coin's leaf key, salt, exit delay and terms, the fills left, its first expiry, the coin's record while it rests, and each fill, with whether it is signed. Not authenticated: a relay polls it |
| `POST tree` | The published tree of a batch, by its round's txid and output, with the signer's record's latest entry when its round was built, signed, every node as the server built it, each leaf's id and script and, for an `htlc-1` leaf, its terms (`htlc`), each leaf's preimage once its participation's went out, and the round's state |
| `POST rounds` | The rounds after a cursor (`after`, a round's number; `limit`, at most 100), oldest first, each with its txid, its state and the outputs of its batches; `next` names the cursor to read on from |
| `POST forfeit_leaves` | Takes a participation's forfeits and its new leaves' unroll authorisations, and returns its preimage; for a take in a round that fills orders and is not broadcast yet, takes them and returns no preimage (it goes out once the round is final) |
| `POST release_leaves` | Takes an owner's release of the lowest node of each coin it gave up, each naming the connector asset of the participation's round |
| `POST mailbox_read` | The coin records in a key's mailbox after a cursor, each a transfer made with the signed head of the signer's record that transfer was recorded at; with `notices`, the notices of coins pending (a transfer recorded and not yet signed) and withdrawn (that transfer dropped, with the reason) among them, in the same order (`kind` `pending` or `withdrawn`, `notice`), which a reader that does not ask for them is not served |
| `POST leaf_data` | Every leaf served to a key, after a cursor (`after`, `limit`, at most 100 a page and about a megabyte of records beyond its first leaf; `next` names the cursor to read on from): the leaves it owns, those whose owner key bound them to it, and the transfer outputs posted to it, in any state (`pending`, `live`, `spent`, `lost`, `expired`). Each comes with its record (a round's leaf's empty until its participation's preimage went out), its owner key and nonce, what it rests on (`batch`: its round, batch output, index in the published tree and participation, with the head of the signer's record when the round was built; `board`: its transaction output and state; `made_by`: the transfer that made it, with the head its last signature was recorded at; each head with the keepers' acknowledgements), and every way it was given up (`given`), each with its owner's own signature: a transfer, with the coin's checkpoint value and the owner's signature over its move into its checkpoint; a participation, with every part its id is a hash of, the coin's attestation, whether the coin was given back, and each forfeit of the coin recorded for it with the owner's half. The `htlc-1` leaf of a payment out of the tree that is paid is served `spent`, with the payment (`payment`: its hash and the preimage that proves it, which its owner checks opens the leaf's hash). The first page also serves every payment into the tree asked under a key bound to the key and not yet claimed or failed back (`receives`: its hash, asset, amount, fee, invoice, owner key and nonce, exit delay, `open` or `accepted`, and once held its participation and the leaf's timeout), so a wallet restored from its mnemonic takes up a leaf held, wanted or not yet released |
| `POST bind_mailbox` | Binds leaves made before their wallet named its mailbox key when it asked for them: up to 64 bindings, each an owner key, a mailbox key and the owner key's signature over the binding; answers the mailbox each key is bound to (a binding made before stands), or none for a key the server knows no leaf of |
| `POST witness` | Takes the heads of the signer's record a wallet holds (at most 32, each `{entry, hash, signature}`) and a nonce the wallet draws fresh for the call, hands them to the signer, and answers the running hash the record holds at each entry, each signed, its latest entry, signed (`head`), the record's end signed together with the nonce (`end`), and whether the signer is stopped (`stopped`), with its proof (`proof`: the signed head that stopped it and, when the record holds another there, that head, signed) |

`mailbox_read`, `leaf_data` and `plans` need a proof of the key: a challenge from
`challenge`, signed with BIP340 over the tagged hash
`SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key ‖ SHA256(request))`
with `T = SHA256("Arca/auth")`, where `request` is what the read asks besides
its proof: for `mailbox_read` its cursor (eight bytes) and page size (four),
little-endian; for `leaf_data` the same of its cursor and page size, or
nothing when it names neither (it then reads the first page); for `plans` nothing. The tag keeps it apart from
everything else a leaf key signs, the genesis hash to one chain, the call and
the request to one read, the challenge to a short while. A challenge is
stored nowhere: it is the time it was issued, 12 random bytes, and a keyed
check over both (HMAC-SHA256 under a key drawn once and kept in the
database, so every server on one database takes the others' challenges, and
its own across a restart), taken within its lifetime
(`challenge_ttl_seconds`, two minutes by default); a proof used again within
it repeats only the very read it was signed for, so whoever sees one (a
proxy, a log) learns nothing more than that read. There is no bearer token. `cosign_transfer` is
authenticated by the owners' signatures over the transfer itself, and so is
`lightning_send`; `lightning_send_status` and `lightning_receive_status` need
only the payment hash, and a preimage proves only a payment;
`lightning_receive` by the signature of the key the leaf is asked under,
issued at the operator nonces' rate; `lightning_receive_claim` by the
preimage and the owners' signatures over the transfer;
`submit_participation` by each owner's attestation over the participation,
and `distribute` by each coin's owner's attestation over the distribution;
`claims` by a proof of each key it names, as a mailbox read is;
`claim_leaf` by the claim key's signatures over the authorisations themselves;
`distribution_status` needs only the distribution's id;
`participation_status` needs only the participation's id, which is a hash
of its request, and `tree` and `rounds` are public. `bind_mailbox` is authenticated by
each leaf's owner key's signature over its binding. `forfeit_leaves` and `release_leaves`
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
`witness_source_per_second` and `witness_source_burst` for each source; 250
a second with bursts of 1,000, and 5 a second with bursts of 60, at the
defaults): a wallet makes one each command, and a caller that uses up the
nonces leaves every wallet its witness. The reads that serve a wallet what
the server holds for it and what it publishes (`leaf_data`, `mailbox_read`,
`tree`, `rounds`, `bind_mailbox`) have a budget of their own too
(`read_per_second` and `read_burst` overall, `read_source_per_second` and
`read_source_burst` for each source; 500 a second with bursts of 2,000, and
10 a second with bursts of 200, at the defaults): a wallet restored from its
mnemonic reads a page of its leaves, a page of its mailbox and a tree for
each round its leaves rest on. The witness's overall budget is set well
under what the signer answers: it keeps the signature of every head it made
or checked and hands that one out again, reads the running hashes a witness
asks for under its record's lock and signs after releasing it, and answers
witnesses on several threads, so on a release build it answers about 2,500
witnesses of 32 heads it never saw a second, on a record of 200,000 entries,
while a co-signature beside eight callers witnessing as fast as they can
waits a couple of milliseconds. A witness names at most 32 heads, of
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
connector's issuance, an offboard's reclaim) and of a taproot output; and the
operator's unroll authorisation for a node (`unroll`), `S`'s signature over
`SHA256("Arca/unroll" ‖ H ‖ t)` built from the node's children hash and a
median time: `S` is a member of every node, and the watcher answers a holder
who brings home a coin it gave up for a step of an offline refresh only after
unrolling that step's leaf, whose tree did not exist when the holder signed.
For an issuer-operated asset whose mint limiter it was started with
(`--issuer <instance file>=<mnemonic file>`), it answers one more request:
the mint at input 0 of a round (`reissue`), which it checks as Issuer-operated
assets says before the limiter's own tool (`--mint-limiter`) signs it with the
limiter's operator key, never `S`; it answers the witness of the limiter's
coin. For such an asset it signs no spend that pays a unit of it anywhere
but a bare `OP_RETURN`. It signs no digest it is handed and no release, and
nothing by a path that checks `S` with `OP_CHECKSIGFROMSTACK`. A rebindable
message for a `landing-1` coin, the leaf of a supervised asset, names the
coin's landing program: the signer builds the message over the constant
that binds it, and signs only while a node of its own
(`--supervision-node`) shows that landing free and the asset not paused (see
Supervised assets). The server
checks each signature it gets back against the message or signature hash it
built.
Beside those it answers reads of its record: its latest head, its entries
after one, a witness of heads (below), and the entries under a salt
(`under`), which the server asks before it takes a coin into a refresh.

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
signs one message, ever: a spend (a message into anything but a forfeit
output, or a fill of a resting order) or a forfeit. A forfeit request names
the forfeit's parts, and the signer rebuilds the forfeit output from them and
checks it is the one output committed to. The same message again is signed
again, so a request repeated after a signer outage completes; any other
message under a salt that has an entry is refused (`already_signed`),
whatever the database holds: a second spend, a spend after a forfeit, a
forfeit after a spend, and a second forfeit, for any round. Two messages
under one salt are what burns the operator's bond ("The equivocation bond"),
so the signer never makes them. The server refuses a second leaf under a salt it has seen, so two
leaves share a salt only where its database has forgotten one; there the
first to spend takes the salt and the other's holder is refused, and can
exit, while a second signature, which would also spend the first coin, is
never given. The server answers such a
refusal with `double_spend`, and logs that its database has lost a spend.
The server asks the signer what it holds under each input's salt before it
asks for any signature of a transfer, so whatever the signer holds there
(another spend, or a forfeit: a coin given up in a refresh and given back
while its forfeit stood in the record), nothing of the transfer is signed:
the server drops the transfer's record, gives its inputs back, answers
`double_spend` naming the coin and what the signer holds, and logs a
forfeit as a forfeit, not a lost spend. The wallet then shows that coin as
given up, and takes it home on the chain.

The record cannot be lost, cut back, torn or shared without the signer
noticing:

- **Lost.** The signer starts only on its record. One is made once, for a new
  operator key, by `arca-signer --create-record`, which names the record's
  keepers for its whole life (see [The keepers](#the-keepers)) and refuses a
  path where a record is; a signer pointed at a path where there is none does not start,
  so a lost record is never silently replaced by an empty one, which would
  sign again what was signed before.
- **Cut back or replaced.** The record's first line names its format, the
  operator key, the chain and the record's keepers, and a record of another
  key or chain does not start. Every entry carries its number and a running
  hash over everything before it, the first line included, so an edited line
  stops the start. The server's database
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
salts. The new record's first line names the old record's keepers, and its
latest entry and running hash, from which its own entries go on, so the entry the server's
database knows is still the record's. It keeps the salt of every entry it
drops, and of every entry an earlier compaction dropped, in a sorted line
`dropped <salt>` each, and the signer refuses any message under a kept salt
(`already_signed`): `S` signed one under it, and a second would burn the
operator's equivocation bond. It carries every other entry's line over
verbatim, and for every entry it drops a line with that entry's number and
running hash (with the kept salt, about 140 bytes an entry, on disk), with a
hash over the keepers, the kept salts and those lines in that first line,
which the signer checks at start. So the record answers the running hash at
every one of its entries, and refuses every salt it signed under, for its
whole life. A record compacted by a signer that kept no salt (formats 2 and
3, and format 4 with a compaction's fields; `record`'s `salts_lost`, and a
line at the signer's start, say so) is signed under a dropped salt again
until it is compacted once more: that compaction keeps every salt the list
names, the ones dropped before with them, since `expired-salts` lists every
expired leaf's salt.
The compaction also writes the new record's side files beside it,
`<new file>.acknowledged` and `<new file>.keepers-seen`, carried over from
the old record's. The operator then moves the new file and those two side
files into the old ones' places together (`<record>`,
`<record>.acknowledged`, `<record>.keepers-seen`), and starts the signer
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
SHA256("Arca/keeper-latest")`. An acknowledgement also names the latest head
the keeper held when it was asked, with `S`'s signature, and the keeper's
signature over `SHA256(T ‖ T ‖ genesis ‖ S ‖ entry ‖ hash ‖ nonce ‖ 0x01 ‖
latest entry ‖ latest hash)` (`‖ 0x00` alone when it held none), `T =
SHA256("Arca/keeper-held")`, `entry` and `hash` the head it acknowledges.
Nobody on the path can make an acknowledgement, replay an older latest, or
hide what the keeper held. Its heads file, like the
record, is made once on purpose (`--create`), locked while it runs, and
synced when it is opened; a last line cut short by a crash is removed.

The keepers are part of the operator's identity, fixed when its record is
made: `arca-signer --create-record` takes each keeper's key (`--keeper-key`,
as `arca-keeper --pubkey` prints it) and how many of them must hold every
head (`--keepers-required`), and writes them into the record's first line
(`keepers=<required>:<key>,<key>,…`), under the running hash every head
commits to while the record has not been compacted. From then on the signer
serves only with that set. Its command
line says only where each keeper is reached (`--keeper <host:port>=<key>`):
one address for every key the record names, and none for a key it does not
name. A start that lacks one, or names another, is refused, saying which key
has no address or which is not the record's, so a restore of the machine, or
a start script that lost a flag, gives a signer that does not start rather
than one that serves without its keepers. A compacted record carries the set
over, but there it is covered only by the carried hash, which anyone holding
the file can compute again without a key: a compacted record's first line,
edited, still opens, every running hash the one the database knows. What
refuses it is the server, which pinned the set in its database the first
time it read it, does not start against a signer naming another, and stops
serving when it finds one under it while it runs; and
every wallet that pinned the set before. Changing the set, replacing a keeper whose machine or key was lost, or
adding keepers to an operator that had none, is a new operator: a new key
and a new record. So an operator requires fewer than all of its keepers (two
of three), so that one lost keeper does not end it at once.

After it has written and synced an entry, the signer hands the
record's latest head, signed, to every keeper, and releases the
co-signature only when the required number have acknowledged it; otherwise
it answers `keepers_unavailable` (the server's `signer_unavailable`), the
entry stays, and the same request again completes once they do. Requests
waiting at once share one hand-over. A keeper takes a head past its latest
on its number alone, without knowing whether it extends what the keeper
holds, so the signer checks the latest head each acknowledgement names
against its record before it releases anything: a latest the record does
not hold, past its end or with another hash, is the proof of a rollback
and stops the signer, as at a start. A signer restored together with its
memory has passed its start check already; whether its first hand-overs
miss the keepers or several requests arrive at once before the first
hand-over, the first acknowledgement that names a keeper's latest from the
lost window stops it before it releases a second spend.

At start, and before the first signature after a start, it asks the keepers for their latest: a keeper's
head past the record's end, or with another hash at an entry the record
holds, is the proof of a rollback, and stops the signer as a wallet's head
would; and until enough keepers have answered it signs nothing the record
governs. Enough is the keepers minus the required plus one, so that any set
of keepers that acknowledged a head includes one that answered: with all
of them required, one answer is enough; with one of two required, both
must answer. A keeper that holds no head is no answer once a head of the
record has been acknowledged by as many keepers as it requires: the signer
notes that beside its record the first time it happens
(`<record>.acknowledged`, synced, carried over by a compaction), and
releases nothing until it has. Before then the keepers of a new operator
have held nothing, and their "no head" counts.

A keeper is only as good as its heads file. One whose heads file is lost,
or would come back from an older copy, no longer holds what it
acknowledged: it is a lost keeper, and it is never started again under its
key, neither on a new heads file nor on an old one. With two of three
required, the operator runs on with the other two and moves to a new
operator, a new key and a new record that its holders' coins are refreshed
into, while it still can. With one keeper, or with all of them required,
the keeper's heads file is the whole of the protection: a lost keeper ends
the operator, and the file lives on durable storage of its own, never
restored, and never on the signer's machine. Where the signer can tell, it
counts a lost keeper no more, and says so: a keeper that names no head once
a head has been acknowledged, or a latest below one it was seen to hold.
What it has seen each keeper hold, and which keepers are lost, it writes
beside its record (`<record>.keepers-seen`, synced, carried over by a
compaction) before it releases anything that taught it more, and reads at
every start, so a keeper that goes back is lost across restarts of the
signer as within one run; it releases nothing it cannot write there. It
writes that file before it notes the first acknowledged head, so a record
with `<record>.acknowledged` beside it has `<record>.keepers-seen` too, and
the signer refuses to start on one that has the first and not the second,
naming both files: taken for empty, the missing file would forget every
lost keeper and every head a keeper was seen to hold. A record whose signer
kept no such file (one made before the signer kept it) is started once with
`--start-keepers-seen` ([Moving to a new revision](#moving-to-a-new-revision)). A
restore of the signer's machine, from disk or with its memory, brings that
file back as old as the record, and a signer so restored cannot tell a
keeper restored from an older copy from one that lagged, which is why the
rule is the operator's to keep.

A keeper restored from an older copy, or a second signer run under the
operator's key on a copy of the record, defeats the keepers: the signer's
second spends then go out acknowledged by keys every wallet trusts. No check
of the signer's can tell either from an honest keeper that lagged, so this
is an operator's rule, not a limit the code keeps for it. Nor can the signer
tell a keeper whose key is in other hands, which can name any head that
keeper once held: a keeper's key is guarded as the operator key is.

Every head the signer hands out carries the acknowledgements it has of it,
and they travel with the head wherever a head travels: `info`, the witness
answer, a transfer's answer, a mailbox record, a published tree (the server
keeps them, by head, in its database). `info` names the keepers' keys and
how many are required (`keepers`), as the record names them. A wallet pins
them when it is created, as it pins the operator key, and from then on takes
no coin and keeps no head that lacks the required acknowledgements; an
operator that shows other keepers is not the operator it pinned, and is
refused as one showing another key is. A keeper on the signer's own
machine adds about three milliseconds to a co-signature (its
acknowledgement, and what the signer writes beside its record, synced), and
one 50 ms away each way about 100 ms more: one round trip, over a
connection the signer keeps open to each keeper.

A record made with `--no-keepers` says so in its first line
(`keepers=none`) and never gains any: the signer refuses `--keeper` on it,
and on a record of the formats before records named keepers, which is a
record without keepers. Its signer says so when it starts; `info` names no
keeper, and a wallet says so in its own `info` and on every coin it
receives out of round. Such an operator's record rests on
its own machine alone: a restore of that machine, its database and record
together, can let a coin paid out of round be spent twice, until a wallet
holding a later head witnesses. Such an operator is for its own coins.

## Running

An operator that holds other people's coins follows
[the operator's procedure](../doc/operator-procedure.md): how it is made,
what is never done, how its storage is kept and restored, and what its
holders are told.

### A new operator with keepers, in order

Every key is 32 random bytes as 64 hex characters, in a file only its owner
can read (`load_key` refuses one others can). The genesis hash is the
chain's block 0, as `sequentia-cli getblockhash 0` prints it. Three keepers,
each on a machine of its own, two of them required:

1. On the signer's machine, the operator key and `S`, its public half:

        umask 077; openssl rand -hex 32 > /etc/arca/operator.key
        arca-signer --key-file /etc/arca/operator.key --pubkey     # prints S

2. On each keeper's machine, its own key and its public half:

        umask 077; openssl rand -hex 32 > /etc/arca/keeper.key
        arca-keeper --key-file /etc/arca/keeper.key --pubkey       # prints the keeper's key

3. On the signer's machine, the record, naming the keepers for good, once:

        arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
            --create-record --keeper-key <keeper 1 key> --keeper-key <keeper 2 key> --keeper-key <keeper 3 key> \
            --keepers-required 2

4. On each keeper's machine, its heads file under `S`, once, then the keeper,
   admitting the signer's address alone:

        arca-keeper --key-file /etc/arca/keeper.key --operator <S> --genesis <genesis hash> \
            --heads /var/lib/arca/keeper.heads --create
        arca-keeper --key-file /etc/arca/keeper.key --operator <S> --genesis <genesis hash> \
            --heads /var/lib/arca/keeper.heads --listen 0.0.0.0:7341 --allow <the signer's address>

5. On the signer's machine, the signer, saying where each keeper is reached,
   then `arcad`, which pins the keepers the first time it reads them, and the
   operator's wallet, funded:

        arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --socket /run/arca/signer.sock \
            --record /var/lib/arca/signer.record \
            --keeper keeper-1.example:7341=<keeper 1 key> --keeper keeper-2.example:7341=<keeper 2 key> \
            --keeper keeper-3.example:7341=<keeper 3 key>
        arcad /etc/arca/arcad.toml
        arcad /etc/arca/arcad.toml address     # a receive address of the operator's wallet, to fund it

An operator without keepers, for its own coins, makes its key as in step 1,
its record with `--create-record --no-keepers` in place of the keepers, and
starts the signer without `--keeper`.

While it runs:

    arcad /etc/arca/arcad.toml expired-salts > expired.salts           # what the record no longer needs
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
        --compact-into /var/lib/arca/signer.record.new --drop-salts expired.salts   # with the signer stopped
    for f in "" .acknowledged .keepers-seen; do                         # the new record and its side files, together
        mv /var/lib/arca/signer.record.new$f /var/lib/arca/signer.record$f
    done
    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --record /var/lib/arca/signer.record \
        --clear-stopped                    # removes the proof of a rollback, with the signer stopped

The keeper's key file holds its 32-byte secret key as 64 hex characters,
readable by its owner alone. A keeper speaks plain TCP, one JSON object a
line: every answer it gives is signed by its key over the asker's nonce,
and it takes nothing but heads `S` signed, so it needs no TLS. It is
reached from the signer alone: it admits a connection only from an address
`--allow` names (the signer's machine, one `--allow` for each address it may
come from). Any other gets one answer, to its first line, before the keeper
closes it: `refused: this keeper admits connections only from the addresses
its --allow names, and <address> is not one`. A signer refused so (one that
moved, or reaches the keeper through NAT or another address family) says
why, at its start and in every `keepers_unavailable` it answers, and
co-signs nothing until the keeper's `--allow`, and its firewall, name the
address it now comes from: change every keeper's `--allow` before the
signer moves. The keeper holds at most
`--max-connections` open (16 by default; the signer keeps one); holding
that many, it closes the next at once with nothing said, from whatever
address, so a stranger is told why only while the keeper has room. It
closes one left idle for `--idle-timeout-ms` (60 seconds by default; the
signer opens a new one when it next needs it), and when an accept fails (out
of descriptors, say) waits before accepting again, saying so once in a while.
A firewall that admits the signer's address alone to the keeper's port does
the same a step earlier, and is the better place for it where the machine
has one. A keeper whose heads file is lost, or would come back from an
older copy, is a lost keeper (see [The keepers](#the-keepers)), and is never
started again under its key. Its key file is backed up as the operator key
is, for one case: a key file lost while its heads file survives. A keeper
whose key is lost without a backup cannot be replaced, since the record
names it for good.

`arcad` serves another asset without a restart: add its `[[assets]]`
entry to the configuration, pay the operator's wallet coins of it (`arcad
<config> address`), and send `arcad` SIGHUP (`systemctl reload`, with
`ExecReload=/bin/kill -HUP $MAINPID`). It reads the configuration again and
from then on serves the asset at every entry, builds its rounds from its pool
and publishes it in `info`, in the configuration's order; an asset's
smallest leaf, its fee schedule and its rate source, `[fees]`'
`refresh_ppm` and `offboard_ppm`, and the assets a round's fee is paid in
(`fee_assets`) are taken the same way, and every rate source is read at
once. A configuration that does not read, or that leaves out
an asset served now, is refused whole and logged, and the server runs on as
it was: an asset stops being served only at a restart, after which the
server takes no new work in it (a transfer or a refresh of its coins is
refused, a participation of it waits) and its holders take their coins on
the chain. Any other setting that changed takes a restart; the log names
it, and the reload leaves it as it was.

`arcad` stops its tasks and exits on SIGINT, so a service manager is set to
send it that signal (systemd's `KillSignal=SIGINT`). The signer is stopped
with SIGTERM: a SIGINT sent from a background shell does not reach it, and a
second start then finds the record held by the first.

### Moving to a new revision

`arcad` and `arca-signer` speak one protocol to each other, so they move
together, built from the same revision. Stop `arcad` (SIGINT), then the
signer (SIGTERM). Start the signer on its record as before, then `arcad`,
which moves its database to the new schema in place at its start. A record
with `<record>.acknowledged` beside it and no `<record>.keepers-seen` (one
made before the signer kept that file) does not start; start it once with
`--start-keepers-seen` added to its command line, which writes that file,
nothing seen of any keeper yet, and from then on is refused:

    arca-signer --key-file /etc/arca/operator.key --genesis <genesis hash> --socket /run/arca/signer.sock \
        --record /var/lib/arca/signer.record --keeper … --start-keepers-seen   # once, for such a record

Never pass it for a record whose `<record>.keepers-seen` was lost: put the
file back from where it lies. Each keeper restarts on its own heads file.

The operator moves before its wallets. A request carries what the revision
that sends it knows (a wallet names its mailbox key when it registers a board
or asks for a leaf, and its receiver's lapse when it pays a request), and the
server refuses a field it does not know (`malformed`), while it takes a
request from a wallet of an earlier revision as that wallet sent it.

[`arcad.example.toml`](arcad.example.toml) lists every setting: the listen
address, the database, the signer's socket, the wallet's mnemonic file, the
node's RPC, the finality rule, the exit-delay bounds, the assets served
with their smallest leaf, how often a round is built, the assets a round's
fee is paid in, the fee schedule, the watcher (`[watcher]`: whether it
acts on its own, early reclaims, the most outputs a sweep takes, how often its
recovery work runs), and the limits on what the unauthenticated calls leave
behind (`[limits]`: the rate of nonces, and the witness's own, for each source and overall, the
proxies trusted to name a request's source, a nonce's lifetime,
how long a board may stay out of every block), where the operator's
metrics are served (`metrics_listen`, a loopback address), and how takes of
on-chain orders are bounded (`[fills]`: how long before its refund an order is
no longer taken, and how long a round that fills orders waits for its takes'
forfeits). The node must run with `-txindex` and `-validateanchor`.

The exit-delay bounds (`exit_delay_units`) change only with a restart, and
they govern the leaves the operator makes from then on: a board, a refresh's
new leaves and a transfer's outputs outside them are refused (`out_of_bounds`),
and so is a coin given up whose leaf or lineage lies outside them
(`invalid_coin`, "… an exit delay of N units; the wallet accepts MIN to MAX"),
so a coin made under other bounds is refreshed, offboarded or paid on by no
round or transfer of this operator: its owner takes it home by its exit, which
needs no operator. Everything the server took before the change is still its
to finish, under the delays its own records carry: the watcher answers such a
coin on the chain with its forfeit or checkpoint and sweeps its batch at the
expiry, a round built before the change takes its forfeits after it, and a
board registered before it is credited. A participation still pending that
wants a leaf, or gives up a coin, outside the new bounds can never run and is
voided, saying why, its coins given back.

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
  outpoint and a zero contract hash. So a coin whose token already names a
  batch, of any round (the issuing coin of a round retired or lost, freed
  again), never issues again, since its token would be that batch's; it can
  still pay a round as an ordinary input. The token is issued with denomination 8,
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

`tests/supervised.rs` issues an asset under the supervision descriptor,
with the pause capability, and serves it supervised after a reload (a
configuration naming another asset supervised is refused). Its signer reads
freezes from the test's node. A board and a refresh of the asset into a
`vtxo-1` leaf, and a board or a transfer with another allowance, are refused;
a holder boards, refreshes into a batch every leaf of which is `landing-1`,
read back from the published tree, and pays another out of round. A freeze
of the first holder's landing is mirrored at once: its transfer, a swap with
it, its refresh, offboard, take of an on-chain order, resting-order fill,
distribution, plan and Lightning payment are each refused with `frozen`, and
the signer refuses the coin on its own node (a signer reading no node
refuses it too). The other holder still pays the frozen one. A pause
refuses the other holder until its lifting is final, as the freeze's lifting
does the first; a participation taken before a freeze is voided when its
round is built.

`tests/issuer.rs` also needs the mint limiter's tool, named by
`MINT_LIMITER` (sequentia-contracts `tools/mint-limiter`, with its `sign`
command), and runs its chains with Simplicity active. On the proof-of-stake
chain an asset is issued with its reissuance token straight into a limiter
and served issuer-operated: a holder boards it, two refreshes each mint
exactly their batch's value from the limiter's coin at input 0, its
successor at output 0; the board taken back is burned whole; an offboard
that would pass the window's allowance waits, saying why, and is minted
once the window ends; both batches are burned by their sweeps after their
notice, their fees in another asset; and the asset's supply, read from every
block, is back at its level before the first round less the fee the holder
paid for its offboard, which was burned, as `issuer_supply` says
transaction by transaction. On the chain without proof of stake, the
server's round minting within the allowance is the control for the same
round minting one atom over it, its mint and its wallet inputs signed again,
which a block refuses (`Assertion failed inside jet`); and a second refresh
that would pass the allowance waits.

The Lightning tests (`tests/lightning_*.rs`) also run SeqLN nodes beside the
server: `LIGHTNINGD_EXEC` names a SeqLN `lightningd` (`make all-programs` in a
SeqLN checkout), whose hold-invoice plugin is taken from the same checkout,
and `sequentia-cli` is taken beside `SEQUENTIAD_EXEC`. They run on the chain
SeqLN's `sequentia-regtest` network assumes
(`sequentia_ext::regtest::Regtest::start_seqln`), with nodes started and
spoken to by `sequentia_ext::lightning`. Without `LIGHTNINGD_EXEC` each says
it is skipped and passes. `tests/lightning_legs.rs` starts an operator node in
asset X and one in Y, each with a channel to a node of its own, and serves Z
with none: `info` shows X's and Y's legs up with their nodes, Z with none; Z
is refused `no_lightning`, an asset not served `out_of_bounds`, receiving in Y
(whose node runs no hold-invoice plugin) `no_lightning`; with Y's node
stopped its leg is down with the reason and refused `lightning_unavailable`
while X's goes on; and Y named, by a reload, a node whose channels are in X
is down, the reason naming the assets its channels are in; and an invoice of
the Bitcoin node's is refused at X's leg (`invoice`), its network not the
leg's. `tests/lightning_pay.rs` pays an invoice in X from a coin in X and one in Y
from a coin in Y: each is paid at the payee's node, its preimage the hash's,
and the books hold to the atom (the leaf holds the amount the operator's node
paid and the operator's fee; the payee's channel gained the amount). A paid
leaf is refused back to its owner. Forced past a wallet, each of these is
refused before anything is signed and records no payment: a coin in X paying
an invoice in Y (its leaf in X, or in Y), a coin in Y paying one in X, a leaf
an atom short of the fee or over it, locked to another hash, with another
operator delay, a timeout too near or too far, the owner's direction, an exit
delay below the operator's least, an invoice for no amount, expiring within a
minute, locking longer than the leaf leaves room for, or no invoice at all,
two `htlc-1` leaves, an `htlc-1` leaf by a plain transfer, and a second
payment of a paid invoice; Y's invoice with Y's node unreachable
(`lightning_unavailable`) and with Y served by no node (`no_lightning`),
while a paid request repeated then is answered as before. A payment to an
invoice its payee dropped fails, and its leaf goes back whole into a new leaf.
The paid leaf in Y, taken on-chain by its owner, is claimed by the watcher
with the preimage once the operator's delay has run, and not before.
`tests/lightning_receive.rs` receives in X and in Y: each invoice, read by
the payer's node, is valid, under the wallet's hash and in its asset; each
payment is held, its leaf made by the asset's next round, validated by its
owner from the published tree and completed with no forfeit; the payment is
settled at the payer's node only once the owner hands over the preimage with
its claim, and the books hold to the atom. Refused, nothing made: a request
signed by another key, an exit delay not past the operator's delay, an
amount whose leaf is below the smallest, an asset not served, another
request under a hash or a key asked for, a claim before the leaf is the
owner's, with another preimage, the leaf spent by a plain transfer, and a
request in Y with Y served by no node. A leaf taken on-chain and never
claimed is refunded by the watcher once its timeout has passed, not before,
and its payment failed back to the payer, a late claim refused; a leaf
claimed on the chain by its owner settles its payment from the preimage the
claim reveals.

`tests/lightning_internal.rs` pays a receive's invoice from a leaf of the same
operator: the payment is held by the send leaf (`held_by: send`), the node's
hold invoice is cancelled and an outside payer of the same invoice fails, the
receiver's claim with its preimage decides the send `paid` with the channels'
balances unchanged, and the paid leaf is refused back to its payer. Refused
before anything is signed: a send leaf whose timeout leaves the receiver's
leaf less than its least lock (`htlc`), and an invoice an outside payer's
payment already holds at the node (`in_use`). A receiver's leaf never
claimed fails the receive back and the send with it, the payer's leaf
co-signed back to it and a late claim refused. A preimage posted to
`lightning_preimage` is refused with nothing held, before the leaf is its
owner's, for another hash (`htlc`) and for a hash nobody receives under
(`unknown_payment`); posted once the leaf is its owner's, it decides the send
`paid` and the owner still claims.

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

`tests/distributions.rs` runs a claim tree: a payer's distribution of five
claims from two boards, its forfeit step with no authorisation for a claim
leaf (one with any refused `leaf_set`), each holder's lookup proven with its
named key (another key's proof refused), one holder's authorisations by its
named key refused and by its claim key taken, its take-up by a transfer and
a second spend refused, the payer's spend of another holder's claim leaf
refused for its signature, its coin refreshed in its free window; then the
claim batch's expiry, release, notice and sweep, after which the watcher
pays the four claims nobody took up back to the return script, exactly, in
one transaction, and nothing more at a later pass, while the holder that
took its claim up still holds its coin. Every refusal of a distribution is
asserted by its code and printed: a key named twice, claims that do not
balance, a claim below the smallest leaf, an exit delay out of bounds, a fee
in another asset, an Arca script, a script that is no standard address or
none as the return script, an
attestation by another key, an asset not served, a claim key another
distribution wants, authorisations before the distribution is released, and
a lookup naming no key.

`tests/reserving.rs` re-serves a wallet's leaves to its mailbox key. A board
bound to it, a transfer's change posted to it and a leaf a participation
wants bound to it are each served to that key, in each state they pass
through, with what each rests on and each way it was given up: the board's
checkpoint signature and the change's attestation and forfeit are checked to
be the owner's own over the messages they sign, the participation's id is
recomputed from the parts served, and a round's leaf is served without its
record until its preimage went out. A binding signed by another key, or
naming a mailbox without its proof, is refused; nothing of a key the request
does not prove is served; pages of one leaf give the same leaves, and a
page's proof is good for that page alone; `bind_mailbox` binds a leaf made
without a binding, keeps the first binding of a key, binds nothing for a key
the server knows no leaf of, and refuses too many at once. A source past its
read budget is refused `rate_limited`. The published tree lists every node,
level by level, as a rebuild gives it, the last level the batch output the
round pays, and each leaf's id; a leaf's preimage is published once its
participation's went out and not before, and from the published tree
alone, a preimage it publishes and authorisations its owner signs again,
the leaf validates against the round as the leaf its owner first took.
`rounds` lists the round with its batch and pages on.

`tests/address.rs` runs `arcad <config> address` beside a running server:
each run hands out the next index, the address is the node's for the script
printed, the server's own next script is another, a coin paid to it is the
wallet's and spendable once final, and the index goes on after a restart.

`tests/round_e2e.rs` runs rounds as wallets meet them. Eight participants in
two assets, one refreshing coins of both in a participation for each and one
leaving half on-chain, share a round for each asset, built in one pass; each
validates its leaves from the published trees,
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
Y not, into a round for each asset in one pass: a batch and a token in each,
an offboard in X's, the connector, nLockTime 0, the operator's coins only,
the fee in X, the wallet holding no policy asset. Once the rounds are final,
each owner validates its
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

`tests/plans.rs` runs offline refresh against the whole server: a plan of
two steps from a coin of a round, each step run in its coin's free window
with no holder present, its participation wanting the plan's leaf, the old
batch released and swept only after the step, and a coin a step gave up
brought on the chain answered with that step's refund, which pays the holder
the step's value at its address. A stopped plan's coin is held, its batch not
released past its expiry, until the holder cancels the plan. A step whose
round is lost (its block disconnected and the operator's input taken by
another transaction, final) is void, the plan stopped, and the holder takes
the coin the step gave up home with nothing answering it. Every refusal of a
quote and a plan (an operator script not the quote's, a holder address that
is an Arca script, a nonce the quote did not draw, an unbalanced step, an
exit delay above the operator's, a second plan of one coin, seven steps,
another key's attestation, a board, a key another plan holds) is asserted by
its code.

`tests/signer_outage.rs` takes a batch to its expiry with the signer
stopped: the watcher's passes cannot sign its token's release, and the
wallet can spend as much as it could before (without the coins going back,
four passes left it nothing of the asset); once the signer is back, the
release goes out.

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
participation in Y wants: in one pass X's round takes the participation in
X, Y's is not built and the one in Y waits and says why, and the next round
takes it once the wallet is paid more Y.

`tests/rates.rs` prices X by the node's own rate, Y by a file and, in a
second server, X by a command: `info` shows each rate, its source and its
age, and a smallest leaf set as a value in atoms at the asset's rate (a board
below it refused); a file that stops reading keeps the last rate, saying
why. Once Y's file says a time two hours back, past the hour a rate is good
for, Y's rate is stale: a board and a participation of Y are refused
`rate_stale` (503) naming Y, while a participation in X is taken, the
participation in Y taken before is answered and runs in Y's round beside
X's, and a coin of Y is paid on; once the file is fresh again a board of Y
is taken. A file dated a day ahead is not taken: no rate, the failure saying why, until it is dated now.

`tests/asset_fees.rs` sets a schedule per asset: X its own parts per
million and fixed parts in X's atoms, Y the defaults and a fixed part as a
value, taken at Y's rate from a file. `info` publishes each asset's schedule
and the defaults at its top; a refresh in each asset one atom short of its
schedule is refused `fee`, naming the asset and its schedule, and the exact
fee is taken; so is an offboard of X with its coin's refresh; a new rate
moves Y's fixed part in atoms; and a reload takes X's new schedule and the
new defaults Y takes.

`tests/asset_sweep.rs` lists X and Y for fees, X the first fee asset, and
takes a batch of Y through its expiry: its token's release pays its fee from
Y's pool and the sweep from the Y it sweeps, and nothing of X's pool moves
for Y's batch.

`tests/assets.rs` serves X and Y each on its own. Participations in X and Y
run in rounds of their own: X's round spends X's pool alone and pays X alone,
Y's (Y not accepted for fees) pays Y's batch from Y's pool and its fee from
X's, and each owner validates its leaf from its round's tree. A participation
carrying both assets, or a Y coin for an X leaf, is refused `out_of_bounds`
naming both. An asset not served (Z) is refused at every entry, its id named:
a board, a transfer's output, a participation's leaf, offboard and fee. And
`arcad`, run as a process serving X, refuses a board of Y; once Y is added to
its configuration, its pool paid and SIGHUP sent, the same process serves Y
(the board is credited and refreshed in a round of Y), and a configuration
leaving out X is refused whole.

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
pays the operator back: the round is retired and its leaves lost. The two
participations whose forfeits for it the signer co-signed are never run
again, void, their coins given up for good (a transfer of one refused), since
the signer co-signs one message under a coin's salt, ever; one of them had
its preimage out (giving up a leaf whose lowest node its owner had
released), and its release is retired. The third, whose forfeit never came,
runs again in a new round under a new unlock hash and operator nonce, as an
ordinary participation, and completes. The release is void on the chain as
well: the lost round's connector asset cannot be issued, and the node
refuses the reclaim of the released node with the release and the new
round's connector asset, or with none, so the node stays its owner's. Last,
the owner of the first brings its old coin on the chain (its node unrolled by
its own authorisation, its entry unlocked), and nothing answers it: its only
forfeit names the lost round.

`tests/rerun.rs` holds a lost round to its participations' coins. A board
whose forfeit for the lost round the watcher published is never taken into
its re-run: void, saying why, its coin not given back, the server's copy of
that forfeit never broadcast again, no preimage for the re-run; the forfeit,
sent by whoever saw it, confirms and is refunded by its owner once its delay
has run. A board whose forfeit the signer co-signed and nobody published is
not run again either, its void saying that the signer co-signs one message
under a salt, ever. A participation of the round whose forfeit never came
completes in the next round with its preimage. A forfeit for the lost round
the watcher logged and never got onto the chain is given up: not broadcast on
a pass, once the node takes its fee asset again or after a restart; the log
refuses another naming the round; an exit of a coin given up in it is
answered with no forfeit, and that coin, its output spent, is never taken
into its re-run. A sender's change on a board's lineage, and on a batch
leaf's, stays live off the chain after the receiver's re-run completes,
nothing of the lineage published, and the sender pays with it.

`tests/rerun_returns.rs` brings a lost round back, every reorganisation driven
through the parent chain: the round R goes out with its Bitcoin block, another
transaction X takes its input, and the participations whose forfeits for R
never came run again in Y, while those whose forfeits the signer co-signed
are void, the signer co-signing one message under a salt, ever. Then the
parent chain takes X out and R, sent again, confirms in its place, and every
other transaction of the disconnected blocks is sent again after it, in its
order, as a node puts them back in its mempool. Where Y spends an input of R
that was still unspent, and where it spends X's output (R's only input
taken), the node refuses Y once R is in the chain (`missing-inputs`), the
server restores R and retires Y: A, released in R, is back in R with its leaf
live (its first unroll taken) and its board claimed with its forfeit for R;
C, run again in Y, is left void, its forfeit for R never signable beside its
forfeit for Y, its leaf of Y lost and its board its own. Where X pays the
operator nothing and R had no other input, A is voided and restored when R
returns, its board claimed with its forfeit for R, and a participant that
gave no forfeit is voided, no coin of the operator's keeping a re-run apart,
its coin given back. A participant whose forfeit for R the watcher published
while R was final, voided while R is out, is restored with R and its forfeit
claimed with R's connector asset; one that refunded that forfeit while R was
out keeps the refund, and its leaf of R is never credited, though its first
unroll is valid. Where A's board's forfeit for Y was published and claimed
before the reorganisation, that forfeit comes back with it and confirms
beside R, Y's claim never can, and A is left void with its leaf of R never
credited and its preimage never out (A's refund of Y's forfeit opening after
its delay); and where A, voided while R was out, exited its board below X,
its leaf of R is never credited, its first unroll valid. After each restore
an ordinary round is built; and the same, with a round built after each,
through the reorganisations both ways (R lost and A run again in Y, R back,
R lost again, Y back): the next round never issues from a coin whose token
names a batch, and A's leaf of Y is the one credited while Y stands, none
while R does.

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
(`invalid_coin`) and in a refresh, and the watcher still publishes nothing
while it rests live on the lineage; from the board's expiry the watcher
publishes the board's checkpoint, the reassignment and B's forfeit, and
claims it, the change coming on the chain as its owner's leaf; once the
claim is final it no longer scans B's coin. And an anchor-driven
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
in Y, which it does not, each in its asset's round, both built in one pass:
nothing is unlocked before the owner's forfeit; then
the watcher unlocks each output to its destination, the margin paying in X and
a coin of X paying for Y, and the boards given up come back, Y's forfeit and
claim paid by coins of X. An offboard whose owner never hands over its forfeit
expires with its participation: the coin is the owner's again, the output is
neither unlocked nor reclaimed early, a reclaim signed before the delay is
refused by the node, and after the delay the watcher reclaims it. An owner who
offboards a batch leaf, is paid on-chain and then brings the leaf back
on-chain is answered by its forfeit and the claim, and its exit is refused.

`tests/expiry.rs` moves the chain's median time on. A participation whose
forfeits have not come is still issued a day after its round was found final,
and expires past its coin's exit deadline: its coin is live again, its new
leaf is expired, a good forfeit for it is refused and stores nothing, its new
leaf's key is free again and wanted by a new participation, and a
participation of the same round whose forfeits came is untouched. So does
one whose forfeit came while the signer was away and was never co-signed:
the forfeit is dropped, the coin stays given up (its forfeit may be in the
signer's record), and the signer is asked nothing for it once back. A
forfeit recorded while the signer was away and filled in once it is back
releases its participation at the next pass, the new leaf credited. Two
coins given up together, the forfeit step stopped between their two
co-signatures (a gate in front of the signer lets the first through): past
the deadline the participation waits, no coin given back and the second
forfeit kept; the gate opened, the second forfeit is filled in, the
participation released, and the watcher takes both boards by their
forfeits and claims them. A forfeit filled in after its owner took the
board on the chain and its exit delay ran is not released, and its owner's
step gets no preimage; the owner's claim made final, it never is, the new
leaf never credited. A payment out of a coin given back while the
signer held its forfeit (the database put as an older server left it) is
refused `double_spend` naming the forfeit, twice alike, the transfer's
record dropped and the coin given back each time; given as the second input
of a payment out of a good board, and of a swap against another owner's
board, it is refused before the signer signs anything, its record gaining
no entry, the transfer's record dropped and both coins given back, and the
good board pays alone. Such a coin offered in a
participation with another, and a board whose spend the signer holds and the
database lost, are each refused `double_spend` when offered, naming the coin
and the entry, nothing recorded. A participation taken before that check
whose forfeit the signer refuses for good (a spend under the coin's salt)
while its other forfeit is whole waits past the deadline; once the other
coin's owner takes its board on the chain and the watcher claims its
forfeit, the participation is released and its leaf credited.
Of two participations of one round, one whose forfeit comes 25 hours after
the round was found final is released, and one whose forfeit never comes is
still issued ten minutes before its coin's exit deadline and expires ten
minutes after it. On batch leaves of a round whose first expiry is
`E`: six days before `E` a refresh is charged for the day before the free
window, and refused one atom short; four days before it is free and runs; a
round time asked for past the exit deadline is refused; past the exit
deadline a coin is refused; and a participation accepted before the deadline
whose coin passes its exit deadline with no round taking it is voided by the
next pass over the rounds, no round built, its coin live again.

`tests/bond.rs` posts and names the equivocation bond on the
proof-of-stake chain: `info.bond` reads `unposted` with its terms, and the
address `bond-address` prints is its script; `bond-post` refuses a treasury's,
a reserve's, an escrow's and a faucet's wallet by name and pays the bond from
an operating node wallet, its fee in the bond's own asset; named in `[bond]`
it reads `bonded`, final, valued at the node's rate; `bond-notice` gives the
notice from the operator's wallet's fee coin, which reads `spent` until the
configuration names it and `noticed` after, with the median time from which
it can be withdrawn; a second notice and a withdrawal before the delay are
refused (`non-BIP68-final`); and a server with a notice one unit short of a
lifetime, the longest exit delay and a day, or with the operator key as the
withdrawal key, does not start. After a board is refreshed in two rounds no
salt holds two messages; with the board's forfeit for the first round held for
the second as well, as a lost round's re-run under the old rule left it,
`bond-post` names the leaf and pays nothing.

`tests/signer.rs` runs `arca-signer` as its own process: its key, a
rebindable message, and the spend of a clock's release whose signature verifies
over the signature hash the library builds; it refuses a raw digest, a stray
field, outputs out of range, an oversized line, a spend by the leaf's
collaborative path or the owner's exit, an input out of range, spent outputs
missing, and an input that spends no taproot output. Its record: a spend
signed again when asked again and a second spend refused; another holder's
leaf under the same salt refused another message once the first leaf spent
under it, and signed the same message; an owner signature by another key,
over another message or for another salt refused and not recorded; a forfeit
of one coin signed, and a second forfeit, for the same round or another,
refused; a spend after a forfeit and a forfeit after a spend refused; forfeit parts that do not make the output
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
running hash and its salt kept, the rest carried over verbatim, the new record going on from
the old one's latest entry; the signer on it refusing another message under a
salt carried over, signing the same message again as its entry, refusing any
message under a kept salt (where a signer before kept salts signed one again
as entry 8), a kept salt changed, unsorted or removed refusing the start,
answering the running hash at a dropped entry, a head
of it signed before the compaction stopping nothing, accepting the
database's knowledge of an entry compacted away whose hash it kept and
refusing another hash there (`record_differs`), listing its entries; a
carried line changed refusing the start; and a compacted record compacted
again, its kept salts kept. A record of format 1, as an operator made it
before records named their keepers, its entries the signer's, compacts into
format 5 with every line accounted for, the head and the running hash at
every entry as they were, and its dropped salts refused. A record an older
signer compacted says it lost salts and signs under one again (entry 6);
compacted again, it keeps every salt listed, the one lost before included, and
refuses them. And the signed head: every rebind's entry and `head` signed by `S`; an
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
up, a start with one down signing nothing until it is back; a signer
whose address the keeper's `--allow` does not name told why by the keeper
and saying so, at its start and in its `keepers_unavailable`; a keeper gone
back to an older copy while another missed the lost window, after a
restart of the signer, a lost keeper still (from `<record>.keepers-seen`),
nothing released, and with the record alone put back to an earlier copy no
second spend released; a signer that cannot write beside its record
releasing nothing until it can; that shape with `<record>.keepers-seen`
lost beside `<record>.acknowledged`, the signer refusing to start, naming
both files; a record from before the signer kept the file refused, then
started once with `--start-keepers-seen`, which writes it, the flag then
refused and the record starting without it, and a compacted record started
on with its side files moved with it; a new operator
with three keepers made in the order "Running" gives, every command run,
`S` read with `arca-signer --pubkey` before its record exists, the signer
co-signing with the keepers' acknowledgements; and what a keeper adds to a
co-signature, printed.

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
another participation; amounts one atom off either way; a fee in an asset
not served (`out_of_bounds`); a fee one atom short of the schedule; a key wanted twice, wanted
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
