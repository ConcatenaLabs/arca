# Running an operator that holds other people's coins

This is the procedure for an Arca operator on Sequentia that holds coins for
anyone other than itself. It is written for the person who runs the
operator's machines. Every step is required. The reasons are in
[the server's README](../server/README.md), linked where a step depends on
one.

An operator that holds only its own coins can run without keepers
([Running](../server/README.md#running)). An operator that holds other
people's coins never does: without keepers, a restore of the signer's machine
can let a coin paid out of round be spent twice.

## Making the operator

Follow [A new operator with keepers, in order](../server/README.md#a-new-operator-with-keepers-in-order),
every command as written, with these choices:

- **Three keepers, two of them required.** Create the record with three
  `--keeper-key` and `--keepers-required 2`. Two of three lets the operator
  run on, and move its holders to a new operator, when one keeper is lost.
- **Each keeper on a machine of its own.** Never the signer's machine, never
  a virtual machine on the same host, and never inside the signer machine's
  snapshots or backups. A keeper is the copy of the record's heads that a
  restore of the signer's machine cannot bring back with it.
- **Each keeper admits the signer alone.** Start each keeper with
  `--allow` naming the address the signer's machine connects from, and give
  the keeper's machine a firewall that admits only that address to the
  keeper's port. Before the signer's machine changes address, change every
  keeper's `--allow` and firewall first.
- **The signer first, then `arcad`.** Start the signer with one `--keeper`
  for each keeper, and check that its log says
  `the keepers agree with the record`. Then start `arcad`, which pins the
  keeper set in its database the first time it reads it. From then on it
  refuses to start against a signer that names another set, and stops
  serving (`signer_replaced`) if it finds one under it while it runs.
- **The record's storage writable.** The signer writes two files beside its
  record, `<record>.acknowledged` and `<record>.keepers-seen`, and releases
  nothing it cannot write there. Keep the record on a directory the signer
  can create files in, on the same durable storage as the record.
- **Every key backed up offline.** The operator key and each keeper's key,
  each on offline media kept apart from the machine that uses it. A key
  file lost without a backup cannot be replaced: the record names the
  keepers for good, and a new operator key is a new operator. A keeper's
  key is guarded as the operator key is: whoever holds it can make the
  keeper name a head it held before.

## What is never done

The keepers rest on these rules, and no code can keep them for the
operator: a keeper restored from an older copy, or a second signer run under
the operator's key, defeats the keepers, and a coin they protect can then be
paid twice.

- **Never start a keeper again whose heads file was lost, or would come back
  from an older copy.** It no longer holds what it acknowledged, so it is a
  lost keeper ([The keepers](../server/README.md#the-keepers)). Leave it
  stopped. With one keeper lost, the operator runs on with the other two;
  make a new operator and move every holder to it while the two remain.
- **Never run a second signer on a copy of the record**, as a standby or
  for any other reason. The keepers find two signers on copies of one record
  out: one of them stops, or both, and a stopped signer ends the operator.
- **Never edit, replace or restore the signer's record, or a file beside
  it**: `<record>.acknowledged`, `<record>.keepers-seen` and
  `<record>.stopped`. They are the signer's memory of what it signed and of
  what its keepers hold.
- **Never clear a stop to resume service.** A signer that stopped on a
  proof of a rollback (`<record>.stopped`) has shown that its record went
  back. That operator is finished: its holders take their coins home, and
  a new operator starts from nothing. `--clear-stopped` exists only to
  remove the proof once that is done.
- **Never restore the database to anything but its latest commit**
  ([Keeping the database](../server/README.md#keeping-the-database)).

## Storage and restore

- **The database** runs with its durability settings on, and keeps every
  commit off the machine as it happens: a synchronous standby, or
  continuous WAL archiving with base backups. A restore is to the latest
  commit only: promote the standby, or recover the base backup with every
  archived WAL segment to the end.
- **The record and the files beside it** live on durable storage of their
  own, storage that loses no write (a mirror), and are never restored from
  a copy. A compaction moves the new record and its two side files,
  `<new file>.acknowledged` and `<new file>.keepers-seen`, into the old
  ones' places together
  ([The signer](../server/README.md#the-signer)). The signer refuses to
  start on a record noted acknowledged whose `<record>.keepers-seen` is
  missing: put the file back from where it lies.
- **Stop the signer with SIGTERM**, and move `arcad` and the signer to a
  new revision together
  ([Moving to a new revision](../server/README.md#moving-to-a-new-revision)).
- **The signer's machine, when it must be restored, is restored cold**:
  from its disk, started from power-off. A restore with its memory (a
  snapshot of a running machine) is caught by the keepers, but it stops the
  signer, and the operator with it.
- **A lost record is a new operator.** The signer does not start without
  its record, and a new record cannot take its place: make a new operator
  (new key, new record, new keepers' heads files) and move the holders to
  it.
- **When the operator stops or moves, tell the holders.** Say which
  operator ends, from which time, and which operator replaces it, so each
  holder runs `arca sync` at once, takes its coins home on the chain, and
  boards them with the new operator.

## What holders are told

Every holder receives these rules before the operator holds their coins:

- **Run a wallet built from the same revision of this repository as the
  operator's server.** An older wallet does not keep its coins alive by
  itself.
- **Run `arca sync` at least once a day while the wallet holds a coin off
  the chain or is waiting for a payment**, whatever `next_sync_at` says.
  `sync` refreshes each coin for free in its last days, and takes a coin
  home on the chain when it cannot have it refreshed. A payment is read
  only by a `sync`; a receive request waits for one 27 days, after which
  `next_sync_at` no longer counts it.
- **Keep an on-chain coin in an asset the node accepts for fees.** Some
  exits need one (a board, or a coin in an asset the node does not accept
  for fees). `arca address` gives an address to pay it to.
- **Read `arca coins`.** For every coin held off the chain it shows
  `exit_by`, the date by which the coin must be on its way home;
  `home_from`, from when `sync` takes it home unless it has been refreshed;
  and `exit_fee`, the fee coin its exit needs, if any. A coin taken home
  comes back whole, less the fees of its exit.
