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

## Posting the equivocation bond

An operator that holds other people's coins posts a bond before it serves a
payment out of round
([The equivocation bond](../server/README.md#the-equivocation-bond)).

- **Draw the withdrawal key on a machine of its own:**
  `arcad bond-key <file>`. Put the key it prints in `[bond] withdraw_key`,
  and keep the file and an offline backup off the server. It is the only key
  that ends a bond. Never use the operator key for it: the server refuses to
  start with one.
- **Set `[bond] notice_units` to at least 5,232** (a coin's 28-day lifetime,
  the 48-hour longest exit delay, and a day). The server refuses to start with
  less.
- **Choose the asset and the size.** Any asset may bond. Size it above what
  holders keep out of round together, not one holder's most: a double-sign
  must cost the operator more than it could take, it could take from many
  holders at once, and one slash burns the bond once. Each wallet checks the
  bond against its own holdings only.
- **Post it from an operating wallet:**
  `arcad <config> bond-post <node wallet> <asset> <atoms>`. Never use a
  treasury, a reserve, a bridge's, an escrow or another service's wallet; the
  command refuses one by its name. It also pays nothing while the operator key
  has already signed two messages under one salt (forfeits a signer gave a
  lost round's re-run before it kept one message per salt): whoever holds the
  database or a backup could burn such a bond, so post it under a new operator
  key instead. Nor does it pay while the signer's record is a compaction by a
  signer that kept no salt it dropped, under which it would sign again: the
  signer says so at start; compact the record once more first, with the list
  `arcad <config> expired-salts` prints, which keeps every salt it names. Add the `outpoint` line it prints to
  `[bond]`, restart `arcad`, and check that `info.bond.state` reads `bonded`
  and `final` reads `true`.
- **To withdraw, give the notice first:** `arcad <config> bond-notice <key
  file>`, then add the `notice` line it prints to `[bond]` and restart. The bond
  can be withdrawn at `info.bond.withdrawable_at`:
  `arcad <config> bond-withdraw <key file> <address>`.
- **Never co-sign anything outside the signer.** The signer signs one message
  under a coin's salt, ever. A second signature made any other way, with a
  copy of the key or by a signer started on another record, burns the bond in
  the hands of whoever holds both.

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

## Spends whose witness ends with an annex

A taproot spend may end its witness with an annex (BIP341). Consensus sets
it aside before the script runs, so the spend is the same spend with or
without it. Sequentia's relay policy takes an annex only on a Simplicity
leaf, and there only when it is zeros and exactly as large as the program's
cost needs; it refuses every other annex, which a block producer can still
mine. Where an Arca coin's spend is authorised by a signature over a
message of its own (a collaborative path, an `order-2` fill) or by no
signature at all (an entry's unlock, a landing, an on-chain order's FILL
leaf), nothing covers the annex (`order-3` and `seqdex/order` version 2,
which every new order uses, refuse one), so whoever mines the spend, or relays it
through a node that does not apply that rule, can add one without changing
its txid. An exit from an accumulator batch and a `vtxo-2` coin's
collaborative spend are the exceptions: their programs refuse an annex.

The server, its watcher and the wallets read every spend found on the chain
with its annex set aside: a forfeit or `htlc-1` claim, a fill, an exit, a
collaborative spend `watch-bond` reads for evidence, an owner's conversion of
a board. An annexed spend is read the same as the plain one; the operator has
nothing to do about one.

An annex does make a spend larger and so lowers its fee rate, and a node
holding one copy of a transaction keeps it against another copy with a
different witness. A relay that adds an annex to a transaction on its way,
among nodes that do not apply the rule above, can therefore hold it at a lower
fee rate than was paid for. Leave fee margin on
transactions the operator broadcasts, and watch that they confirm.

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
- **Bound what Lightning puts on the operator's pools.** A payment held
  for a receive and never claimed keeps its leaf's value in the batch until
  the batch expires, and costs whoever asked for it nothing: keep
  `[lightning] receive_cap_ppm` at its default (a tenth of each asset's
  pool) or lower, so unclaimed receives never stop that asset's rounds.
  Keep `send_stall_margin_seconds` at its default (six hours) or longer, and
  `send_timeout_seconds` well above it (a day): a payment out of the tree
  then resolves before its leaf's timeout through a chain stall that long
  ([Paying an invoice out of the tree](../server/README.md#paying-an-invoice-out-of-the-tree)).
- **Keep several final coins of the first fee asset** when the operator
  serves an asset the node does not accept for fees. That asset's rounds
  pay their fee and connector from the first fee asset's pool, and a round
  spends only final coins: with one such coin, a round of that asset built
  while the other rounds' change is not yet final waits for their
  confirmations.
- **Count a fee for each fill round dropped.** A round that fills on-chain
  orders waits, built, for its takes' forfeits. When one never comes within
  `[fills] forfeit_window_seconds`, or anyone fills one of its orders on the
  chain meanwhile, the server drops the round and spends one of its own
  coins back to its wallet, so the round can never confirm: one small
  transaction's fee, in the round's fee asset, each time. The round's other
  coins are free again at once, and its takes that can still run do so in
  the next round. Takes that share an order run in one round, so a single
  take whose forfeits never come holds every other take of that round back
  for the window before they run again without it.
- **When the operator stops or moves, tell the holders.** Say which
  operator ends, from which time, and which operator replaces it, so each
  holder runs `arca sync` at once, takes its coins home on the chain, and
  boards them with the new operator.

## Turning on receives over Lightning

An asset receives over Lightning once its `[assets.lightning]` names a node
that runs SeqLN's hold-invoice plugin. Leave that off for every asset until
both of these hold:

- **The operator runs a revision whose server answers `transfer_status`.**
  `arcad` and the signer move to it together
  ([Moving to a new revision](../server/README.md#moving-to-a-new-revision));
  at its first start the server posts a pending notice for every transfer
  recorded before and not yet co-signed. Such a server sizes a receive's lock
  so that the holder keeps its window to claim the leaf, and serves a
  receive held and not yet claimed to a holder restoring from its mnemonic
  ([Receiving into the tree](../server/README.md#receiving-into-the-tree)).
- **Every holder who will receive runs a wallet of the same revision**:
  one whose `arca schedule` names `next_exit_at`. Such a wallet takes a
  received leaf home by its claim, should the operator not co-sign it,
  before it asks the operator anything, with a margin of an eighth of the
  leaf's lock; an older one asks the operator first, and an operator that
  answers slowly can then take the leaf by its refund.

Then, for each asset that receives:

- **`[assets.lightning] rpc`** names the asset's own SeqLN node's JSON-RPC
  socket. The node runs on the Sequentia network, holds at least one open
  channel in the asset with room to receive, and runs the hold-invoice
  plugin (`contrib/holdinvoice-seq`). Check `info`: the asset's
  `assets[].lightning` is `up`, and `receives` is `true`.
- **`[lightning]`** keeps `operator_delay_units` below `owner_delay_units`;
  `block_seconds` at the chain's block interval (60); `receive_window_seconds`
  at its default (six hours) or longer, the time a holder has to claim its
  leaf once its round is final; and `receive_cap_ppm` as above.
- **Holders are told what remains.** A received leaf rests on its claim
  being mined before the leaf's timeout, when the operator's refund becomes
  valid beside it. The wallet raises the claim's fee as the timeout nears,
  up to the leaf's whole value, pays it from a coin of another accepted
  asset when the node no longer takes the leaf's, and after the timeout
  replaces any refund with a claim that pays more, so a refund gains the
  operator only what it did not burn. But a chain stall longer than the
  margin opens the claim and the refund in one block, and a fee race decides
  it, which an operator that burns the leaf's value, or produces the block
  itself, can win. A holder whose only coin in an accepted asset is the leaf
  cannot pay its claim at all once that asset is no longer accepted. A
  refund lock that a stall cannot leap would take another leaf template.
- **Payers are told** that the invoice's final lock time is twice the leaf's
  lock, about 5,770 blocks with a 36-hour exit delay and the default window:
  a payer whose node pays with SeqLN's `pay` raises its `maxdelay` to that.

## Serving an asset issuer-operated

An asset's own issuer may run its batches: each round mints the asset's
refresh liquidity through its mint limiter and every sweep burns it
([Issuer-operated assets](../server/README.md#issuer-operated-assets)). The
issuer sets it up so:

- **The token in a limiter, and nowhere else.** Make the instance with the
  limiter's tool (`mint-limiter instance`), its operator key a mnemonic of its
  own on the signer's machine (`mint-limiter key --new --mnemonic-file`), its
  cold key's mnemonic offline, never on any machine of the operator's, and
  move the asset's whole reissuance token to the instance's address. Check
  the issuance: a token outside the limiter can still mint. Make the cold
  key's brake signature (`mint-limiter arm-signature`) and keep it where the
  brake should be pulled from.
- **An allowance the operator's refreshes fit.** A window's allowance bounds
  what the batches made in that window may hold; a round whose mint does not
  fit waits until the window ends, and its holders' coins near their exit
  date go home on the chain. Set it above a window's refreshes, and no
  higher than the issuer would let a stolen minting key make.
- **The signer alone holds the minting key.** Start the signer with
  `--issuer <instance file>=<mnemonic file>`, the mnemonic file readable by
  its owner alone, and `--mint-limiter` naming the tool; never give the
  mnemonic to `arcad` or to any other machine. Then serve the asset with its
  `[assets.issuer]` section and reload or restart `arcad`.
- **Fee coins in another asset.** The operator holds none of the asset and
  pays no fee in it: every round, release, sweep and claim of the asset
  takes a coin of the operator's fee assets, so keep several final coins of
  the first one. A configuration whose fee assets are all issuer-operated is
  refused.
- **One round of the asset at a time.** Each round mints from the coin the
  last one left the limiter, once that round is final and its coin two
  blocks old, so the asset's refreshes gather into rounds no closer together
  than that; a participation waiting for it says so.
- **No Lightning leg, no takes of on-chain orders, no distributions in the
  asset.** The server refuses each.
- **For a bridged asset, the reserve accounting first.** Units minted for a
  refresh are backed by nothing while their batch lives. Before an asset
  that is backed by reserves elsewhere (a bridge's) is served this way, the
  bridge's supply and reserve checks must count the units live under
  burn-only sweeps, which `issuer_supply` lists output by output, or they
  read the mint as inflation. Compages does this for the assets it bridges
  (its `docs/issuer-operated.md`).

## Serving a supervised asset

A supervised asset's issuer can freeze holdings by consensus rule. The
operator serves one so that a frozen holder can neither move nor escape
([Supervised assets](../server/README.md#supervised-assets)):

- **The node says which assets are supervised.** `arcad` reads
  `getsupervisedassets` at start and on every reload and serves each one so,
  whatever its section says; there is nothing to switch on. Name
  `[assets.supervised]` only to set the landing allowance, and keep it at the
  size of a landing's fee: it is the most of a frozen coin its exit can send
  anywhere but its owner's key.
- **The signer reads freezes from a node of its own.** Start the signer with
  `--supervision-node <url> --supervision-cookie <file>`, a node with the
  supervision registry (any current `sequentiad`), the cookie readable by the
  signer alone. A signer without one signs nothing for the asset's coins,
  and its holders' refreshes and transfers fail with `frozen` until it has
  one. A node of its own, not `arcad`'s, so that a fault in either one alone
  cannot let a frozen coin move.
- **Freezes bind at once; liftings once final.** A freeze binds in the tree
  as soon as its record is in a block of the node; a lifting binds only once
  the block that shows it is final. Nothing is to be done by hand: the hold
  is kept in the database and clears itself.
- **No Lightning leg, no takes of on-chain orders, no resting orders, no
  distributions and no plans in the asset, and not issuer-operated.** The
  server refuses each, at start or per request.
- **What the issuer can and cannot do, said plainly.** A freeze stops every
  co-signed spend of a frozen holder's coin in the tree: a transfer, a swap,
  a refresh, an offboard, a take, a fill, a distribution, a plan, a Lightning
  payment. It never stops the holder taking the coin home by its landing,
  into its own key, where the freeze binds on the chain; and a coin not taken
  home before its batch's exit deadline is brought on the chain at its
  batch's release, as any coin neither refreshed nor taken home, its landing
  then its holder's; one a sweep took all the same is repaid as a
  `landing-1` coin to its holder's landing key, less the late-refresh fee.

## Building batches without a sweep

On the main chain (`sequentia`) the server builds every batch without a
sweep, whatever the configuration says: no token, no clock, and nothing the
operator signs can take a coin from a holder who stays away. Elsewhere it
does so with `[batches] no_sweep = true`. Turn it on only once every wallet
your holders use reads such a batch's records (a wallet that does not refuses
their leaves) and signs its forfeits against the round's transaction before
the round is broadcast. A wallet that does says so on each participation; the
server refuses a refresh, offboard or distribution from one that does not,
telling its holder to update it, so an older wallet never holds a round
back.

What it changes for the operator:

- **Every refresh round waits for its forfeits.** A round is built, held,
  and broadcast only once every participation in it that gives up a coin has
  handed its forfeits over, within `[fills] forfeit_window_seconds` of the
  round being built (600 s unless set). One that does not is voided, its
  coins given back; the round is dropped, and a spend of one of its own
  coins kills it on the chain, so it can never confirm; the rest run again
  at once in a round of their own, before any newcomer. The voided coins
  then wait (the window, doubling with each repeat, up to a day) and run
  only in a round of their own, so the same participant never holds anyone
  back twice. Expect a refresh to take one round interval plus the window
  for each participant that drops out beside it.
- **No sweep brings capital back; RECLAIM, RECLAIM-D and collection do.** A
  lowest node every owner of which has refreshed and released comes back by
  RECLAIM as soon as it does (`[watcher] reclaim_early`); with
  `[batches] delegated_reclaim`, one whose coins were paid on out of round
  comes back by RECLAIM-D once their current holders refresh and release.
  Whatever is left of a batch at its service horizon
  (`[batches] collect_after_seconds`, 28 days by default, after its round;
  for a batch of claim leaves, after their deadline where that is later, so
  that a holder takes a claim up whenever it vests) is collected on
  the chain: each holder's coin lands as its own leaf, each given-up coin is
  forfeited and claimed, each coin paid on out of round (a claim taken up
  included) lands through its lineage, and each `htlc-1` coin whose payment
  is decided in the operator's favour is refunded or claimed. Keep the wallet able to pay those fees (the reserves pay them where
  the node takes the batch's asset).
- **No plans.** The server refuses offline-refresh plans, and stops an open
  one before its next step.
- **Accumulator batches without a sweep.** With `accumulator_exit_rate_ppm`
  set, a batch the operator expects few exits from is an accumulator batch
  without a sweep (`arca/accumulator-2`): the watcher releases each slot its
  owner released (up to 14 in one transaction, with an atom of each round's
  connector asset), and collects the rest at the service horizon as it does
  a tree. A holder's own batch is always a tree, and so is the part of a
  round for wallets that do not name `accumulator-4` among the record
  formats they read (older wallets): they get a tree leaf in the same round,
  never a slot. A wallet older than that format cannot read a coin paid to it
  out of round from a slot either, and does not show it until it is updated:
  an updated wallet reads its mailbox again once on its first sync and shows
  it then. Turn the rate on once the wallets your holders use read it, and
  check every client of the operator on its own machine first (makers,
  agents, command lines).
- **The bond's notice** must cover the horizon: `notice_units` at least the
  longer of 28 days and `collect_after_seconds`, plus the longest exit
  delay, plus a day.

## What holders are told

Every holder receives these rules before the operator holds their coins:

- **A payment out of round is covered by the operator's bond.** The wallet
  checks the bond on its own node before it takes one, and refuses while the
  bond is missing, is in notice, or is worth less than what the wallet would
  then hold out of round; the refusal names which. A coin refreshed in a round
  needs no bond. Run `arca watch-bond` beside `arca sync`, and hand your
  `arca bond-evidence` to watchers you trust: whichever of them sees a
  double-sign first burns the bond.

- **Run a wallet built from the same revision of this repository as the
  operator's server.** An older wallet does not keep its coins alive by
  itself.
- **Run `arca sync` at least once a day while the wallet holds a coin off
  the chain or is waiting for a payment**, whatever `next_sync_at` says,
  unless a plan covers every coin held (below).
  `sync` refreshes each coin for free in its last days, and takes a coin
  home on the chain when it cannot have it refreshed. A payment is read
  only by a `sync`. A receive request lasts 27 days and carries the date it
  lapses at: a sender's wallet refuses to pay it from then, and
  `next_sync_at` counts it until then. Hand a payer a new request rather
  than an old one. A request handed out by a wallet before requests
  carried their lapse holds `next_sync_at` at a day until it is paid or
  forgotten (`arca forget-request`). A payment the operator has recorded
  and not yet completed shows as announced by the operator (`sync`'s
  `mailbox.pending`), and holds `next_sync_at` at a day until it comes,
  whatever the request's lapse, for as long as the server shows its
  transfer recorded. An announcement is the operator's statement, not a
  payment: the coin counts only once it comes.
- **To stay away past a coin's expiry, pre-sign a plan and sync by its
  `sync_by`.** `arca plan` hands the operator a plan that refreshes each coin
  of a round once per expiry while the wallet stays closed (two by default,
  six at most), for free, each step in the coin's last days; `arca plans`
  shows until when it covers the coin (`covered_until`) and the date by
  which the wallet must sync again (`sync_by`). A wallet whose every coin a
  plan covers need not sync until then, unless it is waiting for a payment. The operator runs the steps: one that runs none
  and sweeps the coin owes it back as it owes any swept coin, but an operator
  that turns against its holders can keep what it sweeps, so a plan keeps a
  coin alive through an operator that runs, not through one that turns
  against them. A coin a plan names
  is paid out of round only once given up in a round for a leaf no plan
  names (`arca plan-release`), which ends its plan.
- **A wallet that runs `arca care` after each sync plans by itself.** `care`
  takes up open claims, cancels each plan whose coin has moved, and plans each
  coin once its first step could run within ten days; a younger coin stays
  unplanned so it can still be paid out of round. A wallet closed within a
  coin's first two weeks or so and kept closed through that coin's step window
  can therefore find the coin taken on the chain at its batch's release, as
  any absent holder can, and boarded back at its next sync (or, swept all the
  same, repaid less the late-refresh fee).
- **On an operator that builds batches without a sweep, a coin never
  expires.** Nobody can take it. Sync before its batch's service horizon
  (`info.batches.collect_after_seconds` after its round) to keep it off the
  chain; a wallet away past the horizon finds it on the chain, its own, and
  boards it again. A refresh asks the wallet to stay in touch until its
  round is built, to sign its forfeits before the round goes out.
- **A coin left past its expiry is taken on the chain, not swept.** Once
  its batch is released, the operator brings every live coin of it on the
  chain under its holder's key (`[watcher] unroll_at_release`), and so does
  every watchtower the holder's wallet deposited it with (`arca
  watchtowers`; the operator's `info` lists the ones a wallet uses when it
  names none, `[watcher] watchtowers`). Each needs only the chain and the
  coin's record, so the coin is safe while any one of them acts within the
  notice. The wallet, back, finds the coin on the chain ("moved out of the
  Ark to keep it safe while you were away"), takes it home and boards it
  again by itself.
- **A coin a sweep took all the same is repaid, not lost.** A coin whose
  holder neither refreshed it nor took it home, and that nobody brought on
  the chain before its batch was swept, is owed back by the operator, less the late-refresh fee (the asset's refresh fee at
  its full charge: `refresh_ppm` of the coin and `refresh_base`). The next
  `arca sync`, from the wallet or one restored from its mnemonic, finds it,
  claims it, and holds the new coin once its round is final; until then
  `arca balance` counts it as `returning`, and `arca owed` shows each such
  coin. A rollback of the sweep holds the claim until the sweep is final
  again, the coin back in its batch meanwhile. This is the operator's
  policy, published in `info` (`swept`), kept by its server, and owed for as
  long as the operator runs: a holder who wants to rely on no operator for
  it names watchtowers of its own, or refreshes or takes the coin home
  before its exit date.
- **When a payment answers `unreachable`, run `arca sync` again that
  day.** The next `sync` posts the payment again, and its receiver reads it
  once it completes.
- **When receiving over Lightning, follow `next_sync_at`.** After `arca
  lightning receive`, `sync` must run within the operator's window once
  the payer has paid, to take up the leaf and claim it; `next_sync_at`
  wakes the wallet for it, and for the leaf's way home by its claim should
  the operator not answer. That way home is an exit step, which `sync`
  takes before it asks the operator anything; `next_exit_at` names it on
  its own, and `arca sync --exits-only` takes it without asking the
  operator. A wallet that wakes late for it by up to an eighth of the
  leaf's lock still claims first. Keep an on-chain coin in an asset the
  node accepts for fees besides: should the node stop taking the leaf's
  asset, the claim pays its fee from it. A payer whose node pays with
  SeqLN's `pay` raises its `maxdelay` to the invoice's final lock time.
- **When taking an order, follow `next_sync_at`.** After `arca take`, the
  wallet must sync within the operator's forfeit window (ten minutes unless
  the operator sets another) of the take's round being built, or the take is
  void and its coins come back; `next_sync_at` wakes it for that until the
  take is released.
- **A supervised asset's issuer can freeze its holders.** A coin of an
  asset the operator serves supervised (`supervised` in its `info`) lands
  only at the wallet's landing address (`landing_address` in `arca info`).
  When the issuer freezes that address or pauses the asset, `arca coins`
  shows the coin `frozen`, the operator co-signs nothing that spends it,
  and its only way out of the tree is its landing into the holder's own
  key, which `sync` takes before the coin's exit date and `arca exit` takes
  at once. There it stays frozen until the issuer lifts the freeze. A frozen
  coin pays no fee, so keep the fee coin below in another asset.
- **Keep an on-chain coin in an asset the node accepts for fees.** Some
  exits need one (a board, or a coin in an asset the node does not accept
  for fees). `arca address` gives an address to pay it to.
- **Read `arca coins`.** For every coin held off the chain it shows
  `exit_by`, the date by which the coin must be on its way home;
  `home_from`, from when `sync` takes it home unless it has been refreshed;
  and `exit_fee`, the fee coin its exit needs, if any. A coin taken home
  comes back whole, less the fees of its exit.
