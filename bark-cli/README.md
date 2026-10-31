# arca-cli

The command-line wallets of this workspace:

- **`arca`**, the Arca wallet: a dual-chain wallet whose Sequentia side holds
  Arca coins against an Arca server, and whose Bitcoin side is Bark's wallet
  for Bitcoin arks.
- `bark` and `barkd`, Bark's own command-line wallet and daemon for Bitcoin
  arks, here with testnet4 among their networks (`--testnet4`), whose
  Lightning invoices carry testnet's `tb` currency. `arca bitcoin …` runs a
  `bark` as Bark ships it, and the Arca client carries one built from Bark's
  release with the same testnet4 change (`ConcatenaLabs/arca-client`,
  `build/make-bark-bundle.sh`).

## The `arca` wallet

`arca` keeps its state in one directory (`--datadir`, `ARCA_DATADIR`, by
default `~/.arca`, mode 0700): the BIP39 `mnemonic`, the store `arca.sqlite`,
and, when the node is reached with a password, `node_password`, each readable
by its owner alone (mode 0600). The node's password is never a command-line
argument, which other users of the machine can read: `create` takes it from
the environment variable `ARCA_NODE_PASSWORD` or from a file
(`--node-password-file`), once, and keeps it in `node_password`, never in the
store. The wallet library is `bark::arca` (`bark/src/arca/`, the `arca` feature
of `arca-wallet`), built on `arca-covenant` for every script, record and check.
What the library says names the act ("sync", "an exit", "the wallet's
address") and prefixes the texts it hands out `request:`, `swap-offer:` and
`swap-accept:`, unless its client gives its own spelling (`Spelling`,
`Wallet::spell`): `arca` gives its name, so its notes name its commands
(`arca sync`) and its texts are `arca:…`, `arca-offer:…` and `arca-accept:…`.
A text is read whatever its prefix, known by what it holds, so wallets of
every spelling pay one another.

It needs:

- an Arca server (`arcad`), reached over HTTPS at its base URL. Plain
  `http://` is refused except to this machine (a loopback address or
  `localhost`, as for a server behind a local TLS proxy): across a network,
  anyone on the path could answer as the operator;
- a `sequentiad` it can call over JSON-RPC, running with `-txindex` and
  `-validateanchor`. The wallet reads the chain only from this node, and
  refuses one that does not validate its anchors: without that the node has no
  notion of finality.

Every command prints JSON. A refusal prints
`{"error": {"kind", "message"}}` (with the server's `code` and `status` when
the server refused) and exits with status 1. Every refusal is also recorded,
and `arca refusals` lists them. The server has refused only when it answers a
4xx with one of its refusal codes; any other failure (no answer, a timeout, a
5xx, a proxy's error page) says nothing of what it did, so the wallet reports
it as `unreachable` and keeps whatever it asked for standing: a payment stays
in flight and `sync` posts the same request again, which the server answers as
it did the first time.

### Keys

All keys come from the mnemonic, as the Sequentia Wallet Kit derives them, so
one mnemonic serves both:

- each leaf has a key of its own, `m/6'/account'/c1'/c2'/c3'/c4'`, where
  `c1`…`c4` are the first four 31-bit chunks of `SHA256("Arca/key" ‖
  owner_nonce)` and the owner nonce is 32 random bytes drawn for that leaf
  alone. The nonce goes into the leaf's record, so a record names its own key;
- the mailbox key is the key that same derivation gives for the fixed nonce
  `SHA256("Arca/mailbox")`, so any wallet on the kit derives it from the
  mnemonic with the kit's own leaf derivation. It signs only the tagged
  authentication of a call, and no coin is ever accepted for its nonce;
- on-chain keys are `m/84'/1'/0'/<chain>/<index>` (`0'` instead of `1'` on the
  main chain), unblinded P2WPKH: the same key is a Bitcoin and a Sequentia
  address. The wallet looks at each chain of them up to 20 unused scripts past
  the last one holding a coin, so a wallet restored from the mnemonic finds
  its on-chain coins gap by gap, and it never hands out an index it found in
  use. Each index is taken in one statement of the store, so two processes on
  one directory never hand out the same address; each exit claims to one
  address, however often it is run;
- the landing key is the first on-chain key, `m/84'/1'/0'/0/0`: every coin of
  a supervised asset the wallet holds lands there (see Holding a supervised
  asset), and `info` shows its address as `landing_address`;
- order keys are `m/86'/1'/0'/0/<index>` (`0'` instead of `1'` on the main
  chain), one for each order the wallet places on the chain (see Placing an
  order on the chain): the key is the order's REFUND key, and its key-path
  output, tweaked with no script tree under the Elements tags, is the plain
  program every fill pays the maker's credit to. The wallet looks at them as
  at its on-chain keys, gap by gap, counts the credits there in `balance` and
  boards them with an ordinary key-path signature.

The store keeps every owner nonce the wallet has ever drawn, with its key,
written before the key is handed out or signs anything, and never deleted. It
keeps every coin it holds or has held, with its coin record, and refuses a coin
at a salt it has held a coin under. Back the directory up: the mnemonic
restores the wallet from the server and the chain (below), all but what only
the store knew.

### Restoring from the mnemonic

A leaf's key comes from a random nonce, so a mnemonic alone names no leaf. It
names the mailbox key, and every leaf the wallet makes is bound to it at the
server: a board's registration and each leaf a refresh asks for carry the
mailbox key and the leaf key's signature over the binding
(`SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ owner ‖ mailbox)`,
`T = SHA256("Arca/mailbox-of")`), which authorises the server to serve that
leaf to whoever proves the mailbox key and nothing else. A coin paid out of
round is posted to the mailbox key already. A coin a wallet kept before it
bound its leaves is bound by its next `sync` (`bind_mailbox`), as is a leaf
received over Lightning under a request that named no mailbox key, each binding
signed by the coin's own key.

`create --mnemonic` restores a wallet from its mnemonic, and `restore` runs
the restore again (it takes only what the wallet does not hold). A restore
retires the old device: stop the wallet the mnemonic was restored from, and
never run it beside the restored one. Two live stores of one mnemonic draw
their own nonces and refuse each other's coins: a leaf one claims under a
nonce the other never drew is refused there ("a coin for owner nonce …,
which this wallet never drew"), and the other's own claim of it is refused
as a double spend. A restore that stops at an error keeps what it took
before it and says so; `restore` takes the rest once the cause is gone. A
take whose round is held for its takes' forfeits is restored from the round
the take's status serves, as `sync` reads it, and its forfeits handed over
by the restored wallet. It reads
every leaf the server serves to the mailbox key (`leaf_data`, a page at a
time, each page past the cursor it asked from and naming a next cursor past
every leaf it holds, at most a thousand pages, `LEAF_DATA_PAGES`: a server
that serves pages without end is read no further, and the restore says so in
`note`) and takes the operator's word for nothing it can check:

- the keeper set the operator names is pinned only when a head of its
  signer's record that it shows comes with the acknowledgements of as many of
  its keepers as must hold one, and no head it shows is acknowledged by a key
  outside that set; otherwise nothing is restored;
- each coin's owner key must be the key the mnemonic derives from the owner
  nonce its record names (a leaf of another key is refused); its record is
  checked against the chain as a coin held is, as of its expiry once that has
  passed (kept while the chain still holds its path, refused once a sweep that
  cut it is final); a round's leaf is rebuilt from the round's published tree,
  compared with the record the server serves, and its unroll authorisations
  are signed again from the mnemonic, so its exit needs nothing of the
  server's copy; a coin paid out of round is taken only on a head of the
  signer's record its keepers acknowledged;
- a coin is spent, given or forfeited only on its owner's own signature,
  which the wallet checks: a transfer's checkpoint signature, the attestation
  over a participation's id (recomputed from every part of it), the owner's
  half of a forfeit. The server's word on a coin's state is never taken: a
  coin a held coin's record spends was spent by that transfer, which the
  operator co-signed, whatever the server says of it (an old copy), and a coin
  whose forfeit its owner signed is never live;
- a coin whose leaf the lost wallet took home (its own output on the chain)
  is followed as its exit: `exited` once its claim, paying one of the
  mnemonic's receive addresses, is final, `exiting` while it is not or the
  leaf waits for its claim, never held live beside the coin its claim paid;
- a coin that went over Lightning and was not given up on its owner's
  signature stands as its payment does: the leaf of a payment out of the
  tree that the operator reports paid, with a preimage that opens the leaf's
  hash, is spent by the payment, one reported paying is followed, and one
  failed is taken back by the next `sync`; a leaf received over Lightning is
  held `receiving` with its payment rebuilt from its terms and its nonce (the
  preimage derives from them), taken as handed over (the lost wallet may have
  handed the preimage over already), so `sync` claims it and, should the
  operator not co-sign, takes it home by its claim at its home date. So is
  one whose claim the server recorded and has not co-signed, and one whose
  claim the server says it co-signed while the restore holds no coin that
  claim made, checked: a received leaf is spent by its claim only once the
  wallet holds the claim's coin. A restore past the leaf's home date or its
  timeout says on the coin that it came too late to be sure its claim
  wins, and `sync` takes the leaf home at once. A restore
  never credits a leaf the operator may claim with a preimage it has. A leaf
  received over Lightning is bound to the mailbox key when it is made (the
  request names the key), so the restore finds it before it is claimed;
- a payment received over Lightning whose leaf the wallet does not hold yet
  (held, its leaf wanted in a round, or made and not yet released) is served
  with the first page (`receives`), as the request bound it to the mailbox
  key: it is rebuilt when its key is the one the mnemonic derives from the
  nonce it names, the preimage the wallet derives from them opens its hash,
  and its invoice is for that hash, asset and amount with the operator's fee
  within the wallet's default bound; `sync` then takes up the participation
  that wants its leaf and claims the leaf once held;
- a participation in its forfeit step gets back the new leaves the wallet
  validated before it signed, from the published tree. One the operator
  released is completed once the preimage of its new leaves is in hand, from
  the record of a new leaf the server serves or from the published tree (a
  new leaf the server does not serve is then taken from the tree); without
  it, the coin given up stays under its forfeit, followed on the chain, and
  `sync` completes the leaf once the preimage is out;
- the mailbox is read from its start: a coin paid to a key of the mnemonic and
  never read is taken, checked as ever; then a `sync` re-checks every coin,
  follows every forfeit and completes every participation.

What it cannot recover it lists with the reason (`not_recovered`): a record
the server withholds that the published tree does not hold, a coin that fails
a check, a transfer the server recorded and never co-signed (the request to
post again was in the lost store). Receive requests handed out and never paid
were known to the lost store alone: a payment to one is still read, but
since it is read only by `sync`, the restored wallet's schedule holds at a
day until the latest such a request could lapse, 27 days on
(`receive_requests` shows it as `owner: "restored"`); `forget-request
restored` ends that hold once no request was outstanding. An open swap offer,
and a board whose registration never reached the server, are not recovered.

### What it checks

- **A leaf from a round** is rebuilt from the batch the operator publishes,
  of the kind it names (a tree, or an accumulator batch: one output from
  which each leaf leaves in one transaction), and validated against the round
  transaction under the wallet's policy before the wallet signs anything for
  it. A batch that lists a node (an accumulator batch lists none), a leaf's id
  or script other than its parts build, or a preimage that does not open its
  leaf's unlock hash, is refused before anything else is looked at. Then: the five checks on the sweep token and its
  clock, the batch output paid exactly once, the notice, a first expiry at
  least 27 days after the median time of the round's block (so a refresh
  completed a day or two after its round, as the operator allows until the
  coin's exit date, takes the same leaf), the exit delay within the wallet's
  bounds, the depth,
  and reserves on every node (an accumulator batch: on the slot's exit) and on
  the entry of at least four times the node's relay floor in the leaf's
  asset, so the leaf pays its own way out. The wallet hands the operator its
  authorisations to take the leaf out, signed when it takes the leaf: one per
  node of a tree's branch, or one exit from an accumulator batch, which names
  no state of the batch and so stays good whoever leaves before it.
  Where the node does not accept the asset for fees, one atom is the rule (the
  operator's own), and the wallet says, when it gives up a coin for such a
  leaf and again when it takes the leaf, that every exit of it needs a fee coin
  in an accepted asset. Only once the round is final, and only when the operator's status
  shows exactly the leaves the wallet asked for, in order, each validated, each
  of the template it asked for (`vtxo-1`; a resting order, `order-3`, only
  where it asked for one and on exactly its terms; `htlc-1` only for a payment
  it receives over Lightning, locked to that payment's hash), all under the
  participation's one unlock hash, and exactly the coins it gave up. The same
  owner key, nonce, asset and value under another template is another coin:
  an `htlc-1` leaf locked to a hash the operator knows is the operator's to
  claim. A leaf a step of an offline-refresh plan made, and a claim leaf of a
  distribution, are taken only as `vtxo-1`.
  The forfeit of each coin given up is built from the validated leaf of the
  coin's own asset and its round, and its refund delay must end before the new
  leaves' exit deadline.
- **An issuer-operated asset's batch.** An operator may serve an asset
  issuer-operated: each round of it mints the refresh liquidity for its new
  batch through the asset's mint limiter, and every sweep of such a batch only
  burns, a bare `OP_RETURN` at the swept output's index carrying its whole
  amount of the asset. `info` names such an asset's limiter
  (`server_info.assets[].issuer`). A new leaf, or the leaf of an
  offline-refresh plan's step, is refused before the wallet signs anything for
  it when its asset is served issuer-operated and its batch's sweep pays the
  operator (units minted for the refresh could be kept rather than burned),
  and when its batch's sweep is burn-only and the asset is served as no
  issuer-operated asset (the operator's statement and its scripts disagree).
  Whatever `info` says, a round that mints the batch's asset is refused
  unless every sweep above the leaf is burn-only, wherever the round appears
  in a coin's lineage. `coins` names each coin's `batch_profile`, and `supply`
  reads the operator's mints and burns of the asset again from the wallet's
  node.
- **The operator's equivocation bond, before a payment out of round.** The
  operator names its bond in `info.bond`; the wallet rebuilds its scripts from
  the operator key it pinned and the published withdrawal key and notice
  delay, and finds the coin on its own node: unspent, explicit and final at
  the bond's script (`bonded`), or at its notice output (`noticed`); anything
  else is `missing`. Once the wallet has seen a standing bond of its operator,
  or its operator names one, it requires one from then on: `receive`, `swap
  offer` and `swap accept` are refused while the bond is missing or in notice,
  or when the payment would leave the wallet holding more out of round (its
  coins received by a reassignment or a fill, not yet refreshed in a round)
  than the bond is worth, in the reference unit at the wallet's node's rates
  (in atoms when everything is the bond's own asset; a value the node cannot
  price is refused). An operator that never named a bond is shown as such
  (`receive`'s `bond` note) and the wallet goes on. A coin that arrives out of
  round while the bond does not cover it is still the wallet's: `mailbox`
  lists it under `uncovered`, and `sync` asks for its refresh at once. A fill
  of a resting order in the tree (`order rest`, `order fill-resting`) does not
  ask the bond first; the coin it pays counts in what the wallet holds out of
  round and, when the bond does not cover it, is refreshed at once too.
- **A coin received out of round** is validated back to every round and board
  it rests on, under the receipt policy: every pair, preimage and
  authorisation, the exit delay of every leaf of its lineage, the depth limit.
  Its key and nonce must be ones the wallet drew and is waiting on (a receive
  request is single use); no leaf or checkpoint of its lineage may be on the
  chain (every one of them descends from a batch output or board the coin
  rests on, so while each of those is unspent the wallet reads no block; it
  reads the blocks from that of a spent one up); every board it rests on
  must be unspent, and before its exit deadline. A coin read after its
  board or something of its lineage reached the chain (its sender
  converting the board it paid from, or another holder taking home a coin
  the payment rests on) is answered as a coin held is: kept and taken home
  at once from wherever its lineage is, publishing the checkpoint and the
  reassignment the wallet holds before the sender's delay runs out. It is
  refused only once a spend that is no step of its path, and is final, has
  cut that path. A coin read a day or less from its exit date, or past it, is
  kept and taken on the chain at once, from wherever its lineage is; one
  read past its batch's expiry is checked as of that expiry and kept and
  taken on the chain at once while the chain still holds its path (the
  operator sweeps a batch only once its token has waited its notice), and
  refused once a sweep that cut that path is final, its reason naming the
  sweep; while that sweep is not final yet the coin is kept, its note naming
  the sweep, counted as `exiting`, and shown `lost` once the sweep is final.
  After that, the re-check
  watches every coin the wallet holds, handed over or not: when a leaf or
  checkpoint it descends from, its own leaf, or a board it rests on spent
  shows on the chain (a sender converting the board it paid from, or exiting
  a coin it gave up), no off-chain spend of the coin is co-signed any more,
  and the wallet takes the coin on-chain at once, publishing what it holds
  (the checkpoint from a converted board's leaf, then the reassignment)
  before any exit delay runs out.
- **Finality** is the node's: a round or board is final when its block is
  certified by the committee and its Bitcoin anchor buried as many blocks as
  the operator's `info` publishes (`finality.anchor_depth`; 2 for an operator
  that publishes none, and never fewer on the main chain; 0 on the public
  testnet, where a coin is final once its block is certified). A coin
  is spendable only while everything it rests on is final. The wallet asks again
  every time, never remembers: on every start it re-checks every coin against
  the chain, so a rollback un-credits the coins it took out, and credits them
  again when their round or board returns. A live coin a rollback takes out
  of finality stays in the balance: `coins` marks it `redoing`, its note
  saying it is being redone after a Bitcoin reorganisation, until it is live
  again. It reads each round and board from
  the chain, not from what it stored: when another transaction now pays a
  batch output a coin rests on, the checks run again on that one, and a coin
  that fails them on a transaction the chain holds goes into its exit at once.
  A coin resting on a round is as final as that round: one resting on a
  round that is out of the chain while a coin the round spends is spent by
  another transaction that is final, or is made by a transaction that can
  never return either (a chain of transactions left on a branch an
  anchor-driven reorganisation invalidated), is `lost`, its note naming the round, and
  a coin paid to the wallet out of a leaf of that round with it; each is the
  wallet's again once every round and board it rests on is final in the chain
  again, unless a spend that is no step of its exit (the operator's sweep, or
  another spend the operator co-signed) has cut its path and is final. The
  re-check looks at what the chain holds of a coin as of its expiry once that
  has passed, so a round that can never return, or one that returns, is
  followed whenever the wallet next looks, past the coin's exit date or its
  expiry as before them; and a coin it finds past its exit date (three days
  before its first expiry) it takes on the chain at once, whatever command
  started it, since the operator co-signs no spend of it any more. A board
  held as `lost` whose transaction the chain holds is followed again once the
  server reports it credited. A participation such a round ran whose forfeit
  the wallet had not yet handed over, the operator runs again, under the same
  keys and owner nonces, in a round that cannot stand in the chain beside the
  lost one, and the wallet follows it as any participation: it hands over its
  forfeit for the new round and takes its new leaves. One the operator will
  never take is `void`, with the operator's reason shown: a coin of it whose
  forfeit for the lost round the operator's signer co-signed (the signer
  co-signs one message under a coin's salt, ever, since two burn the
  operator's bond), or published, or whose output is spent on the chain, or
  with no coin of the operator's to keep a re-run apart from the lost round.
  A coin given up for good so, its forfeit not on the chain, the wallet takes
  on the chain at once. A lost round can
  return with the parent chain, however deep: a participation follows
  whichever of its rounds is final in the chain, its leaves of that round
  live again and its leaves of the other `lost`, so the wallet holds one leaf
  for each coin it gave up. A leaf of a round that returns after the coin
  given up for it came back to the wallet on the chain (its forfeit's refund,
  or its exit) is the operator's, and stays `lost`.
- **A coin handed over stays the wallet's until the chain says otherwise.** A
  coin given to a participation, or sent in a transfer the server has not
  answered, can be exited at any time; exiting it withdraws the wallet from the
  participation, or abandons the request. A coin whose participation the
  server calls `void`, or lets expire, is live again when the server gives it
  back; one it keeps given up, under a forfeit the wallet signed, is
  `forfeited` (so is a coin whose payment the operator's signer refuses
  because it holds a forfeit of it), and is the wallet's on the chain: by
  that forfeit's refund when
  the forfeit is on the chain, else by its exit, which the wallet starts at
  once, and the forfeit is followed until one of the two is final. Every
  forfeit is
  recorded before it leaves the wallet, with the new leaves it was signed for,
  and `sync` follows each forfeit's output on the chain until a spend of it is
  final: a claim of the output publishes the preimage, which the wallet reads
  from the claim's witness to complete its new leaves at once, whatever it
  broadcast itself; an output left unclaimed until the refund delay has run
  since it confirmed is the wallet's to refund, and the coin is `exited` once
  that refund is final. A wallet that holds the preimage of the new leaves
  (read from a claim a rollback then took out) sends no refund while their
  round can return, nor while the participation stands in another of its
  rounds in the chain: the coin was exchanged for those leaves, and the
  output is the operator's to claim again. That lasts until the new leaves'
  batch has expired, when the wallet refunds; until then, a round in no block
  and no mempool, its inputs unspent, the wallet sends again itself from its
  own copy, so its new leaves are in the chain whoever else is gone. A refund in the mempool, or a claim in a block not
  yet final, decides nothing: the other may still take the output. A forfeit
  decided by a final refund or claim is still looked at until its new
  leaves' batch has expired: a rollback, however deep, that leaves that
  spend not final makes the forfeit undecided again, and the chain decides
  it again, so a claim that confirms in place of a refund still gives the
  wallet the preimage and its new leaves. None of this stops at the coin's
  expiry: the chain can decide a forfeit, or undo what it decided, at any
  time the forfeit's output lives, so the coin is checked as of its expiry
  once that has passed, as its exit checks it, and the new leaves a claim
  completes are taken in their last days, or past their expiry, as well. A
  forfeit never published whose round is lost is void.

- **A board's dates.** A board, and every coin resting on it, carries the
  dates of a batch made when the board confirmed: its service expiry is 28
  days after the median time of the block that holds the board, and its exit
  deadline three days before that. `coins` shows every coin's `expiry` and
  `exit_deadline`, and whether it rests on a board; the wallet says so when it
  receives such a coin. Up to the exit deadline the operator co-signs spends
  of it and takes it into a refresh, as for a coin resting on a batch; after
  it the wallet pays nothing with it and `sync` takes it on the chain. A coin
  that arrives a day or less from its exit date, or past it (a payment the
  server recorded before the deadline, while its signer was away, and
  completed when asked again), whether it rests on a board or a batch, is
  kept and taken on the chain at once, since nothing else can be done with it
  before it expires; its exit goes on from wherever its lineage is, an exit
  of a coin sharing that lineage (its sender's change) included. From the expiry the
  operator may bring the board's lineage on the chain to collect a coin of it
  given up in a refresh; a coin of the wallet's on that lineage then goes on
  the chain, and the wallet exits it. A refresh before the deadline avoids
  that, with the free window as for a batch leaf. The wallet reads the dates
  from the chain, refuses a server that serves boards for less than 28 days,
  and moves them with the board's block after a rollback.

- **The operator's signer's record.** The operator's signer signs every head
  of its record it hands out, an entry and its running hash: the latest with
  `info`, a round's with its tree, and a transfer's with its answer and with
  each coin it made in the mailbox. The wallet keeps each head it is shown
  with the signer's signature (one whose signature is not the signer's is
  refused), and the entry each of its coins was recorded at. Every command
  that reaches the server starts with a witness of the record: the wallet
  hands the server the highest head it holds, its coins' heads and as many
  more as fit, with a nonce it draws fresh for the call, and checks the
  running hash the record holds at each and its latest entry, each signed by
  the signer, and the record's end, signed by the signer together with the
  nonce. The wallet acts on a rollback only on proof the signer made:
  another hash the signer signed at an entry the wallet holds signed (two
  heads the signer signed at one entry), a record ending, signed with the
  call's nonce, before such an entry, or a stopped signer's own proof (the
  signed head that stopped it, and the signed head its record holds there or
  its end before it). Each means the operator's record has been rolled back
  or replaced, with its database, so its signer may sign again what it
  signed. A signed head the record does not hold stops the signer for every
  holder. An answer without that proof, or with a part the signer did not
  sign (whoever answers for the server, a proxy or a compromised server, can
  write one), is an unreachable server: the wallet exits nothing and refuses
  nothing for good, and tries again; and so is a latest entry in `info`
  below the highest the wallet holds, which an older head replayed shows
  just as well. A rollback note kept by an older version of the wallet,
  which acted without that proof, is acted on no more: the next witness
  that succeeds checks it against the signer and drops it unless the signer
  proves it, saying so among the refusals. The wallet then finds the
  highest entry it holds that the record still agrees with, takes on the
  chain at once every coin a transfer recorded after it made (a coin whose
  entry it was never given counts as after), and goes no further with the
  operator: it asks for no payment through it and signs nothing for it. A
  stop is the end of that operator, so the wallet's job from then on is to
  bring everything home: it still reads its mailbox and the coins it kept
  for a retry, checks each coin as ever, and takes each on the chain at
  once, a coin whose lineage is already on the chain included; every coin
  it still holds off the chain (its own leaves and boards, and coins made
  before the point the record agrees with) is shown with the date by which
  it must be exited (`exit_by`, its exit deadline, in `coins` and in
  `sync`'s `home`), and `sync` takes it on the chain when that date is
  within three days, paying any fee its own reserves cannot with a fee coin
  the wallet chooses (below) (`arca exit` takes one at once). A coin given
  up in a refresh the
  operator released, whose new leaf the wallet holds, is not exited: it is
  paid for already. A coin whose way to the chain is cut by another spend
  the operator co-signed, once that spend is final, is shown as lost, with
  that reason, and is no longer counted. `sync` does nothing else with the
  operator. The witness runs inside the wallet library
  itself, in every operation that takes a coin or signs a spend through the
  operator (sending, the mailbox, a board, a refresh, the swap calls,
  `sync`), so a program built on the library cannot leave it out; while no
  witness succeeds (the server denies it, or its answer carries no proof)
  the wallet takes no coin and signs no spend through the operator, and
  `sync` does only what it does on the chain, and brings home what it
  cannot have refreshed (below). The reason is shown, and kept with the
  wallet's refusals.

- **`sync` keeps every coin alive by itself.** Every coin the wallet holds
  off the chain shows its dates in `coins`, median times: `exit_by`, its
  exit deadline, three days before its first expiry (or before the service
  expiry of a board it rests on); `refresh_from`, two days before it;
  `home_from`, a day before it; and `sync_daily_from`, three days before
  it. From `refresh_from`, the coin's free window, `sync` asks for the
  refresh of every live coin by itself, one participation for each, as
  `participate` makes it: nothing is paid there, so a fee asked is refused
  before anything is signed, and a refresh the operator refuses, voids or
  lets expire is asked for again six hours after `sync` last asked for it, a
  quarter of the day-long window, while the coin is still in it (the
  schedule wakes for it then, and not sooner). A participation whose coin is on
  its way home on the chain is not handed over again; once the operator
  releases it, the wallet takes the new leaves with the preimage the server
  publishes. From `home_from`, `sync` takes on the chain every
  coin whose refresh has not completed, in whatever state (`live`, `sending`,
  `given`, `forfeited`, `offered`) and for whatever reason: the operator does
  not answer, shows no proof, refuses, answers but co-signs nothing (its
  keepers gone), or builds no round. A coin counts as refreshed only once the
  wallet holds its new leaf, validated, on a round that is final (one whose
  round is out of the chain does not count). Before `home_from` nothing is taken
  on the chain because the operator fails to answer: the coin is shown with
  its dates and `sync` tries again. One failed witness decides nothing:
  `sync` tries the operator again with back-off for about a minute
  (`--witness-patience`), its last try a second past that, before it takes
  it for unreachable, and a
  `rate_limited` answer means "ask again later". After a stop of the
  operator's signer every coin goes as above, three days ahead. Past its
  exit date, and past its expiry, the wallet goes on bringing a coin home
  until the chain says it is gone: a batch is swept only once its token has
  waited its notice, and a coin whose batch was swept, once the sweep is
  final, is shown as lost, with the sweep, and claimed back from the
  operator (see Swept coins). A payment the wallet waits for
  is read only by `sync` too, and its sender may have paid with a coin days
  from its exit date. So run `sync` at least once a day while the wallet
  holds a coin off the chain or waits for a payment, whatever `next_sync_at`
  says. A receive request lasts 27 days from when it was handed out (the
  acceptance horizon, `REQUEST_HOLDS`) and carries the median time it lapses
  at (`until`): `send` refuses a request past it before anything is built
  or signed ("the request lapsed at …: ask the receiver for a new one"),
  and the payment names it to the server, which records no payment to a
  request past it however late the payment reaches it (a post held, and
  sent again by a later `sync`): the server refuses it (`request_lapsed`),
  and the payer's coins are live again.
  `sync`'s `schedule` says when it must run next (`next_sync_at`; a time it
  names relative to now counts from the last `sync`, so it stands between
  syncs, and `due` turns true once it passes; a wallet that has never synced
  is due at once, so a program that syncs only when `due` syncs on its first
  look): a coin given to a refresh an
  hour after the last sync, an exit under way at its next step (two blocks on while it unrolls, when its
  claim's delay ends, two blocks on while its claim is not yet mined, within
  half an hour while its claim becomes final), a take of an on-chain order
  not yet released within the operator's round interval and within half its
  forfeit window,
  and never
  more than a day ahead while a receive request the wallet handed out is
  unpaid and has not lapsed, saying so (`why`); `receive_requests` lists
  every unpaid request with the median time it was handed out at, `waiting`
  until `lapses_at` and `lapsed` from then (`lapsed_at`), when it no longer
  holds the schedule. A request handed out before requests carried their
  lapse is `waiting` with `lapses_at` null, since its sender may pay it at
  any time: it holds the schedule until it is paid or forgotten
  (`forget-request`). A coin paid to a lapsed or forgotten request is still
  read, by any later `sync`. A payment the operator has recorded and not
  completed (its sender's post waits for the operator's signer or its
  keepers) is a coin announced by the operator as pending for the wallet:
  `sync` reads the operator's notice of it and lists it (`mailbox.pending`,
  and `schedule.pending_coins`) without counting it or spending it, and the
  schedule holds at a day until it comes, whatever the lapse of the request
  it pays, or is withdrawn (`mailbox.withdrawn`, with the operator's
  reason). An announcement is the operator's statement, not a payment: the
  wallet asks the server for the transfer it names (`transfer_status`) when
  it reads the notice and at every `sync` after, and one whose transfer the
  server does not show recorded with that coin is dropped with a note
  (`mailbox.dropped`, and `refusals`) and holds nothing. A program built on the
  library gets the same from `Wallet::sync_schedule`, which it can call on a
  timer (a program that runs `arca` asks `arca schedule`), and runs
  `Wallet::sync` when it says so.
  `sync` re-checks its coins against the chain and takes every exit step
  whose date has come before it asks the operator anything (a received
  leaf's home date first, then every exit under way: an unroll, a claim
  once its delay has run, a claim broadcast again at every sync until it is
  mined and replaced by one paying more when the node's floor rose above
  what it pays, or, for a received leaf, when its fee falls below its share
  of the leaf's value as the timeout nears, and any refund of a received
  leaf in the mempool replaced by a claim that pays more), and again
  whenever one comes while it is asking, so
  an operator that answers slowly holds back no claim. A coin whose refresh
  has not completed by its home date goes home after the operator is
  asked, so a refresh or payment completed in the same `sync` keeps it. The schedule names those dates on
  their own too (`next_exit_at`, and `exit_due`): `sync --exits-only`
  (`Wallet::sync_exits`) takes those steps alone and asks the operator
  nothing. A payment spends the coins furthest from
  their exit date first, so a receiver gets the longest life the wallet can
  give it.

- **The operator's keepers.** An operator's signer may hand every head of its
  record to keepers on other machines, and answer an entry only once enough
  of them hold it; the record names them when it is made, for good, and
  `info` names their keys and how many are required. The
  wallet pins them when it is created, as it pins the operator key (a wallet
  made before keepers existed pins them from the first `info` it reads, and
  shows them on that call), and refuses an operator that shows other
  keepers. From then on it takes no coin and keeps no head without their acknowledgements, each
  a keeper's signature over the head: a co-signature of the wallet's own
  payment that comes without them leaves the payment standing, posted again
  by `sync`, and a coin in the mailbox whose head comes without them waits,
  its message read again. Against an operator with no keeper, the wallet's
  `info` says so, and so does every coin it receives out of round
  (`record_held`): such a coin rests on the operator's machine alone until it
  is refreshed, since a restore of that machine can let its sender spend it
  twice.

- **A spend read from the chain** (a claim that reveals a preimage, a fill
  of an order, an exit from an accumulator batch, a collaborative spend
  `watch-bond` reads) is read with its annex (BIP341) set aside, the last
  witness item when it starts with `0x50`. Consensus ignores an annex, and
  on most of these paths no signature covers it, so whoever relays or mines
  a spend can add one; the wallet reads an annexed spend the same as the
  plain one.

### Fees

Fees are paid in the asset being moved unless another is named
(`--fee-asset`), and no asset is a default. When the node does not accept that
asset for fees, the wallet says so and does nothing; it never falls back to
another asset. An exit is the one exception, since a coin must reach the
chain whatever its asset: each step the coin's own reserves cannot pay (an
asset the node does not take for fees, or a board's conversion, which
carries no reserve) takes an on-chain coin of the wallet's, in the asset
named with `--fee-asset` or, when none is, in one the wallet chooses among
those the node takes for fees now: the asset moved first, where the node
takes it, and otherwise none preferred (the one whose largest coin covers
the most fees). Its exit says which. A wallet that holds no such coin says
so when it takes a coin that will need one, and on every listing (`coins`,
`exit_fee`): that coin cannot come home until the wallet holds one. Fee rates are the node's floor in the fee asset's own atoms,
read when the transaction is built. The transactions a transfer signs in
advance (the checkpoint, the reassignment) leave a margin in the asset moved,
which the operator bounds: at least four times its own node's floor, or one
atom where its node does not accept the asset (whoever broadcasts then
attaches a fee coin), and at most the multiple of that it publishes
(`max_margin_multiple`). Nodes value an asset each for itself, so the wallet
prices these margins from the floors the operator publishes (`info`), never
from its own node's: it leaves twice the operator's least, within the
operator's most, as room for the operator's floor to rise before it
co-signs. And it stays within its own bound: margins above 10,000 millionths
of the coins they come out of are refused before anything is signed, whatever
floor the operator publishes. A forfeit signed in a refresh leaves the
margin the operator prices; the wallet takes one only up to four times the
operator's published floor over 1,000 vbytes, or one atom where the
operator's node does not accept the asset.

The operator charges each asset by that asset's own schedule (`info`'s
`assets[].fees`: parts per million of a coin and a fixed part a coin, in the
asset's atoms; an operator that publishes none for an asset is read at the top
of `fees`), and the wallet prices each coin of a refresh by its asset's. The
fee is bounded by the wallet, not by what the server publishes: a fee above
10,000 millionths of a coin, or any fee for a coin in its free window (the two
days before its exit deadline, five days before its first expiry), is refused
before anything is signed, unless the user raises the bound for that one
command (`participate --max-fee-ppm N`); a fixed part makes a small coin's fee
a larger share of it. Every fee is printed, coin by coin, with the schedule it
was priced by (`quote[].schedule`), before the wallet signs anything for the
refresh, and a schedule that changed since it was shown is not taken: the
server refuses a fee short of the asset's schedule (`fee`), and the browser
wallet submits only the fees it showed.

### Paying and receiving over Lightning

`lightning pay INVOICE` pays a BOLT11 invoice out of the wallet's coins in the
asset the invoice names, through the operator's Lightning node in that asset.
Before anything is signed the wallet reads the invoice itself: a Bitcoin
invoice is paid in native BTC on the Bitcoin side, never from a Sequentia leaf
(see The Bitcoin side). It refuses: an invoice that names no asset (SeqLN's field `a`),
or one in another asset than `--asset` names, since a coin in one asset never
pays an invoice in another; one for no amount, or expiring within a minute;
one it is paying or has paid already; an asset the operator does not serve,
serves with no Lightning node, or whose node is down (`info`); and an
operator's fee above the wallet's bound (10,000 millionths of the amount,
raised for one payment with `--max-fee-ppm`). The coins then go, through
checkpoints and a reassignment, into an `htlc-1` leaf of the wallet's own key
locked to the invoice's payment hash, holding the amount and the operator's
fee, and the change; the operator co-signs and pays the invoice. The wallet
follows the payment (`--wait`, 60 seconds by default, then `sync`): once
`paid`, it checks the preimage against the hash, which is its proof of
payment, and the leaf is spent, the operator's (where the leaf rests on a
lowest node with RECLAIM-D, `sync` then releases that node with the leaf's
key, once, so the operator's capital behind it comes back with the node's
other coins); once `failed`, it takes the
leaf back, co-signed, into a new leaf of its own, the fee with it, and the
payment is `returned`. While the operator has not decided, the leaf is
`paying` and the wallet pays nothing else from it; should the operator never
decide, `exit` takes it home by its refund path, once its timeout and its exit
delay have passed. An invoice is paid once through the operator: a payment
that failed is not tried again with the same invoice. The `htlc-1` leaf
times out a little past the least the operator takes (`info`'s
`lightning.send.timeout_seconds` past the chain's median time) unless
`--timeout` names a median time, which must lie in the operator's window,
that least to twice it, or the payment is refused before anything is signed.
An invoice the operator made itself, for a payment into its tree (one wallet
of the operator paying another), is paid inside the operator, with no lock
time on any channel: the receiver's leaf times out the operator's
`lightning.receive.internal_gap_seconds` before the payer's, and must keep
the receive's least lock, so such a payment needs a timeout that far out.

`lightning receive ASSET AMOUNT` asks for an invoice for `AMOUNT` of `ASSET`
paid into a leaf of the wallet's own, refused before anything is asked when
the asset has no Lightning node at the operator that receives, the
operator's fee (out of the amount) is above the wallet's bound
(`--max-fee-ppm` raises it), or the leaf would be below the operator's
smallest. The invoice is under a payment hash whose preimage the wallet
derives from the leaf's key, so its mnemonic gives it back; the wallet
checks the invoice is for that hash, asset and amount. Once the payment is
held at the operator's node, `sync` takes up the operator's participation
for the leaf as its own: once the leaf's round is final it validates the
leaf from the published tree (an `htlc-1` leaf received under its hash, of
the amount less the fee), hands over its unroll authorisations, and holds
the leaf, `receiving`. Only then does it hand over the preimage, with the
transfer of the leaf into a leaf of its own, and only while the leaf's
timeout leaves it time to unroll the leaf, wait its exit delay and claim it
a margin before the timeout, when the operator's refund of the leaf opens
(the refund's two locks, the timeout and the operator's delay, run at
once). The margin is the larger of three blocks and an eighth of the leaf's
lock, from its round's confirmation to its timeout: a client that wakes
that much late for the leaf's home date still claims it first. Later than
that the wallet keeps the preimage: the payment is failed back to its payer
and the leaf is the operator's. Once the preimage has gone out the payment
is never called failed: if the operator does not answer the claim with its
co-signature, the leaf comes home by its claim at its home date (the
timeout less the exit delay, the unroll and the margin), which `sync` takes
it home at, before it asks the operator anything, whatever the operator
does, and which `sync`'s schedule names (`next_sync_at` and
`next_exit_at`). While a payment is asked for, held or claimed, the schedule
wakes the wallet within a quarter of the operator's window; `exit` takes a
`receiving` leaf home by its claim with the preimage. The payment is settled
when the preimage is handed over. A payment the operator failed back is
`failed`, with the reason.

The claim of a received leaf is a race the wallet runs to win: once its
timeout has passed, the operator's refund is valid beside it. From its
broadcast the claim's fee rises at every wake as the timeout nears, a share
of the leaf's value that grows with the square of the time gone from the
claim's opening (a quarter halfway), up to the leaf's whole value at the
timeout (less what keeps its own output above the node's dust); a claim
replaced this way, or because the node's floor rose, outbids the one before
as the node asks of a replacement. When the node no longer accepts the
leaf's asset for fees, the claim pays its fee from an on-chain coin of an
asset it accepts (the leaf's value then counted at the node's rate, or at the
rate the wallet kept when the node last took that asset), so keep one. After
the timeout `sync` replaces any refund of the leaf in the mempool with a
claim that pays more, at every wake, up to the leaf's whole value: an
operator that takes the leaf by its refund then gains only what it did not
burn in fees. What remains: a chain stall longer than the margin opens the
claim and the refund in one block, and a fee race decides it, which an
operator willing to burn the leaf's value, or that produces the block
itself, can still win; and a wallet whose only coin in an accepted asset is
the leaf cannot pay its claim once the node stops taking that asset. A
refund lock that a stall cannot leap needs another leaf template.

The
invoice locks the payment for twice the leaf's lock, eight sevenths of its
exit delay and the operator's window (so the window survives the margin),
about 5,770 blocks with a 36-hour exit delay and a six-hour window. SeqLN's
`pay` allows up to the network's limit, 20,160 blocks on Sequentia, unless
the payer sets a lower `maxdelay`; a payer that sets one sets it at least that
high, with room for the route (Fulmen adds 270 blocks for each of three hops).

`lightning receive ASSET AMOUNT --hash HASH` asks under a payment hash the
wallet did not make, whose preimage someone else holds and reaches the wallet
later: the hash of a swap made on its other side. The leaf comes as any
received leaf does, but until the wallet holds the preimage it is held apart,
`awaiting_preimage` in `balance`, counted in no row and no total, and `exit`
refuses it before anything is broadcast. The preimage reaches the wallet
either way: `lightning preimage HASH PREIMAGE` hands it over (kept once it
opens the hash), or `sync` takes it from the operator's status of the
payment, which serves it once anyone has posted it (`lightning post-preimage
HASH PREIMAGE`) or a claim on the chain revealed it. Then `sync` claims the
leaf with it, co-signed, and does so whenever the preimage comes, since it is
no secret the wallet keeps; `exit` takes the leaf home on the chain with it.
A payment whose preimage never comes is failed back by the operator once the
time to claim its leaf is over: the receive is `failed` and the leaf the
operator's. A wallet restored from the mnemonic recognises such a leaf by
its preimage not being the one it derives, and holds it the same way.
`lightning lookup HASH` shows the operator's payment into its tree under a
hash as the operator serves it to anyone holding the hash: its invoice and
state, the receiver leaf's exit delay, what holds it (`held_by`: `node`, or
`send` for a payment inside the operator, with that send leaf's timeout), and
the preimage once the operator knows it.

### The Bitcoin side

Every Arca wallet is dual-chain. Its Bitcoin side holds native BTC in a
Bitcoin ark, Bark's server (`captaind`) on a Bitcoin network, through Bark's
own wallet in `<datadir>/bitcoin`, which `arca bitcoin …` runs. It is Bark as
upstream ships it, so the wallet joins any Bark ark; an operator may name its
own (`info`'s `lightning.bitcoin.ark`), which a program can offer as the
default. BTC is never a Sequentia leaf.

`arca bitcoin create` makes the Bitcoin ark wallet from the Arca wallet's own
mnemonic, so one mnemonic restores both sides. Bark keeps its keys on paths
of its own (`m/350'/…` for its leaves, BIP86 on-chain), apart from the Arca
wallet's (`m/6'/…`, `m/84'/…`), so no key signs on both sides. Bark's command
line takes a mnemonic only as an argument, which other users of the machine
can read, so `create` runs Bark's daemon, `barkd`, on a loopback port for as
long as the create takes, hands it the mnemonic in a request body under the
token `barkd` writes in that directory, then stops it and deletes the token.

    arca bitcoin create --testnet4 --ark https://ark.example.org \
        --bitcoind http://127.0.0.1:48332 --bitcoind-cookie ~/.bitcoin/testnet4/.cookie
    arca bitcoin create --testnet4 --ark https://ark.example.org --esplora https://esplora.example.org/testnet4/api

The network is one of `--testnet4` (the network the Sequentia testnet anchors
to), `--mainnet`, `--signet`, `--mutinynet` and `--regtest`. The chain source
is a Bitcoin Core node of version 29 or later, with `-txindex`, named by its
RPC address and its cookie (or `--bitcoind-user`, the password in
`ARCA_BITCOIND_PASSWORD`, never on the command line), or an Esplora server. An
older node is refused before anything is made. A wallet made with a node scans
Bitcoin from the node's tip; to restore a mnemonic that held bitcoin before,
give the height to scan from (`--birthday-height`). Leaves held in the ark are
recovered from the server whatever the height. Every other `arca bitcoin
ARGS…` is Bark's command, run with `--datadir <datadir>/bitcoin`: `board`,
`send`, `address`, `balance`, `vtxos`, `refresh`, `exit`, `onchain …`,
`maintain`. Bark wants `maintain` run now and then, which refreshes leaves
before they expire. A `board` of an amount outside the bounds the ark's
server publishes (`ark-info`'s `min_board_amount_sat`, and `max_vtxo_amount`,
the most a leaf holds) is refused before Bark runs: Bark builds and signs a
board's funding transaction before it asks the server, and keeps a refused
one in its on-chain wallet as spent, though it was never broadcast, so the
next board would spend coins no node knows.

Native BTC goes over Lightning on the Bitcoin side, through Bark's own
Lightning leg on the Bitcoin ark wallet, never through a Sequentia leaf, and
needs nothing of the Arca operator:

- `lightning pay INVOICE` with a Bitcoin invoice runs `bark lightning pay
  invoice INVOICE --wait`, which prints nothing, then reads the payment back
  with `bark lightning pay status INVOICE` (`paid` with its preimage). A
  Bitcoin invoice with `--asset` naming a Sequentia asset is refused before
  anything is signed.
- `lightning receive btc SATS` makes an invoice (`bark lightning invoice "SATS
  sats"`). Bark's server holds a payment to it only until the wallet claims
  it, and fails it back to the payer otherwise, so the wallet must claim while
  the payer pays: `lightning claim INVOICE [--wait SECONDS]` runs `bark
  lightning claim INVOICE --wait` for up to that long (300 seconds by default)
  and answers `claimed`, or `waiting` when no payment came (claim again while
  the payer may still pay).
- A payment the claim can no longer take answers `reissued`, with a fresh
  invoice of the same amount and description for the payer to pay instead
  (`invoice`, and the one it replaces): the claim asks the server for an HTLC
  expiring the invoice's final CLTV delta less the server's
  `htlc_expiry_delta` after the tip, and the server wants that delta again
  below the payment's expiry, so blocks found between the payment's arrival
  and the claim leave the claim too close to the payment's expiry. Bark
  refuses such a claim ("Requested HTLC recv expiry too close to inbound HTLC
  expiry"), or, once it has given the receive up, finds none to claim ("no
  pending lightning receive found for this payment hash"); either way the
  payment goes back to the payer.

While the wallet has no Bitcoin ark wallet, each of these is refused with the
reason and Bark is not run. `ARCA_BARK_EXEC` and `ARCA_BARKD_EXEC` name the
`bark` and `barkd` binaries when they are not the ones beside `arca`.

### Swapping BTC for an asset

`arca btc-swap` swaps native BTC, held in a Bitcoin ark, for an asset held in
the operator's tree, between two wallets of one operator that are in one
Bitcoin ark, under one payment hash. P gives the asset and gets the BTC; Q
gives the BTC and gets the asset. Nothing is pegged: the BTC moves on
Bitcoin, through Bark, and the asset moves in the tree.

    arca btc-swap offer --give asset --asset X --atoms 100000 --sats 30000
    arca btc-swap read OFFER        # the taker: what it gives and gets, every fee
    arca btc-swap take OFFER        # prints the take, for the maker
    arca btc-swap complete TAKE     # the maker
    arca btc-swap follow --wait 25  # both, until each swap is over

Either side may make the offer (`--give btc` or `--give asset`). Offer, take
and completion lock nothing; each shows what the wallet gives and gets with
every fee: the operator's fee for the asset's payment, and Bark's fee for
paying or receiving the BTC, quoted by Bark's daemon for the coins it would
spend. The offer (`btc-swap-offer:…`) and the take (`btc-swap-take:…`) are
handed over by hand; after the completion the two wallets run alone, each
running `follow`, which moves its swaps on and runs Bark as each needs.

- The hash is P's: Bark makes every invoice's preimage itself and takes no
  hash, so P's Bark invoice for the BTC names it, and Q asks the operator to
  receive the asset under it (`lightning receive --hash`).
- P locks first: its asset goes into an `htlc-1` leaf paying the operator's
  invoice for Q's receive, settled inside the operator. The leaf times out
  late enough that Q's leaf, which the operator times out its
  `internal_gap_seconds` earlier, keeps a home date an hour past the latest
  moment the Bitcoin leg can end (the later of P's invoice's expiry and Bark's
  HTLC-send expiry delta and six blocks, at half Bitcoin's pace, and ten
  minutes) after its unroll, its exit delay and an eighth of its lock: on a
  Bitcoin ark with a delta of 258 blocks and 36-hour exit delays that is about
  six and a half days. The timeout must lie in the operator's window for a
  payment's timeout (`lightning.send.timeout_seconds` to twice that), or P
  refuses to lock and says how far out the swap needs it.
- Q pays P's invoice only once its leaf is held and validated, its round
  final (certified, its anchor buried), the leaf the swap's (received under
  the hash, of the atoms less the fee, the operator's delay as published),
  its home date at least an hour past the Bitcoin leg's latest moment, and the
  invoice ten minutes from its expiry at least. It pays once; a payment that
  did not go through is tried again at most twice, which Bark refuses at once
  once it has failed the first back.
- P's claim of the BTC reveals the preimage. `follow` claims it in slices
  (`--claim-slice`, 20 seconds) while the payer may pay, since Bark's server
  fails a payment back unless the receiver claims within its forward timeout,
  and never as a fresh invoice, whose hash would not be the swap's. P then
  posts the preimage to the operator (`lightning post-preimage`), so P's leaf
  is the operator's, and Q takes the preimage from its payment or from the
  operator and claims its leaf.

An abandoned swap leaves each leg with one party. Before P locks, nothing is
locked: a lapsed offer cancels P's invoice. P's lock comes back to P once the
operator fails Q's receive back: Q's leaf never came, or was not claimed by
its time. Q's payment comes back to Q once Bark fails it back (P never
claimed) or cancels P's receive at the invoice's expiry. A swap whose
record is lost with a device leaves its legs where a restore finds them:
`btc-swap list` shows a received leaf held for its preimage, and a restored
payment out of the tree, by hash. Bark keeps an invoice's preimage only in
its own store, so P restored before it claimed cannot claim: Q's payment
fails back and P's lock comes back to it. Q restored after it paid takes the
preimage from the operator, which serves it once P has posted it.

`follow` needs the wallet's Bitcoin ark wallet (`bitcoin create`) and, for
P's claim, the Bitcoin ark's server able to grant the payment's HTLCs: a
server whose pool of VTXOs is empty grants none, and the payer's payment is
failed back. `btc-swap list` shows every swap with its state (`offered`,
`taken`, `locked`, `paying`, `claimed`, `claiming`, then `done`, or `lapsed`,
`abandoned`, `btc_failed`, `refunded`, `cancelled`) and what happened when;
`btc-swap cancel` ends one before the wallet has locked anything.

### Paying an address on the chain

`arca offboard --asset A --amount N --address ADDR` pays `N` of `A` to an
address on the chain from the wallet's leaves, through the operator's next
round: the participation gives up coins of `A` and wants one offboard output of
exactly `N`, paying the address's script, and a change leaf where the coins
hold more. `--script HEX` names the script in place of an address; a
confidential address is refused (the output is explicit: name its
unconfidential form). The fee is in the asset paid (a round carries one asset,
so `--fee-asset` takes only it): each coin's refresh fee, the offboard's fee by
the asset's schedule, and the margin the round's offboard output holds to pay
its unlock. `--quote` shows the fee, the coins and the change before anything
is signed, and `--shown` pays only on that very fee and those coins. The answer
says how soon the round is due (`round_within_seconds`, the operator's interval
between rounds while participations wait) when the operator publishes one.

`sync` hands over the forfeits once the round is final, and the operator then
unlocks the round's offboard output into the address: its output 0 pays exactly
the amount there. The wallet unlocks it itself when the operator has not within
ten minutes of median time. `arca offboards` reads where each stands from the
chain: `waiting` for its round, `in_round`, `unlocking`, `paid` (the unlock's
`txid`, and whether it is `final`), `reclaimed` (the operator took the output
back after its delay) or `not_made` (the participation ended without a round,
or the operator refused it: the coins are the wallet's again). The operator
refuses an offboard paying one of its own Arca scripts (`script_reused`), and
each of its refusals is final: the wallet puts the coins back and posts nothing
again.

    arca offboard --asset X --amount 300000 --address ADDR --quote   # fee, coins, change
    arca offboard … --shown '<the quote>'                            # paid in the next round
    arca offboards                                                   # where each stands

### Placing an order on the chain

A maker who holds only leaves places an ordinary SeqDEX order: `arca order
place` offboards exactly the order's amount into the address SeqDEX's fill
covenant makes for its terms (two leaves under the NUMS point: FILL, which
anyone fills who pays the maker its price, and REFUND, the maker's once the
order's time has passed). The order sells `--amount` of `--sell` for `--for`,
`--rate-num` atoms of it for every `--rate-den` atoms sold, each fill's price
rounded up, in fills of at least `--min-lot` (the whole amount unless named),
and is refundable once the chain's median time passes `--expires` (or
`--expires-in-hours` from now). Fills credit the order's own key (see Keys);
`--maker-prog` names another plain program, and the wallet refuses one that is
the script of any coin it holds or held, of a board, a checkpoint or a forfeit
of one: a pair of rebindable signatures over one credit there would spend every
other credit of the same value, and whoever fills chooses each credit's value.

The participation gives up coins of the asset sold and wants one offboard
output, and a change leaf where the coins hold more. Its fee is each coin's
refresh fee, the offboard's fee by the asset's schedule, and the margin the
round's offboard output holds to pay its unlock, priced as the operator prices
it; `--quote` shows it, the coins and the change before anything is signed, and
`--shown` places the order only on that very fee and those coins. The wallet
refuses an expiry that is a height, one within the operator's order margin
(`info.fills.order_margin_seconds`) and an hour of now, since a take of such an
order would be refused, and an amount whose full price is no whole number of
atoms, which SeqDEX's relay does not list.

`order place` then waits (`--wait`, an hour unless named, 0 not at all),
syncing every few seconds: once the operator's round is final the wallet
hands over its forfeits and takes the preimage; the operator unlocks the
round's offboard output into the order's address, and the wallet unlocks it
itself when the operator has not within ten minutes of median time. It
answers where the order rests (the unlock's output 0, holding exactly the
amount) once that is final, with its terms in the relay's JSON form
(`placed.relay`). The maker may then go offline: anyone fills the order on the
chain, a holder of leaves through the operator's round (`take`), each fill
crediting the maker at `2k` and resting the rest at `2k+1` under the same
script. `arca orders` reads from the chain, each time, where each order rests,
every fill and what it credited, and the credits at its key, so an
anchor-driven rollback that undoes a fill undoes it here too. `arca board`
brings the credits into Arca. `arca order refund` takes what rests home once
the order's time has passed, to an address of the wallet's.

    arca order place --sell X --amount 1000000 --for Y --rate-num 3 --rate-den 2 \
      --min-lot 100000 --expires-in-hours 48 --quote          # coins, fee, change
    arca order place … --shown '<the quote>'                  # rests on the chain
    arca orders                                               # fills, credits, where it rests
    arca board Y 1049000                                      # the credits, into Arca
    arca order refund ORDER                                   # once its time has passed

A wallet restored from the mnemonic finds the coins it gave up for its orders
as spent and the credits at its order keys, but not the orders themselves:
their terms are on the relay and in the order's script.

#### Listing the order on SeqDEX's relay

The order rests on the chain before anything is posted, so it goes onto
SeqDEX's relay in a second step, as any order that already rests there does.
`order place` and `orders` hand out the offer for it (`offer`): a sell of what
the order holds where it rests, at its full price, with its terms and outpoint
as the covenant settlement, unsigned. SeqDEX's scripting client signs it with
the maker's own relay key (a key of the maker's choosing, the offer's
`maker_pubkey`; not a key of the wallet's) and posts it:

    arca orders | jq '.[0].offer' > offer.json
    seqob-relaycli post --http https://relay.example --priv "$MAKER_RELAY_KEY" --offer-file offer.json

The relay checks the outpoint against its node (unspent, paying the script
the terms make, holding the offer's amount of the asset sold) and lists the
order; the outpoint is outside what the key signs, so after each partial fill
the relay moves the offer to the rest at `2k+1` with no new signature. A taker
gives the relay's offer to `arca take` as it is. The relay keeps its book in
memory and an offer lasts at most seven days (the wallet's lasts six, and ends
before the operator's margin ahead of the REFUND): post the offer `orders`
hands out again after a relay restart or before it expires.

### Resting an order in the tree

An order can also rest in the tree, as a leaf of its own (`order-3`), where
takers fill it while the wallet is away. Each fill is co-signed by the
operator alone, and the leaf's program holds every fill to the order's terms:
the maker's credit, a leaf of the asset the order is paid in under the next of
four credit keys of the wallet's, at least the price; and for a part fill the
order resting again under a new salt. An order fills at most four times; what
rests after the fourth is the maker's to cancel.

`arca order rest` gives up leaves of the asset the order sells for one leaf of
exactly the amount, paying their refresh fees (`--quote` shows them, and
`--shown` rests on that very fee and those coins). The wallet checks the leaf
the operator's round makes against exactly the terms it asked for before it
signs a forfeit: a leaf of other terms, or a resting order where it asked for
none, is refused. Once the round is final, `sync` hands over the forfeit and
publishes the order to the operator; the wallet may then stop. On its return,
`sync` takes up each credit and the order resting again from the wallet's
mailbox, and the coin each fill spent is shown spent. `arca order resting`
shows each order as the operator does: where it rests, what is left, its fills,
and the credits the wallet holds of it. A maker that stays away past its
order coin's exit deadline (three days before the coin's expiry) finds the
order landed by the operator: on the chain whole as SeqDEX's order for the
same terms, refundable by its key and fillable there, not swept with its
batch. An order's coin is never paid on,
refreshed by default or planned: `arca order cancel-resting` cancels it, a
transfer of what rests into a leaf of the wallet's own. With `--quote` it
only says what the cancel gives back and its fee (the transfer's margin);
with `--shown '<the quote>'` it goes ahead only for the coin and fee shown.

`arca order fill-resting ORDER` fills another maker's order by its id. The
wallet reads the order, rebuilds the coin's script from its terms and checks
the coin against its round before it signs anything, then gives up coins of
the asset the order is paid in that expire no earlier than the order's coin
(the operator takes no others), each through a checkpoint, for a leaf of what
it fills and its change. A fill the operator does not answer is sent again,
unchanged, by the next `sync`. With `--quote` it only says what the fill
would take, pay and cost and the coin the order rests at now, signing
nothing; with `--shown '<the quote>'` the fill is of the order as the quote
served it and goes ahead only on what it showed. If another taker filled the
order meanwhile, it rests at another coin and the operator refuses the fill
(`order_moved`), giving the coins back: a new quote names the coin it rests
at now.

An order's coin brought on the chain (`arca exit`) comes home by its landing:
after the exit delay the whole of it becomes SeqDEX's own order for the same
terms, which anyone fills on the chain with no signature, paying the order
key's output (`landed_pays`, which the wallet scans). What rests of it
unfilled is the order key's to refund once the chain passes the order's
expiry, by SeqDEX's program; the wallet does not sign that refund. A coin the
operator co-signed a fill of is answered there by the operator with the fill,
within the delay.

    arca order rest --sell X --amount 1000000 --for Y --rate-num 2 --rate-den 1 \
        --min-lot 100000 --expires-in-hours 720 --quote       # the fee, the coins
    arca order rest … --shown '<the quote>'                   # its round runs
    arca sync                                                 # forfeit in; published
    arca order fill-resting ORDER --amount 300000 --quote     # what it takes and costs
    arca order fill-resting ORDER --amount 300000 --shown '<the quote>'   # a taker, in the tree
    arca sync                                                 # the maker: credits, what rests
    arca order cancel-resting ORDER

### Taking an on-chain order

An order resting on the chain under SeqDEX's fill covenant sells one asset
and is paid in another; anyone may fill it who pays its maker its price.
`arca take` has the operator's round fill it for the wallet: the wallet gives
up coins of the asset the order is paid in, worth the order's price for the
fill and the operator's fee, and gets a leaf of what it fills in the asset
the order sells. The operator's round credits the maker on the chain.

The wallet takes nothing on the relay's word. It rebuilds the order's script
from the terms as the relay serves them, finds it on its own node at the
order's outpoint, unspent and final, holding what the take names, and prices
the fill by the covenant's own arithmetic, refusing a fill the covenant would
refuse (below the order's lot, or leaving less than a lot resting) and an
order whose maker could spend it by a key path. The operator's fee is what its
schedule asks for an offboard of the price, in the asset the order is paid
in, within the wallet's bound (`--max-fee-ppm` raises it). The coins given up
hold exactly the price and the fee: where no live coin holds that much, the
wallet first pays itself a coin of that much out of round from its coins of
the asset, whose transfer leaves margins for its fees. `--quote` shows them
(`pays_itself`: the margin, the coins' margins, and the change with its expiry) and what leaves the wallet
in all (`spends`: the price, the fee and those margins), and `--shown` holds
the take to that too.

Where the operator takes them (`info.fills.shared`), the wallet's take shares
the order: other takes of the same order stand beside it, as long as all of
them together take no more than the order holds and leave nothing, or at
least its lot, resting, and the operator's round spends the order once for
all of them. It fills the order by their sum, credits the maker the order's
price for that sum (rounded up once, so never more than the takes' own prices
together) and pays each take a leaf of its own fill. The wallet gives up the
price of its own fill and the fee either way; a take that would leave the
takes standing past what the order holds is refused by the operator
(`order_taken`), saying how much is left to take.

A take asks the wallet for something once more before its round runs. A
round that fills orders pays their makers from the operator's coins, so the
operator broadcasts it only once every take in it has handed over its
forfeits, and voids a take whose forfeits have not come within ten minutes
(the operator's `info.fills.forfeit_window_seconds`) of the round being
built. `sync` hands them over: it validates the new leaf against the round's
transaction as the take's status serves it, checks that the round fills the
order as the take asked (a take that shares the order: by the sum of the takes
its status names, `fill.round_filled`, its own fill among it), and signs the
forfeit of each coin given up. A
later `sync`, once the round is final, takes the leaf. Until the take is
released, `schedule` wakes the wallet within the operator's round interval
(`info.fills.round_interval_seconds`) and within half that window, saying so
(`why`): a program that syncs when `schedule` says it is due completes the
take, and one that sleeps longer than the window loses it, its coins its own
again.

`arca order fill` is the same command.

    arca take @order.json --amount 600000 --quote # price, fee, what it gives up
    arca take @order.json --amount 600000         # taken: waits for a round
    arca sync                                     # forfeits in, once the round is built
    arca sync                                     # the leaf, once the round is final

### Paying many holders in one round, and taking a claim up

`arca distribute` pays many holders from one round: a dividend, a coupon, a
refund, an allocation, a reward payout. Its list holds a line per holder,
`KEY AMOUNT`, the amount in atoms of `--asset`; a key is an x-only key (64 hex
digits), a compressed public key (66), or a taproot address, whose program is
its key. A P2WPKH address names only its key's hash, so the holder hands over
its key instead: `arca address` shows each new address's `key`. A holder can
also be named by its wallet's OpenAMP account key, the key at `m/5/0` that an
OpenAMP account and a SeqPal ID are (`arca openamp-key` shows it), which is
how an application that knows its holders only by that account pays them.
Each holder
gets an ordinary leaf, owned by a key of its own that the wallet derives from
the key named and a nonce it draws, so one address can be paid by any number
of distributions and the address key itself signs nothing of the tree.

The coins given up hold exactly the claims and the operator's fee (its
refresh fee of each coin given up, its fixed part per claim leaf, and its
offboard's fixed part once): where no live coin holds that much, the wallet
first pays itself one out of round. `sync` hands over the forfeits once the
round is final, as for a refresh, and the claims open. A holder takes its
claim up through the operator until the deadline, three days before the
claim batch's first expiry. What no holder has taken up when the operator
sweeps the expired batch goes back to `--return`, by default a new on-chain
address of the wallet's, once that sweep is final. The operator pays that
return out of its own coins: a payer relies on it for the return, and
`arca distributions` shows each claim's state and each payment back.

A holder needs no prior contact. `arca claims` asks the operator for the
claims under the wallet's OpenAMP account key and its on-chain receive keys
(every address handed out and 20 more, or `--scan N`), proving each key with
a signature over the operator's challenge that authorises nothing else, and `arca claim` takes each
open one up. The wallet checks the leaf as it checks a leaf of its own
refresh: rebuilt from the published tree, validated against its round, final,
under its own key, with the preimage that opens its entry. Then it signs the
leaf's unroll authorisations with that key, hands them to the operator, keeps
the leaf as a coin, and pays it out of round to a fresh leaf of its own. A
wallet restored from its mnemonic finds its claims the same way. A claim the
operator does not take up is still the wallet's coin, refreshed or taken home
as any.

    arca address                                        # its key, for a payer
    arca openamp-key                                    # or its OpenAMP account key
    arca distribute holders.txt --asset X --quote       # the fee, the coins given up
    arca distribute holders.txt --asset X --shown 0     # one round pays them all
    arca sync                                           # the forfeits, once final
    arca distributions                                  # each claim, the deadline, the return
    arca claims                                         # on a holder's wallet
    arca claim                                          # taken up

### Watchtowers: a coin kept safe while the wallet is away

A coin the wallet does not refresh before its batch is released is brought on
the chain under its own key before the operator could sweep it: by the
operator, and by any watchtower the wallet deposited it with (the server's
[Coins are taken on the chain before the sweep](../server/README.md#coins-are-taken-on-the-chain-before-the-sweep)).
A coin paid to the wallet out of round is kept the same way from a sender
up its lineage who takes an earlier coin home on the chain: whoever holds
its record publishes the checkpoint and the reassignment within that earlier
leaf's exit delay, and the watchtowers do so as soon as the leaf appears, the
operator up or down. At every `sync` the wallet deposits each live coin
resting on a batch, and each coin paid to it out of round, with each
watchtower it names (`deposits` in the answer): the coin's record, its
own batch leaf's unroll authorisations signed for an hour before its batch's
first expiry, so nothing can unroll it sooner. A deposit only ever puts the
coin on the chain under its owner's key. It is sealed: the watchtower can
read it only once an event it answers is on the chain (a release of a batch
the coin rests on, or a leaf or checkpoint of its lineage), and until then
learns nothing of the coin, its value or its keys. Once a coin is spent, exited or
lost, `sync` withdraws its deposit, signed by the coin's key; a watchtower
that cannot be reached is tried again at the next `sync`.

    arca watchtowers                          # the watchtowers deposited with, and whether the operator's list or the wallet's
    arca watchtowers https://a.example https://b.example   # name them instead
    arca watchtowers --none                   # deposit with none
    arca watchtowers --operator               # back to the ones the operator's info lists

Back from an absence, the wallet finds such a coin on the chain: `coins`
marks it `kept_safe`, with the sentence a program shows its user
(`kept_safe_note`: "moved out of the Ark to keep it safe while you were
away"), and `balance` counts it under `kept_safe` as well as `exiting`.
`sync` takes it home (its exit's claim, the leaf already on the chain) and,
once the claim is final, boards it back (`reboards` in the answer): a board
of what the claim paid less the board's fee. The new board is a coin like any
other; the kept-safe coin then shows `reboarded`.

Any wallet can be a watchtower for other wallets' coins:
`arca --datadir DIR watchtower serve --listen ADDR`, run on a wallet created
against the operator (it checks every deposit as a receiver checks a coin,
against that operator's key), takes deposits over HTTP (`POST /v1/deposit`,
`POST /v1/withdraw`, `GET /v1/info`; the segment after `/v1/` names the
call, so it serves behind any path a proxy gives it) and passes over them
every `--interval` seconds. It leaves a coin alone until a batch it rests on
is released (the batch's token at `R`, in a block or the mempool) or, for a
coin paid out of round, until a leaf or checkpoint it descends from appears
in a block or the mempool, then broadcasts whatever is still missing of the
coin's path (for a lineage exit, the checkpoint and the reassignment), from the lowest
output the chain holds unspent, each transaction paid from the reserve the
output it spends holds when the node accepts the batch's asset for fees, else
from an on-chain coin of the watchtower wallet's. Coins on one branch share
its nodes, whoever built them. It needs only its node, never the operator.
`arca watchtower deposits` lists what it holds (`sealed`, naming no coin
until a block or the mempool shows its trigger; `held`, `brought`,
`on_chain`, `gone`, or `invalid` when what opened does not check) and what
it broadcast for each; `arca watchtower pass`
runs one pass.

### Swept coins

A coin a sweep took all the same (nobody brought it on the chain in time)
is owed back by the operator, less the late-refresh fee (the asset's refresh
fee at its full charge), as the operator publishes (`info`'s `swept`; the
server's [Swept coins are repaid](../server/README.md#swept-coins-are-repaid)).
`sync` asks the operator what it owes the wallet's mailbox key and claims
each coin by itself: signed by the swept coin's key, for one new coin of
exactly what is owed, which the operator makes in the asset's next round and
`sync` completes as it completes a refresh. The swept coin is shown `lost`,
its note saying it is being repaid; until the new coin is held, `balance`
counts what is owed as `returning`. `owed` lists each such coin.

The new coin's key follows from the mnemonic and the swept coin, so a wallet
restored from its mnemonic finds both what is owed and a claim made before
it was restored, and completes it. While a rollback holds the sweep out of
finality the claim waits (`withdrawn`), the coin back in its batch. A
repayment the operator voids (the wallet not back within a day of its round
being final) is claimed again at the next sync, under a new key.

### Refreshing while the wallet stays closed: plans

A wallet that will be closed past a coin's expiry pre-signs an offline-refresh
plan, and the operator refreshes the coin in later rounds without it. `arca
plan` makes one for each coin named (every live coin of a round that no plan
names when none is), with one step per expiry the wallet will be away for:
`--expiries N`, 1 to 6, 2 by default. A plan starts from a leaf of a round, so a
board or a coin received out of round is refreshed in a round first. A plan
starts from a `vtxo-1` leaf; a `vtxo-2` leaf is refreshed by `sync` in its
window instead.

Step i gives up the coin the step before it made (the first gives up the coin
itself) for a new leaf under a key the wallet derives from the mnemonic and a
nonce it draws, with the preimage its entry is locked to derived from that key
and nonce. In place of the forfeit it cannot sign in advance, the wallet signs
the step's refund: its halves over both coins' collaborative paths, each
committing to the new leaf's value at a fresh on-chain address of the wallet's
and the rest, less a margin, at the operator's script. Every use of a refund
pays the wallet's address the step's value, and a refund spends the step's
new leaf together with the coin it gave up, so it is void unless that leaf
exists on the chain. The wallet also signs the coin's attestation
over the plan, each new key's proof and each new key's binding to the mailbox
key, and hands the plan to the operator.

Each step runs no earlier than its coin's `refresh_from`, in the coin's free
window, where a refresh costs nothing: a step whose fee is not zero is refused
before anything is signed, unless `--max-fee-ppm` raises the bound for this
command. `arca plan --quote` says what each plan would cost and until when it
would cover its coin, signing and keeping nothing. Each plan answers two
median times: `covered_until`, the date until which the plan covers the coin
at the earliest if the operator applies it (the last leaf's exit deadline,
counting each new batch from the earliest a step can run), and `sync_by`, the
start of the last leaf's free window, by which the wallet must run `sync`
again. While a plan is open, `schedule` wakes the wallet at `sync_by` for its
coin rather than at the coin's own dates, and `sync` asks for no refresh of
that coin: its step is the refresh.

Back, `sync` reads each plan's status and takes up each step whose round is
final: it rebuilds the step's leaf from the record the operator serves,
validates it against the round, checks it is the leaf the plan names, signs
its unroll authorisations, hands them over, keeps the leaf as a coin, and only
then marks the coin the step gave up spent. The re-check every command runs at its start
leaves the current coin of an open plan to `sync` even past its exit date, so a wallet back
before the operator has released the old batch takes the step's leaf up rather than taking
the coin home. A step it has not taken up leaves
that coin the wallet's, to refresh or take home as any; past its home date
with its step not done, `sync` takes it home. A step it took up whose round
can never return, as the wallet's own node sees it (an input of the round
spent by another transaction, final), did not happen: the coin it gave up is
the wallet's again, and the step shows `lost`. A plan the operator stopped (a
step that can never run, such as one whose round is lost) leaves its coin the
wallet's, and the operator holds that coin's batch while the plan is
stopped: `sync` cancels the plan while the coin can still be refreshed, or
once the coin is home, and keeps it stopped while the coin is on its way. `arca
plans` shows each plan, its steps and their leaves and states, and its dates;
`arca plan-cancel PLAN` cancels the steps that have not started (refused while
a step is running, its participation taken and its round not yet final). A
wallet restored from its mnemonic finds its plans under its mailbox key,
checks every key against the mnemonic, and `sync` takes up their steps.

`arca care` is what a wallet does by itself at a sync, with no prompt: it
takes up every open claim under the wallet's receive keys (`--scan N` names
how many, as `arca claim`), cancels each open plan whose coin has moved
(spent, exited or lost), and plans each live coin of a round that no plan
names once its first step could run within ten days (`PLAN_WITHIN` in
`bark/src/arca/plan.rs`), two expiries ahead (`--expiries`), each step's fee
bounded at 2,000 millionths of the coin (`--max-fee-ppm`). `--plan-within
SECONDS` widens the planning reach alone: `4294967295` plans every leaf of a
round at the first `care` after it is made, which is what a wallet runs when it
pays its planned coins through `plan-release` (below), so that a wallet closed
in a coin's first weeks keeps it. A plan starts only
from a leaf of a round, so a board or a coin received or taken up out of round
is refreshed in a round under the same bound once within that reach, and its
new leaf is planned by a later `care`. A plan's fee is
taken from the coin, in the coin's own asset; a coin the operator will not
plan stays unplanned, with its reason, and `sync` refreshes it while the
wallet is open. At the default reach a younger coin is left unplanned so that it stays free
to pay out of round. That leaves a gap: a wallet closed within a coin's first
two weeks or so and kept closed through that coin's step window can find the
coin swept, as any holder who stays away past an expiry can, and claims it
back, less the late-refresh fee, at its next sync (see Swept coins).
Planning every leaf of a round closes it, at the price that a payment the
unplanned coins cannot cover waits for one round (`plan-release`).

A coin a plan names carries refund halves that stay valid while its script is
unspent, so the operator alone could void a payment of it out of round: no
wallet pays it out of round. `arca plan-release COIN…` gives it up in the next
round instead, for a leaf of the wallet's own that no plan names, which is then
paid or traded out of round like any coin. The operator takes the
participation for the current coin of an open or stopped plan and runs no
step from the coin while it holds it; the plan ends once the round is final
and the forfeit handed over (at `sync`), and stands as it was should the round
never complete, so the coin is never left neither planned nor refreshed. A
payment the unplanned coins cannot cover is refused, naming how much the
planned coins hold and `plan-release`; when they hold enough, the refusal's
JSON is of kind `planned`, with the `asset` and `release`, the fewest planned
coins, largest first, whose release covers the payment. A program pays by
releasing those, running `sync` until the round is final and the new leaf is
held, and asking again (a release can fall short by the new leaf's own margins,
and the refusal then names the next coin). The new leaf costs the refresh fee the
asset's schedule asks then (none in the coin's free window), and `care` leaves
it unplanned for a day. The operator takes a coin a step made into a round once
the batch of the coin that step gave up is swept and the sweep final. The operator applies a plan, as it refreshes any coin: one that
applies no step, or sweeps a coin whose holder is away, owes that coin back as it
owes any coin it sweeps (see Swept coins), and only an operator that turns
against its holders keeps it. A stopped operator,
a step's round replaced, or an operator that co-signs nothing leave the coin
the wallet knows its own, and the wallet takes it home.

    arca plan --quote                             # what each plan costs, until when
    arca plan                                     # two expiries, every coin of a round
    arca plans                                    # each step's state, covered_until, sync_by
    arca sync                                     # back: each step taken up

### Watching the operator's bond

The operator key co-signs every out-of-round spend, and a coin's salt names
that coin alone, so two different messages the operator key signed under one
salt prove it signed twice, and burn its bond. The wallet keeps the
operator's signature over every message its coins rest on: `bond-evidence`
prints them as evidence lines, `{"salt", "form", "rest", "signature"}`, to
hand a watcher. `watch-bond` is that watcher. It takes the wallet's own lines
and every file given with `--evidence` (what another wallet's `bond-evidence`
printed, or one line a line), counts only the lines whose signature the
operator key made (`evidence.refused` counts the rest), and reads the chain
and the mempool for every spend of a script that carries a watched salt's
constant, reading the operator's signature and its message from the
transaction. A wallet with no lines to watch reads nothing. A salt read before
is read on from where the last run stopped; a salt of the wallet's own coins
needs no block read while every batch output and board those coins rest on is
unspent, since every spend under it starts by spending one of them, and is
read from the block of a spent one otherwise; a salt only another wallet's file
names is read from 20,000 blocks back, and none further back than that
(`scanned` says from where, to where, and how many blocks). The chain is read
128 blocks at a time, many to a request, and the signatures found are kept
before the height is noted, so a run cut short goes on where it stopped. One
run reads for five seconds at most, since the wallet is held while it runs;
`scanned.more` says the next run reads on. Two different messages under one salt are a
conflict: the wallet builds the slash, which burns the whole bond with a bare
`OP_RETURN` and pays its fee from an on-chain coin of the wallet's own (the
bond's asset first, or `--fee-asset`, as for an exit), and sends it, and sends
it again at every run until its block is final. A slash needs no key: any
holder of the two signatures can send one, so give your evidence to several
watchers, or run your own. A watcher learns the salts and messages it is
given, not who holds the coins; it cannot take a coin, and a slash pays no
one. Run `watch-bond` beside `sync`, at least as often.

### Channel leaves

A channel leaf (`channel-1`) holds a balance for the wallet and one for the
operator. Paid from, it moves the wallet's balance to the operator's; paid
into, it moves the operator's balance to the wallet's, so it can be paid only
as much as the operator's side holds. A payment between two channels of one
operator is final for the receiver at once, with no round between and nothing
asked of the receiver: the operator signs the receiver's channel a note, a
cumulative credit the receiver can take on the chain with nobody's help.
`info` shows each asset the operator makes channels of (`assets[].channels`:
the most it puts on its side, `capacity`, and its credit window).

    arca channel open --capacity 1000000           # every live coin of one asset into a channel
    arca channel open --capacity 1000000 --keep 1500000   # the same, 1500000 kept in a plain leaf beside it
    arca care --channels                           # or by itself: a channel in each asset the operator makes them of
    arca sync                                      # once the round is final: the channel is live
    arca channel list                              # each channel: its balance, its credit, the operator's side
    arca channel code --address ADDR               # a text a payer pays at once
    arca send CODE --asset X --amount 400000       # over the payer's channel into the receiver's
    arca channel pay LEAF RECEIVER_LEAF 400000     # the same, by the receiver's leaf id
    arca channel sync [LEAF]                       # the operator's latest state and note, checked
    arca channel fold LEAF                         # the credit paid in, into the balance
    arca participate --leaf LEAF                   # close into a round: a leaf of the wallet's side
    arca channel exit LEAF                         # close on the chain alone; run until `exited`

A channel's address is its leaf id: a payer names the receiver's channel
leaf. A receiver hands it out in two texts, both of which `send` takes. A
receive request (`receive`) names the wallet's channels that can be paid now
(live, their round final) under `channels`, by asset, beside the leaf it
asks for. A channel code (`channel code`, kind `channel-code`) names those
channels and nothing else: no key and no lapse, so it can be handed out
again, with an address for a payment on the chain when `--address` gives
one. `send` pays over the payer's channel in the asset into the receiver's
when the text names one in that asset and the payer's channel, its round
final, holds the amount (`route: "channel"` in the answer, with the
operator's receipt); otherwise it pays a receive request to its leaf, as
before (`route: "leaf"`, and why not by a channel under `not_by_channel`),
and refuses a code, naming the code's address for a payment on the chain.
The operator's refusal of the channel payment (the receiver's channel cannot
take that much, or it was closed) leaves nothing standing, and the same
fallback follows. A state sent and not answered stands: `send` refuses it as
unreachable and pays nothing another way, since the next `channel sync`
sends it again. `--route channel` or `--route leaf` takes one way alone.

The payer relies on the operator for the one request a channel payment is:
the operator could co-sign the payer's new state and keep the receiver's
note back. The receiver's payment is final once it holds the note. The wallet's side of a channel is its latest balance and every credit
not yet folded, which `balance` counts and a refresh gives up; the leaf's
value beyond it is the operator's. Paying folds every credit not yet folded in
the same state. The wallet keeps every state both sides signed, the latest
note, and a state it sent and never saw answered, which `channel sync` sends
again; a wallet restored from its mnemonic takes its channel coin as any leaf
and reads its states and note with `channel sync`.

`channel exit` runs one step a run, as far as the chain allows: the coin's
path unrolled as any leaf's, the latest state published over whatever state
the coin is in, its settle once the exit delay has run from that state's
block, the credit not folded claimed from the operator's side, and the
wallet's outputs swept to an address of its own. Fees come from an on-chain
coin of the wallet's, in the asset named (`--fee-asset`) or chosen as for an
exit. An older state the operator publishes never pays the wallet less than
the latest: the wallet's latest note takes the rest from the operator's side.
The wallet follows the coin through whatever was published on it, by whom
and with or without an annex on its witness, by the leaf each spend ran; a
spend it cannot read as one of the coin's leaves stops the exit with the
transaction named, and never marks the coin spent.

Credit not folded has a deadline that a balance does not. Once any state of
the channel is settled on the chain, by whoever published it, the operator
may take back what the note's claim has not taken after the channel's credit
window (`window_units` in `info`, in units of 512 seconds). `sync` does not
notice a channel closed by someone else: a wallet holding credit not folded
either folds it (`channel fold`, or any payment from the channel), after
which nothing of it has a deadline, or runs `channel exit` within the window
of any close.

A channel leaf expires with its round, as any leaf. No plan starts from it:
`care` closes it into a round once its expiry is within reach, for a plain
leaf of the wallet's side, and a new channel is opened from that leaf with
`channel open`, or by the next `care --channels`.

`care --channels` cares for channels first: it reads each channel (the notes
it was paid, a state sent and unanswered sent again) and folds the credit it
was paid into its balance; then, for each asset the operator makes channels
of in which the wallet holds leaves but no channel, it opens one in the next
round, half of what those leaves hold after the refresh fee in the channel
with the operator's whole capacity on its side, and the other half in a
plain leaf beside it. Leaves a plan names, resting orders, coins awaiting a
preimage and leaves of a supervised asset are left as they are, and so are
leaves too small to split into two of the operator's smallest (`opened`
says so). Since it runs before planning, the leaves it opens a channel from
are not planned.

An exit of a channel coin is the channel's exit: `exit LEAF` runs `channel
exit`, and so does a wallet taking the coin home by itself (`sync`, when the
coin cannot be refreshed in time or its path is found on the chain), so a
channel closed by someone else is followed to its settle and its credit
claimed. `exit --quote` refuses a channel coin: each step of its exit is
priced as it is taken.

### Holding a supervised asset

A supervised asset is one whose issuer can freeze holdings by a rule of the
chain: the issuer names an address in a freeze record, or pauses the asset,
which freezes every holder at once. The node lists such assets
(`getsupervisedassets`), and an operator serves one under the supervised
profile, which `info` shows as the asset's `supervised` entry with its
`landing_allowance`.

The wallet holds a coin of such an asset only as a `landing-1` leaf, and only
when its own node lists the asset as supervised and the operator serves it so.
A `landing-1` leaf's exit pays one output only: P2WPKH of the wallet's landing
key (`landing_address` in `info`), explicitly in the asset, all of the coin's
value but at most the allowance. The wallet asks for every leaf of such an
asset that way, in a board, a refresh, a payment it receives (its receive
request carries the landing) and the change of a payment it sends; it pays
such an asset only to a request that names a landing, takes a coin only when
its landing is the wallet's own with the published allowance, and refuses a
round of such an asset with a blinded output, which consensus refuses as well.
The landing is one address for every coin of every supervised asset, so a
freeze of that address reaches every coin the holder has and every one it
receives later, as the issuer expects of an address; the price is that the
holder's coins of supervised assets are linked to each other through it.

The wallet reads a freeze from its own node, at the landing address, never at
a coin's own Arca script: the node calls an Arca script frozen once a record
names it or the asset is paused, although its script-path spends still
confirm. `coins` shows each coin of a supervised asset with its `landing` and
`frozen` (`frozen`, `paused`, and a `note` saying what follows while either
holds). While its holder is frozen the operator co-signs nothing that spends
the coin, no payment, swap, refresh, offboard, take, fill, distribution, plan
or Lightning payment, and refuses with `frozen`; a payment to a frozen holder
is still co-signed, and arrives frozen. The operator takes the lifting of a
freeze only once the block that first showed the landing free is final, so a
coin is still refused in the tree for a while after the node shows it free.

A coin of a supervised asset is never planned or paid out as a claim: the
operator runs no plans and no distributions in such an asset, so `plan`
refuses the coin and `care` leaves it to `sync`, which refreshes it in its
window.

A frozen coin leaves the tree only by its landing. `arca exit LEAF` unrolls
its path and claims it to the landing key, and `sync` does so before the
coin's exit date, as for any coin whose refresh the operator refuses. On the
chain it is an ordinary coin of the wallet's, frozen by the same record:
`balance` counts it in its asset's row and again under
`sequentia_onchain_frozen`, and the wallet keeps it out of every spend (a
board, a fee coin) while the node shows it frozen. Once the issuer lifts the
freeze, the wallet spends it like any other coin.

`arca supervised-check TXID:VOUT` reads a whole published batch of a
supervised asset, as its issuer or an auditor reads one, from the published
tree and the chain alone: the tree rebuilt from its parts and its batch output
compared with the round on the wallet's node, the asset supervised on that
node, every leaf `landing-1` with the allowance the operator publishes, and
every output of the round explicit. Each leaf is listed with where it lands
and whether the node shows that landing frozen; `ok` is true only when every
check holds, and `problems` lists what did not.

    arca info                                     # landing_address
    arca coins                                    # each coin's landing and frozen
    arca exit LEAF                                # a frozen coin home, into the landing key
    arca supervised-check TXID:VOUT               # a supervised batch, read whole

### Finding an operator in the registry

An operator publishes a record of itself in the Sequentia registry: its
operator key, the chain's genesis, its API's address, the assets it serves
with their rate sources and fee schedules, its keepers, its exit delays and
expiry, its template list and a contact, signed with its operator key. The
registry checks each record against the operator's live `info` when it is
listed and on a schedule, and marks it `stale` when the operator has not
answered for a while and `mismatched` when its `info` no longer says what the
record says.

    arca operators --registry https://example.org/registry
    arca join --from-registry <operator key> --registry https://example.org/registry \
      --node-url http://127.0.0.1:18300 --node-cookie ~/.sequentia/regtest/.cookie

The wallet trusts the registry for nothing it can check: it verifies every
record's signature itself (`arca_covenant::operator_record`), so a registry
can leave an operator out but cannot change what an operator said, and `join`
pins the server only when the server's own `info` shows the record's key,
chain and keepers. What the record cannot tell is whether the operator key is
the one the operator means; compare it, as with `create`, with what the
operator publishes through a channel you trust. `ARCA_REGISTRY` sets the
registry for both commands.

### Commands

| Command | Does |
|---|---|
| `create --server URL --node-url URL [--node-user U [--node-password-file FILE] \| --node-cookie FILE] [--mnemonic M \| --mnemonic-file FILE]` | Creates the wallet: a new mnemonic (or the one given, on the command line or read once from a file, `-` for the standard input, a pipe or a socket alike, which keeps it off the command line other users of the machine can read), the node's chain, and the server's operator key, pinned and shown for the user to compare with the key the operator publishes through a channel they trust. `--exit-delay-units` is the exit delay the wallet asks for its own leaves; `--min-exit-delay-units` and `--max-exit-delay-units` bound what it accepts (512-second units; 36 to 48 hours by default). With `--mnemonic`, the wallet is then restored (`restore`), and its answer is under `restore` |
| `join --from-registry KEY --registry URL --node-url URL …` (`create --from-registry`) | Creates the wallet with the operator the Sequentia registry lists under operator key `KEY`, in place of a server named by address, taking the node, mnemonic and delay options of `create`: the operator's record is read from the registry, its signature by `KEY` checked by the wallet itself, the server's address taken from it, and the wallet created only when that server shows the record's operator key, chain and keepers (see Finding an operator in the registry); a record the registry finds `mismatched` is refused. The answer carries the record's listing under `registry` |
| `operators --registry URL [--genesis G]` | The operators the registry lists, each record's signature checked by the wallet (`signature: "verified"`), with what the registry says of each (`status`: `ok`, `stale` or `mismatched`, and the `differences`); a record whose signature does not verify is listed under `refused` with the reason. With `--genesis`, those of that chain only. Needs no wallet |
| `restore` | Restores the wallet from what the server serves to its mailbox key, every record checked (see Restoring from the mnemonic), then reads the mailbox and runs `sync`: what was restored, what was not and why (`not_recovered`), what the checks found (`notes`), and the offline-refresh plans found under the mailbox key, their keys checked against the mnemonic (`plans`) |
| `info` | The wallet's chain, operator, mailbox key and policy, the address every coin of a supervised asset lands at (`landing_address`), and what the server publishes |
| `supervised-check TXID:VOUT` | Reads the published batch at output `VOUT` of round `TXID` of a supervised asset, from the published tree and the chain alone (see Holding a supervised asset): the asset supervised on the wallet's node, every leaf `landing-1` with the allowance the operator publishes, every output of the round explicit, each leaf's landing and whether the node shows it frozen; `ok` and the `problems` found |
| `supply ASSET` | For an asset the operator serves issuer-operated, the operator's supply report (`issuer_supply`): each mint of its rounds and each burn of its own, the totals, what is final, the value live in its burn-only batches and where its mint limiter stands; each mint and burn read again from the wallet's node, with what the chain says beside the operator's figure (`on_chain`, `agrees`), and `checked_on_the_node: true` only when every one agrees. It checks the transactions the report lists, not that the list is whole: a mint left out of it is found only by following the asset's reissuance token on the chain |
| `leaf-template [vtxo-1\|vtxo-2]` | The template of the wallet's own new leaves, after setting it when one is named: its refreshes, its change and what its receive requests ask a sender for. `vtxo-1` (the default) has the tapscript collaborative path; `vtxo-2` has the Simplicity program `arca/collab-2`, whose pair also binds the coin's index and the coins it is spent beside, so one leg of a swap never moves without the other. Both exit alike, by the same script; a `vtxo-2` coin's collaborative spend is larger on the chain (556 vB against 280). Coins held keep their template until refreshed; a coin of a supervised asset is `landing-1` whatever is set, the leaves an in-tree fill of a resting order makes the wallet are `vtxo-1` (the fill request names no template), and a `vtxo-2` coin is refreshed by `sync` rather than planned |
| `bond` | The operator's equivocation bond as the wallet checks it on its own node (`state`: `none`, `bonded`, `noticed` or `missing`, and `why`), its coin, asset and value, when it can be withdrawn while in notice, whether the wallet requires one (`required`), what the wallet holds out of round, and whether the bond covers it (`covers`) |
| `bond-evidence` | Every message the operator key signed that the wallet's coins rest on, as evidence lines (`lines`): what the wallet hands a watcher |
| `watch-bond [--evidence FILE]… [--fee-asset ASSET]` | Compares the wallet's evidence and every file's under each salt, reads the chain and the mempool for spends of the coins they name, and burns the operator's bond on two different messages under one salt: what it counted (`evidence`), what it read (`scanned`), the `conflicts`, the slash it sent (`slashed`), and each slash sent before again until final (`resent`) |
| `address` | A new on-chain address, to pay the wallet's boards and fee coins from, and its key, which a payer names to pay the wallet a claim |
| `openamp-key` | The wallet's OpenAMP account key (`m/5/0`, as every wallet on the kit derives it): the key an OpenAMP account and a SeqPal ID are, which a payer may name to pay the wallet a claim |
| `balance [--without-bitcoin]` | The headline, `total`: what the wallet holds of every Sequentia asset together, Arca coins and on-chain coins, in atoms of the reference unit at the rates of the wallet's own node (the only rates it can check), each asset's value beside it, and the assets the node has no rate for set apart (`unvalued`) and left out; no asset comes first. Then one row per holding, BTC first and always, 0 included (it is on its own chain, and counted apart), then each Sequentia asset the wallet holds anything of, with its value where the node has a rate, each counted as the total counts it (`held`: a coin whose exit's claim is out once, as the claim's output on the chain); and per asset: Arca coins by state (a coin received out of round and not yet refreshed as `operator-confirmed`; a leaf received under a hash the wallet did not make, its preimage not in hand, as `awaiting_preimage`, counted in no row and no total; what the operator owes for a coin its sweep took, until the coin that repays it is held, as `returning`, counted in the row and the total; of what is `exiting`, a coin kept safe on the chain while the wallet was away, to be boarded back, as `kept_safe` too), on-chain coins (the credits of its orders at their keys among them), and the Bitcoin side (Bark's ark balance and its on-chain wallet, `bitcoin`; BTC's row counts both, and has no total when Bark could not be read). `--without-bitcoin` leaves the Bitcoin side out and runs no Bark, for a program that reads it on its own one Bark run at a time (Bark lets one process at a time open its wallet); BTC's row is still first, with no total |
| `coins`, `record LEAF` | Every coin held or once held, with its leaf's template (`template`: `vtxo-1`, `vtxo-2`, `board-1`, …), its dates (`expiry`, `exit_deadline`), whether it rests on a board, the profile of the batches it rests on (`batch_profile`: `issuer-operated` when a sweep above it can only burn, `open` when its batch's sweep pays the operator, none for a coin of boards alone), and, for every coin held off the chain, the dates `sync` keeps (`sync_daily_from`, `refresh_from`, `home_from`, `exit_by`) and the fee coin its exit needs, if any (`exit_fee`); for a coin of a supervised asset, where it lands (`landing`) and whether its holder is frozen (`frozen`); for a coin someone else brought on the chain while the wallet was away, `kept_safe`, the sentence to show (`kept_safe_note`) and whether it is boarded back (`reboarded`); one coin's record |
| `board ASSET AMOUNT [--fee-asset A] [--quote \| --shown FEE]` | With `--quote`, only says what the board would pay now (its fee in the fee asset's own atoms, its size, the coins it spends), signing, asking and broadcasting nothing; with `--shown` (that answer's `fee`, as JSON) it goes ahead only on that very fee, refused before anything is registered or signed when it changed. Otherwise: brings on-chain coins into Arca, the credits of its orders at their keys among them. The server registers the board before it is broadcast, so a refused board spends nothing; the coin is spendable once the board transaction is final. Only a refusal marks the board `lost`: when the server's answer is not seen (no answer, a timeout, a 5xx), the server may hold the board and broadcast it itself, so the coin stays `pending` with its transaction and `sync` posts the same registration again |
| `boards` | Where each board stands, by the server and by the chain |
| `watchtowers [URL…] [--none \| --operator]` | The watchtowers the wallet deposits its coins with and where the list comes from (`setting`, or `operator`: those `info` lists), after naming them when given (see Watchtowers) |
| `watchtower serve [--listen ADDR] [--interval S]` | Runs this wallet as a watchtower for other wallets' coins until stopped: deposits over HTTP, and a pass every `S` seconds (see Watchtowers). `watchtower pass` runs one pass; `watchtower deposits` lists the deposits held, each with its state and what was broadcast for it |
| `receive [--asset A] [--amount N]` | A single-use receive request (`arca:…`): a fresh key and owner nonce, the wallet's mailbox, the exit delay asked for, the template it asks for when it is `vtxo-2` (`leaf-template`), the wallet's channels that can be paid now (`channels`, by asset; in the asset named, when one is), and the median time it lapses at (`until`, 27 days on). A request naming an asset the operator does not serve is refused |
| `forget-request OWNER` | Stops waiting for a payment to the unpaid receive request of key `OWNER` (as `sync`'s `schedule.receive_requests` lists it): it lapses now and no longer holds the schedule; a coin paid to it is still read by any later `sync`. `forget-request restored` ends the hold a restore puts on the schedule for requests handed out before it |
| `send REQUEST [--amount N] [--asset A] [--route any\|channel\|leaf]` | Pays a receive request or a channel code: over the wallet's channel into the receiver's when the text names one in the asset and the wallet's can pay it (see Channel leaves); otherwise a receive request out of round, unless it has lapsed: the coins of the asset (those furthest from their exit date first), each into a checkpoint, and the reassignment into the receiver's leaf and the change. For a coin resting on a lowest node with RECLAIM-D the wallet also signs the delegation of its release to every output's owner key, so the operator can reclaim that node once the coins' holders refresh; never for an order resting again after a fill, whose key is the order's and has delegated. The server co-signs and posts the coins to the mailboxes. `route` in the answer says which |
| `mailbox` | Reads the mailbox and validates every coin in it; each is kept or refused with its reason, and one refused for a passing reason (what it rests on not on the chain now, during a rollback, or the node not answering) is kept aside as `waiting` and checked again on every read. A coin read again that the wallet holds already is shown apart (`already_held`), never as taken; the read's cursor never moves back (a message at or before what was read is not read again, a page with nothing past it ends the read, and one read takes at most a hundred pages of a key, `MAILBOX_PAGES`, the rest left to the next, each said in `note`); a second record of such a coin, whose checks all pass, with other checkpoint values (the operator co-signed two checkpoint values for one coin) is kept with the wallet's refusals as evidence and reported, the coin held as it was |
| `lightning pay INVOICE [--asset A] [--max-fee-ppm N] [--timeout T] [--wait S]` | Pays a BOLT11 invoice out of the wallet's coins in its asset (see Paying and receiving over Lightning): the coins given up, the margins, the change, the transfer, and the payment as it stands after `--wait` seconds (`paid` with its preimage, `returned`, or `paying`, followed by `sync`) |
| `lightning payments` | Every payment over Lightning the wallet made, by payment hash: the invoice, asset, amount, fee, the `htlc-1` leaf, its state and its preimage or reason |
| `lightning receive ASSET AMOUNT [--description D] [--max-fee-ppm N] [--hash H]` | An invoice for `AMOUNT` of `ASSET` paid into a leaf of the wallet's own (see Paying and receiving over Lightning): the invoice, its payment hash, the fee and what the leaf will hold; `sync` claims the leaf once the wallet holds it. With `--hash`, under a hash the wallet did not make, the leaf claimed once its preimage reaches the wallet (`hash_given`). `btc` for native BTC: an invoice for `AMOUNT` satoshis on the Bitcoin ark wallet, which `lightning claim` then claims (see The Bitcoin side) |
| `lightning claim INVOICE [--wait S]` | Claims a payment to a Bitcoin invoice of the wallet's while the payer pays, waiting up to `S` seconds (300): `claimed`, `waiting`, or `reissued` with a fresh invoice when the payment can no longer be claimed (see The Bitcoin side) |
| `lightning preimage HASH PREIMAGE` | Hands the wallet the preimage of a payment it receives under a hash it did not make: kept once it opens the hash; `sync` then claims the leaf |
| `lightning lookup HASH` | The operator's payment into its tree under `HASH`, as it serves it to anyone holding the hash: invoice, state, the leaf's exit delay, `held_by`, and the preimage once known |
| `lightning post-preimage HASH PREIMAGE` | Hands the operator the preimage of a payment into its tree: it claims the payment once its leaf is its owner's and decides a payment held inside the operator; the operator serves it from then on |
| `lightning receives` | Every payment the wallet asked to receive, by payment hash: the invoice, asset, amount, fee, the leaf's value and participation, and its state (`waiting`, `issuing`, `claiming`, `received` or `failed` with the reason); never the preimage |
| `quote [--leaf L]… [--max-fee-ppm N]` | The refresh fee of each coin a participation would give up (every live coin when none is named), coin by coin with the schedule it was priced by (`coins`), within the wallet's bound, before anything is signed |
| `participate [--leaf L]… [--not-before T] [--max-fee-ppm N] [--shown FEES]` (`refresh`) | Gives up the coins named (every live coin when none is) for a new leaf in each of their assets, in one participation per asset, since a round carries one asset, or one per 16 coins of an asset that has more, the most a participation gives up: each asset's coins are refreshed in that asset's next round. Every other command that gives coins up in a participation (`order_rest`, `order_place`, `offboard`, a take) chooses at most 16, the largest first when the wallet holds more, and is refused naming a refresh, which merges them, when 16 do not hold what it needs. Each new leaf is under a fresh key whose own signature proves the wallet holds it; each participation pays the operator's refresh fee in its own asset, within the wallet's bound (`--max-fee-ppm` raises it for this command); each coin's fee is printed before anything is signed. It answers each participation (`participations`), one the server refused or did not take now with its `error` and a `note`: a refused one gives its coins back; one not taken now (no answer, or the operator taking no new work in its asset while its rate is stale, `rate_stale`) stands, its coins given, and `sync` posts it again, while every other asset's goes on. It is refused only when none was taken. With `--shown` (`quote`'s `coins`, as JSON), the participation goes ahead only on the very fees a program showed its user, and is refused before anything is signed when they changed |
| `participations` | Every participation the wallet made, from its own store, asking nothing of the operator: where each stands, the round it ran in, whether it was released, the coins it gave up and the new leaves it wanted, with the state of each. `sync` reports a release once; this answers again whenever it is asked |
| `sync` | Re-checks every coin, posts again the board registrations and transfer requests the server never answered, reads the mailbox, binds to the mailbox key every coin kept before the wallet named it (`bound`), claims back every coin the operator's sweep took and takes up a claim made before a restore (`owed`; see Swept coins), moves every participation on (a take's forfeits as soon as its round is built, against the round as its status serves it; once its round is final, validates the new leaves, signs the forfeits, takes the preimage and releases the old batch leaves' lowest nodes, each release naming the new round's connector asset, and for a coin a reassignment made each lowest node with RECLAIM-D it rests on, as its current holder (never for an order resting again after a fill, whose key is the order's and has delegated); one the server released on forfeits the wallet handed over before is completed with the preimage the server publishes with the round's tree, nothing signed again and none of the checks made before signing made again; the releases, signed with the forfeits, go to the server once the participation is completed however it completes, and again at each `sync` until the server takes them), asks for the refresh of every live coin in its free window (but the current coin of an open offline-refresh plan, which its step refreshes), takes up each step of a plan whose round is final, holds again the coin a step gave up whose round can never return, and cancels a plan the operator stopped while its coin can be refreshed or once it is home (`plans`), follows on the chain every forfeit whose preimage it does not hold, follows
every payment over Lightning the operator has not decided (a paid one closed
with its preimage, a failed one's leaf taken back), moves every payment it
asked to receive on (the operator's participation for its leaf taken up,
the leaf claimed with the preimage once held), takes on the chain every coin whose refresh has not completed a day before its exit date, and moves every exit on; every exit step whose date has come is taken first, before the operator is asked anything, and again whenever one comes while it asks; it says when it must run next (`schedule`). Run it at least once a day while the wallet holds a coin off the chain or waits for a payment. `sync --exits-only` takes the exit steps whose date has come and nothing else, asking the operator nothing |
| `schedule` | When `sync` must next run (`next_sync_at`, a median time, and `due`), when the next exit step is due (`next_exit_at` and `exit_due`, which `sync --exits-only` takes), what holds it back (`why`), the dates of every coin held off the chain (the current coin of an open offline-refresh plan with its `plan` and `sync_by`, the date it wakes for) and the unpaid receive requests, every plan as `plans` shows it, asking nothing of the operator: for a program that runs `sync` on a timer |
| `recheck` | Re-checks every coin against the chain as it is now (while the chain has only grown since the last re-check, a live coin is read again only when an output it descends from no longer stands or its exit date is near; after a rollback every coin is), starts the exit of any coin whose round or board the chain holds fails the wallet's checks, whose lineage shows on the chain, or that is past its exit date, and reports what changed and whether the tip it last saw was reorganised away |
| `channel list` | Every channel leaf the wallet holds: its latest state, its balance (the latest state's and every credit not folded), its credit and what of it is not folded, the operator's side, and whether a state waits for the operator's answer (see Channel leaves) |
| `channel open [--leaf LEAF]… --capacity N [--keep K] [--max-fee-ppm P]` | Gives up the coins named (every live coin of one asset when none is) in the operator's next round for a channel leaf: what they hold, less the refresh fee (and less `K`, kept in a plain leaf of the wallet's beside it), on the wallet's side and `N` on the operator's, at most the capacity `info` publishes; `sync` takes it once the round is final |
| `channel sync [LEAF]` | Reads the channel (every live one when none is named) from the operator and takes every newer state and note, each checked by the wallet's and the operator's keys; a state sent and never answered is sent again |
| `channel code [--address ADDR]` | A channel code: the wallet's channels that can be paid now, one for each asset, and `ADDR` for a payment on the chain instead, for a payer's `send` (see Channel leaves). Refused while the wallet holds none |
| `channel pay LEAF TO AMOUNT` | Pays `AMOUNT` from the channel `LEAF` into the operator's channel `TO`, in the same asset: the next state signed, every credit not folded folded in it, and the answer the operator's signature and the receiver's note (`receipt`). Refused beyond the wallet's side, beyond what the receiver's operator side can take, or into the channel itself |
| `channel fold LEAF` | Folds every credit the channel was paid into its balance |
| `channel exit LEAF [--fee-asset A]` | Closes the channel on the chain, one step a run (see Channel leaves); `exited` once the wallet's side is swept home |
| `exit LEAF [--fee-asset A] [--quote \| --shown FEES]` | With `--quote`, only says what this run would broadcast (each transaction's size, fee and what pays it, their fees by asset as `unroll`) and the claim's fee at the floor now, broadcasting and writing nothing (for an exit whose claim is out, `state: claimed` with the claim and nothing to pay); with `--shown` (that answer's `unroll`, as JSON) the path is broadcast only on those very fees, nothing broadcast when they changed. Otherwise: takes a coin on-chain from its record alone, without the server, paying what its own reserves cannot with a fee coin in the asset named or, when none is, one the wallet chooses (see Fees), whether it is live, waiting, held for a swap, given to a participation, under a forfeit whose preimage the wallet does not hold, in a transfer the server never answered, or the `htlc-1` leaf of a payment over Lightning the operator has not decided: the unroll and entry of each batch leaf (for a leaf of an accumulator batch, its exit from the batch output where the last exit left it, followed from the round through each exit's witness, then its entry), a board's conversion, each checkpoint and reassignment; then, once the exit delay has run, the claim to one on-chain address of the wallet's (for a `landing-1` leaf, its landing key, the only output its exit can pay; for an `htlc-1` leaf, its refund, which the chain takes once the leaf's timeout has passed too). Each run starts from where the chain holds the coin's path now (whichever round pays its batch output, whatever step someone else published), goes as far as the chain allows, and remembers the fee asset; run it again, or `sync`, to go on. The coin is `exited` once its claim is final; until then the wallet follows the claim, and builds it again should it leave the chain. A coin whose path another spend the operator co-signed has cut (a coin it rests on paid twice) is refused, naming that coin and the transaction that took it |
| `take ORDER [--amount N] [--max-fee-ppm N] [--quote \| --shown TAKE]` | Takes an on-chain order in the operator's round (see Taking an on-chain order): `ORDER` is the order as a relay serves it (its `CovenantTerms` JSON, or an offer whose settlement is one), `@FILE`, or `-` for standard input; `--amount` is how much of the asset it sells to take, all of it unless named. With `--quote`, only says what it would cost (the fill, what rests again, the price, the operator's fee, what the coins given up hold, and whether the wallet pays itself a coin of that much first); with `--shown` (that answer, as JSON) the take goes ahead only on that very fill, price and fee. Answers the take: a participation `sync` completes |
| `order place --sell A --amount N --for B --rate-num N --rate-den D [--min-lot N] (--expires T \| --expires-in-hours H) [--maker-prog P] [--max-fee-ppm N] [--quote \| --shown QUOTE] [--wait S]` | Places an order on the chain from the wallet's leaves (see Placing an order on the chain): with `--quote`, only says what it would cost (the coins, the fee and its parts, the change, the full price); with `--shown` (that answer, as JSON) it is placed only on that very fee and those coins. Waits up to `S` seconds (3600; 0 not at all) for the order to rest on the chain, final, and answers where (`placed`), with its terms as SeqDEX's relay serves them (`placed.relay`) |
| `offboard --asset A --amount N (--address ADDR \| --script HEX) [--fee-asset A] [--max-fee-ppm N] [--quote \| --shown QUOTE]` | Pays an address on the chain from the wallet's leaves through the operator's next round (see Paying an address on the chain): with `--quote`, only says what it would cost (the coins, the fee and its parts, the change); with `--shown` (that answer, as JSON) it goes ahead only on that very fee and those coins. Answers the offboard, named by its participation, and `round_within_seconds` |
| `offboards` | Every offboard the wallet asked for, as the chain shows it now, asking the node only: `waiting`, `in_round`, `unlocking`, `paid` (with the unlock's `txid` and whether it is `final`), `reclaimed` or `not_made` |
| `orders` | Every order the wallet placed, as the chain shows it now, asking the node only: its state (`waiting` for its round, `in_round`, `unlocking`, `resting`, `filled`, `refunded`, `not_placed`), where it rests and what it holds there, its terms (`relay`, with the outpoint, while it rests) and the unsigned offer for SeqDEX's relay (`offer`, see Listing the order on SeqDEX's relay), each fill with what it credited, the credits unspent at its credit program, and when its REFUND opens (`refund_from`) |
| `order fill ORDER [--amount N] [--max-fee-ppm N] [--quote \| --shown FILL]` | `take` (see Taking an on-chain order), by the name an order's side goes by |
| `order rest --sell A --amount N --for B --rate-num N --rate-den D [--min-lot N] (--expires T \| --expires-in-hours H) [--max-fee-ppm N] [--quote \| --shown QUOTE]` | Rests an order in the tree as a leaf of its own (see Resting an order in the tree): with `--quote`, only says what it would cost; with `--shown` it is rested only on that fee and those coins. Answers the participation that rests it and `landed_pays`, the script a landed order's fills pay; `sync` publishes it once its round is final |
| `order resting [ORDER…]` | The wallet's resting orders as the operator shows them (state, coin, what is left, each fill) with the credits the wallet holds of each, and any other resting orders named |
| `order fill-resting ORDER [--amount N] [--quote \| --shown Q]` | Fills another maker's resting order in the tree: what is filled, the price paid, the fill's fee and the change, and the coins it makes the wallet's; `--quote` only says so and the coin it rests at, `--shown` fills only as quoted. A coin given up that rests on a lowest node with RECLAIM-D carries the delegation of its release to every output of the fill |
| `order cancel-resting ORDER [--quote \| --shown Q]` | Cancels a resting order of the wallet's: what rests comes back to a leaf of its own; `--quote` only says what comes back and the fee, `--shown` cancels only as quoted |
| `order refund ORDER [--fee-asset A]` | Takes what order `ORDER` holds where it rests home by its REFUND, once the chain's median time has passed its expiry, to an address of the wallet's; the fee from the order's own value where the node takes its asset for fees, else from an on-chain coin in `A` |
| `distribute LIST --asset A [--return ADDRESS] [--quote \| --shown FEE]` | Pays the holders of `LIST` (a file or `-`, a line `KEY AMOUNT` each) in one round (see Paying many holders in one round): with `--quote`, only says what it would cost (the operator's fee, the coins it gives up, whether the wallet first pays itself a coin of exactly the claims and the fee), signing and asking nothing; with `--shown`, goes ahead only on that very fee. Refused before anything is signed, with `--quote` too: a key named twice, a claim below the operator's smallest leaf, a key the text does not name (a P2WPKH address), claims and a fee beyond what the wallet's live coins of the asset hold; without `--quote`, a fee that changed since it was shown |
| `distributions` | Every distribution the wallet made, as the operator shows it: its state, round, deadline and expiry, each claim's key, claim key, value, leaf and state (`pending`, `open`, `claimed`, `returned`), and each payment of what no holder took up back to the return script, with its state |
| `claims [--scan N]` | The claims paid to the wallet, found by asking the operator under its OpenAMP account key and each address key: each claim's distribution, the key it was named under and what that key is (`named_as`: `address`, with the `address`, or `openamp`), value, state, deadline, and the coin the wallet holds of it |
| `claim [CLAIM]… [--scan N]` | Takes up the open claims named (`DISTRIBUTION:INDEX` or a leaf id), or every one: each checked, its authorisations handed over, kept as a coin, and paid out of round to a fresh leaf of the wallet's own; a claim not open says its state |
| `plan [LEAF]… [--expiries N] [--quote] [--max-fee-ppm N]` | Pre-signs an offline-refresh plan for each coin named (every live coin of a round that no plan names when none is), one step per expiry the wallet will be away for (1 to 6, 2 by default), quoted by the operator, signed and handed over: each step's leaf under a key from the mnemonic, the refund halves that pay the wallet the step's value at a fresh address of its own, the attestation, the key proofs and their bindings to the mailbox key. A step that costs anything is refused before anything is signed unless `--max-fee-ppm` raises the bound for this command. Each plan answers `covered_until` and `sync_by`; one the operator refused answers its `error`. `--quote` answers what each plan would cost and those dates, signing and keeping nothing (see Refreshing while the wallet stays closed) |
| `owed` | What the operator owes the wallet for coins its sweeps took (see Swept coins): each coin, its value, the late-refresh fee, what is owed, the sweep, its state (`owed`, `claimed`, `repaid`, `withdrawn`) and its repayment participation |
| `plans` | Every plan the wallet made or restored: its coin, its state, each step's value, fee, state and leaf once taken up, `covered_until` and `sync_by`, and the operator's reason for a plan it stopped |
| `plan-cancel PLAN` | Cancels the steps of plan `PLAN` that have not started, signed with the mailbox key; refused while a step is running. Every coin the plan named stays out of out-of-round payments until it is refreshed in a round |
| `plan-release COIN… [--max-fee-ppm N]` | Gives up each named coin, the current coin of an open or stopped plan, in the next round for a leaf of the wallet's own that no plan names; the plan ends once the round is final and the forfeit handed over, and stands should the round never complete. The new leaf is paid out of round like any coin |
| `care [--scan N] [--expiries N] [--max-fee-ppm N] [--plan-within S] [--channels]` | With `--channels`, first reads every channel, folds its credit and opens one in each asset the operator makes them of (see Channel leaves; under `channels`). Takes up every open claim, cancels each plan whose coin has moved, and plans each coin whose first step could run within ten days (a coin of no round is refreshed in a round first; a coin of a supervised asset is left to `sync`'s refresh and counted under `supervised`); what a wallet does by itself at a sync |
| `swap offer --give-asset A --give N --want-asset B --want M` | Offers one asset for another in one reassignment (`arca-offer:…`), holding the coins it gives and signing nothing; answers what the maker gives, gets and pays (the reassignment's margin and its coins' checkpoint margins, in the asset it gives) |
| `swap accept OFFER [--accept-near-deadline]` | Checks the maker's coins as a receiver would, adds the wallet's side and signs it (`arca-accept:…`). Every coin the swap makes rests on every coin it spends, so the coins the wallet gets carry the earliest dates among them (a batch's first expiry, a board's service expiry); they are shown before anything is signed, and the swap is refused when their exit deadline is less than two days away unless `--accept-near-deadline` is passed |
| `swap complete ACCEPT [--accept-near-deadline]`, `swap cancel ID` | The maker checks its outputs are all there, signs and has the server co-sign; the coins it gets rest on every coin the swap spends, the taker's included, so they carry the earliest dates among them, which are shown, and the swap is refused when their exit deadline is less than two days away unless `--accept-near-deadline` is passed. Or a swap is given up. An offer has nothing signed in it, and its coins are freed. An acceptance does: the maker holds the taker's signatures, so the taker's coins are spent to a fresh leaf of the wallet's own, after which the acceptance can never complete; if that cannot be done, the answer says the acceptance still stands |
| `btc-swap offer --give btc\|asset --asset A --atoms N --sats S [--lapse-seconds L]` | Offers a swap of native BTC for an asset with another wallet of the operator (see Swapping BTC for an asset); giving the asset, makes the Bitcoin invoice the taker pays. The offer's text and what the wallet gives and gets, with every fee; nothing locked |
| `btc-swap read OFFER`, `btc-swap take OFFER`, `btc-swap complete TAKE` | What taking an offer gives and gets, with every fee; the take (asking the operator to receive under the offer's hash, or making the Bitcoin invoice), its text for the maker; the maker's completion |
| `btc-swap follow [SWAP] [--wait S] [--claim-slice C]` | Moves the wallet's swaps on, running Bark as each needs (lock, claim, payment, claim of the leaf), for `S` seconds; one pass when 0 |
| `btc-swap list`, `btc-swap cancel SWAP` | Every swap with its state and log, and the legs a restore found; cancels a swap the wallet has locked nothing of |
| `refusals` | Every refusal the wallet made, with its reason |
| `bitcoin create (--testnet4 \| --mainnet \| --signet \| --mutinynet \| --regtest) --ark URL (--bitcoind URL (--bitcoind-cookie F \| --bitcoind-user U) \| --esplora URL) [--birthday-height H]` | Makes the wallet's Bitcoin ark wallet from its own mnemonic, through Bark's daemon (see The Bitcoin side): the network, the ark, the chain source (no password), the height it scans from and what the ark's server says of itself |
| `bitcoin [--] ARGS…` | Runs Bark's `bark` with `--datadir <datadir>/bitcoin` and the arguments given: the wallet's Bitcoin side. Put `--` before an argument `arca` would read itself, such as `--help` |

A coin's states: `pending` (what it rests on is not final), `live`, `offered`
(held for a swap), `sending` (in a transfer the server has not answered),
`given` (in a participation, no forfeit signed), `forfeited` (a forfeit of it
signed, the preimage not in hand), `paying` (the `htlc-1` leaf of a payment
over Lightning the operator has not decided), `receiving` (the `htlc-1` leaf
of a payment received over Lightning, not yet claimed), `spent`, `exiting`,
`exited` and `lost`.
`coins` and `balance` show a live coin that rests on a reassignment, one
received out of round and not yet refreshed into a round, as
`operator-confirmed`: it relies on the operator and its sender not colluding,
which a round removes.

### An example

    arca --datadir ~/.arca create --server https://example.org/arca \
      --node-url http://127.0.0.1:<rpc port>/ --node-cookie <node datadir>/.cookie
    arca address                                  # pay it on-chain
    arca board <asset> 2000000                    # spendable once final
    arca sync
    arca receive                                  # on the receiving wallet
    arca send arca:… --amount 600000 --asset <asset>
    arca mailbox                                  # on the receiving wallet
    arca participate && arca sync                 # refresh into the next round

## Testing

`tests/arca_scenarios.rs` runs `arca` as a user runs it against a whole Arca
server (`arca-signer` in its own process, with `arca-keeper` processes where
a test runs keepers, `Server::start` with its tasks, its
watcher and its HTTP listener) on an anchored proof-of-stake regtest chain, its wallet
paid in an issued asset and never the policy asset. Two wallets are created
and board, a board is credited once final; one pays the other out of round,
the receiver validates the coin from its mailbox; a wallet refreshes through a
round; the two swap two assets in one reassignment; a rollback
(`invalidateblock`) makes the re-check un-credit and then credit again every
coin on the round; and a coin is exited from its record alone, with the server
stopped, through its unroll, its checkpoints, its reassignment and its claim,
a fee coin the wallet chooses (the one asset it holds that the node takes)
paying where its asset is not accepted for fees. A second test puts
a proxy between a wallet and the server that rewrites the published tree (a
leaf's value, the last expiry, a clock running backwards, a node listed one
atom more, a leaf named by another id, a preimage that does not open its
leaf): the wallet refuses
each before it signs anything, and completes once the tree is honest; a
second refresh then gives up that batch leaf and releases its lowest node for
the new round. Every
refusal is asserted by its reason.

`tests/arca_accumulator.rs` runs the same way, its operator building
accumulator batches (`[batches] accumulator_exit_rate_ppm`): six wallets
refresh in one round into one accumulator batch, each holding its leaf with
one exit authorisation; one pays another out of round from its leaf; a
wallet restored from one holder's mnemonic finds its leaf; one
takes its leaf out (the exit, the entry, the claim), its exit and entry
mined in a block anchored to a parent block that is then orphaned, and goes
on once they are back; another's exit, by the authorisation it signed before,
spends the batch output where the first left it; one refreshes its leaf in
a round of its own; the payment is taken out
through the payer's leaf, its checkpoint and its reassignment; and the last
holder, away past the expiry and the notice, finds its coin `lost` to the
operator's sweep of the batch output where the last exit left it. A second
test makes an offline-refresh plan from a leaf of an accumulator batch: its
first step runs in the leaf's free window, and the holder, back, takes up the
step's leaf.

`tests/arca_channel_route.rs` runs the same way: `care --channels` opens a
channel in two wallets, half of each one's leaves in it and half kept beside
it, and opens no second one; payments to a channel code and to a receive
request go over the channels, folding credit in the payer's state; a request
of a wallet holding no channel is paid to its leaf, a code is never paid to a
leaf, and a payment beyond the receiver's channel is refused there with
nothing standing (a code's refusal names its address) and paid to a
request's leaf instead; `care` folds what a channel was paid; and `exit` of a
channel coin runs the channel's exit.

`tests/arca_channel.rs` runs the same way: two wallets open channel leaves
in one round, the operator funding its side of each; they pay each other,
each payment final at once with no round between, the refusals worded as the
wallet words them (more than its side, more than the receiver can take, into
itself, a channel given up); one, offline while paid, reads its credit on
return and folds it; one closes into a round for a leaf of its side; the
other closes on the chain alone, its latest state published, settled after
the exit delay, its credit claimed and its side swept home.

`tests/arca_release_delegation.rs` runs the same way against a server whose
batches carry RECLAIM-D: two wallets' leaves share a lowest node, one pays a
third wallet out of round (its `send` signing the delegation of the coin's
release to every output), the three refresh and release (the payer's change
and the payee as holders of coins a reassignment made), and the watcher
reclaims the node by RECLAIM-D on the chain. A swap of X for Y delegates both
sides (the taker's delegation carried in its acceptance); the taker is then
restored from its mnemonic alone, and once both refresh, the X node and the Y
node each come back by RECLAIM-D. A payment over Lightning from such a coin
carries its delegation too (run where `LIGHTNINGD_EXEC` names SeqLN's
`lightningd`). A payee that takes its whole coin off the tree by an offboard
releases the node through the offboard, and the node comes back the same way.
Once the Lightning payment is paid, the sender's `sync` releases the node its
`htlc-1` leaf rests on, and after the change refreshes the node comes back.
A resting order filled in the tree: the taker's `order fill-resting`
delegates its coin, the maker's next `sync` (taking up its credit and the
order resting again) delegates the order's coin, once; a second fill of the
rest and the maker's cancel of what then rests carry no delegation, since
the order resting again keeps the order's key, which has delegated; both
refresh, and neither node comes back by RECLAIM-D before its expiry.

`tests/arca_fills.rs` runs the same way: two orders made with SeqDEX's fill
covenant (their scripts derived by SeqDEX's own `seqob-covenant` when
`SEQOB_COVENANT_EXEC` names it) sell one asset for another; two wallets take
them with `arca take`, one paying itself a coin of the price and the fee
first, hand over their forfeits at `sync` once the operator's round is built,
and hold their leaves once it is final, the makers credited on the chain at
`2k`; the part of the first order left resting is taken again from its new
outpoint in a round where it sits at input 1; and each refusal (an order not
final, a fill leaving less than a lot, a fee over the bound, a maker's key
path, terms not the order's, an order other takes already fill whole, an order spent) is
printed as the wallet words it.

`tests/arca_shared_fills.rs` runs the same way: a sale-shaped order (Y for
X, by lots of 10,000, credited to a taproot treasury) stands at input 1 of a
round behind another order, ten wallets take parts of it, each sharing it,
and one spend of it serves all ten, the treasury credited at `2k` and the
rest resting at `2k+1`; a take below the lot is refused by the wallet; the
round is mined and its Bitcoin anchor orphaned, and it leaves the chain and
comes back; ten more takes of what rests, one wallet never syncing, are
dropped past the window and the nine others served in the round after it.
When `ARCA_TEST_OBSERVER` names a program, it is run at each step with the
step's name as its argument and the step's facts as JSON on its standard
input, so a launchpad's ledger or an order book can follow the same rounds
and check what it reads elsewhere; at the step `order` it may answer the
order as it serves it, and the wallets take that.

`tests/arca_orders.rs` runs the same way: a maker that holds only leaves of
X places an order selling them for Y with `arca order place`, each refusal
printed (an Arca script of its own as the credit program, a height as the
expiry, an expiry within the operator's margin, a price the relay cannot
list, a fee over the bound, more than it holds), the fee quoted and shown, and
waits while the operator's round runs; the order rests at the unlock's output
0 under SeqDEX's own script holding exactly its amount, final. Two wallets
holding Y fill it in part with `arca take`, one round after the other, each
crediting the maker at output 0 and resting the rest at output 1 under the
same script; with `SEQOB_RELAY_EXEC` and `SEQOB_RELAYCLI_EXEC` naming
SeqDEX's `seqobd` and `seqob-relaycli`, the order is posted to a relay
watching the node with `seqob-relaycli post` from the offer the wallet hands
out, and each taker reads it from the relay's book, the second at the
outpoint the relay moved it to. A wallet made from the maker's mnemonic finds the coin given up
spent and the credits at the order key. The maker reads both fills with `arca
orders`, boards its credits from the order key, and its REFUND is refused by
the wallet and by the node before the expiry and mined after it. A second
test runs an operator whose watcher never unlocks the order: the maker's
`sync` unlocks it itself once the ten minutes have passed.

`tests/arca_resting.rs` runs the same way: a maker that holds only leaves of
X rests an order selling 1,000,000 X for Y with `arca order rest`, each
refusal printed (a height as the expiry, an expiry within the operator's
margin, more than it holds, one asset for itself, an amount below the lot),
the fee quoted and shown; its `sync` publishes the order once the round is
final. Two wallets holding leaves of Y fill it in part with `arca order
fill-resting` (each refusal printed first: below the lot, leaving less than a
lot resting, an order not published), each holding its leaf of X; the second
was quoted before the first filled, so its fill as shown is refused
`order_moved` and made again from a new quote at the coin the order rests at. The maker's
one `sync` on return takes up both credits and what rests; `arca order
resting` shows both fills. It cancels what rests, as quoted, and a fill after
is refused.
A second maker's order is brought on with `arca exit`, lands after the exit
delay as SeqDEX's order, and a taker on the chain fills it with no signature.

`tests/arca_owed.rs` runs a swept coin with the `arca` binary: A boards X
under an operator charging a refresh fee of 5,000 parts per million,
refreshes it into a round leaf and is lost; the batch is swept with A's coin
in it, and the server owes A the coin less that fee. A wallet restored from
A's mnemonic claims it at its first sync and counts it as `returning`; that
wallet is lost too, a third restored from the mnemonic takes the claim up as
its own, and once the repayment's round is final its sync holds a new coin of
exactly the coin's value less the fee, nothing returning any more.

`tests/arca_claims.rs` runs the same way: a payer boards its X and pays 20
holders in one round with `arca distribute` (the wallet first paying itself a
coin of exactly the claims), eight of them wallets that exist and handed out
an address, whose key it names, and twelve that exist only as mnemonics,
named by the key of their first address as an x-only key, a compressed public
key or the key's taproot address. Fourteen take their claims up with `arca
claims` and `arca claim`, the mnemonic ones from wallets created after the
round; each claimed coin is refreshed by its holder's `sync` in its free
window. After the claim batch's expiry, release, notice and sweep, the
operator pays the six claims nobody took up back to the payer's return
address, exactly, and every holder that claimed still holds its coin; a
wallet made later from an unclaimed holder's mnemonic finds its claim
returned. Each refusal (a key named twice, a claim below the smallest leaf,
a P2WPKH address in place of a key, a fee that changed since it was shown) is
asserted by its reason.

`tests/arca_offline_refresh.rs` runs the same way: a holder pre-signs a plan
of two steps with `arca plan` and its wallet stays closed across two expiries.
The operator applies both steps in the coin's free window, releasing and
sweeping each old batch after it, and the holder comes back to its value live
in the second step's leaf, the coins it gave up spent, and pays no coin a plan
names out of round. An operator stopped after step 1 and back past that coin's
exit deadline runs step 2 late, its batch never released meanwhile, and a
wallet restored from the mnemonic alone after the absence holds the second
step's leaf. An operator stopped for good after step 1 sweeps nothing, and the
holder, back, takes home the coin the plan started from at its whole value. A
plan stopped because a step can never run holds that coin's batch unreleased
past its expiry until the holder, back, cancels the plan and takes the coin
home. An operator whose signer is stopped builds its rounds and runs the steps,
and the holder, back, cannot witness the signer's record, takes no coin from
it, and takes home the coin the plan started from, which no refund answers.
A step the holder took up whose round an anchor-driven reorganisation then
removes for good (its parent block orphaned, the operator's input taken by
another transaction, final) did not happen: the wallet's own re-check holds
the coin again and the step's leaf lost, `sync` cancels the stopped plan, and
the coin is refreshed in a round, its whole value live. When the parent chain
brings that round back, final, the re-check holds the step's leaf again and
the coin spent again, the value counted once. The server's own tests (`server/tests/plans.rs`) run a step whose round is
replaced, and the refunds' scripts with each negative mined into a block are
in `covenant/tests/plan_refund.rs`.

`tests/arca_restore.rs` runs the same way. A wallet holds a leaf of a batch,
a board, its change from a payment out of round, a payment to it not yet
read, a board given up in a refresh whose forfeit is signed and not
co-signed (the keeper down), a board in a block not yet final, and coins it
spent in a payment and a refresh; its device is lost, and a wallet created
from its mnemonic alone restores every one of them and holds no other: after a
sync each, its `coins` (every field of every coin), `balance` and schedule are
the lost wallet's, but for the hold for requests it cannot know, which
`forget-request restored` ends. The refresh then completes in both, and with
the server stopped the restored wallet exits its batch leaf from the published
tree, its authorisations signed again from the mnemonic. A second test
restores a wallet whose board was registered without the binding, as an
older wallet registered it: a restore finds nothing until the wallet's next
`sync` binds it, and then finds the board. A third restores a wallet through a
proxy that lies one way at a time, each refused with its reason and nothing
credited on it: a payment served without its record and kept from the
mailbox (not recovered); a leaf of a batch not served (taken from the
published tree with the preimage published there, and, with the tree and the
forfeit step holding the preimage back, not recovered, its board held under
its forfeit); a tree listing its batch output one atom more (the leaf
refused); another wallet's board served to the mailbox key (refused as a leaf
of another key); the board a payment spent served live and given up nowhere
(held spent, by the transfer the wallet's change rests on); and every keeper
acknowledgement stripped, or no keeper named while a keeper's
acknowledgements are shown (nothing restored). A fourth restores two wallets
past their batch leaves' expiry: before the operator's sweep, the leaf is
taken, checked as of its expiry, and brought home at once; once the sweep of
the other's batch is final, that leaf is refused, the sweep named, and the
board given up for it is spent.

`tests/arca_assets.rs` runs the same way, a wallet holding X (listed for
fees) and Y (not listed). Its coins of both are refreshed in one
participation per asset, each in its asset's own round, and each new leaf
rests on its own round. With X charging 5,000 millionths of a coin and Y
1,000 and 400 atoms a coin, `participate` prices each coin by its asset's
schedule: a refresh of every coin is refused before anything is signed for the
coin of Y the fixed part takes past the wallet's bound; X's is paid, printed
first; Y's is paid with the bound raised for the command; and each new leaf
holds its coin less its own asset's fee.

Its third test is the several-asset proof, end to end. X is priced by the
node's own rate and Y by the operator's file, with a fixed part of a refresh
set as a value at Y's rate; Z is issued and not served. Two wallets, each
holding X and Y, board, pay each other, refresh (a round of X and a round of
Y, both wallets in each, built in one pass), swap X for Y, and refresh again
while Y's rate is stale: a board of Y and a participation in Y stand, X's
round runs alone, and once the rate is fresh `sync` posts both again and Y's
round runs. Each then takes a coin of Y home, its exit's fees in X, named by
one wallet and chosen by the other. After every step each wallet holds, in
Arca and on the chain, in both assets, exactly what the books say by what
each command reported (fees, margins, the reserve atoms an exit takes home),
and `balance`'s headline is the total at the node's rates with Y set apart.
A board, a request, a payment and a swap in Z are each refused, naming it.

`tests/arca_lightning.rs` runs the same way, with SeqLN nodes beside the
server (`LIGHTNINGD_EXEC`; without it the scenario says it is skipped): the
operator's node in X and in Y, each with a channel to a payee. A wallet
holding a leaf in X and one in Y pays an invoice in X from X and one in Y
from Y, each paid at the payee's node with the preimage in the wallet's hands,
and in each asset the wallet holds exactly the amount, the operator's fee and
the transfer's margins less, while the operator's channel paid the amount and
the payee's gained it. Asked to pay Y's invoice from X, the wallet refuses
before anything is signed and nothing moves; an invoice paid already is
refused; and a payment to an invoice the payee dropped fails, its leaf back
in the wallet less only the margins. The same wallet then receives in X and
in Y: its invoice paid by the payer's node and held, the leaf made by the
asset's next round and claimed by `sync` with the preimage, the payment
settled at the payer's node only then; in each asset the wallet holds the
amount less the fee and the claim's margins, and a fee above the wallet's
bound is refused before anything is asked.

`tests/arca_lightning_hash.rs` runs the same way, with the operator's SeqLN
node in X: a receiver asks under hashes whose preimages it does not hold, and
a payer of the same operator pays each invoice with a leaf timing out when it
says, the payment held inside the operator (`held_by: send`, the receiver's
leaf timing out `internal_gap_seconds` before the payer's). Refused before
anything is signed or asked: a timeout below the operator's window and one
above it, a BTC invoice under a hash, a second receive under the same hash,
a preimage of another hash, one for a hash the wallet receives nothing
under. Each leaf is held apart, `awaiting_preimage`, counted in no row and
no total, and `exit` refuses it. One is claimed once its preimage is handed
to the wallet, the payer's payment then `paid` with it; one is held the same
way by a wallet restored from the mnemonic and claimed once the payer posts
the preimage to the operator; one is taken home on the chain by its claim
with the preimage handed over, which the operator reads there and decides
the payer's payment `paid`; and one whose preimage never comes is failed back
past the time to claim it, the payer's leaf co-signed back to it and the
receiver's receive `failed`, nothing of it ever counted.

`tests/arca_program_commands.rs` runs the same way, for a program that runs
`arca` for its user: a wallet restored with its mnemonic read from the standard
input (`--mnemonic-file -`), given as a socket as Node.js gives it, has the
mailbox key and the board of the wallet it restores, and a mnemonic file that
cannot be read makes no wallet;
`quote` hands nothing over; `participate --shown` with a fee other than the
one shown is refused before anything is signed, the coin still live, and with
the very fees shown completes in a round; `schedule` names the board's free
window as the next sync.

`tests/arca_bitcoin_side.rs` checks the Bitcoin side at its boundary, Bark
replaced by a stand-in that records what it is asked: with no Bitcoin ark
wallet, a Bitcoin invoice, a receive in BTC and a claim are refused with the
reason and Bark is not run; otherwise a payment is `lightning pay invoice
INVOICE --wait` then `lightning pay status INVOICE --no-sync`, a receive
`lightning invoice "1000 sats" --description …`, a claim `lightning claim
INVOICE --wait` then `lightning receive status INVOICE --no-sync`, and BTC's
row counts Bark's ark balance and its on-chain wallet; a Bitcoin invoice with
a Sequentia asset named is refused, nothing paid or asked on the Sequentia
side; and an operator that names no Bitcoin ark changes nothing of it.

`tests/arca_bitcoin_ark.rs` runs the Bitcoin side against a real Bitcoin ark
on regtest, `contrib/bitcoin-ark-regtest/` (Bark's server at the release the
wallet bundles, its Lightning gateway with the hold plugin, and a peer node):
`bitcoin create` from the wallet's own mnemonic, and refused without one or a
second time; boards under and over the server's bounds refused with nothing
spent, then a board; a Lightning payment out, its preimage the payee's; a
payment in, claimed as the payer pays; a claim with no payment `waiting`, then
claimed; blocks found between a payment's arrival and the claim, counted from
the held payment's expiry, give `reissued`, the first payment failed back and
the fresh invoice paid and claimed; a second wallet restored from the same
mnemonic holds the same; a refresh; and an exit alone, its leaves claimed to
the on-chain wallet. It needs the harness running (`ARCA_TEST_BITCOIN_ARK`,
the harness script with its environment) and the patched `bark` and `barkd`
(`ARCA_BARK_EXEC`, `ARCA_BARKD_EXEC`), and is skipped without them.

`tests/arca_btc_swap.rs` runs the swap of BTC for an asset (`btc-swap`) with
both: a whole Arca server with its SeqLN node in X (`LIGHTNINGD_EXEC`) and the
Bitcoin ark on regtest (`ARCA_TEST_BITCOIN_ARK`, `ARCA_BARK_EXEC`,
`ARCA_BARKD_EXEC`), two dual-chain wallets each with its Bitcoin ark wallet
made from its own mnemonic, run one test at a time since they share the ark.
A swap completes in each direction, the maker giving the asset and then the
BTC, each side seeing its fees before anything is locked, and the books hold
to the atom and the satoshi: P gives the atoms, the operator's fee and the
transfer's margins and gets the satoshis less Bark's receive fee; Q gives the
satoshis and Bark's send fee and gets the atoms less the fee and its claim's
margins. Each row of an abandoned swap is forced, and nobody ends holding
both legs: an offer never taken lapses and its Bark invoice is cancelled; one
taken and never completed lapses at the operator, and a late completion locks
nothing; P's lock with Q's leaf never coming, with Q never paying, and with
Q's payment failed back by Bark because P never claims, each comes back to P
once its time is over, Q's BTC coming back in full; and a P that claims the
BTC with Bark alone and posts nothing still loses its lock to the operator,
which reads the preimage from Q's claim. The Sequentia leg's round is rolled
back through its Bitcoin anchor before the swap (Q pays nothing while it is
out of the chain or not final, then pays once it is back, the same
transaction) and after it, three Bitcoin blocks deep, past finality (the round
returns with the same txid and every coin of the swap is the same coin
again). A Q killed while Bark pays reads the payment back when it starts
again and claims; a Q restored from the mnemonic after it paid claims its leaf
with the preimage P posted; a P restored before it claimed cannot claim, as
Bark kept the preimage only on the lost device, and Q's payment comes back to
Q and P's lock to the restored P.

`tests/arca_quotes.rs` runs the same way: a board's quote and an exit's quote
(`--quote`, and the library's `board_quote` and `exit_quote`) sign, ask,
write and broadcast nothing, and `board` and `exit` given a fee other than the
one now (`--shown`, the library's `shown`) are refused, naming the fee now, before
anything is registered or broadcast; given the fee shown, they pay exactly it.

`tests/arca_swap_commands.rs` runs the same way: an in-tree swap through the
library's commands, as a browser or a mobile app runs it. `swap_offer` holds the
maker's coin and answers what it pays; `swap_read` refuses an offer whose coins
do not keep what it gives, and otherwise answers what the taker gives, gets and
pays with nothing signed, held or stored; `swap_accept` given terms other than
those (`shown`) is refused, naming them, before anything is signed; given them,
it signs, and `swap_complete` settles the swap with each side paying exactly what
it was shown. `swap_cancel` frees an offer's coin, and `swaps` lists both.

`tests/arca_lightning_commands.rs` runs the same way, with the operator's SeqLN
node in X (`LIGHTNINGD_EXEC`): a payment under a hash between two wallets of one
operator through the library's commands. `lightning_receive_quote` answers what
the receiver's leaf will hold once claimed, asking the operator nothing;
`lightning_pay_quote` answers what the payment takes in all, signing and keeping
nothing, and `lightning_pay` on other terms than it is refused before anything is
signed. `lightning_receive_ready` answers not ready before the leaf's round, ready
after it, and refuses a wait longer than the leaf's home date allows. The claim
then leaves exactly the quoted amount and the payer's coins fall by exactly the
quoted amount.

`tests/arca_adversity.rs` runs the same way, with a proxy that can rewrite any
answer of the server or any request on its way there, or hold a call unanswered, and with transactions the test
builds itself as the operator or as a sender. Each case is one way an operator
lies, stalls or vanishes, or a sender goes back on a payment, and each ends
with the wallet refusing before it signs anything, or taking its coin on-chain
and holding it there, with the reason shown:

- a refresh whose status hides a new leaf, or names another unlock hash;
- a round rolled back and replaced by one that fails check 1, which the
  wallet's re-check exits from at once;
- a coin given to a participation that expires, or that the operator never
  runs;
- a coin in flight when the operator vanishes;
- a preimage withheld and a participation called void after its forfeit, the
  preimage then read from the operator's claim on the chain;
- a lost round, which refreshed two boards and a leaf of an
  earlier round, both boards' forfeits published: every participation is
  `void`, each board's for its published forfeit and the leaf's because the
  signer co-signed its forfeit, the operator's reason shown, the wallet
  waiting on none of them, and the leaf taken on the chain at once; the board whose forfeit someone sent again is refunded after
  its delay, `exited` once the refund is final, and the other, its forfeit
  not on the chain, is exited at once (its conversion's fee paid with a coin
  of the wallet's it chooses) and claimed;
- a lost round that returns: a leaf refreshed in round R, which goes out of
  the chain with its Bitcoin parent block while another transaction of the
  operator's takes R's input; the participation, its forfeit for R co-signed,
  is `void` and nothing runs again; then the parent chain takes that
  transaction out and R confirms in its place, and the wallet holds its leaf
  of R, live, one leaf for the coin it gave up;
- a coin paid out of a lost round's leaf: B pays M out of its leaf of a round
  that is then lost; the server holds M's coin `lost` and voids B's re-run,
  saying B's leaf of the round was paid on; M's wallet shows the coin `lost`,
  resting on that round; when the round returns, M's coin is live again, at
  the server and in M's wallet, and B's participation is back in the round;
- a forfeit's refund sent once its delay has run and replaced in the mempool
  by the operator's claim, which confirms: the wallet reads the preimage from
  the claim and holds its new leaf, and the coin given up is spent; a refund
  that confirms, which decides the coin only once it is final; and a final
  refund taken out by an anchor-driven rollback (the Bitcoin parent block it
  is anchored to orphaned) and replaced by the claim, after which the wallet
  holds its new leaf; and a final claim taken out by a rollback after the
  wallet read the preimage from it, the refund delay long run: the wallet
  sends no refund, keeps its new leaf, and the claim sent again is taken;
- that claim and its round both taken out, the operator gone, and only the
  forfeit sent again: the wallet sends the round again from its own copy
  and sends no refund; and a wallet away until the new leaf's batch has
  expired refunds the forfeit;
- a refresh fee of half of every coin, and one inside a coin's free window,
  refused by `sync`'s own refresh there as by `participate`;
- wallets whose own nodes value an asset 10% or 25% above or 10% below the
  operator's, do not accept it, or accept one the operator's node does not,
  each sending with the margins the operator publishes; and an operator
  floor that would take margins above the wallet's bound, refused before
  anything is signed;
- a sender converting the board it paid from, answered at once by the
  receiver, on its own, with the operator stopped;
- an operator whose database and signer's record are rolled back together
  to a backup, after which the server starts: the wallet that was shown a
  later entry stops the signer at its next command, takes its coin of the
  lost payment on the chain and refuses to go on, saying why; a head whose
  hash an operator altered is refused, its signature no longer the
  signer's; a round's published tree carries the record's latest entry when
  the round was built, signed;
- the same rollback seen by a receiver that only syncs: its `sync` hands
  back the head of the payment the record lost, which stops the signer, and
  takes that coin on the chain at once; every other wallet then learns the
  signer is stopped, and the older copy of the sender's wallet, shown the
  record as it was in a witness answer the signer did not make, finds the
  spent coin's lineage on the chain and signs nothing, and shown the signer's
  own answer goes no further, on the stopped signer's proof; and the same rollback
  where that older copy spends the coin again before any wallet witnesses,
  and another payment takes the record past every entry the receiver holds:
  the receiver's next `sync` finds another hash at its own highest entry,
  stops the signer and takes its coin on the chain first, and the second
  spend's coin cannot follow, its exit naming the coin spent twice;
- the witness rewritten for one wallet on its way, with nothing rolled back:
  another running hash at its highest entry, an older head the signer
  signed as the latest and as the record's end, a whole earlier answer
  replayed, a stop without proof and with a "proof" the record holds, and an
  older signed head in `info`: each is an unreachable server, the wallet
  exits nothing, takes no coin from its mailbox, refuses nothing for good,
  and goes on once the answers are honest; the signer is never stopped;
- the same restore with a keeper running, on another machine, and the
  snapshot's start script, which lost `--keeper`: the signer refuses to start,
  naming the record's keeper that has no address, and refuses a keeper of
  another key, naming it; started with its keeper, it
  asks the keeper for its latest head before
  it serves anything, finds it past its record's end and stops; the older
  copy's second spend is never co-signed, the receiver of it gets nothing,
  and the receiver of the lost payment learns of the stop on the signer's own
  proof and takes that coin on the chain; and the same restore with no
  keeper, where the second spend is still co-signed;
- after a stop, everything brought home: a receiver offline across the
  joint rollback comes online, reads the coin it was sent before the
  snapshot, and takes it on the chain at once, ending with it there, less
  its claim's fee; the sender's untouched board is shown with its exit date,
  kept, and taken on the chain by `sync` two days before that date (after a
  stop, three days ahead); and in
  the restore with no keeper, the coin whose second spend reached the chain
  first is shown as lost, with the coin the operator co-signed another spend
  of, and not counted as pending;
- a wallet made before keepers existed shows the keepers it pins on the
  `info` that pins them, and refuses the operator once it shows others;
- an operator with one keeper whose record is compacted and its first line
  edited to name none, the carried hash computed again: the signer starts on
  it without the keeper, the running server's `info` goes on showing the
  keeper it pinned, and a new start of the server against that signer is
  refused, naming both sets;
- a keeper down: a payment is held up with nothing taken, the request
  standing, and completes when the keeper is back; the receiver shows the
  keeper it pinned;
- a proxy stripping the keepers' acknowledgements: the wallet's own payment
  stands and a coin in its mailbox waits, until the answers are whole; the
  coins after it, read again with it, are shown as held, never as taken;
- a rollback note an older wallet kept without the signer's proof: dropped
  at the next witness, saying so, nothing exited, the wallet going on;
- `participations` before and after a release, twice, and with the operator
  gone: the same state, round, coins given and new leaves from the wallet's
  own store;
- a coin the operator cannot refresh: with the signer's proof withheld from
  every witness, and with the server gone (tried again before it is taken
  for unreachable), `sync` and `coins` show each board's dates and say
  nothing is taken before `home_from`, taking nothing weeks ahead, five days
  ahead, or two days ahead; with the operator answering two days ahead, one
  board's refresh is asked for and waits, and a coin whose refresh the
  operator refuses is asked for again, refused, and stays; an hour before
  `home_from`, withheld again, nothing goes; from `home_from`, withheld and
  gone, every coin goes on the chain;
- an operator that has lost its one keeper for good, answering every
  witness and building rounds, co-signing nothing: of two batch leaves and
  a board, two in payments it cannot co-sign and one never touched, and
  a board in an asset the node does not take for fees whose refresh ran in a
  round and was never co-signed (the operator takes that participation's
  forfeits until the board's exit date, so the board stays `forfeited`);
  one `sync` a day in their last three days: nothing at three days, the
  refresh of the coin never touched asked for at two days and run in a round
  nobody co-signs, every coin on the chain at one day, the board
  in the unaccepted asset paid with a fee coin of another, and every claim
  final days before the first expiry, nothing left for the sweep;
- a round that never comes: the refresh asked for at two days waits, the
  coin goes home at one day (the wallet withdrawing), and the operator voids
  the participation at the exit date, no round built; and a wallet that
  syncs once, a day before the exit date of a board and a batch leaf, takes
  both home before their expiry;
- the witness answered `429 rate_limited` three times in the free window,
  the wallet's default patience: tried again, nothing on the chain, both
  boards' refreshes asked for, free, and completed in the next round, and
  the next sync weeks on;
- a coin whose asset the node has delisted for fees: the wallet holding a
  coin of an asset the node takes shows that asset on the coin and exits
  with it; one holding none says so on every listing and when it takes a
  coin in that asset, its exit refused saying the coin cannot come home,
  and exits once it holds one, every fee in that asset;
- past its expiry, a coin whose wallet was away goes on the chain ahead of
  the sweep and comes home; one whose batch the operator has swept is shown
  lost, with the sweep, once that is final;
- holders that sync 25 and 45 hours after `sync` asked for their free
  refresh both complete it, nothing taken on the chain;
- a witness answered `502` for 6.5 s against a patience of 6 s: reached by
  the try a second past the patience, nothing taken for unreachable; a
  participation whose coin goes home not posted again, and once the
  operator releases it completed with the preimage the server publishes; a refused refresh not asked for again an hour on, nor ten
  minutes short of six hours on, the schedule waking six hours after the
  ask, and asked for again ten minutes past it; and a server whose signer is swapped
  under it for one naming other keepers answering every call
  `signer_replaced`;
- a receiver waiting for a payment: its schedule a day ahead at most,
  saying why; paid at that time out of the sender's oldest coin, a day from
  its exit date, it takes the coin home whole; another, away, reads its
  coin past the batch's expiry, before any sweep, and takes it home too; and
  a payment out of a wallet holding an old leaf and a younger board takes
  the board; and a request never paid holds the schedule at a day until it
  lapses 27 days after it was handed out, and no longer the day after;
  paid the day after its lapse, the payment refused before anything is
  signed, the payer's coins as they were; paid on day 26, read at the
  receiver's next scheduled wake; and a request handed out without a lapse
  holding the schedule past 27 days, paid on day 28 and read, and another
  holding it until it is forgotten; and a payment held on its way and sent
  again past the lapse, refused by the server (`request_lapsed`) and the
  payer's coin live again, while one the server recorded before the lapse
  completes and is read;
- a forfeit whose operator's half came ten minutes late, after the wallet
  took its board home in the coin's last day: the server releases the
  participation, the watcher answers the exit with the forfeit, and the
  wallet holds its new leaf, live at the server too, and pays out of it; a
  forfeit held back by a keeper down: with the keeper back before the
  deadline, the participation released and paid out of, and with it down
  past the deadline, the board kept given up, never offered for a payment,
  and brought home whole; and released by the server's pass while the
  wallet was away, the wallet's first sync 25 days after the round, when
  the forfeits' refund delay would end after the new leaf's exit deadline,
  completing it with the published preimage and holding the new leaf, the
  board spent and never taken home;
- a coin paid to a receiver who reads it only after the operator swept its
  batch: refused, naming the sweep, and counted nowhere once the sweep is
  final; kept while the sweep is not final yet, its note naming the sweep,
  its exit refused for it, and `lost` once the sweep is final;
- a coin past its exit date, looked at by a command other than `sync`: taken
  on the chain at once, shown `exiting` and why, and brought home;
- a round lost for good, first seen a day past its leaf's exit date: the
  leaf `lost`, counted nowhere, and the coin given up for it brought home; a
  lost round that returns, and a coin paid out of its leaf, first seen again
  past their expiry, before the sweep: each held again and brought home; and
  a payment's answer lost to a 502 and read again past its input's expiry:
  the request completes and the change comes home;
- a batch leaf's forfeit followed past the leaf's expiry, the operator gone
  before its claim: the refund sent at the first sync past the expiry, final,
  and the operator back finding the output spent; the forfeit claimed by the
  operator and read only two days before the new leaf's expiry: the new leaf
  held and brought home; and a final refund taken out past the expiry by an
  anchor-driven rollback, sent again and final;
- the witness denied (a 503 on the way): `send`, `board`, `participate`, a
  swap's offer and the mailbox are refused before anything reaches the
  operator, and `sync` does only what it does on the chain; once the witness
  answers again, the coin that waited in the mailbox is taken and the
  payment goes through;
- a forfeit's margin bounded from the operator's published floor: a wallet
  whose node values the asset five times higher than the operator's
  completes its refresh;
- a receiver's refresh of two coins paid from a board, which leaves the
  sender's change on the same lineage live off chain (nothing of the lineage
  published, the sender's wallet untouched), every coin showing the board's
  dates and the receiver told so; after the board's expiry the operator
  brings the lineage on the chain and claims both forfeits, and the sender's
  change, on the chain with it, goes into its exit;
- a server named `https://` whose certificate no root vouches for, refused by
  TLS itself, and a plain-HTTP server on another host, refused before anything
  is sent;
- a payment whose answer comes back as a gateway's 502, posted again;
- a payment asked for while the operator's signer is away (it goes after the
  sender's witness, before the server asks it to co-sign: a 503), posted again
  after the board's exit deadline has passed: it completes, and the sender's
  change and the receiver's coin, past their deadline, are each kept and
  taken on the chain at once, a refresh of the receiver's refused; and one
  out of a batch
  leaf, posted again after the batch's exit deadline has passed and the
  node's floor in the asset has fallen a hundredfold: it completes, its
  margins judged as when it was recorded, and the sender's change and the
  receiver's coin are each exited at once, the receiver claiming its coin
  before the batch expires;
- a participation whose answer comes back as a gateway's 502, posted again
  without its key proofs: the server, which holds it, answers with its
  status, the coin stays given up and the participation completes, while a
  participation the server does not hold is refused without them;
- a board whose registration is answered with a 502 after the server took
  it, kept pending and registered again, and one answered with a refusal the
  server never made, followed again once the server reports it credited;
- a coin received while its board is rolled out of the chain, taken once the
  board returns;
- a tree whose reserves are one atom in an asset the wallet's node accepts for
  fees, refused before any forfeit, and the same tree accepted where the node
  does not accept the asset, the fee coin its exit needs stated;
- two payments from one payer, both resting on the payer's first transfer,
  paid on together for their whole value less the margins, which the
  wallet's refusal of the whole sum names; the receiver accepts the coin and
  exits it, its exit building that first transfer once;
- an acceptance of a swap cancelled, after which the maker's completion is
  refused;
- a swap of fresh coins taken with the dates of the coins it gives shown,
  which the coins then carry; and one whose coins reach their exit deadline
  a day and a half later refused, saying so, by the taker and by the maker,
  and taken with `--accept-near-deadline`; and a maker whose own coin is
  fresh, given coins resting on a taker's board a day and a half from its
  exit deadline, refused alike before it signs anything;
- an exit and a forfeit's refund at the specification's delays, on the
  regtest chain's clock, with a wallet made with its defaults: the claim of
  a board's leaf refused by the node an hour before its 36-hour exit delay
  has run and taken after it, and a forfeit the operator published and
  never claimed refunded only once its 48-hour refund delay has run, each
  coin `exited` once final;
- a batch leaf's exit at those delays, the watcher on: its node and entry
  unrolled, its claim refused an hour before the 36-hour exit delay has run
  from the leaf's confirmation and taken after it, `exited` once final; and
  a stale exit of a leaf its holder refreshed, from a copy of the wallet
  taken before the refresh, answered by the operator's forfeit and its claim
  within the hour, long inside the delay, the copy's own claim refused once
  the delay has run;
- the files a fresh wallet writes, readable by their owner alone, the node's
  password in none of the store's, and its balance of one row, 0 BTC; and a
  wallet restored from the mnemonic that finds on-chain coins past the first
  20 unused addresses.

`tests/arca_supervised.rs` runs the same way, with an asset Z issued under
the supervision descriptor (the pause capability allowed), which the operator
serves under the supervised profile once its node lists it, and a signer that
reads freezes from a node of its own. A holder boards Z and refreshes it, and
`supervised-check` reads the round's batch whole (every leaf `landing-1` at
the published allowance, every output explicit) and finds a batch of X not a
supervised one; the holder pays a second holder out of round, both coins
landing at their holders' landing keys. A freeze record then names the first
holder's landing address: `coins` shows its coin frozen, a payment and a
refresh are refused with `frozen`, and a payment to it from the second holder
is co-signed and arrives frozen. `exit` takes its frozen coin home: the claim
pays the landing key, explicitly in Z, all but at most the allowance, every
output explicit; the node shows the landed coin frozen, `balance` counts it
under `sequentia_onchain_frozen`, and the wallet keeps it out of a board. Once
the issuer lifts the freeze, a board spends the landed coin, and once the
lifting is final the holder pays from that board in the tree.

`tests/arca_operator_for_browsers.rs` is not a test that ends: ignored by
default, it starts the scenarios' server and keeps it running for a wallet
outside the process (the wallet built for a browser, `wallet-wasm/`), with a
control address to fund a script, produce and bury blocks, build a round and
move the chain's median time (`ARCA_OPERATOR_CONTROL`, the file's comment
lists the calls). It runs until it is told to stop (`POST /quit`):

    ARCA_OPERATOR_CONTROL=127.0.0.1:18640 cargo test -p arca-cli --test arca_operator_for_browsers -- --ignored --nocapture

With `ARCA_OPERATOR_LIGHTNING` set (and `LIGHTNINGD_EXEC`), it runs on the
chain SeqLN's `sequentia-regtest` network assumes, with a SeqLN node in X that
receives and payments out of the tree timing out four to eight days out, so a
client can run a swap of BTC for an asset against it between wallets with the
specification's 36-hour exit delays. With `ARCA_OPERATOR_BTC_LIGHTNING` set to a
count `n` as well (and `BITCOIND_EXEC`, a Bitcoin Core `bitcoind` with
`bitcoin-cli` beside it), a Bitcoin regtest chain runs beside it with a hub
Lightning node and `n` others, each with a channel of 10,000,000 sat from the
hub, half of it its own: a maker of BTC and the wallets that trade BTC for an
asset under one hash, as the web wallet's user-mode drill runs them. `/state`
names their sockets (`btc_lightning`) and `/btc_mine` mines on Bitcoin.

`tests/arca_digests.rs` checks the wallet's call authentication,
participation id and plan digests against the server's own, and its list
of refusal codes against the server's: the wallet takes every code the server
answers with a 4xx for a refusal (but `rate_limited`, a request to slow down), and no other.

They need `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` (as for the server's tests:
[server/README.md](../server/README.md)) and the signer and keeper binaries,
built beside `arca` or named by `ARCA_SIGNER_EXEC` and `ARCA_KEEPER_EXEC`.
Building the workspace's Bark crates needs `protoc` (`apt install
protobuf-compiler`).

    cargo build -p arca-server --bin arca-signer --bin arca-keeper
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-cli --test arca_scenarios --test arca_adversity -- --nocapture
    cargo test -p arca-wallet --features arca --lib arca::
