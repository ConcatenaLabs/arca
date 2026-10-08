# arca-cli

The command-line wallets of this workspace:

- **`arca`**, the Arca wallet: a dual-chain wallet whose Sequentia side holds
  Arca coins against an Arca server, and whose Bitcoin side is Bark's wallet
  for Bitcoin arks.
- `bark` and `barkd`, Bark's own command-line wallet and daemon for Bitcoin
  arks, which `arca bitcoin …` runs.

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
  address, however often it is run.

The store keeps every owner nonce the wallet has ever drawn, with its key,
written before the key is handed out or signs anything, and never deleted. It
keeps every coin it holds or has held, with its coin record, and refuses a coin
at a salt it has held a coin under. Back the directory up: the mnemonic restores
the keys, but which coins were spent off-chain is in the store and the server.

### What it checks

- **A leaf from a round** is rebuilt from the tree the operator publishes and
  validated against the round transaction under the wallet's policy before the
  wallet signs anything for it. A tree that lists a node, a leaf's id or
  script other than its parts build, or a preimage that does not open its
  leaf's unlock hash, is refused before anything else is looked at. Then: the five checks on the sweep token and its
  clock, the batch output paid exactly once, the notice, a first expiry at
  least 27 days after the median time of the round's block (so a refresh
  completed a day or two after its round, as the operator allows until the
  coin's exit date, takes the same leaf), the exit delay within the wallet's
  bounds, the depth,
  and reserves on every node and on the entry of at least four times the
  node's relay floor in the leaf's asset, so the leaf pays its own way out.
  Where the node does not accept the asset for fees, one atom is the rule (the
  operator's own), and the wallet says, when it gives up a coin for such a
  leaf and again when it takes the leaf, that every exit of it needs a fee coin
  in an accepted asset. Only once the round is final, and only when the operator's status
  shows exactly the leaves the wallet asked for, in order, each validated, all
  under the participation's one unlock hash, and exactly the coins it gave up.
  The forfeit of each coin given up is built from the validated leaf of the
  coin's own asset and its round, and its refund delay must end before the new
  leaves' exit deadline.
- **A coin received out of round** is validated back to every round and board
  it rests on, under the receipt policy: every pair, preimage and
  authorisation, the exit delay of every leaf of its lineage, the depth limit.
  Its key and nonce must be ones the wallet drew and is waiting on (a receive
  request is single use); no leaf or checkpoint of its lineage may be on the
  chain; every board it rests on must be unspent, and before its exit
  deadline. A coin read a day or less from its exit date, or past it, is
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
  certified by the committee and its Bitcoin anchor buried two blocks. A coin
  is spendable only while everything it rests on is final. The wallet asks again
  every time, never remembers: on every start it re-checks every coin against
  the chain, so a rollback un-credits the coins it took out, and credits them
  again when their round or board returns. It reads each round and board from
  the chain, not from what it stored: when another transaction now pays a
  batch output a coin rests on, the checks run again on that one, and a coin
  that fails them on a transaction the chain holds goes into its exit at once.
  A coin resting on a round is as final as that round: one resting on a
  round that is out of the chain while a coin the round spends is spent by
  another transaction that is final is `lost`, its note naming the round, and
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
  server reports it credited. Every participation such a round ran, the
  operator runs again, under the same keys and owner nonces, in a round that
  cannot stand in the chain beside the lost one, and the wallet follows it as
  any participation: it hands over its forfeit for the new round and takes its
  new leaves. One the operator will never take (a coin of it whose forfeit for
  the lost round the operator published, or whose output is spent on the
  chain, or with no coin of the operator's to keep a re-run apart from the
  lost round) is `void`, with the operator's reason shown. A lost round can
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
  final, is shown as lost, with the sweep. A payment the wallet waits for
  is read only by `sync` too, and its sender may have paid with a coin days
  from its exit date. So run `sync` at least once a day while the wallet
  holds a coin off the chain or waits for a payment, whatever `next_sync_at`
  says. A receive request lasts 27 days from when it was handed out (the
  acceptance horizon, `REQUEST_HOLDS`) and carries the median time it lapses
  at (`until`): `send` refuses a request past it before anything is built
  or signed ("the request lapsed at …: ask the receiver for a new one").
  `sync`'s `schedule` says when it must run next (`next_sync_at`), and never
  more than a day ahead while a receive request the wallet handed out is
  unpaid and has not lapsed, saying so (`why`); `receive_requests` lists
  every unpaid request with the median time it was handed out at, `waiting`
  until `lapses_at` and `lapsed` from then (`lapsed_at`), when it no longer
  holds the schedule. A request handed out before requests carried their
  lapse is `waiting` with `lapses_at` null, since its sender may pay it at
  any time: it holds the schedule until it is paid or forgotten
  (`forget-request`). A coin paid to a lapsed or forgotten request is still
  read, by any later `sync`. A program built on the library gets the same
  from `Wallet::sync_schedule`, which it can call on a timer, and runs
  `Wallet::sync` when it says so. A payment spends the coins furthest from
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

The operator's refresh fee is bounded by the wallet, not by what the server
publishes: a fee above 10,000 millionths of a coin, or any fee for a coin in
its free window (the two days before its exit deadline, five days before its
first expiry), is refused before anything is signed, unless the user raises
the bound for that one command (`participate --max-fee-ppm N`). Every fee is
printed, coin by coin, before the wallet signs anything for the refresh.

### Commands

| Command | Does |
|---|---|
| `create --server URL --node-url URL [--node-user U [--node-password-file FILE] \| --node-cookie FILE] [--mnemonic M]` | Creates the wallet: a new mnemonic (or the one given), the node's chain, and the server's operator key, pinned and shown for the user to compare with the key the operator publishes through a channel they trust. `--exit-delay-units` is the exit delay the wallet asks for its own leaves; `--min-exit-delay-units` and `--max-exit-delay-units` bound what it accepts (512-second units; 36 to 48 hours by default) |
| `info` | The wallet's chain, operator, mailbox key and policy, and what the server publishes |
| `address` | A new on-chain address, to pay the wallet's boards and fee coins from |
| `balance` | One row per holding, BTC first and always, 0 included, then each Sequentia asset the wallet holds anything of; and per asset: Arca coins by state (a coin received out of round and not yet refreshed as `operator-confirmed`), on-chain coins, and the Bitcoin side |
| `coins`, `record LEAF` | Every coin held or once held, with its dates (`expiry`, `exit_deadline`) and whether it rests on a board, and, for every coin held off the chain, the dates `sync` keeps (`sync_daily_from`, `refresh_from`, `home_from`, `exit_by`) and the fee coin its exit needs, if any (`exit_fee`); one coin's record |
| `board ASSET AMOUNT [--fee-asset A]` | Brings on-chain coins into Arca. The server registers the board before it is broadcast, so a refused board spends nothing; the coin is spendable once the board transaction is final. Only a refusal marks the board `lost`: when the server's answer is not seen (no answer, a timeout, a 5xx), the server may hold the board and broadcast it itself, so the coin stays `pending` with its transaction and `sync` posts the same registration again |
| `boards` | Where each board stands, by the server and by the chain |
| `receive [--asset A] [--amount N]` | A single-use receive request (`arca:…`): a fresh key and owner nonce, the wallet's mailbox, the exit delay asked for, and the median time it lapses at (`until`, 27 days on) |
| `forget-request OWNER` | Stops waiting for a payment to the unpaid receive request of key `OWNER` (as `sync`'s `schedule.receive_requests` lists it): it lapses now and no longer holds the schedule; a coin paid to it is still read by any later `sync` |
| `send REQUEST [--amount N] [--asset A]` | Pays a receive request out of round, unless it has lapsed: the coins of the asset (those furthest from their exit date first), each into a checkpoint, and the reassignment into the receiver's leaf and the change. The server co-signs and posts the coins to the mailboxes |
| `mailbox` | Reads the mailbox and validates every coin in it; each is kept or refused with its reason, and one refused for a passing reason (what it rests on not on the chain now, during a rollback, or the node not answering) is kept aside as `waiting` and checked again on every read. A coin read again that the wallet holds already is shown apart (`already_held`), never as taken; a second record of such a coin, whose checks all pass, with other checkpoint values (the operator co-signed two checkpoint values for one coin) is kept with the wallet's refusals as evidence and reported, the coin held as it was |
| `participate [--leaf L]… [--not-before T] [--max-fee-ppm N]` (`refresh`) | Gives up the coins named (every live coin when none is) for one new leaf per asset in the next round, each under a fresh key whose own signature proves the wallet holds it, paying the operator's refresh fee in each coin's own asset, within the wallet's bound (`--max-fee-ppm` raises it for this command); each coin's fee is printed before anything is signed |
| `participations` | Every participation the wallet made, from its own store, asking nothing of the operator: where each stands, the round it ran in, whether it was released, the coins it gave up and the new leaves it wanted, with the state of each. `sync` reports a release once; this answers again whenever it is asked |
| `sync` | Re-checks every coin, posts again the board registrations and transfer requests the server never answered, reads the mailbox, moves every participation on (once its round is final, validates the new leaves, signs the forfeits, takes the preimage and releases the old batch leaves' lowest nodes, each release naming the new round's connector asset; one the server released on forfeits the wallet handed over before is completed with the preimage the server publishes with the round's tree, nothing signed again and none of the checks made before signing made again), asks for the refresh of every live coin in its free window, follows on the chain every forfeit whose preimage it does not hold, takes on the chain every coin whose refresh has not completed a day before its exit date, and moves every exit on; it says when it must run next (`schedule`). Run it at least once a day while the wallet holds a coin off the chain or waits for a payment |
| `recheck` | Re-checks every coin against the chain as it is now, starts the exit of any coin whose round or board the chain holds fails the wallet's checks, whose lineage shows on the chain, or that is past its exit date, and reports what changed and whether the tip it last saw was reorganised away |
| `exit LEAF [--fee-asset A]` | Takes a coin on-chain from its record alone, without the server, paying what its own reserves cannot with a fee coin in the asset named or, when none is, one the wallet chooses (see Fees), whether it is live, waiting, held for a swap, given to a participation, under a forfeit whose preimage the wallet does not hold, or in a transfer the server never answered: the unroll and entry of each batch leaf, a board's conversion, each checkpoint and reassignment; then, once the exit delay has run, the claim to one on-chain address of the wallet's. Each run starts from where the chain holds the coin's path now (whichever round pays its batch output, whatever step someone else published), goes as far as the chain allows, and remembers the fee asset; run it again, or `sync`, to go on. The coin is `exited` once its claim is final; until then the wallet follows the claim, and builds it again should it leave the chain. A coin whose path another spend the operator co-signed has cut (a coin it rests on paid twice) is refused, naming that coin and the transaction that took it |
| `swap offer --give-asset A --give N --want-asset B --want M` | Offers one asset for another in one reassignment (`arca-offer:…`); the maker pays its margin, in the asset it gives |
| `swap accept OFFER [--accept-near-deadline]` | Checks the maker's coins as a receiver would, adds the wallet's side and signs it (`arca-accept:…`). Every coin the swap makes rests on every coin it spends, so the coins the wallet gets carry the earliest dates among them (a batch's first expiry, a board's service expiry); they are shown before anything is signed, and the swap is refused when their exit deadline is less than two days away unless `--accept-near-deadline` is passed |
| `swap complete ACCEPT [--accept-near-deadline]`, `swap cancel ID` | The maker checks its outputs are all there, signs and has the server co-sign; the coins it gets rest on every coin the swap spends, the taker's included, so they carry the earliest dates among them, which are shown, and the swap is refused when their exit deadline is less than two days away unless `--accept-near-deadline` is passed. Or a swap is given up. An offer has nothing signed in it, and its coins are freed. An acceptance does: the maker holds the taker's signatures, so the taker's coins are spent to a fresh leaf of the wallet's own, after which the acceptance can never complete; if that cannot be done, the answer says the acceptance still stands |
| `refusals` | Every refusal the wallet made, with its reason |
| `bitcoin [--] ARGS…` | Runs Bark's `bark` with `--datadir <datadir>/bitcoin` and the arguments given: the wallet's Bitcoin side. Put `--` before an argument `arca` would read itself, such as `--help` |

A coin's states: `pending` (what it rests on is not final), `live`, `offered`
(held for a swap), `sending` (in a transfer the server has not answered),
`given` (in a participation, no forfeit signed), `forfeited` (a forfeit of it
signed, the preimage not in hand), `spent`, `exiting`, `exited` and `lost`.
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
  earlier round, both boards' forfeits published: the leaf's participation,
  run again, is taken into the next round and the wallet takes its new leaf;
  each board's is `void`, the operator's reason shown, the wallet waiting on
  it no more; the board whose forfeit someone sent again is refunded after
  its delay, `exited` once the refund is final, and the other, its forfeit
  not on the chain, is exited at once (its conversion's fee paid with a coin
  of the wallet's it chooses) and claimed;
- a lost round that returns: a leaf refreshed in round R, which goes out of
  the chain with its Bitcoin parent block while another transaction of the
  operator's takes R's input; the participation run again in Y, which spends
  that transaction's output, the wallet taking Y's leaf; then the parent
  chain takes that transaction out and R confirms in its place: the node
  refuses Y, and the wallet holds its leaf of R, live, and its leaf of Y
  `lost`, one leaf for the coin it gave up;
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
  holding it until it is forgotten;
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

`tests/arca_operator_for_browsers.rs` is not a test that ends: ignored by
default, it starts the scenarios' server and keeps it running for a wallet
outside the process (the wallet built for a browser, `wallet-wasm/`), with a
control address to fund a script, produce and bury blocks, build a round and
move the chain's median time (`ARCA_OPERATOR_CONTROL`, the file's comment
lists the calls). It runs until it is told to stop (`POST /quit`):

    ARCA_OPERATOR_CONTROL=127.0.0.1:18640 cargo test -p arca-cli --test arca_operator_for_browsers -- --ignored --nocapture

`tests/arca_digests.rs` checks the wallet's call authentication and
participation id against the server's own, and its list of refusal codes
against the server's: the wallet takes every code the server answers with a
4xx for a refusal (but `rate_limited`, a request to slow down), and no other.

They need `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` (as for the server's tests:
[server/README.md](../server/README.md)) and the signer and keeper binaries,
built beside `arca` or named by `ARCA_SIGNER_EXEC` and `ARCA_KEEPER_EXEC`.
Building the workspace's Bark crates needs `protoc` (`apt install
protobuf-compiler`).

    cargo build -p arca-server --bin arca-signer --bin arca-keeper
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-cli --test arca_scenarios --test arca_adversity -- --nocapture
    cargo test -p arca-wallet --features arca --lib arca::
