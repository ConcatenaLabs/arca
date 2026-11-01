# Testing an operator: load, and what happens when it stops

An Arca operator co-signs its holders' payments out of round, builds the
rounds that refresh their coins, and settles their payments over Lightning.
Two questions follow for anyone who runs one, or holds coins with one: how
much does it carry before something gives, and what happens to everyone's
coins, payments and swaps when it stops. `contrib/operator-bundle/test/`
answers both by running real `arca` wallets against your own operator:
`operator-tests.sh` loads it, stops and starts it at chosen moments, and
writes down what each wallet holds and says ([its README](../contrib/operator-bundle/test/README.md)
lists every variable it reads). This page says what each test shows, how to
run it, and what the run below measured.

The figures and the words quoted here come from one run on regtest, on a
laptop with an AMD Ryzen 9 8940HX (32 threads) and 32 GB of memory, shared
with other work while it ran: operator B, `arcad` and `arca-signer` as
release builds with a PostgreSQL 16 cluster of their own and a SeqLN node
in asset X with a channel to operator A's; operator A, the scenarios' whole
server (`bark-cli/tests/arca_operator_for_browsers.rs`); a Bitcoin ark
(`contrib/bitcoin-ark-regtest/regtest.sh`: Bitcoin Core 31.1, `captaind`
from Bark 0.7.1, Core Lightning 26.06.6 with Boltz's hold plugin). B's exit
delays were one 512-second unit at the least and the wallets asked for
four, 2,048 s, so every exit in the run reached its claim; on the testnet
the same steps take the 36 to 48 hours an operator publishes.

## Running the tests

On the machine the operator runs on, with the variables its README lists:

    contrib/operator-bundle/test/operator-tests.sh down-idle down-transfer down-round down-swap
    contrib/operator-bundle/test/operator-tests.sh down-lightning down-btc-swap down-desk ark-down
    contrib/operator-bundle/test/operator-tests.sh load

Each scenario makes wallets of its own, funds them through `FUND` (a
command you write, naming the node wallet it pays from), brings them to the
moment, stops the operator with `STOP_OPERATOR` (or kills it with
`KILL_OPERATOR`, the failure no service manager announces), records what
every wallet says and holds, takes one holder home on the chain while the
operator is down, starts the operator with `START_OPERATOR` and checks that
every other holder comes through with nothing done by hand. `results` holds
one line per finding and `verbatim` every wallet's words.

The script stops only an operator on its own machine, one that answers with
the key `OPERATOR_KEY` names. When `PEER_OPERATOR_URL` names another
operator, the script checks it answers before every stop and after it, and
stops at once, starting yours again, if it does not: it never stops anyone
else's operator.

To try it without an operator of your own, `regtest-standin.sh up` brings
up both operators and the Bitcoin ark on one machine and `env` prints the
variables, as the README shows.

## What happens when the operator stops

An operator's stopping takes nothing from a holder who holds its coins'
records: every such coin is the holder's to take home on the chain,
whatever the operator does, and the run took each one home alone. Two cases
in the table below are the exceptions the run found: a payment its receiver
had not read yet, and a desk that paid before its coin was made. `arca
exit` unrolls a coin's path, waits its exit delay and claims it to an
address of the wallet's. While the operator
is down a wallet keeps everything it holds, counts it as before, and says
so:

> the operator cannot be reached now: nothing is taken on the chain for that
> before a coin's home_from (a day before its exit date, exit_by); from then
> sync takes it on the chain unless its refresh has completed. Run `arca
> sync` at least once a day while the wallet holds a coin off the chain or
> waits for a payment

with the reason (`cannot reach the server: witness: Connection refused (os
error 111)`). Every command that needs the operator (`send`, `receive`,
`swap complete`, `lightning pay`) refuses with that reason and signs
nothing. When the operator comes back on its own database, at its own
address and under its own key, each wallet's next command goes on where it
stopped.

| Moment | Can a holder lose coins? | What refunds, and when | Taken home alone, operator down | Back after the restart |
|---|---|---|---|---|
| Idle | No | Nothing is in flight | A round leaf: home for 22 atoms of fees; a coin paid out of round to another wallet: home for 22 | Payments go through at once |
| Payment out of round, co-signed, not yet read | With the run's wallet, yes, when the sender went home before the receiver read it; a wallet that answers such a coin (arca #344) keeps it (below) | Nothing: the payment is complete | The sender's change; the receiver cannot see the coin until it reads its mailbox | The receiver reads it at its next sync |
| Payment, signer gone | No | Nothing was sent: the wallet asks for the signer's witness first and refuses (`503 signer_unavailable`) | | The payment goes through when asked again |
| Payment, operator killed in flight | No | | | The receiver holds it after the restart |
| Round in the mempool, confirmed while down | No | The coin given up is the holder's until it hands over its forfeit | The given coin: home for 62 atoms | The refresh completes; the given coin of the one who went home is `withdrawn` |
| Swap of two assets, accepted, not completed | No | Nothing moved | The taker's offered coin | The maker completes; a maker whose taker went home cancels and holds its coin again |
| Lightning payment to the other operator, this server down | No | | | The payment reads `paid` with its preimage |
| BTC for an asset (`btc-swap`), asset locked, receiver's leaf not made | No | Nothing yet | | The swap completes |
| `btc-swap`, receiver's leaf made, operator killed before the BTC is paid | No | The BTC is never paid (`not paying, ever`); the asset's lock comes back once the operator, back, fails the receive back after the leaf's time to claim | | The swap is `abandoned`; the asset comes back |
| `btc-swap`, operator killed as the BTC is paid | No | | The receiver's leaf, by its claim with the preimage: 99,900 atoms home for 30 | The payer's asset leg reads `paid` |
| BTC desk paid early, operator back in time | No | | | The desk's leaf is made and claimed |
| BTC desk paid early, operator down past the buyer's lock | **The desk's BTC, within its caps** | The buyer's asset, by its refund, after its timeout and exit delay | The buyer takes its asset home | The desk's receive fails back |
| The Bitcoin ark's server down as the BTC is to be paid | No | The asset's lock, once its time to claim is over (4.9 days in the run): back whole, less 416 atoms of transfer fees | | The swap ends (`btc_failed`): it does not resume when the ark returns |

The rows are the results of the run described above; the sections below say
what each scenario does and what it saw.

### Idle

Three holders: one of a round leaf, one of a coin paid out of round to it,
one of a board. The operator stops (`SIGINT` to `arcad`, `SIGTERM` to the
signer). Every total stays as it was. The round leaf's holder takes it home
alone: `arca exit` broadcasts the unroll at once, claims after the exit
delay, and the coin comes home for 22 atoms. The coin paid out of round
rested on that leaf, so its receiver's wallet saw its lineage on the chain
and started taking it home by itself (`on the chain: its own leaf; no
off-chain spend of it is co-signed any more, and the wallet takes it
on-chain before any exit delay runs out`); it came home for 22 atoms too.
One holder's exit brings home every coin out of round that rests on the
same leaf: that is the protocol working, not a fault. After the restart the
board's holder pays at once.

### A payment out of round in flight

Three cases. A payment the operator co-signed whose receiver has not read
its mailbox: the coin's record is in that mailbox at the operator and
nowhere else. A payment asked for while the signer is gone: the wallet asks
for the signer's witness before anything and refuses, `cannot reach the
server: witness: the server answered 503 signer_unavailable: cannot reach
the signer at …`, so nothing is recorded. A payment in flight when the
operator is killed (`SIGKILL`): in the run it had been co-signed before the
kill, and its receiver held it after the restart.

**A finding: a stuck coin.** The sender of the first payment took its change home
with the operator down. That broadcast the reassignment that made both the
change and the receiver's coin, so the receiver's coin stood on the chain,
unspent, under the receiver's key. After the restart the receiver's wallet
refused it, `refused: the board at …:0 is spent`, and held nothing: the
coin was stuck, spendable by nobody else and never claimed. Had the
receiver read it while only the sender's board conversion was on the
chain, the sender could have claimed its converted leaf after its delay and
taken the coin back: the receiver holds the checkpoint and the reassignment
that answer it, and published neither. The wallet built from arca #344 on
answers such a coin as it answers a coin it already holds: kept and taken
home at once, its path published from wherever the chain holds it, and
refused only once a final spend that is no step of its path has cut it.
Its test, the run's case, ends with the receiver's claim paying 399,978 of
its 400,000 atoms. Run these tests with a wallet built from the operator's
own revision.

**A limit, open.** A receiver that has not read its mailbox learns of a
coin paid to it only from that mailbox, at the operator. While the operator
is down it cannot see the coin, and if the operator never comes back and
nobody publishes the coin's path, it cannot take the coin home: the coin's
record, the transactions that make it, is held by the operator and the
sender's wallet, not the receiver's. Two ways to close it, either of which a
wallet can carry without the operator:

- the sender's wallet hands the coin's record to the receiver by another
  channel (a text the receiver imports, as a swap's offer and take are
  handed over), so the receiver holds what it needs to exit before it ever
  reads its mailbox;
- the wallet watches the chain for the scripts of its own leaves, which it
  can derive from the nonces of the receive requests it handed out, and
  takes home a coin it finds there from the transactions that made it.

Until then: run `arca sync` soon after being paid, and keep the receive
request's text. A payment out of round rests on the operator until it is
read, as it rests on the operator and its sender not colluding until it is
refreshed in a round.

### A round

Two holders give up their boards in one round. Once the round is in the
node's mempool the operator is killed; the round then confirms and becomes
final with the operator down. Neither holder has handed over a forfeit, so
each coin given up is still its own (`given`; the participation `pending`).
One holder takes its given coin home alone for 62 atoms of fees. After the
restart the other's participation is released and its new leaf is live; the
one that went home sees its participation `withdrawn`. The operator's own
log then says, every half second, that the participation waits because `its
own leaf is on-chain`: it is voided only at the coin's exit deadline.

### A swap of two assets in the tree

Two swaps, each offered and accepted, wait for the maker's completion when
the operator stops. The makers' completions answer `cannot reach the server`
and nothing moves. One taker takes its offered coin home alone. After the
restart the first maker completes its swap; the second's completion is
refused because its taker's coin went home (`refused: the board at …:0 is
spent`), and `swap cancel` gives the maker its coin back, live.

### A payment over Lightning to the other operator

A wallet of this operator pays a wallet of the other operator's 200,000
atoms of X: through this operator's SeqLN node and the other's. The
operator's server and signer stop with the payment `paying`; its SeqLN node
keeps running. The other operator makes the receiver's leaf and the
receiver claims it (199,384 atoms after the fees), which settles the
payment back along the channels to this operator's node. After the restart
the payer's wallet reads its payment `paid`, with the preimage. A Lightning
node that stops with a payment held in its channels is a channel matter
(its peer closes the channel on the chain to claim the payment before its
lock times out) and is not covered here.

### BTC in a Bitcoin ark for this operator's asset

`arca btc-swap` swaps native BTC in a Bitcoin ark for an asset in this
operator's tree, under one payment hash, between two wallets of this
operator. A wallet of another operator cannot take the offer: `refused: the
offer is for operator …, and this wallet's operator is …: a swap runs
between two wallets of one operator`. The Bitcoin ark may be anyone's: both
wallets only have to be in the same one.

P gives 100,000 atoms of X for Q's 30,000 sat. Three moments:

- **Stopped after P locks, before Q's leaf is made.** Q's wallet waits
  (`not paying yet: the receive under hash … is "waiting"`) and P's waits
  for a payment to claim (`claiming the BTC: no payment claimed yet`). No
  BTC moves. After the restart the operator makes Q's leaf, Q pays, P claims
  and posts the preimage, and both wallets read `done`: P +29,840 sat (30,000
  less Bark's fee), Q +99,484 atoms of X.
- **Killed after Q's leaf is made, before Q pays.** Q never pays: `not
  paying, ever: cannot reach the server: witness: Connection refused (os
  error 111); the asset leg fails back to its payer`, and the swap reads
  `abandoned`. P's lock comes back once the operator, back, fails Q's
  receive back, after the time to claim Q's leaf is over.
- **Killed the moment Q starts paying.** The whole Bitcoin leg then runs
  with the operator down: Q's payment goes through, P claims the BTC (P
  `claimed`, +29,840 sat), and its claim reveals the preimage, which Q
  reads from its own payment (`claiming the asset leaf with the preimage`).
  Q cannot claim its leaf through the operator, so it takes it home alone,
  by the leaf's claim path with the preimage: 99,900 atoms brought home
  for 30 atoms of fees. P's wallet says
  `the BTC is claimed; the asset leg is decided once the operator has the
  preimage`; after the restart the operator reads the preimage from Q's
  claim on the chain and P's asset leg reads `paid`, the swap `done` and
  the operator's receive `claimed`.

So no party can lose coins to the operator stopping: the BTC moves only
once Q holds its leaf, and once the BTC moves the preimage is Q's to claim
its leaf with, through the operator or on the chain. What the operator can
lose is its own: if it stays down past P's lock, P may refund the asset it
already paid with the preimage; its watcher, back in time, claims P's leaf
first.

The hash locks, as the run computed them: P's asset lock (its `htlc-1` send
leaf) times out 393,405 s, about 4.6 days, after it locks; Q's received leaf
times out the operator's internal gap (its operator delay, the stall margin
and an hour) before that. Q pays BTC only once its leaf is held and final,
and its home date is at least an hour past the latest moment the Bitcoin leg
can end. With the testnet's 36-hour exit delays and a Bitcoin ark whose
HTLC delta is 258 blocks, the same rules put P's lock about 6.6 days out.

### The BTC desk paying early

A BTC desk that sells BTC for an asset may pay the BTC as soon as the
operator holds the buyer's payment (the desk's receive `issuing`), before
the desk's leaf is made, within caps it sets per swap and in all. The
scenario models it with two wallets of this operator: the buyer makes a
Bitcoin invoice, the desk asks to receive the asset under its hash, the
buyer pays the operator's invoice from its leaf, and the desk pays the
Bitcoin invoice once its receive is `issuing`, learning the preimage.

- **The operator back in time.** The operator is killed once the desk has
  paid; when it comes back it makes the desk's leaf in its next round, the
  desk claims it with the preimage its BTC payment bought, and its receive
  reads `received`: the desk holds 99,484 atoms of X and the buyer 29,840
  sat. Nobody lost anything.
- **The operator down past the buyer's lock.** The operator holds the
  buyer's payment for the desk (`{"state":"accepted","held_by":"send"}`),
  the desk pays the BTC, the buyer claims it (29,840 sat), and the operator
  is killed before the desk's leaf is made. The buyer's asset is in its
  payment's `htlc-1` leaf, which times out 518,400 s (six days) after it
  paid. Once that and its exit delay have run, the buyer takes the leaf home
  by its refund, alone: its asset comes back whole, less 30 atoms of fees.
  The buyer keeps the BTC and its asset; the desk paid 30,000 sat and holds
  nothing for it. When the operator comes back the desk's receive reads
  `failed`, `its leaf was not claimed in time`.

That loss is the desk's, and it is the risk paying early takes: the desk
pays against the operator's promise to make its leaf, and an operator that
stays down past the buyer's lock never makes it. The desk bounds it with
its caps (per swap, and outstanding at once); a desk that waits for its
leaf to be made and final before it pays takes no such risk. An operator
that comes back before the buyer's lock times out (days, not minutes) costs
the desk nothing.

### The Bitcoin ark's server down

`ark-down` stops the Bitcoin ark's server, `captaind`, with its chain and
its Lightning gateway running, after P has locked its asset and Q holds its
leaf, before Q pays. On the testnet the ark is someone else's; this test is
for an ark you run, or a regtest one. Q's wallet tries to pay and the
payment fails at once: `the BTC payment did not go through; the asset leg
fails back to its payer`, and the swap ends (`btc_failed` for Q, `btc_lost`
for P: the BTC leg ended unclaimed). Nothing was paid and nothing is lost,
but the swap does not resume when the ark returns: a wallet tries a payment
at most three times, so an ark outage at the moment of paying ends the swap.
P's asset stays locked until the operator fails Q's receive back, once the
time to claim Q's leaf is over: in the run P's lock ran until median time
1,793,790,223, about 4.9 days after it locked; moved past it, the operator
failed the receive back and P's swap read `refunded`, its 100,000 atoms
back less 416 atoms of transfer fees.

### On the public testnet

`down-idle`, `down-transfer` and `down-lightning` also ran against a second
operator on the public testnet, a bundle beside sequentiatestnet.com's with
leaves of at least 1,000,000 atoms and an exit delay of 254 units (36 hours),
paying across to sequentiatestnet.com's operator over Lightning:

- **Idle**: no holder's total moved while it was down; it came back in 1.1 s
  with the same key, and the holder that had waited paid at once. The two
  holders that went home alone had their exits on the chain, waiting out the
  36-hour delay.
- **A payment in flight**: with the signer gone the payment was refused
  (`503 signer_unavailable`) and nothing changed; killed in flight, the payment
  went out; after the restart (17.3 s) every receiver held what it was paid.
- **A payment over Lightning to the other operator**: paid with this operator
  stopped 0.3 s later. The other operator held the payment for its next round
  and the receiver held 1,999,584 of its 2,000,000 atoms 142 s later (the rest
  is the claim's margins). The payer read `paying` until this operator came
  back, and `paid` with its preimage 2 s after the restart.

On a live chain the scenarios wait for blocks and for the other operator's
round where regtest makes them at once, and their amounts are leaf-sized:
each run's funding costs a few hundredths of a unit of the asset.

## Load

`operator-tests.sh load` makes many wallets, funds them all in one round (a
distribution, one claim leaf each, which every wallet takes up), and has
them pay each other out of round: one wallet at a time, then 2, 4, 8, 16 and
32 at once, each step a minute. A timing proxy in front of the operator
records how long the operator takes to answer every co-signature. A coin is
paid on out of round at most five times from its round; a wallet whose
coins are that deep asks for a refresh and pays again once its new leaf is
final, so the rounds run beside the payments. The run stops at the first
limit: throughput growing less than a fifth from one step to the next, more
than 2% of payments refused, or a co-signature's 95th percentile above
three seconds.

### What the run measured

Operator B in release builds; the wallets were the debug `arca` command
line, one process a command, on the same machine and against the same
Sequentia node as the operator (the stand-in's), with the machine busy with
other work besides (load average 8 to 29). B's round interval was ten
seconds.

**From one machine, with the operator's default limits**, the operator's
per-source budget is the limit before anything else: a witness of the
signer's record is handed to one source at five a second with bursts of 60,
and every wallet command asks for one. In a run of 100 wallets the operator
answered 552 witnesses and refused 5,849 (`429 rate_limited`); receive
requests could not be made fast enough to load it at all. Real holders come
from many addresses; a load test from one machine raises these limits for
the run (`[limits]`, the `*_source_*` settings) and sets them back after.

**With the per-source limits raised, 1,000 wallets:**

| Step | At once | Transfers a second | Send command p50 / p95 | Co-signature p50 / p95 | Refused | Operator CPU | Operator memory |
|---|---|---|---|---|---|---|---|
| 1 | 1 | 4.0 | 0.15 s / 0.27 s | 25 ms / 97 ms | 0 | 0.44 cores | 1.0 GB |
| 2 | 2 | 5.3 | 0.20 s / 0.44 s | 44 ms / 144 ms | 0 | 0.50 cores | 1.1 GB |
| 3 | 4 | 10.3 | 0.18 s / 0.49 s | 34 ms / 165 ms | 0 | 0.67 cores | 1.3 GB |
| 4 | 8 | **15.5** | 0.19 s / 0.71 s | 37 ms / 268 ms | 0 | 0.88 cores | 1.7 GB |
| 5 | 16 | 13.0 | 0.30 s / 0.88 s | 64 ms / 397 ms | 242 | 2.19 cores | 2.1 GB |
| 6 | 32 | 10.8 | 0.61 s / 2.56 s | 177 ms / 1,212 ms | 157 | 2.40 cores | 2.4 GB |

The co-signature figures are the operator's own time to answer
`cosign_transfer`, measured at a proxy in front of it; the send command's
are the wallet's whole command. Operator CPU is `arcad`, `arca-signer` and
the PostgreSQL cluster together, in cores kept busy over the step; memory
is their resident memory summed (shared PostgreSQL pages counted in each
process, so an upper bound).

**The first limit** came at 16 wallets at once: throughput stopped growing
at about 15.5 transfers a second and fell after, while the operator used
under a tenth of the machine's cores. Two things gave:

- The Sequentia node. At 32 at once it refused calls with `HTTP 503: Work
  queue depth exceeded`: 63 payments failed at the wallet's own node call,
  and 14 co-signatures failed inside the operator (`500 internal: the node:
  the node answered HTTP 503: Work queue depth exceeded`), whose finality
  service logged the same. The wallets and the operator shared one node
  with `sequentiad`'s default RPC queue of 16. An operator's node serves the
  operator alone, and holders use nodes of their own, so in use this limit
  sits further out; an operator under load raises `-rpcworkqueue` and
  `-rpcthreads`.
- The depth limit, by design. A coin is paid on out of round at most five
  times from its round (`422 depth_limit`, 239 at 16 at once): a wallet
  that pays often has its coins refreshed in a round and pays again once
  its new leaf is final. The rounds ran beside the payments.

Three wallets were told `cannot reach the server: the operator shows its
signer's record ending at entry 7792, below entry 7794 the wallet holds`
and asked again: the operator serves its signed record head from a cache
of a few seconds, older than the co-signature the wallet had just been
given.

Most requests a wallet makes are reads, not co-signatures: in the run,
54,702 challenges and 53,460 mailbox reads against 4,594 co-signatures. A
wallet reads its mailbox under its mailbox key and under the key of every
receive request it has handed out and not yet been paid on (the load test
hands out a dozen each).

**Rounds.** Each round's time from its timer's tick to its broadcast (the
tick's phase taken from the operator's start):

| Participations | vbytes on the chain | Built and broadcast after the tick |
|---|---|---|
| 1 | 500 | 0.9 s |
| 2 | 866 | 1.3 s |
| 18 | 3,428 | 2.1 s |
| 57 | 3,428 | 4.8 s |
| 239 | 3,295 | 9.1 s |
| 4 distributions, 1,000 claim leaves | 1,391 | 3.0 s |

About a second, plus some 35 ms a participation. At a ten-second interval a
round of a few hundred participations takes most of the interval.

**Funding 1,000 wallets** shows a second limit, in the wallet that pays
many holders at once. One distribution's request carries every holder's
claim: a list of 1,000 is over the operator's `max_request_bytes` (64 KiB)
and refused (`413 request_too_large`), so the test pays them in four
distributions of 250. Then the payer's `sync` asks the operator for the
round's whole published tree once for every claim leaf of it, not once per
batch: 2,417 tree requests, each answered in about 0.57 s, which kept the
payer's sync running for over twenty minutes and made funding 1,000 wallets
take 28 minutes, and 1,972 s of the operator's CPU. Taking the claims up
was quick: 1,000 claims in 205 s, 16 at a time, each `claim_leaf` answered
in 77 ms on average.

**What 1,000 holders cost the operator**, from the samples before and after
funding: about 530 MB more resident memory (most of it PostgreSQL's cache),
36 MB more disk (the database and the signer's record), and the CPU above.

**Compared with the testnet operator.** LQ3's volume run sets the testnet
operator's stop rule at a co-signature p95 above three seconds and aims at
about 25,000 trades a day, 0.3 a second. B carried 15.5 transfers a second
(about 1.3 million a day) with a co-signature p95 of 268 ms, and stayed
under that stop rule at every step, 1.2 s at 32 at once. LQ3's own
measurements on the live operator were not in hand for this run.
