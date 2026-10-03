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
  wallet signs anything for it: the five checks on the sweep token and its
  clock, the batch output paid exactly once, the notice, a first expiry at
  least 27 days ahead, the exit delay within the wallet's bounds, the depth,
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
  chain; every board it rests on must be unspent. After that, the re-check
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
  A coin resting on a round that can never return (a coin the round spends is
  spent by another transaction that is final) is `lost`.
- **A coin handed over stays the wallet's until the chain says otherwise.** A
  coin given to a participation, or sent in a transfer the server has not
  answered, can be exited at any time; exiting it withdraws the wallet from the
  participation, or abandons the request. A coin whose participation the
  server calls `void`, or lets expire, is live again, unless the wallet signed
  a forfeit of it for a round that is not gone: such a coin is `forfeited`, and
  is spent again only once that round can never return. Every forfeit is
  recorded before it leaves the wallet, with the new leaves it was signed for,
  and `sync` follows each forfeit's output on the chain until a spend of it is
  final: a claim of the output publishes the preimage, which the wallet reads
  from the claim's witness to complete its new leaves at once, whatever it
  broadcast itself; an output left unclaimed until the refund delay has run
  since it confirmed is the wallet's to refund, and the coin is `exited` once
  that refund is final. A refund in the mempool, or a claim in a block not
  yet final, decides nothing: the other may still take the output. A forfeit
  never published whose round can never return is void, and the coin is live
  again.

### Fees

Fees are paid in the asset being moved unless another is named
(`--fee-asset`), and no asset is a default. When the node does not accept that
asset for fees, the wallet says so and does nothing; it never falls back to
another asset. Fee rates are the node's floor in the fee asset's own atoms,
read when the transaction is built. The transactions a transfer signs in
advance (the checkpoint, the reassignment) leave a margin of four times the
floor in the asset moved, or one atom where the node does not accept it, in
which case whoever broadcasts attaches a fee coin; the operator co-signs no
transfer whose margins are below that, or above the multiple of it it
publishes (`max_margin_multiple`).

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
| `coins`, `record LEAF` | Every coin held or once held; one coin's record |
| `board ASSET AMOUNT [--fee-asset A]` | Brings on-chain coins into Arca. The server registers the board before it is broadcast, so a refused board spends nothing; the coin is spendable once the board transaction is final |
| `boards` | Where each board stands, by the server and by the chain |
| `receive [--asset A] [--amount N]` | A single-use receive request (`arca:…`): a fresh key and owner nonce, the wallet's mailbox, the exit delay asked for |
| `send REQUEST [--amount N] [--asset A]` | Pays a receive request out of round: the coins of the asset, each into a checkpoint, and the reassignment into the receiver's leaf and the change. The server co-signs and posts the coins to the mailboxes |
| `mailbox` | Reads the mailbox and validates every coin in it; each is kept or refused with its reason, and one refused for a passing reason (what it rests on not on the chain now, during a rollback, or the node not answering) is kept aside as `waiting` and checked again on every read |
| `participate [--leaf L]… [--not-before T] [--max-fee-ppm N]` (`refresh`) | Gives up the coins named (every live coin when none is) for one new leaf per asset in the next round, paying the operator's refresh fee in each coin's own asset, within the wallet's bound (`--max-fee-ppm` raises it for this command); each coin's fee is printed before anything is signed |
| `sync` | Re-checks every coin, posts again the transfer requests the server never answered, reads the mailbox, moves every participation on (once its round is final, validates the new leaves, signs the forfeits, takes the preimage and releases the old batch leaves' lowest nodes, each release naming the new round's connector asset), follows on the chain every forfeit whose preimage it does not hold, and moves every exit on |
| `recheck` | Re-checks every coin against the chain as it is now, starts the exit of any coin whose round or board the chain holds fails the wallet's checks or whose lineage shows on the chain, and reports what changed and whether the tip it last saw was reorganised away |
| `exit LEAF [--fee-asset A]` | Takes a coin on-chain from its record alone, without the server, whether it is live, waiting, held for a swap, given to a participation, under a forfeit whose preimage the wallet does not hold, or in a transfer the server never answered: the unroll and entry of each batch leaf, a board's conversion, each checkpoint and reassignment; then, once the exit delay has run, the claim to one on-chain address of the wallet's. Each run starts from where the chain holds the coin's path now (whichever round pays its batch output, whatever step someone else published), goes as far as the chain allows, and remembers the fee asset; run it again, or `sync`, to go on. The coin is `exited` once its claim is final; until then the wallet follows the claim, and builds it again should it leave the chain |
| `swap offer --give-asset A --give N --want-asset B --want M` | Offers one asset for another in one reassignment (`arca-offer:…`); the maker pays its margin, in the asset it gives |
| `swap accept OFFER` | Checks the maker's coins as a receiver would, adds the wallet's side and signs it (`arca-accept:…`) |
| `swap complete ACCEPT`, `swap cancel ID` | The maker checks its outputs are all there, signs and has the server co-sign; or a swap is given up. An offer has nothing signed in it, and its coins are freed. An acceptance does: the maker holds the taker's signatures, so the taker's coins are spent to a fresh leaf of the wallet's own, after which the acceptance can never complete; if that cannot be done, the answer says the acceptance still stands |
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
server (`arca-signer` in its own process, `Server::start` with its tasks, its
watcher and its HTTP listener) on an anchored proof-of-stake regtest chain, its wallet
paid in an issued asset and never the policy asset. Two wallets are created
and board, a board is credited once final; one pays the other out of round,
the receiver validates the coin from its mailbox; a wallet refreshes through a
round; the two swap two assets in one reassignment; a rollback
(`invalidateblock`) makes the re-check un-credit and then credit again every
coin on the round; and a coin is exited from its record alone, with the server
stopped, through its unroll, its checkpoints, its reassignment and its claim,
a fee coin paying where its asset is not accepted for fees. A second test puts
a proxy between a wallet and the server that rewrites the published tree (a
leaf's value, the last expiry, a clock running backwards): the wallet refuses
each before it signs anything, and completes once the tree is honest; a
second refresh then gives up that batch leaf and releases its lowest node for
the new round. Every
refusal is asserted by its reason.

`tests/arca_adversity.rs` runs the same way, with a proxy that can rewrite any
answer of the server or hold a call unanswered, and with transactions the test
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
- a round that can never return, whose coins come back, a forfeit of one of
  them published anyway and refunded after its delay, the coin `exited` once
  the refund is final;
- a forfeit's refund sent once its delay has run and replaced in the mempool
  by the operator's claim, which confirms: the wallet reads the preimage from
  the claim and holds its new leaf, and the coin given up is spent; and a
  refund that confirms, which decides the coin only once it is final;
- a refresh fee of half of every coin, and one inside a coin's free window;
- a sender converting the board it paid from, answered at once by the
  receiver;
- a server named `https://` whose certificate no root vouches for, refused by
  TLS itself, and a plain-HTTP server on another host, refused before anything
  is sent;
- a payment whose answer comes back as a gateway's 502, posted again;
- a coin received while its board is rolled out of the chain, taken once the
  board returns;
- a tree whose reserves are one atom in an asset the wallet's node accepts for
  fees, refused before any forfeit, and the same tree accepted where the node
  does not accept the asset, the fee coin its exit needs stated;
- an acceptance of a swap cancelled, after which the maker's completion is
  refused;
- the files a fresh wallet writes, readable by their owner alone, the node's
  password in none of the store's, and its balance of one row, 0 BTC; and a
  wallet restored from the mnemonic that finds on-chain coins past the first
  20 unused addresses.

`tests/arca_digests.rs` checks the wallet's call authentication and
participation id against the server's own, and its list of refusal codes
against the server's: the wallet takes every code the server answers with a
4xx for a refusal (but `rate_limited`, a request to slow down), and no other.

They need `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` (as for the server's tests:
[server/README.md](../server/README.md)) and the signer binary, built beside
`arca` or named by `ARCA_SIGNER_EXEC`. Building the workspace's Bark crates
needs `protoc` (`apt install protobuf-compiler`).

    cargo build -p arca-server --bin arca-signer
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-cli --test arca_scenarios --test arca_adversity -- --nocapture
    cargo test -p arca-wallet --features arca --lib arca::
