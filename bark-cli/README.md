# arca-cli

The command-line wallets of this workspace:

- **`arca`**, the Arca wallet: a dual-chain wallet whose Sequentia side holds
  Arca coins against an Arca server, and whose Bitcoin side is Bark's wallet
  for Bitcoin arks.
- `bark` and `barkd`, Bark's own command-line wallet and daemon for Bitcoin
  arks, which `arca bitcoin …` runs.

## The `arca` wallet

`arca` keeps its state in one directory (`--datadir`, `ARCA_DATADIR`, by
default `~/.arca`): the BIP39 `mnemonic` (mode 0600), and `arca.sqlite`, the
store. The wallet library is `bark::arca` (`bark/src/arca/`, the `arca` feature
of `arca-wallet`), built on `arca-covenant` for every script, record and check.

It needs:

- an Arca server (`arcad`), reached over HTTP at its base URL;
- a `sequentiad` it can call over JSON-RPC, running with `-txindex` and
  `-validateanchor`. The wallet reads the chain only from this node, and
  refuses one that does not validate its anchors: without that the node has no
  notion of finality.

Every command prints JSON. A refusal prints
`{"error": {"kind", "message"}}` (with the server's `code` and `status` when
the server refused) and exits with status 1. Every refusal is also recorded,
and `arca refusals` lists them.

### Keys

All keys come from the mnemonic, as the Sequentia Wallet Kit derives them, so
one mnemonic serves both:

- each leaf has a key of its own, `m/6'/account'/c1'/c2'/c3'/c4'`, where
  `c1`…`c4` are the first four 31-bit chunks of `SHA256("Arca/key" ‖
  owner_nonce)` and the owner nonce is 32 random bytes drawn for that leaf
  alone. The nonce goes into the leaf's record, so a record names its own key;
- the mailbox key is `m/6'/account'/0'`;
- on-chain keys are `m/84'/1'/0'/<chain>/<index>` (`0'` instead of `1'` on the
  main chain), unblinded P2WPKH: the same key is a Bitcoin and a Sequentia
  address.

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
  least 27 days ahead, the exit delay within the wallet's bounds, the depth, the
  reserves. Only once the round is final. The forfeit of each coin given up is
  built from that validated leaf and round, and its refund delay must end
  before the new leaves' exit deadline.
- **A coin received out of round** is validated back to every round and board
  it rests on, under the receipt policy: every pair, preimage and
  authorisation, the exit delay of every leaf of its lineage, the depth limit.
  Its key and nonce must be ones the wallet drew and is waiting on (a receive
  request is single use); no leaf or checkpoint of its lineage may be on the
  chain; every board it rests on must be unspent.
- **Finality** is the node's: a round or board is final when its block is
  certified by the committee and its Bitcoin anchor buried two blocks. A coin
  is spendable only while everything it rests on is final. The wallet asks again
  every time, never remembers: on every start it re-checks every coin against
  the chain, so a rollback un-credits the coins it took out, and credits them
  again when their round or board returns.

### Fees

Fees are paid in the asset being moved unless another is named
(`--fee-asset`), and no asset is a default. When the node does not accept that
asset for fees, the wallet says so and does nothing; it never falls back to
another asset. Fee rates are the node's floor in the fee asset's own atoms,
read when the transaction is built. The transactions a transfer signs in
advance (the checkpoint, the reassignment) leave a margin of four times the
floor in the asset moved, or none where the node does not accept it, in which
case whoever broadcasts attaches a fee coin.

### Commands

| Command | Does |
|---|---|
| `create --server URL --node-url URL [--node-user U --node-password P \| --node-cookie FILE] [--mnemonic M]` | Creates the wallet: a new mnemonic (or the one given), the node's chain, and the server's operator key, pinned. `--exit-delay-units` is the exit delay the wallet asks for its own leaves; `--min-exit-delay-units` and `--max-exit-delay-units` bound what it accepts (512-second units; 36 to 48 hours by default) |
| `info` | The wallet's chain, operator, mailbox key and policy, and what the server publishes |
| `address` | A new on-chain address, to pay the wallet's boards and fee coins from |
| `balance` | Per asset: Arca coins by state, on-chain coins, and the Bitcoin side |
| `coins`, `record LEAF` | Every coin held or once held; one coin's record |
| `board ASSET AMOUNT [--fee-asset A]` | Brings on-chain coins into Arca. The server registers the board before it is broadcast, so a refused board spends nothing; the coin is spendable once the board transaction is final |
| `boards` | Where each board stands, by the server and by the chain |
| `receive [--asset A] [--amount N]` | A single-use receive request (`arca:…`): a fresh key and owner nonce, the wallet's mailbox, the exit delay asked for |
| `send REQUEST [--amount N] [--asset A]` | Pays a receive request out of round: the coins of the asset, each into a checkpoint, and the reassignment into the receiver's leaf and the change. The server co-signs and posts the coins to the mailboxes |
| `mailbox` | Reads the mailbox and validates every coin in it; each is kept or refused with its reason |
| `participate [--leaf L]… [--not-before T]` (`refresh`) | Gives up the coins named (every live coin when none is) for one new leaf per asset in the next round, paying the operator's refresh fee in each coin's own asset |
| `sync` | Re-checks every coin, posts again the transfer requests the server never answered, reads the mailbox, and moves every participation on: once its round is final, validates the new leaves, signs the forfeits, takes the preimage and releases the old leaves' lowest nodes |
| `recheck` | Re-checks every coin against the chain as it is now, and reports what changed and whether the tip it last saw was reorganised away |
| `exit LEAF [--fee-asset A]` | Takes a coin on-chain from its record alone, without the server: the unroll and entry of each batch leaf, a board's conversion, each checkpoint and reassignment; then, once the exit delay has run, the claim to the wallet's on-chain address. Each run goes as far as the chain allows; run it again to go on |
| `swap offer --give-asset A --give N --want-asset B --want M` | Offers one asset for another in one reassignment (`arca-offer:…`); the maker pays its margin, in the asset it gives |
| `swap accept OFFER` | Checks the maker's coins as a receiver would, adds the wallet's side and signs it (`arca-accept:…`) |
| `swap complete ACCEPT`, `swap cancel ID` | The maker checks its outputs are all there, signs and has the server co-sign; or a swap is given up and its coins freed |
| `refusals` | Every refusal the wallet made, with its reason |
| `bitcoin [--] ARGS…` | Runs Bark's `bark` with `--datadir <datadir>/bitcoin` and the arguments given: the wallet's Bitcoin side. Put `--` before an argument `arca` would read itself, such as `--help` |

A coin's states: `pending` (what it rests on is not final), `live`, `offered`
(held for a swap), `sending` (in a transfer the server has not answered),
`given` (in a participation), `spent`, `exiting`, `exited` and `lost`.

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
server (`arca-signer` in its own process, `Server::start` with its tasks and
its HTTP listener) on an anchored proof-of-stake regtest chain, its wallet
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
each before it signs anything, and completes once the tree is honest. Every
refusal is asserted by its reason. `tests/arca_digests.rs` checks the wallet's
call authentication and participation id against the server's own.

They need `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` (as for the server's tests:
[server/README.md](../server/README.md)) and the signer binary, built beside
`arca` or named by `ARCA_SIGNER_EXEC`. Building the workspace's Bark crates
needs `protoc` (`apt install protobuf-compiler`).

    cargo build -p arca-server --bin arca-signer
    ARCA_TEST_POSTGRES=postgres://arca@127.0.0.1:55432/postgres \
    SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p arca-cli --test arca_scenarios -- --nocapture
    cargo test -p arca-wallet --features arca --lib arca::
