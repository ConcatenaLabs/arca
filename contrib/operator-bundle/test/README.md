# Testing an operator: load, and what happens when it stops

`operator-tests.sh` puts an Arca operator you run through two things its
holders care about: how much it carries before something gives, and what
happens to their coins, their payments and their swaps when it stops. It
drives real `arca` wallets against the operator, stops and starts the
operator with your own service commands, and writes down what each wallet
holds and says at every step. [doc/operator-bundle-tests.md](../../../doc/operator-bundle-tests.md)
explains each scenario, how to read its results, and the results of the run
that produced them.

Run it only against an operator on the machine it runs on. It refuses an
operator URL that is not on this machine, an operator that shows another key
than `OPERATOR_KEY`, and, whenever a second operator is named, it checks that
operator still answers before and after every stop, starting yours again and
stopping if it does not. Stopping someone else's operator is never its to do.

## Running it

    export ARCA=/usr/local/bin/arca
    export OPERATOR_URL=http://127.0.0.1:3535 OPERATOR_KEY=<the key arca-signer --pubkey prints>
    export NODE_URL=http://127.0.0.1:18884/ NODE_COOKIE=<the node's .cookie file>
    export ASSET=<an asset the operator serves> ASSET_B=<a second one, for the swap>
    export FUND=/path/to/fund.sh          # see below
    ./operator-tests.sh down-idle down-transfer down-round down-swap
    ./operator-tests.sh load

Every amount a scenario moves is at least the operator's smallest leaf in
`ASSET` (and the other operator's, for a payment into it), read from each
operator's `/v1/info` at the start: an out-of-round payment or a receive below
it is refused. On an operator with larger leaves the scenarios move leaf-sized
amounts, and `FUND` pays a little more.

Each run keeps everything in a directory of its own (`RUN`, by default
`./operator-tests.<time>` under the current directory): every wallet, its
standard error, `log`, `results` (one line per finding, the table the run
prints at its end) and `verbatim` (what each wallet said, word for word).

| Scenario | What it shows |
|---|---|
| `load` | Wallets paying each other out of round, more at once each step, until throughput stops growing, more than 2% are refused, or a co-signature's 95th percentile passes 3 s |
| `down-idle` | The operator stops while its holders do nothing; one holder of a round leaf and one of a coin paid out of round take them home alone; the others pay at once after the restart |
| `down-transfer` | A payment co-signed and not yet read; a payment refused because the signer is gone; the operator killed with a payment in flight; a sender that goes home before its receiver reads |
| `down-round` | The operator killed with a round in the mempool, which confirms while it is down; one holder takes home the coin it gave up, the other's refresh completes after the restart |
| `down-swap` | Two swaps of two assets in the tree waiting for the maker's completion; one completes after the restart, the other's taker goes home first |
| `down-lightning` | A payment from this operator's wallet to the other operator's wallet over Lightning, through both operators' SeqLN nodes, with this operator's server down |
| `down-btc-swap` | A swap of BTC in a Bitcoin ark for this operator's asset (`arca btc-swap`): stopped after the asset is locked, and after the BTC is claimed |
| `down-desk` | A BTC desk that pays on the operator's acceptance, before its leaf is made: the operator back in time, and the operator down past the buyer's lock |
| `ark-down` | The Bitcoin ark's server down while a swap with this operator is in flight |

`all` runs every scenario but `load`.

## What it reads

| Variable | What | Default |
|---|---|---|
| `ARCA` | The `arca` command-line wallet, built from the operator's revision | required |
| `OPERATOR_URL`, `OPERATOR_KEY` | The operator under test, on this machine, and its operator key | required |
| `NODE_URL`, and `NODE_COOKIE` or `NODE_USER` with `NODE_PASSWORD_FILE` | The Sequentia node's RPC, with `-txindex` and `-validateanchor`: its cookie file (a bundle's is under its data directory), or a login whose password is read from the file, never an argument | required |
| `ASSET`, `ASSET_B` | The asset the wallets hold; the second asset of `down-swap` | required; `ASSET_B` for `down-swap` |
| `FUND` | A command run as `$FUND ADDRESS ASSET ATOMS` that pays test coins to the address on the chain and prints the payment's txid (`sendtoaddress` does), which a board then waits on to confirm (`FUND_BLOCKS`, default 30 blocks). Write it to name the node wallet it pays from, and never a treasury's, a reserve's or a service's | required |
| `NAME` | The bundle's name, which its service units carry | `arca-bundle` |
| `STOP_OPERATOR`, `START_OPERATOR` | Stopping and starting the operator as its service manager does | `systemctl stop\|start $NAME-arcad.service $NAME-arca-signer.service` |
| `KILL_OPERATOR`, `KILL_SIGNER` | The failure no service manager announces | each unit's main process killed with SIGKILL, then the unit stopped so its `Restart=` does not bring it back mid-scenario: both units, the signer's |
| `PEER_OPERATOR_URL`, `PEER_OPERATOR_KEY` | The other operator, for the Lightning scenario and the cross-operator refusal; never stopped | none |
| `PEER_ROUND` | A command that makes the other operator build a round (regtest only) | none |
| `LN_WAIT` | How long `down-lightning` waits for the receive, then for the payment, in seconds: the other operator makes the receiver's leaf in its next round | 40 with `PEER_ROUND`, 900 without |
| `CHAIN_PRODUCE`, `CHAIN_BURY`, `CHAIN_ADVANCE SECONDS` | Regtest hooks: a block, a block buried until final, the median time moved on | none: on a live chain the script waits for blocks, and an exit that must wait its delay is left for a later `arca sync` |
| `BITCOIN_ARK_URL`, `BITCOIND_URL`, `BITCOIND_COOKIE` (or `ESPLORA_URL`), `BITCOIN_NETWORK` | The Bitcoin ark and its chain, for the BTC scenarios | `regtest` |
| `BTC_FUND`, `BTC_MINE` | `$BTC_FUND ADDRESS BTC` pays a Bark wallet on Bitcoin; `$BTC_MINE N` mines (regtest) | required for the BTC scenarios |
| `STOP_ARK`, `START_ARK` | Stopping and starting the Bitcoin ark's server, for `ark-down`: an ark you run | none |
| `OPERATOR_PROCESSES` or `OPERATOR_PIDS_CMD`, `OPERATOR_DATA` | The operator's process ids (arcad, arca-signer, PostgreSQL), and its data directories, for the load test's CPU, memory and disk | none |
| `USERS`, `PAR`, `STEPS`, `STEP_SECONDS`, `AMOUNT`, `PAY`, `REQUESTS` | The load test's wallets, how many are made at once, the steps (how many pay at once), each step's length, each wallet's funding, each payment, receive requests per wallet | 100, 8, `1 2 4 8 16 32`, 60, 200000, 1000, 10 |

For a bundle from the installer, the operator's processes are its units'
main processes:

    export OPERATOR_PIDS_CMD='systemctl show -p MainPID --value arca-bundle-arcad arca-bundle-arca-signer postgresql@16-arca_bundle'

A load run from one machine is one source to the operator: its `[limits]`
per source (`source_per_second`, `witness_source_per_second`,
`read_source_per_second`) bound it long before the operator's own capacity,
and the run then names `rate_limited` as the first limit. Raise those for the
run, and set them back after.

## On regtest

`regtest-standin.sh` brings up everything the scenarios need on one machine:
operator A, the scenarios' whole server (`bark-cli/tests/arca_operator_for_browsers.rs`
with its SeqLN nodes) with the chain and its control address; operator B,
`arcad` and `arca-signer` as processes of their own with a PostgreSQL
cluster and a SeqLN node with a channel to A's; and a Bitcoin ark
(`contrib/bitcoin-ark-regtest/regtest.sh`). B is the operator the tests stop.

    export S=/tmp/standin HARNESS=target/debug/deps/arca_operator_for_browsers-<hash>
    export ARCA_BIN=target/debug B_BIN=target/release SEQUENTIAD_EXEC=… LIGHTNINGD_EXEC=…
    export PG_BIN=… CORE_BIN=… CLN_BIN=… HOLD=… CAPTAIND=… ARCA_BARK_EXEC=… ARCA_BARKD_EXEC=…
    contrib/operator-bundle/test/regtest-standin.sh up
    eval "$(contrib/operator-bundle/test/regtest-standin.sh env)"
    contrib/operator-bundle/test/operator-tests.sh all
    contrib/operator-bundle/test/regtest-standin.sh down

`env` prints the variables above, its hooks pointing back at the stand-in.
B's exit delays are as short as the operator allows (one 512-second unit),
so every exit runs to its claim in the run.

`timing-proxy.py` is the reverse proxy the load test puts between the
wallets and the operator, to time each call the operator answers.
