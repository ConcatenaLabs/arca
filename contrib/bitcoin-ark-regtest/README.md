# A Bitcoin ark on regtest

`regtest.sh` runs a complete Bitcoin ark on one machine, for the tests of the
wallet's Bitcoin side (`bark-cli/tests/arca_bitcoin_ark.rs`) and for trying a
wallet or the Arca client against one:

| Process | What it is |
| --- | --- |
| `bitcoind` | Bitcoin Core on regtest, with a funded wallet `miner`; blocks only when asked (`mine N`, or `miner-start SECS`) |
| `postgres` | A PostgreSQL cluster of its own, holding captaind's database |
| `lightningd` (gateway) | Upstream Core Lightning with `cln-grpc` and Boltz's hold plugin: the ark's Lightning gateway |
| `lightningd` (peer) | A second Core Lightning node with a channel from the gateway (2,000,000 sat, half pushed to it): the outside payer and payee |
| `captaind` | Bark's server, configured by `captaind.toml.in`, its round wallet funded with 5 BTC |

The binaries are not built here. It takes:

| Variable | What |
| --- | --- |
| `H` | The directory every daemon keeps its data and logs in (`$H/log`) |
| `CORE_BIN` | A directory with `bitcoind` and `bitcoin-cli`, version 31 or later (captaind's own minimum) |
| `CLN_BIN` | A directory with upstream `lightningd` and `lightning-cli`, whose plugins include `cln-grpc` |
| `HOLD` | Boltz's hold plugin (`github.com/BoltzExchange/hold`) |
| `CAPTAIND` | Bark's `captaind` (`gitlab.com/ark-bitcoin/bark`, package `bark-server`) |
| `PG_BIN` | A directory with `initdb`, `postgres` and `psql` |
| `PORT_BASE` | The first of the 100 loopback ports it uses (23100 by default, below Linux's ephemeral range) |

`.github/workflows/bitcoin-ark.yml` pins the versions the tests run with and
builds them; follow it to build them by hand.

    regtest.sh up          # starts everything, opens the channel, funds the ark, prints info
    regtest.sh info        # {"ark", "bitcoind", "cookie"}: what a wallet joins with
    regtest.sh mine 6
    regtest.sh btc …       # bitcoin-cli on the regtest node
    regtest.sh gw … / peer …   # lightning-cli on the gateway or the peer
    regtest.sh admin …     # captaind's admin RPC
    regtest.sh down        # stops every process `up` started, by the PIDs in $H/pids

The ark's settings are short so a test runs in minutes: rounds every 10
seconds, a leaf lifetime of 432 blocks, an exit delta of 12 blocks, two
confirmations for a board. Its Lightning settings are the testnet ark's
(`htlc_expiry_delta` 40, `max_user_invoice_cltv_delta` 250), so a receive
leaves the room it leaves there.

A wallet joins it with the values `info` prints:

    arca bitcoin create --regtest --ark http://127.0.0.1:23145 \
        --bitcoind http://127.0.0.1:23142 --bitcoind-cookie $H/btc/regtest/.cookie

and the test runs with the harness, the `bark` and `barkd` the wallet runs,
and the server's test environment:

    ARCA_TEST_BITCOIN_ARK=/path/to/a/script/that/sets/the/variables/and/runs/regtest.sh \
    ARCA_BARK_EXEC=/path/to/bark ARCA_BARKD_EXEC=/path/to/barkd \
    cargo test -p arca-cli --test arca_bitcoin_ark -- --nocapture
