# Running an operator bundle

This runbook sets up an **operator bundle** — an Arca operator on both chains,
with its own nodes and Lightning gateways — on Linux, macOS or Windows,
connects it to the Sequentia testnet's own bundle at sequentiatestnet.com, and
pays between the two. Every command is written out; every value you fill in is
named where you need it, and each stage ends with the check that shows it
worked.

> **Testnet software.** The bundle runs on the Sequentia testnet and Bitcoin
> testnet4 and refuses Bitcoin's main network. Do not use it with anything of
> value.

## Choose your path

| Your machine | Path |
| --- | --- |
| Linux (any distribution with Docker) | [Docker Compose](#path-1-docker-compose) |
| macOS (Apple silicon or Intel) | [Docker Compose](#path-1-docker-compose), with Docker Desktop |
| Windows 10, 11 or Server | [Docker Compose](#path-1-docker-compose) with Docker Desktop, or [WSL2](#path-3-windows-with-wsl2) |
| An Ubuntu 24.04 server | [the native installer](#path-2-the-native-installer-ubuntu-2404), or Docker Compose |

Then, on every path, [the shared steps](#funding-it): funding, connecting to
sequentiatestnet.com, the registry, paying between operators. Every path runs
the same programs with the same settings and ends in the same place; only how
the programs are started differs. Docker Desktop on macOS and Windows, and the
WSL2 script, have not been run on their own systems yet, and say so where they
start; the Linux paths are the ones tested.

## What the bundle is

| Chain | Program | What it does |
| --- | --- | --- |
| Sequentia | `sequentiad` (Sequentia Core) | The chain arcad and the gateway read, with `-txindex` and `-validateanchor`: every anchor is checked against the bundle's own Bitcoin node |
| | PostgreSQL | arcad's state (and captaind's), every write-ahead log segment archived |
| | `arca-signer` | Holds the operator key and signs for arcad on a Unix socket |
| | `arcad` | The Arca operator's server: boards, transfers, rounds, the watcher |
| | SeqLN (`lightningd`) | The Sequentia gateway: one channel per served asset, with the hold-invoice plugin |
| | price server | The node's fee rates, from a price feed: an asset is accepted for fees only with a rate |
| | watchtower (`arca watchtower serve`) | Watches the coins of the peer operator's users (`PEER_ARCA_URL`): takes their sealed deposits and, should a batch be released or a sender take an earlier coin home, brings each coin on the chain under its owner's key |
| Bitcoin | `bitcoind` (Bitcoin Core) | testnet4, with a transaction index |
| | fee proxy | The node's RPC with fee estimates from the live mempool, for Bark's server and the Bitcoin gateway (testnet4's own estimates often say a sat or two while its mempool queues at tens, or nothing at all, and a gateway with no estimate refuses every channel opened to it) |
| | `captaind`, `watchmand` | Bark's server and watchman: the Bitcoin ark |
| | Bitcoin ark watchtower (`arca btc-watchtower serve`) | Takes holders' deposits of Bitcoin ark coins (each with a claim its holder signed) and, a day before a coin's expiry, brings it on chain and claims it to its holder's own address, paying the fees from its own BTC |
| | Core Lightning | The Bitcoin gateway, with Boltz's hold-invoice plugin |
| Both | Caddy | The public route over TLS: the operator at `https://<your domain>/arca`, the Bitcoin ark at `https://<your domain>` |

Its files are in [`contrib/operator-bundle/`](../contrib/operator-bundle/):
`install.sh` (the installer, and the commands every path uses: `status`,
`addresses`, `connect`, `bond`, `register`, `credentials`), `bundle.env.example` (every
setting, with what it does), `pins.env` (the version and checksum of everything
downloaded or built), `docker/` (the image and the compose file) and
`windows/setup-wsl.ps1`.

Its ports. Each listens on the machine's loopback alone, but for the two
gateways and Caddy:

| Port | Program | Reached from |
| --- | --- | --- |
| 9835 | SeqLN | anywhere: other operators' gateways and wallets open channels to it |
| 9935 | Core Lightning | anywhere: the same, on Bitcoin |
| 80, 443 | Caddy | anywhere: the certificate's challenge, and wallets |
| 3535, 3545 | arcad, captaind | this machine; others through Caddy, over TLS |
| 3537 | the watchtower | this machine; others through Caddy, at `/watchtower` |
| 3541 | the Bitcoin ark watchtower | this machine; others through Caddy, at `/btc-watchtower` |
| 18884, 48332 | the Sequentia and Bitcoin nodes' RPC | this machine |
| the rest (`bundle.env.example`) | the fee proxy, PostgreSQL, metrics, the gateways' gRPC | this machine |

Opening the two gateways' ports is safe: a Lightning node's peer port speaks
an authenticated, encrypted protocol (BOLT 8), and all a stranger can do
through it is ask for a channel. Commands reach a node only through its RPC
socket, on the machine.

### What it needs

- 4 cores, 8 GB of memory, and 60 GB of free disk: Bitcoin testnet4 with its
  transaction index is the largest part, 15 GB; the Sequentia chain about 1
  GB. The first install builds four programs from source, which takes an hour
  or more and about 10 GB of build space.
- For a public operator: a DNS name pointing at the machine, and TCP 80, 443,
  9835 and 9935 reaching it from the internet (a router's port forwarding at
  home; a cloud server's security group on a VPS).
- Testnet coins to fund it: the assets you serve and an asset accepted for
  fees, from the [faucet](https://sequentiatestnet.com/), and testnet4 BTC.

### The settings

Every path reads the same settings, described line by line in
`bundle.env.example`. What you fill in:

- `ARCA_ASSETS`, required: the assets the operator serves, each as
  `<asset id>:<smallest leaf in atoms>:<rate source>`, separated by spaces.
  Nothing is served by default, and no asset comes first: list the ones you
  hold and want to serve. The rate source is `node` (the node's own rate for
  the asset, the one it values fees in it at) or `none`. An asset's id is in
  the explorer.
- `ARCA_FEE_ASSETS`: the assets a round's fee is paid in, each accepted for
  fees by the node. Empty: those of the served assets the node accepts.
- `PRICE_FEED_URL`: where the node's fee rates come from. A node takes fees
  only in the assets it has a rate for, and a gateway opens a channel in an
  asset with a fee in that asset, so each asset served over Lightning needs a
  rate. The bundle runs the price server that comes with Sequentia Core, which
  reads the feed and the asset registry and gives the node a rate for every
  asset the feed prices: on the public testnet its own feed, with nothing to
  set. `none` turns it off; then set the rates yourself
  (`sequentia-cli setfeeexchangerates`).
- `DOMAIN`, `CONTACT_NAME`, `CONTACT_EMAIL`: the public route and who runs it.
  Without a domain the operator answers only on this machine.
- `BACKUP_DIR` (native path): where the database's write-ahead log is
  archived. Put it on other storage than the machine's disk.
- `PEER_*`, `CHANNEL_USD`, `CHANNEL_ATOMS`, `CHANNEL_SAT`: the peer bundle the
  gateways open channels to, and their sizes. `CHANNEL_USD` gives every asset's
  channel the same worth at the node's rate (1000: 1,000 of a dollar coin, a
  quarter of an ounce of a gold token); `CHANNEL_ATOMS` pairs override it per
  asset. The defaults name sequentiatestnet.com.
  `PEER_ARCA_URL` is also the operator whose users the bundle's watchtower
  watches for, and `PEER_WATCHTOWER` the watchtower that operator runs for
  this bundle's users, which arcad's `info` names to them (see
  [Watching each other's users](#watching-each-others-users)).
- `BTC_TOWER_ARKS`: the Bitcoin arks, by server key, whose coins the bundle's
  Bitcoin ark watchtower takes. Empty, any ark's.
- `BUILD_JOBS`: 2 unless the machine has more than 8 GB of memory to spare.

## Path 1: Docker Compose

Every daemon runs in a container of its own, from one image built from this
repository: all of them share one network namespace (each reaches the others
on 127.0.0.1) and the named volumes that hold the keys, the chains and the
sockets. Every key is drawn on the first start, into the `etc` volume; none is
in the image or in the compose file.

**Docker.** Linux: Docker Engine with the compose plugin
(`docker compose version`). macOS and Windows: Docker Desktop, with at least 6
GB of memory and 80 GB of disk given to it (Settings, Resources); on Windows
with the WSL2 backend. The image is `linux/amd64`, since Sequentia Core, Core
Lightning and Bark's server publish x86_64 builds: on an Apple-silicon Mac,
turn on "Use Rosetta for x86_64/amd64 emulation" in Docker Desktop's
settings, and it runs under emulation.

> **Docker Desktop on macOS and Windows has not been run.** The compose
> bundle is tested on Linux. Docker Desktop runs the same image in a Linux
> VM, so it is expected to work the same; if it does not, the native path in
> a Linux VM (Path 2), or WSL2 on Windows (Path 3), reaches the same result.

**1. The source and the settings:**

    git clone https://github.com/ConcatenaLabs/arca
    cd arca/contrib/operator-bundle/docker
    cp ../bundle.env.example bundle.env

Edit `bundle.env` as [The settings](#the-settings) says (any text editor).

**2. Build and start.** The build runs the installer's download and build
steps in the image (an hour or more the first time); `up` then starts every
service, the `init` service first, which draws the keys and writes each
daemon's configuration:

    docker compose up -d --build

**Check:**

    docker compose ps                     # every service running; init exited 0
    docker compose exec net bundle status

`status` shows both chains syncing, the operator's key and its assets, the
ark's round wallet, and both gateways answering. Each daemon's log:
`docker compose logs -f arcad` (or `sequentiad`, `captaind`, …).

In the shared steps below, `$B` is the bundle's command and `$A` its wallet:

    B="docker compose exec net bundle"
    A="docker compose exec net /opt/arca-bundle/bin/arca"

Stop and start: `docker compose stop`, `docker compose start`. A changed
`bundle.env` takes `docker compose up -d --force-recreate`. An update:
`git pull`, then `docker compose up -d --build`. The volumes keep everything
across all three; `docker compose down -v` deletes them, keys included.

On Linux, `docker-compose.host.yml` puts the bundle on the host's own network
instead, as the native installer runs it, for test chains whose nodes listen
on the host's loopback:
`LISTEN_HOST=127.0.0.1 docker compose -f docker-compose.yml -f docker-compose.host.yml up -d`.

## Path 2: the native installer (Ubuntu 24.04)

For a server with systemd. Each daemon runs as a systemd unit named
`<NAME>-<program>` (`arca-bundle-arcad`, `arca-bundle-captaind`, …), as the
system user `<NAME>`, and PostgreSQL as a cluster of its own
(`postgresql@16-arca_bundle`), all in one slice (`arca_bundle.slice`) whose
memory and CPU `BUNDLE_MEMORY_MAX` and `BUNDLE_CPU_QUOTA` can bound. As root:

**1. The installer.** It writes the settings file and stops:

    apt-get update && apt-get install -y git
    git clone https://github.com/ConcatenaLabs/arca /opt/arca-src
    /opt/arca-src/contrib/operator-bundle/install.sh

**2. The settings.** Edit `/etc/arca-bundle/bundle.env` as
[The settings](#the-settings) says.

**3. Install and start.** It downloads what has a release (each checked
against its checksum), builds the rest, draws every key on the machine into
mode-600 files, writes each daemon's configuration, and starts every unit in
order (an hour or more the first time):

    /opt/arca-src/contrib/operator-bundle/install.sh

Run the same command again after any change to `bundle.env`, or after a
`git pull` in `/opt/arca-src`, to update: what is done is found done, a key
is never drawn twice, and a daemon restarts only when its binary or its
configuration changed.

While the chains are still syncing it stops before the gateways, saying how
far the sync is: the nodes run on and keep syncing, and the same command, run
again once both have caught up, starts the gateways, Bark's server, its
watchman and arcad. (A new Sequentia node takes no block until the bundle's
Bitcoin node has synced past the Bitcoin blocks its anchors name.)

**Check:** it ends with `every unit is running`, and
`/opt/arca-src/contrib/operator-bundle/install.sh status` shows both chains
syncing, the operator's key and assets, the ark's round wallet, and both
gateways answering.

In the shared steps, as root:

    B=/opt/arca-src/contrib/operator-bundle/install.sh
    A=/opt/arca-bundle/bin/arca

| To | Run |
| --- | --- |
| Follow a daemon's log | `journalctl -fu arca-bundle-arcad`, and `/var/log/arca-bundle/` |
| Stop the operator | `systemctl stop arca-bundle-arcad arca-bundle-arca-signer` |
| Stop everything | `systemctl stop arca_bundle.slice` |
| Start everything | `systemctl start postgresql@16-arca_bundle 'arca-bundle-*'` |

Its files: settings `/etc/arca-bundle/bundle.env`; keys and configurations
`/etc/<NAME>/`; chains, data, the signer's record and the gateways' wallets
`/var/lib/<NAME>/`; logs `/var/log/<NAME>/`; binaries `/opt/<NAME>/`; the
downloads, toolchain and builds `/var/cache/arca-bundle/` (shared by every
bundle on the machine). A second bundle takes its own `NAME` and ports in its
own settings file: `BUNDLE_ENV=/etc/arca-b/bundle.env install.sh`.

## Path 3: Windows with WSL2

A WSL2 distro of Ubuntu 24.04 with systemd, set up by one PowerShell script,
then the native installer (Path 2) inside it.

> **The Windows script has not been run on Windows.** `setup-wsl.ps1` is
> written to Microsoft's documented WSL interfaces. Where it fails, each step
> below says what it does, to do by hand; or take Path 1 with Docker Desktop.

In an elevated PowerShell (Run as administrator), as the Windows user the
bundle will run under, from `contrib\operator-bundle\windows\`:

    powershell -ExecutionPolicy Bypass -File setup-wsl.ps1

Its parameters, all optional: `-Distro` (`ArcaBundle`), `-InstallDir`
(`C:\ArcaBundle`: put it on the drive with the most room), `-Ports`
(`9835, 9935, 80, 443`, matching `SEQLN_PORT` and `CLN_PORT`), `-Networking`
(`auto`: `mirrored` where Windows supports it, otherwise `nat`).

1. **WSL2.** `wsl --install --no-distribution` when WSL is missing. Restart
   Windows when it says so, and run the script again.
2. **The distro.** Ubuntu 24.04's WSL image from
   `cloud-images.ubuntu.com/wsl/releases/24.04/current/`, checked against the
   `SHA256SUMS` published beside it, imported with `wsl --import`, systemd on
   in `/etc/wsl.conf` (`[boot] systemd=true`).
3. **`%UserProfile%\.wslconfig`.** `vmIdleTimeout=-1` under `[wsl2]`, so the
   VM never shuts down for being idle; in mirrored mode also
   `networkingMode=mirrored` and `firewall=true`.
4. **The ports.** A Windows Firewall rule per port, a Hyper-V firewall rule
   per port in mirrored mode, and in NAT mode a `netsh interface portproxy`
   from the host to the distro, renewed at each start.
5. **Start at boot.** A scheduled task run at startup whether you are logged
   on or not: it starts the distro, whose systemd starts the bundle, and keeps
   it running (`wsl -d ArcaBundle --exec /bin/sleep infinity`).

**Check:** `wsl -l -v` (ArcaBundle, Running, version 2);
`wsl -d ArcaBundle -u root -- systemctl is-system-running` (running);
`Get-ScheduledTask -TaskName ArcaBundle` (Running). Then Path 2's steps
inside the distro, each prefixed with `wsl -d ArcaBundle -u root --`.

## Funding it

    $B addresses

prints an address for each part to fund, with what it is for:

- **operator-pools**: pay each served asset to it. Every round is funded from
  these coins, which stay in batches until they expire and are swept back,
  weeks later.
- **ark-rounds**: testnet4 BTC the ark's rounds are built from. Keep at least
  the ark's VTXO pool (`ARK_VTXO_POOL`, 200,000 sat) and fees: a Lightning
  receive into the ark is paid out of that pool, and with none ready it is
  failed back.
- **seqln**: each asset the gateway's channels are opened in: a channel's size
  and a little more of the same asset, since each channel is opened with its
  fee in its own asset. `addresses` lists each asset's channel size in atoms:
  `CHANNEL_USD` at the node's rate, or a `CHANNEL_ATOMS` pair where one names
  the asset. An asset the node has no rate for gets no channel under
  `CHANNEL_USD`; without `CHANNEL_USD`, `CHANNEL_ATOMS` given as pairs needs a
  pair for every served asset (`connect` says `no channel size set`).
- **cln**: testnet4 BTC for the Bitcoin gateway's channel, its anchor reserve
  (25,000 sat) and its fees.
- **btc-watchtower**: testnet4 BTC for the fees of the coins the Bitcoin ark
  watchtower brings on chain (see [Bitcoin ark coins](#bitcoin-ark-coins)).

**Check:** `$B status` shows the ark's `trusted_balance`.

**A payment that does not confirm.** Pay from a Sequentia node of your own,
and read the payment there:

    sequentia-cli gettransaction <txid>

While it waits, two fields say why: `refused` is the node's reason for not
holding it (`non-final` for a payment carrying a lock time the chain has not
reached, which a Bitcoin reorg can cause, since a Bitcoin reorg can cost
Sequentia height), and `unbroadcast: true` means no peer has fetched it in the
minute since it was sent. The node offers it to its peers again every 10 to 15
minutes, and the wallet hands a refused payment back as soon as the node takes
it, so both clear on their own. A payment that stays `unbroadcast` for long has
not reached the block producers: `sequentia-cli getpeerinfo` shows whether the
node has peers.

## Connecting to the sequentiatestnet.com bundle

The two Sequentia nodes already share one chain (a node on the testnet peers
with its public node on its own), and both Bitcoin nodes follow public
testnet4. What joins the two operators is Lightning: each of this bundle's
gateways opens a channel to the testnet bundle's gateway, in each asset both
serve and in BTC, with half of each channel pushed to the other side so
payments run both ways from the start:

    $B connect

It reads the peer's gateways from its `GET /v1/info`, refuses a peer on
another chain, opens only the channels not open yet, and refuses an asset
the node has no fee rate for (see `PRICE_FEED_URL`).

**Check:** after the funding transactions confirm, `$B status` lists each
channel `CHANNELD_NORMAL` and each asset's Lightning leg `up`.

## Posting the equivocation bond

An operator that holds other people's coins posts a bond: a coin it loses if
it ever co-signs two spends of one coin, which wallets weigh before trusting a
payment made out of round
([operator-procedure.md](operator-procedure.md#posting-the-equivocation-bond)).
One that holds only its own coins can skip it. The bundle walks through it:

    $B bond

Each run says what is still missing and stops there; run it again after each
step:

1. **What to choose**, in the settings: `BOND_WITHDRAW_KEY`, `BOND_ASSET`,
   `BOND_ATOMS` (`bundle.env.example` says what each is). The withdrawal key is
   the only key that can ever end the bond: draw it on another machine, never
   on the bundle's, with the bundle's `arcad` copied there
   (`arcad bond-key bond-withdraw.key`), and keep that file and a backup
   offline. Then run the installer again (on Docker,
   `docker compose up -d --force-recreate`): it writes `[bond]` into arcad's
   configuration and turns the Sequentia node's wallet on.
2. **What to pay:** it makes and loads the operating wallet (`BOND_WALLET`)
   and prints the address to pay the bond's asset to, and how much: the bond
   and a thousandth more for its fee.
3. **The post:** once the wallet holds enough, confirmed, it pays the bond
   (`arcad bond-post`), writes its coin into `[bond]` (kept in
   `/etc/<NAME>/bond.outpoint` across runs of the installer) and restarts
   arcad.

**Check:** `$B bond` (or `$B status`) reads the bond `bonded`, and
`https://<DOMAIN>/arca/v1/info` shows it under `bond`, `final` once its block
is final. To end a bond, the notice and the withdrawal are arcad's own
commands, signed with the withdrawal key's file
([the server's README](../server/README.md#the-equivocation-bond)).

## Listing the operator in the registry

Wallets find operators in the Sequentia registry. With `DOMAIN` and
`CONTACT_NAME` set and Caddy serving `https://<DOMAIN>/arca`:

    $B register

It writes the operator's record from its own `info` (sequentia-registry's
`tools/operator-record.js`), signs it with the operator key
(`arca-signer --sign-operator-record`, which signs that record and nothing
else), and posts it. Caddy serves the domain proof the registry may ask for
at `https://<DOMAIN>/.well-known/sequentia-operator-proof-<operator key>`. A
change to what the operator serves, charges or names takes a new record: run
`register` again.

**Check:** `$A operators --registry https://sequentiatestnet.com/registry`
lists the operator `ok`.

## Watching each other's users

The two operators watch for each other's users. A wallet deposits each coin
it holds, sealed, with the watchtowers its operator's `info` names and with
those its wallet program adds by default; a watchtower reads a deposit only
once its batch is released or a sender up the coin's lineage takes an
earlier coin home on the chain, and then brings the coin on the chain under
its owner's key. A coin is safe while any one of them acts, so each operator
runs one for the other's users, where neither depends on the other being up.

The bundle's watchtower is made at install against `PEER_ARCA_URL`, whose
users it watches for, and served at `https://<DOMAIN>/watchtower`. Its
wallet's on-chain coins pay what a coin's own reserves cannot when it acts:
fund it with an asset the node accepts for fees (`$B addresses`, the line
`watchtower`). arcad's `info` names `PEER_WATCHTOWER` to this bundle's own
users.

**An installed bundle takes it on with an update** (`git pull` in the clone,
then `$B install`, or `docker compose up -d --build`): the installer makes
the watchtower's wallet, starts it, adds the route, and names the peer's
watchtower in arcad's configuration, from the defaults in
`bundle.env.example`. A `bundle.env` written before has neither setting:
add the two lines the example holds under the peer's settings
(`PEER_WATCHTOWER`, and `WATCHTOWER_PORT` with the ports) before the update,
or the bundle runs its watchtower but names none to its users.

**Check:** `$B status` shows, under "the watchtower for the users of
https://sequentiatestnet.com/arca", its deposits and the operator it watches
for, and under the Arca operator "watchtowers it names for its users" the
peer's. From anywhere,

    curl -s https://<DOMAIN>/watchtower/v1/info

answers `"watchtower": true`, the operator key of sequentiatestnet.com and
`"sealed": 1`. Tell the sequentiatestnet.com operator that URL: its wallets
add it to the watchtowers they deposit with, and its info names it.

### Bitcoin ark coins

On a Bitcoin ark the operator may sweep the tree above a coin from the coin's
expiry, and nothing in script stops an operator that does. Every transaction
of a coin's way out is already signed, though, so anyone holding the coin's
data can bring it on chain before then, choosing nothing but the fee. A
wallet therefore deposits, with each Bitcoin ark watchtower it names, every
coin worth rescuing (at least 20 times what bringing it on chain costs, at the
rate the watchtower charges for it), together with a claim its holder signs
once: the coin to the holder's own address, less that rescue fee to the
watchtower. A
day (144 blocks) before a coin's expiry the watchtower broadcasts the coin's
transactions level by level, paying each through its anchor from its own
BTC, and once the coin's exit delay has passed it broadcasts the claim. It
also acts at once when an earlier holder of a coin paid out of round takes
that earlier coin home, which the coin must answer within its exit delay.
A wallet that spends a coin withdraws its deposit; the coin's holder signs
the withdrawal, and nobody else can make one. A coin whose exit the wallet
has started keeps its deposit until that exit is claimed, so a wallet closed
mid-exit leaves the rest to the watchtowers. A coin has a watchtower or the
ark's delegated refresh, never both: a wallet deposits only coins with no
refresh scheduled, and schedules none for the coins it deposits.

Each operator runs one for the other's users, so a holder who goes away needs
one of two watchtowers run by different operators, and neither operator's
honesty. The bundle's is `arca btc-watchtower`, made at install with its own
phrase and served at `https://<DOMAIN>/btc-watchtower`. It takes the coins of
every ark unless `BTC_TOWER_ARKS` names some. Its BTC pays the fees and the
claims pay it back, and it takes only the deposits its BTC can pay for, so
it covers about one coin per rescue's worth of BTC (about 42,000 sat at 30
sat/vB). Fund it with several separate coins (`$B addresses`, the line
`btc-watchtower`), since each fee is paid from a confirmed coin and one coin
pays one fee per block: a watchtower of one coin refuses a round's worth of
coins coming due together. Its `info` says what it can still pay for
(`capacity_sat`) and what it can bring on chain in one margin
(`exits_per_margin`). What a watchtower cannot do is listed in
[the CLI's README](../bark-cli/README.md#what-a-bitcoin-ark-watchtower-does-not-do).

**An installed bundle takes it on with an update** (`git pull` in the clone,
then `$B install`, or `docker compose up -d --build`); a `bundle.env` written
before needs no new line.

**Check:** `$B status` shows, under "the watchtower for Bitcoin ark coins",
its deposits, the BTC it holds for fees and the arks it watches. From
anywhere,

    curl -s https://<DOMAIN>/btc-watchtower/v1/info

answers `"kind": "bitcoin-ark-watchtower"`, `"network": "testnet4"`, the
payout address its rescue fees are paid to, and `capacity_sat`. Tell the sequentiatestnet.com
operator that URL: its wallets add it to the Bitcoin ark watchtowers they
deposit with.

On its own machine, `arca --datadir /var/lib/arca-bundle/btc btc-watchtower
deposits` lists every deposit with its state: `waiting`, `rescuing` (its
transactions going on chain), `claiming` (waiting out the exit delay),
`claimed`, or `taken` (the coin was spent another way: its holder had given it
up and the operator answered with what the holder signed, which costs the
watchtower the fees it paid and the holder nothing).

## Paying between the two operators

Two wallets, one joined to each operator, each reading the chain through this
bundle's node. The asset is one both operators serve over Lightning:

    W=/var/lib/arca-bundle/wallets
    COOKIE=/var/lib/arca-bundle/sequentia/testnet3/.cookie
    $A --datadir $W/mine create --server http://127.0.0.1:3535 \
        --node-url http://127.0.0.1:18884/ --node-cookie $COOKIE
    $A --datadir $W/theirs create --server https://sequentiatestnet.com/arca \
        --node-url http://127.0.0.1:18884/ --node-cookie $COOKIE

Fund `mine` (`$A --datadir $W/mine address`), board it
(`$A --datadir $W/mine board <asset> <atoms>`, spendable once final), then:

    $A --datadir $W/theirs lightning receive <asset> 100000000    # an invoice
    $A --datadir $W/mine lightning pay <invoice> --wait 120       # through this gateway to theirs
    $A --datadir $W/theirs sync                                   # the leaf, claimed

and back, the other way round. The receiving operator holds the payment
until its next round makes the receiver's leaf, and the receiver's wallet
claims it when it syncs, so until then the payer's wallet reads `paying` and
the receiver's `issuing`: a round and its block, about a minute on the public
testnet, longer while the receiving operator restarts. A receiver that stays
offline lets the payment fail back to the payer before its lock ends.

On Bitcoin, each wallet joins its operator's
Bitcoin ark, and the receiver claims while the payer pays:

    BCOOKIE=/var/lib/arca-bundle/bitcoin/testnet4/.cookie
    $A --datadir $W/mine bitcoin create --testnet4 --ark http://127.0.0.1:3545 \
        --bitcoind http://127.0.0.1:48342 --bitcoind-cookie $BCOOKIE
    $A --datadir $W/theirs bitcoin create --testnet4 --ark https://sequentiatestnet.com \
        --bitcoind http://127.0.0.1:48342 --bitcoind-cookie $BCOOKIE
    $A --datadir $W/theirs lightning receive btc 2000                 # an invoice
    $A --datadir $W/theirs lightning claim <invoice> --wait 300 &     # claims while the payer pays
    $A --datadir $W/mine lightning pay <invoice>                      # paid, with its preimage

A Bitcoin ark wallet boards from its own on-chain address first
(`$A --datadir $W/mine bitcoin -- onchain address`, then
`$A --datadir $W/mine bitcoin -- board "60000 sat"`).

**What a payment between operators can lock.** An operator's invoice for a
payment into its tree carries a final lock of about 5,790 blocks (four days at
a minute a block) at the specification's exit delays, so the paying operator
must let a payment out of its tree stay unresolved that long: the bundle sets
`ARCA_SEND_TIMEOUT` to nine days. That costs nothing while payments settle,
as they do within a round. A payment that gets stuck on its way (a gateway that
holds the HTLC and never answers) keeps the payer's coins until its timeout,
up to eighteen days, and then they come back to the payer; meanwhile the
payer's wallet shows the payment `paying`, never `failed`, since it follows
what the operator says. Bitcoin is the same in miniature: a Bark ark lets a
payment lock up to 258 blocks, which another ark's 184-block invoice needs.

## A Lightning wallet beside it

**Fulmen**, the SeqLN desktop wallet, runs its own Lightning node and reads
the chains through this bundle's nodes, with the logins `$B credentials`
prints (both nodes' RPC are on this machine's 127.0.0.1 on every path; on
Windows all WSL2 distros share one network). Installing it and opening its
channels to an operator's gateways:
[Fulmen's README](https://github.com/ConcatenaLabs/fulmen#connecting-to-an-operators-gateways).
Fulmen ships for Linux (AppImage) and Windows (WSL2).

**Without Fulmen** (macOS, or anywhere else): the same channels and payments
are made with SeqLN for the assets and Core Lightning for BTC on the command
line, step by step, natively or in containers of this bundle's image:
[operator-gateways-cli.md](https://github.com/ConcatenaLabs/fulmen/blob/master/docs/operator-gateways-cli.md).
Generic Core Lightning interfaces (RTL over clnrest, for one) drive the BTC
node fully, but cannot show or choose a channel's asset on SeqLN.

## What it costs

Measured on the runs that test the bundle, with what each figure is:

| | The bundle at rest | Under load |
| --- | --- | --- |
| Memory | about 170 MB for every daemon together, on regtest chains (PostgreSQL 55 MB, Core Lightning 26 MB, SeqLN 17 MB, the nodes 12–16 MB each); the two nodes' caches grow with the public chains, and `dbcache=300` bounds the Bitcoin node's | the operator's server 1.0–2.4 GB at 8 to 16 transfers in flight, about 530 MB more per thousand holders ([the load test](operator-bundle-tests.md#load)) |
| CPU | a sixth of one core (PostgreSQL's WAL timer, arcad's polls) | the operator's server 0.4–2.4 cores; the first limit, at about 15 transfers a second, is the shared node's RPC queue, not the server |
| Disk | Bitcoin testnet4 with its transaction index 15 GB; the Sequentia chain under 1 GB; the binaries 0.8 GB; the database archive about 200 KB per WAL segment, a segment at least every five minutes | about 36 MB more database per thousand holders |
| To install | the native build cache 7 GB in `/var/cache/arca-bundle` (delete it once installed); the Docker image 2.1 GB (611 MB compressed) and a build that needs about 10 GB while it runs | |

Fulmen, beside it: its Lightning node is a SeqLN node like the bundle's
gateways (about 20 MB at rest); the Linux AppImage is about 150 MB, and on
Windows its WSL distro about 150 MB.

## Running it

**What it commits you to.** Every round is funded from your own coins, locked
in batches until they expire. Every payment and refresh needs your
co-signature, and your watcher answers stale exits: while the operator is
down its holders can only take their coins home on the chain. Holders refresh
or exit each coin before its exit deadline, three days before its batch
expires: keep the operator running, and announce any end of service far
ahead.

**BTC past its expiry, on the Bitcoin ark.** A Bitcoin ark coin lives a fixed
number of blocks (`vtxo_lifetime`), after which the watchman sweeps what is
left of its batch back to your server's wallet; without covenants on Bitcoin
that sweep is how the server gets its capital back, and it cannot be turned
off. Wallets renew each coin before then: while they are open, and through a
renewal they hand your server ahead of time, which it runs by itself shortly
before the expiry. The policy every operator running this bundle keeps, and
says so to its users: **an expired coin is taken back in a round when its
holder returns.** The holder's wallet asks for the coin's refresh, your server
includes it in a round as a new coin, less the refresh fee, however long the
holder was away. Bark's server does this as it ships; your part is to keep its
database (back it up as above) and never to refuse such a refresh. It is a
promise, not a rule in script: a server that loses its database, or an
operator who stops keeping it, keeps the expired coins. A holder who wants to
depend on no promise takes the coin to the chain before it expires; the
wallets do that by themselves when your server stops renewing a coin that is
worth its exit.

**Back up**, to offline media, apart from the machine: `operator.key`,
`wallet.mnemonic` (in `/etc/arca-bundle/`, the `etc` volume with Docker),
`captaind/mnemonic`, and each gateway's `hsm_secret` (`seqln/<network>/` and
`cln/<network>/`, under `/var/lib/arca-bundle/`, the `lib` volume). The
signer's record is never restored from a copy. The database archives every
write-ahead log segment, compressed, into `BACKUP_DIR/wal` (the `backup`
volume) as it is written, at least every five minutes: take a base backup
from time to time (`pg_basebackup`), and remove the segments older than it
with `pg_archivecleanup`, or the archive grows by about the database's write
rate.

**When it goes down, and how much it carries.**
[Testing an operator](operator-bundle-tests.md) runs an operator under load to
its first limit, and stops it at chosen moments (idle, mid-payment, mid-round,
mid-swap, mid cross-chain swap, the Bitcoin ark down): for each, what its
holders see, what refunds when, and how each takes its coins home alone. The
tests in `contrib/operator-bundle/test/` run against a bundle, never against
anyone else's operator.

**Keepers.** The bundle makes the signer's record without keepers, which suits
an operator holding its own coins and test operators. An operator that holds
other people's coins runs with three keepers on machines of their own, two
required, as [the operator's procedure](operator-procedure.md) sets out.

**Test chains.** The bundle also runs on test chains, which is how it is
tested without the public networks: `BTC_CHAIN=regtest`, a custom Sequentia
chain in `SEQ_CHAIN` with its consensus settings in `SEQ_CHAIN_CONF` (one per
line, or separated by `;`, the same on every node of that chain), and
`SEQ_ADDNODE` / `BTC_ADDNODE` naming a node of each chain to connect to.
