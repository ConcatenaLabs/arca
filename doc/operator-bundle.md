# Running an operator bundle on Windows

This runbook sets up an **operator bundle** on one Windows machine (Windows
10 or 11, or Windows Server), connects it to the Sequentia testnet's own
bundle at sequentiatestnet.com, and pays between the two. Every command is
written out; every value you fill in is named where you need it, and each
stage ends with the check that shows it worked. The same installer runs on
any Ubuntu 24.04 server with systemd: there, skip the Windows part and start
at [Installing the bundle](#installing-the-bundle).

The files it uses live beside it in this repository:

| File | What it is |
| --- | --- |
| [`contrib/operator-bundle/windows/setup-wsl.ps1`](../contrib/operator-bundle/windows/setup-wsl.ps1) | The Windows side: WSL2, the Ubuntu 24.04 distro with systemd, the ports, start at boot |
| [`contrib/operator-bundle/install.sh`](../contrib/operator-bundle/install.sh) | The installer, run inside the distro: installs, configures and starts the whole bundle |
| [`contrib/operator-bundle/bundle.env.example`](../contrib/operator-bundle/bundle.env.example) | Every setting, with what it does |
| [`contrib/operator-bundle/pins.env`](../contrib/operator-bundle/pins.env) | The version and checksum of everything the installer downloads or builds |

> **Testnet software.** The bundle runs on the Sequentia testnet and Bitcoin
> testnet4 and refuses Bitcoin's main network. Do not use it with anything of
> value.

> **The Windows script has not been run on Windows.** `setup-wsl.ps1` is
> written to Microsoft's documented WSL interfaces but has not been executed
> on a Windows machine. The Linux half (everything inside the distro) is
> what runs and is tested; where the Windows script fails, the manual steps in
> each section below do the same thing.

## What the bundle is

A bundle runs an operator on both chains:

| Chain | Program | What it does |
| --- | --- | --- |
| Sequentia | `sequentiad` (Sequentia Core) | The chain arcad and the gateway read, with `-txindex` and `-validateanchor`: every anchor is checked against the bundle's own Bitcoin node |
| | PostgreSQL | arcad's state (and captaind's), in a cluster of the bundle's own, every write-ahead log segment archived |
| | `arca-signer` | Holds the operator key and signs for arcad on a Unix socket |
| | `arcad` | The Arca operator's server: boards, transfers, rounds, the watcher |
| | SeqLN (`lightningd`) | The Sequentia gateway: one channel per served asset, with the hold-invoice plugin |
| Bitcoin | `bitcoind` (Bitcoin Core) | testnet4, with a transaction index |
| | fee proxy | The node's RPC with fee estimates from the live mempool (testnet4's own estimates often say a sat or two while its mempool queues at tens) |
| | `captaind`, `watchmand` | Bark's server and watchman: the Bitcoin ark |
| | Core Lightning | The Bitcoin gateway, with Boltz's hold-invoice plugin |
| Both | Caddy | The public route over TLS: the operator at `https://<your domain>/arca`, the Bitcoin ark at `https://<your domain>` |

Each runs as a systemd unit named `<NAME>-<program>` (`arca-bundle-arcad`,
`arca-bundle-captaind`, …), as the system user `<NAME>`, and PostgreSQL as
`postgresql@16-<NAME with underscores>` (`postgresql@16-arca_bundle`), all in
one systemd slice, `<NAME with underscores>.slice`, whose memory and CPU
`BUNDLE_MEMORY_MAX` and `BUNDLE_CPU_QUOTA` can bound. Its files:

| What | Where |
| --- | --- |
| Settings | `/etc/arca-bundle/bundle.env` |
| Keys and configuration: `operator.key`, `wallet.mnemonic`, the nodes' RPC passwords (mode 600) and every daemon's configuration | `/etc/<NAME>/` |
| Chains, databases' data, the signer's record (`arca/signer.record`), the gateways' wallets (`seqln/`, `cln/`, each with its `hsm_secret`), captaind's key (`captaind/mnemonic`) | `/var/lib/<NAME>/` |
| Logs | `/var/log/<NAME>/` and `journalctl -u <NAME>-<program>` |
| Binaries | `/opt/<NAME>/` |
| Downloads, the Rust toolchain and the builds, shared by every bundle on the machine | `/var/cache/arca-bundle/` |

Its ports. All of them listen on 127.0.0.1 alone, but for the two gateways
and Caddy:

| Port | Program | Reached from |
| --- | --- | --- |
| 9835 | SeqLN | anywhere: other operators' gateways and wallets open channels to it |
| 9935 | Core Lightning | anywhere: the same, on Bitcoin |
| 80, 443 | Caddy | anywhere: the certificate's challenge, and wallets |
| 48333 | Bitcoin Core peer-to-peer | anywhere (outbound peers are enough; open it to serve others) |
| 18884, 18885, 48332, 48342, 5433, 3535, 3536, 3545–3547, 9937, 9938 | the nodes' RPC, the fee proxy, PostgreSQL, arcad, captaind, the gateways' gRPC | this machine only |

Opening the two gateways' ports is safe: a Lightning node's peer port speaks
an authenticated, encrypted protocol (BOLT 8), and all a stranger can do
through it is ask for a channel. Commands reach a node only through its RPC
socket on the machine. arcad and captaind are reached from outside only
through Caddy, over TLS.

## What it needs

- Windows 10 version 2004 or later, Windows 11, or Windows Server 2022 or
  later, with hardware virtualisation on in the firmware. Mirrored
  networking (the simplest) needs Windows 11 22H2 or later, or Windows
  Server 2025; older versions forward ports instead.
- 4 cores and 8 GB of memory (the first install builds four programs from
  source; the running bundle uses about 2 GB), and 60 GB of free disk on the
  drive the distro lives on: Bitcoin testnet4 with its transaction index is
  the largest part (15 GB).
- For a public operator: a DNS name pointing at the machine, and TCP 80, 443,
  9835 and 9935 forwarded to it from the internet (a router's port
  forwarding at home; a cloud server's security group on a VPS).
- Testnet coins to fund it: tSEQ or another asset accepted for fees, and the
  assets you serve, from the [faucet](https://sequentiatestnet.com/), and
  testnet4 BTC.

## The Windows side

In an elevated PowerShell (Run as administrator), as the Windows user the
bundle will run under, from a copy of this repository's
`contrib/operator-bundle/windows/` directory:

    powershell -ExecutionPolicy Bypass -File setup-wsl.ps1

It takes these parameters, all optional:

| Parameter | Default | What it is |
| --- | --- | --- |
| `-Distro` | `ArcaBundle` | The WSL distro's name |
| `-InstallDir` | `C:\ArcaBundle` | Where the distro's disk lives: put it on the drive with the most room |
| `-Ports` | `9835, 9935, 80, 443` | The ports opened to the outside: they must match `SEQLN_PORT` and `CLN_PORT` in `bundle.env` |
| `-Networking` | `auto` | `mirrored` where Windows supports it, otherwise `nat`; `nat` forces the port proxy |

What it does:

1. **WSL2.** `wsl --install --no-distribution` when WSL is missing. Restart
   Windows when it says so, and run the script again.
2. **The distro.** Downloads Ubuntu 24.04's WSL image from
   `cloud-images.ubuntu.com/wsl/releases/24.04/current/`, checks it against
   the `SHA256SUMS` published beside it, imports it (`wsl --import`), and
   turns systemd on in `/etc/wsl.conf` (`[boot] systemd=true`).
3. **`%UserProfile%\.wslconfig`.** `vmIdleTimeout=-1` under `[wsl2]`, so the
   VM never shuts down for being idle, and in mirrored mode
   `networkingMode=mirrored` and `firewall=true`.
4. **The ports.** A Windows Firewall rule per port, a Hyper-V firewall rule
   per port in mirrored mode, and in NAT mode a `netsh interface portproxy`
   from the host to the distro, renewed at each start since the distro's
   address changes.
5. **Start at boot.** A scheduled task named after the distro, run at startup
   whether you are logged on or not: it starts the distro, whose systemd
   starts the bundle, and keeps it running (`wsl -d ArcaBundle --exec
   /bin/sleep infinity`).

**Check:**

    wsl -l -v                                          # ArcaBundle, Running, version 2
    wsl -d ArcaBundle -u root -- systemctl is-system-running   # running (or degraded)
    Get-ScheduledTask -TaskName ArcaBundle             # State: Running

## Installing the bundle

Inside the distro, as root. On Windows, prefix each command with
`wsl -d ArcaBundle -u root --`, or open a shell in it with
`wsl -d ArcaBundle -u root`.

**1. The installer.** It writes the settings file and stops:

    apt-get update && apt-get install -y git
    git clone https://github.com/ConcatenaLabs/arca /opt/arca-src
    /opt/arca-src/contrib/operator-bundle/install.sh

**2. The settings.** Edit `/etc/arca-bundle/bundle.env`
(`nano /etc/arca-bundle/bundle.env`). What you fill in:

- `ARCA_ASSETS`, required: the assets the operator serves, each as
  `<asset id>:<smallest leaf in atoms>:<rate source>`, separated by spaces.
  Nothing is served by default, and no asset comes first: list the ones you
  hold and want to serve. The rate source is `node` (the node's own rate for
  the asset, the one it values fees in it at) or `none`. An asset's id is in
  the explorer, or `sequentia-cli dumpassetlabels` on any wallet node.
- `ARCA_FEE_ASSETS`: the assets a round's fee is paid in, each accepted for
  fees by the node. Empty: those of the served assets the node accepts.
- `DOMAIN`, `CONTACT_NAME`, `CONTACT_EMAIL`: the public route and who runs it.
  Without a domain the operator answers only on this machine.
- `BACKUP_DIR`: where the database's write-ahead log is archived. Put it on
  other storage than the distro's disk, such as a second drive mounted in
  the distro.
- `PEER_*`, `CHANNEL_ATOMS`, `CHANNEL_SAT`: the peer bundle the gateways open
  channels to, and their sizes. The defaults name sequentiatestnet.com.
- `BUILD_JOBS`: 2 unless the machine has more than 8 GB of memory to spare.

**3. Install and start.** The first run downloads Sequentia Core, Bitcoin
Core, Core Lightning, Bark's server and Caddy (each checked against its
checksum), installs the Rust toolchain, and builds arcad and arca-signer,
Bark's client, the hold-invoice plugin and SeqLN: an hour or more. It then
draws every key on the machine (the operator key, the operator wallet's
mnemonic, the nodes' RPC passwords; captaind and the two gateways draw their
own), writes each daemon's configuration, makes the PostgreSQL cluster and
starts every unit in order:

    /opt/arca-src/contrib/operator-bundle/install.sh

Run the same command again after any change to `bundle.env`, or after a
`git pull` in `/opt/arca-src`, to update: what is done is found done, a key
is never drawn twice, and a daemon restarts only when its binary or its
configuration changed. `install.sh build` does only the downloads and the
builds.

**Check:** it ends with `every unit is running`, and

    /opt/arca-src/contrib/operator-bundle/install.sh status

shows every unit `active`, both chains syncing, the operator's key and its
assets, the ark's round wallet, and both gateways answering.

**Sync.** Both nodes now catch up with their chains: the Sequentia node from
the testnet's public node (it peers with it on its own, with no setting), and
the Bitcoin node from testnet4's public peers. `status` shows how far each
is. arcad takes no work until its node is synced; the Bitcoin node takes the
longest.

## Funding it

    /opt/arca-src/contrib/operator-bundle/install.sh addresses

prints four addresses:

- **The operator's pools**: pay each served asset to it. Every round is funded
  from these coins, which stay in batches until they expire and are swept
  back, weeks later.
- **The Bitcoin ark's round wallet**: testnet4 BTC its rounds are built from.
- **The SeqLN gateway**: each asset its channels are opened in, plus a little
  of a fee asset.
- **The Bitcoin gateway**: testnet4 BTC for its channel and its fees.

**Check:** `status` shows the ark's `trusted_balance`, and the gateways'
funds (`lightning-cli listfunds`).

## Connecting to the sequentiatestnet.com bundle

The two Sequentia nodes already share one chain, and both Bitcoin nodes
follow public testnet4. What joins the two operators is Lightning: each of
this bundle's gateways opens a channel to the testnet bundle's gateway, in
each asset both serve and in BTC, with half of each channel pushed to the
other side so payments run both ways from the start:

    /opt/arca-src/contrib/operator-bundle/install.sh connect

It reads the peer's gateways' keys from its `GET /v1/info`, refuses a peer on
another chain, and opens only the channels not open yet.

**Check:** after the funding transactions confirm (a few blocks on each
chain), `status` lists each channel `CHANNELD_NORMAL`, and arcad's `info`
shows each asset's Lightning leg `up`:

    curl -s http://127.0.0.1:3535/v1/info | jq '.assets[] | {asset, lightning}'

## Listing the operator in the registry

Wallets find operators in the Sequentia registry. With `DOMAIN` and
`CONTACT_NAME` set and Caddy serving `https://<DOMAIN>/arca`:

    /opt/arca-src/contrib/operator-bundle/install.sh register

It writes the operator's record from its own `info`
(sequentia-registry's `tools/operator-record.js`), signs it with the
operator key (`arca-signer --sign-operator-record`, which signs that record
and nothing else), and posts it. Caddy serves the domain proof the registry
may ask for at
`https://<DOMAIN>/.well-known/sequentia-operator-proof-<operator key>`. A
change to what the operator serves, charges or names takes a new record:
run `register` again.

**Check:** `arca operators --registry https://sequentiatestnet.com/registry`
lists the operator `ok`.

## Paying between the two operators

Two wallets, one joined to each operator. `arca` is in `/opt/<NAME>/bin`;
each wallet reads the chain through this bundle's node, as root (who can
read the node's cookie). The asset is one both operators serve over
Lightning.

    A=/opt/arca-bundle/bin/arca
    COOKIE=/var/lib/arca-bundle/sequentia/testnet3/.cookie
    $A --datadir ~/w-mine create --server http://127.0.0.1:3535 \
        --node-url http://127.0.0.1:18884/ --node-cookie $COOKIE
    $A --datadir ~/w-theirs create --server https://sequentiatestnet.com/arca \
        --node-url http://127.0.0.1:18884/ --node-cookie $COOKIE

Fund `w-mine` (`$A --datadir ~/w-mine address`), board it
(`$A --datadir ~/w-mine board <asset> <atoms>`, spendable once final), then:

    $A --datadir ~/w-theirs lightning receive <asset> 100000     # an invoice
    $A --datadir ~/w-mine lightning pay <invoice> --wait 60      # paid: through this gateway to theirs
    $A --datadir ~/w-theirs sync                                 # the leaf, claimed

and back, the other way round. On Bitcoin, each wallet joins its operator's
Bitcoin ark and pays the other's invoice:

    BCOOKIE=/var/lib/arca-bundle/bitcoin/testnet4/.cookie
    $A --datadir ~/w-mine bitcoin create --testnet4 --ark http://127.0.0.1:3545 \
        --bitcoind http://127.0.0.1:48332 --bitcoind-cookie $BCOOKIE
    $A --datadir ~/w-theirs bitcoin create --testnet4 --ark https://sequentiatestnet.com \
        --bitcoind http://127.0.0.1:48332 --bitcoind-cookie $BCOOKIE
    $A --datadir ~/w-theirs lightning receive btc 2000          # an invoice
    $A --datadir ~/w-theirs lightning claim <invoice> --wait 300 &   # claims while the payer pays
    $A --datadir ~/w-mine lightning pay <invoice>                # paid, with its preimage

A Bitcoin ark wallet boards from its own on-chain address first
(`$A --datadir ~/w-mine bitcoin address`, then `bitcoin board`).

## A Lightning wallet beside it: Fulmen

Fulmen, the SeqLN desktop wallet, runs its own Lightning node on Windows in a
WSL distro of its own, and reads the chains through this bundle's nodes (all
WSL2 distros share one network, so `127.0.0.1` reaches them). The logins it
needs:

    /opt/arca-src/contrib/operator-bundle/install.sh credentials

Installing it and opening its channels to an operator's gateways is
described in [Fulmen's README](https://github.com/ConcatenaLabs/fulmen#connecting-to-an-operators-gateways).
Where Fulmen does not run, the same channels and payments are made with
SeqLN and Core Lightning on the command line:
[operator-gateways-cli.md](https://github.com/ConcatenaLabs/fulmen/blob/master/docs/operator-gateways-cli.md).

## Running it

| To | Run |
| --- | --- |
| See everything | `install.sh status` |
| Follow a daemon's log | `journalctl -fu arca-bundle-arcad` (or `-sequentiad`, `-captaind`, …), and `/var/log/arca-bundle/` |
| Stop the operator | `systemctl stop arca-bundle-arcad arca-bundle-arca-signer` (arcad stops on SIGINT, the signer on SIGTERM; the units send each its own) |
| Stop everything | `systemctl stop arca_bundle.slice` |
| Start everything | `systemctl start postgresql@16-arca_bundle 'arca-bundle-*'` |
| Serve another asset | add it to `ARCA_ASSETS` and run `install.sh` (arcad takes it on SIGHUP, without a restart) |
| Update | `git -C /opt/arca-src pull && /opt/arca-src/contrib/operator-bundle/install.sh` |

**What running it commits you to.** Every round is funded from your own
coins, locked in batches until they expire. Every payment and refresh needs
your co-signature, and your watcher answers stale exits: while the operator is
down its holders can only take their coins home on the chain. Holders refresh
or exit each coin before its exit deadline, three days before its batch
expires: keep the operator running, and announce any end of service far
ahead. [What happens when an operator goes down](operator-bundle-tests.md)
shows each case.

**Back up**, to offline media, apart from the machine: `/etc/<NAME>/operator.key`,
`/etc/<NAME>/wallet.mnemonic`, `/var/lib/<NAME>/captaind/mnemonic`, and each
gateway's `hsm_secret` (`/var/lib/<NAME>/seqln/<network>/hsm_secret`,
`/var/lib/<NAME>/cln/<network>/hsm_secret`). The signer's record is never
restored from a copy.

**Keepers.** The installer makes the signer's record without keepers, which
suits an operator holding its own coins and test operators. An operator that
holds other people's coins runs with three keepers on machines of their own,
two required, as [the operator's procedure](operator-procedure.md) sets out.

## Two bundles on one machine, and test chains

Each bundle takes its own `NAME` and its own set of ports in its own settings
file: `BUNDLE_ENV=/etc/arca-b/bundle.env install.sh`. They share the
downloads and builds in `/var/cache/arca-bundle/`, and nothing else: their
users, directories, units and PostgreSQL clusters are their own.

The installer also runs on test chains, which is how it is tested without the
public networks: `BTC_CHAIN=regtest`, a custom Sequentia chain in `SEQ_CHAIN`
with its consensus settings in `SEQ_CHAIN_CONF` (one per line, the same on
every node of that chain), and `SEQ_ADDNODE` / `BTC_ADDNODE` naming a node of
each chain to connect to.
