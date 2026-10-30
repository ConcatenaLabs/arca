# The operator bundle

Everything an Arca operator runs, on both chains, on one machine (Linux,
macOS or Windows): the
Sequentia and Bitcoin nodes, PostgreSQL, `arcad` and `arca-signer`, Bark's
`captaind` and `watchmand`, and a Lightning gateway on each chain (SeqLN for
the assets, Core Lightning for BTC). [doc/operator-bundle.md](../../doc/operator-bundle.md)
is the runbook: how to install it, fund it, connect it to another operator
and run it.

| File | What it is |
| --- | --- |
| `install.sh` | The installer for an Ubuntu 24.04 machine with systemd (a server, or a WSL2 distro on Windows), and the commands every path uses (`status`, `addresses`, `connect`, `register`, `credentials`) |
| `docker/Dockerfile`, `docker/docker-compose.yml` | The bundle in containers, one per daemon, for any system with Docker; `docker/bundle-run` is each container's entrypoint, and `docker/docker-compose.host.yml` puts the bundle on a Linux host's own network |
| `bundle.env.example` | Every setting, with what it does |
| `pins.env` | The version and checksum of every download and the commit of every build |
| `fee-proxy.py` | The Bitcoin node's RPC with fee estimates from the live mempool, for `captaind` and `watchmand` |
| `patches/bark-testnet4.patch` | Adds testnet4 to the networks Bark's client lists, and lets a testnet4 wallet pay its network's invoices |
| `patches/hold-testnet4.patch` | Lets Boltz's [hold-invoice plugin](https://github.com/BoltzExchange/hold) run on testnet4 |
| `windows/setup-wsl.ps1` | The Windows side: WSL2, the distro, the ports, start at boot |

Bark is Second's, under its MIT licence; the hold-invoice plugin is Boltz's,
under its own. The installer downloads and builds them at the pinned commits
and applies the two patches above, which change nothing else.
