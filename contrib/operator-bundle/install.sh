#!/usr/bin/env bash
# install.sh: an Arca operator bundle on one Ubuntu 24.04 machine with systemd
# (a server, or a WSL2 distro on Windows), on both chains:
#
#   Sequentia: a Sequentia Core node (-txindex -validateanchor), PostgreSQL,
#              arcad and arca-signer, and a SeqLN gateway node for the assets
#              the operator serves over Lightning;
#   Bitcoin:   a Bitcoin Core node, its fee proxy, Bark's server (captaind)
#              and watchman (watchmand), and a Core Lightning gateway with
#              Boltz's hold-invoice plugin.
#
# Run as root from a clone of ConcatenaLabs/arca: the operator's server is built
# from that clone's checked-out commit, everything else from pins.env.
#
#   contrib/operator-bundle/install.sh [install]   install, configure and start; again to update
#   contrib/operator-bundle/install.sh build       only download and build (the longest part), nothing configured or started
#   contrib/operator-bundle/install.sh status      what runs, how far each node has synced, what each holds
#   contrib/operator-bundle/install.sh addresses   where to pay the pools and the gateways
#   contrib/operator-bundle/install.sh connect     open the gateways' channels to the peer bundle's
#   contrib/operator-bundle/install.sh register    list the operator in the registry
#   contrib/operator-bundle/install.sh credentials the nodes' RPC logins for a Lightning wallet beside them
#
# Settings: /etc/arca-bundle/bundle.env (BUNDLE_ENV names another file),
# documented in bundle.env.example. Every step can run again: what is done is
# found done, a key is drawn once and never replaced, and a daemon restarts
# only when its binary or its configuration changed.
set -Eeuo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
ARCA_SRC=$(cd "$HERE/../.." && pwd)
BUNDLE_ENV=${BUNDLE_ENV:-/etc/arca-bundle/bundle.env}
CMD=${1:-install}

STEP=start
trap 'printf "\nSTOPPED in step \"%s\" (line %s): %s\n" "$STEP" "$LINENO" "$BASH_COMMAND" >&2' ERR
step() { STEP="$*"; printf '\n=== %s ===\n' "$*"; }
say()  { printf '  %s\n' "$*"; }
die()  { printf '\nSTOPPED in step "%s": %s\n' "$STEP" "$*" >&2; exit 1; }
sha256_of() { local x; x=$(sha256sum "$1"); printf '%s\n' "${x%% *}"; }

# --- settings ------------------------------------------------------------------
[ "$(id -u)" = 0 ] || die "run it as root (sudo $0 $CMD)"
if [ ! -f "$BUNDLE_ENV" ]; then
  install -d -m 755 "$(dirname "$BUNDLE_ENV")"
  install -m 644 "$HERE/bundle.env.example" "$BUNDLE_ENV"
  printf '\nWrote %s from bundle.env.example. Fill in ARCA_ASSETS (and DOMAIN for a public\nroute), then run %s again.\n' "$BUNDLE_ENV" "$0"
  exit 0
fi
# shellcheck disable=SC1090
. "$BUNDLE_ENV"
# shellcheck disable=SC1091
. "$HERE/pins.env"
: "${NAME:=arca-bundle}" "${SEQ_CHAIN:=test}" "${BTC_CHAIN:=testnet4}" "${BUILD_JOBS:=2}"
: "${ARCA_ASSETS:=}" "${ARCA_FEE_ASSETS:=}" "${ARCA_EXIT_DELAY_UNITS:=254 338}" "${ARCA_ROUND_INTERVAL:=60}" "${ARCA_SEND_TIMEOUT:=777600}"
: "${DOMAIN:=}" "${CONTACT_NAME:=}" "${CONTACT_EMAIL:=}" "${REGISTRY_URL:=https://sequentiatestnet.com/registry}"
: "${PEER_ARCA_URL:=}" "${PEER_HOST:=}" "${PEER_SEQLN_PORT:=19850}" "${PEER_BTC_LN_PORT:=19746}"
: "${PEER_WATCHTOWER:=}" "${WATCHTOWER_PORT:=3537}" "${BTC_WATCHTOWER_PORT:=3541}" "${BTC_TOWER_ARKS:=}"
: "${CHANNEL_ATOMS:=2000000000}" "${CHANNEL_SAT:=1000000}" "${PEER_SEQLN_ID:=}" "${PEER_BTC_LN_ID:=}"
: "${SEQ_RPC_PORT:=18884}" "${SEQ_P2P_PORT:=18885}" "${BTC_RPC_PORT:=48332}" "${BTC_P2P_PORT:=48333}" "${FEE_PROXY_PORT:=48342}"
: "${PG_PORT:=5433}" "${ARCAD_PORT:=3535}" "${ARCAD_METRICS_PORT:=3536}" "${SEQLN_PORT:=9835}" "${CLN_PORT:=9935}"
: "${CLN_GRPC_PORT:=9937}" "${HOLD_GRPC_PORT:=9938}" "${CAPTAIND_PORT:=3545}" "${CAPTAIND_ADMIN_PORT:=3546}" "${CAPTAIND_INTEGRATION_PORT:=3547}"
# A test chain (README: "A rehearsal on test chains"): the custom chain's
# consensus settings, one per line; a node each chain's node connects to; and
# the anchor's parent node, when it is not this bundle's Bitcoin node.
: "${SEQ_CHAIN_CONF:=}" "${SEQ_ADDNODE:=}" "${BTC_ADDNODE:=}" "${SEQ_ANCHOR_RPC:=}" "${SEQ_ANCHOR_AUTH:=}"
: "${SEQLN_NETWORK:=}" "${BTC_FEE_FLOOR:=30}"
# The Bitcoin blocks that must bury a certified block's anchor before the
# operator, and the wallets that use it, call a coin in it final: 0 on the
# public testnet, where a coin is tradeable once its block is certified, and 2
# on any other chain.
[ "$SEQ_CHAIN" = test ] && : "${ARCA_ANCHOR_DEPTH:=0}"
: "${ARCA_ANCHOR_DEPTH:=2}"
# Limits on everything the bundle runs together (a systemd slice): empty for none.
# Where the operator, the ark and the nodes' RPC listen: 127.0.0.1 on a machine;
# all addresses in a container, whose ports the compose file publishes to the
# host's loopback alone.
: "${LISTEN_HOST:=127.0.0.1}"
: "${BUNDLE_MEMORY_MAX:=}" "${BUNDLE_CPU_QUOTA:=}" "${ARK_VTXO_POOL:=10000sat:10 50000sat:2}"
# The equivocation bond ($0 bond): its withdrawal key, drawn on another
# machine; its asset and size; the notice before a withdrawal; and the node
# wallet it is paid from. With a withdrawal key set, the node's wallet is on.
: "${BOND_WITHDRAW_KEY:=}" "${BOND_ASSET:=}" "${BOND_ATOMS:=}" "${BOND_NOTICE_UNITS:=5232}" "${BOND_WALLET:=operating}"
[ -z "$BOND_WITHDRAW_KEY" ] || [[ $BOND_WITHDRAW_KEY =~ ^[0-9a-f]{64}$ ]] || die "BOND_WITHDRAW_KEY is the withdraw_key arcad bond-key prints (64 hex characters)"
[ -z "$BOND_ASSET" ] || [[ $BOND_ASSET =~ ^[0-9a-f]{64}$ ]] || die "BOND_ASSET is an asset id (64 hex characters)"
[ -z "$BOND_ATOMS" ] || [[ $BOND_ATOMS =~ ^[1-9][0-9]*$ ]] || die "BOND_ATOMS is a whole number of atoms"
[[ $BOND_NOTICE_UNITS =~ ^[0-9]+$ ]] || die "BOND_NOTICE_UNITS is a number of 512-second units"
[[ $BOND_WALLET =~ ^[A-Za-z0-9_-]+$ ]] || die "BOND_WALLET is a node wallet's name: letters, digits, _ and -"

case "$NAME" in *[!a-z0-9-]*|"") die "NAME is lower-case letters, digits and dashes: $NAME";; esac
USER_=$NAME
OPT=/opt/$NAME; ETC=/etc/$NAME; LIB=/var/lib/$NAME; LOG=/var/log/$NAME
BIN=$OPT/bin
# Downloads, the toolchain and the builds are shared by every bundle on the machine.
CACHE=/var/cache/arca-bundle
: "${BACKUP_DIR:=/var/backups/$NAME}"
export CARGO_HOME=$CACHE/toolchain/cargo RUSTUP_HOME=$CACHE/toolchain/rustup
export PATH=$CARGO_HOME/bin:$PATH
export CARGO_BUILD_JOBS=$BUILD_JOBS CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols
U() { printf '%s-%s.service' "$NAME" "$1"; }
# Where the node's fee rates come from: the node's own price server, reading a
# public price feed and the asset registry. The public testnet's by default
# there; on another chain none, and the operator sets the rates himself
# (sequentia-cli setfeeexchangerates).
[ "$SEQ_CHAIN" = test ] && : "${PRICE_FEED_URL:=http://sequentiatestnet.com/prices}"
[ "${PRICE_FEED_URL:-}" = none ] && PRICE_FEED_URL=""
: "${PRICE_FEED_URL:=}" "${ASSET_REGISTRY_INDEX:=http://sequentiatestnet.com/registry/index.minimal.json}"
UNITS="bitcoind feeproxy sequentiad $( [ -n "$PRICE_FEED_URL" ] && echo priceserver ) arca-signer arcad seqln cln captaind watchmand${PEER_ARCA_URL:+ watchtower} btc-watchtower"
# PostgreSQL names a cluster's unit postgresql@<version>-<cluster>, where a dash
# in the cluster name would read as a path: the cluster takes underscores.
PG_CLUSTER=${NAME//-/_}
# A dash in a slice name would make it a child of another slice: the same.
SLICE=$PG_CLUSTER
PG_UNIT="postgresql@16-$PG_CLUSTER.service"
case "$SEQ_CHAIN" in
  test) SEQ_SUB=testnet3; : "${SEQLN_NETWORK:=sequentia-testnet}";;
  *) SEQ_SUB=$SEQ_CHAIN; : "${SEQLN_NETWORK:=sequentia-regtest}";;
esac
case "$BTC_CHAIN" in
  testnet4) BTC_SUB=testnet4; BARK_NET=testnet4;; regtest) BTC_SUB=regtest; BARK_NET=regtest;; signet) BTC_SUB=signet; BARK_NET=signet;;
  main|bitcoin) die "this bundle is for test networks: BTC_CHAIN=$BTC_CHAIN is refused";;
  *) die "BTC_CHAIN is testnet4, signet or regtest: $BTC_CHAIN";;
esac
as_user() { runuser -u "$USER_" -- "$@"; }
SEQCLI=("$OPT/sequentia/bin/sequentia-cli" -conf="$ETC/sequentia.conf" -datadir="$LIB/sequentia")
BTCCLI=("$OPT/core/bin/bitcoin-cli" -conf="$ETC/bitcoin.conf" -datadir="$LIB/bitcoin")
seq_cli() { as_user "${SEQCLI[@]}" "$@" </dev/null; }
# The node's fee rates, keyed by asset id. The node keys an asset by its label
# when it knows one (USDX, tSEQ on the public testnet), so an id alone would
# miss every labelled asset; dumpassetlabels maps the labels back.
node_rates() {
  local r l
  r=$(seq_cli getfeeexchangerates 2>/dev/null) || r='{}'
  l=$(seq_cli dumpassetlabels 2>/dev/null) || l='{}'
  jq -c --argjson l "$l" 'with_entries(.key = ($l[.key] // .key))' <<<"$r" 2>/dev/null || echo '{}'
}
btc_cli() { as_user "${BTCCLI[@]}" "$@" </dev/null; }
seqln() { as_user "$OPT/seqln/cli/lightning-cli" --lightning-dir="$LIB/seqln" "$@" </dev/null; }
cln() { as_user "$OPT/cln/usr/bin/lightning-cli" --lightning-dir="$LIB/cln" "$@" </dev/null; }
captaind_rpc() { as_user "$BIN/captaind" rpc --addr "http://127.0.0.1:$CAPTAIND_ADMIN_PORT" "$@" </dev/null; }
arcad_cmd() { as_user "$BIN/arcad" "$ETC/arcad.toml" "$@" </dev/null; }
info() { curl -sf --max-time 10 "http://127.0.0.1:$ARCAD_PORT/v1/info"; }
wait_for() {   # wait_for <seconds> <what> <command...>
  local t=$1 what=$2 i; shift 2
  for ((i = 0; i < t; i++)); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 1; done
  die "$what: not after $t s ($(journalctl -u "${WAIT_UNIT:-none}" -n 5 --no-pager -o cat 2>/dev/null | tr '\n' ' '))"
}

# The served assets: ASSET_IDS, and per id its smallest leaf and rate source.
declare -A MIN_LEAF RATE
ASSET_IDS=()
for a in $ARCA_ASSETS; do
  IFS=: read -r id ml rs <<<"$a"
  [[ $id =~ ^[0-9a-f]{64}$ ]] || die "ARCA_ASSETS: $id is not an asset id (64 hex characters)"
  [[ ${ml:-} =~ ^[0-9]+$ ]] || die "ARCA_ASSETS: $a names no smallest leaf in atoms"
  case ${rs:-none} in node|none) ;; *) die "ARCA_ASSETS: $a: the rate source is node or none";; esac
  ASSET_IDS+=("$id"); MIN_LEAF[$id]=$ml; RATE[$id]=${rs:-none}
done
channel_atoms() {   # the channel size for asset $1
  local x
  for x in $CHANNEL_ATOMS; do case $x in "$1":*) echo "${x#*:}"; return;; *:*) ;; *) echo "$x"; return;; esac; done
  echo 0
}

# ===========================================================================================
# What the native installer and the containers (docker/bundle-run) share: the keys, and
# every daemon's configuration, written from the settings.
# write_conf <unit word> <mode> <file>: stdin is the content; a changed file marks its unit.
write_conf() {
  local t; t=$(mktemp); cat > "$t"
  if [ -f "$3" ] && cmp -s "$t" "$3"; then rm -f "$t"; return 0; fi
  install -m "$2" -o "$USER_" -g "$USER_" "$t" "$3"; rm -f "$t"; changed+=" $1"
}

draw_keys() {
step "keys and passwords, drawn here (made once, never replaced)"
umask 077
key_file() {   # key_file <file> <command...>: the command writes the secret to stdout
  local f=$ETC/$1; shift
  if [ ! -s "$f" ]; then "$@" > "$f.new"; mv "$f.new" "$f"; say "drew $f"; fi
  chown "$USER_:$USER_" "$f"; chmod 600 "$f"
}
key_file operator.key openssl rand -hex 32
[ "$(tr -d '\n' < "$ETC/operator.key" | wc -c)" = 64 ] || die "$ETC/operator.key is not 64 hex characters"
key_file wallet.mnemonic python3 -I - "$CARGO_HOME" <<'PY'
import glob, hashlib, os, re, sys
# The BIP39 English list, from the bip39 crate the build fetched, checked
# against the list's published SHA-256 before use.
lists = glob.glob(os.path.join(sys.argv[1], "registry/src/*/bip39-*/src/language/english.rs"))
if not lists: sys.exit("no BIP39 word list under the cargo registry")
words = re.findall(r'"([a-z]+)"', open(sorted(lists)[-1]).read())
if len(words) != 2048 or hashlib.sha256(("\n".join(words) + "\n").encode()).hexdigest() != \
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda":
    sys.exit("the BIP39 word list does not match the standard English list")
entropy = os.urandom(32)
bits = int.from_bytes(entropy, "big") << 8 | hashlib.sha256(entropy).digest()[0]
print(" ".join(words[(bits >> (11 * (23 - i))) & 2047] for i in range(24)))
PY
[ "$(wc -w < "$ETC/wallet.mnemonic")" = 24 ] || die "$ETC/wallet.mnemonic is not 24 words"
key_file seq-rpc.password openssl rand -hex 24
key_file btc-rpc.password openssl rand -hex 24
umask 022
# rpcauth lines: the nodes keep only a salted hash of each login's password.
rpcauth() { python3 -I - "$1" "$2" <<'PY'
import hashlib, hmac, os, sys
salt = os.urandom(16).hex()
pw = open(sys.argv[2]).read().strip()
print("%s:%s$%s" % (sys.argv[1], salt, hmac.new(salt.encode(), pw.encode(), hashlib.sha256).hexdigest()))
PY
}

}

write_configs() {
step "configuration"
changed=""
# An rpcauth line is drawn with a fresh salt, so it is written once and kept.
for n in seq btc; do
  if [ ! -s "$ETC/$n-rpcauth" ] || [ "$(cut -d: -f1 "$ETC/$n-rpcauth")" != "$NAME" ]; then rpcauth "$NAME" "$ETC/$n-rpc.password" > "$ETC/$n-rpcauth"; chmod 640 "$ETC/$n-rpcauth"; chgrp "$USER_" "$ETC/$n-rpcauth"; fi
done
btc_addnode=""; [ -n "$BTC_ADDNODE" ] && btc_addnode="addnode=$BTC_ADDNODE"
write_conf bitcoind 640 "$ETC/bitcoin.conf" <<EOF
# Bitcoin Core for the bundle's Bitcoin ark and its Sequentia node's anchors.
# Written by install.sh from $BUNDLE_ENV.
chain=$BTC_CHAIN

[$BTC_CHAIN]
server=1
# Bark's server reads any transaction by its id, so the node keeps a full
# transaction index (and is never pruned).
txindex=1
disablewallet=1
listen=1
bind=0.0.0.0:$BTC_P2P_PORT
$btc_addnode
rpcbind=$LISTEN_HOST
rpcallowip=$( [ "$LISTEN_HOST" = 127.0.0.1 ] && echo 127.0.0.1 || echo 0.0.0.0/0 )
rpcport=$BTC_RPC_PORT
# The cookie is for the bundle's own daemons; the login below is for a
# Lightning wallet beside them (install.sh credentials).
rpccookieperms=group
rpcauth=$(cat "$ETC/btc-rpcauth")
debuglogfile=$LOG/bitcoind.log
shrinkdebugfile=0
dbcache=300
maxmempool=200
EOF
seq_addnode=""; [ -n "$SEQ_ADDNODE" ] && seq_addnode="addnode=$SEQ_ADDNODE"
if [ -n "$SEQ_ANCHOR_RPC" ]; then
  anchor="mainchainrpchost=${SEQ_ANCHOR_RPC%:*}
mainchainrpcport=${SEQ_ANCHOR_RPC##*:}
mainchainrpcuser=${SEQ_ANCHOR_AUTH%%:*}
mainchainrpcpassword=${SEQ_ANCHOR_AUTH#*:}"
else
  # By the bundle's own login on its Bitcoin node, named outright: the public
  # testnet's chain settings name a shared gateway's login otherwise, which
  # would take the place of a cookie.
  anchor="mainchainrpchost=127.0.0.1
mainchainrpcport=$BTC_RPC_PORT
mainchainrpcuser=$NAME
mainchainrpcpassword=$(cat "$ETC/btc-rpc.password")"
fi
testnet_rules=""; [ "$SEQ_CHAIN" = test ] && testnet_rules="# The public testnet's network-wide rules.
pospubliccommittee=1
poscommitteesize=250"
# The wallet stays off but for the bond: the operating wallet it is paid
# from ($BOND_WALLET), made and loaded by "$0 bond".
wallet_conf="disablewallet=1"
[ -n "$BOND_WITHDRAW_KEY" ] && wallet_conf="# The operating wallet the bond is paid from (BOND_WALLET), and nothing else.
disablewallet=0"
write_conf sequentiad 640 "$ETC/sequentia.conf" <<EOF
# The Sequentia node: the chain arcad and the SeqLN gateway read. Written by
# install.sh from $BUNDLE_ENV.
chain=$SEQ_CHAIN

[$SEQ_CHAIN]
$testnet_rules
${SEQ_CHAIN_CONF//;/$'\n'}
server=1
txindex=1
$wallet_conf
# Every anchor is checked against this machine's Bitcoin node: the chain
# follows Bitcoin's reorganisations, and arcad's finality waits on them.
validateanchor=1
$anchor
listen=1
bind=127.0.0.1:$SEQ_P2P_PORT
$seq_addnode
rpcbind=$LISTEN_HOST
rpcallowip=$( [ "$LISTEN_HOST" = 127.0.0.1 ] && echo 127.0.0.1 || echo 0.0.0.0/0 )
rpcport=$SEQ_RPC_PORT
rpccookieperms=group
rpcauth=$(cat "$ETC/seq-rpcauth")
debuglogfile=$LOG/sequentiad.log
shrinkdebugfile=0
EOF
write_conf cln 640 "$LIB/cln/config" <<EOF
# The Bitcoin gateway: Core Lightning with the hold-invoice plugin, driven by
# Bark's server over gRPC. Written by install.sh.
network=$BTC_CHAIN
alias=$NAME-btc
bitcoin-cli=$OPT/core/bin/bitcoin-cli
bitcoin-datadir=$LIB/bitcoin
# The node through the fee proxy, as Bark's server reads it: Core often has no
# estimate on testnet4, and Core Lightning then refuses every channel a peer
# opens to it ("Cannot accept channel: feerates unknown"), whatever
# force-feerates says. The proxy always answers, at the going rate.
bitcoin-rpcport=$FEE_PROXY_PORT
bitcoin-rpcconnect=127.0.0.1
# Peers reach it from anywhere: its channels are its route to other
# operators' gateways and to wallets.
bind-addr=0.0.0.0:$CLN_PORT
grpc-port=$CLN_GRPC_PORT
important-plugin=$BIN/hold
hold-grpc-port=$HOLD_GRPC_PORT
log-file=$LOG/cln.log
log-level=info
# arcad, in the same group, reads it through its socket.
rpc-file-mode=0660
$( [ "$BTC_CHAIN" = testnet4 ] && echo "# testnet4's own fee estimates often say nothing; these fixed rates (sat per
# 1,000 weight) let it open and close channels. The option exists on test
# networks only.
force-feerates=7500/7500/500/7500/7500/7500
# A peer's commitment rate is taken as it is. Core Lightning's floor is half
# its slowest estimate, which the proxy puts at the going rate (15 sat/vB and
# up): every opener proposing an anchor channel's usual 1 to 2 sat/vB would be
# refused. The anchor lifts a commitment when it is needed.
ignore-fee-limits=true" )
EOF
write_conf seqln 640 "$LIB/seqln/config" <<EOF
# The Sequentia gateway: SeqLN with the hold-invoice plugin, one channel in
# each asset served over Lightning. Written by install.sh.
network=$SEQLN_NETWORK
alias=$NAME-seq
bitcoin-cli=$OPT/sequentia/bin/sequentia-cli
bitcoin-datadir=$LIB/sequentia
bitcoin-rpcport=$SEQ_RPC_PORT
bitcoin-rpcconnect=127.0.0.1
bind-addr=0.0.0.0:$SEQLN_PORT
plugin=$OPT/seqln/contrib/holdinvoice-seq/holdinvoice.py
log-file=$LOG/seqln.log
log-level=info
rpc-file-mode=0660
EOF
if [ -n "$PRICE_FEED_URL" ]; then
  # The node's own price server (it comes with Sequentia Core): its example
  # configuration, pointed at this node, the feed and the registry.
  write_conf priceserver 640 "$LIB/price-server.json" < <(python3 -I -c '
import json, sys
c = json.load(open(sys.argv[1]))
c["node_rpc"] = {"host": "127.0.0.1", "port": int(sys.argv[2]), "cookie": sys.argv[3]}
c["source"]["url"] = sys.argv[4]
c["registry_url"] = sys.argv[5]
print(json.dumps(c, indent=2))' "$OPT/sequentia/price-server/config.example.json" "$SEQ_RPC_PORT" "$LIB/sequentia/$SEQ_SUB/.cookie" "$PRICE_FEED_URL" "$ASSET_REGISTRY_INDEX")
fi
}

captaind_toml() {   # the server's (no argument) or the watchman's (watchman) configuration
  local fee="[fee_estimator]
update_interval = \"1m\"
history_duration = \"60m\"
fallback_fee_rate_fast = \"${BTC_FEE_FLOOR}sat/vb\"
fallback_fee_rate_regular = \"${BTC_FEE_FLOOR}sat/vb\"
fallback_fee_rate_slow = \"${BTC_FEE_FLOOR}sat/vb\"
max_fee_rate = \"100sat/vb\""
  local pg="[postgres]
host = \"/var/run/postgresql\"
port = $PG_PORT
name = \"bark\"
user = \"$USER_\""
  # By the bundle's login, not the cookie: the node draws a new cookie each
  # time it starts, and Bark's server reads its credentials once.
  local node="[bitcoind]
url = \"http://127.0.0.1:$FEE_PROXY_PORT\"
rpc_user = \"$NAME\"
rpc_pass = \"$(cat "$ETC/btc-rpc.password")\""
  if [ "${1:-}" = watchman ]; then cat <<EOF
# Bark's watchman: answers exits and sweeps expired rounds back to the
# server's round wallet. Written by install.sh.
data_dir = "$LIB/watchmand"
network = "$BARK_NET"
sync_manager_block_poll_interval = "1s"
htlc_settlement_poll_interval = "60s"
min_trusted_confs = 2
otel_deployment_name = "$NAME-watchman"
sweep_address = "$SWEEP_ADDRESS"

[watchman]
reaction_interval = "1m"
sweep_interval = "2h"
progress_grace_period = 2
claim_chunksize = 20
incremental_relay_fee = "100 sat/kvb"
min_cpfp_amount = "10000 sat"

$fee

$pg
max_connections = 5

$node
EOF
  return; fi
  cat <<EOF
# Bark's server for the bundle's Bitcoin ark. Every value Bark's template
# names is set, so nothing falls back to a default unseen. Written by install.sh.
data_dir = "$LIB/captaind"
network = "$BARK_NET"
vtxo_lifetime = 2016
vtxo_exit_delta = 72
max_vtxo_amount = "5000000 sat"
min_board_amount = "10000 sat"
max_board_amount = "5000000 sat"
max_offboard_amount = "5000000 sat"
max_arkoor_amount = "5000000 sat"
max_vtxo_exit_depth = 100
max_arkoor_fanout = 4
required_board_confirmations = 2
min_trusted_confs = 2
rpc_rich_errors = true
sync_manager_block_poll_interval = "1s"
nursery_confirm_target_blocks = 6
otel_deployment_name = "$NAME"
max_read_mailbox_items = 100
round_interval = "30s"
round_submit_time = "5s"
round_sign_time = "5s"
nb_round_nonces = 8
round_forfeit_nonces_timeout = "30s"
offboard_session_timeout = "30s"
offboard_check_interval = "1s"
offboard_acceptable_fee_rate_duration = "15m"
cln_reconnect_interval = "10s"
invoice_check_interval = "3s"
cln_xpay_timeout = "60s"
invoice_check_base_delay = "10s"
max_invoice_check_delay = "10m"
invoice_poll_interval = "30s"
htlc_settlement_poll_interval = "60s"
track_all_base_delay = "1s"
max_track_all_delay = "60s"
htlc_expiry_delta = 40
# A payment out of the ark may lock up to this many blocks. A Bark receive
# invoice asks a final lock of twice vtxo_exit_delta and htlc_expiry_delta
# (184 blocks here), so paying another ark's invoice over a channel or two
# needs well over that: 258 leaves room for the hops.
htlc_send_expiry_delta = 258
max_user_invoice_cltv_delta = 250
invoice_expiry = "48h"
receive_htlc_forward_timeout = "3min"
ln_receive_anti_dos_required = false
max_ln_receive_amount = "1000000 sat"
max_ln_send_amount = "1000000 sat"
ln_max_fee_ppm = 900000

[[cln_array]]
uri = "https://localhost:$CLN_GRPC_PORT"
priority = 1
server_cert_path = "$LIB/cln/$BTC_SUB/ca.pem"
client_cert_path = "$LIB/cln/$BTC_SUB/client.pem"
client_key_path = "$LIB/cln/$BTC_SUB/client-key.pem"
hold_invoice.uri = "https://localhost:$HOLD_GRPC_PORT"
hold_invoice.server_cert_path = "$LIB/cln/$BTC_SUB/hold/ca.pem"
hold_invoice.client_cert_path = "$LIB/cln/$BTC_SUB/hold/client.pem"
hold_invoice.client_key_path = "$LIB/cln/$BTC_SUB/hold/client-key.pem"

[fees.board]
min_fee_sat = 330
base_fee_sat = 100
ppm = 1000

[fees.offboard]
base_fee_sat = 200
fixed_additional_vb = 221
ppm_expiry_table = [
    { expiry_blocks_threshold = 0, ppm = 0 },
    { expiry_blocks_threshold = 97, ppm = 1000 },
    { expiry_blocks_threshold = 199, ppm = 4000 },
    { expiry_blocks_threshold = 2161, ppm = 8000 },
]

[fees.refresh]
base_fee_sat = 150
ppm_expiry_table = [
    { expiry_blocks_threshold = 0, ppm = 0 },
    { expiry_blocks_threshold = 97, ppm = 1000 },
    { expiry_blocks_threshold = 199, ppm = 4000 },
    { expiry_blocks_threshold = 2161, ppm = 8000 },
]

[fees.lightning_receive]
base_fee_sat = 100
ppm = 2000

[fees.lightning_send]
min_fee_sat = 10
base_fee_sat = 75
ppm_expiry_table = [
    { expiry_blocks_threshold = 0, ppm = 0 },
    { expiry_blocks_threshold = 97, ppm = 1000 },
    { expiry_blocks_threshold = 199, ppm = 4000 },
    { expiry_blocks_threshold = 2161, ppm = 8000 },
]

[vtxopool]
vtxo_targets = [ $(for t in $ARK_VTXO_POOL; do printf '"%s", ' "$t"; done | sed 's/, $//') ]
vtxo_target_issue_threshold = 80
vtxo_lifetime = 432
vtxo_pre_expiry = 144
max_vtxo_exit_depth = 3

$fee

[rpc]
public_address = "$LISTEN_HOST:$CAPTAIND_PORT"
admin_address = "127.0.0.1:$CAPTAIND_ADMIN_PORT"
integration_address = "127.0.0.1:$CAPTAIND_INTEGRATION_PORT"

$pg
max_connections = 10

$node
EOF
}

write_arcad_toml() {
ark_url="http://127.0.0.1:$CAPTAIND_PORT"; [ -n "$DOMAIN" ] && ark_url="https://$DOMAIN"
assets_toml=""; fee_assets=""
rates=$(node_rates)
for id in "${ASSET_IDS[@]}"; do
  assets_toml+="
[[assets]]
asset = \"$id\"
min_leaf = \"${MIN_LEAF[$id]}\"
"
  [ "${RATE[$id]}" = node ] && assets_toml+="[assets.rate]
source = \"node\"
"
  assets_toml+="[assets.lightning]
rpc = \"$LIB/seqln/$SEQLN_NETWORK/lightning-rpc\"
"
  if [ -z "$ARCA_FEE_ASSETS" ] && jq -e --arg a "$id" 'has($a)' <<<"$rates" >/dev/null; then fee_assets+="\"$id\", "; fi
done
for id in $ARCA_FEE_ASSETS; do fee_assets+="\"$id\", "; done
[ -n "$fee_assets" ] || die "no served asset is accepted for fees by the node, so no round could pay its fee: name one in ARCA_FEE_ASSETS"
read -r dmin dmax <<<"$ARCA_EXIT_DELAY_UNITS"
# The bond's terms once a withdrawal key is chosen, and its coin once
# "$0 bond" has posted it ($ETC/bond.outpoint).
bond_toml=""
if [ -n "$BOND_WITHDRAW_KEY" ]; then
  bond_toml="
[bond]
withdraw_key = \"$BOND_WITHDRAW_KEY\"
notice_units = $BOND_NOTICE_UNITS"
  [ -s "$ETC/bond.outpoint" ] && bond_toml+="
outpoint = \"$(cat "$ETC/bond.outpoint")\""
  [ -s "$ETC/bond.notice" ] && bond_toml+="
notice = \"$(cat "$ETC/bond.notice")\""
fi
write_conf arcad 600 "$ETC/arcad.toml" <<EOF
# arcad's configuration, written by install.sh from $BUNDLE_ENV. Every
# setting is described in arca's server/arcad.example.toml.
listen = "$LISTEN_HOST:$ARCAD_PORT"
database = "host=/var/run/postgresql port=$PG_PORT user=$USER_ dbname=arca"
signer_socket = "/run/$NAME/signer.sock"
wallet_mnemonic_file = "$ETC/wallet.mnemonic"
fee_multiple = 2
round_interval_seconds = $ARCA_ROUND_INTERVAL
exit_delay_units = [$dmin, $dmax]
metrics_listen = "127.0.0.1:$ARCAD_METRICS_PORT"
fee_assets = [${fee_assets%, }]

[node]
rpc_url = "http://127.0.0.1:$SEQ_RPC_PORT/"
cookie_file = "$LIB/sequentia/$SEQ_SUB/.cookie"

[finality]
anchor_depth = $ARCA_ANCHOR_DEPTH
certification = "required"
poll_interval_ms = 1000

[watcher]
enabled = true
reclaim_early = true
block_interval_seconds = 60
# The watchtowers this operator's info names for its users' wallets: the
# peer operator's, run for this one's users (PEER_WATCHTOWER).
watchtowers = [${PEER_WATCHTOWER:+\"$PEER_WATCHTOWER\"}]

[fees]
refresh_ppm = 0
offboard_ppm = 0

[limits]
trusted_proxies = ["127.0.0.1", "::1"]

[lightning]
# Another operator's invoice for a payment into its tree locks the payment for
# about 5,790 blocks at the specification's exit delays, which takes a
# timeout of about nine days to pay. It binds only a payment that is never
# settled: its coins come back to the payer after the timeout (up to twice
# it), and the payer's wallet shows the payment "paying" until then.
send_timeout_seconds = $ARCA_SEND_TIMEOUT
receive_cap_ppm = 100000

[lightning.bitcoin]
rpc = "$LIB/cln/$BTC_SUB/lightning-rpc"
ark = "$ark_url"
$bond_toml
$assets_toml
EOF
}

# The watchtower this bundle runs for the peer operator's users: a wallet of
# its own, made once against the peer (whose key it pins from the peer's
# info, and checks every deposit against), reading this bundle's node. Its
# on-chain coins pay what a coin's own reserves cannot when it acts.
tower_wallet() {
  [ -s "$LIB/watchtower/arca.sqlite" ] && return 0
  install -d -m 700 -o "$USER_" -g "$USER_" "$LIB/watchtower"
  local err; err=$(as_user "$BIN/arca" --datadir "$LIB/watchtower" create --server "$PEER_ARCA_URL" \
    --node-url "http://127.0.0.1:$SEQ_RPC_PORT/" --node-cookie "$LIB/sequentia/$SEQ_SUB/.cookie" 2>&1 >/dev/null </dev/null) \
    || { printf '%s\n' "$err" | tail -3; return 1; }
}

# The watchtower for Bitcoin ark coins: holders' deposits (each coin with a
# claim its holder signed), brought on chain a day before the coin's expiry
# and claimed to the holder's address, the children paid from its own BTC. It
# watches the arks named in BTC_TOWER_ARKS by server key (empty: any ark,
# this bundle's own and the peer's), and reads the chain through the fee
# proxy by the bundle's login, whose password it takes from an environment
# file only its user reads.
btc_tower_make() {
  install -d -m 700 -o "$USER_" -g "$USER_" "$LIB/btc"
  install -m 640 -o root -g "$USER_" /dev/null "$ETC/btc-watchtower.env.tmp"
  printf 'ARCA_BITCOIND_PASSWORD=%s\n' "$(cat "$ETC/btc-rpc.password")" > "$ETC/btc-watchtower.env.tmp"
  mv -f "$ETC/btc-watchtower.env.tmp" "$ETC/btc-watchtower.env"
  [ -s "$LIB/btc/btc-watchtower/config.json" ] && return 0
  local a=() k err
  for k in $BTC_TOWER_ARKS; do a+=(--ark "$k"); done
  err=$(ARCA_BITCOIND_PASSWORD="$(cat "$ETC/btc-rpc.password")" as_user "$BIN/arca" --datadir "$LIB/btc" btc-watchtower create --network "$BARK_NET" \
    --bitcoind "http://127.0.0.1:$FEE_PROXY_PORT" --bitcoind-user "$NAME" "${a[@]}" 2>&1 >/dev/null </dev/null) \
    || { printf '%s\n' "$err" | tail -3; return 1; }
}

caddyfile() {
  cat <<EOF
# The bundle's public route, written by install.sh: the Arca operator under
# /arca, the watchtower for the peer operator's users under /watchtower, the
# watchtower for Bitcoin ark coins under /btc-watchtower, the
# Bitcoin ark by its two gRPC services, and the registry's domain proof.
# Caddy obtains the certificate itself.
$DOMAIN {
	handle_path /arca/* {
		reverse_proxy 127.0.0.1:$ARCAD_PORT {
			transport http {
				keepalive 30s
			}
		}
	}
	handle_path /watchtower/* {
		reverse_proxy 127.0.0.1:$WATCHTOWER_PORT
	}
	handle_path /btc-watchtower/* {
		reverse_proxy 127.0.0.1:$BTC_WATCHTOWER_PORT
	}
	@bitcoinark path /bark_server.ArkService/* /mailbox_server.MailboxService/*
	handle @bitcoinark {
		reverse_proxy h2c://127.0.0.1:$CAPTAIND_PORT
	}
	handle /.well-known/sequentia-operator-proof-* {
		root * $LIB/www
		file_server
	}
	handle {
		respond 404
	}
}
EOF
}

# ===========================================================================================
prepare() {
step "the machine"
os=$(. /etc/os-release; echo "${ID:-}:${VERSION_ID:-}:${PRETTY_NAME:-an unknown system}")
[ "${os%%:*:*}" = ubuntu ] && [ "$(cut -d: -f2 <<<"$os")" = 24.04 ] || say "this is ${os#*:*:}; the bundle is made for Ubuntu 24.04"
[ -d /run/systemd/system ] || [ "$CMD" = build ] || die "systemd is not running. In WSL2 put [boot] systemd=true in /etc/wsl.conf and restart the distro (wsl --terminate <distro>)"
[ "$(uname -m)" = x86_64 ] || die "the bundle's downloads are for x86_64; this machine is $(uname -m)"
mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo); free_gb=$(df -Pk / | awk 'NR==2 {print int($4/1048576)}')
say "$(nproc) cores, $mem MB of memory, $free_gb GB free on /"
[ "$mem" -ge 3500 ] || say "less than 4 GB of memory: the builds may fail; lower BUILD_JOBS to 1"
[ "$free_gb" -ge 40 ] || say "less than 40 GB free: the Bitcoin node's chain and transaction index may not fit"

step "packages"
pkgs="ca-certificates curl git jq python3 python3-mako openssl xz-utils build-essential pkg-config autoconf automake libtool gettext
      libsqlite3-dev libsodium-dev zlib1g-dev libffi-dev libpq-dev libssl-dev protobuf-compiler postgresql postgresql-contrib nodejs
      iproute2 logrotate lowdown python3-setuptools"
missing=""; for p in $pkgs; do st=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true); [ "$st" = "install ok installed" ] || missing+=" $p"; done
if [ -n "$missing" ]; then
  say "installing:$missing"
  apt-get update -q >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $missing >/dev/null
fi
say "all present"

step "ports"
mine=" "
# Every process of the bundle's own units (a daemon's port may be held by a child).
for u in $UNITS caddy; do
  cg=$(systemctl show -p ControlGroup --value "$(U "$u")" 2>/dev/null || true)
  if [ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/cgroup.procs" ]; then mine+="$(tr '\n' ' ' < "/sys/fs/cgroup$cg/cgroup.procs")"; fi
done
for port in $SEQ_RPC_PORT $SEQ_P2P_PORT $BTC_RPC_PORT $BTC_P2P_PORT $FEE_PROXY_PORT $PG_PORT $ARCAD_PORT $ARCAD_METRICS_PORT \
            $SEQLN_PORT $CLN_PORT $CLN_GRPC_PORT $HOLD_GRPC_PORT $CAPTAIND_PORT $CAPTAIND_ADMIN_PORT $CAPTAIND_INTEGRATION_PORT $WATCHTOWER_PORT $BTC_WATCHTOWER_PORT; do
  l=$(ss -ltnpH "sport = :$port" 2>/dev/null || true)
  [ -n "$l" ] || continue
  pids=$(grep -o 'pid=[0-9]*' <<<"$l" | cut -d= -f2 | sort -u | tr '\n' ' ' || true)
  [ -n "$pids" ] || pids=unknown
  ok=1; for p in $pids; do case "$mine" in *" $p "*) ;; *) ok=0;; esac; done
  # PostgreSQL's port is held by its own cluster, which runs under its unit.
  [ "$port" = "$PG_PORT" ] && systemctl is-active --quiet "$PG_UNIT" && ok=1
  [ "$ok" = 1 ] || die "port $port is taken by another program ($l); give this bundle other ports in $BUNDLE_ENV"
done
say "every port is free, or held by this bundle"

step "the service user and directories"
if ! id "$USER_" >/dev/null 2>&1; then
  useradd --system --home-dir "$LIB" --no-create-home --shell /usr/sbin/nologin "$USER_"
  say "created the system user $USER_"
fi
install -d -m 755 "$OPT" "$BIN" "$CACHE" "$CACHE/dl" "$CACHE/build"
install -d -m 750 -o root -g "$USER_" "$ETC"
for d in "$LIB" "$LIB/sequentia" "$LIB/bitcoin" "$LIB/seqln" "$LIB/cln" "$LIB/arca" "$LIB/captaind" "$LIB/watchmand" "$LOG" "$BACKUP_DIR" "$BACKUP_DIR/wal"; do
  install -d -m 750 -o "$USER_" -g "$USER_" "$d"
done
chmod 700 "$LIB/captaind" "$LIB/watchmand" "$LIB/arca"
say "$OPT, $ETC, $LIB, $LOG; backups in $BACKUP_DIR"

step "downloads, each checked against its checksum"
changed_bins=""
link() {   # link <target> <name> <unit word>: points $OPT/<name> at <target>; a change restarts the unit
  [ "$(readlink "$OPT/$2" 2>/dev/null)" = "$1" ] && return 0
  ln -sfn "$1" "$OPT/$2"; changed_bins+=" $3"
}
fetch() {   # fetch <url> <file> <sha256|sha512:hex>
  local f=$CACHE/dl/$2 want=$3 got
  if [ -f "$f" ]; then
    case $want in sha512:*) got=sha512:$(sha512sum "$f" | cut -d' ' -f1);; *) got=$(sha256_of "$f");; esac
    [ "$got" = "$want" ] && return 0
  fi
  curl -sSfL --retry 3 -o "$f.part" "$1"
  case $want in sha512:*) got=sha512:$(sha512sum "$f.part" | cut -d' ' -f1);; *) got=$(sha256_of "$f.part");; esac
  [ "$got" = "$want" ] || { rm -f "$f.part"; die "$1 does not have the expected checksum ($got)"; }
  mv "$f.part" "$f"
}
unpack() {   # unpack <archive> <dir> [tar options]
  local a=$CACHE/dl/$1 d=$OPT/$2; shift 2
  [ -d "$d" ] && return 0
  rm -rf "$d.part"; mkdir -p "$d.part"; tar xf "$a" -C "$d.part" "$@"; mv "$d.part" "$d"
}
# Sequentia Core: the newest release on the download page, as the network runs.
sums=$(curl -sSfL --retry 3 https://sequentiatestnet.com/download/SHA256SUMS)
seqtar=$(awk '{print $2}' <<<"$sums" | grep -E '^sequentia-core-[0-9.]+-linux-x86_64\.tar\.gz$' | sort -V | tail -n 1)
[ -n "$seqtar" ] || die "the download page lists no Sequentia Core for Linux"
seqver=${seqtar#sequentia-core-}; seqver=${seqver%-linux-x86_64.tar.gz}
fetch "https://sequentiatestnet.com/download/$seqtar" "$seqtar" "$(awk -v f="$seqtar" '$2 == f {print $1}' <<<"$sums")"
unpack "$seqtar" "sequentia-$seqver" --strip-components=1
link "sequentia-$seqver" sequentia sequentiad
say "Sequentia Core $seqver"
fetch "https://bitcoincore.org/bin/bitcoin-core-$CORE_VERSION/bitcoin-$CORE_VERSION-x86_64-linux-gnu.tar.gz" "bitcoin-$CORE_VERSION.tar.gz" "$CORE_SHA256"
unpack "bitcoin-$CORE_VERSION.tar.gz" "core-$CORE_VERSION" --strip-components=1
link "core-$CORE_VERSION" core bitcoind
say "Bitcoin Core $CORE_VERSION"
cln_tar=clightning-v$CLN_VERSION-Ubuntu-24.04-amd64.tar.xz
fetch "https://github.com/ElementsProject/lightning/releases/download/v$CLN_VERSION/$cln_tar" "$cln_tar" "$CLN_SHA256_UBUNTU_24_04"
unpack "$cln_tar" "cln-$CLN_VERSION"
link "cln-$CLN_VERSION" cln cln
say "Core Lightning $CLN_VERSION"
rel=https://gitlab.com/api/v4/projects/ark-bitcoin%2Fbark/packages/generic/release-assets/server-${BARK_SERVER_VERSION//./%2E}
fetch "$rel/captaind-${BARK_SERVER_VERSION//./%2E}-linux-x86_64" "captaind-$BARK_SERVER_VERSION" "$CAPTAIND_SHA256"
fetch "$rel/watchmand-${BARK_SERVER_VERSION//./%2E}-linux-x86_64" "watchmand-$BARK_SERVER_VERSION" "$WATCHMAND_SHA256"
say "Bark's server and watchman $BARK_SERVER_VERSION"
if [ -n "$DOMAIN" ] || [ "${WITH_CADDY:-}" = 1 ]; then
  fetch "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" \
    "caddy-$CADDY_VERSION.tar.gz" "sha512:$CADDY_SHA512"
  unpack "caddy-$CADDY_VERSION.tar.gz" "caddy-$CADDY_VERSION"
  say "Caddy $CADDY_VERSION"
fi

step "the Rust toolchain (for what is built from source)"
if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
  r=https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
  curl -sSfL --retry 3 -o "$CACHE/dl/rustup-init" "$r"
  want=$(curl -sSfL --retry 3 "$r.sha256" | cut -d' ' -f1)
  [ "$(sha256_of "$CACHE/dl/rustup-init")" = "$want" ] || die "rustup-init does not have its published checksum"
  chmod 755 "$CACHE/dl/rustup-init"
  "$CACHE/dl/rustup-init" -y -q --no-modify-path --profile minimal --default-toolchain stable >/dev/null
fi
say "$(cargo --version)"

# build <name> <source dir> <stamp> <command...>: runs the command in the source
# unless the stamp file says it was built from exactly this.
build() {
  local name=$1 src=$2 stamp=$3; shift 3
  if [ "$(cat "$CACHE/build/$name.built" 2>/dev/null)" = "$stamp" ]; then say "$name: built already"; return 0; fi
  say "$name: building (this takes a while)"
  ( cd "$src" && nice -n 19 ionice -c 3 "$@" ) > "$CACHE/build/$name.log" 2>&1 || { tail -20 "$CACHE/build/$name.log"; die "$name did not build (log: $CACHE/build/$name.log)"; }
  printf '%s\n' "$stamp" > "$CACHE/build/$name.built"
}
clone_at() {   # clone_at <url> <dir> <commit>
  [ -d "$2/.git" ] || git clone -q "$1" "$2"
  git -C "$2" cat-file -e "$3^{commit}" 2>/dev/null || git -C "$2" fetch -q origin
  git -C "$2" -c advice.detachedHead=false checkout -q -f --detach "$3"
}

step "arcad, arca-signer and arca, from this clone"
if git -C "$ARCA_SRC" rev-parse HEAD >/dev/null 2>&1; then
  # The last commit that changed what is built: an update of the bundle's own
  # scripts or of the documents rebuilds nothing.
  ARCA_COMMIT=$(git -C "$ARCA_SRC" log -1 --format=%H -- . ':!contrib/operator-bundle' ':!doc' ':!*.md')
  dirty=$(git -C "$ARCA_SRC" status --porcelain --untracked-files=no -- . ':!contrib/operator-bundle' || true)
  [ -z "$dirty" ] || die "$ARCA_SRC has changes outside contrib/operator-bundle; the operator is built from a commit"
else
  # A source tree without its history (a copy): built as it is, every time.
  ARCA_COMMIT=${ARCA_COMMIT:-unversioned-$(date +%s)}
fi
build arca "$ARCA_SRC" "$ARCA_COMMIT" env CARGO_TARGET_DIR="$CACHE/build/arca-target" \
  sh -c 'cargo build --release --locked -p arca-server --bin arcad --bin arca-signer && cargo build --release --locked -p arca-cli --bin arca'
say "arca at ${ARCA_COMMIT:0:12}"

step "Bark's client, with the testnet4 patch (for the operator's own wallets)"
[ "$(sha256_of "$HERE/patches/bark-testnet4.patch")" = "$BARK_PATCH_SHA256" ] || die "patches/bark-testnet4.patch is not the patch pins.env names"
if [ "$(cat "$CACHE/build/bark.built" 2>/dev/null)" != "$BARK_COMMIT+$BARK_PATCH_SHA256" ]; then
  clone_at https://gitlab.com/ark-bitcoin/bark.git "$CACHE/build/bark" "$BARK_COMMIT"
  git -C "$CACHE/build/bark" apply "$HERE/patches/bark-testnet4.patch"
fi
build bark "$CACHE/build/bark" "$BARK_COMMIT+$BARK_PATCH_SHA256" env CARGO_TARGET_DIR="$CACHE/build/bark-target" \
  cargo build --release --locked -p bark-cli --bin bark --bin barkd

step "the hold-invoice plugin, with the testnet4 patch"
[ "$(sha256_of "$HERE/patches/hold-testnet4.patch")" = "$HOLD_PATCH_SHA256" ] || die "patches/hold-testnet4.patch is not the patch pins.env names"
if [ "$(cat "$CACHE/build/hold.built" 2>/dev/null)" != "$HOLD_COMMIT+$HOLD_PATCH_SHA256" ]; then
  clone_at https://github.com/BoltzExchange/hold.git "$CACHE/build/hold" "$HOLD_COMMIT"
  git -C "$CACHE/build/hold" apply "$HERE/patches/hold-testnet4.patch"
fi
build hold "$CACHE/build/hold" "$HOLD_COMMIT+$HOLD_PATCH_SHA256" env CARGO_TARGET_DIR="$CACHE/build/hold-target" \
  cargo build --release --locked --bin hold

step "SeqLN, the Sequentia gateway"
if [ "$(cat "$CACHE/build/seqln.built" 2>/dev/null)" != "$SEQLN_COMMIT" ]; then
  clone_at https://github.com/ConcatenaLabs/seqln.git "$CACHE/build/seqln" "$SEQLN_COMMIT"
  git -C "$CACHE/build/seqln" submodule update -q --init --recursive
fi
# A fresh clone's checkout times can make the schema bundle look older than
# the schemas it is made from; it is committed current, so it is not remade.
build seqln "$CACHE/build/seqln" "$SEQLN_COMMIT" sh -c "touch contrib/msggen/msggen/schema.json && PYTHON=python3 ./configure --disable-rust --disable-valgrind && make -j$BUILD_JOBS"
D=$OPT/seqln-${SEQLN_COMMIT:0:12}
if [ ! -x "$D/lightningd/lightningd" ]; then
  S=$CACHE/build/seqln
  rm -rf "$D.part"; mkdir -p "$D.part/lightningd" "$D.part/plugins" "$D.part/cli" "$D.part/contrib"
  cp -p "$S"/lightningd/lightningd "$S"/lightningd/lightning_* "$D.part/lightningd/"
  find "$S/plugins" -maxdepth 1 -type f -perm -u+x -exec cp -p {} "$D.part/plugins/" \;
  cp -p "$S/cli/lightning-cli" "$D.part/cli/"
  cp -a "$S/contrib/holdinvoice-seq" "$S/contrib/pyln-client" "$D.part/contrib/"
  rm -rf "$D.part/contrib/holdinvoice-seq/__pycache__"
  mv "$D.part" "$D"
fi
link "$(basename "$D")" seqln seqln
say "SeqLN $("$OPT/seqln/lightningd/lightningd" --version)"

step "binaries in $BIN"
put() { if ! cmp -s "$1" "$BIN/$2"; then install -m 755 "$1" "$BIN/$2.new"; mv "$BIN/$2.new" "$BIN/$2"; changed_bins+=" $2"; fi; }
put "$CACHE/build/arca-target/release/arcad" arcad
put "$CACHE/build/arca-target/release/arca-signer" arca-signer
put "$CACHE/build/arca-target/release/arca" arca
put "$CACHE/build/bark-target/release/bark" bark
put "$CACHE/build/bark-target/release/barkd" barkd
put "$CACHE/build/hold-target/release/hold" hold
put "$CACHE/dl/captaind-$BARK_SERVER_VERSION" captaind
put "$CACHE/dl/watchmand-$BARK_SERVER_VERSION" watchmand
put "$HERE/fee-proxy.py" fee-proxy.py
if [ -n "$DOMAIN" ] || [ "${WITH_CADDY:-}" = 1 ]; then put "$OPT/caddy-$CADDY_VERSION/caddy" caddy; fi
say "${changed_bins:- nothing changed}"
printf '%s\n' "$changed_bins" >> "$CACHE/build/.changed-$NAME"
say "$("$BIN/captaind" --version 2>&1 | head -1); $("$BIN/bark" --version 2>&1 | head -1)"

}

configure_and_start() {
[ ${#ASSET_IDS[@]} -gt 0 ] || die "name at least one asset to serve in $BUNDLE_ENV (ARCA_ASSETS): none is served by default"
changed_bins=$(cat "$CACHE/build/.changed-$NAME" 2>/dev/null || true); rm -f "$CACHE/build/.changed-$NAME"
draw_keys
write_configs
step "PostgreSQL: a cluster of the bundle's own on port $PG_PORT"
uchanged=""
# One slice holds every daemon of the bundle, PostgreSQL included, so its
# limits bound them together.
t=$(mktemp)
{ echo "[Unit]"; echo "Description=The $NAME operator bundle"; echo; echo "[Slice]"
  [ -n "$BUNDLE_MEMORY_MAX" ] && echo "MemoryMax=$BUNDLE_MEMORY_MAX"
  [ -n "$BUNDLE_CPU_QUOTA" ] && echo "CPUQuota=$BUNDLE_CPU_QUOTA"
  true; } > "$t"
if cmp -s "$t" "/etc/systemd/system/$SLICE.slice"; then rm -f "$t"; else install -m 644 "$t" "/etc/systemd/system/$SLICE.slice"; rm -f "$t"; uchanged+=" slice"; fi
install -d -m 755 "/etc/systemd/system/$PG_UNIT.d"
printf '[Service]\nSlice=%s.slice\n' "$SLICE" > "/etc/systemd/system/$PG_UNIT.d/slice.conf"
systemctl daemon-reload
cl=$(pg_lsclusters -h 2>/dev/null || true)
if ! awk -v n="$PG_CLUSTER" '$1 == 16 && $2 == n {f = 1} END {exit !f}' <<<"$cl"; then
  pg_createcluster -q 16 "$PG_CLUSTER" -p "$PG_PORT" -- --auth-local=peer --auth-host=scram-sha-256 >/dev/null
  say "created the cluster 16/$PG_CLUSTER"
fi
pgconf=/etc/postgresql/16/$PG_CLUSTER/conf.d/arca-bundle.conf
t=$(mktemp)
cat > "$t" <<EOF
# The operator's database never loses a commit (arca's doc/operator-procedure.md):
# durability on, and every WAL segment archived as it is written.
listen_addresses = 'localhost'
port = $PG_PORT
fsync = on
full_page_writes = on
synchronous_commit = on
wal_level = replica
archive_mode = on
# Each segment compressed as it is archived: a segment closed by the timeout
# is mostly empty, and compresses to almost nothing. Restore with gunzip -c.
archive_command = 'test ! -f $BACKUP_DIR/wal/%f.gz && gzip -c %p > $BACKUP_DIR/wal/%f.gz.part && mv $BACKUP_DIR/wal/%f.gz.part $BACKUP_DIR/wal/%f.gz'
archive_timeout = 300
EOF
pg_changed=0; cmp -s "$t" "$pgconf" 2>/dev/null || { install -m 644 "$t" "$pgconf"; pg_changed=1; }; rm -f "$t"
# PostgreSQL writes the archive, so it must reach it: the backup directory
# lets others pass through (751) and the archive is PostgreSQL's own.
chmod 751 "$BACKUP_DIR"; chown postgres:postgres "$BACKUP_DIR/wal"; chmod 750 "$BACKUP_DIR/wal"
x=$(runuser -u postgres -- sh -c "test -w '$BACKUP_DIR/wal' && echo ok" 2>/dev/null || true)
[ "$x" = ok ] || die "PostgreSQL cannot write $BACKUP_DIR/wal: every directory above it must let others pass through (chmod o+x)"
systemctl enable -q "$PG_UNIT"
if [ "$pg_changed" = 1 ] && systemctl is-active --quiet "$PG_UNIT"; then systemctl restart "$PG_UNIT"; else systemctl start "$PG_UNIT"; fi
psql_su() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -p "$PG_PORT" -d postgres "$@" </dev/null; }
WAIT_UNIT=$PG_UNIT wait_for 60 "PostgreSQL answering" psql_su -c 'select 1'
[ "$(psql_su -tAc "select 1 from pg_roles where rolname = '$USER_'")" = 1 ] || psql_su -c "create role \"$USER_\" login"
for db in arca bark; do
  [ "$(psql_su -tAc "select 1 from pg_database where datname = '$db'")" = 1 ] || psql_su -c "create database \"$db\" owner \"$USER_\""
done
say "databases arca and bark, owned by $USER_, reached over the Unix socket"

step "systemd units"
unit() {   # unit <word> <description> <after> <ExecStart> [extra lines]
  local f=/etc/systemd/system/$(U "$1") t; t=$(mktemp)
  cat > "$t" <<EOF
[Unit]
Description=$2 ($NAME)
After=network-online.target $3
Wants=network-online.target $3

[Service]
Type=simple
User=$USER_
Group=$USER_
Slice=$SLICE.slice
ExecStart=$4
${5:-}
UMask=0027
Restart=always
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LIB $LOG /run/$NAME
LogRateLimitIntervalSec=30s
LogRateLimitBurst=2000

[Install]
WantedBy=multi-user.target
EOF
  if [ -f "$f" ] && cmp -s "$t" "$f"; then rm -f "$t"; else install -m 644 "$t" "$f"; rm -f "$t"; uchanged+=" $1"; fi
}
RUNDIR="RuntimeDirectory=$NAME
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes"
unit bitcoind "Bitcoin Core" "" "$OPT/core/bin/bitcoind -conf=$ETC/bitcoin.conf -datadir=$LIB/bitcoin -daemon=0 -printtoconsole=0" \
  "TimeoutStopSec=600
$RUNDIR"
unit feeproxy "the Bitcoin node's RPC with fee estimates from the live mempool" "$(U bitcoind)" \
  "/usr/bin/python3 -I $BIN/fee-proxy.py --listen 127.0.0.1:$FEE_PROXY_PORT --upstream 127.0.0.1:$BTC_RPC_PORT --cookie $LIB/bitcoin/$BTC_SUB/.cookie --floor $BTC_FEE_FLOOR --cap 500 $( [ "$BTC_CHAIN" = testnet4 ] || echo '--api ""' )" "$RUNDIR"
unit sequentiad "Sequentia Core" "$(U bitcoind)" "$OPT/sequentia/bin/sequentiad -conf=$ETC/sequentia.conf -datadir=$LIB/sequentia -daemon=0 -printtoconsole=0" \
  "TimeoutStopSec=600
$RUNDIR"
if [ -n "$PRICE_FEED_URL" ]; then
  unit priceserver "the node's price server: its fee rates from the price feed" "$(U sequentiad)" \
    "/usr/bin/python3 -I $OPT/sequentia/price-server/price_server.py --config $LIB/price-server.json" "$RUNDIR"
fi
unit arca-signer "the Arca signer: holds the operator key" "" \
  "$BIN/arca-signer --key-file $ETC/operator.key --genesis \${ARCA_GENESIS} --socket /run/$NAME/signer.sock --record $LIB/arca/signer.record" \
  "EnvironmentFile=$ETC/signer.env
$RUNDIR"
unit arcad "arcad, the Arca operator's server" "$PG_UNIT $(U arca-signer) $(U sequentiad) $(U seqln) $(U cln)" "$BIN/arcad $ETC/arcad.toml" \
  "KillSignal=SIGINT
ExecReload=/bin/kill -HUP \$MAINPID
TimeoutStopSec=30
Environment=RUST_LOG=info
$RUNDIR"
unit seqln "SeqLN, the Sequentia gateway" "$(U sequentiad)" "$OPT/seqln/lightningd/lightningd --lightning-dir=$LIB/seqln" \
  "ExecStartPre=-/bin/sh -c 'for d in $LIB/seqln/*/; do chmod 0750 \"\$\$d\"; done'
TimeoutStopSec=120
$RUNDIR"
unit cln "Core Lightning, the Bitcoin gateway" "$(U bitcoind) $(U feeproxy)" "$OPT/cln/usr/bin/lightningd --lightning-dir=$LIB/cln" \
  "ExecStartPre=-/bin/sh -c 'for d in $LIB/cln/*/; do chmod 0750 \"\$\$d\"; done'
TimeoutStopSec=120
$RUNDIR"
unit captaind "Bark's server (captaind)" "$PG_UNIT $(U feeproxy) $(U cln)" "$BIN/captaind --config $ETC/captaind.toml start" \
  "Environment=CAPTAIND_LOG=info
TimeoutStopSec=90
$RUNDIR"
unit watchmand "Bark's watchman (watchmand)" "$PG_UNIT $(U feeproxy) $(U captaind)" "$BIN/watchmand --config $ETC/watchmand.toml start" \
  "Environment=WATCHMAND_LOG=info
TimeoutStopSec=90
$RUNDIR"
if [ -n "$PEER_ARCA_URL" ]; then
  unit watchtower "the watchtower for the peer operator's users" "$(U sequentiad)" \
    "$BIN/arca --datadir $LIB/watchtower watchtower serve --listen 127.0.0.1:$WATCHTOWER_PORT --interval 10" "$RUNDIR"
fi
unit btc-watchtower "the watchtower for Bitcoin ark coins" "$(U feeproxy)" \
  "$BIN/arca --datadir $LIB/btc btc-watchtower serve --listen 127.0.0.1:$BTC_WATCHTOWER_PORT --interval 30" "EnvironmentFile=$ETC/btc-watchtower.env
$RUNDIR"
systemctl daemon-reload
say "units:${uchanged:- none changed}"
restart_if() {   # restart_if <word>: restarts its unit when its unit, binary or configuration changed, else starts it
  local w=$1 u; u=$(U "$1"); shift
  systemctl enable -q "$u"
  for x in "$w" "$@"; do case " $changed $uchanged $changed_bins " in *" $x "*) systemctl restart "$u"; say "restarted $u"; return;; esac; done
  systemctl is-active --quiet "$u" || { systemctl start "$u"; say "started $u"; }
}

step "the ports, kept from the kernel's ephemeral ports"
# Outgoing connections take local ports from 32768 to 60999; one that takes a
# daemon's port first stops it from listening. The bundle's ports are
# reserved (the union with any other bundle's, in one file).
f=/etc/sysctl.d/60-arca-bundles.conf
have=""; [ -f "$f" ] && have=$(sed -n 's/^net.ipv4.ip_local_reserved_ports *= *//p' "$f" | tr ',' ' ')
want=$(printf '%s\n' $have $SEQ_RPC_PORT $SEQ_P2P_PORT $BTC_RPC_PORT $BTC_P2P_PORT $FEE_PROXY_PORT $PG_PORT $ARCAD_PORT $ARCAD_METRICS_PORT \
  $SEQLN_PORT $CLN_PORT $CLN_GRPC_PORT $HOLD_GRPC_PORT $CAPTAIND_PORT $CAPTAIND_ADMIN_PORT $CAPTAIND_INTEGRATION_PORT $WATCHTOWER_PORT $BTC_WATCHTOWER_PORT | sort -n -u | paste -sd, -)
printf '# Ports the Arca operator bundles on this machine listen on (install.sh).\nnet.ipv4.ip_local_reserved_ports = %s\n' "$want" > "$f.new"
mv "$f.new" "$f"
sysctl -q -w "net.ipv4.ip_local_reserved_ports=$want" || say "could not reserve the ports here (a container without that right): a busy machine may take one before its daemon"
say "reserved: $want"

step "the Bitcoin node and its fee proxy"
restart_if bitcoind
WAIT_UNIT=$(U bitcoind) wait_for 300 "the Bitcoin node answering" btc_cli getblockchaininfo
restart_if feeproxy fee-proxy.py
say "$(btc_cli getblockchaininfo | jq -r '"\(.chain): \(.blocks) of \(.headers) blocks, \(.verificationprogress * 100 | floor)% verified"')"

step "the Sequentia node"
restart_if sequentiad
WAIT_UNIT=$(U sequentiad) wait_for 300 "the Sequentia node answering" seq_cli getblockchaininfo
GENESIS=$(seq_cli getblockhash 0)
say "$(seq_cli getblockchaininfo | jq -r '"\(.chain): \(.blocks) of \(.headers) blocks"'), genesis $GENESIS"
write_conf arca-signer 640 "$ETC/signer.env" < <(printf 'ARCA_GENESIS=%s\n' "$GENESIS")
if [ -n "$PRICE_FEED_URL" ]; then
  restart_if priceserver sequentiad
  # The rates the gateway opens its channels with and arcad values each asset
  # at. A price server that stops clears the node's whole list, so after its
  # restart the node takes no fee at all until its first publish (the feed and
  # the registry read first): up to a few minutes.
  for ((i = 0; i < 360; i++)); do
    r=$(node_rates); missing=""
    for id in "${ASSET_IDS[@]}"; do jq -e --arg a "$id" 'has($a)' <<<"$r" >/dev/null || missing+=" ${id:0:12}…"; done
    [ -z "$missing" ] && break; sleep 1
  done
  if [ -n "$missing" ]; then say "the price feed gives no rate for:$missing so the node takes no fee in it: no channel opens in it, and its rate source must be none; set its rate yourself (sequentia-cli setfeeexchangerates) or serve another asset"
  else say "a fee rate for every served asset, from $PRICE_FEED_URL"; fi
fi

step "the signer and its record"
if [ ! -f "$LIB/arca/signer.record" ]; then
  # An operator holding only its own coins runs without keepers; one that holds
  # other people's coins follows doc/operator-procedure.md (three keepers).
  as_user "$BIN/arca-signer" --key-file "$ETC/operator.key" --genesis "$GENESIS" --record "$LIB/arca/signer.record" --create-record --no-keepers </dev/null
  say "made the record (no keepers)"
fi
OPERATOR_KEY=$(as_user "$BIN/arca-signer" --key-file "$ETC/operator.key" --pubkey </dev/null)
restart_if arca-signer arca-signer
WAIT_UNIT=$(U arca-signer) wait_for 60 "the signer's socket" test -S "/run/$NAME/signer.sock"
say "operator key $OPERATOR_KEY"

x=$(btc_cli getblockchaininfo); y=$(seq_cli getblockchaininfo)
if [ "$(jq -r '.initialblockdownload' <<<"$x")" = true ] || [ "$(jq -r '.initialblockdownload' <<<"$y")" = true ]; then
  # The Sequentia node checks every block's anchor against this Bitcoin node,
  # so it takes no block (not even a header) anchored above what that node
  # has: it waits for it. The gateways, Bark's server, its watchman and arcad
  # want their chains caught up, so they start once both are.
  for u in seqln cln captaind watchmand arcad; do systemctl stop "$(U "$u")" 2>/dev/null || true; done
  printf '\nThe chains are still syncing: Bitcoin %s of %s blocks, Sequentia %s of %s (it waits for the\nBitcoin node, whose blocks its anchors name). The nodes run on and keep syncing; run\n%s again once both have caught up (%s status shows how far they are), to\nstart the gateways, Bark'"'"'s server, its watchman and arcad.\n' \
    "$(jq -r .blocks <<<"$x")" "$(jq -r .headers <<<"$x")" "$(jq -r .blocks <<<"$y")" "$(jq -r .headers <<<"$y")" "$0" "$0"
  exit 0
fi

step "the gateways"
restart_if seqln lightningd
WAIT_UNIT=$(U seqln) wait_for 600 "SeqLN answering" seqln getinfo
restart_if cln hold
WAIT_UNIT=$(U cln) wait_for 300 "Core Lightning answering" cln getinfo
for f in ca.pem client.pem client-key.pem hold/ca.pem hold/client.pem hold/client-key.pem; do
  WAIT_UNIT=$(U cln) wait_for 120 "the Bitcoin gateway's $f" test -s "$LIB/cln/$BTC_SUB/$f"
done
say "SeqLN $(seqln getinfo | jq -r '.id + " on " + .network'), port $SEQLN_PORT"
say "Core Lightning $(cln getinfo | jq -r '.id + " on " + .network'), port $CLN_PORT"

step "Bark's server and watchman"
ark_url="http://127.0.0.1:$CAPTAIND_PORT"; [ -n "$DOMAIN" ] && ark_url="https://$DOMAIN"
SWEEP_ADDRESS=""
write_conf captaind 640 "$ETC/captaind.toml" < <(captaind_toml)
x=$(as_user "$BIN/captaind" check-config "$ETC/captaind.toml" 2>&1 </dev/null) || die "captaind refuses its configuration: $x"
if [ ! -f "$LIB/captaind/mnemonic" ]; then
  as_user "$BIN/captaind" --config "$ETC/captaind.toml" create > "$LOG/captaind-create.log" 2>&1 </dev/null \
    || { tail -5 "$LOG/captaind-create.log"; die "captaind create failed"; }
  say "captaind drew its key: $LIB/captaind/mnemonic (mode 600)"
fi
restart_if captaind captaind
WAIT_UNIT=$(U captaind) wait_for 300 "captaind's admin interface" captaind_rpc wallet
SWEEP_ADDRESS=$(cat "$LIB/captaind/sweep-address" 2>/dev/null || true)
if [ -z "$SWEEP_ADDRESS" ]; then
  SWEEP_ADDRESS=$(captaind_rpc wallet | jq -r '.rounds.address')
  [ -n "$SWEEP_ADDRESS" ] && [ "$SWEEP_ADDRESS" != null ] || die "captaind names no round wallet address"
  printf '%s\n' "$SWEEP_ADDRESS" > "$LIB/captaind/sweep-address"; chown "$USER_:$USER_" "$LIB/captaind/sweep-address"
fi
if [ ! -f "$LIB/watchmand/mnemonic" ]; then install -m 600 -o "$USER_" -g "$USER_" "$LIB/captaind/mnemonic" "$LIB/watchmand/mnemonic"; fi
cmp -s "$LIB/captaind/mnemonic" "$LIB/watchmand/mnemonic" || die "the watchman's key is not the server's"
write_conf watchmand 640 "$ETC/watchmand.toml" < <(captaind_toml watchman)
x=$(as_user "$BIN/captaind" check-config --watchman "$ETC/watchmand.toml" 2>&1 </dev/null) || die "watchmand's configuration is refused: $x"
restart_if watchmand watchmand
say "the ark's round wallet: $SWEEP_ADDRESS"

step "arcad"
write_arcad_toml
restart_if arcad arcad
syncing=$(seq_cli getblockchaininfo | jq -r '.initialblockdownload or (.blocks < .headers)')
if [ "$syncing" = true ]; then
  say "the Sequentia node is still syncing: arcad starts serving once it has caught up (install.sh status)"
else
  WAIT_UNIT=$(U arcad) wait_for 600 "arcad answering" info
  say "serving: $(info | jq -r '[.assets[].asset[0:12]] | join(", ")')"
fi

if [ -n "$PEER_ARCA_URL" ]; then
  step "the watchtower for the users of $PEER_ARCA_URL"
  tower_wallet || die "the watchtower's wallet could not be made against $PEER_ARCA_URL (above): its operator must answer; run $0 install again, or set PEER_ARCA_URL empty to run without one"
  restart_if watchtower arca
  WAIT_UNIT=$(U watchtower) wait_for 120 "the watchtower answering" curl -sf --max-time 5 "http://127.0.0.1:$WATCHTOWER_PORT/v1/info"
  say "it holds $(curl -sf --max-time 5 "http://127.0.0.1:$WATCHTOWER_PORT/v1/info" | jq -r .deposits) deposits; fund it with a fee asset ($0 addresses)"
fi

step "the watchtower for Bitcoin ark coins"
btc_tower_make || die "the Bitcoin ark watchtower could not be set up (above)"
restart_if btc-watchtower arca
WAIT_UNIT=$(U btc-watchtower) wait_for 120 "the Bitcoin ark watchtower answering" curl -sf --max-time 5 "http://127.0.0.1:$BTC_WATCHTOWER_PORT/v1/info"
say "it holds $(curl -sf --max-time 5 "http://127.0.0.1:$BTC_WATCHTOWER_PORT/v1/info" | jq -r .deposits) deposits; fund it with BTC ($0 addresses)"

if [ -n "$DOMAIN" ]; then
  step "the route: Caddy at https://$DOMAIN"
  install -d -m 755 "$LIB/www/.well-known"
  printf 'Authorize linking the domain name %s to the Arca operator key %s' "$DOMAIN" "$OPERATOR_KEY" > "$LIB/www/.well-known/sequentia-operator-proof-$OPERATOR_KEY"
  chmod 644 "$LIB/www/.well-known/sequentia-operator-proof-$OPERATOR_KEY"
  t=$(mktemp); caddyfile > "$t"
  c=0; cmp -s "$t" "$ETC/Caddyfile" 2>/dev/null || { install -m 644 "$t" "$ETC/Caddyfile"; c=1; }; rm -f "$t"
  t=$(mktemp)
  cat > "$t" <<EOF
[Unit]
Description=Caddy, the public route ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=$BIN/caddy run --environ --config $ETC/Caddyfile --adapter caddyfile
ExecReload=$BIN/caddy reload --config $ETC/Caddyfile --adapter caddyfile --force
Environment=XDG_DATA_HOME=$LIB/caddy XDG_CONFIG_HOME=$LIB/caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  if ! cmp -s "$t" "/etc/systemd/system/$(U caddy)" 2>/dev/null; then install -m 644 "$t" "/etc/systemd/system/$(U caddy)"; systemctl daemon-reload; c=1; fi; rm -f "$t"
  systemctl enable -q "$(U caddy)"
  if [ "$c" = 1 ]; then systemctl restart "$(U caddy)"; else systemctl start "$(U caddy)"; fi
  say "https://$DOMAIN/arca/v1/info, the watchtower at https://$DOMAIN/watchtower/v1/info and the Bitcoin ark at https://$DOMAIN"
fi

step "log rotation"
cat > "/etc/logrotate.d/$NAME" <<EOF
$LOG/*.log {
	daily
	rotate 14
	compress
	delaycompress
	missingok
	notifempty
	copytruncate
	su $USER_ $USER_
}
EOF
say "/etc/logrotate.d/$NAME"

step "check"
for u in $UNITS; do st=$(systemctl is-active "$(U "$u")" || true); [ "$st" = active ] || { [ "$u" = arcad ] && [ "$syncing" = true ] && [ "$st" = activating ]; } || die "$(U "$u") is not running: $(journalctl -u "$(U "$u")" -n 5 --no-pager -o cat | tr '\n' ' ')"; done
systemctl is-active --quiet "$PG_UNIT" || die "$PG_UNIT is not running"
say "every unit is running"
cat <<EOF

The bundle runs. Next:
  1. Wait for both nodes to sync: $0 status
  2. Pay the pools and the gateways: $0 addresses
  3. Open the gateways' channels to the peer's: $0 connect
  4. Holding other people's coins, post the equivocation bond: $0 bond
  5. With DOMAIN set, list the operator: $0 register
EOF
}

# ===========================================================================================
status() {
  if ! command -v systemctl >/dev/null; then
    step "containers"; say "each daemon runs in a container of its own: docker compose ps"
  else
  step "units"
  for u in $UNITS caddy; do
    [ -f "/etc/systemd/system/$(U "$u")" ] || continue
    printf '  %-28s %s\n' "$(U "$u")" "$(systemctl is-active "$(U "$u")" || true)"
  done
  printf '  %-28s %s\n' "$PG_UNIT" "$(systemctl is-active "$PG_UNIT" || true)"
  fi
  step "chains"
  say "Bitcoin:   $(btc_cli getblockchaininfo 2>/dev/null | jq -r '"\(.chain) \(.blocks)/\(.headers) blocks, \(.verificationprogress * 100 | floor)% verified"' || echo 'not answering')"
  say "Sequentia: $(seq_cli getblockchaininfo 2>/dev/null | jq -r '"\(.chain) \(.blocks)/\(.headers) blocks"' || echo 'not answering'), $(seq_cli getconnectioncount 2>/dev/null || echo 0) peers"
  step "the Arca operator"
  i=$(info || true)
  if [ -n "$i" ]; then
    say "key $(jq -r .operator <<<"$i"), exit delays $(jq -c .exit_delay_units <<<"$i")"
    jq -r '.assets[] | "  \(.asset[0:16])… min leaf \(.min_leaf), lightning \(.lightning.state // "none"), \(.lightning.channels // 0) channels"' <<<"$i" | cut -c1-200
    say "Bitcoin leg: $(jq -r '.lightning.bitcoin // {} | "\(.node.state // "none"), \(.node.channels // 0) channels, ark \(.ark // "none")"' <<<"$i")"
    say "bond: $(jq -r '.bond // {} | .state // "none"' <<<"$i") ($0 bond)"
    say "watchtowers it names for its users: $(jq -c '.watchtowers // []' <<<"$i")"
  else say "arcad is not answering"; fi
  if [ -n "$PEER_ARCA_URL" ]; then
    step "the watchtower for the users of $PEER_ARCA_URL"
    say "$(curl -sf --max-time 5 "http://127.0.0.1:$WATCHTOWER_PORT/v1/info" | jq -r '"\(.deposits) deposits, for operator \(.operator[0:16])…"' || echo 'not answering')"
  fi
  step "the watchtower for Bitcoin ark coins"
  say "$(curl -sf --max-time 5 "http://127.0.0.1:$BTC_WATCHTOWER_PORT/v1/info" | jq -r '"\(.deposits) deposits, \(.float_sat) sat of its own for fees, arks \(if (.arks | length) == 0 then "any" else (.arks | join(", ")) end)"' || echo 'not answering')"
  step "the Bitcoin ark"
  say "$(captaind_rpc wallet 2>/dev/null | jq -c '.rounds | {address, total_balance, trusted_balance}' || echo 'captaind is not answering')"
  step "gateways"
  say "SeqLN: $(seqln getinfo 2>/dev/null | jq -r '"\(.id) block \(.blockheight), \(.num_active_channels) active channels"' || echo 'not answering')"
  seqln listpeerchannels 2>/dev/null | jq -r '.channels[] | "    \(.peer_id[0:16])… \(.state) asset \((.channel_asset // .asset // "?")[0:12]) ours \(.to_us_msat) of \(.total_msat)"' || true
  say "Core Lightning: $(cln getinfo 2>/dev/null | jq -r '"\(.id) block \(.blockheight), \(.num_active_channels) active channels"' || echo 'not answering')"
  cln listpeerchannels 2>/dev/null | jq -r '.channels[] | "    \(.peer_id[0:16])… \(.state) ours \(.to_us_msat) of \(.total_msat)"' || true
}

addresses() {
  step "where to pay (each line: what, then a fresh address)"
  say "operator-pools: $(arcad_cmd address 2>/dev/null | jq -r .address)"
  say "    the Arca operator's pools: each served asset; every round is funded from them"
  say "ark-rounds: $(captaind_rpc wallet | jq -r .rounds.address)"
  say "    the Bitcoin ark's round wallet: BTC its rounds are built from"
  say "seqln: $(seqln newaddr | jq -r '.bech32 // .p2tr')"
  say "    the SeqLN gateway: each asset its channels are opened in, and a fee asset"
  say "cln: $(cln newaddr p2tr | jq -r '.p2tr // .bech32')"
  say "    the Bitcoin gateway: BTC for its channel and its fees"
  if [ -s "$LIB/watchtower/arca.sqlite" ]; then
    say "watchtower: $(as_user "$BIN/arca" --datadir "$LIB/watchtower" address </dev/null 2>/dev/null | jq -r .address)"
    say "    the watchtower for the peer's users: an asset accepted for fees, for steps a coin's reserves cannot pay"
  fi
  if [ -s "$LIB/btc/btc-watchtower/config.json" ]; then
    say "btc-watchtower: $(set -a; . "$ETC/btc-watchtower.env"; as_user "$BIN/arca" --datadir "$LIB/btc" btc-watchtower address </dev/null 2>/dev/null | jq -r .address)"
    say "    the watchtower for Bitcoin ark coins: BTC for the fees of the coins it brings on chain, several coins so it can pay several at once"
  fi
}

connect() {
  [ -n "$PEER_ARCA_URL" ] && [ -n "$PEER_HOST" ] || die "set PEER_ARCA_URL and PEER_HOST in $BUNDLE_ENV"
  step "the peer: $PEER_ARCA_URL"
  pi=$(curl -sf --max-time 20 "$PEER_ARCA_URL/v1/info") || die "the peer's info does not answer at $PEER_ARCA_URL/v1/info"
  [ "$(jq -r .genesis_hash <<<"$pi")" = "$(seq_cli getblockhash 0)" ] || die "the peer runs another chain than this node"
  step "SeqLN: a channel to the peer's node in each served asset it serves too"
  for id in "${ASSET_IDS[@]}"; do
    pid=$(jq -r --arg a "$id" '.assets[] | select(.asset == $a) | .lightning.node // empty' <<<"$pi")
    # A leg names its node only while up, which takes a channel in the asset:
    # a peer with none yet is named by PEER_SEQLN_ID.
    if [ -z "$pid" ] && [ -n "$PEER_SEQLN_ID" ] && jq -e --arg a "$id" '.assets[] | select(.asset == $a) | .lightning' <<<"$pi" >/dev/null; then pid=$PEER_SEQLN_ID; fi
    [ -n "$pid" ] || { say "${id:0:12}…: the peer's leg in it is not up (it serves no Lightning in it, or its node is down); no channel"; continue; }
    seqln connect "$pid" "$PEER_HOST" "$PEER_SEQLN_PORT" >/dev/null
    have=$(seqln listpeerchannels "$pid" | jq --arg a "$id" '[.channels[] | select((.channel_asset // .asset) == $a and (.state | test("CLOSING|ONCHAIN|CLOSED") | not))] | length')
    if [ "$have" -gt 0 ]; then say "${id:0:12}…: a channel is open already"; continue; fi
    amt=$(channel_atoms "$id"); [ "$amt" -gt 0 ] || { say "${id:0:12}…: no channel size set"; continue; }
    jq -e --arg a "$id" 'has($a)' <<<"$(node_rates)" >/dev/null \
      || die "${id:0:12}…: this node takes no fee in it, and a channel in an asset is opened with a fee in that asset: run the price server (PRICE_FEED_URL) or set its rate (sequentia-cli setfeeexchangerates)"
    r=$(seqln -k fundchannel id="$pid" amount="$amt" asset="$id" push_msat="$((amt / 2 * 1000))" announce=false 2>&1) \
      || die "${id:0:12}…: SeqLN did not open the channel: $(jq -r '.message // empty' <<<"$r" 2>/dev/null || true) ${r:0:300}"
    say "${id:0:12}…: opened $amt atoms, half pushed: $(jq -r .txid <<<"$r")"
  done
  step "Core Lightning: a channel to the peer's Bitcoin gateway"
  bid=$(jq -r '.lightning.bitcoin.node.node // empty' <<<"$pi"); [ -n "$bid" ] || bid=$PEER_BTC_LN_ID
  if [ -z "$bid" ]; then say "the peer names no Bitcoin gateway; no channel"; else
    cln connect "$bid" "$PEER_HOST" "$PEER_BTC_LN_PORT" >/dev/null
    have=$(cln listpeerchannels "$bid" | jq '[.channels[] | select(.state | test("CLOSING|ONCHAIN|CLOSED") | not)] | length')
    if [ "$have" -gt 0 ]; then say "a channel is open already"; else
      r=$(cln -k fundchannel id="$bid" amount="$CHANNEL_SAT" push_msat="$((CHANNEL_SAT / 2 * 1000))" announce=false 2>&1) \
        || die "Core Lightning did not open the channel: ${r:0:300}"
      say "opened $CHANNEL_SAT sat, half pushed: $(jq -r .txid <<<"$r")"
    fi
  fi
  say "the channels are usable once their funding confirms: $0 status"
}

register() {
  [ -n "$DOMAIN" ] || die "the registry lists an operator by its public route: set DOMAIN in $BUNDLE_ENV"
  [ -n "$CONTACT_NAME" ] || die "set CONTACT_NAME in $BUNDLE_ENV"
  step "the operator's record, from its own info"
  R=$CACHE/build/sequentia-registry
  if [ -d "$R/.git" ]; then git -C "$R" pull -q --ff-only; else git clone -q https://github.com/ConcatenaLabs/sequentia-registry.git "$R"; fi
  w=$(mktemp -d); chmod 755 "$w"
  args=(--info "http://127.0.0.1:$ARCAD_PORT" --api "https://$DOMAIN/arca" --contact-name "$CONTACT_NAME" --contact-domain "$DOMAIN")
  [ -n "$CONTACT_EMAIL" ] && args+=(--contact-email "$CONTACT_EMAIL")
  node "$R/tools/operator-record.js" "${args[@]}" > "$w/record.json"
  chmod 644 "$w/record.json"
  as_user "$BIN/arca-signer" --key-file "$ETC/operator.key" --genesis "$(seq_cli getblockhash 0)" --sign-operator-record "$w/record.json" > "$w/signed.json" </dev/null
  step "posted to $REGISTRY_URL"
  out=$(curl -s -w '\n%{http_code}' -X POST -H 'content-type: application/json' --data @"$w/signed.json" "$REGISTRY_URL/operators")
  rm -rf "$w"
  code=${out##*$'\n'}; say "${out%$'\n'*}"
  case $code in 2*) say "listed";; *) die "the registry answered $code";; esac
}

# The equivocation bond, one step at a time: it says what is still to choose
# or to pay, and where, and posts the bond once everything is there. Run it
# again after each step; once the bond stands it only reports it.
bond() {
  step "the equivocation bond"
  say "A coin the operator loses if it ever co-signs two spends of one coin: wallets weigh it"
  say "before trusting payments made out of round. An operator holding only its own coins can"
  say "go without; one holding other people's posts it (doc/operator-procedure.md)."
  local i st todo=() fees
  i=$(info) || die "arcad is not answering: $0 status"
  st=$(jq -r '.bond.state // "none"' <<<"$i")
  case $st in
    bonded)
      say "bonded: $(jq -r '.bond | "\((.value | tonumber) / 100000000) of \(.asset[0:12])…, \(.outpoint), final: \(.final)"' <<<"$i")"
      say "to end it, give the notice first, with the withdrawal key's file: arcad $ETC/arcad.toml bond-notice <file>"
      return 0 ;;
    unconfirmed) say "posted, in no block yet: $(jq -r .bond.outpoint <<<"$i"). Run $0 bond again once it confirms."; return 0 ;;
    missing|spent|noticed) die "the bond reads $st: $(jq -r '.bond.why // empty' <<<"$i")" ;;
  esac

  fees=$(sed -n 's/^fee_assets = \[\(.*\)\]$/\1/p' "$ETC/arcad.toml" | tr -d '" ' | tr ',' '\n' | sed 's/^/      /')
  [ -n "$BOND_WITHDRAW_KEY" ] || todo+=("BOND_WITHDRAW_KEY, the withdrawal key: the only key that can ever end the bond.
    Draw it on a machine other than this one, never here: copy $BIN/arcad (Linux x86_64)
    there and run   arcad bond-key bond-withdraw.key
    It prints {\"withdraw_key\": ...}: put that key here. Keep the file, and a backup of it, off
    this server: whoever holds it can end the bond, and without it nobody can.")
  [ -n "$BOND_ASSET" ] || todo+=("BOND_ASSET, the asset the bond is posted in, its fee paid in it too: one this node
    takes fees in. The operator's fee assets:
$fees")
  [ -n "$BOND_ATOMS" ] || todo+=("BOND_ATOMS, its size in atoms. Size it above what holders keep out of round together,
    not one holder's most: a double spend must cost the operator more than it could take,
    and one slash burns the bond once.")
  if [ ${#todo[@]} -gt 0 ]; then
    step "still to choose, in $BUNDLE_ENV"
    for t in "${todo[@]}"; do printf '  - %s\n' "$t"; done
    say "BOND_NOTICE_UNITS ($BOND_NOTICE_UNITS) is the notice before a withdrawal, at least a coin's lifetime,"
    say "the longest exit delay and a day; BOND_WALLET ($BOND_WALLET) the node wallet it is paid from."
    say "Then: $0 install (it writes the bond's terms and turns the node's wallet on), and $0 bond again."
    exit 1
  fi
  grep -q "^withdraw_key = \"$BOND_WITHDRAW_KEY\"" "$ETC/arcad.toml" && [ "$st" = unposted ] \
    || die "arcad does not run with these terms yet: $0 install, then $0 bond again"

  step "the operating wallet: $BOND_WALLET"
  if ! seq_cli -rpcwallet="$BOND_WALLET" getwalletinfo >/dev/null 2>&1; then
    seq_cli loadwallet "$BOND_WALLET" >/dev/null 2>&1 \
      || seq_cli -named createwallet wallet_name="$BOND_WALLET" load_on_startup=true >/dev/null \
      || die "the node made no wallet $BOND_WALLET: is its wallet on? $0 install"
    say "made and loaded"
  else
    say "loaded"
  fi
  # The bond, and a thousandth over for its fee (at least 0.001 of a unit):
  # what is left stays in the wallet.
  local need have pend addr
  need=$((BOND_ATOMS + (BOND_ATOMS / 1000 > 100000 ? BOND_ATOMS / 1000 : 100000)))
  units() { python3 -I -c 'import sys; from decimal import Decimal as D; print(D(sys.argv[1]) / D(100000000))' "$1"; }
  atoms() { python3 -I -c 'import sys; from decimal import Decimal as D; print(int(D(sys.argv[1]) * 100000000))' "$1"; }
  have=$(atoms "$(seq_cli -rpcwallet="$BOND_WALLET" -named getbalance minconf=1 assetlabel="$BOND_ASSET")")
  if [ "$have" -lt "$need" ]; then
    pend=$(atoms "$(seq_cli -rpcwallet="$BOND_WALLET" -named getbalance minconf=0 assetlabel="$BOND_ASSET")")
    addr=$(seq_cli -rpcwallet="$BOND_WALLET" getnewaddress "bond" bech32)
    addr=$(seq_cli -rpcwallet="$BOND_WALLET" getaddressinfo "$addr" | jq -r '.unconfidential // .address')
    step "to pay"
    say "$(units "$need") of ${BOND_ASSET:0:12}… (the bond, $(units "$BOND_ATOMS"), and its fee) to"
    say "  $addr"
    say "the wallet holds $(units "$have") confirmed$( [ "$pend" -gt "$have" ] && printf ', %s with what is still unconfirmed' "$(units "$pend")")."
    say "Once it confirms: $0 bond"
    return 0
  fi

  step "posting $(units "$BOND_ATOMS") of ${BOND_ASSET:0:12}… from $BOND_WALLET"
  local r err; err=$(mktemp)
  r=$(arcad_cmd bond-post "$BOND_WALLET" "$BOND_ASSET" "$BOND_ATOMS" 2>"$err") \
    || { r=$(tail -c 400 "$err"); rm -f "$err"; die "arcad did not post the bond: $r"; }
  rm -f "$err"
  jq -r .outpoint <<<"$r" > "$ETC/bond.outpoint"
  chown root:"$USER_" "$ETC/bond.outpoint"; chmod 640 "$ETC/bond.outpoint"
  say "paid: $(jq -r .outpoint <<<"$r")"
  write_arcad_toml
  if [ -d /run/systemd/system ]; then
    systemctl restart "$(U arcad)"
    WAIT_UNIT=$(U arcad) wait_for 300 "arcad answering" info
    say "the bond reads $(info | jq -r .bond.state); $0 bond again shows it once final"
  else
    say "restart arcad to name it (docker compose restart arcad), then $0 bond"
  fi
}

credentials() {
  step "RPC logins for a Lightning wallet beside the bundle (Fulmen)"
  say "Sequentia node: 127.0.0.1:$SEQ_RPC_PORT, user $NAME, password $(cat "$ETC/seq-rpc.password")"
  say "Bitcoin node:   127.0.0.1:$BTC_RPC_PORT, user $NAME, password $(cat "$ETC/btc-rpc.password")"
}

# Sourced by docker/bundle-run for the functions above: nothing runs.
[ "${BUNDLE_LIB:-}" = 1 ] && return 0

case $CMD in
  install) prepare; configure_and_start ;;
  build) prepare ;;
  status) status ;;
  addresses) addresses ;;
  connect) connect ;;
  register) register ;;
  bond) bond ;;
  credentials) credentials ;;
  *) die "unknown command $CMD (install, status, addresses, connect, bond, register, credentials)" ;;
esac
