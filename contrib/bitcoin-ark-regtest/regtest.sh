#!/usr/bin/env bash
# A Bitcoin ark on regtest, for the tests of the wallet's Bitcoin side
# (bark-cli/tests/arca_bitcoin_ark.rs) and for trying the Arca client against
# one: Bitcoin Core, a gateway Core Lightning with Boltz's hold plugin and
# cln-grpc, a peer Core Lightning (the outside payer and payee, with a
# channel from the gateway), PostgreSQL, and Bark's server, captaind, at the
# release the wallet bundles. Every process it starts is written to $H/pids,
# and `down` stops exactly those.
#
#   regtest.sh up | down | info | mine N | miner-start SECS | miner-stop
#   regtest.sh btc ARGS… | gw ARGS… | peer ARGS… | admin ARGS…
#
# Environment (the binaries are not built here; see README.md):
#   H          the directory for every daemon's data and logs (required)
#   CORE_BIN   a directory with bitcoind and bitcoin-cli, version 31 or later
#              (captaind's own minimum)
#   CLN_BIN    a directory with lightningd and lightning-cli (upstream Core
#              Lightning, whose plugins include cln-grpc)
#   HOLD       Boltz's hold plugin
#   CAPTAIND   Bark's captaind
#   PG_BIN     a directory with initdb, postgres and psql
#   PORT_BASE  the first of 100 loopback ports to use (default 23100)
set -euo pipefail
: "${H:?name the state directory, H}" "${CORE_BIN:?}" "${CLN_BIN:?}" "${HOLD:?}" "${CAPTAIND:?}" "${PG_BIN:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"
P=${PORT_BASE:-23100}
BTC_RPC=$((P + 42)) BTC_P2P=$((P + 43)) PG_PORT=$((P + 20))
GW_PORT=$((P + 74)) GW_GRPC=$((P + 75)) HOLD_GRPC=$((P + 76)) PEER_PORT=$((P + 84))
ARK_PORT=$((P + 45)) ADMIN_PORT=$((P + 46)) INTEGRATION_PORT=$((P + 47))
CORE=$CORE_BIN CLN=$CLN_BIN PGBIN=$PG_BIN

btc() { $CORE/bitcoin-cli -regtest -datadir=$H/btc -rpcport=$BTC_RPC "$@"; }
gw() { $CLN/lightning-cli --lightning-dir=$H/gw --network=regtest "$@"; }
peer() { $CLN/lightning-cli --lightning-dir=$H/peer --network=regtest "$@"; }
admin() { $CAPTAIND rpc --addr "http://127.0.0.1:$ADMIN_PORT" "$@"; }
rec() { echo "$1 $2" >> $H/pids; }
wait_for() { local t=$1; shift; local i; for i in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; echo "timed out: $*" >&2; return 1; }
mine() { btc generatetoaddress "$1" "$(cat $H/miner.addr)" >/dev/null; }

up() {
  mkdir -p $H/btc $H/gw $H/peer $H/captaind $H/log
  : > $H/pids
  echo "=== bitcoind ==="
  $CORE/bitcoind -regtest -datadir=$H/btc -rpcport=$BTC_RPC -port=$BTC_P2P -bind=127.0.0.1:$BTC_P2P -listen=1 -txindex=1 \
    -fallbackfee=0.0001 -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -debuglogfile=$H/log/bitcoind.log -printtoconsole=0 >/dev/null 2>&1 &
  rec bitcoind $!
  wait_for 60 btc getblockchaininfo
  btc createwallet miner >/dev/null
  btc getnewaddress > $H/miner.addr
  mine 150
  echo "=== postgres ==="
  $PGBIN/initdb -D $H/pg -U postgres -A trust >$H/log/initdb.log
  $PGBIN/postgres -D $H/pg -p $PG_PORT -k $H -c listen_addresses=127.0.0.1 >$H/log/pg.log 2>&1 &
  rec postgres $!
  wait_for 30 $PGBIN/psql -h 127.0.0.1 -p $PG_PORT -U postgres -c 'select 1'
  $PGBIN/psql -q -h 127.0.0.1 -p $PG_PORT -U postgres -c 'CREATE ROLE bark LOGIN' -c 'CREATE DATABASE bark_captaind OWNER bark'
  echo "=== gateway CLN (hold, cln-grpc) ==="
  cat > $H/gw/config <<EOF
network=regtest
bitcoin-datadir=$H/btc
bitcoin-rpcport=$BTC_RPC
bitcoin-cli=$CORE/bitcoin-cli
alias=ark-gateway
addr=127.0.0.1:$GW_PORT
grpc-port=$GW_GRPC
important-plugin=$HOLD
hold-grpc-port=$HOLD_GRPC
developer
dev-fast-gossip
dev-bitcoind-poll=1
log-file=$H/log/gw.log
log-level=info
EOF
  $CLN/lightningd --lightning-dir=$H/gw >/dev/null 2>&1 &
  rec lightningd-gw $!
  echo "=== peer CLN ==="
  cat > $H/peer/config <<EOF
network=regtest
bitcoin-datadir=$H/btc
bitcoin-rpcport=$BTC_RPC
bitcoin-cli=$CORE/bitcoin-cli
alias=peer
addr=127.0.0.1:$PEER_PORT
disable-plugin=cln-grpc
developer
dev-fast-gossip
dev-bitcoind-poll=1
log-file=$H/log/peer.log
log-level=info
EOF
  $CLN/lightningd --lightning-dir=$H/peer >/dev/null 2>&1 &
  rec lightningd-peer $!
  wait_for 60 gw getinfo; wait_for 60 peer getinfo
  for f in ca.pem client.pem client-key.pem hold/ca.pem hold/client.pem hold/client-key.pem; do wait_for 60 test -f $H/gw/regtest/$f; done
  echo "=== channel gateway -> peer, 2,000,000 sat, 1,000,000 pushed ==="
  btc -rpcwallet=miner sendtoaddress "$(gw newaddr p2tr | jq -r .p2tr)" 0.05 >/dev/null
  btc -rpcwallet=miner sendtoaddress "$(peer newaddr p2tr | jq -r .p2tr)" 0.05 >/dev/null
  mine 6
  wait_for 60 sh -c "[ \"\$($CLN/lightning-cli --lightning-dir=$H/gw --network=regtest listfunds | jq '.outputs|length')\" -gt 0 ]"
  gw connect "$(peer getinfo | jq -r .id)@127.0.0.1:$PEER_PORT" >/dev/null
  gw fundchannel "$(peer getinfo | jq -r .id)" 2000000 normal true 1 null 1000000000msat >/dev/null
  mine 6
  wait_for 120 sh -c "$CLN/lightning-cli --lightning-dir=$H/gw --network=regtest listpeerchannels | jq -e '.channels[0].state==\"CHANNELD_NORMAL\"'"
  echo "=== captaind ==="
  sed -e "s#@H@#$H#g" -e "s#@PG_PORT@#$PG_PORT#g" -e "s#@BTC_RPC@#$BTC_RPC#g" -e "s#@GW_GRPC@#$GW_GRPC#g" -e "s#@HOLD_GRPC@#$HOLD_GRPC#g" \
    -e "s#@ARK_PORT@#$ARK_PORT#g" -e "s#@ADMIN_PORT@#$ADMIN_PORT#g" -e "s#@INTEGRATION_PORT@#$INTEGRATION_PORT#g" \
    $HERE/captaind.toml.in > $H/captaind.toml
  $CAPTAIND --config $H/captaind.toml create > $H/log/captaind-create.log 2>&1
  CAPTAIND_LOG=info $CAPTAIND --config $H/captaind.toml start > $H/log/captaind.log 2>&1 &
  rec captaind $!
  wait_for 120 admin wallet
  addr=$(admin wallet | jq -r .rounds.address)
  btc -rpcwallet=miner sendtoaddress "$addr" 5 >/dev/null
  mine 3
  info
  echo UP
}

down() {
  miner_stop || true
  [ -f $H/pids ] || { echo "nothing recorded"; return 0; }
  tac $H/pids | while read -r name pid; do
    if kill -0 "$pid" 2>/dev/null; then echo "stopping $name ($pid)"; kill "$pid"; fi
  done
  for _ in $(seq 60); do
    alive=0; while read -r _n pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < $H/pids
    [ $alive = 0 ] && break; sleep 1
  done
  while read -r name pid; do kill -0 "$pid" 2>/dev/null && echo "STILL RUNNING $name $pid"; done < $H/pids
  echo DOWN
}

info() {
  printf '{"ark": "http://127.0.0.1:%s", "bitcoind": "http://127.0.0.1:%s", "cookie": "%s"}\n' "$ARK_PORT" "$BTC_RPC" "$H/btc/regtest/.cookie"
}

miner_start() {   # a block every $1 seconds, while it runs
  ( while true; do mine 1 || true; sleep "$1"; done ) > /dev/null 2>&1 &
  echo $! > $H/miner.pid
  echo "miner $(cat $H/miner.pid)"
}
miner_stop() { if [ -f $H/miner.pid ]; then kill "$(cat $H/miner.pid)" 2>/dev/null || true; rm -f $H/miner.pid; fi; }

cmd=${1:-}; shift || true
case "$cmd" in
  up) up ;; down) down ;; info) info ;; mine) mine "$1" ;; miner-start) miner_start "$1" ;; miner-stop) miner_stop ;;
  btc) btc "$@" ;; gw) gw "$@" ;; peer) peer "$@" ;; admin) admin "$@" ;;
  *) echo "usage: regtest.sh up|down|info|mine N|miner-start S|miner-stop|btc|gw|peer|admin" >&2; exit 1 ;;
esac
