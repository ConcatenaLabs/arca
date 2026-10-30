#!/usr/bin/env bash
# Two operators and a Bitcoin ark on one machine, on regtest, for running
# operator-tests.sh where stopping an operator harms nobody:
#
#   operator A   the scenarios' whole server kept running
#                (bark-cli/tests/arca_operator_for_browsers.rs, with
#                ARCA_OPERATOR_LIGHTNING): the chain, its SeqLN nodes in X,
#                and the control address that produces blocks, buries them,
#                moves the median time and pays from the test's coins
#   operator B   arcad and arca-signer as separate processes, with a
#                PostgreSQL cluster of its own and a SeqLN node in X with a
#                channel to A's: the operator the tests stop and start
#   Bitcoin ark  contrib/bitcoin-ark-regtest/regtest.sh: Bitcoin Core,
#                captaind, its Core Lightning gateway and a peer
#
#   regtest-standin.sh up | down | env | ctl PATH [JSON] | stop-b | kill-b |
#                      start-b | stop-ark | start-ark | fund ADDRESS ASSET ATOMS
#
# `env` prints the variables operator-tests.sh reads, with the chain hooks
# pointing back at this script. Every process `up` starts is written to
# $S/pids, and `down` stops exactly those (and B's, and the ark's).
#
# Environment:
#   S           the directory for every daemon's data and logs (required)
#   ARCA_BIN    a directory with arca, arcad, arca-signer (target/debug)
#   B_BIN       the directory B's arcad and arca-signer come from (ARCA_BIN)
#   HARNESS     the compiled test binary of arca_operator_for_browsers
#   SEQUENTIAD_EXEC   sequentiad (sequentia-cli beside it)
#   LIGHTNINGD_EXEC   SeqLN's lightningd (lightning-cli in ../cli/)
#   PG_BIN      a directory with initdb and postgres (B's cluster is its own,
#               and B uses its database postgres)
#   CORE_BIN, CLN_BIN, HOLD, CAPTAIND   as contrib/bitcoin-ark-regtest needs
#   ARCA_BARK_EXEC, ARCA_BARKD_EXEC     Bark's bark and barkd, for wallets
#   PORT_BASE   the first of 200 loopback ports (default 23400)
set -euo pipefail
: "${S:?name the state directory, S}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
P=${PORT_BASE:-23400}
CTL=127.0.0.1:$((P + 100)) B_PORT=$((P + 101)) PGA_PORT=$((P + 102)) PGB_PORT=$((P + 103)) BLN_PORT=$((P + 104))
ARCA_BIN=${ARCA_BIN:-$ROOT/target/debug}
# Operator B's arcad and arca-signer: a release build for the load test.
B_BIN=${B_BIN:-$ARCA_BIN}
LCLI="$(dirname "$(dirname "${LIGHTNINGD_EXEC:-x/x/x}")")/cli/lightning-cli"

ctl() { local body=${2:-'{}'}; curl -sS -m 900 -X POST "http://$CTL$1" -H 'content-type: application/json' -d "$body"; }
rec() { echo "$1 $2" >> "$S/pids"; }
wait_for() { local t=$1; shift; local i; for i in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; echo "timed out: $*" >&2; return 1; }
state() { ctl /state; }
bln() { "$LCLI" --lightning-dir="$S/b/ln" --network="$(cat "$S/chain")" "$@"; }
ark() { H="$S/ark" PORT_BASE=$((P + 0)) "$ROOT/contrib/bitcoin-ark-regtest/regtest.sh" "$@"; }

start_pg() {   # $1 name, $2 port
  local d="$S/$1"
  if [ ! -d "$d/data" ]; then
    mkdir -p "$d"
    "$PG_BIN/initdb" -D "$d/data" -U postgres -A trust > "$d/initdb.log"
  fi
  "$PG_BIN/postgres" -D "$d/data" -p "$2" -k "$d" -c listen_addresses=127.0.0.1 > "$d/pg.log" 2>&1 &
  rec "$1" $!
  wait_for 30 grep -q "ready to accept connections" "$d/pg.log"
}

b_config() {
  local st x y url user pass ln=""
  st=$(state)
  x=$(jq -r .x <<<"$st"); y=$(jq -r .y <<<"$st"); url=$(jq -r .node_url <<<"$st")
  user=$(jq -r .node_user <<<"$st"); pass=$(jq -r .node_password <<<"$st")
  [ -S "$S/b/ln/$(cat "$S/chain")/lightning-rpc" ] && ln="
[assets.lightning]
rpc = \"$S/b/ln/$(cat "$S/chain")/lightning-rpc\""
  cat > "$S/b/arcad.toml" <<EOF
listen = "127.0.0.1:$B_PORT"
database = "postgres://postgres@127.0.0.1:$PGB_PORT/postgres"
signer_socket = "$S/b/signer.sock"
wallet_mnemonic_file = "$S/b/wallet.mnemonic"
fee_multiple = 2
round_interval_seconds = ${B_ROUND_SECONDS:-10}
exit_delay_units = [1, 338]
metrics_listen = "127.0.0.1:$((P + 105))"

[node]
rpc_url = "$url"
rpc_user = "$user"
rpc_password = "$pass"

[finality]
poll_interval_ms = 500

[watcher]
enabled = true
recovery_interval_seconds = 5

[limits]
issue_per_second = ${B_LIMIT:-250}
issue_burst = 10000
source_per_second = ${B_SOURCE_LIMIT:-1}
source_burst = ${B_SOURCE_BURST:-10}
witness_per_second = ${B_LIMIT:-250}
witness_burst = 1000
witness_source_per_second = ${B_SOURCE_LIMIT:-5}
witness_source_burst = ${B_SOURCE_BURST:-60}
read_per_second = ${B_READ_LIMIT:-500}
read_burst = 2000
read_source_per_second = ${B_SOURCE_LIMIT:-10}
read_source_burst = ${B_SOURCE_BURST:-200}

[fees]
lightning_ppm = 1000

[[assets]]
asset = "$x"
min_leaf = "1000"
$ln

[[assets]]
asset = "$y"
min_leaf = "1000"

[lightning]
poll_seconds = 1
operator_delay_units = 1
owner_delay_units = 2
send_timeout_seconds = 345600
send_stall_margin_seconds = 3600
retry_seconds = 10
receive_window_seconds = 600
EOF
}

# Whether the process whose id FILE holds runs.
alive() { local p; p=$(cat "$1" 2>/dev/null || true); [[ "$p" =~ ^[0-9]+$ ]] && kill -0 "$p" 2>/dev/null; }

start_b() {   # what is not running, as `systemctl start` does
  local g
  g=$(jq -r .genesis_hash <<<"$(state)")
  if ! alive "$S/b/signer.pid"; then
    rm -f "$S/b/signer.sock"
    "$B_BIN/arca-signer" --key-file "$S/b/operator.key" --genesis "$g" --socket "$S/b/signer.sock" \
      --record "$S/b/signer.record" >> "$S/b/signer.log" 2>&1 &
    echo $! > "$S/b/signer.pid"
    wait_for 30 test -S "$S/b/signer.sock"
  fi
  alive "$S/b/arcad.pid" && return 0
  # Each line of arcad's log stamped with the wall time it came, to the
  # millisecond: the load test reads round build times from it.
  RUST_LOG=${B_LOG:-info} "$B_BIN/arcad" "$S/b/arcad.toml" > /dev/null 2> >(python3 -u -c '
import sys, time
for l in sys.stdin:
    sys.stdout.write("%.3f %s" % (time.time(), l)); sys.stdout.flush()' >> "$S/b/arcad.log") &
  echo $! > "$S/b/arcad.pid"
  echo "$(date +%s.%N) start" >> "$S/b/starts"
  wait_for 120 curl -fsS -m 5 "http://127.0.0.1:$B_PORT/v1/info"
}

# Stops B as its service manager does: arcad on SIGINT, then the signer on
# SIGTERM, each waited for.
stop_b() {
  local f pid sig
  for f in arcad:INT signer:TERM; do
    pid=$(cat "$S/b/${f%%:*}.pid" 2>/dev/null || true); sig=${f##*:}
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || continue
    kill -s "$sig" "$pid"
    for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$pid" 2>/dev/null && { echo "${f%%:*} ($pid) did not stop on SIG$sig" >&2; return 1; }
  done
  echo "B stopped"
}

# The failure no service manager gives notice of: both processes killed.
kill_b() {
  local f pid
  for f in arcad signer; do
    pid=$(cat "$S/b/$f.pid" 2>/dev/null || true)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
  done
  sleep 1
  echo "B killed"
}

b_lightning() {
  echo "=== operator B's SeqLN node in X, a channel to A's ==="
  local st x node_dir node_port pass addr script
  st=$(state); x=$(jq -r .x <<<"$st")
  node_dir=$(jq -r .node_datadir <<<"$st"); node_port=$(jq -r .node_url <<<"$st" | sed -E 's#.*:([0-9]+)/?#\1#')
  pass=$(jq -r .node_password <<<"$st")
  mkdir -p "$S/b/ln"
  "$LIGHTNINGD_EXEC" --developer --network="$(cat "$S/chain")" --lightning-dir="$S/b/ln" \
    --bitcoin-cli="$(dirname "$SEQUENTIAD_EXEC")/sequentia-cli" --bitcoin-datadir="$node_dir" \
    --bitcoin-rpcuser=arca --bitcoin-rpcpassword="$pass" --bitcoin-rpcconnect=127.0.0.1 --bitcoin-rpcport="$node_port" \
    --addr=127.0.0.1:$BLN_PORT --log-file="$S/b/ln/log" --log-level=info --dev-bitcoind-poll=1 --dev-fast-gossip --disable-dns \
    --plugin="$(dirname "$(dirname "$LIGHTNINGD_EXEC")")/contrib/holdinvoice-seq/holdinvoice.py" > /dev/null 2>&1 &
  rec b-seqln $!
  wait_for 60 bln getinfo
  addr=$(bln newaddr bech32 | jq -r .bech32)
  script=$(ctl /rpc "{\"method\":\"validateaddress\",\"params\":[\"$addr\"]}" | jq -r .scriptPubKey)
  ctl /fund "{\"script\":\"$script\",\"asset\":\"$x\",\"amount\":2000000000}" > /dev/null
  ctl /produce > /dev/null
  wait_for 60 sh -c "[ \"\$('$LCLI' --lightning-dir='$S/b/ln' --network='$(cat "$S/chain")' listfunds | jq '.outputs|length')\" -gt 0 ]"
  bln connect "$(jq -r .x_lightning.operator.id <<<"$st")@$(jq -r .x_lightning.operator.addr <<<"$st")" > /dev/null
  bln -k fundchannel id="$(jq -r .x_lightning.operator.id <<<"$st")" amount=1000000000 asset="$x" push_msat=500000000000 > "$S/b/fundchannel.json"
  for _ in $(seq 60); do
    ctl /produce > /dev/null
    [ "$(bln listpeerchannels | jq -r '[.channels[]|select(.state=="CHANNELD_NORMAL")]|length')" -gt 0 ] && break
    sleep 1
  done
}

up() {
  mkdir -p "$S/b"
  : > "$S/pids"
  echo "=== PostgreSQL for A and for B ==="
  start_pg pga "$PGA_PORT"
  start_pg pgb "$PGB_PORT"
  echo "=== operator A and the chain ==="
  local lnflag=""
  [ -n "${LIGHTNINGD_EXEC:-}" ] && lnflag=1
  env ARCA_OPERATOR_CONTROL=$CTL ${lnflag:+ARCA_OPERATOR_LIGHTNING=1} ARCA_TEST_POSTGRES="postgres://postgres@127.0.0.1:$PGA_PORT/postgres" \
    "$HARNESS" --ignored --nocapture --exact operator_for_browsers > "$S/a.log" 2>&1 &
  rec harness $!
  wait_for 600 ctl /state
  jq -r .chain <<<"$(state)" > "$S/chain"
  ( umask 077; jq -r .node_password <<<"$(state)" > "$S/node.password" )
  if [ -n "${CAPTAIND:-}" ]; then
    echo "=== the Bitcoin ark ==="
    ark up > "$S/ark-up.log" 2>&1
  fi
  echo "=== operator B: key, record, wallet ==="
  ( umask 077; openssl rand -hex 32 > "$S/b/operator.key" )
  # A regtest wallet only: the BIP39 test vector, never another operator's.
  ( umask 077; echo "legal winner thank year wave sausage worth useful legal winner thank yellow" > "$S/b/wallet.mnemonic" )
  "$B_BIN/arca-signer" --key-file "$S/b/operator.key" --pubkey > "$S/b/operator.pub"
  "$B_BIN/arca-signer" --key-file "$S/b/operator.key" --genesis "$(jq -r .genesis_hash <<<"$(state)")" \
    --record "$S/b/signer.record" --create-record --no-keepers > "$S/b/record.log" 2>&1
  local st x node_dir node_port pass addr script
  st=$(state); x=$(jq -r .x <<<"$st")
  [ -n "${LIGHTNINGD_EXEC:-}" ] && b_lightning
  echo "=== operator B: arcad and arca-signer ==="
  b_config
  start_b
  echo "=== operator B's pools, funded and final ==="
  local y baddr bscript
  y=$(jq -r .y <<<"$st")
  for a in "$x" "$x" "$y"; do
    baddr=$("$B_BIN/arcad" "$S/b/arcad.toml" address)
    bscript=$(jq -r .script_pubkey <<<"$baddr")
    ctl /fund "{\"script\":\"$bscript\",\"asset\":\"$a\",\"amount\":500000000}" > /dev/null
  done
  ctl /produce > /dev/null
  ctl /bury > /dev/null
  echo "B: http://127.0.0.1:$B_PORT  key $(cat "$S/b/operator.pub")"
  echo UP
}

down() {
  stop_b || kill_b || true
  ark down || true
  [ -f "$S/pids" ] || { echo "nothing recorded"; return 0; }
  # The harness stops the chain, its nodes and A's signer itself on /quit.
  ctl /quit > /dev/null 2>&1 || true
  tac "$S/pids" | while read -r name pid; do
    [ "$name" = harness ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      echo "stopping $name ($pid)"
      if [ "$name" = b-seqln ]; then bln stop > /dev/null 2>&1 || kill "$pid"; else kill -INT "$pid"; fi
    fi
  done
  for _ in $(seq 60); do
    alive=0; while read -r _n pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < "$S/pids"
    [ $alive = 0 ] && break; sleep 1
  done
  while read -r name pid; do kill -0 "$pid" 2>/dev/null && echo "STILL RUNNING $name $pid"; done < "$S/pids"
  echo DOWN
}

env_out() {
  local st ai
  st=$(state); ai=$(ark info 2>/dev/null || echo "{}")
  cat <<EOF
export ARCA=$ARCA_BIN/arca
export ARCA_BARK_EXEC=${ARCA_BARK_EXEC:-} ARCA_BARKD_EXEC=${ARCA_BARKD_EXEC:-}
export OPERATOR_URL=http://127.0.0.1:$B_PORT
export OPERATOR_KEY=$(cat "$S/b/operator.pub")
export PEER_OPERATOR_URL=$(jq -r .server <<<"$st")
export NODE_URL=$(jq -r .node_url <<<"$st") NODE_USER=$(jq -r .node_user <<<"$st")
export NODE_PASSWORD_FILE=$S/node.password
export ASSET=$(jq -r .x <<<"$st") ASSET_B=$(jq -r .y <<<"$st")
export STOP_OPERATOR="$HERE/regtest-standin.sh stop-b" START_OPERATOR="$HERE/regtest-standin.sh start-b"
export KILL_OPERATOR="$HERE/regtest-standin.sh kill-b" KILL_SIGNER="$HERE/regtest-standin.sh kill-signer"
export FUND="$HERE/regtest-standin.sh fund"
export CHAIN_PRODUCE="$HERE/regtest-standin.sh ctl /produce" CHAIN_BURY="$HERE/regtest-standin.sh ctl /bury"
export CHAIN_ADVANCE="$HERE/regtest-standin.sh advance"
export PEER_ROUND="$HERE/regtest-standin.sh ctl /round"
export BITCOIN_ARK_URL=$(jq -r .ark <<<"$ai") BITCOIND_URL=$(jq -r .bitcoind <<<"$ai") BITCOIND_COOKIE=$(jq -r .cookie <<<"$ai")
export BTC_FUND="$HERE/regtest-standin.sh btc-fund" BTC_MINE="$HERE/regtest-standin.sh btc-mine"
export STOP_ARK="$HERE/regtest-standin.sh stop-ark" START_ARK="$HERE/regtest-standin.sh start-ark"
export OPERATOR_PIDS_CMD="$HERE/regtest-standin.sh pids"
export OPERATOR_DATA="$S/pgb/data $S/b/signer.record"
export OPERATOR_LOG_CMD="cat $S/b/arcad.log"
export S=$S PORT_BASE=$P
EOF
}

pg_pid() { head -1 "$S/pgb/data/postmaster.pid" 2>/dev/null || true; }

# captaind alone stops and starts: the ark's server down, its chain and its
# Lightning gateway up, as when the process dies.
stop_ark() {
  local pid
  pid=$(awk '$1=="captaind"{print $2}' "$S/ark/pids" | tail -1)
  kill -0 "$pid" 2>/dev/null && kill "$pid"
  for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  echo "captaind stopped"
}
start_ark() {
  CAPTAIND_LOG=info "$CAPTAIND" --config "$S/ark/captaind.toml" start >> "$S/ark/log/captaind.log" 2>&1 &
  echo "captaind $!" >> "$S/ark/pids"
  wait_for 120 ark admin wallet
  echo "captaind started"
}

cmd=${1:-}; shift || true
case "$cmd" in
  up) up ;;
  down) down ;;
  env) env_out ;;
  ctl) ctl "$@"; echo ;;
  advance) ctl /advance "{\"seconds\":$1}"; echo ;;
  fund)   # ADDRESS ASSET ATOMS: from the test's coins, then a block
    script=$(ctl /rpc "{\"method\":\"validateaddress\",\"params\":[\"$1\"]}" | jq -r .scriptPubKey)
    ctl /fund "{\"script\":\"$script\",\"asset\":\"$2\",\"amount\":$3}"; echo ;;
  btc-fund) ark btc -rpcwallet=miner sendtoaddress "$1" "$2" ;;
  btc-mine) ark mine "${1:-1}" ;;
  stop-b) stop_b ;;
  kill-b) kill_b ;;
  kill-signer) pid=$(cat "$S/b/signer.pid"); kill -0 "$pid" 2>/dev/null && kill -9 "$pid"; echo "B's signer killed" ;;
  start-b) start_b; echo "B started" ;;
  stop-ark) stop_ark ;;
  start-ark) start_ark ;;
  b-config) b_config ;;
  pids) echo "$(cat "$S/b/arcad.pid" 2>/dev/null) $(cat "$S/b/signer.pid" 2>/dev/null) $(pg_pid)" ;;
  bln) bln "$@" ;;
  *) echo "usage: regtest-standin.sh up|down|env|ctl|advance|fund|btc-fund|btc-mine|stop-b|kill-b|start-b|stop-ark|start-ark|bln" >&2; exit 1 ;;
esac
