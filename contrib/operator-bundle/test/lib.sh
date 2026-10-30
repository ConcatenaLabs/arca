# Shared by operator-tests.sh's scenarios: wallets, the chain, the operator.
# Sourced, never run.

say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUN/log"; }
die() { say "STOP: $*"; exit 1; }
# One line of the scenario's result table, kept in $RUN/results.
result() { printf '%s\t%s\t%s\n' "$SCENARIO" "$1" "$2" | tee -a "$RUN/results"; }
# A wallet's own words, verbatim, for the record.
verbatim() { printf '%s\t%s\t%s\n' "$SCENARIO" "$1" "$2" >> "$RUN/verbatim"; say "  [$1] $2"; }

# arca NAME ARGS…: the wallet NAME's command, its JSON on standard output;
# its exit status is arca's.
arca() {
  local name=$1; shift
  "$ARCA" --datadir "$RUN/w/$name" --witness-patience "${PATIENCE:-3}" "$@" 2>> "$RUN/w/$name.stderr"
}
# Like arca, but the answer is kept in $OUT and the status in $OK, and the
# script goes on whatever it was.
try() { set +e; OUT=$(arca "$@"); OK=$?; set -e; }
# The message of a refusal in $OUT, or the whole answer.
msg() { jq -r '.error.message // .' <<<"$OUT" 2>/dev/null || echo "$OUT"; }
must() { try "$@"; [ "$OK" = 0 ] || die "arca $1 ${2:-}: $(msg)"; echo "$OUT"; }

# The chain: hooks on regtest, waiting on a live chain.
produce() { if [ -n "${CHAIN_PRODUCE:-}" ]; then $CHAIN_PRODUCE > /dev/null; else sleep "${BLOCK_SECONDS:-60}"; fi; }
bury() { if [ -n "${CHAIN_BURY:-}" ]; then $CHAIN_BURY > /dev/null; else sleep $((3 * ${BLOCK_SECONDS:-60})); fi; }
# Moves the median time on: on a live chain it cannot, and says so.
advance() {
  if [ -n "${CHAIN_ADVANCE:-}" ]; then $CHAIN_ADVANCE "$1" > /dev/null; return 0; fi
  say "  (the chain's clock moves on by itself here: $1 s to wait, not waited)"; return 1
}
mtp() { node_rpc getblockchaininfo | jq -r .mediantime; }
node_rpc() {
  local m=$1; shift; local p; p=$(printf '%s' "$*")
  local auth; if [ -n "${NODE_COOKIE:-}" ]; then auth=$(cat "$NODE_COOKIE"); else auth="$NODE_USER:$(cat "$NODE_PASSWORD_FILE")"; fi
  curl -fsS -m 30 --user "$auth" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"1.0\",\"id\":0,\"method\":\"$m\",\"params\":[${p}]}" "$NODE_URL" | jq -c .result
}

# The operator under test.
op_up() { curl -fsS -m 5 "$OPERATOR_URL/v1/info" > /dev/null 2>&1; }
peer_up() { [ -z "${PEER_OPERATOR_URL:-}" ] || curl -fsS -m 5 "$PEER_OPERATOR_URL/v1/info" > /dev/null 2>&1; }
op_key() { curl -fsS -m 5 "$OPERATOR_URL/v1/info" | jq -r .operator; }
stop_op() {   # [kill]: SIGKILL in place of the service manager's stop
  local how=${1:-stop} t0
  peer_up || die "the other operator does not answer before the stop: nothing is stopped"
  t0=$(date +%s.%N)
  if [ "$how" = kill ]; then $KILL_OPERATOR > /dev/null; else $STOP_OPERATOR > /dev/null; fi
  for _ in $(seq 60); do op_up || break; sleep 1; done
  op_up && die "the operator at $OPERATOR_URL still answers after its stop command: it is not the operator this command stops"
  peer_up || { $START_OPERATOR > /dev/null || true; die "the other operator stopped answering with this one: started this one again, and stopped"; }
  say "operator stopped ($how) in $(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - $t0}") s"
}
start_op() {
  local t0; t0=$(date +%s.%N)
  $START_OPERATOR > /dev/null
  for _ in $(seq 300); do op_up && break; sleep 1; done
  op_up || die "the operator did not answer within 300 s of its start"
  [ "$(op_key)" = "$OPERATOR_KEY" ] || die "the operator came back under another key"
  say "operator back in $(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - $t0}") s, same key"
}

# A wallet of the operator under test (or, with PEER=1, of the other one).
mkwallet() {
  local name=$1 url=$OPERATOR_URL key=$OPERATOR_KEY
  if [ "${PEER:-0}" = 1 ]; then url=$PEER_OPERATOR_URL; key=${PEER_OPERATOR_KEY:-}; fi
  mkdir -p "$RUN/w"
  local node=(--node-user "${NODE_USER:-}" --node-password-file "${NODE_PASSWORD_FILE:-}")
  [ -n "${NODE_COOKIE:-}" ] && node=(--node-cookie "$NODE_COOKIE")
  must "$name" create --server "$url" --node-url "$NODE_URL" "${node[@]}" \
    --exit-delay-units "$EXIT_UNITS" --min-exit-delay-units 1 > /dev/null
  if [ -n "$key" ] && [ "$(arca "$name" info | jq -r .operator)" != "$key" ]; then die "wallet $name pinned another operator key"; fi
}
# NAME ATOMS: on-chain coins paid by FUND, boarded, credited.
# With FEE_ASSET, the board's fee is paid in that asset (for an asset the
# node does not accept for fees), from coins of it paid beside.
board() {
  local name=$1 atoms=$2 addr fee=()
  addr=$(must "$name" address | jq -r .address)
  if [ -n "${FEE_ASSET:-}" ] && [ "$FEE_ASSET" != "$ASSET" ]; then
    $FUND "$addr" "$ASSET" "$atoms" > /dev/null
    $FUND "$(must "$name" address | jq -r .address)" "$FEE_ASSET" 1000000 > /dev/null
    fee=(--fee-asset "$FEE_ASSET")
  else
    $FUND "$addr" "$ASSET" $((atoms + 1000000)) > /dev/null
  fi
  produce
  must "$name" board "$ASSET" "$atoms" "${fee[@]}" > /dev/null
  produce; bury
  for _ in $(seq 120); do
    [ "$(arca "$name" boards | jq '[.[]|select(.server.state!="credited")]|length')" = 0 ] && break
    sleep 1
  done
  must "$name" sync > /dev/null
}
# What NAME holds of ASSET: its row's total, and its live coins.
held() { arca "$1" balance --without-bitcoin | jq -r --arg a "$ASSET" '[.rows[]|select(.asset==$a)|.total][0] // "0"'; }
coins() { arca "$1" coins | jq -c --arg a "$ASSET" '[.[]|select(.asset==$a)|{leaf_id,state,value}]'; }
