#!/usr/bin/env bash
# What an Arca operator's holders go through under load and when the
# operator stops: run against an operator you run yourself, on its own
# machine, never against anyone else's. README.md says what each scenario
# shows and how to read its results.
#
#   operator-tests.sh SCENARIO…    (or `all`: every scenario but load)
#
# Scenarios: load, down-idle, down-transfer, down-round, down-swap,
# down-btc-swap, down-lightning, down-desk, ark-down.
#
# Everything is read from the environment; no secret is ever an argument.
# See README.md for the full list. The essentials:
#   ARCA              the arca command-line wallet
#   OPERATOR_URL      the operator under test (on this machine)
#   OPERATOR_KEY      its operator key, as its signer prints it
#   NODE_URL, and NODE_COOKIE or NODE_USER with NODE_PASSWORD_FILE: the
#                     Sequentia node's RPC
#   ASSET             the asset the wallets hold
#   FUND              a command run as `$FUND ADDRESS ASSET ATOMS` that pays
#                     test coins on the chain (it names its own source wallet)
#   STOP_OPERATOR, START_OPERATOR, KILL_OPERATOR, KILL_SIGNER
#                     the operator's own service commands
#   CHAIN_PRODUCE, CHAIN_BURY, CHAIN_ADVANCE   regtest hooks (optional)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${ARCA:?}" "${OPERATOR_URL:?}" "${OPERATOR_KEY:?}" "${NODE_URL:?}" "${ASSET:?}" "${FUND:?}"
[ -n "${NODE_COOKIE:-}" ] || : "${NODE_USER:?name the node RPC login: NODE_COOKIE, or NODE_USER and NODE_PASSWORD_FILE}" "${NODE_PASSWORD_FILE:?}"
NAME=${NAME:-arca-bundle}
STOP_OPERATOR=${STOP_OPERATOR:-systemctl stop $NAME-arcad.service $NAME-arca-signer.service}
START_OPERATOR=${START_OPERATOR:-systemctl start $NAME-arca-signer.service $NAME-arcad.service}
KILL_OPERATOR=${KILL_OPERATOR:-systemctl kill -s KILL $NAME-arcad.service $NAME-arca-signer.service}
KILL_SIGNER=${KILL_SIGNER:-systemctl kill -s KILL $NAME-arca-signer.service}
OPERATOR_PIDS_CMD=${OPERATOR_PIDS_CMD:-}
RUN=${RUN:-$PWD/operator-tests.$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$RUN/w"
SCENARIO=setup
source "$HERE/lib.sh"
source "$HERE/load.sh"
source "$HERE/scenarios.sh"

# Stopping an operator other people use is never this script's to do: it
# stops only an operator on this machine, one that answers with the key
# named, and it checks the other operator still answers around every stop.
host=$(sed -E 's#^[a-z]+://(\[[^]]+\]|[^/:]+).*#\1#' <<<"$OPERATOR_URL" | tr -d '[]')
case "$host" in
  127.*|localhost|::1) ;;
  *) ip -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$host" || \
       die "$OPERATOR_URL is not on this machine: this script stops only an operator it runs beside" ;;
esac
op_up || die "the operator at $OPERATOR_URL does not answer"
[ "$(op_key)" = "$OPERATOR_KEY" ] || die "the operator at $OPERATOR_URL shows key $(op_key), not OPERATOR_KEY"
if [ -n "${PEER_OPERATOR_URL:-}" ]; then
  [ "$PEER_OPERATOR_URL" != "$OPERATOR_URL" ] || die "PEER_OPERATOR_URL is the operator under test"
  peer_up || die "the other operator at $PEER_OPERATOR_URL does not answer"
fi
# Exit delays: the operator's least, so a holder's exit is as short as the
# operator allows (on a regtest stand-in, a few minutes).
EXIT_UNITS=${EXIT_UNITS:-$(curl -fsS "$OPERATOR_URL/v1/info" | jq -r '.exit_delay_units.min // .exit_delay_units[0] // 254')}
[ "$EXIT_UNITS" -lt 4 ] && EXIT_UNITS=4
say "run $RUN: operator $OPERATOR_KEY at $OPERATOR_URL, asset $ASSET, exit delay $EXIT_UNITS units"

[ $# -gt 0 ] || { sed -n '2,12p' "$0"; exit 2; }
for s in "$@"; do
  case "$s" in
    all) for t in down-idle down-transfer down-round down-swap down-btc-swap down-lightning down-desk ark-down; do "scenario_${t//-/_}"; done ;;
    load|down-idle|down-transfer|down-round|down-swap|down-btc-swap|down-lightning|down-desk|ark-down) "scenario_${s//-/_}" ;;
    *) die "no scenario $s" ;;
  esac
done
op_up || { say "the operator was left stopped: starting it"; start_op; }
say "done: $RUN/results"
column -t -s $'\t' "$RUN/results" 2>/dev/null || cat "$RUN/results"
