# operator-tests.sh's scenarios of the operator going down. Sourced.
# Each scenario makes wallets of its own (named after it), brings them to
# the moment, stops the operator, records what each wallet says and holds,
# takes one holder home on the chain while the operator is down, starts the
# operator again and checks every other holder comes through.

# Moves NAME's participations on until each is released.
released() {
  local name=$1 i
  for i in $(seq "${ROUND_TRIES:-40}"); do
    arca "$name" sync > /dev/null 2>&1 || true
    [ "$(arca "$name" participations | jq '[.[]|select(.state!="released" and .state!="void" and .state!="expired")]|length')" = 0 ] && return 0
    sleep "${ROUND_WAIT:-3}"; produce; bury
  done
  return 1
}
# NAME's live coin of ASSET out of a round (a refreshed one), NAME boarded
# with ATOMS and refreshed.
round_holder() { board "$1" "$2"; must "$1" participate > /dev/null; released "$1" || die "$1's refresh was never released"; }
first_live() { arca "$1" coins | jq -r --arg a "$ASSET" '[.[]|select(.asset==$a and .state=="live")][0].leaf_id // empty'; }
# NAME's first coin of ASSET still off the chain, in whatever state.
first_held() { arca "$1" coins | jq -r --arg a "$ASSET" '[.[]|select(.asset==$a and (.state|IN("spent","exited","lost")|not))][0].leaf_id // empty'; }
# A receive request of NAME, or nothing when it cannot make one.
request() { arca "$1" receive --asset "$ASSET" 2>/dev/null | jq -r '.request // empty' 2>/dev/null || true; }
# What NAME holds of ASSET in every form, coins and on the chain: the total
# of its row (an exit's claim lands on the chain and counts there).
total() { held "$1"; }

# Takes NAME's coin LEAF home on the chain with the operator down, from its
# record alone, through to the claim final; records the outcome.
exit_home() {
  local name=$1 leaf=$2 i st before after delay
  before=$(total "$name")
  delay=$((EXIT_UNITS * 512 + 120))
  for i in $(seq "${EXIT_TRIES:-14}"); do
    try "$name" exit "$leaf"
    st=$(jq -r '.state // .error.message // "?"' <<<"$OUT")
    [ $i = 1 ] && verbatim "$name exit" "$(jq -c '{state, next, broadcast: [.broadcast[]?.txid]}' <<<"$OUT" 2>/dev/null || msg)"
    case "$st" in
      exited) break ;;
      waiting)
        # A refund waits for its leaf's timeout: the median time its note
        # names, when that is ahead.
        local until now; until=$(jq -r '.next // ""' <<<"$OUT" | grep -oE '\b1[0-9]{9}\b' | sort -n | tail -1 || true)
        now=$(mtp)
        if [ -n "$until" ] && [ "$until" -gt "$now" ]; then advance $((until - now + 600)) || break
        else advance "$delay" || break; fi ;;
    esac
    produce; bury
  done
  after=$(total "$name")
  if [ "$st" = exited ]; then
    result "$name exits alone" "exited with the operator down: $before -> $after atoms held (on the chain now), fees $((before - after))"
  else
    result "$name exits alone" "not finished: last state $st ($(msg | head -c 200))"
  fi
}

# What a wallet says, in its own words, while the operator is down.
down_words() {
  local name=$1
  try "$name" sync
  verbatim "$name sync" "$(jq -r '.unreachable.note // empty' <<<"$OUT") | $(jq -r '.unreachable.why // empty' <<<"$OUT")"
  try "$name" receive --asset "$ASSET"
  verbatim "$name receive" "$(msg)"
}

scenario_down_idle() {
  SCENARIO=down-idle
  say "== $SCENARIO: the operator stops while its holders do nothing"
  mkwallet di1; mkwallet di2; mkwallet di3
  round_holder di1 "$(atoms 3000000 3)"
  local req; req=$(must di2 receive --asset "$ASSET" | jq -r .request)
  must di1 send "$req" --amount "$(atoms 500000)" > /dev/null
  must di2 sync > /dev/null
  board di3 "$(atoms 1000000 2)"
  local req3; req3=$(request di3)
  local h1 h2 h3; h1=$(total di1); h2=$(total di2); h3=$(total di3)
  stop_op stop
  down_words di1
  # A request di3 made before the stop, paid while the operator is down.
  try di2 send "$req3" --amount "$(atoms 1000)"
  verbatim "di2 send" "$(msg)"
  [ "$(total di1)" = "$h1" ] && [ "$(total di2)" = "$h2" ] && [ "$(total di3)" = "$h3" ] && \
    result "loss" "none: every holder's total unchanged with the operator down ($h1, $h2, $h3)" || \
    result "loss" "TOTALS MOVED: $h1->$(total di1) $h2->$(total di2) $h3->$(total di3)"
  # One holder of each kind goes home alone: a round leaf, an out-of-round
  # coin. The board's holder waits.
  exit_home di1 "$(first_live di1)"
  # di2's coin rests on di1's: di1's exit put its lineage on the chain, and
  # di2's wallet took it home by itself (`exiting`). It is finished here.
  verbatim "di2 coins after di1's exit" "$(arca di2 coins | jq -c '[.[]|{state,note}]')"
  exit_home di2 "$(first_held di2)"
  start_op
  try di3 sync
  req=$(request di1)
  try di3 send "$req" --amount "$(atoms 1000)"
  [ "$OK" = 0 ] && result "recovery" "di3 (waited) paid di1 at once after the restart; nothing done by hand" || \
    result "recovery" "di3 could not pay di1 after the restart: $(msg)"
}

scenario_down_transfer() {
  SCENARIO=down-transfer
  say "== $SCENARIO: the operator stops in the middle of an out-of-round transfer"
  local n; for n in dt1 dt2 dt3 dt5 dt6; do mkwallet $n; done
  board dt1 "$(atoms 3000000 4)"; board dt5 "$(atoms 3000000 4)"
  local req req3 req6 h5 pid a2 a6
  a2=$(atoms 400000); a6=$(atoms 250000)
  req=$(request dt2); req3=$(request dt3); req6=$(request dt6)
  # (a) Paid and co-signed, not yet read by its receiver: the coin's record
  # is in dt2's mailbox at the operator, and nowhere else.
  must dt1 send "$req" --amount "$a2" > /dev/null
  # (b) The signer gone: the wallet asks for its witness first, so nothing
  # is sent or recorded.
  $KILL_SIGNER > /dev/null 2>&1 || true
  sleep 1
  try dt1 send "$req3" --amount "$(atoms 300000)"
  verbatim "dt1 send, the signer gone" "$(msg)"
  result "signer gone" "send exit $OK; dt1's coins $(coins dt1)"
  $START_OPERATOR > /dev/null 2>&1 || true
  for _ in $(seq 30); do op_up && break; sleep 1; done
  # (c) The operator killed while a transfer is in flight.
  h5=$(total dt5)
  ( arca dt5 send "$req6" --amount "$a6" > "$RUN/dt5.send.json" 2>&1; echo "exit $?" >> "$RUN/dt5.send.json" ) &
  pid=$!
  sleep "${KILL_AFTER:-0.05}"
  stop_op kill
  wait "$pid" || true
  verbatim "dt5 send, operator killed in flight" "$(jq -r '.error.message // ("sent: " + (.sent|tostring))' "$RUN/dt5.send.json" 2>/dev/null | head -1)"
  down_words dt6
  result "loss while down" "dt2 holds $(total dt2) of $a2 sent (unread at the stop); dt6 $(total dt6) of $a6; dt5 $h5 -> $(total dt5), coins $(coins dt5)"
  # dt1 goes home alone with its change: the reassignment that made it also
  # made dt2's coin, which reaches the chain with it.
  exit_home dt1 "$(first_held dt1)"
  start_op
  local i
  for i in 1 2 3; do arca dt5 sync > /dev/null 2>&1 || true; arca dt6 sync > /dev/null 2>&1 || true; arca dt2 sync > /dev/null 2>&1 || true; done
  result "recovery" "after the restart: dt6 holds $(total dt6) (paid in flight), dt5 $(total dt5); dt2 $(total dt2) (its sender went home first)"
  verbatim "dt2 refusals" "$(arca dt2 refusals | jq -c '[.[]|.reason]')"
  [ "$(total dt2)" = 0 ] && result "FINDING" "dt2's $a2 is on the chain under dt2's key (the reassignment dt1's exit broadcast), and dt2's wallet refuses it: $(arca dt2 refusals | jq -r '.[-1].reason')"
}

scenario_down_round() {
  SCENARIO=down-round
  say "== $SCENARIO: the operator stops in the middle of a round"
  mkwallet dr1; mkwallet dr2
  board dr1 2000000; board dr2 2000000
  local h1 h2; h1=$(total dr1); h2=$(total dr2)
  local before i round=""
  before=$(node_rpc getrawmempool)
  must dr1 participate > /dev/null; must dr2 participate > /dev/null
  # The round built and broadcast, not yet in a block: a new transaction in
  # the node's mempool.
  for i in $(seq 120); do
    round=$(jq -r --argjson b "$before" '[.[]|select(. as $t|$b|index($t)|not)][0] // empty' <<<"$(node_rpc getrawmempool)")
    [ -n "$round" ] && break
    sleep 1
  done
  result "moment" "round ${round:-none} built and in the mempool, not in a block; participations $(arca dr1 participations | jq -c '[.[]|.state]')"
  stop_op kill
  produce; bury   # the round confirms and is final with the operator down
  down_words dr1
  try dr1 participations; verbatim "dr1 participations" "$(jq -c '[.[]|{state,round,released}]' <<<"$OUT")"
  try dr1 coins; verbatim "dr1 coins" "$(jq -c '[.[]|{state,value,kind}]' <<<"$OUT")"
  result "loss while down" "dr1 $h1 -> $(total dr1), dr2 $h2 -> $(total dr2)"
  # dr1 goes home alone with the coin it gave up: its forfeit was never
  # handed over, so the coin is still its own.
  exit_home dr1 "$(arca dr1 coins | jq -r --arg a "$ASSET" '[.[]|select(.asset==$a and (.state=="given" or .state=="live"))][0].leaf_id')"
  start_op
  released dr2 && result "recovery" "dr2's participation released after the restart: $(total dr2) held; $(coins dr2)" || \
    result "recovery" "dr2's participation not released: $(arca dr2 participations | jq -c '[.[]|.state]')"
  # The operator's watcher on dr1's exit: the forfeit it does not hold.
  try dr1 sync; result "dr1 after the restart" "$(arca dr1 participations | jq -c '[.[]|.state]'); holds $(total dr1)"
}

scenario_down_swap() {
  SCENARIO=down-swap
  say "== $SCENARIO: the operator stops in the middle of a swap of two assets in the tree"
  local x=$ASSET y=${ASSET_B:?ASSET_B names the second asset of the swap}
  local n; for n in ds1 ds2 ds3 ds4; do mkwallet $n; done
  board ds1 2000000; board ds3 2000000
  ASSET=$y FEE_ASSET=$x board ds2 2000000
  ASSET=$y FEE_ASSET=$x board ds4 2000000
  local offer acc1 acc2 id2
  # Two swaps, each offered and accepted, waiting for the maker's completion.
  offer=$(must ds1 swap offer --give-asset "$x" --give 100000 --want-asset "$y" --want 90000 | jq -r .offer)
  acc1=$(must ds2 swap accept "$offer" | jq -r .accept)
  offer=$(must ds3 swap offer --give-asset "$x" --give 100000 --want-asset "$y" --want 90000)
  id2=$(jq -r '.swap // .id // empty' <<<"$offer"); offer=$(jq -r .offer <<<"$offer")
  acc2=$(must ds4 swap accept "$offer" | jq -r .accept)
  stop_op stop
  try ds1 swap complete "$acc1"
  verbatim "ds1 swap complete, operator down" "$(msg)"
  down_words ds2
  verbatim "ds4 coins" "$(arca ds4 coins | jq -c '[.[]|{state,value,asset: .asset[0:8]}]')"
  result "loss while down" "ds1 $(total ds1) X, ds2 $(ASSET=$y total ds2) Y, ds3 $(total ds3) X, ds4 $(ASSET=$y total ds4) Y: nothing moved"
  # ds4 takes the coin it offered home alone.
  ASSET=$y exit_home ds4 "$(ASSET=$y first_held ds4)"
  start_op
  try ds1 swap complete "$acc1"
  [ "$OK" = 0 ] && result "recovery" "ds1 completed the swap after the restart: ds1 holds $(ASSET=$y total ds1) Y, ds2 $(total ds2) X" || \
    result "recovery" "ds1 could not complete after the restart: $(msg)"
  try ds3 swap complete "$acc2"
  verbatim "ds3 swap complete, the taker's coin gone home" "$(msg)"
  try ds3 swap cancel "${id2:-none}"
  result "the swap whose taker went home" "ds3's completion: $(msg | head -c 200); after cancel ds3 holds live $(arca ds3 coins | jq -c --arg a "$x" '[.[]|select(.asset==$a and .state=="live")|.value]')"
}

scenario_down_lightning() {
  SCENARIO=down-lightning
  say "== $SCENARIO: a payment over Lightning from this operator's wallet to the other operator's, the operator down mid-way"
  : "${PEER_OPERATOR_URL:?}" "${PEER_ROUND:-}"
  mkwallet dl1
  PEER=1 mkwallet dl2
  board dl1 "$(atoms 3000000 3)"
  local inv hash
  inv=$(must dl2 lightning receive "$ASSET" "$(atoms 200000)")
  hash=$(jq -r .payment_hash <<<"$inv"); inv=$(jq -r .invoice <<<"$inv")
  try dl1 lightning pay "$inv" --wait 2
  verbatim "dl1 lightning pay" "$(jq -c '{payment, error}' <<<"$OUT" | head -c 600)"
  stop_op stop
  # The other operator makes dl2's leaf and dl2 claims it: the preimage
  # goes back along the channels to this operator's node.
  local i
  for i in $(seq 20); do
    [ -n "${PEER_ROUND:-}" ] && $PEER_ROUND > /dev/null 2>&1 || true
    arca dl2 sync > /dev/null 2>&1 || true
    [ "$(arca dl2 lightning receives | jq -r --arg h "$hash" '.[$h].state')" = received ] && break
    sleep 2
  done
  result "while down" "dl2's receive at the other operator: $(arca dl2 lightning receives | jq -r --arg h "$hash" '.[$h].state'); dl2 holds $(total dl2)"
  down_words dl1
  try dl1 lightning payments; verbatim "dl1 payments" "$(jq -c --arg h "$hash" '.[$h]|{state,reason}' <<<"$OUT")"
  start_op
  for i in $(seq 20); do
    arca dl1 sync > /dev/null 2>&1 || true
    [ "$(arca dl1 lightning payments | jq -r --arg h "$hash" '.[$h].state')" = paid ] && break
    sleep 2
  done
  result "recovery" "dl1's payment after the restart: $(arca dl1 lightning payments | jq -c --arg h "$hash" '.[$h]|{state,preimage}')"
}

# ---------------------------------------------------------------------------
# The Bitcoin side: Bark wallets in a Bitcoin ark beside each Arca wallet.
# ---------------------------------------------------------------------------

bark() { local n=$1; shift; "$ARCA" --datadir "$RUN/w/$n" bitcoin --quiet "$@" 2>> "$RUN/w/$n.stderr"; }
btc_mine() { if [ -n "${BTC_MINE:-}" ]; then $BTC_MINE "${1:-1}" > /dev/null; else sleep 600; fi; }
spendable_sat() { bark "$1" balance | jq -r '.spendable_sat // 0'; }
spendable_ok() { bark "$1" maintain > /dev/null 2>&1 || true; [ "$(spendable_sat "$1")" -gt 0 ]; }
onchain_ok() { [ "$(bark "$1" onchain balance | jq -r '.confirmed_sat // 0')" -ge 2000000 ]; }
until_btc() {   # SECONDS WHAT TEST…: a Bitcoin block and each wallet's Bark caught up, until TEST holds
  local secs=$1 what=$2; shift 2; local t0; t0=$(date +%s)
  until "$@"; do
    [ $(( $(date +%s) - t0 )) -lt "$secs" ] || { say "  not within $secs s: $what"; return 1; }
    btc_mine 1; sleep 1
  done
}
# NAME SATS: the wallet's Bitcoin ark wallet, from its own mnemonic, with
# SATS boarded into the ark.
btcwallet() {
  local n=$1 sats=$2 addr
  local src=(--bitcoind "$BITCOIND_URL" --bitcoind-cookie "$BITCOIND_COOKIE")
  [ -n "${ESPLORA_URL:-}" ] && src=(--esplora "$ESPLORA_URL")
  must "$n" bitcoin create "--${BITCOIN_NETWORK:-regtest}" --ark "$BITCOIN_ARK_URL" "${src[@]}" > /dev/null
  [ "$sats" -gt 0 ] || return 0
  addr=$(bark "$n" onchain address | jq -r .address)
  $BTC_FUND "$addr" 0.02 > /dev/null
  btc_mine 1
  until_btc 120 "$n's on-chain funding" onchain_ok "$n"
  must "$n" bitcoin board "$sats sat" > /dev/null
  until_btc 180 "$n's board" spendable_ok "$n"
}
swap_state() { arca "$1" btc-swap list | jq -r --arg i "$2" '.swaps[$i].state'; }
swap_note() { arca "$1" btc-swap list | jq -r --arg i "$2" '.swaps[$i].note // ""'; }
# NAME ID STATE SECS: follows NAME's swaps until swap ID is in STATE, the
# operator's rounds made final and Bitcoin blocks mined meanwhile.
follow_until() {
  local n=$1 id=$2 want=$3 secs=$4 t0 st; t0=$(date +%s)
  while :; do
    arca "$n" btc-swap follow --claim-slice 5 > /dev/null 2>&1 || true
    st=$(swap_state "$n" "$id")
    [ "$st" = "$want" ] && return 0
    [ $(( $(date +%s) - t0 )) -lt "$secs" ] || { say "  $n's swap is $st, not $want, after $secs s: $(swap_note "$n" "$id")"; return 1; }
    produce; bury; btc_mine 1; sleep 2
  done
}
follow_bg() { ( "$ARCA" --datadir "$RUN/w/$1" btc-swap follow --wait "$2" --claim-slice 15 > "$RUN/w/$1.follow.json" 2>> "$RUN/w/$1.stderr" ) & echo $!; }
# P gives ATOMS of ASSET for SATS of Q's BTC: the offer, the take, the
# completion; prints the swap's id.
swap_open() {
  local p=$1 q=$2 atoms=$3 sats=$4 offer id take
  refill_pool > /dev/null
  offer=$(must "$p" btc-swap offer --give asset --asset "$ASSET" --atoms "$atoms" --sats "$sats")
  id=$(jq -r .swap <<<"$offer")
  take=$(must "$q" btc-swap take "$(jq -r .offer <<<"$offer")" | jq -r .take)
  must "$p" btc-swap complete "$take" > /dev/null
  echo "$id"
}
# The Bitcoin ark's server grants a Lightning receive's HTLCs from a pool of
# VTXOs it refills on the chain as blocks come; empty, it grants none and the
# payer's payment fails back. Blocks with pauses refill it before a swap.
refill_pool() { local i; for i in 1 2 3 4; do btc_mine 1; sleep 3; done; }
receive_state() { arca "$1" lightning lookup "$2" | jq -r '.state // .status // .error.message'; }

scenario_down_btc_swap() {
  SCENARIO=down-btc-swap
  say "== $SCENARIO: BTC in the Bitcoin ark for this operator's asset, the operator down mid-swap"
  local n; for n in bs1 bs2 bs3 bs4; do mkwallet $n; done
  board bs1 3000000; board bs3 3000000
  btcwallet bs1 0; btcwallet bs2 300000; btcwallet bs3 0; btcwallet bs4 300000
  local id hash
  if [[ " ${BTC_SWAP_CASES:-a b} " == *" a "* ]]; then
  # (a) P has locked its asset; Q's leaf is not made yet. The operator
  # stops, comes back, and the swap goes on to the end.
  id=$(swap_open bs1 bs2 100000 30000)
  hash=$(arca bs1 btc-swap list | jq -r --arg i "$id" '.swaps[$i].hash')
  follow_until bs1 "$id" locked 120 || true
  result "(a) moment" "P locked; the operator's receive under the hash: $(receive_state bs2 "$hash")"
  stop_op stop
  try bs2 btc-swap follow; verbatim "Q follow, operator down" "$(swap_note bs2 "$id")"
  try bs1 btc-swap follow; verbatim "P follow, operator down" "$(swap_note bs1 "$id")"
  result "(a) while down" "P's swap $(swap_state bs1 "$id"), Q's $(swap_state bs2 "$id"); Q paid no BTC: $(spendable_sat bs2) sat spendable"
  start_op
  local pf; pf=$(follow_bg bs1 300)
  follow_until bs2 "$id" done 300 || true
  wait "$pf" 2>/dev/null || true
  follow_until bs1 "$id" done 120 || true
  result "(a) recovery" "after the restart: P $(swap_state bs1 "$id"), Q $(swap_state bs2 "$id"); P holds $(spendable_sat bs1) sat, Q $(total bs2) of the asset"
  fi
  [[ " ${BTC_SWAP_CASES:-a b} " == *" b "* ]] || return 0
  # (b) The operator is killed the moment Q starts paying the BTC: Q's
  # payment goes through, P claims the BTC (revealing the preimage), and Q
  # cannot claim its leaf through the operator. Q takes the preimage from
  # its own payment and its leaf home alone, by its claim.
  # (Killed before Q pays instead, Q never pays: "not paying, ever", and
  # P's lock comes back once the operator fails Q's receive back.)
  id=$(swap_open bs3 bs4 100000 30000)
  hash=$(arca bs3 btc-swap list | jq -r --arg i "$id" '.swaps[$i].hash')
  follow_until bs3 "$id" locked 120 || true
  for _ in $(seq 40); do
    produce; bury; arca bs4 sync > /dev/null 2>&1 || true
    [ "$(arca bs4 coins | jq --arg a "$ASSET" '[.[]|select(.asset==$a and .template=="htlc-1")]|length')" -gt 0 ] && break
    sleep 2
  done
  refill_pool > /dev/null
  local pf qf; pf=$(follow_bg bs3 240); qf=$(follow_bg bs4 240)
  for _ in $(seq 600); do [ "$(swap_state bs4 "$id")" = paying ] && break; sleep 0.2; done
  stop_op kill
  result "(b) moment" "the operator killed as Q started paying: Q $(swap_state bs4 "$id"), P $(swap_state bs3 "$id")"
  wait "$pf" "$qf" 2>/dev/null || true
  arca bs4 btc-swap follow > /dev/null 2>&1 || true
  verbatim "Q follow, operator down, after paying" "$(swap_note bs4 "$id")"
  verbatim "P follow, operator down, after claiming" "$(swap_note bs3 "$id")"
  result "(b) while down" "P $(swap_state bs3 "$id") with $(spendable_sat bs3) sat; Q $(swap_state bs4 "$id") with $(spendable_sat bs4) sat; Q's leaf $(arca bs4 coins | jq -c --arg a "$ASSET" '[.[]|select(.asset==$a and .template=="htlc-1")|.state]')"
  exit_home bs4 "$(arca bs4 coins | jq -r --arg a "$ASSET" '[.[]|select(.asset==$a and .template=="htlc-1" and (.state|IN("spent","exited")|not))][0].leaf_id // empty')"
  start_op
  for _ in 1 2 3; do arca bs3 btc-swap follow > /dev/null 2>&1 || true; arca bs3 sync > /dev/null 2>&1 || true; produce; bury; done
  result "(b) recovery" "after the restart: P's asset leg $(arca bs3 lightning payments | jq -c '[.[]|.state]'), P $(swap_state bs3 "$id"); the operator's receive $(receive_state bs4 "$hash")"
  # A wallet of the other operator cannot take this operator's offer.
  if [ -n "${PEER_OPERATOR_URL:-}" ]; then
    PEER=1 mkwallet bs5; btcwallet bs5 0
    local offer; offer=$(must bs1 btc-swap offer --give asset --asset "$ASSET" --atoms 10000 --sats 3000 | jq -r .offer)
    try bs5 btc-swap take "$offer"; verbatim "a wallet of the other operator takes the offer" "$(msg)"
  fi
}

scenario_ark_down() {
  SCENARIO=ark-down
  say "== $SCENARIO: the Bitcoin ark's server (captaind) down while a swap with this operator is in flight"
  : "${STOP_ARK:?STOP_ARK names the command that stops the Bitcoin ark server}" "${START_ARK:?}"
  local n; for n in ad1 ad2; do mkwallet $n; done
  board ad1 3000000; btcwallet ad1 0; btcwallet ad2 300000
  local id hash pf
  id=$(swap_open ad1 ad2 100000 30000)
  hash=$(arca ad1 btc-swap list | jq -r --arg i "$id" '.swaps[$i].hash')
  follow_until ad1 "$id" locked 120 || true
  for _ in $(seq 30); do produce; bury; [ "$(receive_state ad2 "$hash")" != open ] && break; sleep 2; done
  # Q's leaf is made and final; the ark's server stops before Q pays.
  for _ in $(seq 20); do produce; bury; arca ad2 btc-swap follow > /dev/null 2>&1 || true; [ "$(swap_state ad2 "$id")" = taken ] || break; done
  $STOP_ARK > /dev/null
  try ad2 btc-swap follow; verbatim "Q follow, ark down" "$(swap_note ad2 "$id")"
  result "before Q pays" "Q $(swap_state ad2 "$id"), P $(swap_state ad1 "$id"); Q's BTC unmoved"
  $START_ARK > /dev/null
  pf=$(follow_bg ad1 300)
  follow_until ad2 "$id" done 300 || true
  wait "$pf" 2>/dev/null || true
  follow_until ad1 "$id" done 120 || true
  result "recovery" "the ark back: P $(swap_state ad1 "$id"), Q $(swap_state ad2 "$id"); P $(spendable_sat ad1) sat, Q $(total ad2) of the asset"
  # A swap the ark's outage ended: P's lock comes back once the operator
  # fails Q's receive back, after the time to claim Q's leaf is over.
  if [ "$(swap_state ad2 "$id")" != done ]; then
    local before; before=$(total ad1)
    local t; t=$(arca ad1 btc-swap list | jq -r --arg i "$id" '.swaps[$i].log[]?.what' | grep -o 'median time [0-9]*' | head -1 | awk '{print $3}' || true)
    [ -n "$t" ] && advance $(( t - $(mtp) + 7200 )) || true
    for _ in $(seq 20); do
      produce; bury; arca ad1 btc-swap follow > /dev/null 2>&1 || true; arca ad1 sync > /dev/null 2>&1 || true
      [ "$(swap_state ad1 "$id")" = refunded ] && break; sleep 2
    done
    result "refund" "P's swap $(swap_state ad1 "$id") once its lock's time passed (lock until median time ${t:-?}): P holds $before -> $(total ad1) of the asset; Q's receive $(receive_state ad2 "$hash")"
  fi
}

scenario_down_desk() {
  SCENARIO=down-desk
  say "== $SCENARIO: a BTC desk pays early on the operator's acceptance, then the operator stops"
  # The desk D sells BTC for the asset; the buyer W pays the asset into
  # D's receive under the hash of W's Bitcoin invoice. D pays the BTC as
  # soon as the operator holds W's payment (its receive accepted), within
  # its caps, before its leaf is made: the BTC desk's early pay.
  local n; for n in dd1 dw1 dd2 dw2; do mkwallet $n; done
  board dw1 3000000; board dw2 3000000
  btcwallet dd1 300000; btcwallet dw1 0; btcwallet dd2 300000; btcwallet dw2 0
  desk_pay() {   # DESK BUYER: the trade up to the BTC paid; prints the hash
    local d=$1 w=$2 binv hash xinv t
    binv=$(must "$w" lightning receive btc 30000)
    binv=$(jq -r .invoice <<<"$binv"); hash=$(python3 "$HERE/bolt11_hash.py" "$binv")
    xinv=$(must "$d" lightning receive "$ASSET" 100000 --hash "$hash" | jq -r .invoice)
    t=$(( $(mtp) + 6 * 86400 ))
    must "$w" lightning pay "$xinv" --timeout "$t" --wait 5 > /dev/null
    echo "$t" > "$RUN/$w.timeout"
    # The desk's rule: pay once the operator holds the payment for it, its
    # receive accepted (the desk's library calls it issuing).
    for _ in $(seq 30); do [ "$(receive_state "$d" "$hash")" = accepted ] && break; sleep 1; done
    [ "$(receive_state "$d" "$hash")" = accepted ] || { result "$d" "the operator never accepted the payment: $(receive_state "$d" "$hash"); the desk pays nothing"; return 1; }
    result "$d accepted" "the operator holds W's payment for the desk ($(arca "$d" lightning lookup "$hash" | jq -c '{state, held_by}')): the desk pays the BTC now, before its leaf is made"
    refill_pool > /dev/null
    ( arca "$w" lightning claim "$binv" --wait 120 > "$RUN/$w.claim.json" ) &
    local c=$!
    try "$d" lightning pay "$binv"
    wait $c || true
    verbatim "$d pays the BTC" "$(jq -c . <<<"$OUT" 2>/dev/null | head -c 400 || msg)"
    echo "$hash $(jq -r '[.. | .preimage? // empty | strings][0] // empty' <<<"$OUT" 2>/dev/null)" > "$RUN/$d.hash"
  }
  local h pre
  if [[ " ${DESK_CASES:-a b} " == *" a "* ]]; then
  # (a) The operator stops and comes back: the desk's leaf is made, and the
  # desk claims it with the preimage its BTC payment bought.
  desk_pay dd1 dw1
  stop_op kill
  verbatim "dd1 receives, operator down" "$(arca dd1 lightning receives | jq -c '[.[]|{state,reason}]')"
  start_op
  read -r h pre < "$RUN/dd1.hash"
  [ -n "$pre" ] && arca dd1 lightning preimage "$h" "$pre" > /dev/null 2>&1 || true
  for _ in $(seq 30); do produce; bury; arca dd1 sync > /dev/null 2>&1 || true; [ "$(arca dd1 lightning receives | jq -r --arg h "$h" '.[$h].state')" = received ] && break; sleep 2; done
  result "(a) recovery" "the desk's receive after the restart: $(arca dd1 lightning receives | jq -r --arg h "$h" '.[$h].state'); desk holds $(total dd1) of the asset, buyer $(spendable_sat dw1) sat"
  fi
  [[ " ${DESK_CASES:-a b} " == *" b "* ]] || return 0
  # (b) The operator stays down past the buyer's lock: the buyer takes its
  # asset home by its refund, and keeps the BTC. The desk bears the loss,
  # up to its caps.
  desk_pay dd2 dw2
  local before; before=$(total dw2)
  stop_op kill
  # The buyer's refund opens once its lock's timeout has passed, then its
  # exit delay: the chain's clock moved there.
  local tw; tw=$(cat "$RUN/dw2.timeout")
  result "(b) the buyer's lock" "times out at median time $tw, $(( tw - $(mtp) )) s from now; the desk's receive at the operator: $(receive_state dd2 "$(cut -d' ' -f1 "$RUN/dd2.hash")")"
  advance $(( tw - $(mtp) + 600 )) || true
  exit_home dw2 "$(arca dw2 coins | jq -r --arg a "$ASSET" '[.[]|select(.asset==$a and .state=="paying")][0].leaf_id // empty')"
  result "(b) loss" "the buyer took its asset home ($before -> $(total dw2)) and holds $(spendable_sat dw2) sat; the desk paid 30000 sat and holds $(total dd2) of the asset: the desk's loss, within its caps"
  start_op
  for _ in 1 2 3; do produce; bury; arca dd2 sync > /dev/null 2>&1 || true; done
  result "(b) after the restart" "the desk's receive: $(arca dd2 lightning receives | jq -c '[.[]|{state,reason}]')"
}
