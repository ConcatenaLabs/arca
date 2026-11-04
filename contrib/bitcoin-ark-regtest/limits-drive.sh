#!/usr/bin/env bash
# The wallet against an ark whose operator lowers its limits while coins made
# under the old ones are still out: the Bitcoin ark wallet's own library
# (bark-wasm's command set, run natively by its `regtest_drive` example), on the
# ark `regtest.sh up` started.
#
# The ark takes coins of up to 1 BTC; the wallet boards 0.3 BTC and twice
# 0.06 BTC. The ark then takes Second's mainnet figures: its largest coin and
# board 10,000,000 sat, its least board 50,000 sat, offboards of up to 1 BTC
# still. The wallet must
#   - read the new figures from the server (`info`);
#   - be refused a board below the least and above the largest;
#   - once its coins are due, take the 0.3 BTC coin, which the server can no
#     longer refresh, out of the ark to its own first Bitcoin address
#     (`offboarded`), and refresh the two 0.06 BTC coins, 0.12 BTC in all, in two
#     refreshes that each fit under the largest coin.
#
#   H=… REGTEST=…/regtest.sh DRIVE=…/regtest_drive limits-drive.sh
set -euo pipefail
: "${H:?}" "${REGTEST:?the harness, regtest.sh}" "${DRIVE:?the regtest_drive example binary}"
R() { "$REGTEST" "$@"; }
info=$(R info)
export ARK=$(jq -r .ark <<< "$info") BITCOIND=$(jq -r .bitcoind <<< "$info") COOKIE=$(jq -r .cookie <<< "$info")
# BIP39's test phrase: a regtest wallet's, holding nothing anywhere else.
export MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
W=$H/limits-wallet
d() { "$DRIVE" "$W" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
spendable() { d sync >/dev/null; d coins | jq -c '[.coins[] | select(.state == "Spendable") | .amount | tonumber] | sort'; }

echo "=== the ark takes coins of up to 1 BTC ==="
R limits 100000000 10000 100000000
fa=$(d funding_address | jq -r .address)
R btc -rpcwallet=miner sendtoaddress "$fa" 1 >/dev/null
R mine 1
for s in 30000000 6000000 6000000; do
  d board_funding "{\"sats\":\"$s\"}"
  R mine 1
done
R mine 3
for _ in $(seq 60); do
  c=$(spendable)
  [ "$(jq length <<< "$c")" = 3 ] && break
  sleep 2
done
echo "spendable coins: $c"
[ "$(jq length <<< "$c")" = 3 ] || fail "the three boards are not spendable"

echo "=== the ark takes Second's mainnet figures ==="
R limits 10000000 50000
i=$(d info)
echo "$i"
[ "$(jq -r .max_vtxo_sat <<< "$i")" = 10000000 ] || fail "info's max_vtxo_sat"
[ "$(jq -r .min_board_sat <<< "$i")" = 50000 ] || fail "info's min_board_sat"

echo "=== boards outside them are refused ==="
if out=$(d board_funding '{"sats":"40000"}' 2>&1); then fail "a board of 40,000 sat was taken: $out"; fi
echo "$out" | grep -qE "less than minimum board amount|does not meet minimum" || fail "a board below the least, refused for another reason: $out"
echo "below the least: $(echo "$out" | grep -o 'board amount.*' | head -1)"
if out=$(d board_funding '{"sats":"20000000"}' 2>&1); then fail "a board of 20,000,000 sat was taken: $out"; fi
echo "$out" | grep -qE "(exceeds|more than|greater than) (the )?maximum" || fail "a board above the largest, refused for another reason: $out"
echo "above the largest: $(echo "$out" | grep -o 'board amount.*' | head -1)"

echo "=== the coins come due ==="
exp=$(d coins | jq '[.coins[] | select(.state == "Spendable") | .expiry_height] | min')
tip=$(R btc getblockcount)
R mine $((exp - tip - 10))
d coins | jq -c '{tip, coins: [.coins[] | {amount, expiry_height, state}]}'

echo "=== a refresh: the coin above the largest leaves, one refresh that fits ==="
r1=$(d refresh)
echo "$r1"
[ "$(jq '.offboarded | length' <<< "$r1")" = 1 ] || fail "the oversized coin did not leave"
txid=$(jq -r '.offboarded[0].txid // empty' <<< "$r1")
[ -n "$txid" ] || fail "the offboard was refused: $(jq -c .offboarded <<< "$r1")"
paid=$(R btc getrawtransaction "$txid" true | jq --arg a "$fa" '[.vout[] | select(.scriptPubKey.address == $a) | .value] | add')
echo "offboard $txid pays $paid BTC to the wallet's own address $fa"
awk -v p="$paid" 'BEGIN { exit !(p > 0.29 && p < 0.3) }' || fail "the offboard paid $paid BTC to the wallet's address"
[ "$(jq .refreshed <<< "$r1")" = 1 ] || fail "the first refresh took $(jq .refreshed <<< "$r1") coins, not one"
R mine 1

echo "=== the next refresh takes the other ==="
r2=$(d refresh)
echo "$r2"
[ "$(jq .refreshed <<< "$r2")" = 1 ] || fail "the second refresh took $(jq .refreshed <<< "$r2") coins, not one"
R mine 1
r3=$(d refresh)
echo "$r3"
[ "$(jq .refreshed <<< "$r3")" = 0 ] || fail "a third refresh found more"
c=$(spendable)
echo "spendable coins: $c"
[ "$(jq length <<< "$c")" = 2 ] || fail "two refreshed coins are not spendable"
jq -e 'all(. <= 10000000)' <<< "$c" >/dev/null || fail "a coin above the largest"
echo "LIMITS DRIVE PASSED"
