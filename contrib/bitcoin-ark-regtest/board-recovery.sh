#!/usr/bin/env bash
# A board whose wallet is lost before the board is registered, found again
# from the phrase alone (`catch_up`), against the Bitcoin ark `regtest.sh`
# runs. Each step opens the wallet, runs one command and closes it, as a
# browser's page does (`bark-wasm/examples/regtest_drive.rs`).
#
#   ARK_SH=…/ark.sh DRIVE=…/regtest_drive board-recovery.sh
#
# ARK_SH runs regtest.sh with its environment set (as the bitcoin-ark
# workflow writes it); DRIVE is the built `regtest_drive` example.
set -euo pipefail
: "${ARK_SH:?name the script that runs regtest.sh, ARK_SH}" "${DRIVE:?name the built regtest_drive, DRIVE}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

info=$("$ARK_SH" info)
export ARK=$(jq -r .ark <<<"$info") BITCOIND=$(jq -r .bitcoind <<<"$info") COOKIE=$(jq -r .cookie <<<"$info")
# A fresh phrase of the BIP39 English list's first words and a random last
# word that checks: the wallet's coins are this run's alone.
export MNEMONIC=$("$DRIVE" "$W/gen" new_mnemonic 2>/dev/null | jq -r .mnemonic)
drive() { "$DRIVE" "$W/$1" "${@:2}"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

echo "=== the phrase's Bitcoin coins ==="
addr=$(drive A funding_address | jq -r .address)
"$ARK_SH" btc -rpcwallet=miner sendtoaddress "$addr" 0.005 >/dev/null
"$ARK_SH" mine 1

echo "=== store A boards 300000 sat, and is lost before it registers the board ==="
board=$(drive A board_funding '{"sats":"300000"}')
echo "$board"
txid=$(jq -r .funding_txid <<<"$board")
# The funding confirms past the server's two confirmations while no store of
# the phrase is open, so nothing registers it.
"$ARK_SH" mine 3
rm -rf "$W/A"

echo "=== store B, from the phrase alone ==="
b1=$(drive B catch_up)
echo "$b1"
[ "$(jq '.boards | length' <<<"$b1")" = 1 ] || fail "catch_up found $(jq -c .boards <<<"$b1") boards, not the one board"
[ "$(jq -r '.boards[0].outcome' <<<"$b1")" = adopted ] || fail "the board was not adopted: $(jq -c '.boards[0]' <<<"$b1")"
[ "$(jq -r '.boards[0].funding' <<<"$b1")" = "$txid:0" ] || fail "catch_up found $(jq -r '.boards[0].funding' <<<"$b1"), not $txid:0"
bal=$(drive B balance)
echo "$bal"
spendable=$(jq -r .spendable <<<"$bal")
[ "$spendable" -gt 0 ] || fail "store B holds no spendable coin after the board was adopted: $bal"

echo "=== catch_up again: nothing new ==="
b2=$(drive B catch_up)
[ "$(jq '.boards | length' <<<"$b2")" = 0 ] || fail "a second catch_up found boards again: $(jq -c .boards <<<"$b2")"
[ "$(jq -r .spendable <<<"$(drive B balance)")" = "$spendable" ] || fail "a second catch_up changed the balance"

echo "=== store C, from the phrase alone, after B registered the board ==="
c1=$(drive C catch_up)
[ "$(jq '.boards | length' <<<"$c1")" = 0 ] || fail "store C found the registered board on the chain again: $(jq -c .boards <<<"$c1")"
[ "$(jq -r .spendable <<<"$(drive C balance)")" = "$spendable" ] || fail "store C does not hold what store B holds"

echo "=== done: the board of a lost store is held by every store of its phrase, once ($spendable sat) ==="
