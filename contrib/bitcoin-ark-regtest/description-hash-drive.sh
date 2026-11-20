#!/usr/bin/env bash
# A payment name's invoice on the Bitcoin ark: the wallet's library (bark-wasm's
# command set, run natively by its `regtest_drive` example) asks the server for
# an invoice that commits to the SHA-256 of a payment name's LNURL-pay metadata
# (BOLT11 `h`, as LUD-06 asks), and an outside payer pays it.
# It needs a captaind built with
# contrib/operator-bundle/patches/captaind-description-hash.patch.
#
#   - The invoice carries `h` = sha256 of exactly the metadata string, and no memo.
#   - An invoice asked with a memo and no hash is made as it always was: the memo,
#     no `h` (the field left out changes nothing).
#   - A hash that is not 64 hex characters, or a hash beside a memo, is refused.
#   - The peer, a Core Lightning node, reads the hash from the invoice
#     (`decode`) and pays it, and the wallet claims the payment.
# Core Lightning 26's `pay` no longer checks a description against the hash
# (xpay, which serves it, ignores one; the old `pay` that did is deprecated), so
# the hash is checked here against sha256 of the metadata's bytes.
#
#   H=… REGTEST=…/regtest.sh DRIVE=…/regtest_drive description-hash-drive.sh
set -euo pipefail
: "${H:?}" "${REGTEST:?the harness, regtest.sh}" "${DRIVE:?the regtest_drive example binary}"
R() { "$REGTEST" "$@"; }
info=$(R info)
export ARK=$(jq -r .ark <<< "$info") BITCOIND=$(jq -r .bitcoind <<< "$info") COOKIE=$(jq -r .cookie <<< "$info")
# A regtest wallet's own phrase, holding nothing anywhere else.
export MNEMONIC="legal winner thank year wave sausage worth useful legal winner thank yellow"
W=$H/description-hash-wallet
d() { "$DRIVE" "$W" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# lightning-cli prints a progress line before some answers.
json() { sed -n '/^{/,$p'; }

# The metadata a payment name serves (the web wallet's lnaddr.js `lnurlMetadata`).
META='[["text/plain","Payment to alice@sequentiatestnet.com"],["text/identifier","alice@sequentiatestnet.com"]]'
HASH=$(printf '%s' "$META" | sha256sum | cut -d' ' -f1)
echo "metadata: $META"
echo "sha256:   $HASH"

echo "=== a coin in the ark, so the wallet can claim what it receives ==="
fa=$(d funding_address | jq -r .address)
R btc -rpcwallet=miner sendtoaddress "$fa" 0.01 >/dev/null
R mine 1
d board_funding '{"sats":"300000"}' >/dev/null
R mine 3
for _ in $(seq 60); do
  n=$(d sync >/dev/null; d coins | jq '[.coins[] | select(.state == "Spendable")] | length')
  [ "$n" -ge 1 ] && break
  sleep 2
done
[ "$n" -ge 1 ] || fail "the board is not spendable"

echo "=== an invoice that commits to the metadata ==="
inv=$(d invoice "{\"sats\":\"21000\",\"description_hash\":\"$HASH\"}" | jq -r .invoice)
echo "$inv"
dec=$(R peer decode "$inv" | json)
jq -c '{description_hash, description, amount_msat}' <<< "$dec"
[ "$(jq -r '.description_hash // empty' <<< "$dec")" = "$HASH" ] || fail "the invoice's h is not sha256 of the metadata"
[ -z "$(jq -r '.description // empty' <<< "$dec")" ] || fail "the invoice carries a memo beside the hash"

echo "=== an invoice asked with a memo and no hash: as before ==="
plain=$(d invoice '{"sats":"21000","description":"Receive BTC"}' | jq -r .invoice)
pd=$(R peer decode "$plain" | json)
jq -c '{description_hash, description, amount_msat}' <<< "$pd"
[ "$(jq -r '.description // empty' <<< "$pd")" = "Receive BTC" ] || fail "the memo is not the one asked"
[ -z "$(jq -r '.description_hash // empty' <<< "$pd")" ] || fail "an invoice with no hash asked carries one"

echo "=== a malformed hash, and a hash beside a memo: refused ==="
if out=$(d invoice '{"sats":"21000","description_hash":"abcd"}' 2>&1); then fail "a 2-byte hash was taken: $out"; fi
echo "$out" | grep -q "not 64 hex characters" || fail "a short hash, refused for another reason: $out"
echo "short hash: $(echo "$out" | grep -o "'description_hash'.*" | head -1)"
if out=$(d invoice "{\"sats\":\"21000\",\"description\":\"x\",\"description_hash\":\"$HASH\"}" 2>&1); then fail "a hash beside a memo was taken: $out"; fi
echo "$out" | grep -q "not both" || fail "a hash beside a memo, refused for another reason: $out"
echo "hash and memo: $(echo "$out" | grep -o "give a description.*" | head -1)"

echo "=== the peer pays it, the wallet claims ==="
before=$(d balance | jq -r .spendable)
# The payer is bounded and stopped with the script, so a payment that hangs fails the drive
# instead of holding it open.
( timeout 150 "$REGTEST" peer pay "$inv" > "$H/description-hash-pay.out" 2>&1 ) &
payer=$!
trap 'kill "$payer" 2>/dev/null || true' EXIT
got=$(timeout 120 "$DRIVE" "$W" receive_status "{\"hash\":\"$(jq -r .payment_hash <<< "$dec")\",\"claim\":true,\"wait\":true}") || fail "the claim did not finish: $got"
echo "$got" | jq -c .
[ "$(jq -r .state <<< "$got")" = paid ] || fail "the wallet did not claim the payment: $got"
wait "$payer" || fail "the peer's payment failed: $(cat "$H/description-hash-pay.out")"
jq -c '{status, amount_msat}' < <(json < "$H/description-hash-pay.out")
[ "$(json < "$H/description-hash-pay.out" | jq -r .status)" = complete ] || fail "the peer's payment is not complete"
after=$(d balance | jq -r .spendable)
echo "spendable: $before -> $after"
[ "$after" -gt "$before" ] || fail "the payment did not reach the wallet"
echo "=== done ==="
