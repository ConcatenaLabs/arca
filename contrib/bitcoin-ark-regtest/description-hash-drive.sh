#!/usr/bin/env bash
# A payment name's invoice on the Bitcoin ark: the wallet's library (bark-wasm's
# command set, run natively by its `regtest_drive` example) asks the server for
# an invoice that commits to the SHA-256 of a payment name's LNURL-pay metadata
# (BOLT11 `h`, which payers that check the description hash compare with the
# metadata), and an outside payer pays it.
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
#   - With OLD_CAPTAIND (captaind built without the patch) the server is swapped
#     for it: the wallet refuses the plain invoice it gets back, says the server
#     keeps that invoice (0.7.1 refuses every cancel), and one request leaves
#     exactly one invoice on the gateway; a memo request is served as before.
#
#   H=… REGTEST=…/regtest.sh DRIVE=…/regtest_drive [OLD_CAPTAIND=…] description-hash-drive.sh
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
# Both Lightning nodes at the tip first: a payer still behind offers an HTLC that expires a
# block too early for captaind, which then drops the receive and leaves the HTLC held.
tip=$(R btc getblockcount)
for _ in $(seq 60); do
  ph=$(R peer getinfo | json | jq .blockheight); gh=$(R gw getinfo | json | jq .blockheight)
  [ "$ph" = "$tip" ] && [ "$gh" = "$tip" ] && break
  sleep 1
done
[ "$ph" = "$tip" ] && [ "$gh" = "$tip" ] || fail "the Lightning nodes are not at the tip $tip (peer $ph, gateway $gh)"
# The payer is bounded and stopped with the script, so a payment that hangs fails the drive
# instead of holding it open.
( timeout 120 "$REGTEST" peer pay "$inv" > "$H/description-hash-pay.out" 2>&1 ) &
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

# With OLD_CAPTAIND (a captaind built without the patch), the ark's server is swapped for it:
# the wallet refuses the plain invoice it gets back, says the server keeps it, and leaves exactly
# one invoice behind for one request (it does not try again); a memo request is served as ever.
# The patched server ($CAPTAIND, as the harness was started) is put back after.
if [ -n "${OLD_CAPTAIND:-}" ]; then
  echo "=== a server without the patch ==="
  lim() { sed -n "s/^$1 = \"\([0-9]*\) sat\"/\1/p" "$H/captaind.toml"; }
  max=$(lim max_vtxo_amount) min=$(lim min_board_amount) off=$(lim max_offboard_amount)
  CAPTAIND=$OLD_CAPTAIND R limits "$max" "$min" "$off" >/dev/null
  held() { R gw listholdinvoices | json | jq '.holdinvoices | length'; }
  h0=$(held)
  if out=$(d invoice "{\"sats\":\"21000\",\"description_hash\":\"$HASH\"}" 2>&1); then fail "a plain invoice was taken for a committed one: $out"; fi
  echo "$out" | grep -q "does not support committing an invoice to a description hash" || fail "refused for another reason: $out"
  echo "$out" | grep -q "keeps that one invoice unpaid until it expires" || fail "the error does not say what the server kept: $out"
  echo "refused: $(echo "$out" | grep -o 'Ark server returned.*' | head -1)"
  sleep 5
  h1=$(held)
  echo "hold invoices on the gateway: $h0 -> $h1"
  [ "$h1" = $((h0 + 1)) ] || fail "one refused request left $((h1 - h0)) invoices, not one"
  pd=$(R peer decode "$(d invoice '{"sats":"21000","description":"Receive BTC"}' | jq -r .invoice)" | json)
  [ "$(jq -r '.description // empty' <<< "$pd")" = "Receive BTC" ] || fail "a memo request is not served as before"
  echo "a memo request: $(jq -c '{description, description_hash}' <<< "$pd")"
  R limits "$max" "$min" "$off" >/dev/null
fi
echo "=== done ==="
