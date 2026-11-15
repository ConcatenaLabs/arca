#!/usr/bin/env bash
# price-server.sh: the bundle's price server and node, configured by install.sh's
# own functions, on a regtest chain in a throwaway Ubuntu 24.04 container, as
# root and as the bundle's user, the way the units run them.
#
#   SEQUENTIA=<dir> contrib/operator-bundle/test/price-server.sh
#
# SEQUENTIA is a Sequentia Core build laid out as a release: bin/sequentiad,
# bin/sequentia-cli and price-server/ (a source checkout's src/ and
# contrib/price-server/ are linked into that shape). A stand-in serves the price
# feed and the asset registry. It checks:
#
#   * a release whose node reads a price server (-feepriceserver): the price
#     server's configuration holds no login to the node, it publishes on
#     loopback at PRICE_SERVER_PORT, the node's configuration connects it there,
#     and the node's whitelist is dynamic with the feed's assets; the node keeps
#     that list while the price server is down and across its own restart;
#   * an older release: the price server writes the list with the node's cookie
#     and the node's configuration names no price server;
#   * configuring twice changes nothing.
set -euo pipefail
: "${SEQUENTIA:?name a Sequentia Core build, SEQUENTIA}"
HERE=$(cd "$(dirname "$0")" && pwd)
ARCA=$(cd "$HERE/../../.." && pwd)
SEQ=$(cd "$SEQUENTIA" && pwd)
IMAGE=arca-bundle-price-server-test
printf '%s\n' 'FROM ubuntu:24.04' \
  'RUN apt-get update && apt-get install -y --no-install-recommends python3 jq openssl && apt-get clean' \
  | docker build -q -t "$IMAGE" - >/dev/null
exec docker run --rm -i --network none \
  -v "$ARCA:/opt/arca-src:ro" -v "$SEQ:/opt/sequentia-release:ro" \
  "$IMAGE" bash -s < <(cat <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
command -v python3 >/dev/null && command -v jq >/dev/null && command -v openssl >/dev/null \
  || fail "the container needs python3, jq and openssl (the image built for this test has them)"
NAME=arca-bundle; OPT=/opt/$NAME; ETC=/etc/$NAME; LIB=/var/lib/$NAME; LOG=/var/log/$NAME
useradd --system --home-dir "$LIB" --shell /usr/sbin/nologin "$NAME"
install -d "$OPT/sequentia/bin" "$OPT/sequentia/price-server"
src=/opt/sequentia-release
for b in sequentiad sequentia-cli; do
  f=$src/bin/$b; [ -x "$f" ] || f=$src/src/$b; cp "$f" "$OPT/sequentia/bin/"
done
p=$src/price-server; [ -d "$p" ] || p=$src/contrib/price-server
cp "$p/price_server.py" "$p/config.example.json" "$OPT/sequentia/price-server/"
for d in "$LIB" "$LIB/sequentia" "$LIB/bitcoin" "$LIB/seqln" "$LIB/cln" "$LIB/arca" "$LIB/captaind" "$LIB/watchmand" "$LIB/www" "$LOG" "/run/$NAME"; do install -d -m 750 -o "$NAME" -g "$NAME" "$d"; done
install -d -m 750 -o root -g "$NAME" "$ETC"
# The keys draw_keys would draw (its word list comes from a cargo build).
openssl rand -hex 32 > "$ETC/operator.key"
python3 -c 'print(" ".join(["abandon"] * 23 + ["art"]))' > "$ETC/wallet.mnemonic"
openssl rand -hex 24 > "$ETC/seq-rpc.password"; openssl rand -hex 24 > "$ETC/btc-rpc.password"

# A stand-in price feed and registry, on loopback.
install -d /srv/standin
cat > /srv/standin/serve.py <<'PY'
import http.server, json, sys
gold = "33" * 32
routes = {
    "/prices": {"SEQ": {"price": 0.5, "market_cap": 1e9, "volume_24h": 1e7},
                "GOLD": {"price": 3000.0, "market_cap": 1e9, "volume_24h": 1e7}},
    "/registry": {sys.argv[2]: ["example.test", "SEQ", "Sequence", 8, 1, 0],
                  gold: ["example.test", "GOLD", "Gold", 8, 1, 0]},
}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(routes.get(self.path, {})).encode()
        self.send_response(200 if self.path in routes else 404)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

cat > "$ETC/bundle.env" <<EOF
NAME=$NAME
SEQ_CHAIN=elementsregtest
BTC_CHAIN=regtest
ARCA_ASSETS=""
PRICE_FEED_URL=http://127.0.0.1:18999/prices
ASSET_REGISTRY_INDEX=http://127.0.0.1:18999/registry
PRICE_SERVER_PORT=18890
SEQ_CHAIN_CONF="con_any_asset_fees=1;con_seed_fee_whitelist=0;blindedaddresses=0;con_blocksubsidy=0"
EOF
export BUNDLE_ENV=$ETC/bundle.env
BUNDLE_LIB=1 . /opt/arca-src/contrib/operator-bundle/install.sh
draw_keys >/dev/null
configure() { write_configs >/dev/null; echo "$changed"; }

cli() { runuser -u "$NAME" -- "$OPT/sequentia/bin/sequentia-cli" -conf="$ETC/sequentia.conf" -datadir="$LIB/sequentia" "$@"; }
start_node() {
  runuser -u "$NAME" -- "$OPT/sequentia/bin/sequentiad" -conf="$ETC/sequentia.conf" -datadir="$LIB/sequentia" \
    -validateanchor=0 -validatepegin=0 -daemon=0 -printtoconsole=0 >>"$LOG/node.stderr" 2>&1 & NODE=$!
  for i in $(seq 120); do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; done
  fail "the node did not answer: $(tail -5 "$LOG/node.stderr" 2>&1 || true)"
}
stop_node() { cli stop >/dev/null; wait "$NODE" || true; }
start_ps() {
  # shellcheck disable=SC2046
  runuser -u "$NAME" -- $(price_server_cmd) >>"$LOG/price-server.log" 2>&1 & PS=$!
}
stop_ps() { kill "$PS"; wait "$PS" 2>/dev/null || true; }

changed=$(configure)
grep -q '^\[elementsregtest\]' "$ETC/sequentia.conf" || fail "no chain section in sequentia.conf"
if node_reads_price_server; then
  echo "== a release whose node reads a price server"
  jq -e 'has("node_rpc") or has("node_rpcs") | not' "$LIB/price-server.json" >/dev/null \
    || fail "the price server's configuration holds a node login"
  grep -qx "feepriceserver=http://127.0.0.1:18890/feewhitelist" "$ETC/sequentia.conf" \
    || fail "the node is not connected to the bundle's price server"
  [ "$(price_server_cmd)" = "/usr/bin/python3 -I $OPT/sequentia/price-server/price_server.py --config $LIB/price-server.json --ui-host 127.0.0.1 --ui-port 18890" ] \
    || fail "the price server's command line: $(price_server_cmd)"
  ok "configured: no node login, published on 127.0.0.1:18890, the node connected to it"
  start_node
  policy=$(cli getsidechaininfo | jq -r .pegged_asset)
  python3 -I /srv/standin/serve.py 18999 "$policy" & STANDIN=$!
  start_ps
  for i in $(seq 240); do
    n=$(cli getfeeexchangerates | jq 'length'); [ "$n" = 2 ] && break; sleep 1
  done
  st=$(cli getfeepriceserver)
  jq -e '.connected and .whitelist == "dynamic" and .url == "http://127.0.0.1:18890/feewhitelist" and .decided_by == "configuration file"' <<<"$st" >/dev/null \
    || fail "the node's state: $st"
  [ "$(cli getfeeexchangerates | jq 'length')" = 2 ] || fail "the node's list: $(cli getfeeexchangerates)"
  ok "the node reads the price server's list after $i s: $(cli getfeeexchangerates | jq -c 'keys|map(.[0:8])'), dynamic, decided by the configuration file"
  stop_ps
  sleep 3
  [ "$(cli getfeeexchangerates | jq 'length')" = 2 ] || fail "the list went with the price server"
  stop_node; start_node
  [ "$(cli getfeeexchangerates | jq 'length')" = 2 ] || fail "the list did not survive the node's restart with the price server down"
  ok "the price server down: the node keeps its list, across its own restart too"
  stop_node; kill "$STANDIN"; wait "$STANDIN" 2>/dev/null || true
else
  echo "== an older release: the price server writes to the node"
  jq -e '.node_rpc.cookie == "/var/lib/arca-bundle/sequentia/elementsregtest/.cookie" and .node_rpc.port == 18884' "$LIB/price-server.json" >/dev/null \
    || fail "the price server's node login: $(jq -c .node_rpc "$LIB/price-server.json")"
  ! grep -q '^feepriceserver=\|^nofeepriceserver=' "$ETC/sequentia.conf" || fail "an older node's configuration names a price server"
  [ "$(price_server_cmd)" = "/usr/bin/python3 -I $OPT/sequentia/price-server/price_server.py --config $LIB/price-server.json" ] \
    || fail "the price server's command line: $(price_server_cmd)"
  ok "configured: the price server writes with the node's cookie; no price server in the node's configuration"
  start_node
  policy=$(cli getsidechaininfo | jq -r .pegged_asset)
  python3 -I /srv/standin/serve.py 18999 "$policy" & STANDIN=$!
  start_ps
  for i in $(seq 240); do
    n=$(cli getfeeexchangerates | jq 'length'); [ "$n" = 2 ] && break; sleep 1
  done
  [ "$(cli getfeeexchangerates | jq 'length')" = 2 ] || fail "the node's list: $(cli getfeeexchangerates); $(tail -5 "$LOG/price-server.log")"
  ok "the price server wrote the list after $i s: $(cli getfeeexchangerates | jq -c 'keys|map(.[0:8])')"
  stop_ps; stop_node; kill "$STANDIN"; wait "$STANDIN" 2>/dev/null || true
fi
again=$(configure)
[ -z "$again" ] || fail "configuring again changed:$again"
ok "configuring again changes nothing"
echo "PASS"
INNER
)
