#!/usr/bin/env python3
"""fee-proxy.py: the Bitcoin ark's node RPC, with fee estimates from the live mempool.

Bark's server (captaind), its watchman (watchmand) and Bark wallets price every
transaction they make (a round, an offboard, a board, an exit's child) from
Bitcoin Core's `estimatesmartfee`, as Core gives it. testnet4 often mines empty
blocks while its public mempool queues at tens of sat/vB, and Core's estimate,
read from the blocks, then says a sat or two: a round paid at that waits for
hours. Bark takes no floor of its own, and uses its configured fallback rates
only when Core gives no estimate at all.

This proxy sits between them and the ark's node. Every request is passed through
unchanged, with its own credentials (the node's cookie, which the caller holds),
except that an `estimatesmartfee` answer is raised to the going rate: the most of
a floor, Core's own estimate, the rate that makes the next block of the node's
mempool, and the public mempool's rate (mempool.space: its fastest rate, or the
median of its next projected block), capped. The going rate is read every
`--refresh` seconds in the background, with the node's cookie, so a request never
waits on it.

    fee-proxy.py --listen 127.0.0.1:18352 --upstream 127.0.0.1:18342 \\
        --cookie /var/lib/bitcoin-ark/bitcoind/testnet4/.cookie \\
        [--floor 30] [--cap 500] [--api https://mempool.space/testnet4/api/v1/fees] [--refresh 30]

It listens on loopback only and logs a line when the going rate changes.
"""
import argparse, base64, http.server, json, math, socketserver, sys, threading, time, urllib.error, urllib.request

A = None
GOING = {"rate": None, "why": "not read yet"}


def upstream(path, body, headers, timeout=300):
    req = urllib.request.Request("http://%s%s" % (A.upstream, path), data=body, method="POST")
    for k in ("Authorization", "Content-Type"):
        if headers.get(k):
            req.add_header(k, headers[k])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def own_call(method, *params):
    cookie = open(A.cookie).read().strip()
    h = {"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode(), "Content-Type": "application/json"}
    status, body = upstream("/", json.dumps({"jsonrpc": "1.0", "id": "fee-proxy", "method": method, "params": list(params)}).encode(), h, 60)
    r = json.loads(body)
    if r.get("error"):
        raise RuntimeError(r["error"])
    return r["result"]


def next_block_rate():
    txs = []
    for e in own_call("getrawmempool", True).values():
        f = e.get("fees") or {}
        own = f.get("base", 0) * 1e8 / max(1, e.get("vsize", 1))
        anc = f.get("ancestor", 0) * 1e8 / max(1, e.get("ancestorsize", 1)) if e.get("ancestorsize") else own
        txs.append((min(own, anc), e.get("vsize", 0)))
    cum = 0
    for rate, size in sorted(txs, reverse=True):
        cum += size
        if cum >= 950000:
            return rate + 1
    return 0.0


def public_rate():
    if not A.api:
        return 0.0
    g = lambda p: json.loads(urllib.request.urlopen(A.api + p, timeout=10).read())
    r = float(g("/recommended").get("fastestFee") or 0)
    b = g("/mempool-blocks")
    if b:
        fr = b[0].get("feeRange") or [0]
        r = max(r, float(b[0].get("medianFee") or 0), float(fr[len(fr) // 2]))
    return r


def refresh_once():
    parts = {}
    for name, f in (("node estimate", lambda: (own_call("estimatesmartfee", 2, "CONSERVATIVE").get("feerate") or 0) * 1e5),
                    ("node mempool next block", next_block_rate), ("public mempool", public_rate)):
        try:
            parts[name] = float(f())
        except Exception as e:
            parts[name] = 0.0
            parts[name + " unread"] = str(e)[:80]
    r = max([A.floor] + [v for k, v in parts.items() if isinstance(v, float)])
    capped = r > A.cap
    r = min(r, A.cap)
    why = "floor %g, %s%s" % (A.floor, ", ".join("%s %.1f" % (k, v) for k, v in parts.items() if isinstance(v, float)),
                              "; capped at %g" % A.cap if capped else "")
    if GOING["rate"] != r:
        print("going rate %.1f sat/vB (%s)" % (r, why), flush=True)
    GOING["rate"], GOING["why"] = r, why


def refresher():
    while True:
        try:
            refresh_once()
        except Exception as e:
            print("going rate not read: %s" % e, flush=True)
        time.sleep(A.refresh)


def raise_estimate(req, resp):
    """resp: Core's answer to one estimatesmartfee request; raised to the going rate."""
    rate = GOING["rate"] if GOING["rate"] is not None else A.floor
    if not isinstance(resp, dict) or resp.get("error"):
        return resp
    res = resp.get("result") or {}
    core = res.get("feerate") or 0
    want = math.ceil(rate * 1000) / 1e8  # sat/vB to BTC/kvB, rounded up
    if core < want:
        params = req.get("params")
        target = (params[0] if isinstance(params, list) and params else (params or {}).get("conf_target", 2)) if params else 2
        res = {"feerate": want, "blocks": int(target) if str(target).isdigit() else 2}
    else:
        res = dict(res)
    # written back as Core writes it, eight decimal places, never in exponent form
    res["feerate"] = FEE_MARK + "%.8f" % res["feerate"]
    return dict(resp, result=res)


FEE_MARK = "@@fee-proxy-btc@@"


def dumps(resp):
    import re
    return re.sub(r'"%s([0-9.]+)"' % FEE_MARK, r"\1", json.dumps(resp)).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        try:
            req = json.loads(body)
        except ValueError:
            req = None
        est = isinstance(req, dict) and req.get("method") == "estimatesmartfee"
        batch = isinstance(req, list) and any(isinstance(x, dict) and x.get("method") == "estimatesmartfee" for x in req)
        status, out = upstream(self.path, body, self.headers)
        if est or batch:
            try:
                resp = json.loads(out)
                if est:
                    resp = raise_estimate(req, resp)
                else:
                    by_id = {json.dumps(x.get("id")): x for x in req if isinstance(x, dict)}
                    resp = [raise_estimate(by_id.get(json.dumps(r.get("id")), {}), r)
                            if by_id.get(json.dumps(r.get("id")), {}).get("method") == "estimatesmartfee" else r for r in resp]
                out = dumps(resp)
            except (ValueError, AttributeError, TypeError):
                pass
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global A
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--listen", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--cookie", required=True)
    p.add_argument("--floor", type=float, default=30)
    p.add_argument("--cap", type=float, default=500)
    p.add_argument("--api", default="https://mempool.space/testnet4/api/v1/fees")
    p.add_argument("--refresh", type=float, default=30)
    A = p.parse_args()
    host, port = A.listen.rsplit(":", 1)
    if host not in ("127.0.0.1", "::1", "localhost"):
        sys.exit("fee-proxy listens on loopback only, not %s" % host)
    try:
        refresh_once()
    except Exception as e:
        print("going rate not read at start: %s; the floor until it is" % e, flush=True)
    threading.Thread(target=refresher, daemon=True).start()
    print("fee-proxy on %s for the node at %s" % (A.listen, A.upstream), flush=True)
    Server((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
