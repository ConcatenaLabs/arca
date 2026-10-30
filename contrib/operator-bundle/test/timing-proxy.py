#!/usr/bin/env python3
"""A reverse proxy in front of an Arca server that writes down how long the
server took to answer each request, for operator-tests.sh's load test.

    timing-proxy.py LISTEN_PORT UPSTREAM_URL LOG_FILE

Each request is passed on unchanged, its answer passed back, and one line
written to LOG_FILE: the wall time it ended, the call's path, the HTTP
status, and the seconds from the request read to the answer read. The proxy
adds the connecting address to X-Forwarded-For as a reverse proxy does.
It listens on 127.0.0.1 only.
"""
import http.client
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, UPSTREAM, LOG = int(sys.argv[1]), urllib.parse.urlsplit(sys.argv[2]), sys.argv[3]
BASE = UPSTREAM.path.rstrip("/")
lock = threading.Lock()
log = open(LOG, "a", buffering=1)
local = threading.local()


def upstream():
    c = getattr(local, "conn", None)
    if c is None:
        c = http.client.HTTPConnection(UPSTREAM.hostname, UPSTREAM.port or 80, timeout=300)
        local.conn = c
    return c


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def relay(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length")}
        fwd = self.headers.get("x-forwarded-for")
        headers["X-Forwarded-For"] = (fwd + ", " if fwd else "") + self.client_address[0]
        t0 = time.monotonic()
        for attempt in (0, 1):
            try:
                c = upstream()
                c.request(self.command, BASE + self.path, body=body, headers=headers)
                r = c.getresponse()
                data = r.read()
                break
            except (http.client.HTTPException, OSError):
                local.conn = None
                if attempt:
                    self.send_response(502)
                    self.send_header("content-length", "0")
                    self.end_headers()
                    with lock:
                        log.write("%.3f %s 502 %.6f\n" % (time.time(), self.path, time.monotonic() - t0))
                    return
        took = time.monotonic() - t0
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        with lock:
            log.write("%.3f %s %d %.6f\n" % (time.time(), self.path, r.status, took))

    do_GET = relay
    do_POST = relay


ThreadingHTTPServer.daemon_threads = True
ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
