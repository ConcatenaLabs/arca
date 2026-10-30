#!/usr/bin/env python3
"""Prints the payment hash of a BOLT11 invoice: bolt11_hash.py INVOICE."""
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
inv = sys.argv[1].strip().lower()
data = [CHARSET.index(c) for c in inv[inv.rfind("1") + 1:]][:-6]
i = 7  # the timestamp, 35 bits
while i + 3 <= len(data) - 104:  # the signature, 520 bits, ends it
    tag, n = data[i], data[i + 1] * 32 + data[i + 2]
    field = data[i + 3:i + 3 + n]
    if CHARSET[tag] == "p" and n == 52:
        bits = "".join(format(v, "05b") for v in field)[:256]
        print("%064x" % int(bits, 2))
        sys.exit(0)
    i += 3 + n
sys.exit("no payment hash in the invoice")
