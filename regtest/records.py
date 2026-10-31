#!/usr/bin/env python3
"""The reference for Arca's leaf record: the tree, the record, its id and its
two encodings, in plain Python.

This module is the independent half of the record's golden vectors. It shares
no code with the Rust crate `arca-covenant`; it builds every script with the
suite's own builders (arklib3.py) and writes the record exactly as the
specification below says. `vectors.py` calls `generate()` and writes the result
to `vectors/records.json`, which the Rust tests must reproduce byte for byte.

The tree
--------
A batch holds the leaves of one asset. Each leaf sits behind a hash-locked
entry, whose value is the leaf's value plus the entry's reserve. The entries
are laid left to right and grouped into lowest nodes; the lowest nodes are
grouped the same way into the level above, and so on until one node is left:
the batch output. At every level the children are spread as evenly as
possible over the fewest nodes that hold them: n children at radix r go to
k = ceil(n / r) nodes, the first n mod k of them holding n // k + 1 children
and the rest n // k. Every node then holds 2 to r children; the one node with
a single child is the batch output of a batch of one leaf. The radix is 3 to
6 (at radix 2 an odd level would need a node of one child). Every node's
script is built for its own child count. A key holds one leaf: a batch
with an owner key on two leaves is refused. A node's value is
the sum of its children's values plus its reserve. Its members are the
operator and the owners of every leaf under it, in leaf order, padded to a
power of two with the operator's key. The batch output's sweep has no notice;
every other node's and every entry's has the notice `W`. The lowest nodes
(including a batch output whose children are entries) carry RECLAIM.

Each leaf's salt has a contribution from each side:
SHA256("Arca/salt" || owner_nonce || operator_nonce), the second nonce being
that of the leaf's creator, here the operator, which builds the round. The
record carries both nonces and not the salt, which is rebuilt from them.

The record, format version 2
----------------------------
All integers are little-endian. Asset ids and the genesis hash are in internal
byte order.

    u8    format version, 2
    u8    template, 1 (vtxo), 3 (htlc), 4 (order), 5 (landing), 7 (channel) or 8 (claim)
    u8    template version, 1 (vtxo, htlc, landing, channel, claim), 2 or 3 (order), or 2
          (vtxo-2, a vtxo leaf whose collaborative path is arca/collab-2, collab2.py)
    [32]  owner key A                 the vtxo-1 parameters
    [32]  owner nonce
    [32]  operator nonce
    u16   exit delay, 512-second units
          htlc-1 only (a leaf whose exit is a claim with a preimage and a
          refund after a timeout, arklib3.htlc_taptree):
    u8    direction, 0 send (the operator claims) or 1 receive (the owner claims)
    [32]  payment hash
    u32   timeout, a median time
    u16   operator delay, 512-second units; shorter than the exit delay
          order-2 and order-3 only (a resting order, order.py; it sells the leaf's asset):
    [32]  asset B, what it is paid in
    u64   rate numerator   u64 rate denominator   u64 minimum lot
    [32]  SHA256 of the scriptPubKey the landed order's fills pay
    u32   the landed order's REFUND time, a median time
    [32]  the landed order's refund key
    4 × [32]  the next credit keys, the next first, zero once used
          landing-1 only (a leaf of a supervised asset, arklib3.landing_taptree):
    [20]  P, the landing program: hash160 of the owner's landing key L
    u64   the fee allowance: the exit's output 0 holds at least the value
          less this; below the value
          channel-1 only (a leaf with a balance for each side, channel.py):
    u64   the operator's opening balance, below the value
    u16   the credit window, 512-second units, no shorter than the exit delay
          claim-1 only (a distribution's claim leaf, arklib3.claim_taptree):
    u32   the deadline D, a median time: the lapse waits for it
    u64   the fee allowance: the lapse's output holds at least the value less
          this; below the value
    u16   the return script's length, 1 to 10,000, then the return script
    [32]  asset                       the leaf and its entry
    u64   value
    [32]  unlock hash h
    u64   entry reserve
    [32]  genesis hash                the batch
    [32]  operator key S
    [32]  token T
    u16   notice W, 512-second units
    u8    flags: bit 0, the sweeps are burn-only; bit 1, the lowest node
          carries RECLAIM-D; other bits zero
    u8    expiry count, 1 to 64, then each expiry E_k as u32
    u8    level count, 1 to 16, then each level from the batch output down:
            u8    child count k, 1 to 6
            u8    index of the child on the leaf's path, below k
            u64   reserve
            k-1 × (u64 value, [32] program)    the other children, in order
          above the lowest level:
            u32   the owner's index in the node's member list
            u8    member depth D, 1 to 17, then D × [32] the member path's
                  siblings, bottom level first
          at the lowest level (the last):
            k-1 × [32]                         the other owners, in order

A record of a batch without a sweep is format version 3: the same fields,
with the token, the notice and the expiries left out, since such a batch has
no token and no clock and no output above its leaves carries a sweep leaf.
In their place, after the operator key:

    u8    flags: bit 1, the lowest node carries RECLAIM-D; other bits zero

and its JSON form has "version": 3 and no "token", "notice_units", "burn" or
"expiries". A version 2 record never names the no-sweep token
SHA256("Arca/no-sweep").

The leaf id is the BIP340 tagged hash, tag "Arca/leaf-id", of

    batch output's witness program (32) ‖ level count (u8)
    ‖ each level's child index (u8), from the batch output down
    ‖ the leaf's witness program (32)

The JSON form has the same fields; an htlc-1 record's terms are one object,
`htlc`: {"direction": "send" or "receive", "payment_hash", "timeout",
"operator_delay_units"}, and an order-2 or order-3 record's `order`:
{"asset_b", "rate_num", "rate_den", "min_lot", "maker", "expiry",
"refund_key", "credits"}, with "version": 3 for order-3, and a landing-1 record's `landing`: {"program", "allowance"},
and a channel-1 record's `channel`: {"capacity", "window_units"},
and a claim-1 record's `claim`: {"deadline", "allowance", "return_script"}.
Its canonical text has its keys sorted and
no whitespace. Asset ids, the token and the genesis hash are hex in display
order (the order the node's RPCs print), every other byte string hex in its
own order, lower case. Amounts are decimal strings, so that no reader rounds
them; counts, indices, delays and times are numbers.
"""
import json
import struct

from arklib3 import *                      # noqa: F401,F403
from test_framework.messages import (COutPoint, CTxIn, CTxOut, CTxOutAsset, CTxOutNonce, CTxOutValue,
                                     CAssetIssuance, uint256_from_str)

FORMAT_VERSION = 2
FORMAT_VERSION_NO_SWEEP = 3
NO_SWEEP_TOKEN = sha256(b"Arca/no-sweep")
TEMPLATES = {"vtxo": 1, "board": 2, "htlc": 3, "order": 4, "landing": 5, "channel": 7, "claim": 8}   # name -> template id; a board record names board
TEMPLATE_VTXO, TEMPLATE_VTXO_VERSION = 1, 1
TEMPLATE_BOARD, TEMPLATE_BOARD_VERSION = 2, 1
TEMPLATE_HTLC, TEMPLATE_HTLC_VERSION = 3, 1
TEMPLATE_ORDER, TEMPLATE_ORDER_VERSION = 4, 2
TEMPLATE_LANDING, TEMPLATE_LANDING_VERSION = 5, 1
TEMPLATE_CHANNEL, TEMPLATE_CHANNEL_VERSION = 7, 1
TEMPLATE_CLAIM, TEMPLATE_CLAIM_VERSION = 8, 1
TEMPLATE_VTXO2_VERSION = 2


class _Spk:
    def __init__(self, spk):
        self.scriptPubKey = spk


def vtxo2_leaf_tap(lf, S, salt, ctag):
    """A vtxo-2 leaf, through collab2.py's own derivation."""
    import collab2
    return _Spk(collab2.Collab2(lf["owner"], S, salt, ctag, exit_leaf(lf["owner"], SEQ_TIME | lf["exit_delay"])).spk)


def order_leaf_tap(lf, S, salt, ctag, asset):
    """An order-3 or order-2 leaf (by its terms' version), through order.py's own derivation."""
    import order as order_py
    o = lf["order"]
    terms = {"asset_a": asset, "asset_b": o["asset_b"], "num": o["num"], "den": o["den"], "min_lot": o["min_lot"],
             "maker": o["maker"], "expiry": o["expiry"], "refund_key": o["refund_key"]}
    return _Spk(order_py.Order(terms, lf["owner"], S, salt, ctag, SEQ_TIME | lf["exit_delay"], o["credits"],
                               o.get("version", 2)).spk)
DIRECTIONS = {"send": 0, "receive": 1}
LEAF_ID_TAG = b"Arca/leaf-id"
SALT_TAG = b"Arca/salt"


def leaf_salt(owner_nonce, operator_nonce):
    return sha256(SALT_TAG + owner_nonce + operator_nonce)


def spread(n, r):
    """The children of each node, as (start, end) ranges, when n children are
    grouped at radix r: the fewest nodes, as evenly as possible, the larger
    ones first."""
    k = (n + r - 1) // r
    q, rem = divmod(n, k)
    out, at = [], 0
    for j in range(k):
        size = q + (1 if j < rem else 0)
        out.append((at, at + size))
        at += size
    return out


def tagged_hash(tag, msg):
    t = sha256(tag)
    return sha256(t + t + msg)


def le16(n):
    return struct.pack("<H", n)


def le32(n):
    return struct.pack("<I", n)


def le64(n):
    return struct.pack("<Q", n)


def display(b):
    """Internal byte order to the hex an RPC prints."""
    return bytes(b)[::-1].hex()


# --------------------------------------------------------------------------
# The id of an issued asset (Elements: a fast Merkle root of two leaves is the
# SHA256 compression of their concatenation, without padding)
# --------------------------------------------------------------------------

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_midstate(block64):
    """The SHA256 state after compressing one 64-byte block from the IV."""
    assert len(block64) == 64
    w = list(struct.unpack(">16I", block64))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = _IV
    for i in range(64):
        t1 = (h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & 0xffffffff
        t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
        a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffff, a, b, c, (d + t1) & 0xffffffff, e, f, g
    return struct.pack(">8I", *[(x + y) & 0xffffffff for x, y in zip(_IV, [a, b, c, d, e, f, g, h])])


def issued_asset(txid_internal, vout, contract_hash=bytes(32)):
    """The asset an input spending (txid, vout) issues with `contract_hash`."""
    prevout_hash = sha256(sha256(txid_internal + le32(vout)))
    entropy = sha256_midstate(prevout_hash + contract_hash)
    return sha256_midstate(entropy + bytes(32))


# --------------------------------------------------------------------------
# The tree
# --------------------------------------------------------------------------

def reclaim_script(prefix, owners, s_x):
    """RECLAIM for one owner or more (arklib3.reclaim_leaf): each owner's
    release, SHA256(prefix || M), names the round of that owner's new leaf."""
    return reclaim_leaf(prefix, owners, s_x)


class Batch:
    """A batch built by the rules above.

    p: genesis (internal), asset (internal), operator (x-only), token
    (internal), notice (units), expiries, burn, radix, node_reserve,
    entry_reserve. leaves: [{owner, owner_nonce, operator_nonce, value,
    exit_delay, unlock_hash}], an htlc-1 leaf also with htlc: {direction,
    payment_hash, timeout, operator_delay}."""

    def __init__(self, p, leaves):
        self.p, self.leaves = p, leaves
        S, r = p["operator"], p["radix"]
        assert 3 <= r <= 6
        owners = [lf["owner"] for lf in leaves]
        if len(set(owners)) != len(owners):
            raise ValueError("a key holds one leaf: an owner key appears on two leaves")
        notice = SEQ_TIME | p["notice"]
        r_tap, _ = r_taptree(S, notice)
        self.r_spk = bytes(r_tap.scriptPubKey)
        r_prog = self.r_spk[2:]

        def sweep(root):
            if p.get("no_sweep"):
                return None
            w = None if root else notice
            return burn_sweep(p["token"], r_prog, S, w) if p["burn"] else sweep_token(p["token"], r_prog, S, w)

        ctag = chain_tag(p["genesis"])
        self.leaf_taps, self.entries = [], []
        level = []
        for i, lf in enumerate(leaves):
            salt = leaf_salt(lf["owner_nonce"], lf["operator_nonce"])
            h = lf.get("htlc")
            if lf.get("order") is not None:
                tap = order_leaf_tap(lf, S, salt, ctag, p["asset"])
            elif lf.get("channel") is not None:
                import channel as channel_py
                c = lf["channel"]
                ch = channel_py.Channel(p["genesis"], salt, lf["owner"], S, SEQ_TIME | lf["exit_delay"], lf["value"],
                                        c["capacity"], SEQ_TIME | c["window"])
                tap, _ = ch.tap(ch.opening())
            elif lf.get("claim") is not None:
                q = lf["claim"]
                tap, _ = claim_taptree(lf["owner"], S, salt, ctag, SEQ_TIME | lf["exit_delay"], q["deadline"],
                                       q["return_script"], p["asset"], lf["value"], q["allowance"])
            elif lf.get("landing") is not None:
                g = lf["landing"]
                tap, _ = landing_taptree(lf["owner"], S, salt, ctag, SEQ_TIME | lf["exit_delay"], g["program"], p["asset"],
                                         lf["value"], g["allowance"])
            elif lf.get("v2"):
                tap = vtxo2_leaf_tap(lf, S, salt, ctag)
            elif h is None:
                tap, _ = leaf3_taptree(lf["owner"], S, salt, ctag, SEQ_TIME | lf["exit_delay"], fold=True)
            else:
                assert h["operator_delay"] < lf["exit_delay"], "an htlc-1 operator delay is shorter than the exit delay"
                tap, _ = htlc_taptree(lf["owner"], S, salt, ctag, h["payment_hash"], h["timeout"],
                                      SEQ_TIME | lf["exit_delay"], SEQ_TIME | h["operator_delay"],
                                      receive=h["direction"] == "receive")
            self.leaf_taps.append(tap)
            etap, _ = entry_taptree(lf["unlock_hash"], p["asset"], lf["value"], bytes(tap.scriptPubKey)[2:],
                                    sweep(False))
            value = lf["value"] + p["entry_reserve"]
            self.entries.append({"tap": etap, "value": value})
            level.append({"value": value, "prog": bytes(etap.scriptPubKey)[2:], "first": i, "owners": [i]})
        self.levels = []                   # lowest nodes first; the last holds the batch output alone
        lowest = True
        while True:
            groups = spread(len(level), r)
            is_root = len(groups) == 1
            nodes = []
            for lo, hi in groups:
                kids = level[lo:hi]
                tuples = [(p["asset"], k["value"], k["prog"]) for k in kids]
                owners = sum((k["owners"] for k in kids), [])
                keys = [S] + [leaves[o]["owner"] for o in owners]
                mlevels, _ = hmerkle(keys, S)
                unroll = hgate_unroll(mlevels[-1][0], len(mlevels) - 1, tuples, timed=True)
                reclaim = None
                if lowest:
                    prefix = release_prefix(p["genesis"], tuples)
                    reclaim = reclaim_script(prefix, [leaves[o]["owner"] for o in owners], S)
                if lowest and p.get("delegated"):
                    reclaim_d = reclaim_delegated_leaf(prefix, delegate_prefix(p["genesis"]),
                                                       [leaves[o]["owner"] for o in owners], S)
                    tap, _ = node_taptree_delegated(unroll, sweep(is_root), reclaim, reclaim_d)
                else:
                    tap, _ = node_taptree3(unroll, sweep(is_root), reclaim)
                nodes.append({"tap": tap, "prog": bytes(tap.scriptPubKey)[2:], "kids": kids, "owners": owners,
                              "first": kids[0]["first"], "mlevels": mlevels, "lo": lo, "hi": hi,
                              "value": sum(k["value"] for k in kids) + p["node_reserve"]})
            self.levels.append(nodes)
            level, lowest = nodes, False
            if is_root:
                break
        self.root = self.levels[-1][0]
        self.clocks = None if p.get("no_sweep") else clock_chain(p["token"], self.r_spk, S, p["expiries"])

    def batch_spk(self):
        return bytes(self.root["tap"].scriptPubKey)

    def record(self, i):
        """Leaf i's record, as a dict of the format's fields."""
        p, lf = self.p, self.leaves[i]
        levels = []
        idx = i
        for depth, nodes in enumerate(self.levels):
            j = next(j for j, nd in enumerate(nodes) if nd["lo"] <= idx < nd["hi"])
            node = nodes[j]
            k = idx - node["lo"]
            sib = [(c["value"], c["prog"]) for n, c in enumerate(node["kids"]) if n != k]
            level = {"children": len(node["kids"]), "index": k, "reserve": p["node_reserve"], "siblings": sib}
            if depth == 0:
                level["owners"] = [self.leaves[o]["owner"] for n, o in enumerate(node["owners"]) if n != k]
            else:
                m = 1 + i - node["first"]
                level["member_index"] = m
                level["member_path"] = [s for s, _ in mpath(node["mlevels"], m)]
            levels.append(level)
            idx = j
        levels.reverse()                   # from the batch output down
        h = lf.get("htlc")
        o = lf.get("order")
        g = lf.get("landing")
        c = lf.get("channel")
        q = lf.get("claim")
        return {
            "template": ("order", o.get("version", TEMPLATE_ORDER_VERSION)) if o else ("htlc", TEMPLATE_HTLC_VERSION) if h
            else ("landing", TEMPLATE_LANDING_VERSION) if g else ("channel", TEMPLATE_CHANNEL_VERSION) if c
            else ("claim", TEMPLATE_CLAIM_VERSION) if q
            else ("vtxo", TEMPLATE_VTXO2_VERSION) if lf.get("v2") else ("vtxo", TEMPLATE_VTXO_VERSION),
            "htlc": h,
            "order": o,
            "landing": g,
            "channel": c,
            "claim": q,
            "owner": lf["owner"], "owner_nonce": lf["owner_nonce"], "operator_nonce": lf["operator_nonce"],
            "exit_delay": lf["exit_delay"],
            "asset": p["asset"], "value": lf["value"], "unlock_hash": lf["unlock_hash"],
            "entry_reserve": p["entry_reserve"],
            "genesis": p["genesis"], "operator": p["operator"], "token": p["token"], "notice": p["notice"],
            "burn": p["burn"], "delegated": bool(p.get("delegated")), "expiries": list(p["expiries"]),
            "no_sweep": bool(p.get("no_sweep")),
            "path": levels,
        }


# --------------------------------------------------------------------------
# Encodings and the id
# --------------------------------------------------------------------------

def encode(rec):
    name, ver = rec["template"]
    no_sweep = rec.get("no_sweep")
    b = bytes([FORMAT_VERSION_NO_SWEEP if no_sweep else FORMAT_VERSION, TEMPLATES[name], ver])
    b += rec["owner"] + rec["owner_nonce"] + rec["operator_nonce"] + le16(rec["exit_delay"])
    if name == "htlc":
        h = rec["htlc"]
        b += bytes([DIRECTIONS[h["direction"]]]) + h["payment_hash"] + le32(h["timeout"]) + le16(h["operator_delay"])
    if name == "order":
        o = rec["order"]
        b += o["asset_b"] + le64(o["num"]) + le64(o["den"]) + le64(o["min_lot"]) + o["maker"] + le32(o["expiry"])
        b += o["refund_key"] + b"".join(o["credits"])
    if name == "landing":
        g = rec["landing"]
        b += g["program"] + le64(g["allowance"])
    if name == "channel":
        c = rec["channel"]
        b += le64(c["capacity"]) + le16(c["window"])
    if name == "claim":
        q = rec["claim"]
        b += le32(q["deadline"]) + le64(q["allowance"]) + le16(len(q["return_script"])) + q["return_script"]
    b += rec["asset"] + le64(rec["value"]) + rec["unlock_hash"] + le64(rec["entry_reserve"])
    if no_sweep:
        b += rec["genesis"] + rec["operator"] + bytes([2 if rec.get("delegated") else 0])
    else:
        b += rec["genesis"] + rec["operator"] + rec["token"] + le16(rec["notice"])
        b += bytes([(1 if rec["burn"] else 0) | (2 if rec.get("delegated") else 0)])
        b += bytes([len(rec["expiries"])]) + b"".join(le32(e) for e in rec["expiries"])
    b += bytes([len(rec["path"])])
    for n, lv in enumerate(rec["path"]):
        b += bytes([lv["children"], lv["index"]]) + le64(lv["reserve"])
        b += b"".join(le64(v) + prog for v, prog in lv["siblings"])
        if n + 1 < len(rec["path"]):
            b += le32(lv["member_index"]) + bytes([len(lv["member_path"])]) + b"".join(lv["member_path"])
        else:
            b += b"".join(lv["owners"])
    return b


def to_json(rec):
    """The JSON form, as a Python object."""
    name, ver = rec["template"]
    path = []
    for lv in rec["path"]:
        o = {"index": lv["index"], "reserve": str(lv["reserve"]),
             "siblings": [{"value": str(v), "program": prog.hex()} for v, prog in lv["siblings"]]}
        if "owners" in lv:
            o["owners"] = [k.hex() for k in lv["owners"]]
        else:
            o["member_index"] = lv["member_index"]
            o["member_path"] = [s.hex() for s in lv["member_path"]]
        path.append(o)
    o = {
        "version": FORMAT_VERSION, "template": "%s-%d" % (name, ver),
        "owner": rec["owner"].hex(), "owner_nonce": rec["owner_nonce"].hex(),
        "operator_nonce": rec["operator_nonce"].hex(), "exit_delay_units": rec["exit_delay"],
        "asset": display(rec["asset"]), "value": str(rec["value"]), "unlock_hash": rec["unlock_hash"].hex(),
        "entry_reserve": str(rec["entry_reserve"]),
        "genesis_hash": display(rec["genesis"]), "operator": rec["operator"].hex(), "token": display(rec["token"]),
        "notice_units": rec["notice"], "burn": rec["burn"], "expiries": rec["expiries"],
        "path": path,
    }
    if rec.get("no_sweep"):
        o["version"] = FORMAT_VERSION_NO_SWEEP
        for k in ("token", "notice_units", "burn", "expiries"):
            del o[k]
    if rec.get("delegated"):
        o["reclaim_delegated"] = True
    if name == "htlc":
        h = rec["htlc"]
        o["htlc"] = {"direction": h["direction"], "payment_hash": h["payment_hash"].hex(), "timeout": h["timeout"],
                     "operator_delay_units": h["operator_delay"]}
    if name == "order":
        t = rec["order"]
        o["order"] = order_json(t)
    if name == "landing":
        g = rec["landing"]
        o["landing"] = {"program": g["program"].hex(), "allowance": str(g["allowance"])}
    if name == "channel":
        c = rec["channel"]
        o["channel"] = {"capacity": str(c["capacity"]), "window_units": c["window"]}
    if name == "claim":
        q = rec["claim"]
        o["claim"] = {"deadline": q["deadline"], "allowance": str(q["allowance"]), "return_script": q["return_script"].hex()}
    return o


def order_json(t):
    """An order's terms; an order-3 leaf's carry "version": 3, an order-2 leaf's none."""
    o = {"asset_b": display(t["asset_b"]), "rate_num": str(t["num"]), "rate_den": str(t["den"]),
         "min_lot": str(t["min_lot"]), "maker": t["maker"].hex(), "expiry": t["expiry"],
         "refund_key": t["refund_key"].hex(), "credits": [c.hex() for c in t["credits"]]}
    if t.get("version", 2) == 3:
        o["version"] = 3
    return o


def json_text(obj):
    """The canonical text: keys sorted, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def leaf_id(batch_program, rec, leaf_program):
    msg = batch_program + bytes([len(rec["path"])]) + bytes(lv["index"] for lv in rec["path"]) + leaf_program
    return tagged_hash(LEAF_ID_TAG, msg)


# --------------------------------------------------------------------------
# The vectors
# --------------------------------------------------------------------------

def label_hash(kind, label):
    return sha256(("Arca test vector %s/%s" % (kind, label)).encode())


def xonly(label):
    from test_framework.key import SECP256K1_ORDER
    d = int.from_bytes(label_hash("key", label), "big") % SECP256K1_ORDER
    return compute_xonly_pubkey(d.to_bytes(32, "big"))[0]


# The same chain, operator and batch asset as vectors/arca.json.
GENESIS = bytes.fromhex("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c")[::-1]
ASSET = label_hash("asset", "X")
OPERATOR = xonly("S")
H = 3600
DAY = 24 * H
CREATED = 1_791_000_000
NOTICE = (36 * H + 511) // 512
EXIT_DELAY = NOTICE


def txout(asset, value, spk):
    return CTxOut(nValue=CTxOutValue(value), scriptPubKey=bytes(spk), nAsset=CTxOutAsset(b"\x01" + asset),
                  nNonce=CTxOutNonce())


def batch_vector(name, n, radix, burn=False, node_reserve=2_500, entry_reserve=1_000, export=None,
                 expiries=(28, 56, 84), odd_delay=None, htlc=None, order=None, order_version=2, landing=None, channel=None,
                 v2=None, delegated=False, no_sweep=False, claim=None):
    """One batch: its inputs, the round that funds it, and the records of the
    leaves in `export` (all when None)."""
    issuer_txid = label_hash("outpoint", "%s round issuer" % name)
    token = issued_asset(issuer_txid, 0)
    p = {"genesis": GENESIS, "asset": ASSET, "operator": OPERATOR, "token": token, "notice": NOTICE,
         "expiries": [CREATED + d * DAY for d in expiries], "burn": burn, "radix": radix,
         "node_reserve": node_reserve, "entry_reserve": entry_reserve, "delegated": delegated, "no_sweep": no_sweep}
    leaves = []
    for i in range(n):
        leaves.append({
            "owner": xonly("%s owner %d" % (name, i)),
            "owner_nonce": label_hash("owner nonce", "%s leaf %d" % (name, i)),
            "operator_nonce": label_hash("operator nonce", "%s leaf %d" % (name, i)),
            "value": 10_000_000 + 1_000 * i,
            "exit_delay": odd_delay if (odd_delay and i == n - 1) else EXIT_DELAY,
            "unlock_hash": sha256(label_hash("preimage", "%s entry %d" % (name, i))),
        })
    # htlc: {leaf index: direction}; each such leaf is an htlc-1 leaf.
    for i, direction in (htlc or {}).items():
        leaves[i]["htlc"] = {"direction": direction, "payment_hash": sha256(label_hash("preimage", "%s payment %d" % (name, i))),
                             "timeout": CREATED + 2 * DAY, "operator_delay": EXIT_DELAY // 3}
    # order: [leaf index]; each such leaf is an order leaf selling the batch's
    # asset, order-2, or order-3 with order_version 3.
    for i in (order or []):
        leaves[i]["order"] = {**({"version": 3} if order_version == 3 else {}),"asset_b": label_hash("asset", "%s paid in %d" % (name, i)), "num": 3, "den": 2,
                              "min_lot": 1_000, "maker": sha256(b"\x51\x20" + xonly("%s maker %d" % (name, i))),
                              "expiry": CREATED + 10 * DAY, "refund_key": xonly("%s refund %d" % (name, i)),
                              "credits": [xonly("%s credit %d.%d" % (name, i, k)) for k in range(4)]}
    # landing: [leaf index]; each such leaf is a landing-1 leaf of a supervised asset.
    for i in (landing or []):
        leaves[i]["landing"] = {"program": label_hash("landing", "%s leaf %d" % (name, i))[:20], "allowance": 2_000 + i}
    # channel: {leaf index: capacity}; each such leaf is a channel-1 leaf, the
    # operator's opening balance that part of its value.
    for i, capacity in (channel or {}).items():
        leaves[i]["channel"] = {"capacity": capacity, "window": 2 * EXIT_DELAY}
    # claim: [leaf index]; each such leaf is a claim-1 leaf of one distribution,
    # lapsing to its return script after its deadline.
    for i in (claim or []):
        leaves[i]["claim"] = {"deadline": CREATED + 14 * DAY,
                              "return_script": b"\x00\x14" + label_hash("claim", "%s return" % name)[:20],
                              "allowance": 1_500 + i}
    # v2: [leaf index]; each such leaf is a vtxo-2 leaf.
    for i in (v2 or []):
        leaves[i]["v2"] = True
    b = Batch(p, leaves)

    # The round: the issuing input, the batch output at 0, the token's atom in
    # clock 0 at 1, then the fee. Its lock time is 0.
    tx = Tx()
    tx.nVersion, tx.nLockTime = 2, 0
    vin = CTxIn(COutPoint(uint256_from_str(issuer_txid), 0), nSequence=0xffffffff)
    iss = CAssetIssuance()
    iss.assetBlindingNonce, iss.assetEntropy = 0, 0
    iss.nAmount, iss.nInflationKeys, iss.denomination = CTxOutValue(1), CTxOutValue(), 0
    vin.assetIssuance = iss
    tx.vin = [vin]
    if no_sweep:
        # A batch without a sweep: the round issues nothing and pays no token.
        vin.assetIssuance = CAssetIssuance()
        tx.vout = [txout(ASSET, b.root["value"], b.batch_spk()), txout(ASSET, 5_000, b"")]
    else:
        tx.vout = [txout(ASSET, b.root["value"], b.batch_spk()), txout(token, 1, b.clocks[0]["spk"]),
                   txout(ASSET, 5_000, b"")]
    ArkBase.pad(tx)

    batch_prog = b.batch_spk()[2:]
    lf_nonces = [(lf["owner_nonce"], lf["operator_nonce"]) for lf in leaves]
    records = []
    for i in (range(n) if export is None else export):
        rec = b.record(i)
        lprog = bytes(b.leaf_taps[i].scriptPubKey)[2:]
        records.append({
            "leaf": i,
            "salt": leaf_salt(lf_nonces[i][0], lf_nonces[i][1]).hex(),
            "position": [lv["index"] for lv in rec["path"]],
            "leaf_program": lprog.hex(),
            "entry_program": bytes(b.entries[i]["tap"].scriptPubKey)[2:].hex(),
            "leaf_id": leaf_id(batch_prog, rec, lprog).hex(),
            "binary": encode(rec).hex(),
            "json": json_text(to_json(rec)),
        })
    return {
        "name": name,
        "inputs": {
            "radix": radix, "burn": burn, "node_reserve": node_reserve, "entry_reserve": entry_reserve,
            **({"delegated_reclaim": True} if delegated else {}),
            **({"no_sweep": True} if no_sweep else {
                "token_issuer": {"txid": display(issuer_txid), "vout": 0, "contract_hash": bytes(32).hex()},
                "token": display(token), "notice_units": NOTICE, "expiries": p["expiries"]}),
            "leaves": [dict({"owner": lf["owner"].hex(), "owner_nonce": lf["owner_nonce"].hex(),
                             "operator_nonce": lf["operator_nonce"].hex(), "value": lf["value"],
                             "exit_delay_units": lf["exit_delay"], "unlock_hash": lf["unlock_hash"].hex()},
                            **({"htlc": {"direction": lf["htlc"]["direction"],
                                         "payment_hash": lf["htlc"]["payment_hash"].hex(),
                                         "timeout": lf["htlc"]["timeout"],
                                         "operator_delay_units": lf["htlc"]["operator_delay"]}} if "htlc" in lf else {}),
                            **({"order": order_json(lf["order"])} if "order" in lf else {}),
                            **({"landing": {"program": lf["landing"]["program"].hex(),
                                            "allowance": lf["landing"]["allowance"]}} if "landing" in lf else {}),
                            **({"channel": {"capacity": lf["channel"]["capacity"],
                                            "window_units": lf["channel"]["window"]}} if "channel" in lf else {}),
                            **({"claim": {"deadline": lf["claim"]["deadline"], "allowance": lf["claim"]["allowance"],
                                          "return_script": lf["claim"]["return_script"].hex()}} if "claim" in lf else {}),
                            **({"template": "vtxo-2"} if lf.get("v2") else {}))
                       for lf in leaves],
        },
        "levels": [len(lv) for lv in b.levels],
        "children": [[nd["hi"] - nd["lo"] for nd in lv] for lv in b.levels],
        "batch_output": {"asset": display(ASSET), "value": b.root["value"],
                         "script_pubkey": b.batch_spk().hex()},
        **({} if no_sweep else {"clock0_script_pubkey": b.clocks[0]["spk"].hex()}),
        "round": {"tx": tx.serialize().hex(), "batch_vout": 0},
        "records": records,
    }


def invalid_vectors(valid_binary, valid_json):
    """Encodings a decoder must refuse, each with the reason's kind."""
    v = bytes.fromhex(valid_binary)
    # Offsets of the fixed part (see the format above).
    OWNER, EXIT, VALUE = 3, 99, 133
    GEN = 3 + 32 + 32 + 32 + 2 + 32 + 8 + 32 + 8
    NOTICE_AT = GEN + 96
    FLAGS = NOTICE_AT + 2
    EXP = FLAGS + 1
    n_exp = v[EXP]
    LEVELS = EXP + 1 + 4 * n_exp
    FIRST = LEVELS + 1

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("format version 1", v[:0] + b"\x01" + v[1:], "version"),
        ("format version 4", v[:0] + b"\x04" + v[1:], "version"),
        ("the no-sweep token in a version 2 record", put(GEN + 64, NO_SWEEP_TOKEN), "sweep"),
        ("template 2", put(1, b"\x02"), "template"),
        ("template vtxo, version 3", put(2, b"\x03"), "template_version"),
        ("a trailing byte", v + b"\x00", "trailing"),
        ("the last byte missing", v[:-1], "end"),
        ("empty", b"", "end"),
        ("owner key not on the curve", put(OWNER, bytes(32)), "key"),
        ("an exit delay of zero", put(EXIT, le16(0)), "time"),
        ("a value of zero", put(VALUE, le64(0)), "value"),
        ("a value above the largest money range", put(VALUE, le64(400_000_000 * 100_000_000 + 1)), "value"),
        ("a notice of zero", put(NOTICE_AT, le16(0)), "time"),
        ("flag bit 2 set", put(FLAGS, b"\x04"), "flag"),
        ("no expiries", put(EXP, b"\x00"), "count"),
        ("an expiry that is a height", put(EXP + 1, le32(499_999_999)), "time"),
        ("no levels", put(LEVELS, b"\x00"), "count"),
        ("seven children", put(FIRST, b"\x07"), "count"),
        ("a child index past the child count", put(FIRST + 1, bytes([v[FIRST]])), "index"),
    ]
    vectors = [{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out]

    j = json.loads(valid_json)

    def text(o):
        return json_text(o)

    def edit(f):
        o = json.loads(valid_json)
        f(o)
        return text(o)

    jbad = [
        ("an unknown field", edit(lambda o: o.update({"extra": 1})), "field"),
        ("a missing field", edit(lambda o: o.pop("owner_nonce")), "field"),
        ("the salt in place of the nonces", edit(lambda o: (o.pop("owner_nonce"), o.pop("operator_nonce"),
                                                            o.update({"salt": "00" * 32}))), "field"),
        ("template vtxo-3", edit(lambda o: o.update({"template": "vtxo-3"})), "template_version"),
        ("template enclave-1", edit(lambda o: o.update({"template": "enclave-1"})), "template"),
        ("template landing-1 without its terms", edit(lambda o: o.update({"template": "landing-1"})), "field"),
        ("format version 1", edit(lambda o: o.update({"version": 1})), "version"),
        ("a value as a number", edit(lambda o: o.update({"value": int(j["value"])})), "type"),
        ("a value with a leading zero", edit(lambda o: o.update({"value": "0" + j["value"]})), "value"),
        ("upper-case hex", edit(lambda o: o.update({"owner_nonce": j["owner_nonce"].upper()})), "hex"),
        ("a key one byte short", edit(lambda o: o.update({"owner": j["owner"][:-2]})), "hex"),
        ("a member path on the lowest level", edit(lambda o: o["path"][-1].update({"member_index": 1})), "field"),
        ("not JSON", "{", "json"),
    ]
    return vectors, [{"name": n, "json": t, "kind": k} for n, t, k in jbad]


def invalid_htlc_vectors(valid_binary, valid_json):
    """htlc-1 records a decoder must refuse."""
    v = bytes.fromhex(valid_binary)
    DIR = 3 + 32 + 32 + 32 + 2
    OPD = DIR + 1 + 32 + 4
    EXIT = 99

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("htlc-1: direction 2", put(DIR, b"\x02"), "flag"),
        ("htlc-1: a timeout that is a height", put(DIR + 33, le32(499_999_999)), "time"),
        ("htlc-1: an operator delay of zero", put(OPD, le16(0)), "time"),
        ("htlc-1: the operator's delay as long as the exit delay", put(OPD, v[EXIT:EXIT + 2]), "htlc"),
        ("htlc-1 named vtxo-1: its terms are read as what follows the exit delay", put(1, b"\x01"), "flag"),
    ]

    def edit(f):
        o = json.loads(valid_json)
        f(o)
        return json_text(o)

    jbad = [
        ("htlc-1 without its terms", edit(lambda o: o.pop("htlc")), "field"),
        ("htlc-1 terms on a vtxo-1 record", edit(lambda o: o.update({"template": "vtxo-1"})), "field"),
        ("htlc-1: direction sideways", edit(lambda o: o["htlc"].update({"direction": "sideways"})), "type"),
        ("htlc-1: an unknown field in its terms", edit(lambda o: o["htlc"].update({"extra": 1})), "field"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def invalid_landing_vectors(valid_binary, valid_json):
    """landing-1 records a decoder must refuse."""
    v = bytes.fromhex(valid_binary)
    PROG = 3 + 32 + 32 + 32 + 2
    ALLOW = PROG + 20
    VALUE = ALLOW + 8 + 32
    value = struct.unpack("<Q", v[VALUE:VALUE + 8])[0]

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("landing-1: an allowance as large as the value", put(ALLOW, le64(value)), "landing"),
        ("landing-1: an allowance above the value", put(ALLOW, le64(value + 1)), "landing"),
        ("landing-1, version 2", put(2, b"\x02"), "template_version"),
    ]

    def edit(f):
        o = json.loads(valid_json)
        f(o)
        return json_text(o)

    jbad = [
        ("landing-1 without its terms", edit(lambda o: o.pop("landing")), "field"),
        ("landing-1 terms on a vtxo-1 record", edit(lambda o: o.update({"template": "vtxo-1"})), "field"),
        ("landing-1: a program one byte short", edit(lambda o: o["landing"].update({"program": o["landing"]["program"][:-2]})),
         "hex"),
        ("landing-1: an allowance as a number", edit(lambda o: o["landing"].update({"allowance": 2000})), "type"),
        ("landing-1: an allowance as large as the value", edit(lambda o: o["landing"].update({"allowance": o["value"]})),
         "landing"),
        ("landing-1: an unknown field in its terms", edit(lambda o: o["landing"].update({"extra": 1})), "field"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def invalid_claim_vectors(valid_binary, valid_json):
    """claim-1 records a decoder must refuse."""
    v = bytes.fromhex(valid_binary)
    DEADLINE = 3 + 32 + 32 + 32 + 2
    ALLOW = DEADLINE + 4
    LEN = ALLOW + 8
    n = struct.unpack("<H", v[LEN:LEN + 2])[0]
    VALUE = LEN + 2 + n + 32
    value = struct.unpack("<Q", v[VALUE:VALUE + 8])[0]

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("claim-1: an allowance as large as the value", put(ALLOW, le64(value)), "claim"),
        ("claim-1: a deadline that is a height", put(DEADLINE, le32(499_999_999)), "time"),
        ("claim-1: an empty return script", v[:LEN] + le16(0) + v[LEN + 2 + n:], "claim"),
        ("claim-1, version 2", put(2, b"\x02"), "template_version"),
    ]

    def edit(f):
        o = json.loads(valid_json)
        f(o)
        return json_text(o)

    jbad = [
        ("claim-1 without its terms", edit(lambda o: o.pop("claim")), "field"),
        ("claim-1 terms on a vtxo-1 record", edit(lambda o: o.update({"template": "vtxo-1"})), "field"),
        ("claim-1: an allowance as a number", edit(lambda o: o["claim"].update({"allowance": 1500})), "type"),
        ("claim-1: an allowance above the value", edit(lambda o: o["claim"].update({"allowance": str(int(o["value"]) + 1)})),
         "claim"),
        ("claim-1: a return script of odd hex", edit(lambda o: o["claim"].update({"return_script": o["claim"]["return_script"][:-1]})),
         "hex"),
        ("claim-1: an unknown field in its terms", edit(lambda o: o["claim"].update({"extra": 1})), "field"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def invalid_channel_vectors(valid_binary, valid_json):
    """channel-1 records a decoder must refuse."""
    v = bytes.fromhex(valid_binary)
    CAP = 3 + 32 + 32 + 32 + 2
    WINDOW = CAP + 8
    VALUE = WINDOW + 2 + 32
    value = struct.unpack("<Q", v[VALUE:VALUE + 8])[0]

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("channel-1: a capacity as large as the value", put(CAP, le64(value)), "channel"),
        ("channel-1: a window one unit shorter than the exit delay", put(WINDOW, le16(EXIT_DELAY - 1)), "channel"),
        ("channel-1, version 2", put(2, b"\x02"), "template_version"),
    ]

    def edit(f):
        o = json.loads(valid_json)
        f(o)
        return json_text(o)

    jbad = [
        ("channel-1 without its terms", edit(lambda o: o.pop("channel")), "field"),
        ("channel-1 terms on a vtxo-1 record", edit(lambda o: o.update({"template": "vtxo-1"})), "field"),
        ("channel-1: a capacity as a number", edit(lambda o: o["channel"].update({"capacity": 1000})), "type"),
        ("channel-1: a capacity as large as the value", edit(lambda o: o["channel"].update({"capacity": o["value"]})),
         "channel"),
        ("channel-1: an unknown field in its terms", edit(lambda o: o["channel"].update({"extra": 1})), "field"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def invalid_no_sweep_vectors(valid_binary, valid_json, swept_json):
    """Records of a batch without a sweep a decoder must refuse, and a version
    2 record naming the no-sweep token."""
    v = bytes.fromhex(valid_binary)
    FLAGS = 3 + 32 + 32 + 32 + 2 + 32 + 8 + 32 + 8 + 64

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [
        ("without a sweep, the burn-only flag set", put(FLAGS, bytes([v[FLAGS] | 1])), "flag"),
        ("without a sweep, flag bit 2 set", put(FLAGS, bytes([v[FLAGS] | 4])), "flag"),
        ("without a sweep, read as version 2", put(0, b"\x02"), "flag"),
    ]

    def edit(f, text=valid_json):
        o = json.loads(text)
        f(o)
        return json_text(o)

    jbad = [
        ("without a sweep, with a token", edit(lambda o: o.update({"token": display(NO_SWEEP_TOKEN)})), "field"),
        ("without a sweep, with expiries", edit(lambda o: o.update({"expiries": [CREATED]})), "field"),
        ("without a sweep, burn-only", edit(lambda o: o.update({"burn": False})), "field"),
        ("the no-sweep token in a version 2 record", edit(lambda o: o.update({"token": display(NO_SWEEP_TOKEN)}), swept_json),
         "sweep"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def invalid_order_vectors(valid_binary, valid_json, order_2_json):
    """order-3 records a decoder must refuse, and an order-2 record claiming order-3's terms."""
    v = bytes.fromhex(valid_binary)

    def put(off, b):
        return v[:off] + b + v[off + len(b):]

    out = [("order, version 4", put(2, b"\x04"), "template_version")]

    def edit(f, text=valid_json):
        o = json.loads(text)
        f(o)
        return json_text(o)

    jbad = [
        ("order-3 terms without their version", edit(lambda o: o["order"].pop("version")), "template"),
        ("order-2 terms that name version 3", edit(lambda o: o["order"].update({"version": 3}), order_2_json), "template"),
        ("order terms naming version 2", edit(lambda o: o["order"].update({"version": 2})), "type"),
        ("order-4", edit(lambda o: o.update({"template": "order-4"})), "template_version"),
    ]
    return ([{"name": n, "binary": b.hex(), "kind": k} for n, b, k in out],
            [{"name": n, "json": t, "kind": k} for n, t, k in jbad])


def generate():
    batches = [
        batch_vector("one leaf", 1, 4),
        batch_vector("five leaves", 5, 4),
        batch_vector("sixteen leaves", 16, 4, odd_delay=NOTICE * 2),
        batch_vector("seventeen leaves, issuer-operated", 17, 4, burn=True, node_reserve=3_100, entry_reserve=900),
        batch_vector("ten leaves at radix 3", 10, 3, expiries=(28,)),
        batch_vector("seven leaves at radix 6", 7, 6, node_reserve=0, entry_reserve=0),
        batch_vector("sixty-four leaves", 64, 4, export=[0, 5, 21, 42, 63]),
        batch_vector("five leaves, two of them htlc-1", 5, 4, htlc={1: "receive", 3: "send"}),
        batch_vector("five leaves, two of them order-2", 5, 4, order=[0, 3]),
        batch_vector("five leaves, two of them order-3", 5, 4, order=[1, 4], order_version=3),
        batch_vector("five leaves of a supervised asset, every one landing-1", 5, 4, landing=[0, 1, 2, 3, 4]),
        batch_vector("five leaves, two of them channel-1", 5, 4, channel={1: 4_000_000, 4: 0}),
        batch_vector("five leaves, two of them vtxo-2", 5, 4, v2=[1, 2]),
        batch_vector("seventeen leaves, RECLAIM-D on every lowest node", 17, 4, delegated=True),
        batch_vector("seventeen leaves without a sweep, RECLAIM-D on every lowest node", 17, 4, delegated=True,
                     no_sweep=True),
        batch_vector("five leaves without a sweep, two of them vtxo-2", 5, 4, v2=[1, 2], no_sweep=True),
        batch_vector("five leaves without a sweep, two of them claim-1", 5, 4, claim=[1, 3], no_sweep=True),
        batch_vector("five leaves, two of them claim-1", 5, 4, claim=[0, 4]),
    ]
    first = batches[2]["records"][5]
    invalid, invalid_json = invalid_vectors(first["binary"], first["json"])
    h = batches[7]["records"][1]
    hi, hj = invalid_htlc_vectors(h["binary"], h["json"])
    invalid += hi
    invalid_json += hj
    o3, o2 = batches[9]["records"][1], batches[8]["records"][0]
    oi, oj = invalid_order_vectors(o3["binary"], o3["json"], o2["json"])
    invalid += oi
    invalid_json += oj
    g = batches[10]["records"][2]
    gi, gj = invalid_landing_vectors(g["binary"], g["json"])
    invalid += gi
    invalid_json += gj
    c = batches[11]["records"][1]
    ci, cj = invalid_channel_vectors(c["binary"], c["json"])
    invalid += ci
    invalid_json += cj
    ns = batches[14]["records"][3]
    ni, nj = invalid_no_sweep_vectors(ns["binary"], ns["json"], first["json"])
    invalid += ni
    invalid_json += nj
    q = batches[16]["records"][1]
    qi, qj = invalid_claim_vectors(q["binary"], q["json"])
    invalid += qi
    invalid_json += qj
    return {
        "about": "Golden vectors for Arca's leaf record, its id and its encodings. Generated by "
                 "regtest/vectors.py from regtest/records.py; do not edit.",
        "conventions": {
            "format": "regtest/records.py states the binary layout, the leaf id and the JSON form.",
            "byte_order": "In the binary form, asset ids, the token and the genesis hash are in internal byte "
                          "order. In the JSON form and in this file's own fields they are in display order (as "
                          "RPCs print them), except where noted.",
            "keys": "x-only test keys: secret = SHA256(\"Arca test vector key/\" + label) mod n. They hold nothing.",
            "round": "The round issues one explicit atom of the token from its first input (contract hash zero), "
                     "pays the batch output at 0 and the atom to clock 0 at 1.",
        },
        "inputs": {
            "genesis_hash": display(GENESIS), "asset": display(ASSET), "operator": OPERATOR.hex(),
            "leaf_id_tag": LEAF_ID_TAG.decode(),
        },
        "batches": batches,
        "invalid_binary": invalid,
        "invalid_json": invalid_json,
    }
