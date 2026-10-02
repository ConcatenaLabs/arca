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
SHA256("Arca/salt" || owner_nonce || operator_nonce). The record carries both
nonces and not the salt, which is rebuilt from them.

The record, format version 2
----------------------------
All integers are little-endian. Asset ids and the genesis hash are in internal
byte order.

    u8    format version, 2
    u8    template, 1 (vtxo)          u8  template version, 1
    [32]  owner key A                 the vtxo-1 parameters
    [32]  owner nonce
    [32]  operator nonce
    u16   exit delay, 512-second units
    [32]  asset                       the leaf and its entry
    u64   value
    [32]  unlock hash h
    u64   entry reserve
    [32]  genesis hash                the batch
    [32]  operator key S
    [32]  token T
    u16   notice W, 512-second units
    u8    flags: bit 0, the sweeps are burn-only; other bits zero
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

The leaf id is the BIP340 tagged hash, tag "Arca/leaf-id", of

    batch output's witness program (32) ‖ level count (u8)
    ‖ each level's child index (u8), from the batch output down
    ‖ the leaf's witness program (32)

The JSON form has the same fields; its canonical text has its keys sorted and
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
TEMPLATES = {"vtxo": 1}                    # name -> template id
TEMPLATE_VTXO, TEMPLATE_VTXO_VERSION = 1, 1
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

def reclaim_script(release, owners, s_x):
    """RECLAIM for one owner or more."""
    if len(owners) == 1:
        return CScript([release, owners[0], OP_CHECKSIGFROMSTACKVERIFY, s_x, OP_CHECKSIG])
    return reclaim_leaf(release, owners, s_x)


class Batch:
    """A batch built by the rules above.

    p: genesis (internal), asset (internal), operator (x-only), token
    (internal), notice (units), expiries, burn, radix, node_reserve,
    entry_reserve. leaves: [{owner, owner_nonce, operator_nonce, value,
    exit_delay, unlock_hash}]."""

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
            w = None if root else notice
            return burn_sweep(p["token"], r_prog, S, w) if p["burn"] else sweep_token(p["token"], r_prog, S, w)

        ctag = chain_tag(p["genesis"])
        self.leaf_taps, self.entries = [], []
        level = []
        for i, lf in enumerate(leaves):
            salt = leaf_salt(lf["owner_nonce"], lf["operator_nonce"])
            tap, _ = leaf3_taptree(lf["owner"], S, salt, ctag, SEQ_TIME | lf["exit_delay"], fold=True)
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
                    reclaim = reclaim_script(release_msg(p["genesis"], tuples), [leaves[o]["owner"] for o in owners], S)
                tap, _ = node_taptree3(unroll, sweep(is_root), reclaim)
                nodes.append({"tap": tap, "prog": bytes(tap.scriptPubKey)[2:], "kids": kids, "owners": owners,
                              "first": kids[0]["first"], "mlevels": mlevels, "lo": lo, "hi": hi,
                              "value": sum(k["value"] for k in kids) + p["node_reserve"]})
            self.levels.append(nodes)
            level, lowest = nodes, False
            if is_root:
                break
        self.root = self.levels[-1][0]
        self.clocks = clock_chain(p["token"], self.r_spk, S, p["expiries"])

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
        return {
            "template": ("vtxo", TEMPLATE_VTXO_VERSION),
            "owner": lf["owner"], "owner_nonce": lf["owner_nonce"], "operator_nonce": lf["operator_nonce"],
            "exit_delay": lf["exit_delay"],
            "asset": p["asset"], "value": lf["value"], "unlock_hash": lf["unlock_hash"],
            "entry_reserve": p["entry_reserve"],
            "genesis": p["genesis"], "operator": p["operator"], "token": p["token"], "notice": p["notice"],
            "burn": p["burn"], "expiries": list(p["expiries"]),
            "path": levels,
        }


# --------------------------------------------------------------------------
# Encodings and the id
# --------------------------------------------------------------------------

def encode(rec):
    name, ver = rec["template"]
    b = bytes([FORMAT_VERSION, TEMPLATES[name], ver])
    b += rec["owner"] + rec["owner_nonce"] + rec["operator_nonce"] + le16(rec["exit_delay"])
    b += rec["asset"] + le64(rec["value"]) + rec["unlock_hash"] + le64(rec["entry_reserve"])
    b += rec["genesis"] + rec["operator"] + rec["token"] + le16(rec["notice"])
    b += bytes([1 if rec["burn"] else 0])
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
    return {
        "version": FORMAT_VERSION, "template": "%s-%d" % (name, ver),
        "owner": rec["owner"].hex(), "owner_nonce": rec["owner_nonce"].hex(),
        "operator_nonce": rec["operator_nonce"].hex(), "exit_delay_units": rec["exit_delay"],
        "asset": display(rec["asset"]), "value": str(rec["value"]), "unlock_hash": rec["unlock_hash"].hex(),
        "entry_reserve": str(rec["entry_reserve"]),
        "genesis_hash": display(rec["genesis"]), "operator": rec["operator"].hex(), "token": display(rec["token"]),
        "notice_units": rec["notice"], "burn": rec["burn"], "expiries": rec["expiries"],
        "path": path,
    }


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
                 expiries=(28, 56, 84), odd_delay=None):
    """One batch: its inputs, the round that funds it, and the records of the
    leaves in `export` (all when None)."""
    issuer_txid = label_hash("outpoint", "%s round issuer" % name)
    token = issued_asset(issuer_txid, 0)
    p = {"genesis": GENESIS, "asset": ASSET, "operator": OPERATOR, "token": token, "notice": NOTICE,
         "expiries": [CREATED + d * DAY for d in expiries], "burn": burn, "radix": radix,
         "node_reserve": node_reserve, "entry_reserve": entry_reserve}
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
            "token_issuer": {"txid": display(issuer_txid), "vout": 0, "contract_hash": bytes(32).hex()},
            "token": display(token), "notice_units": NOTICE, "expiries": p["expiries"],
            "leaves": [{"owner": lf["owner"].hex(), "owner_nonce": lf["owner_nonce"].hex(),
                        "operator_nonce": lf["operator_nonce"].hex(), "value": lf["value"],
                        "exit_delay_units": lf["exit_delay"], "unlock_hash": lf["unlock_hash"].hex()}
                       for lf in leaves],
        },
        "levels": [len(lv) for lv in b.levels],
        "children": [[nd["hi"] - nd["lo"] for nd in lv] for lv in b.levels],
        "batch_output": {"asset": display(ASSET), "value": b.root["value"],
                         "script_pubkey": b.batch_spk().hex()},
        "clock0_script_pubkey": b.clocks[0]["spk"].hex(),
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
        ("format version 3", v[:0] + b"\x03" + v[1:], "version"),
        ("template 2", put(1, b"\x02"), "template"),
        ("template vtxo, version 2", put(2, b"\x02"), "template_version"),
        ("a trailing byte", v + b"\x00", "trailing"),
        ("the last byte missing", v[:-1], "end"),
        ("empty", b"", "end"),
        ("owner key not on the curve", put(OWNER, bytes(32)), "key"),
        ("an exit delay of zero", put(EXIT, le16(0)), "time"),
        ("a value of zero", put(VALUE, le64(0)), "value"),
        ("a value above the largest money range", put(VALUE, le64(400_000_000 * 100_000_000 + 1)), "value"),
        ("a notice of zero", put(NOTICE_AT, le16(0)), "time"),
        ("flag bit 1 set", put(FLAGS, b"\x02"), "flag"),
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
        ("template vtxo-2", edit(lambda o: o.update({"template": "vtxo-2"})), "template_version"),
        ("template landing-1", edit(lambda o: o.update({"template": "landing-1"})), "template"),
        ("format version 1", edit(lambda o: o.update({"version": 1})), "version"),
        ("a value as a number", edit(lambda o: o.update({"value": int(j["value"])})), "type"),
        ("a value with a leading zero", edit(lambda o: o.update({"value": "0" + j["value"]})), "value"),
        ("upper-case hex", edit(lambda o: o.update({"owner_nonce": j["owner_nonce"].upper()})), "hex"),
        ("a key one byte short", edit(lambda o: o.update({"owner": j["owner"][:-2]})), "hex"),
        ("a member path on the lowest level", edit(lambda o: o["path"][-1].update({"member_index": 1})), "field"),
        ("not JSON", "{", "json"),
    ]
    return vectors, [{"name": n, "json": t, "kind": k} for n, t, k in jbad]


def generate():
    batches = [
        batch_vector("one leaf", 1, 4),
        batch_vector("five leaves", 5, 4),
        batch_vector("sixteen leaves", 16, 4, odd_delay=NOTICE * 2),
        batch_vector("seventeen leaves, issuer-operated", 17, 4, burn=True, node_reserve=3_100, entry_reserve=900),
        batch_vector("ten leaves at radix 3", 10, 3, expiries=(28,)),
        batch_vector("seven leaves at radix 6", 7, 6, node_reserve=0, entry_reserve=0),
        batch_vector("sixty-four leaves", 64, 4, export=[0, 5, 21, 42, 63]),
    ]
    first = batches[2]["records"][5]
    invalid, invalid_json = invalid_vectors(first["binary"], first["json"])
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
