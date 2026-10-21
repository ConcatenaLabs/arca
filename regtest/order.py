#!/usr/bin/env python3
"""Golden vectors for the `order-2` leaf: a resting order in the tree.

vectors.py writes them to vectors/order.json and checks them in CI. Everything
here is derived independently of the Rust crate: the collaborative script from
this suite's own builder (arklib3.collab3_loop, folded), the landing script
from CScript, and the taproot tree, which mixes tapscript leaves, a Simplicity
leaf and a hidden data leaf that the functional test framework's
taproot_construct cannot express, from the tagged hashes themselves.

    root = TapBranch( TapBranch(collab, land), TapBranch(fill, data) )

The fill leaf is the Simplicity program arca/order-2, named by its commitment
root; the landed order is seqdex/order, named by its own. Both roots come from
sequentia-contracts (templates/arca_order/fills.json and
templates/seqdex_order/fills.json).
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.key import TaggedHash, tweak_add_pubkey
from test_framework.script import OP_GREATERTHANOREQUAL64, OP_INSPECTOUTPUTNONCE

ORDER_CMR = bytes.fromhex("fac4e5ebe8c377159c28f5fc74e6c492132983859d500081e46c727641b9e164")
SEQDEX_CMR = bytes.fromhex("f9b42b838b6295f4f376760fbb02eed9cb20f872f07ee4b9df7273d26822ee44")
LEAF_TAPSCRIPT = 0xc4
LEAF_SIMPLICITY = 0xbe


def compact(n):
    assert n < 0xfd
    return bytes([n])


def tapleaf(version, script):
    return TaggedHash("TapLeaf/elements", bytes([version]) + compact(len(script)) + script)


def tapbranch(a, b):
    return TaggedHash("TapBranch/elements", min(a, b) + max(a, b))


def tapdata(b):
    return TaggedHash("TapData", b)


def output_of(root):
    """(output key, odd) of the NUMS internal key and root."""
    return tweak_add_pubkey(NUMS, TaggedHash("TapTweak/elements", NUMS + root))


def spk_of(root):
    return b"\x51\x20" + output_of(root)[0]


def control_block(version, root, path):
    return bytes([version | (1 if output_of(root)[1] else 0)]) + NUMS + b"".join(path)


def be8(n):
    return n.to_bytes(8, "big")


def seqdex_data(t):
    """seqdex/order's 156-byte data leaf."""
    return (t["asset_a"] + t["asset_b"] + be8(t["num"]) + be8(t["den"]) + be8(t["min_lot"]) + t["maker"]
            + t["expiry"].to_bytes(4, "big") + t["refund_key"])


def seqdex_root(t):
    return tapbranch(tapleaf(LEAF_SIMPLICITY, SEQDEX_CMR), tapdata(seqdex_data(t)))


def landing_script(t, delay):
    landed = output_of(seqdex_root(t))[0]
    return CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                    0, OP_INSPECTOUTPUTSCRIPTPUBKEY, 1, OP_EQUALVERIFY, landed, OP_EQUALVERIFY,
                    0, OP_INSPECTOUTPUTASSET, 1, OP_EQUALVERIFY, t["asset_a"], OP_EQUALVERIFY,
                    0, OP_INSPECTOUTPUTNONCE, 0, OP_EQUALVERIFY,
                    0, OP_INSPECTOUTPUTVALUE, 1, OP_EQUALVERIFY,
                    OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE, 1, OP_EQUALVERIFY, OP_GREATERTHANOREQUAL64])


def order_data(t, owner, operator, salt, delay, land_leaf, credits):
    units = delay & 0xffff
    return (t["asset_a"] + t["asset_b"] + be8(t["num"]) + be8(t["den"]) + be8(t["min_lot"]) + owner + operator + salt
            + units.to_bytes(2, "big") + land_leaf + b"".join(credits))


class Order:
    def __init__(self, t, owner, operator, salt, ctag, delay, credits):
        self.t, self.owner, self.operator, self.salt, self.ctag, self.delay = t, owner, operator, salt, ctag, delay
        self.credits = list(credits)
        self.collab = collab3_loop(owner, operator, salt, ctag, fold=True)
        self.land = landing_script(t, delay)
        self.land_leaf = tapleaf(LEAF_TAPSCRIPT, bytes(self.land))
        self.collab_leaf = tapleaf(LEAF_TAPSCRIPT, bytes(self.collab))
        self.data = order_data(t, owner, operator, salt, delay, self.land_leaf, self.credits)
        self.data_leaf = tapdata(self.data)
        self.fill_leaf = tapleaf(LEAF_SIMPLICITY, ORDER_CMR)
        self.left = tapbranch(self.collab_leaf, self.land_leaf)
        self.right = tapbranch(self.fill_leaf, self.data_leaf)
        self.root = tapbranch(self.left, self.right)
        self.spk = spk_of(self.root)

    def next(self):
        return Order(self.t, self.owner, self.operator, sha256(sha256(b"Arca/order-rest") + self.salt), self.ctag, self.delay,
                     self.credits[1:] + [bytes(32)])

    def credit(self):
        """The vtxo-1 leaf a fill of this coin pays its credit to."""
        salt = sha256(sha256(b"Arca/order-credit") + self.salt)
        tap, _ = leaf3_taptree(self.credits[0], self.operator, salt, self.ctag, self.delay, fold=True)
        return salt, tap

    def json(self):
        return {
            "params": self.data.hex(), "data_leaf": self.data_leaf.hex(),
            "collab": self.collab.hex(), "landing": bytes(self.land).hex(), "land_leaf": self.land_leaf.hex(),
            "merkle_root": self.root.hex(), "script_pubkey": self.spk.hex(),
            "control_blocks": {
                "collab": control_block(LEAF_TAPSCRIPT, self.root, [self.land_leaf, self.right]).hex(),
                "land": control_block(LEAF_TAPSCRIPT, self.root, [self.collab_leaf, self.right]).hex(),
                "fill": control_block(LEAF_SIMPLICITY, self.root, [self.data_leaf, self.left]).hex(),
            },
        }


def output_hash(asset, value, spk):
    """Simplicity's output_hash of an explicit output with no nonce."""
    return sha256(b"\x01" + asset + b"\x01" + be8(value) + b"\x00" + sha256(spk) + sha256(b""))


def fill_digest(genesis, salt, asset, value_in, outs):
    acc = sha256(sha256(b"Arca/order-fill") + genesis) + salt + asset + be8(value_in) + bytes([len(outs)])
    for a, v, spk in outs:
        acc += output_hash(a, v, spk)
    return sha256(acc)


def generate(genesis, keys, label_hash, delay):
    """The vectors: an order, its remainder after one fill, the credit that
    fill pays, the landed order, and the operator's fill digest."""
    x, y = label_hash("asset", "X"), label_hash("asset", "Y")
    terms = {"asset_a": x, "asset_b": y, "num": 3, "den": 2, "min_lot": 1_000,
             "maker": sha256(b"\x51\x20" + keys["refund"].x), "expiry": 1_800_000_000, "refund_key": keys["refund"].x}
    ctag = chain_tag(genesis)
    o = Order(terms, keys["maker"].x, keys["S"].x, label_hash("salt", "order"), ctag, delay,
              [keys["credit%d" % i].x for i in range(4)])
    n = o.next()
    csalt, ctap = o.credit()
    locked, filled = 10_000_000, 4_000_000
    price = (filled * 3 + 1) // 2
    outs = [(y, price, ctap.scriptPubKey), (x, locked - filled, n.spk),
            (x, filled, b"\x51\x20" + keys["taker"].x), (y, 1_000, b"\x51\x20" + keys["taker"].x)]
    digest = fill_digest(genesis, o.salt, x, locked, outs)
    return {
        "genesis": genesis.hex(),
        "keys": {k: v.x.hex() for k, v in keys.items()},
        "terms": {"asset_a": x.hex(), "asset_b": y.hex(), "rate_num": 3, "rate_den": 2, "min_lot": 1_000,
                  "maker": terms["maker"].hex(), "expiry": 1_800_000_000},
        "exit_delay_sequence": delay,
        "salt": o.salt.hex(),
        "landed": {"params": seqdex_data(terms).hex(), "script_pubkey": spk_of(seqdex_root(terms)).hex()},
        "order": o.json(),
        "remainder": dict(n.json(), salt=n.salt.hex()),
        "credit": {"salt": csalt.hex(), "script_pubkey": ctap.scriptPubKey.hex()},
        "fill": {"locked": locked, "filled": filled, "outputs": [{"asset": a.hex(), "value": v, "script_pubkey": s.hex()}
                                                                 for a, v, s in outs],
                 "digest": digest.hex(), "operator_signature": keys["S"].sign(digest).hex()},
    }
