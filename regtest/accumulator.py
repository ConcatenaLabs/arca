#!/usr/bin/env python3
"""Golden vectors for the accumulator batch, `arca/accumulator-1`.

vectors.py writes them to vectors/accumulator.json and checks them in CI.
Everything here is derived independently of the Rust crate, from the
specification's sentences:

- The batch output is P2TR(NUMS, TapBranch(TapBranch(X, D), SWEEP)): X the
  Simplicity leaf of the program's commitment root, D the hidden data leaf
  H_TapData(ROOT || OPERATOR || BITMAP), SWEEP the token-gated sweep of a
  batch output, with no notice.
- rec_j = SHA256(0x00 || j || OWNER || SPK || VALUE || RESERVE), weight
  VALUE + RESERVE; an inner node is SHA256(0x01 || h_l || w_l || h_r || w_r),
  weight w_l + w_r; an empty slot is 32 zero bytes of weight 0; the tree has
  depth 10, and slot j's path turns by j's bits, the lowest first. j is two
  bytes, weights and amounts eight, all big-endian.
- BITMAP is 16 big-endian words; slot j's bit is bit 63 - j mod 64 of word
  j / 64.
- An exit's authorisation is a BIP340 signature over
  SHA256(SHA256("Arca/accumulator-exit") || genesis || ROOT || rec_j || t),
  t four bytes big-endian.
- The exit's witness value is ROOT, OPERATOR, BITMAP, j, OWNER, SPK, VALUE,
  RESERVE, each sibling and its weight, t, then the operator's flag as one bit
  and the signature, padded to a whole byte.
- A leaf's record (version 1) is a tree leaf record's fields up to the clock,
  little-endian, then the slot (u16), the reserve of its exit (u64) and its
  ten siblings with their weights (32 bytes and a u64 each); its coin record
  (tag 6) is the record's length (u16) and bytes, the entry's preimage, the
  owner's exit signature and its time (u32). Its leaf id is the tagged hash
  "Arca/leaf-id" of the batch output's program, the byte 2, the slot
  big-endian and the leaf's program.

The leaves sit behind the entries a tree's lowest node would pay
(records.Batch builds them), each slot's record naming its entry.
"""
from arklib3 import *                      # noqa: F401,F403
from order import be8, control_block, spk_of, tapbranch, tapdata, tapleaf, LEAF_SIMPLICITY, LEAF_TAPSCRIPT

ACC_CMR = bytes.fromhex("a85d27ba922892647b3fe4435fa05e4197d1c6096a14f9f665a92574b0d2a874")
EXIT_TAG = b"Arca/accumulator-exit"
DEPTH = 10
SLOTS = 1 << DEPTH


def record(j, owner, spk_hash, value, reserve):
    return sha256(b"\x00" + j.to_bytes(2, "big") + owner + spk_hash + be8(value) + be8(reserve))


def inner(left, right):
    return sha256(b"\x01" + left[0] + be8(left[1]) + right[0] + be8(right[1]))


class SlotTree:
    def __init__(self, slots):
        level = list(slots) + [(bytes(32), 0)] * (SLOTS - len(slots))
        self.levels = [level]
        for _ in range(DEPTH):
            level = [(inner(level[i], level[i + 1]), level[i][1] + level[i + 1][1]) for i in range(0, len(level), 2)]
            self.levels.append(level)

    def root(self):
        return self.levels[DEPTH][0]

    def path(self, j):
        return [self.levels[d][(j >> d) ^ 1] for d in range(DEPTH)]


def bitmap_with(words, j):
    w = list(words)
    w[j // 64] |= 1 << (63 - j % 64)
    return w


class State:
    def __init__(self, root, operator, words, sweep):
        self.root, self.operator, self.words, self.sweep = root, operator, words, sweep

    def data(self):
        return self.root + self.operator + b"".join(w.to_bytes(8, "big") for w in self.words)

    def tree(self):
        return tapbranch(tapbranch(tapleaf(LEAF_SIMPLICITY, ACC_CMR), tapdata(self.data())),
                         tapleaf(LEAF_TAPSCRIPT, bytes(self.sweep)))

    def spk(self):
        return spk_of(self.tree())

    def control_block(self):
        return control_block(LEAF_SIMPLICITY, self.tree(), [tapdata(self.data()), tapleaf(LEAF_TAPSCRIPT, bytes(self.sweep))])

    def after(self, j):
        return State(self.root, self.operator, bitmap_with(self.words, j), self.sweep)


def exit_digest(genesis, root, rec, t):
    return sha256(sha256(EXIT_TAG) + genesis + root + rec + t.to_bytes(4, "big"))


def exit_witness(state, j, slot, path, t, by_operator, sig):
    b = state.data() + j.to_bytes(2, "big") + slot["owner"] + slot["spk_hash"] + be8(slot["value"]) + be8(slot["reserve"])
    for h, w in path:
        b += h + be8(w)
    b += t.to_bytes(4, "big")
    bits = "".join(format(x, "08b") for x in b) + ("1" if by_operator else "0") + "".join(format(x, "08b") for x in sig)
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


RECORD_VERSION = 1
COIN_RECORD_VERSION = 1
COIN_TAG = 6


def encode_record(p, lf, slot, exit_reserve, path):
    """A vtxo-1 leaf's record in an accumulator batch."""
    import records as R
    b = bytes([RECORD_VERSION, R.TEMPLATES["vtxo"], 1])
    b += lf["owner"] + lf["owner_nonce"] + lf["operator_nonce"] + R.le16(lf["exit_delay"])
    b += p["asset"] + R.le64(lf["value"]) + lf["unlock_hash"] + R.le64(p["entry_reserve"])
    b += p["genesis"] + p["operator"] + p["token"] + R.le16(p["notice"]) + bytes([1 if p["burn"] else 0])
    b += bytes([len(p["expiries"])]) + b"".join(R.le32(e) for e in p["expiries"])
    b += R.le16(slot) + R.le64(exit_reserve)
    for h, w in path:
        b += h + R.le64(w)
    return b


def encode_coin(rec, preimage, sig, t):
    import records as R
    return bytes([COIN_RECORD_VERSION, COIN_TAG]) + R.le16(len(rec)) + rec + preimage + sig + R.le32(t)


def generate(genesis, keys):
    """A batch of six leaves behind their entries, its state and output, and
    two exits: one by an owner, then one by the operator from the state the
    first leaves."""
    import records
    p = {"genesis": genesis, "asset": records.ASSET, "operator": keys["S"].x,
         "token": records.issued_asset(records.label_hash("outpoint", "accumulator round issuer"), 0),
         "notice": records.NOTICE, "expiries": [records.CREATED + d * records.DAY for d in (28, 56)], "burn": False,
         "radix": 4, "node_reserve": 0, "entry_reserve": 1_000}
    leaves = []
    for i in range(6):
        leaves.append({
            "owner": keys["owner%d" % i].x,
            "owner_nonce": records.label_hash("owner nonce", "accumulator leaf %d" % i),
            "operator_nonce": records.label_hash("operator nonce", "accumulator leaf %d" % i),
            "value": 10_000_000 + 1_000 * i,
            "exit_delay": records.EXIT_DELAY,
            "unlock_hash": sha256(records.label_hash("preimage", "accumulator entry %d" % i)),
        })
    b = records.Batch(p, leaves)
    exit_reserve = 2_500
    slots = []
    for i, lf in enumerate(leaves):
        spk = bytes(b.entries[i]["tap"].scriptPubKey)
        slots.append({"owner": lf["owner"], "spk": spk, "spk_hash": sha256(spk), "value": b.entries[i]["value"],
                      "reserve": exit_reserve})
    recs = [(record(j, s["owner"], s["spk_hash"], s["value"], s["reserve"]), s["value"] + s["reserve"])
            for j, s in enumerate(slots)]
    tree = SlotTree(recs)
    root, total = tree.root()
    r_tap, _ = r_taptree(p["operator"], SEQ_TIME | p["notice"])
    sweep = sweep_token(p["token"], bytes(r_tap.scriptPubKey)[2:], p["operator"], None)
    s0 = State(root, p["operator"], [0] * 16, sweep)

    def exit_vector(state, j, key, by_operator, t):
        rec = recs[j][0]
        digest = exit_digest(genesis, root, rec, t)
        sig = key.sign(digest)
        nxt = state.after(j)
        return {"slot": j, "by_operator": by_operator, "time": t, "record": rec.hex(), "weight": recs[j][1],
                "path": [{"hash": h.hex(), "weight": w} for h, w in tree.path(j)],
                "digest": digest.hex(), "signature": sig.hex(),
                "witness": exit_witness(state, j, slots[j], tree.path(j), t, by_operator, sig).hex(),
                "next_bitmap": b"".join(w.to_bytes(8, "big") for w in nxt.words).hex(),
                "next_script_pubkey": nxt.spk().hex()}, nxt

    t = records.CREATED + records.DAY
    e1, s1 = exit_vector(s0, 3, keys["owner3"], False, t)
    e2, _ = exit_vector(s1, 0, keys["S"], True, t + 600)

    # Each leaf's record, its coin record (the owner's exit authorisation at
    # t) and its leaf id; and records a reader must refuse.
    batch_prog = s0.spk()[2:]
    held = []
    for j, lf in enumerate(leaves):
        rec = encode_record(p, lf, j, exit_reserve, tree.path(j))
        pre = records.label_hash("preimage", "accumulator entry %d" % j)
        sig = keys["owner%d" % j].sign(exit_digest(genesis, root, recs[j][0], t))
        lprog = bytes(b.leaf_taps[j].scriptPubKey)[2:]
        held.append({"slot": j, "preimage": pre.hex(), "auth_time": t, "auth_signature": sig.hex(),
                     "leaf_program": lprog.hex(),
                     "leaf_id": records.tagged_hash(records.LEAF_ID_TAG, batch_prog + bytes([2]) + j.to_bytes(2, "big") + lprog).hex(),
                     "record": rec.hex(), "coin": encode_coin(rec, pre, sig, t).hex()})
    good = bytes.fromhex(held[0]["record"])
    refuse = [
        {"why": "version 2", "record": (bytes([2]) + good[1:]).hex()},
        {"why": "a byte past the end", "record": (good + b"\x00").hex()},
        {"why": "slot 1,024", "record": (good[:-(2 + 8 + 400)] + records.le16(1024) + good[-(8 + 400):]).hex()},
        {"why": "template 7", "record": (good[:1] + bytes([7]) + good[2:]).hex()},
        {"why": "one sibling short", "record": good[:-40].hex()},
    ]
    return {
        "genesis": genesis.hex(),
        "cmr": ACC_CMR.hex(),
        "asset": p["asset"].hex(),
        "operator": p["operator"].hex(),
        "token": p["token"].hex(),
        "notice_units": p["notice"],
        "expiries": p["expiries"],
        "entry_reserve": p["entry_reserve"],
        "exit_reserve": exit_reserve,
        "leaves": [{"owner": lf["owner"].hex(), "owner_nonce": lf["owner_nonce"].hex(),
                    "operator_nonce": lf["operator_nonce"].hex(), "value": lf["value"],
                    "exit_delay_units": lf["exit_delay"], "unlock_hash": lf["unlock_hash"].hex()} for lf in leaves],
        "slots": [{"entry_script_pubkey": s["spk"].hex(), "value": s["value"], "reserve": s["reserve"],
                   "record": recs[j][0].hex()} for j, s in enumerate(slots)],
        "root": root.hex(),
        "total": total,
        "sweep_script": bytes(sweep).hex(),
        "data": s0.data().hex(),
        "data_leaf": tapdata(s0.data()).hex(),
        "merkle_root": s0.tree().hex(),
        "script_pubkey": s0.spk().hex(),
        "control_block": s0.control_block().hex(),
        "exits": [e1, e2],
        "held": held,
        "refuse": refuse,
    }
