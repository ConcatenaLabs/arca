#!/usr/bin/env python3
"""Golden vectors for every frozen Arca script.

    SEQUENTIA_DIR=/path/to/Sequentia regtest/vectors.py          # write every file in vectors/
    SEQUENTIA_DIR=/path/to/Sequentia regtest/vectors.py --check  # regenerate them all and compare

The scripts come from the suite's own builders (arklib.py, arklib3.py), the
taproot outputs and signature hashes from the node's functional test
framework. No node runs. Every input is derived from a fixed label, every
signature is BIP340 with zero auxiliary randomness, so the file regenerates
byte for byte. The keys are test keys: secret = SHA256("Arca test vector
key/" + label) reduced modulo the group order. They hold nothing anywhere.

What the file holds, per taproot output: the inputs that determine it, each
script leaf (bytes, opcodes, depth, leaf hash, control block), the merkle
root, the output key and the scriptPubKey. Per spend: a transaction that
spends the output by one path, the outputs it spends, and for that path the
signature hash or the signed message and its digest, the test keys'
signatures and the full witness. Every sample transaction is a valid spend
of its covenant input under the node's script rules.

vectors/records.json holds the leaf record's vectors, which records.py
generates: whole batches built by the tree rules, the round that funds each,
and every exported leaf's record in both encodings with its leaf id.

vectors/transactions.json holds the off-chain transactions' vectors, which
offchain.py generates: the board and its record, the forfeit with the
issuance of the connector asset, its claim and refund, and the offboard's
unlock and reclaim, each transaction whole, witnesses included.
"""
import json
import os
import sys
sys.dont_write_bytecode = True

from arklib3 import *                      # noqa: F401,F403
from test_framework.key import SECP256K1_ORDER
from test_framework.messages import (COutPoint, CTxIn, CTxOut, CTxOutAsset, CTxOutNonce,
                                     CTxOutValue, uint256_from_str)
from test_framework.script import TaprootSignatureHash, LEAF_VERSION_TAPSCRIPT

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors", "arca.json")
RECORDS_OUT = os.path.join(HERE, "vectors", "records.json")
TRANSACTIONS_OUT = os.path.join(HERE, "vectors", "transactions.json")

# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------

# The genesis block of the suite's chain (`elementsregtest` with the suite's
# arguments), in internal byte order: the order a header serialises it, the
# reverse of what `getblockhash` prints.
GENESIS_DISPLAY = "16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c"
GENESIS = bytes.fromhex(GENESIS_DISPLAY)[::-1]
CTAG = chain_tag(GENESIS)

H = 3600
DAY = 24 * H
CREATED = 1_791_000_000                    # the batch's creation time (median time)
EXPIRIES = [CREATED + 28 * DAY, CREATED + 56 * DAY, CREATED + 84 * DAY]
W_SECONDS = 36 * H
W = rel_time(W_SECONDS)                    # sweep notice, 512-second units
DELAY = rel_time(36 * H)                   # exit and forfeit-refund delay
T_WATCH = EXPIRIES[0] - 3 * DAY            # a watch service's authorisation time
HTLC_TIMEOUT = CREATED + 2 * DAY

RADIX = 4
NLEAVES = 64
LEAF_VALUE = 10_000_000
ENTRY_RESERVE = 1_000
NODE_RESERVE = 2_500
PATH_LEAF = 5                              # the leaf whose path the vectors export


def label_hash(kind, label):
    return sha256(("Arca test vector %s/%s" % (kind, label)).encode())


class Key:
    def __init__(self, label):
        d = int.from_bytes(label_hash("key", label), "big") % SECP256K1_ORDER
        self.label, self.sec = label, d.to_bytes(32, "big")
        self.x = compute_xonly_pubkey(self.sec)[0]

    def sign(self, digest):
        return sign_schnorr(self.sec, digest)

    def json(self):
        return {"secret": self.sec.hex(), "xonly": self.x.hex()}


S = Key("S")
OWNERS = [Key("A%d" % i) for i in range(NLEAVES)]
A = OWNERS[PATH_LEAF]
B = Key("B")                               # a receiver
FEE_KEY = Key("fee")

X_ID = label_hash("asset", "X")            # the batch asset, internal byte order
T_ID = label_hash("asset", "T")            # the sweep token
OTHER_ID = label_hash("asset", "Y")        # some other asset
X_OUT = b"\x01" + X_ID
T_OUT = b"\x01" + T_ID

SALTS = {i: label_hash("salt", "leaf%d" % i) for i in range(NLEAVES)}
SALT_CHECKPOINT = label_hash("salt", "checkpoint")
SALT_RECV = label_hash("salt", "receiver leaf")
SALT_CHANGE = label_hash("salt", "change leaf")
SALT_HTLC = {k: label_hash("salt", "htlc " + k) for k in ("claim", "claim_both", "refund_both")}
PREIMAGES = {i: label_hash("preimage", "entry%d" % i) for i in range(NLEAVES)}
FORFEIT_PREIMAGE = label_hash("preimage", "forfeit")
# The round the forfeit is given up for, and its connector output.
ROUND_TXID = label_hash("outpoint", "the round")   # internal byte order
CONNECTOR_VOUT = 2
PAYMENT_PREIMAGE = label_hash("preimage", "payment")

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def hx(b):
    return bytes(b).hex()


def outpoint(label, vout=0):
    txid = label_hash("outpoint", label)
    return COutPoint(uint256_from_str(txid), vout), txid[::-1].hex()


def txout(value, spk, asset_out=X_OUT):
    return CTxOut(nValue=CTxOutValue(value), scriptPubKey=bytes(spk), nAsset=CTxOutAsset(asset_out),
                  nNonce=CTxOutNonce())


def fee_out(value, asset_out=X_OUT):
    return txout(value, b"", asset_out)


# A coin anyone can spend by a tapscript of OP_1, standing in for the
# operator's fee coin in the sample transactions.
FEE_COIN_TAP = taproot_construct(NUMS, [("op_true", CScript([OP_1]))])
FEE_COIN_WITNESS = [bytes(CScript([OP_1])), control_block(FEE_COIN_TAP, "op_true")]
OPERATOR_SPK = bytes(taproot_construct(S.x).scriptPubKey)


class Spend:
    """A sample transaction: inputs are (label, spent txout, sequence)."""

    def __init__(self, inputs, outputs, locktime=0, version=2):
        self.tx = Tx()
        self.tx.nVersion, self.tx.nLockTime = version, locktime
        self.prev = []
        for lbl, spent, seq in inputs:
            op, _ = outpoint(lbl)
            self.tx.vin.append(CTxIn(op, nSequence=seq))
            self.prev.append(spent)
        self.tx.vout = list(outputs)
        ArkBase.pad(self.tx)

    def sighash(self, idx, script):
        return TaprootSignatureHash(self.tx, self.prev, 0, uint256_from_str(GENESIS), idx,
                                    scriptpath=True, script=CScript(script))

    def witness(self, idx, stack):
        self.tx.wit.vtxinwit[idx].scriptWitness.stack = [bytes(x) for x in stack]

    def json(self, idx):
        return {"tx": self.tx.serialize().hex(), "prevouts": [o.serialize().hex() for o in self.prev],
                "input_index": idx}


def leaf_json(tap, name, depth):
    leaf = tap.leaves[name]
    return {"script": hx(leaf.script), "asm": asm(leaf.script), "bytes": len(bytes(leaf.script)), "depth": depth,
            "leaf_version": "%02x" % LEAF_VERSION_TAPSCRIPT, "leaf_hash": hx(leaf.leaf_hash),
            "control_block": hx(control_block(tap, name))}


def output_json(template, params, tap, shape):
    """shape: [(leaf name, depth)] in the order the tree lists them."""
    return {"template": template, "params": params, "internal_key": NUMS.hex(),
            "leaves": {n: leaf_json(tap, n, d) for n, d in shape},
            "merkle_root": hx(tap.merkle_root), "output_key": hx(tap.output_pubkey),
            "script_pubkey": hx(tap.scriptPubKey)}


def wit(tap, name, below):
    return list(below) + [bytes(tap.leaves[name].script), control_block(tap, name)]


def children_json(tuples):
    return [{"asset": hx(a), "value": v, "program": hx(p)} for a, v, p in tuples]


# --------------------------------------------------------------------------
# The constructions
# --------------------------------------------------------------------------

R_TAP, R_LV = r_taptree(S.x, W)
R_SPK = bytes(R_TAP.scriptPubKey)
R_PROG = R_SPK[2:]
CLOCKS = clock_chain(T_ID, R_SPK, S.x, EXPIRIES)


def sweep_for(level_is_root, burn):
    w = None if level_is_root else W
    return burn_sweep(T_ID, R_PROG, S.x, w) if burn else sweep_token(T_ID, R_PROG, S.x, w)


def leaf_tap(i, key=None, salt=None):
    key = key or OWNERS[i]
    return leaf3_taptree(key.x, S.x, salt or SALTS[i], CTAG, DELAY, fold=True)


def build(burn=False):
    """The 64-leaf batch: leaves, their hash-locked entries, 16 lowest nodes,
    4 inner nodes and the batch output. Returns every level."""
    leaves = [leaf_tap(i) for i in range(NLEAVES)]
    entry_sweep = sweep_for(False, burn)
    entries = []
    for i, (tap, _) in enumerate(leaves):
        etap, elv = entry_taptree(sha256(PREIMAGES[i]), X_ID, LEAF_VALUE, bytes(tap.scriptPubKey)[2:], entry_sweep)
        entries.append({"spk": bytes(etap.scriptPubKey), "value": LEAF_VALUE + ENTRY_RESERVE, "tap": etap,
                        "lv": elv, "owners": [i]})
    levels = [entries]
    level = entries
    while len(level) > 1:
        nxt = []
        is_root = len(level) <= RADIX
        lowest = level is entries
        for j in range(0, len(level), RADIX):
            kids = level[j:j + RADIX]
            tuples = [(X_ID, k["value"], k["spk"][2:]) for k in kids]
            owners = sum((k["owners"] for k in kids), [])
            keys = [S.x] + [OWNERS[o].x for o in owners]
            mlevels, padded = hmerkle(keys, S.x)
            unroll = hgate_unroll(mlevels[-1][0], len(mlevels) - 1, tuples, timed=True)
            sweep = sweep_for(is_root, burn)
            reclaim = None
            if lowest:
                reclaim = reclaim_leaf(release_msg(GENESIS, tuples), [OWNERS[o].x for o in owners], S.x)
            tap, lv = node_taptree3(unroll, sweep, reclaim)
            nxt.append({"spk": bytes(tap.scriptPubKey), "value": sum(k["value"] for k in kids) + NODE_RESERVE,
                        "tap": tap, "lv": lv, "owners": owners, "children": kids, "tuples": tuples,
                        "members": keys, "padded": padded, "mlevels": mlevels, "is_root": is_root,
                        "lowest": lowest})
        levels.append(nxt)
        level = nxt
    return leaves, levels


# --------------------------------------------------------------------------
# Vectors
# --------------------------------------------------------------------------

def records():
    """The injective record of several kinds of output."""
    prog32 = label_hash("program", "p")[:32]
    cases = [
        ("explicit taproot output", X_ID, 123_456, bytes([0x51, 0x20]) + prog32),
        ("explicit v0 output, 20-byte program", X_ID, 1, bytes([0x00, 0x14]) + prog32[:20]),
        ("explicit v0 output, 33-byte program", X_ID, 1, bytes([0x00, 0x21]) + prog32 + b"\x01"),
        ("fee output (empty script)", X_ID, 500, b""),
        ("bare OP_RETURN", X_ID, 1_000_000, BURN_SPK),
        ("bare OP_TRUE", T_ID, 1, bytes([0x51])),
        ("43 bytes shaped like a program, which the node does not read as one", X_ID, 7,
         bytes([0x51, 41]) + label_hash("program", "long")[:32] + bytes(9)),
    ]
    return [{"name": n, "asset": hx(a), "value": v, "script_pubkey": hx(s), "record": hx(record(a, v, s))}
            for n, a, v, s in cases]


def node_vectors(n, label, kind):
    tuples = n["tuples"]
    shape = [("unroll", 1), ("sweep", 1)] if not n["lowest"] else [("unroll", 1), ("sweep", 2), ("reclaim", 2)]
    params = {
        "kind": kind,
        "children": children_json(tuples),
        "children_hash": hx(children_hash(tuples)),
        "members": [hx(k) for k in n["members"]],
        "members_padded": [hx(k) for k in n["padded"]],
        "member_root": hx(n["mlevels"][-1][0]),
        "member_depth": len(n["mlevels"]) - 1,
        "operator": hx(S.x), "token": hx(T_ID), "r_program": hx(R_PROG),
        "notice": None if n["is_root"] else W,
    }
    if n["lowest"]:
        params["owners"] = [hx(OWNERS[o].x) for o in n["owners"]]
        params["release_message"] = hx(release_msg(GENESIS, tuples))
    return output_json(kind, params, n["tap"], shape)


def unroll_spend(n, label, signer, t, own_fee):
    """An unroll of node n, the authorisation signed by `signer` for time t.
    own_fee: the reserve pays the fee; otherwise a fee coin pays and the
    reserve goes to the broadcaster as change."""
    kids = [txout(k["value"], k["spk"]) for k in n["children"]]
    spent = txout(n["value"], n["spk"])
    if own_fee:
        sp = Spend([(label, spent, 0xfffffffe)], kids + [fee_out(NODE_RESERVE)], locktime=t)
    else:
        sp = Spend([(label, spent, 0xfffffffe), (label + " fee coin", txout(5_000, FEE_COIN_TAP.scriptPubKey), 0xfffffffe)],
                   kids + [txout(NODE_RESERVE, OPERATOR_SPK), fee_out(5_000)], locktime=t)
        sp.witness(1, FEE_COIN_WITNESS)
    pos = n["members"].index(signer.x)
    msg_pre = UTAG + children_hash(n["tuples"]) + sn(t)
    digest = unroll_auth3(n["tuples"], t)
    assert digest == sha256(msg_pre)
    sig = signer.sign(digest)
    path = mpath(n["mlevels"], pos)
    sp.witness(0, wit(n["tap"], "unroll", hgate_witness(sig, path, signer.x, t)))
    d = sp.json(0)
    d.update({"name": label, "output": label.split("/")[0], "leaf": "unroll", "signer": signer.label,
              "member_index": pos, "t": t, "t_bytes": hx(sn(t)),
              "message": hx(msg_pre), "digest": hx(digest), "signatures": {signer.label: hx(sig)},
              "merkle_path": [{"sibling": hx(s), "is_left": il} for s, il in path],
              "witness": [hx(x) for x in sp.tx.wit.vtxinwit[0].scriptWitness.stack]})
    return d


def checksig_spend(name, output, leafname, tap, sp, idx, signer, below_before=(), below_after=()):
    """A spend whose path ends in <key> OP_CHECKSIG: the signature commits to
    the transaction (Elements taproot signature hash, SIGHASH_DEFAULT)."""
    script = tap.leaves[leafname].script
    sh = sp.sighash(idx, script)
    sig = signer.sign(sh)
    stack = list(below_before) + [sig] + list(below_after)
    sp.witness(idx, wit(tap, leafname, stack))
    d = sp.json(idx)
    d.update({"name": name, "output": output, "leaf": leafname, "sighash_type": "default",
              "sighash": hx(sh), "signatures": {signer.label: hx(sig)},
              "witness": [hx(x) for x in sp.tx.wit.vtxinwit[idx].scriptWitness.stack]})
    return d


def rebind_spend(name, output, leafname, tap, ctag, salt, spent, outs3, signers, m_item=True, extra=(),
                 locktime=0, seq=0xffffffff, fee=None):
    """A spend by a rebindable path: both (or one) of the signers sign the
    frozen message over the coin spent and the committed outputs."""
    asset_in, value_in = X_ID, spent.nValue.getAmount()
    acc = leaf_const(ctag, salt, fold=True) + input_record(asset_in, value_in) + bytes([len(outs3)])
    for a, v, s in outs3:
        acc += sha256(record(a, v, s))
    digest = rebind_msg3(ctag, salt, asset_in, value_in, outs3, fold=True)
    assert digest == sha256(acc)
    outs = [txout(v, s, b"\x01" + a) for a, v, s in outs3]
    left = value_in - sum(v for _, v, _ in outs3)
    sp = Spend([(name, spent, seq)], outs + [fee_out(left)], locktime=locktime)
    sigs = [k.sign(digest) for k in signers]
    below = list(sigs) + ([bytes([len(outs3)])] if m_item else []) + list(extra)
    sp.witness(0, wit(tap, leafname, below))
    d = sp.json(0)
    d.update({"name": name, "output": output, "leaf": leafname, "m": len(outs3),
              "K": hx(leaf_const(ctag, salt, fold=True)), "message": hx(acc), "digest": hx(digest),
              "signatures": {k.label: hx(s) for k, s in zip(signers, sigs)},
              "witness": [hx(x) for x in sp.tx.wit.vtxinwit[0].scriptWitness.stack]})
    return d


def generate():
    leaves, levels = build(burn=False)
    _, burn_levels = build(burn=True)
    entries, lowest, inner, (root,) = levels
    i = PATH_LEAF
    e = entries[i]
    n1 = lowest[i // RADIX]
    n2 = inner[i // (RADIX * RADIX)]
    ltap, llv = leaves[i]

    outputs = {}
    spends = []

    # ---- the leaf ------------------------------------------------------
    outputs["leaf"] = output_json("vtxo-1 leaf", {
        "owner": hx(A.x), "operator": hx(S.x), "salt": hx(SALTS[i]), "chain_tag": hx(CTAG),
        "K": hx(leaf_const(CTAG, SALTS[i], fold=True)), "exit_delay": DELAY, "max_outputs": M_MAX},
        ltap, [("collab", 1), ("exit", 1)])
    leaf_spent = txout(LEAF_VALUE, ltap.scriptPubKey)

    # ---- the clock and R -----------------------------------------------
    outputs["r"] = output_json("R", {"operator": hx(S.x), "notice": W}, R_TAP, [("spend", 0)])
    for j, c in enumerate(CLOCKS):
        shape = [("roll", 1), ("release", 1)] if "roll" in c["lv"] else [("release", 0)]
        nxt = CLOCKS[j + 1]["spk"] if j + 1 < len(CLOCKS) else None
        outputs["clock%d" % j] = output_json("clock", {
            "step": j, "token": hx(T_ID), "operator": hx(S.x), "r_script_pubkey": hx(R_SPK),
            "expiry": c["E"], "next_script_pubkey": hx(nxt) if nxt else None,
            "schedule": EXPIRIES}, c["tap"], shape)

    # ---- the tree ------------------------------------------------------
    outputs["entry"] = output_json("hash-locked entry", {
        "unlock_hash": hx(sha256(PREIMAGES[i])), "asset": hx(X_ID), "value": LEAF_VALUE,
        "leaf_program": hx(bytes(ltap.scriptPubKey)[2:]), "token": hx(T_ID), "r_program": hx(R_PROG),
        "operator": hx(S.x), "notice": W}, e["tap"], [("unlock", 1), ("sweep", 1)])
    outputs["lowest_node"] = node_vectors(n1, "lowest_node", "lowest node")
    outputs["inner_node"] = node_vectors(n2, "inner_node", "inner node")
    outputs["batch_output"] = node_vectors(root, "batch_output", "batch output")
    b_entries, b_lowest, _, (b_root,) = burn_levels
    outputs["entry_burn"] = output_json("hash-locked entry, issuer-operated", {
        "unlock_hash": hx(sha256(PREIMAGES[i])), "asset": hx(X_ID), "value": LEAF_VALUE,
        "leaf_program": hx(bytes(ltap.scriptPubKey)[2:]), "token": hx(T_ID), "r_program": hx(R_PROG),
        "operator": hx(S.x), "notice": W}, b_entries[i]["tap"], [("unlock", 1), ("sweep", 1)])
    outputs["lowest_node_burn"] = node_vectors(b_lowest[i // RADIX], "lowest_node_burn", "lowest node, issuer-operated")
    outputs["batch_output_burn"] = node_vectors(b_root, "batch_output_burn", "batch output, issuer-operated")

    # ---- forfeit, checkpoint, htlc-1 ----------------------------------
    # The forfeit gives up the path leaf, whose id it carries, for the round
    # whose connector asset M it requires at its claim.
    import records as record_ref
    leaf_id = record_ref.tagged_hash(record_ref.LEAF_ID_TAG, bytes(root["spk"])[2:] + bytes([3, i // 16, (i // 4) % 4, i % 4])
                                  + bytes(ltap.scriptPubKey)[2:])
    m_id = record_ref.issued_asset(ROUND_TXID, CONNECTOR_VOUT)
    ftap, flv = forfeit_taptree(sha256(FORFEIT_PREIMAGE), A.x, S.x, DELAY, leaf_id, m_id)
    outputs["forfeit"] = output_json("forfeit", {"unlock_hash": hx(sha256(FORFEIT_PREIMAGE)), "owner": hx(A.x),
                                                 "operator": hx(S.x), "refund_delay": DELAY, "leaf_id": hx(leaf_id),
                                                 "connector": {"round_txid": ROUND_TXID[::-1].hex(),
                                                               "vout": CONNECTOR_VOUT, "asset": hx(m_id)}},
                                     ftap, [("claim", 1), ("refund", 1)])
    cp_sweep = sweep_token(T_ID, R_PROG, S.x, W)
    ctap, clv = checkpoint_taptree(A.x, S.x, SALT_CHECKPOINT, CTAG, cp_sweep)
    outputs["checkpoint"] = output_json("checkpoint", {
        "owner": hx(A.x), "operator": hx(S.x), "salt": hx(SALT_CHECKPOINT),
        "K": hx(leaf_const(CTAG, SALT_CHECKPOINT, fold=True)), "token": hx(T_ID), "r_program": hx(R_PROG),
        "notice": W}, ctap, [("collab", 1), ("sweep", 1)])
    htap, hlv = htlc1_taptree(A.x, S.x, sha256(PAYMENT_PREIMAGE), HTLC_TIMEOUT, SALT_HTLC, CTAG)
    outputs["htlc"] = output_json("htlc-1", {
        "owner": hx(A.x), "operator": hx(S.x), "claimer": hx(S.x), "refunder": hx(A.x),
        "payment_hash": hx(sha256(PAYMENT_PREIMAGE)), "timeout": HTLC_TIMEOUT,
        "salts": {k: hx(v) for k, v in SALT_HTLC.items()},
        "K": {k: hx(leaf_const(CTAG, v, fold=True)) for k, v in SALT_HTLC.items()}},
        htap, [("claim", 2), ("claim_both", 2), ("refund", 2), ("refund_both", 2)])
    htap_r, _ = htlc1_taptree(A.x, S.x, sha256(PAYMENT_PREIMAGE), HTLC_TIMEOUT, SALT_HTLC, CTAG,
                              claimer_x=A.x, refunder_x=S.x)
    outputs["htlc_receive"] = output_json("htlc-1, payment into the tree", {
        "owner": hx(A.x), "operator": hx(S.x), "claimer": hx(A.x), "refunder": hx(S.x),
        "payment_hash": hx(sha256(PAYMENT_PREIMAGE)), "timeout": HTLC_TIMEOUT,
        "salts": {k: hx(v) for k, v in SALT_HTLC.items()},
        "K": {k: hx(leaf_const(CTAG, v, fold=True)) for k, v in SALT_HTLC.items()}},
        htap_r, [("claim", 2), ("claim_both", 2), ("refund", 2), ("refund_both", 2)])

    # ---- spends: the tree ---------------------------------------------
    spends.append(unroll_spend(root, "batch_output/unroll by an owner, reserve fee", A, CREATED, True))
    spends.append(unroll_spend(n2, "inner_node/unroll by the operator, reserve fee", S, CREATED, True))
    spends.append(unroll_spend(n1, "lowest_node/unroll by a watch service, own fee", A, T_WATCH, False))

    sp = Spend([("entry/unlock", txout(e["value"], e["spk"]), 0xffffffff)],
               [txout(LEAF_VALUE, ltap.scriptPubKey), fee_out(ENTRY_RESERVE)])
    sp.witness(0, wit(e["tap"], "unlock", [PREIMAGES[i]]))
    d = sp.json(0)
    d.update({"name": "entry/unlock", "output": "entry", "leaf": "unlock", "preimage": hx(PREIMAGES[i]),
              "witness": [hx(x) for x in sp.tx.wit.vtxinwit[0].scriptWitness.stack]})
    spends.append(d)

    # sweeps: the swept output at input 0, the token at R at input 1 (k = 1)
    def sweep_spend(name, output, node_tap, value, spk, notice, burn):
        r_in = (name + " token", txout(1, R_SPK, T_OUT), W)
        node_in = (name, txout(value, spk), W if notice else 0xfffffffe)
        if burn:
            outs = [txout(value, BURN_SPK), txout(1, R_SPK, T_OUT), txout(9_000, OPERATOR_SPK, X_OUT),
                    fee_out(1_000)]
            fee_in = (name + " fee coin", txout(10_000, FEE_COIN_TAP.scriptPubKey), 0xfffffffe)
            s = Spend([node_in, r_in, fee_in], outs)
            s.witness(2, FEE_COIN_WITNESS)
        else:
            outs = [txout(value - 3_000, OPERATOR_SPK), txout(1, R_SPK, T_OUT), fee_out(3_000)]
            s = Spend([node_in, r_in], outs)
        d = checksig_spend(name, output, "sweep", node_tap, s, 0, S, below_after=[sn(1)])
        r_script = R_LV["spend"]
        s.witness(1, wit(R_TAP, "spend", [S.sign(s.sighash(1, r_script))]))
        d["tx"] = s.tx.serialize().hex()
        d["k"] = 1
        return d

    spends.append(sweep_spend("batch_output/sweep", "batch_output", root["tap"], root["value"], root["spk"],
                              False, False))
    spends.append(sweep_spend("lowest_node/sweep after the notice", "lowest_node", n1["tap"], n1["value"],
                              n1["spk"], True, False))
    spends.append(sweep_spend("entry/sweep after the notice", "entry", e["tap"], e["value"], e["spk"], True, False))
    bl = b_lowest[i // RADIX]
    spends.append(sweep_spend("lowest_node_burn/burn after the notice", "lowest_node_burn", bl["tap"], bl["value"],
                              bl["spk"], True, True))
    spends.append(sweep_spend("batch_output_burn/burn", "batch_output_burn", b_root["tap"], b_root["value"],
                              b_root["spk"], False, True))

    # reclaim of the lowest node: every owner signs the release, the operator the transaction
    rel = release_msg(GENESIS, n1["tuples"])
    owners = [OWNERS[o] for o in n1["owners"]]
    osigs = [k.sign(rel) for k in owners]
    sp = Spend([("lowest_node/reclaim", txout(n1["value"], n1["spk"]), 0xffffffff)],
               [txout(n1["value"] - 2_000, OPERATOR_SPK), fee_out(2_000)])
    d = checksig_spend("lowest_node/reclaim", "lowest_node", "reclaim", n1["tap"], sp, 0, S,
                       below_after=list(reversed(osigs)))
    d["release_message"] = hx(RTAG + GENESIS + children_hash(n1["tuples"]))
    d["release_digest"] = hx(rel)
    d["signatures"].update({k.label: hx(s) for k, s in zip(owners, osigs)})
    spends.append(d)

    # ---- spends: the clock --------------------------------------------
    def clock_spend(name, j, path, to_spk, locktime):
        c = CLOCKS[j]
        seq = 0xfffffffe
        s = Spend([(name, txout(1, c["spk"], T_OUT), seq),
                   (name + " fee coin", txout(5_000, FEE_COIN_TAP.scriptPubKey), seq)],
                  [txout(1, to_spk, T_OUT), fee_out(5_000)], locktime=locktime)
        s.witness(1, FEE_COIN_WITNESS)
        d = checksig_spend(name, "clock%d" % j, path, c["tap"], s, 0, S)
        d["tx"] = s.tx.serialize().hex()
        return d

    spends.append(clock_spend("clock0/roll", 0, "roll", CLOCKS[1]["spk"], 0))
    spends.append(clock_spend("clock1/roll", 1, "roll", CLOCKS[2]["spk"], 0))
    spends.append(clock_spend("clock0/release", 0, "release", R_SPK, EXPIRIES[0]))
    spends.append(clock_spend("clock2/release", 2, "release", R_SPK, EXPIRIES[2]))
    sp = Spend([("r/spend", txout(1, R_SPK, T_OUT), W),
                ("r/spend fee coin", txout(5_000, FEE_COIN_TAP.scriptPubKey), 0xfffffffe)],
               [txout(1, R_SPK, T_OUT), fee_out(5_000)])
    sp.witness(1, FEE_COIN_WITNESS)
    d = checksig_spend("r/spend", "r", "spend", R_TAP, sp, 0, S)
    d["tx"] = sp.tx.serialize().hex()
    spends.append(d)

    # ---- spends: the leaf ---------------------------------------------
    sp = Spend([("leaf/exit", leaf_spent, DELAY)], [txout(LEAF_VALUE - 600, bytes(taproot_construct(A.x).scriptPubKey)),
                                                    fee_out(600)])
    spends.append(checksig_spend("leaf/exit", "leaf", "exit", ltap, sp, 0, A))

    cp_out = [(X_ID, LEAF_VALUE - 600, bytes(ctap.scriptPubKey))]
    spends.append(rebind_spend("leaf/collab m=1, into the checkpoint", "leaf", "collab", ltap, CTAG, SALTS[i],
                               leaf_spent, cp_out, [S, A]))
    rtap, _ = leaf_tap(0, key=B, salt=SALT_RECV)
    chtap, _ = leaf_tap(0, key=A, salt=SALT_CHANGE)
    v_cp = LEAF_VALUE - 600
    re_outs = [(X_ID, 7_000_000, bytes(rtap.scriptPubKey)), (X_ID, v_cp - 7_000_000 - 600, bytes(chtap.scriptPubKey))]
    spends.append(rebind_spend("checkpoint/collab m=2, the reassignment", "checkpoint", "collab", ctap, CTAG,
                               SALT_CHECKPOINT, txout(v_cp, ctap.scriptPubKey), re_outs, [S, A]))
    four = [(X_ID, 2_499_850 + j, bytes(leaf_tap(j)[0].scriptPubKey)) for j in range(4)]
    spends.append(rebind_spend("leaf/collab m=4", "leaf", "collab", ltap, CTAG, SALTS[i], leaf_spent, four, [S, A]))
    spends.append(rebind_spend("leaf/collab m=1, into the forfeit", "leaf", "collab", ltap, CTAG, SALTS[i],
                               leaf_spent, [(X_ID, LEAF_VALUE - 600, bytes(ftap.scriptPubKey))], [S, A]))
    # A committed output whose script looks like a witness program but has 43
    # bytes: the node reads it as SHA256(script) with version -1.
    long_spk = bytes([0x51, 41]) + label_hash("program", "long")[:32] + bytes(9)
    spends.append(rebind_spend("leaf/collab m=1, into a 43-byte script", "leaf", "collab", ltap, CTAG, SALTS[i],
                               leaf_spent, [(X_ID, LEAF_VALUE - 600, long_spk)], [S, A]))
    spends.append(sweep_spend("checkpoint/sweep after the notice", "checkpoint", ctap, v_cp, bytes(ctap.scriptPubKey),
                              True, False))

    # ---- spends: the forfeit ------------------------------------------
    f_spent = txout(LEAF_VALUE - 600, ftap.scriptPubKey)
    # The connector atom is input 1 (k = 1) and goes back to the operator.
    m_out = b"\x01" + m_id
    sp = Spend([("forfeit/claim", f_spent, 0xffffffff),
                ("forfeit/claim connector", txout(1, FEE_COIN_TAP.scriptPubKey, m_out), 0xffffffff)],
               [txout(LEAF_VALUE - 1200, OPERATOR_SPK), txout(1, OPERATOR_SPK, m_out), fee_out(600)])
    sp.witness(1, FEE_COIN_WITNESS)
    d = checksig_spend("forfeit/claim", "forfeit", "claim", ftap, sp, 0, S, below_after=[FORFEIT_PREIMAGE, sn(1)])
    d["preimage"] = hx(FORFEIT_PREIMAGE)
    d["connector_input"] = 1
    spends.append(d)
    sp = Spend([("forfeit/refund", f_spent, DELAY)], [txout(LEAF_VALUE - 1200, bytes(taproot_construct(A.x).scriptPubKey)),
                                                      fee_out(600)])
    spends.append(checksig_spend("forfeit/refund", "forfeit", "refund", ftap, sp, 0, A))

    # ---- spends: htlc-1 -----------------------------------------------
    h_spent = txout(LEAF_VALUE, htap.scriptPubKey)
    h_out = [(X_ID, LEAF_VALUE - 500, OPERATOR_SPK)]
    d = rebind_spend("htlc/claim", "htlc", "claim", htap, CTAG, SALT_HTLC["claim"], h_spent, h_out, [S],
                     m_item=False, extra=[PAYMENT_PREIMAGE])
    d["preimage"] = hx(PAYMENT_PREIMAGE)
    spends.append(d)
    d = rebind_spend("htlc/claim_both", "htlc", "claim_both", htap, CTAG, SALT_HTLC["claim_both"], h_spent, h_out,
                     [S, A], m_item=False, extra=[PAYMENT_PREIMAGE])
    d["preimage"] = hx(PAYMENT_PREIMAGE)
    spends.append(d)
    back = [(X_ID, LEAF_VALUE - 500, bytes(leaf_tap(0, key=A, salt=SALT_CHANGE)[0].scriptPubKey))]
    spends.append(rebind_spend("htlc/refund_both", "htlc", "refund_both", htap, CTAG, SALT_HTLC["refund_both"],
                               h_spent, back, [S, A], m_item=False, locktime=HTLC_TIMEOUT, seq=0xfffffffe))
    sp = Spend([("htlc/refund", h_spent, 0xfffffffe)], [txout(LEAF_VALUE - 500, bytes(taproot_construct(A.x).scriptPubKey)),
                                                        fee_out(500)], locktime=HTLC_TIMEOUT)
    spends.append(checksig_spend("htlc/refund", "htlc", "refund", htap, sp, 0, A))

    return {
        "about": "Golden vectors for the frozen Arca scripts. Generated by regtest/vectors.py; do not edit.",
        "conventions": {
            "byte_order": "Asset ids, transaction ids and the genesis hash are given in internal byte order (as "
                          "serialised), except where a field is named `display`.",
            "leaf_version": "c4: tapscript, with the Elements tagged hashes (TapLeaf/elements, TapBranch/elements, "
                            "TapTweak/elements, TapSighash/elements).",
            "keys": "secret = SHA256(\"Arca test vector key/\" + label) mod n. Test keys only.",
            "signatures": "BIP340 with 32 zero bytes of auxiliary randomness.",
            "witness": "Bottom of the stack first, ending with the script and the control block.",
            "time": "Absolute times are median-time values for OP_CHECKLOCKTIMEVERIFY; relative ones are "
                    "OP_CHECKSEQUENCEVERIFY operands in 512-second units (bit 22 set).",
        },
        "inputs": {
            "genesis_hash": {"internal": hx(GENESIS), "display": GENESIS_DISPLAY},
            "chain_tag": hx(CTAG),
            "nums": hx(NUMS),
            "keys": dict([("S", S.json()), ("B", B.json())] + [(k.label, k.json()) for k in OWNERS]),
            "assets": {"X": hx(X_ID), "T": hx(T_ID), "Y": hx(OTHER_ID)},
            "created": CREATED, "expiries": EXPIRIES, "notice": W, "notice_seconds": W_SECONDS,
            "exit_delay": DELAY, "watch_service_time": T_WATCH, "htlc_timeout": HTLC_TIMEOUT,
            "radix": RADIX, "leaves": NLEAVES, "leaf_value": LEAF_VALUE, "entry_reserve": ENTRY_RESERVE,
            "node_reserve": NODE_RESERVE, "path_leaf": PATH_LEAF,
            "salts": dict([("leaf%d" % j, hx(SALTS[j])) for j in range(NLEAVES)]
                          + [("checkpoint", hx(SALT_CHECKPOINT)), ("receiver leaf", hx(SALT_RECV)),
                             ("change leaf", hx(SALT_CHANGE))]
                          + [("htlc " + k, hx(v)) for k, v in SALT_HTLC.items()]),
            "preimages": dict([("entry%d" % j, hx(PREIMAGES[j])) for j in range(NLEAVES)]
                              + [("forfeit", hx(FORFEIT_PREIMAGE)), ("payment", hx(PAYMENT_PREIMAGE))]),
            "fee_coin_script_pubkey": hx(FEE_COIN_TAP.scriptPubKey),
            "operator_script_pubkey": hx(OPERATOR_SPK),
        },
        "records": records(),
        "outputs": outputs,
        "spends": spends,
    }


def main():
    import offchain
    import records
    files = [(OUT, json.dumps(generate(), indent=1) + "\n"),
             (RECORDS_OUT, json.dumps(records.generate(), indent=1) + "\n"),
             (TRANSACTIONS_OUT, json.dumps(offchain.generate(), indent=1) + "\n")]
    if "--check" in sys.argv[1:]:
        stale = []
        for path, text in files:
            try:
                with open(path) as f:
                    old = f.read()
            except OSError:
                old = None
            if old != text:
                stale.append(os.path.relpath(path))
            else:
                print("%s regenerates byte for byte" % os.path.relpath(path))
        if stale:
            sys.exit("%s does not match what vectors.py generates; run regtest/vectors.py and commit the result"
                     % ", ".join(stale))
        return
    for path, text in files:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        print("wrote %s" % os.path.relpath(path))


if __name__ == "__main__":
    main()
