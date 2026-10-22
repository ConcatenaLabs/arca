#!/usr/bin/env python3
"""The operator's equivocation bond: its scripts, and the golden vectors that
vectors.py writes to vectors/bond.json.

Built here independently of the Rust crate, from the specification's
sentences:

- A message S signs under a coin's salt is SHA256(K || rest) for a
  collaborative path, K = SHA256(SHA256("ArcaRbd1" || genesis) || salt), or
  SHA256(F || salt || rest) for an order-2 fill,
  F = SHA256(SHA256("Arca/order-fill") || genesis).
- SLASH takes the salt, for each of two signatures its form (empty: rebind,
  0x01: fill) and its rest in three chunks of at most 80 bytes, and the two
  signatures; it computes both digests itself, requires them to differ,
  checks both under S, and requires the output at its own index to burn the
  input's whole explicit amount of its asset with a bare OP_RETURN.
- NOTICE moves the bond whole to the notice output under W's signature.
- WITHDRAW, on the notice output: <D> CSV DROP <W> CHECKSIG.

    bond output:   [SLASH, NOTICE]        notice output:   [SLASH, WITHDRAW]
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.script import OP_NOT, OP_ROLL, OP_TUCK

FILL_TAG = b"Arca/order-fill"
BURN = bytes([0x6a])
ITEM = 80


def fill_prefix(genesis):
    return sha256(sha256(FILL_TAG) + genesis)


def whole_at_current_output():
    c = OP_PUSHCURRENTINPUTINDEX
    return [c, OP_INSPECTINPUTVALUE, 1, OP_EQUALVERIFY,
            c, OP_INSPECTOUTPUTVALUE, 1, OP_EQUALVERIFY, OP_EQUALVERIFY,
            c, OP_INSPECTINPUTASSET, 1, OP_EQUALVERIFY,
            c, OP_INSPECTOUTPUTASSET, 1, OP_EQUALVERIFY, OP_EQUALVERIFY]


def slash_script(genesis, s_x):
    """Witness, bottom to top:
    <sig_b> <b3> <b2> <b1> <form_b> <sig_a> <a3> <a2> <a1> <form_a> <salt>."""
    pick = [OP_IF, OP_NIP, OP_ELSE, OP_DROP, OP_ENDIF]
    return CScript(whole_at_current_output() + [
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY, -1, OP_EQUALVERIFY, sha256(BURN), OP_EQUALVERIFY,
        OP_SIZE, 32, OP_EQUALVERIFY,
        chain_tag(genesis), OP_OVER, OP_CAT, OP_SHA256,          # K
        fill_prefix(genesis), OP_ROT, OP_CAT,                    # F || salt
        OP_2DUP, OP_TOALTSTACK, OP_TOALTSTACK, OP_ROT] + pick + [
        OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_SHA256, OP_DUP, OP_TOALTSTACK,
        s_x, OP_DUP, OP_TOALTSTACK, OP_CHECKSIGFROMSTACKVERIFY,
        OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK, 4, OP_ROLL] + pick + [
        3, OP_ROLL, OP_CAT, 3, OP_ROLL, OP_CAT, 3, OP_ROLL, OP_CAT, OP_SHA256,
        OP_TUCK, OP_EQUAL, OP_NOT, OP_VERIFY, OP_SWAP, OP_CHECKSIGFROMSTACK])


def withdraw_script(delay, w_x):
    return CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, w_x, OP_CHECKSIG])


def notice_tap(genesis, s_x, w_x, delay):
    return taproot_construct(NUMS, [("slash", slash_script(genesis, s_x)), ("withdraw", withdraw_script(delay, w_x))])


def notice_script(n_program, w_x):
    return CScript(whole_at_current_output() + [
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY, 1, OP_EQUALVERIFY, n_program, OP_EQUALVERIFY,
        w_x, OP_CHECKSIG])


def bond_tap(genesis, s_x, w_x, delay):
    n = notice_tap(genesis, s_x, w_x, delay)
    return taproot_construct(NUMS, [("slash", slash_script(genesis, s_x)), ("notice", notice_script(n.scriptPubKey[2:], w_x))])


def digest(genesis, form, salt, rest):
    if form == "fill":
        return sha256(fill_prefix(genesis) + salt + rest)
    return sha256(sha256(chain_tag(genesis) + salt) + rest)


def rebind_rest(asset_in, value_in, outs):
    """What follows K in a collaborative path's message."""
    acc = input_record(asset_in, value_in) + bytes([len(outs)])
    for a, v, spk in outs:
        acc += sha256(record(a, v, spk))
    return acc


def chunks(rest):
    assert len(rest) <= 3 * ITEM
    return [rest[:ITEM], rest[ITEM:2 * ITEM], rest[2 * ITEM:]]


def slash_items(salt, a, b):
    """a, b: (form, rest, signature)."""
    def part(x):
        form, rest, sig = x
        c1, c2, c3 = chunks(rest)
        return [sig, c3, c2, c1, b"\x01" if form == "fill" else b""]
    return part(b) + part(a) + [salt]


def generate(genesis, keys, label_hash, delay):
    """A bond of S under W with notice delay `delay`, and a slash of it on two
    messages under one leaf salt: a payment to a receiver and a second spend
    of the same leaf."""
    s, w = keys["S"], keys["W"]
    x = label_hash("asset", "X")
    salt = label_hash("salt", "bond leaf")
    value = 10_000_000
    to_receiver = [(x, value - 1_000, b"\x51\x20" + keys["B"].x)]
    to_owner = [(x, value - 1_000, b"\x51\x20" + keys["A"].x), (x, 400, b"\x51\x20" + keys["A"].x)]
    ra, rb = rebind_rest(x, value, to_receiver), rebind_rest(x, value, to_owner)
    da, db = digest(genesis, "rebind", salt, ra), digest(genesis, "rebind", salt, rb)
    assert da == rebind_msg3(chain_tag(genesis), salt, x, value, to_receiver, fold=True)
    a = ("rebind", ra, s.sign(da))
    b = ("rebind", rb, s.sign(db))
    fill_rest = bytes(range(169))
    df = digest(genesis, "fill", salt, fill_rest)
    f = ("fill", fill_rest, s.sign(df))
    bond, notice = bond_tap(genesis, s.x, w.x, delay), notice_tap(genesis, s.x, w.x, delay)
    slash = slash_script(genesis, s.x)
    return {
        "genesis": genesis.hex(),
        "keys": {"S": s.x.hex(), "W": w.x.hex()},
        "notice_sequence": delay,
        "fill_prefix": fill_prefix(genesis).hex(),
        "scripts": {"slash": slash.hex(), "notice": notice_script(notice.scriptPubKey[2:], w.x).hex(),
                    "withdraw": withdraw_script(delay, w.x).hex()},
        "bond": {"script_pubkey": bond.scriptPubKey.hex(), "merkle_root": bond.merkle_root.hex(),
                 "control_blocks": {"slash": control_block(bond, "slash").hex(),
                                    "notice": control_block(bond, "notice").hex()}},
        "notice_output": {"script_pubkey": notice.scriptPubKey.hex(), "merkle_root": notice.merkle_root.hex(),
                          "control_blocks": {"slash": control_block(notice, "slash").hex(),
                                             "withdraw": control_block(notice, "withdraw").hex()}},
        "evidence": {
            "salt": salt.hex(), "asset": x.hex(), "value": value,
            "a": {"form": "rebind", "rest": ra.hex(), "digest": da.hex(), "signature": a[2].hex(),
                  "outputs": [{"asset": aa.hex(), "value": v, "script_pubkey": sp.hex()} for aa, v, sp in to_receiver]},
            "b": {"form": "rebind", "rest": rb.hex(), "digest": db.hex(), "signature": b[2].hex(),
                  "outputs": [{"asset": aa.hex(), "value": v, "script_pubkey": sp.hex()} for aa, v, sp in to_owner]},
            "fill": {"form": "fill", "rest": fill_rest.hex(), "digest": df.hex(), "signature": f[2].hex()},
            "slash_items": [i.hex() for i in slash_items(salt, a, b)],
            "slash_items_with_fill": [i.hex() for i in slash_items(salt, a, f)],
        },
    }
