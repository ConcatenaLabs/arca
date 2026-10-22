#!/usr/bin/env python3
"""channel-1: a leaf with a balance for each of owner and operator, its
scripts, and the golden vectors that vectors.py writes to
vectors/channel.json.

Built here independently of the Rust crate, from the specification's
sentences. A channel's state is (n, a, s, F): its number, the owner's
balance, the operator's balance and the cumulative credit already folded
into the owner's; a + s is the leaf's value V. Every channel output, the leaf
itself being the output of state 0, is a taproot output with the NUMS
internal key and the leaves

    [collab, [update(n), settle(n)]]

- collab: vtxo-1's collaborative path under the salt's K, the same in every
  state, so a pair made for the coin spends it in whatever state it reached.
- update(n), witness <sig_S> <sig_A> <m>: m is 8 bytes and m > n; both sign
  SHA256(Q || le8(m) || P), P the v1 program of the output at the input's
  own index, which keeps the input's asset and value;
  Q = SHA256(SHA256("ArcaChn1" || genesis) || salt).
- settle(n), no witness: after the exit delay, output 0 pays exactly a to
  OP_1 <A> and output 1 exactly s to the credit output of state n, both in
  the input's asset; a zero balance's half is left out and the other takes
  output 0.

The credit output of state n: [claim(n), provider].

- claim(n), witness <sig> <c>: c is 8 bytes; S signed SHA256(N || le8(c)),
  N = SHA256(SHA256("ArcaCrd1" || genesis) || salt). With B = s + F, it pays
  min(c, B) - (B - value in) > 0 to OP_1 <A> at the input's own index i and,
  unless it is zero, the rest to this same script at output i+1, all in the
  input's asset.
- provider: <window> CSV DROP <S> CHECKSIG.
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.script import OP_GREATERTHAN64, OP_SUB64, OP_TUCK, OP_1ADD

STATE_TAG = b"ArcaChn1"
CREDIT_TAG = b"ArcaCrd1"
ZERO8 = le8(0)


def state_const(genesis, salt):
    """Q = SHA256(SHA256("ArcaChn1" || genesis) || salt), genesis internal order."""
    return sha256(sha256(STATE_TAG + genesis) + salt)


def credit_const(genesis, salt):
    """N = SHA256(SHA256("ArcaCrd1" || genesis) || salt)."""
    return sha256(sha256(CREDIT_TAG + genesis) + salt)


def state_msg(q, m, program):
    """The digest both sign for state m: SHA256(Q || le8(m) || P)."""
    assert len(q) == 32 and len(program) == 32
    return sha256(q + le8(m) + program)


def note_msg(n, c):
    """The digest S signs for a cumulative credit c: SHA256(N || le8(c))."""
    return sha256(n + le8(c))


def same_asset_at(index_ops):
    """The output at `index_ops` is in the current input's asset (asset and
    prefix compared)."""
    return index_ops + [OP_INSPECTOUTPUTASSET, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET,
                        OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY]


def update_script(q, n, a_x, s_x):
    c = OP_PUSHCURRENTINPUTINDEX
    return CScript([
        OP_SIZE, 8, OP_EQUALVERIFY, OP_DUP, le8(n), OP_GREATERTHAN64, OP_VERIFY,
        q, OP_SWAP, OP_CAT,
        c, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, OP_CAT,
        OP_SHA256, OP_TUCK, a_x, OP_CHECKSIGFROMSTACKVERIFY, s_x, OP_CHECKSIGFROMSTACKVERIFY,
        c, OP_INSPECTOUTPUTVALUE, c, OP_INSPECTINPUTVALUE, OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY,
        c, OP_INSPECTOUTPUTASSET, c, OP_INSPECTINPUTASSET, OP_ROT, OP_EQUALVERIFY, OP_EQUAL])


def settle_script(delay, a_x, a, credit_program, s):
    """The present halves take outputs 0 and 1 in order: the owner's first
    when it has a balance, then the operator's."""
    assert a > 0 or s > 0
    halves = ([(a_x, a)] if a > 0 else []) + ([(credit_program, s)] if s > 0 else [])
    body = []
    for i, (prog, v) in enumerate(halves):
        idx = OP_0 if i == 0 else OP_1
        body += [idx, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, prog, OP_EQUALVERIFY]
        body += same_asset_at([idx])
        last = i == len(halves) - 1
        body += [idx, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(v), OP_EQUAL if last else OP_EQUALVERIFY]
    return CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP] + body)


def claim_script(ncon, s_x, b, a_x):
    """Pays the owner at the input's own index i, the rest at i+1."""
    c = OP_PUSHCURRENTINPUTINDEX
    nxt = [c, OP_1ADD]
    return CScript([
        OP_SIZE, 8, OP_EQUALVERIFY,
        OP_DUP, ncon, OP_SWAP, OP_CAT, OP_SHA256, OP_ROT, OP_SWAP, s_x, OP_CHECKSIGFROMSTACKVERIFY,   # c
        le8(b), OP_2DUP, OP_GREATERTHAN64, OP_IF, OP_NIP, OP_ELSE, OP_DROP, OP_ENDIF,                 # min(c, B)
        le8(b), c, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY, OP_SUB64, OP_VERIFY,                    # m paid
        OP_SUB64, OP_VERIFY, OP_DUP, ZERO8, OP_GREATERTHAN64, OP_VERIFY,                               # delta > 0
        c, OP_DUP, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, a_x, OP_EQUALVERIFY]            # delta i
        + same_asset_at([OP_DUP]) + [
        OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, OP_OVER, OP_EQUALVERIFY,                          # delta
        c, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY, OP_SWAP, OP_SUB64, OP_VERIFY,                   # rest
        OP_DUP, ZERO8, OP_EQUAL, OP_NOTIF]
        + nxt + [OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, OP_OVER, OP_EQUALVERIFY]
        + nxt + [OP_INSPECTOUTPUTSCRIPTPUBKEY, c, OP_INSPECTINPUTSCRIPTPUBKEY, OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY]
        + same_asset_at(nxt) + [
        OP_ENDIF, OP_DROP, OP_1])


def provider_script(window, s_x):
    return CScript([window, OP_CHECKSEQUENCEVERIFY, OP_DROP, s_x, OP_CHECKSIG])


class Channel:
    """One channel: its keys, salt, chain, exit delay, value V, opening
    capacity and credit window. Every script is a function of a state."""

    def __init__(self, genesis, salt, a_x, s_x, delay, value, capacity, window):
        assert 0 <= capacity < value
        self.genesis, self.salt, self.a_x, self.s_x = genesis, salt, a_x, s_x
        self.delay, self.value, self.capacity, self.window = delay, value, capacity, window
        self.ctag = chain_tag(genesis)
        self.q = state_const(genesis, salt)
        self.ncon = credit_const(genesis, salt)
        self.collab = collab3_loop(a_x, s_x, salt, self.ctag, fold=True)

    def opening(self):
        return (0, self.value - self.capacity, self.capacity, 0)

    def credit_tap(self, state):
        n, a, s, f = state
        claim = claim_script(self.ncon, self.s_x, s + f, self.a_x)
        prov = provider_script(self.window, self.s_x)
        return taproot_construct(NUMS, [("claim", claim), ("provider", prov)]), {"claim": claim, "provider": prov}

    def tap(self, state):
        n, a, s, f = state
        assert a + s == self.value and a >= 0 and s >= 0
        credit_prog = bytes(self.credit_tap(state)[0].scriptPubKey)[2:]
        upd = update_script(self.q, n, self.a_x, self.s_x)
        stl = settle_script(self.delay, self.a_x, a, credit_prog, s)
        tap = taproot_construct(NUMS, [("collab", self.collab), [("update", upd), ("settle", stl)]])
        return tap, {"collab": self.collab, "update": upd, "settle": stl}

    def program(self, state):
        return bytes(self.tap(state)[0].scriptPubKey)[2:]

    def state_digest(self, state):
        return state_msg(self.q, state[0], self.program(state))

    def note_digest(self, c):
        return note_msg(self.ncon, c)


def owner_spk(a_x):
    """Where the owner's balance and its credit are paid: OP_1 <A>."""
    return bytes([0x51, 0x20]) + a_x


def hx(b):
    return bytes(b).hex()


def generate(genesis, keys, label_hash, delay, window):
    """The vectors: one channel, its outputs at states 0, 1 (a payment out)
    and 2 (a fold), each state's digest and both signatures, the credit
    output of state 2, two notes and their signatures."""
    A, S = keys["A"], keys["S"]
    salt = label_hash("salt", "channel")
    V, CAP = 1_000_000, 400_000
    ch = Channel(genesis, salt, A.x, S.x, delay, V, CAP, window)
    states = [ch.opening(), (1, 450_000, 550_000, 0), (2, 520_000, 480_000, 70_000)]

    def tapj(tap, scripts):
        return {
            "script_pubkey": hx(tap.scriptPubKey),
            "merkle_root": hx(tap.merkle_root),
            "leaves": {k: hx(v) for k, v in scripts.items()},
            "control_blocks": {k: hx(control_block(tap, k)) for k in scripts},
        }

    out = {
        "genesis": hx(genesis),
        "salt": hx(salt),
        "keys": {"A": A.x.hex(), "S": S.x.hex()},
        "exit_delay_sequence": delay,
        "window_sequence": window,
        "value": V,
        "capacity": CAP,
        "state_constant": hx(ch.q),
        "credit_constant": hx(ch.ncon),
        "owner_script_pubkey": hx(owner_spk(A.x)),
        "states": [],
        "notes": [],
    }
    for st in states:
        tap, scripts = ch.tap(st)
        ctap, cscripts = ch.credit_tap(st)
        d = ch.state_digest(st)
        out["states"].append({
            "number": st[0], "owner": st[1], "operator": st[2], "folded": st[3],
            "output": tapj(tap, scripts),
            "credit_output": tapj(ctap, cscripts),
            "digest": hx(d),
            "signatures": {"A": hx(A.sign(d)), "S": hx(S.sign(d))},
        })
    for c in (70_000, 125_000):
        d = ch.note_digest(c)
        out["notes"].append({"cumulative": c, "digest": hx(d), "signature": hx(S.sign(d))})
    return out
