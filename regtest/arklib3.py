#!/usr/bin/env python3
"""The frozen Arca constructions (T16-T21), on top of arklib.py.

arklib.py keeps the earlier constructions that T0-T15 measure, with their
meaning unchanged. This module adds the ones the specification freezes: the
rebindable message bound to the coin and the chain, the hardened membership
gate with a timed authorisation, the token-gated sweep and its clock, the
reclaim, the notice on the token, and the time helpers that median-time locks
need.
"""
from arklib import *                      # noqa: F401,F403
from arklib import _csfs_2of2
import os as _os
from test_framework.messages import CAssetIssuance, CTxOutValue as _Val
from test_framework.script import OP_INSPECTINPUTISSUANCE, OP_INSPECTINPUTSCRIPTPUBKEY

TAG = b"ArcaRbd1"
UTAG = b"Arca/unroll"
RTAG = b"Arca/release"
SEQ_TIME = 1 << 22                        # BIP68 type flag: 512-second units


def sn(n):
    """Minimal script-number encoding WITHOUT the push prefix (the bytes the
    stack element holds)."""
    if n == 0:
        return b""
    neg, a, r = n < 0, abs(n), bytearray()
    while a:
        r.append(a & 0xff)
        a >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return bytes(r)


def rel_time(seconds):
    """nSequence / CSV operand for a time-based relative lock of >= seconds."""
    return SEQ_TIME | ((seconds + 511) // 512)


# --------------------------------------------------------------------------
# T16: rebindable message bound to the coin and the chain
# --------------------------------------------------------------------------

def chain_tag(genesis_internal):
    """chain_tag = SHA256("ArcaRbd1" || genesis_hash), genesis in INTERNAL byte
    order (the order it is serialised in a block header; the reverse of the
    hex getblockhash prints)."""
    assert len(genesis_internal) == 32
    return sha256(TAG + genesis_internal)


def input_record_ops():
    """Leaves  asset(32) || asset_prefix || value_prefix || value(8)  of the
    CURRENT input: the record form of T1 without the script part."""
    return [OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET, OP_CAT,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE, OP_SWAP, OP_CAT, OP_CAT]


def input_record(asset, value):
    return asset + b"\x01" + b"\x01" + le8(value)


def leaf_const(ctag, salt, fold=False):
    """The constant the script pushes: chain_tag || salt (64 bytes, as
    specified) or, folded, SHA256(chain_tag || salt) (32 bytes)."""
    return sha256(ctag + salt) if fold else ctag + salt


def rebind_msg3(ctag, salt, asset_in, value_in, outs, fold=False):
    """msg = SHA256(chain_tag || salt || asset_in || 01 || 01 || value_in || m || SHA256(rec_0) ..)
    folded: chain_tag || salt is replaced by SHA256(chain_tag || salt)."""
    assert len(ctag) == 32 and len(salt) == 32 and 1 <= len(outs) <= 255
    acc = leaf_const(ctag, salt, fold) + input_record(asset_in, value_in) + bytes([len(outs)])
    for a, v, spk in outs:
        acc += sha256(record(a, v, spk))
    return sha256(acc)


def collab3_loop(a_x, s_x, salt, ctag, M=M_MAX, fold=False):
    """T10 loop with the coin and the chain in the message.
    Witness (bottom -> top): <sig_S> <sig_A> <m>."""
    s = [OP_SIZE, OP_1, OP_EQUALVERIFY]
    s += [OP_DUP, OP_1, M + 1, OP_WITHIN, OP_VERIFY]
    s += [OP_DUP, leaf_const(ctag, salt, fold)] + input_record_ops() + [OP_CAT, OP_SWAP, OP_CAT, OP_SWAP]
    for j in range(M):
        slot = record_ops(j) + [OP_SHA256, OP_ROT, OP_SWAP, OP_CAT, OP_SWAP]
        s += slot if j == 0 else [OP_DUP, j, OP_GREATERTHAN, OP_IF] + slot + [OP_ENDIF]
    s += [OP_DROP, OP_SHA256] + _csfs_2of2(a_x, s_x)
    return CScript(s)


def exit_leaf(a_x, delay):
    return CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, a_x, OP_CHECKSIG])


def leaf3_taptree(a_x, s_x, salt, ctag, delay, sweep=None, fold=False):
    """sweep=None: the noticed leaf of T20, [collab, exit]. With a sweep script:
    the T10 shape [collab, [exit, sweep]] (used by T16 for a like-for-like size)."""
    collab, ex = collab3_loop(a_x, s_x, salt, ctag, fold=fold), exit_leaf(a_x, delay)
    if sweep is None:
        tap = taproot_construct(NUMS, [("collab", collab), ("exit", ex)])
        return tap, {"collab": collab, "exit": ex}
    tap = taproot_construct(NUMS, [("collab", collab), [("exit", ex), ("sweep", sweep)]])
    return tap, {"collab": collab, "exit": ex, "sweep": sweep}


# --------------------------------------------------------------------------
# T17: the hardened gate and the timed authorisation
# --------------------------------------------------------------------------

def hmerkle(keys, pad_key):
    """Member tree: leaf SHA256(0x00||key), inner SHA256(0x01||l||r); the key
    list is padded to a power of two with pad_key (the operator's).
    Returns (levels, padded_keys)."""
    n = 1
    while n < len(keys):
        n *= 2
    keys = list(keys) + [pad_key] * (n - len(keys))
    lvl = [sha256(b"\x00" + k) for k in keys]
    levels = [lvl]
    while len(lvl) > 1:
        lvl = [sha256(b"\x01" + lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
        levels.append(lvl)
    return levels, keys


def mpath(levels, idx):
    path = []
    for lvl in levels[:-1]:
        path.append((lvl[idx ^ 1], idx % 2 == 0))
        idx //= 2
    return path


def hgate_prefix(root, depth):
    s = [OP_SIZE, 32, OP_EQUALVERIFY, OP_DUP, OP_TOALTSTACK, b"\x00", OP_SWAP, OP_CAT, OP_SHA256]
    for _ in range(depth):
        s += [OP_SWAP, OP_IF, OP_SWAP, OP_ENDIF, OP_CAT, OP_1, OP_SWAP, OP_CAT, OP_SHA256]
    return s + [root, OP_EQUALVERIFY]


def hgate_unroll(root, depth, children, timed=True):
    """Hardened, pre-signed gated UNROLL (compact body).
    Witness (bottom -> top): <sig> [<t>] {<sibling> <dir>} top level first, <key>.
    msg = SHA256("Arca/unroll" || H || t), t enforced with CLTV (timed=True);
    msg = SHA256("Arca/unroll" || H) otherwise."""
    s = hgate_prefix(root, depth)
    s += unroll_compact_body(children, tail=False)
    s += [OP_DUP, children_hash(children), OP_EQUALVERIFY]
    if timed:
        s += [OP_SWAP, OP_CHECKLOCKTIMEVERIFY, OP_CAT]
    s += [UTAG, OP_SWAP, OP_CAT, OP_SHA256, OP_FROMALTSTACK, OP_CHECKSIGFROMSTACK]
    return CScript(s)


def unroll_auth3(children, t=None):
    return sha256(UTAG + children_hash(children) + (sn(t) if t is not None else b""))


def hgate_witness(sig, path, key, t=None):
    w = [sig] + ([sn(t)] if t is not None else [])
    for sib, is_left in reversed(path):
        w += [sib, b"\x01" if is_left else b""]
    return w + [key]


# --------------------------------------------------------------------------
# T18: token-gated sweep and the clock
# --------------------------------------------------------------------------

def pin_current_output(asset, value, spk, verify=False):
    """The output at THIS input's index must be exactly (explicit asset, explicit
    value, spk): its injective record is hashed and compared."""
    c = OP_PUSHCURRENTINPUTINDEX
    return [c, OP_INSPECTOUTPUTASSET, OP_CAT, c, OP_INSPECTOUTPUTVALUE, OP_SWAP, OP_CAT, OP_CAT,
            c, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_2, OP_ADD, OP_CAT, OP_CAT, OP_SHA256,
            sha256(record(asset, value, spk)), OP_EQUALVERIFY if verify else OP_EQUAL]


def token_check(T_id, R_prog):
    """Witness top: k. Input k must hold explicit asset T at the v1 program R."""
    return [OP_DUP, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY, T_id, OP_EQUALVERIFY,
            OP_INSPECTINPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, R_prog, OP_EQUALVERIFY]


def sweep_token(T_id, R_prog, s_x, W=None):
    """Token-gated sweep. Witness (bottom -> top): <sig_S> <k>.
    With W: also a relative lock on THIS input (notice for nodes that appear late)."""
    s = token_check(T_id, R_prog)
    if W is not None:
        s += [W, OP_CHECKSEQUENCEVERIFY, OP_DROP]
    return CScript(s + [s_x, OP_CHECKSIG])


def sweep_token_asset_only(T_id, s_x):
    """The FIRST sketch (r3 item 1): only checks that input k carries T."""
    return CScript([OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY, T_id, OP_EQUALVERIFY, s_x, OP_CHECKSIG])


def r_taptree(s_x, W=None):
    """R, the script T rests at once released. W=None: <S> CHECKSIG (T18 as
    specified). W given: <W> CSV DROP <S> CHECKSIG (the notice moved onto T)."""
    sc = CScript(([W, OP_CHECKSEQUENCEVERIFY, OP_DROP] if W is not None else []) + [s_x, OP_CHECKSIG])
    tap = taproot_construct(NUMS, [("spend", sc)])
    return tap, {"spend": sc}


def clock_chain(T_id, R_spk, s_x, expiries):
    """Clocks built last first. clock j: ROLL(j) -> clock j+1 (none for the
    last), RELEASE(j) at E(j) -> R. Each pins the output at its own input index
    to (T, 1, next script). Witness for both paths: <sig_S>."""
    K = len(expiries)
    out = [None] * K
    nxt = None
    for j in reversed(range(K)):
        release = CScript([expiries[j], OP_CHECKLOCKTIMEVERIFY, OP_DROP, s_x, OP_CHECKSIGVERIFY]
                          + pin_current_output(T_id, 1, R_spk))
        lv = {"release": release}
        if nxt is not None:
            roll = CScript([s_x, OP_CHECKSIGVERIFY] + pin_current_output(T_id, 1, nxt["spk"]))
            lv["roll"] = roll
            tap = taproot_construct(NUMS, [("roll", roll), ("release", release)])
        else:
            tap = taproot_construct(NUMS, [("release", release)])
        out[j] = {"tap": tap, "lv": lv, "spk": bytes(tap.scriptPubKey), "E": expiries[j], "j": j}
        nxt = out[j]
    return out


def client_check_round(tx, T_hex, clock0_spk):
    """What a wallet checks in the round transaction before accepting a leaf.
    `tx` is the CTransaction; T_hex the asset id the tree names (display hex).
    Returns a list of failures (empty = accept)."""
    fails = []
    issuing = [i for i, vin in enumerate(tx.vin) if not vin.assetIssuance.isNull()]
    if len(issuing) != 1:
        fails.append("expected exactly one issuance input, found %d" % len(issuing))
        return fails
    iss = tx.vin[issuing[0]].assetIssuance
    if iss.assetBlindingNonce != 0:
        fails.append("issuance is a reissuance")
    amt = iss.nAmount.vchCommitment
    if not amt or amt[0] != 1:
        fails.append("issued amount is not explicit")
    elif iss.nAmount.getAmount() != 1:
        fails.append("issued amount is %d atoms, not 1" % iss.nAmount.getAmount())
    if not iss.nInflationKeys.isNull():
        keys = iss.nInflationKeys.vchCommitment
        if keys[0] != 1 or iss.nInflationKeys.getAmount() != 0:
            fails.append("issuance creates a reissuance token")
    T_out = b"\x01" + bytes.fromhex(T_hex)[::-1]
    holding = [(i, o) for i, o in enumerate(tx.vout) if o.nAsset.vchCommitment == T_out]
    if len(holding) != 1:
        fails.append("T appears in %d explicit outputs, expected 1" % len(holding))
    else:
        i, o = holding[0]
        if o.nValue.vchCommitment[0] != 1 or o.nValue.getAmount() != 1:
            fails.append("T output is not one explicit atom")
        if bytes(o.scriptPubKey) != bytes(clock0_spk):
            fails.append("T does not sit in the first clock")
    # any output whose asset is blinded could be hiding T
    if any(o.nAsset.vchCommitment[:1] in (b"\x0a", b"\x0b") for o in tx.vout):
        fails.append("a blinded asset output exists; T could be hidden in it")
    return fails


# --------------------------------------------------------------------------
# T19: reclaim
# --------------------------------------------------------------------------

def release_prefix(genesis_internal, children):
    """The fixed part of a release: "Arca/release" || genesis_hash || H (76
    bytes), the genesis hash in internal byte order. RECLAIM pushes it."""
    return RTAG + genesis_internal + children_hash(children)


def release_msg(genesis_internal, children, m):
    """The release an owner signs: SHA256("Arca/release" || genesis_hash || H
    || M), M the connector asset (internal byte order) of the round that made
    the owner's new leaf."""
    assert len(m) == 32
    return sha256(release_prefix(genesis_internal, children) + m)


def reclaim_leaf(prefix, owners, s_x):
    """RECLAIM: each owner i's signature over SHA256(prefix || M_i), M_i the
    asset of the input k_i names, read explicitly; then S's signature.
    Witness (bottom -> top): <sig_S> <sig_{n-1}> <k_{n-1}> ... <sig_0> <k_0>.
    One owner: the prefix is pushed in place, with no alt stack."""
    read_m = [OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY]
    if len(owners) == 1:
        s = read_m + [prefix, OP_SWAP, OP_CAT, OP_SHA256, owners[0], OP_CHECKSIGFROMSTACKVERIFY]
    else:
        s = [prefix, OP_TOALTSTACK]
        for k in owners[:-1]:
            s += read_m + [OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK, OP_SWAP, OP_CAT, OP_SHA256,
                           k, OP_CHECKSIGFROMSTACKVERIFY]
        s += read_m + [OP_FROMALTSTACK, OP_SWAP, OP_CAT, OP_SHA256, owners[-1], OP_CHECKSIGFROMSTACKVERIFY]
    return CScript(s + [s_x, OP_CHECKSIG])


def reclaim_items(s_sig, owner_sigs, ks):
    """The items below RECLAIM: owner_sigs and ks in owner order 0..n-1, so
    owner 0's pair ends on top."""
    below = [s_sig]
    for sig, k in reversed(list(zip(owner_sigs, ks))):
        below += [sig, sn(k)]
    return below


# --------------------------------------------------------------------------
# T20: notice
# --------------------------------------------------------------------------

def pending_taptree(children, s_x, W):
    unroll = CScript(unroll_compact_body(children))
    final = CScript([W, OP_CHECKSEQUENCEVERIFY, OP_DROP, s_x, OP_CHECKSIG])
    tap = taproot_construct(NUMS, [("unroll", unroll), ("final", final)])
    return tap, {"unroll": unroll, "final": final}


def sweep_start(T_id, R_prog, s_x, asset, value, pending_spk):
    """Batch output's sweep, as specified: token check, then the output at this
    input's index must be the whole value under PENDING. Witness <sig_S> <k>."""
    return CScript(token_check(T_id, R_prog) + pin_current_output(asset, value, pending_spk, verify=True)
                   + [s_x, OP_CHECKSIG])


# --------------------------------------------------------------------------
# Mixin: time, issuance, generic spends
# --------------------------------------------------------------------------

class Ark3:
    def generate(self, *a, **k):
        """Mine, then wait until -txindex has caught up with the tip (it is
        asynchronous; getrawtransaction on a just-mined tx can otherwise fail)."""
        import time
        r = super().generate(*a, **k)
        for _ in range(200):
            i = self.nodes[0].getindexinfo("txindex").get("txindex", {})
            if i.get("synced") and i.get("best_block_height") == self.nodes[0].getblockcount():
                break
            time.sleep(0.05)
        return r

    def genesis_internal(self):
        return bytes.fromhex(self.node.getblockhash(0))[::-1]

    # -- median time -----------------------------------------------------
    def mtp(self):
        return self.node.getblockheader(self.node.getbestblockhash())["mediantime"]

    def clock_start(self):
        self.mock = max(int(self.node.getblockheader(self.node.getbestblockhash())["time"]) + 1,
                        getattr(self, "mock", 0))
        self.node.setmocktime(self.mock)

    def tick(self, n=1, step=60):
        for _ in range(n):
            self.mock += step
            self.node.setmocktime(self.mock)
            self.generate(self.node, 1)

    def mtp_past(self, t, step=1800):
        """Mine until the tip's median time past is strictly greater than t."""
        while self.mtp() <= t:
            gap = t - self.mtp()
            self.tick(1, step=max(60, min(step, gap // 6 + 60)))

    def csv_ready_at(self, txid, seconds):
        """Earliest tip-MTP at which an input spending an output of `txid` with
        a time-based relative lock of `seconds` is final (BIP68)."""
        h = self.node.getrawtransaction(txid, True)["blockhash"]
        height = self.node.getblockheader(h)["height"]
        cointime = self.node.getblockheader(self.node.getblockhash(height - 1))["mediantime"]
        units = (seconds + 511) // 512
        return cointime + units * 512 - 1          # final once tip MTP > this

    def wait_csv(self, txid, seconds):
        self.mtp_past(self.csv_ready_at(txid, seconds))

    # -- an issuing round ------------------------------------------------
    def issuing_input(self, w, amount=1, keys=0, entropy=0, denomination=0):
        iss = CAssetIssuance()
        iss.assetBlindingNonce = 0
        iss.assetEntropy = entropy
        iss.nAmount = _Val(amount)
        iss.nInflationKeys = _Val(keys) if keys else _Val()
        iss.denomination = denomination
        return iss

    def issued_ids(self, tx, vin=0):
        d = self.node.decoderawtransaction(tx.serialize().hex())
        i = d["vin"][vin]["issuance"]
        return i["asset"], i.get("token")

    def stx(self, ins, outs, locktime=0):
        """mktx + nVersion 2; same as mktx but lets callers set sequences."""
        return self.mktx(ins, outs, locktime)

    def spend_path(self, u, tap, name, stack_below, outs, locktime=0, seq=None, extra_ins=(), sign_with=None,
                   wallet=False):
        """Spend utxo u (input 0) by script path `name`. stack_below: witness
        items below the script (bottom -> top). If sign_with=(sec, pos) a BIP340
        signature over the tx is inserted at position pos of stack_below."""
        s = (seq if seq is not None else (0xfffffffe if locktime else 0xffffffff))
        tx = self.mktx([(u, s)] + list(extra_ins), outs, locktime)
        leaf = tap.leaves[name].script
        st = list(stack_below)
        if sign_with is not None:
            sec, pos = sign_with
            st.insert(pos, self.sign(sec, tx, 0, leaf))
        self.setwit(tx, 0, st + [bytes(leaf), control_block(tap, name)])
        return self.wallet_sign(tx) if wallet else tx


# --------------------------------------------------------------------------
# Generic tree builder (round 3)
# --------------------------------------------------------------------------

def build_tree3(asset_id, leaf_spks, leaf_value, radix, reserve, scripts_fn):
    """Bottom-up covenant tree. scripts_fn(kids, child_tuples, level, is_root)
    returns an ordered taptree list [(name, script), ...] (or nested) and a dict
    of the scripts by name. Node: {spk, value, kind:'node', tap, leaves, children,
    level, is_root}; leaf: {spk, value, kind:'leaf', idx}."""
    level = [{"spk": bytes(spk), "value": leaf_value, "kind": "leaf", "idx": i}
             for i, spk in enumerate(leaf_spks)]
    lvl = 1
    while len(level) > 1:
        nxt = []
        is_root = (len(level) + radix - 1) // radix == 1
        for j in range(0, len(level), radix):
            kids = level[j:j + radix]
            tuples = [(asset_id, k["value"], k["spk"][2:]) for k in kids]
            tree, lv = scripts_fn(kids, tuples, lvl, is_root)
            tap = taproot_construct(NUMS, tree)
            nxt.append({"spk": bytes(tap.scriptPubKey), "value": sum(k["value"] for k in kids) + reserve,
                        "kind": "node", "tap": tap, "leaves": lv, "children": kids, "level": lvl,
                        "is_root": is_root})
        level = nxt
        lvl += 1
    return level[0]


def _assemble(self, ins, outs, spends, locktime=0, wallet=False, version=2):
    """ins: [Utxo | (Utxo, nSequence)]; spends: {idx: (tap, name, below, sec, pos)}.
    Script-path witnesses: below (bottom -> top) with a BIP340 signature by
    `sec` inserted at position `pos` (sec None: no signature), then script and
    control block. Wallet inputs are signed last when wallet=True."""
    tx = self.mktx(ins, outs, locktime, version)
    for idx, (tap, name, below, sec, pos) in spends.items():
        leaf = tap.leaves[name].script
        st = list(below)
        if sec is not None:
            st.insert(pos, self.sign(sec, tx, idx, leaf))
        self.setwit(tx, idx, st + [bytes(leaf), control_block(tap, name)])
    return self.wallet_sign(tx) if wallet else tx


Ark3.assemble = _assemble


def clock_schedule_check(T_id, R_spk, s_x, expiries, clock0_spk, min_first=None):
    """Client check on the clock chain: rebuild it from the published schedule
    and compare with the script the round pays T to. Returns failures."""
    fails = []
    if any(b < a for a, b in zip(expiries, expiries[1:])):
        fails.append("clock schedule is not non-decreasing: %s" % (expiries,))
    if min_first is not None and expiries[0] < min_first:
        fails.append("first expiry %d earlier than the advertised %d" % (expiries[0], min_first))
    if clock_chain(T_id, R_spk, s_x, expiries)[0]["spk"] != bytes(clock0_spk):
        fails.append("first clock script does not match the schedule rebuilt from (T, R, S, E)")
    return fails


def _issuing_round(self, value, build, label, asset=None, asset_out=None, change=5000, fee=1000, keep=None):
    """Round that issues one explicit atom of a new asset T (no token).
    build(T_id) -> (root_spk, clock0_spk); the round pays `value` of the batch
    asset to root_spk at output 0 and T to clock0_spk at output 1."""
    asset, asset_out = asset or self.X, asset_out or self.X_OUT
    w = self.wallet_utxo(value + change + fee, asset)
    sk = self.mktx([w], [self.out(1, self.wallet_spk(), asset_out)])
    sk.vin[0].assetIssuance = self.issuing_input(w)
    T_hex = self.issued_ids(sk)[0]
    T_id = bytes.fromhex(T_hex)[::-1]
    root_spk, clock0_spk = build(T_id)
    T_OUT = b"\x01" + T_id
    tx = self.mktx([w], [self.out(value, root_spk, asset_out), self.out(1, clock0_spk, T_OUT),
                         self.out(change, self.wallet_spk(), asset_out), self.fee(fee, asset_out)])
    tx.vin[0].assetIssuance = self.issuing_input(w)
    tx = self.wallet_sign(tx)
    txid = self.send(tx, label)
    return {"T_hex": T_hex, "T_id": T_id, "T_OUT": T_OUT, "txid": txid, "tx": tx,
            "root_u": self.utxo_at(txid, 0), "T_u": self.utxo_at(txid, 1)}


Ark3.issuing_round = _issuing_round


def tree_value(nleaves, leaf_value, radix, reserve):
    n, total, lvl = nleaves, nleaves * leaf_value, nleaves
    while lvl > 1:
        lvl = (lvl + radix - 1) // radix
        total += lvl * reserve
    return total


# --------------------------------------------------------------------------
# The remaining frozen constructions, on the frozen message and the token
# sweep: the hash-locked entry, the forfeit output, the checkpoint output, the
# burn-only sweep and htlc-1. Their scripts are exported as golden vectors by
# vectors.py.
# --------------------------------------------------------------------------

BURN_SPK = bytes([0x6a])                  # a bare OP_RETURN


def hash_gate(h):
    """A 32-byte preimage of h, taken from the witness."""
    return [OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY]


def burn_sweep(T_id, R_prog, s_x, W=None):
    """Burn-only sweep: the token check, the notice when W is given, then the
    output at this input's index must be a bare OP_RETURN carrying this
    input's full amount of this input's asset. Witness: <sig_S> <k>."""
    c = OP_PUSHCURRENTINPUTINDEX
    s = token_check(T_id, R_prog)
    if W is not None:
        s += [W, OP_CHECKSEQUENCEVERIFY, OP_DROP]
    s += [c, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY,
          c, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
          c, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY,
          c, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
          c, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1NEGATE, OP_EQUALVERIFY, sha256(BURN_SPK), OP_EQUALVERIFY,
          s_x, OP_CHECKSIG]
    return CScript(s)


def entry_taptree(h, asset_id, value, leaf_prog, sweep):
    """Hash-locked entry: unlock = a preimage of h moves the whole entry into
    output 0 = (asset, value, the owner's leaf); sweep = the batch's sweep with
    notice. Witness for unlock: <preimage>."""
    unlock = CScript(hash_gate(h) + unroll_body([(asset_id, value, leaf_prog)]))
    tap = taproot_construct(NUMS, [("unlock", unlock), ("sweep", sweep)])
    return tap, {"unlock": unlock, "sweep": sweep}


def forfeit_taptree(h, a_x, s_x, delay, leaf_id, connector):
    """Forfeit output, bound to the leaf it replaces and to its round:
    claim = the leaf id (pushed and dropped), an input k holding the connector
    asset M explicitly (k from the witness), the preimage of h and S's
    signature; refund = A after the relative delay. Claim witness, bottom to
    top: <sig_S> <preimage> <k>. `connector` is M's id in internal byte order."""
    claim = CScript([leaf_id, OP_DROP, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY, connector, OP_EQUALVERIFY]
                    + hash_gate(h) + [s_x, OP_CHECKSIG])
    refund = exit_leaf(a_x, delay)
    tap = taproot_construct(NUMS, [("claim", claim), ("refund", refund)])
    return tap, {"claim": claim, "refund": refund}


def board_taptree(a_x, s_x, salt, ctag, asset_id, value, leaf_prog):
    """board-1: collab = the leaf's own collaborative path, the very script
    the leaf carries, so one pair spends the coin as the board or as the leaf;
    convert = A's signature, then output 0 = (asset, value, the leaf).
    Witness for convert: <sig_A>."""
    collab = collab3_loop(a_x, s_x, salt, ctag, fold=True)
    convert = CScript([a_x, OP_CHECKSIGVERIFY] + unroll_body([(asset_id, value, leaf_prog)]))
    tap = taproot_construct(NUMS, [("collab", collab), ("convert", convert)])
    return tap, {"collab": collab, "convert": convert}


def connector_taptree(s_x):
    """The round's connector output: one leaf, spent only by the operator and
    only by issuing, on that input, one explicit atom of the asset it issues
    with a zero contract hash (the round's connector asset M), with no
    reissuance token. OP_INSPECTINPUTISSUANCE leaves, bottom to top: the
    reissuance token amount and its prefix, the amount and its prefix, the
    entropy, the blinding nonce. Witness: <sig_S>."""
    issue = CScript([s_x, OP_CHECKSIGVERIFY, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTISSUANCE,
                     bytes(32), OP_EQUALVERIFY,              # blinding nonce: a new issuance
                     bytes(32), OP_EQUALVERIFY,              # entropy: a zero contract hash
                     OP_1, OP_EQUALVERIFY, (1).to_bytes(8, "little"), OP_EQUALVERIFY,   # one explicit atom
                     OP_1, OP_EQUALVERIFY, bytes(8), OP_EQUAL])                         # no reissuance token
    tap = taproot_construct(NUMS, [("issue", issue)])
    return tap, {"issue": issue}


def checkpoint_taptree(a_x, s_x, salt, ctag, sweep):
    """Checkpoint output: the leaf's collaborative path with the checkpoint's
    own salt, and the sweep with notice of its batch."""
    collab = collab3_loop(a_x, s_x, salt, ctag, fold=True)
    tap = taproot_construct(NUMS, [("collab", collab), ("sweep", sweep)])
    return tap, {"collab": collab, "sweep": sweep}


def htlc_taptree(a_x, s_x, salt, ctag, h, timeout, exit_delay, operator_delay, receive=False):
    """htlc-1: a leaf whose exit is replaced by a hash-locked pair.

      collab  the leaf's collaborative path, the very script vtxo-1 carries
              under this leaf's own salt          <sig_S> <sig_A> <m>
      claim   <delay> CSV DROP, a 32-byte preimage of h, the claimer's
              signature                           <sig> <preimage>
      refund  <timeout> CLTV DROP <delay> CSV DROP, the refunder's
              signature                           <sig>

    A payment out of the tree (receive=False): the operator claims after
    `operator_delay`, the owner refunds after the timeout and `exit_delay`.
    A payment into it (receive=True): the owner claims after `exit_delay`,
    the operator refunds after the timeout and `operator_delay`. Either way
    the operator's path waits less than the owner's, so the side that holds
    the preimage, or that waited out the timeout, always has the time between
    the two delays to answer once the output is on-chain; and the
    collaborative path, which waits for nothing, answers both. Delays are
    CSV operands (rel_time); the timeout is a median time."""
    collab = collab3_loop(a_x, s_x, salt, ctag, fold=True)
    claimer, claim_delay = (a_x, exit_delay) if receive else (s_x, operator_delay)
    refunder, refund_delay = (s_x, operator_delay) if receive else (a_x, exit_delay)
    claim = CScript([claim_delay, OP_CHECKSEQUENCEVERIFY, OP_DROP] + hash_gate(h) + [claimer, OP_CHECKSIG])
    refund = CScript([timeout, OP_CHECKLOCKTIMEVERIFY, OP_DROP, refund_delay, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                      refunder, OP_CHECKSIG])
    tap = taproot_construct(NUMS, [("collab", collab), [("claim", claim), ("refund", refund)]])
    return tap, {"collab": collab, "claim": claim, "refund": refund}


def node_taptree3(unroll, sweep, reclaim=None):
    """A tree node: [UNROLL, SWEEP], or for a lowest node [UNROLL, [SWEEP, RECLAIM]]."""
    if reclaim is None:
        tap = taproot_construct(NUMS, [("unroll", unroll), ("sweep", sweep)])
        return tap, {"unroll": unroll, "sweep": sweep}
    tap = taproot_construct(NUMS, [("unroll", unroll), [("sweep", sweep), ("reclaim", reclaim)]])
    return tap, {"unroll": unroll, "sweep": sweep, "reclaim": reclaim}


# --------------------------------------------------------------------------
# A round's connector asset, issued for real (T19, T21)
# --------------------------------------------------------------------------

OP_TRUE_TAP = taproot_construct(NUMS, [("op_true", CScript([OP_1]))])
OP_TRUE_SPK = bytes(OP_TRUE_TAP.scriptPubKey)
OP_TRUE_WITNESS = [bytes(CScript([OP_1])), control_block(OP_TRUE_TAP, "op_true")]


def _connector_atom(self, s_sec, label, asset=None, asset_out=None, value=5_000, fee=1_000):
    """A round's connector asset M, issued as the operator issues it: a
    transaction standing for the round pays the connector output, then the
    operator spends that output by its one leaf, issuing one explicit atom of M
    (a zero contract hash, no reissuance token) to an OP_1 tapscript anyone can
    spend. Returns M (internal byte order), its asset prefix form, the atom's
    utxo, and the stand-in round's txid and connector index."""
    asset, asset_out = asset or self.X, asset_out or self.X_OUT
    s_x = compute_xonly_pubkey(s_sec)[0]
    ctap, clv = connector_taptree(s_x)
    round_u = self.fund(ctap.scriptPubKey, value, asset)
    tx = self.mktx([round_u], [self.out(1, OP_TRUE_SPK, b"\x01" + bytes(32)),
                               self.out(value - fee, OP_TRUE_SPK, asset_out), self.fee(fee, asset_out)])
    tx.vin[0].assetIssuance = self.issuing_input(round_u)
    m_hex = self.issued_ids(tx)[0]
    m_id = bytes.fromhex(m_hex)[::-1]
    tx.vout[0].nAsset = CTxOutAsset(b"\x01" + m_id)
    self.setwit(tx, 0, [self.sign(s_sec, tx, 0, clv["issue"]), bytes(clv["issue"]), control_block(ctap, "issue")])
    txid = self.send(tx, label)
    return {"M_id": m_id, "M_OUT": b"\x01" + m_id, "M_u": self.utxo_at(txid, 0), "round_txid": round_u.txid,
            "round_vout": round_u.vout}


Ark3.connector_atom = _connector_atom
