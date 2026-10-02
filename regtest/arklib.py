#!/usr/bin/env python3
"""Shared helpers for Arca's regtest suite.

The suite drives a Sequentia node through the node's own functional test
framework, imported read-only from the node source tree named by
SEQUENTIA_DIR. Nothing is written into that tree: bytecode writing is
disabled and every data directory lives under the test's --tmpdir. The node
binary is the one the framework is given (`run` passes SEQUENTIAD_EXEC).
"""
import sys
sys.dont_write_bytecode = True
import os as _os_env
REPO = _os_env.environ.get("SEQUENTIA_DIR")
if not REPO or not _os_env.path.isdir(_os_env.path.join(REPO, "test", "functional", "test_framework")):
    sys.exit("SEQUENTIA_DIR must name a Sequentia node source tree (it provides "
             "test/functional/test_framework); see regtest/README.md")
sys.path.insert(0, REPO + "/test/functional")

import json
import os
import hashlib
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import BITCOIN_ASSET
from test_framework.address import program_to_witness
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.messages import (
    COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxOutAsset,
    CTxOutNonce, CTxOutValue, CTxOutWitness, uint256_from_str, tx_from_hex,
)
from test_framework.script import (
    CScript, CScriptOp, taproot_construct, TaprootSignatureHash,
    OP_0, OP_1, OP_1NEGATE, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGFROMSTACK, OP_CHECKSIGFROMSTACKVERIFY,
    OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK,
    OP_IF, OP_SHA256, OP_SIZE, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, OP_RETURN,
    OP_2, OP_ADD, OP_ROT, OP_WITHIN, OP_GREATERTHAN, OP_2DUP, OP_INSPECTNUMINPUTS,
    OP_INSPECTVERSION, OP_INSPECTINPUTSEQUENCE, OP_INSPECTOUTPUTNONCE, OP_NOTIF, OP_OVER, OP_NIP,
    OP_INSPECTINPUTVALUE, OP_INSPECTINPUTASSET, OP_PUSHCURRENTINPUTINDEX,
    OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTVALUE, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTNUMOUTPUTS, OP_INSPECTLOCKTIME,
    OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_SHA256FINALIZE,
)

PROTO = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.environ.get("ARCA_RESULTS") or os.path.join(PROTO, "results")

# BIP341 nothing-up-my-sleeve point: no known discrete log, so no key path.
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def sha256(b):
    return hashlib.sha256(b).digest()


def le8(n):
    assert 0 <= n < (1 << 63)
    return int(n).to_bytes(8, "little")


def asm(script):
    """Human-readable opcode form of a script."""
    out = []
    for el in CScript(script):
        if isinstance(el, CScriptOp):
            out.append(str(el))
        elif isinstance(el, int):
            out.append("OP_%d" % el if 0 <= el <= 16 else ("OP_1NEGATE" if el == -1 else str(el)))
        elif len(el) == 0:
            out.append("OP_0")
        elif len(el) <= 4:
            # a short push is a script number (timelock, size): show it in decimal
            b = bytes(el)
            n = int.from_bytes(b[:-1] + bytes([b[-1] & 0x7f]), "little")
            out.append("<%d>" % (-n if b[-1] & 0x80 else n))
        else:
            out.append("<%s>" % bytes(el).hex())
    return " ".join(out)


def control_block(tap, name):
    leaf = tap.leaves[name]
    return bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def wit_bytes(stack):
    """Serialized size of a witness stack (count + length-prefixed items)."""
    n = 1
    for it in stack:
        l = len(it)
        n += (1 if l < 253 else 3) + l
    return n


class Tx(CTransaction):
    """CTransaction without __slots__, so it can carry its prevouts (.prev)."""

    @classmethod
    def from_hex(cls, h):
        from io import BytesIO
        t = cls()
        t.deserialize(BytesIO(bytes.fromhex(h)))
        return t


class Utxo:
    def __init__(self, txid, vout, txout):
        self.txid, self.vout, self.txout = txid, vout, txout

    @property
    def amount(self):
        return self.txout.nValue.getAmount()

    @property
    def spk(self):
        return bytes(self.txout.scriptPubKey)

    def __repr__(self):
        return "Utxo(%s:%d)" % (self.txid, self.vout)


# --------------------------------------------------------------------------
# Script constructions
# --------------------------------------------------------------------------

def unroll_body(children, final_equal=True):
    """T1(a) UNROLL, plain form. children = [(asset32, value_atoms, prog32)].

    Output i (i = 0..r-1) must carry exactly: explicit asset == pinned id,
    explicit value == pinned amount, scriptPubKey == witness v1 <prog>.
    No signature, no witness data. Nothing else in the tx is constrained.
    """
    s = []
    n = len(children)
    for i, (asset, value, prog) in enumerate(children):
        assert len(asset) == 32 and len(prog) == 32
        s += [i, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset, OP_EQUALVERIFY]
        s += [i, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(value), OP_EQUALVERIFY]
        last = OP_EQUAL if (final_equal and i == n - 1) else OP_EQUALVERIFY
        s += [i, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, prog, last]
    return s


def child_blob(asset, value, prog, ver=1):
    """ROUND-1 record, kept only to demonstrate its flaw (see T1c):
    asset(32)||0x01 || value_le8||0x01 || program(32)||version.
    The version is a script number, so witness v0 contributes NO byte: a v0
    output with the 33-byte program `program||0x01` yields the same bytes."""
    return asset + b"\x01" + le8(value) + b"\x01" + prog + bytes([ver])


def record_ops(i):
    """Script fragment leaving the INJECTIVE record of output i on the stack:
        asset(32) || asset_prefix(1) || value_prefix(1) || value(8 or 32)
                  || program || (witness_version + 2)(1)
    Prefix-before-value makes the value self-delimiting; version+2 is always
    exactly one non-zero byte (-1 -> 0x01, v0 -> 0x02, v1 -> 0x03 ...), so the
    program's length is the remainder and no two outputs share a record."""
    return [i, OP_INSPECTOUTPUTASSET, OP_CAT,
            i, OP_INSPECTOUTPUTVALUE, OP_SWAP, OP_CAT, OP_CAT,
            i, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_2, OP_ADD, OP_CAT, OP_CAT]


def record(asset, value, spk):
    """Off-chain mirror of record_ops for an EXPLICIT output paying `spk`."""
    spk = bytes(spk)
    # A witness program as the node reads it (CScript::IsWitnessProgram): 4 to
    # 42 bytes, a version opcode, then one push that fills the rest.
    if 4 <= len(spk) <= 42 and (spk[0] == 0 or 0x51 <= spk[0] <= 0x60) and spk[1] == len(spk) - 2:
        ver, prog = (0 if spk[0] == 0 else spk[0] - 0x50), spk[2:]
    else:
        ver, prog = -1, sha256(spk)
    return asset + b"\x01" + b"\x01" + le8(value) + prog + bytes([ver + 2])


def unroll_compact_v1_body(children, final_equal=True):
    """ROUND-1 compact form (ambiguous record) -- for the T1c demonstration only."""
    s = []
    blob = b""
    for i, (asset, value, prog) in enumerate(children):
        s += [i, OP_INSPECTOUTPUTASSET, OP_CAT]
        s += [i, OP_INSPECTOUTPUTVALUE, OP_CAT, OP_CAT]
        s += [i, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_CAT, OP_CAT]
        if i > 0:
            s += [OP_CAT]
        blob += child_blob(asset, value, prog)
    s += [OP_SHA256, sha256(blob), OP_EQUAL if final_equal else OP_EQUALVERIFY]
    return s


def children_hash(children):
    """H = SHA256 of the concatenated injective records of the children."""
    return sha256(b"".join(record(a, v, bytes([0x51, 0x20]) + p) for a, v, p in children))


def unroll_compact_body(children, final_equal=True, tail=True):
    """T1(a) UNROLL, compact form: concatenate the injective records of outputs
    0..r-1 with OP_CAT, SHA256, compare with ONE 32-byte constant. The 520-byte
    stack element limit caps this at r <= 6."""
    s = []
    for i in range(len(children)):
        s += record_ops(i)
        if i > 0:
            s += [OP_CAT]
    assert 75 * len(children) <= 520, "OP_CAT result would exceed 520 bytes"
    s += [OP_SHA256]
    if tail:
        s += [children_hash(children), OP_EQUAL if final_equal else OP_EQUALVERIFY]
    return s


def unroll_stream_body(children, final_equal=True):
    """Compact form with the streaming SHA256 opcodes, for radix > 6."""
    s = []
    assert len(children) >= 2
    for i in range(len(children)):
        s += record_ops(i)
        if i == 0:
            s += [OP_SHA256INITIALIZE]
        elif i < len(children) - 1:
            s += [OP_SHA256UPDATE]
        else:
            s += [OP_SHA256FINALIZE]
    s += [children_hash(children), OP_EQUAL if final_equal else OP_EQUALVERIFY]
    return s


def sweep_leaf(expiry, s_x):
    """T1(b) SWEEP: <expiry> CLTV DROP <S> CHECKSIG."""
    return CScript([expiry, OP_CHECKLOCKTIMEVERIFY, OP_DROP, s_x, OP_CHECKSIG])


def node_taptree(children, expiry, s_x, form="plain"):
    body = {"plain": unroll_body, "compact": unroll_compact_body,
            "compact_v1": unroll_compact_v1_body,
            "stream": unroll_stream_body}[form](children)
    unroll = CScript(body)
    sweep = sweep_leaf(expiry, s_x)
    tap = taproot_construct(NUMS, [("unroll", unroll), ("sweep", sweep)])
    return tap, {"unroll": unroll, "sweep": sweep}


def leaf_taptree(a_x, s_x, delay, expiry):
    """T2 LEAF (the user's virtual output).
      collab : <A> CHECKSIGVERIFY <S> CHECKSIG
      exit   : <delay> CSV DROP <A> CHECKSIG
      sweep  : <expiry> CLTV DROP <S> CHECKSIG
    """
    collab = CScript([a_x, OP_CHECKSIGVERIFY, s_x, OP_CHECKSIG])
    exit_ = CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, a_x, OP_CHECKSIG])
    sweep = sweep_leaf(expiry, s_x)
    tap = taproot_construct(NUMS, [("collab", collab), [("exit", exit_), ("sweep", sweep)]])
    return tap, {"collab": collab, "exit": exit_, "sweep": sweep}


# --------------------------------------------------------------------------
# Framework base
# --------------------------------------------------------------------------

class ArkBase:
    """Mixin: use as `class T(ArkBase, BitcoinTestFramework)` and define
    set_test_params (calling self.ark_params()) and run_test in the subclass --
    the framework's metaclass insists both live in the concrete class."""
    NAME = "base"
    EXTRA = []

    def ark_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-initialfreecoins=2100000000000000",
            "-anyonecanspendaremine=1",
            "-blindedaddresses=0",
            "-con_default_blinded_addresses=0",
            "-validatepegin=0",
            "-con_parent_chain_signblockscript=51",
            "-con_any_asset_fees=1",
            "-maxtxfee=100.0",
            "-txindex=1",
        ] + list(self.EXTRA)]
        self.R = {}          # results, dumped as JSON

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()

    # -- results ---------------------------------------------------------
    def rec(self, key, value):
        self.R[key] = value
        self.dump()

    def dump(self):
        os.makedirs(RESULTS, exist_ok=True)
        with open(os.path.join(RESULTS, self.NAME + ".json"), "w") as f:
            json.dump(self.R, f, indent=1, default=str)

    # -- chain bootstrap -------------------------------------------------
    def boot(self, issue=("X", "Y")):
        node = self.nodes[0]
        self.node = node
        self.generate(node, 101)
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000,
                           fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        self.genesis = uint256_from_str(bytes.fromhex(node.getblockhash(0))[::-1])
        self.POL = BITCOIN_ASSET
        self.POL_OUT = self.asset_out(BITCOIN_ASSET)
        self.assets = {}
        for name in issue:
            a = node.issueasset(assetamount=1000000, tokenamount=0, blind=False,
                                fee_asset=BITCOIN_ASSET)["asset"]
            self.generate(node, 1)
            self.assets[name] = a
            setattr(self, name, a)
            setattr(self, name + "_OUT", self.asset_out(a))
            setattr(self, name + "_ID", bytes.fromhex(a)[::-1])
        self.rates0 = node.getfeeexchangerates()
        self.log.info("fee whitelist at boot: %s", self.rates0)

    def whitelist(self, *assets):
        """Fee whitelist = boot whitelist + the named assets at 1:1."""
        rates = dict(self.rates0)
        for a in assets:
            rates[a] = 100000000
        self.node.setfeeexchangerates(rates)
        return self.node.getfeeexchangerates()

    # -- output / utxo helpers ------------------------------------------
    @staticmethod
    def asset_out(display_hex):
        return b"\x01" + bytes.fromhex(display_hex)[::-1]

    @staticmethod
    def out(amount, spk, asset_out):
        return CTxOut(nValue=CTxOutValue(amount), scriptPubKey=spk,
                      nAsset=CTxOutAsset(asset_out), nNonce=CTxOutNonce())

    @staticmethod
    def fee(amount, asset_out):
        return CTxOut(nValue=CTxOutValue(amount), scriptPubKey=b"",
                      nAsset=CTxOutAsset(asset_out), nNonce=CTxOutNonce())

    def wallet_spk(self):
        a = self.node.getnewaddress("", "bech32")
        info = self.node.getaddressinfo(a)
        u = info.get("unconfidential", a)
        return bytes.fromhex(self.node.getaddressinfo(u)["scriptPubKey"])

    def utxo_of(self, txid, spk, hexraw=None):
        tx = tx_from_hex(hexraw or self.node.getrawtransaction(txid))
        for i, o in enumerate(tx.vout):
            if bytes(o.scriptPubKey) == bytes(spk):
                return Utxo(txid, i, o)
        raise AssertionError("spk not found in " + txid)

    def utxo_at(self, txid, vout):
        tx = tx_from_hex(self.node.getrawtransaction(txid))
        return Utxo(txid, vout, tx.vout[vout])

    def fund(self, spk, atoms, asset, mine=True):
        """Pay `atoms` of `asset` to a witness-v1 spk from the wallet."""
        spk = bytes(spk)
        ver = 0 if spk[0] == 0 else spk[0] - 0x50
        addr = program_to_witness(ver, spk[2:])
        txid = self.node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN,
                                       assetlabel=asset, fee_asset_label=BITCOIN_ASSET)
        if mine:
            self.generate(self.node, 1)
        return self.utxo_of(txid, spk)

    def wallet_utxo(self, atoms, asset=None):
        """A fresh wallet-owned P2WPKH utxo of exactly `atoms`."""
        asset = asset or BITCOIN_ASSET
        spk = self.wallet_spk()
        return self.fund(spk, atoms, asset)

    # -- tx assembly -----------------------------------------------------
    def mktx(self, ins, outs, locktime=0, version=2):
        """ins: [Utxo] or [(Utxo, nSequence)]; outs: [CTxOut]."""
        tx = Tx()
        tx.nVersion = version
        tx.nLockTime = locktime
        self._prev = []
        for i in ins:
            u, seq = i if isinstance(i, tuple) else (i, 0xfffffffe if locktime else 0xffffffff)
            tx.vin.append(CTxIn(COutPoint(int(u.txid, 16), u.vout), nSequence=seq))
            self._prev.append(u)
        tx.vout = list(outs)
        self.pad(tx)
        tx.prev = list(self._prev)
        return tx

    @staticmethod
    def pad(tx):
        while len(tx.wit.vtxinwit) < len(tx.vin):
            tx.wit.vtxinwit.append(CTxInWitness())
        while len(tx.wit.vtxoutwit) < len(tx.vout):
            tx.wit.vtxoutwit.append(CTxOutWitness())

    def wallet_sign(self, tx):
        """Let the wallet sign its own inputs; covenant witnesses are kept."""
        prev = tx.prev
        saved = [list(w.scriptWitness.stack) for w in tx.wit.vtxinwit]
        r = self.node.signrawtransactionwithwallet(tx.serialize().hex())
        tx2 = Tx.from_hex(r["hex"])
        self.pad(tx2)
        for i, st in enumerate(saved):
            if st and not tx2.wit.vtxinwit[i].scriptWitness.stack:
                tx2.wit.vtxinwit[i].scriptWitness.stack = st
        tx2.prev = prev
        return tx2

    def sighash(self, tx, idx, leaf_script, hash_type=0):
        self.pad(tx)
        return TaprootSignatureHash(tx, [u.txout for u in tx.prev], hash_type,
                                    self.genesis, idx, scriptpath=True,
                                    script=CScript(leaf_script))

    def sign(self, sec, tx, idx, leaf_script):
        return sign_schnorr(sec, self.sighash(tx, idx, leaf_script))

    @staticmethod
    def setwit(tx, idx, stack):
        tx.wit.vtxinwit[idx].scriptWitness.stack = [bytes(x) for x in stack]

    # -- measuring / broadcasting ---------------------------------------
    def measure(self, tx):
        d = self.node.decoderawtransaction(tx.serialize().hex())
        m = {"size": d["size"], "vsize": d["vsize"], "weight": d["weight"],
             "nin": len(d["vin"]), "nout": len(d["vout"])}
        if "discountvsize" in d:
            m["discountvsize"] = d["discountvsize"]
        return m

    def accept(self, tx):
        return self.node.testmempoolaccept([tx.serialize().hex()])[0]

    def send(self, tx, label, mine=True, extra=None):
        """testmempoolaccept -> sendrawtransaction -> mine -> confirm. Records sizes."""
        m = self.measure(tx)
        res = self.accept(tx)
        m["testmempoolaccept"] = bool(res["allowed"])
        if not res["allowed"]:
            m["reject-reason"] = res.get("reject-reason")
            self.rec(label, m)
            raise AssertionError("%s not accepted: %s" % (label, res))
        if "fees" in res:
            m["fees"] = res["fees"]
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        m["txid"] = txid
        if mine:
            self.generate(self.node, 1)
            v = self.node.getrawtransaction(txid, True)
            assert v.get("confirmations", 0) >= 1, "not confirmed"
            m["confirmed"] = True
            m["block_height"] = self.node.getblockcount()
        if extra:
            m.update(extra)
        m["witness_input0_bytes"] = wit_bytes(tx.wit.vtxinwit[0].scriptWitness.stack)
        self.log.info("PASS %-44s vsize=%d weight=%d size=%d", label, m["vsize"], m["weight"], m["size"])
        self.rec(label, m)
        return txid

    def reject(self, tx, label, expect=None, consensus=True):
        """Assert a tx is rejected; record both the testmempoolaccept reason and
        the exact sendrawtransaction RPC error."""
        res = self.accept(tx)
        assert not res["allowed"], "%s unexpectedly ACCEPTED" % label
        reason = res.get("reject-reason", "")
        rpc = None
        try:
            self.node.sendrawtransaction(tx.serialize().hex())
            raise AssertionError("%s unexpectedly broadcast" % label)
        except JSONRPCException as e:
            rpc = "%s (code %s)" % (e.error["message"], e.error["code"])
        d = {"rejected": True, "reject-reason": reason, "rpc-error": rpc}
        if consensus:
            # Bypass mempool policy entirely: ask the node to build a block
            # containing the raw tx. A consensus-invalid tx makes block
            # assembly/validation fail; nothing is mined.
            h0 = self.node.getblockcount()
            try:
                self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()],
                                        invalid_call=False)
                raise AssertionError("%s: tx was MINED via generateblock (policy-only reject)" % label)
            except JSONRPCException as e:
                d["block-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
            assert self.node.getblockcount() == h0
        self.log.info("REJECT %-42s %s | block: %s", label, rpc, d.get("block-error"))
        if expect is not None:
            assert expect in reason or expect in rpc, (label, reason, rpc)
        self.rec(label, d)
        return reason

    def probe(self, tx, label):
        """Record what the mempool says, without asserting either way."""
        res = self.accept(tx)
        d = {"probe": True, "testmempoolaccept": bool(res["allowed"]),
             "reject-reason": res.get("reject-reason"), "vsize": self.measure(tx)["vsize"]}
        self.log.info("PROBE %-43s allowed=%s %s", label, d["testmempoolaccept"], d["reject-reason"])
        self.rec(label, d)
        return d

    def mine_raw(self, tx, label):
        """Mine a tx directly into a block (bypassing relay policy). Used to show
        a tx is consensus-valid even when policy refuses to relay it."""
        m = self.measure(tx)
        res = self.accept(tx)
        m["testmempoolaccept"] = bool(res["allowed"])
        m["reject-reason"] = res.get("reject-reason")
        self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
        tx.rehash()
        v = self.node.getrawtransaction(tx.hash, True)
        assert v.get("confirmations", 0) >= 1
        m["txid"] = tx.hash
        m["confirmed_via_generateblock"] = True
        self.log.info("MINED(raw) %-38s vsize=%d policy-allowed=%s (%s)", label, m["vsize"],
                      m["testmempoolaccept"], m["reject-reason"])
        self.rec(label, m)
        return tx.hash

    def rec_script(self, label, script, tap=None, name=None):
        d = {"asm": asm(script), "hex": bytes(script).hex(), "bytes": len(bytes(script))}
        if tap is not None:
            d["scriptPubKey"] = bytes(tap.scriptPubKey).hex()
            if name:
                d["control_block_bytes"] = len(control_block(tap, name))
        self.rec(label, d)
        return d

    def mine_to(self, height):
        n = height - self.node.getblockcount()
        if n > 0:
            self.generate(self.node, n)

    def p2tr(self, sec=None):
        """A plain key-path taproot spk for a random key (pinned-child stand-in)."""
        sec = sec or generate_privkey()
        x = compute_xonly_pubkey(sec)[0]
        tap = taproot_construct(x)
        return bytes(tap.scriptPubKey), sec


# --------------------------------------------------------------------------
# Tree builder (used by T3, T8, T9)
# --------------------------------------------------------------------------

def build_tree(asset_id, leaf_spks, leaf_value, radix, reserve, expiry, s_x, form="compact"):
    """Bottom-up covenant tree. Every node output = sum(children) + reserve.
    Returns the root node dict. Node: {spk,value,kind:'node',tap,leaves,children};
    leaf: {spk,value,kind:'leaf',idx}."""
    level = [{"spk": bytes(spk), "value": leaf_value, "kind": "leaf", "idx": i}
             for i, spk in enumerate(leaf_spks)]
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level), radix):
            kids = level[j:j + radix]
            tap, lv = node_taptree([(asset_id, k["value"], k["spk"][2:]) for k in kids],
                                   expiry, s_x, form)
            nxt.append({"spk": bytes(tap.scriptPubKey),
                        "value": sum(k["value"] for k in kids) + reserve,
                        "kind": "node", "tap": tap, "leaves": lv, "children": kids})
        level = nxt
    return level[0]


def _round_tx(self, spk, value, asset, asset_out, fee=300, change=5000, sign=True):
    """An explicit 'round' transaction: one wallet P2WPKH input of `asset`,
    outputs = [tree root, wallet change, fee]. Built by hand because the node
    wallet blinds its change whenever a tx has two change outputs (see report)."""
    w = self.wallet_utxo(value + change + fee, asset)
    tx = self.mktx([w], [self.out(value, bytes(spk), asset_out),
                         self.out(change, self.wallet_spk(), asset_out),
                         self.fee(fee, asset_out)])
    return self.wallet_sign(tx) if sign else tx


ArkBase.round_tx = _round_tx


# --------------------------------------------------------------------------
# Round 2: rebindable 2-of-2 collaborative leaf (T10-T12, T15)
# --------------------------------------------------------------------------
from test_framework.script import OP_TUCK   # noqa: E402

TAG = b"ArcaRbd1"          # fixed 8-byte domain tag
M_MAX = 4


def rebind_msg2(salt, outs, tag=TAG):
    """The 32-byte message both parties sign.
    outs = [(asset32, value_atoms, scriptPubKey)], the committed outputs 0..m-1.
        msg = SHA256( tag(8) || leaf_salt(32) || m(1) || SHA256(rec_0) || ... || SHA256(rec_{m-1}) )
    """
    assert len(tag) == 8 and len(salt) == 32 and 1 <= len(outs) <= 255
    acc = tag + salt + bytes([len(outs)])
    for asset, value, spk in outs:
        acc += sha256(record(asset, value, spk))
    return sha256(acc)


def _csfs_2of2(a_x, s_x):
    # [sig_S, sig_A, msg] -> bool.  CSFS is given the 32-byte msg itself.
    return [OP_TUCK, a_x, OP_CHECKSIGFROMSTACKVERIFY, s_x, OP_CHECKSIGFROMSTACK]


def collab_rebind_loop(a_x, s_x, salt, M=M_MAX, tag=TAG, prefix=()):
    """Bounded-loop form. Witness (bottom -> top): <sig_S> <sig_A> <m>, m = one
    byte 0x01..M. Outputs 0..m-1 are committed; everything else is free."""
    s = list(prefix)
    s += [OP_SIZE, OP_1, OP_EQUALVERIFY]                     # m is exactly one byte
    s += [OP_DUP, OP_1, M + 1, OP_WITHIN, OP_VERIFY]         # 1 <= m <= M
    s += [OP_DUP, tag + salt, OP_SWAP, OP_CAT, OP_SWAP]      # [acc = tag||salt||m, m]
    for j in range(M):
        slot = record_ops(j) + [OP_SHA256, OP_ROT, OP_SWAP, OP_CAT, OP_SWAP]
        if j == 0:
            s += slot
        else:
            s += [OP_DUP, j, OP_GREATERTHAN, OP_IF] + slot + [OP_ENDIF]
    s += [OP_DROP, OP_SHA256]                                # [sig_S, sig_A, msg]
    s += _csfs_2of2(a_x, s_x)
    return CScript(s)


def collab_rebind_fixed(a_x, s_x, salt, m, tag=TAG, prefix=()):
    """Fixed-m form (one leaf per m). Witness: <sig_S> <sig_A>."""
    s = list(prefix) + [tag + salt + bytes([m])]
    for j in range(m):
        s += record_ops(j) + [OP_SHA256, OP_CAT]
    s += [OP_SHA256] + _csfs_2of2(a_x, s_x)
    return CScript(s)


def rebind_leaf_taptree(a_x, s_x, salt, delay, expiry, family=False, M=M_MAX):
    """T10 leaf. Loop form: [collab, [exit, sweep]].
    Family form: [[collab1, collab2], [[collab3, collab4], [exit, sweep]]]."""
    exit_ = CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, a_x, OP_CHECKSIG])
    sweep = sweep_leaf(expiry, s_x)
    if not family:
        collab = collab_rebind_loop(a_x, s_x, salt, M)
        tap = taproot_construct(NUMS, [("collab", collab), [("exit", exit_), ("sweep", sweep)]])
        return tap, {"collab": collab, "exit": exit_, "sweep": sweep}
    assert M == 4
    c = {m: collab_rebind_fixed(a_x, s_x, salt, m) for m in (1, 2, 3, 4)}
    tap = taproot_construct(NUMS, [[("collab1", c[1]), ("collab2", c[2])],
                                   [[("collab3", c[3]), ("collab4", c[4])], [("exit", exit_), ("sweep", sweep)]]])
    lv = {"collab%d" % m: c[m] for m in c}
    lv.update({"exit": exit_, "sweep": sweep})
    return tap, lv


def checkpoint_taptree(a_x, s_x, salt, expiry, M=M_MAX):
    """T12 checkpoint output: [collab_rebind(new salt), sweep by S after expiry]."""
    collab = collab_rebind_loop(a_x, s_x, salt, M)
    sweep = sweep_leaf(expiry, s_x)
    tap = taproot_construct(NUMS, [("collab", collab), ("sweep", sweep)])
    return tap, {"collab": collab, "sweep": sweep}


def rebind_witness(tap, lv, sig_s, sig_a, m, family=False):
    if family:
        name = "collab%d" % m
        return [sig_s, sig_a, bytes(lv[name]), control_block(tap, name)]
    return [sig_s, sig_a, bytes([m]), bytes(lv["collab"]), control_block(tap, "collab")]


def _unroll_node_tx(self, u, n, asset_out, reserve, external=False, ext_in=50_000, ext_fee=1000):
    """Unroll one tree node `n` held at utxo `u`.
    external=False: the node's reserve becomes the fee output (1 input; the
                    'canonical' shape, deterministic txid for a given outpoint).
    external=True : a wallet input pays the fee in the policy asset; the reserve
                    goes to a change output (different txid)."""
    kids = [self.out(k["value"], k["spk"], asset_out) for k in n["children"]]
    wit = [bytes(n["leaves"]["unroll"]), control_block(n["tap"], "unroll")]
    if not external:
        tx = self.mktx([u], kids + [self.fee(reserve, asset_out)])
        self.setwit(tx, 0, wit)
        return tx
    w = self.wallet_utxo(ext_in)
    tx = self.mktx([u, w], kids + [self.out(reserve, self.wallet_spk(), asset_out),
                                   self.out(ext_in - ext_fee, self.wallet_spk(), self.POL_OUT),
                                   self.fee(ext_fee, self.POL_OUT)])
    self.setwit(tx, 0, wit)
    return self.wallet_sign(tx)


def _with_fee_input(self, covenant_ins, outs, leftover_out=None, ext_in=50_000, ext_fee=1000, locktime=0):
    """A tx whose first inputs are covenant inputs and whose LAST input is a
    wallet P2WPKH input paying the fee in the policy asset. `outs` come first
    (the committed ones), then optional leftover output, policy change, fee.
    Witnesses for the covenant inputs must be set by the caller BEFORE
    wallet-signing (wallet_sign keeps them)."""
    w = self.wallet_utxo(ext_in)
    extra = [leftover_out] if leftover_out is not None else []
    tx = self.mktx(list(covenant_ins) + [w], list(outs) + extra +
                   [self.out(ext_in - ext_fee, self.wallet_spk(), self.POL_OUT), self.fee(ext_fee, self.POL_OUT)],
                   locktime)
    return tx


ArkBase.unroll_node_tx = _unroll_node_tx
ArkBase.with_fee_input = _with_fee_input
