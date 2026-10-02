#!/usr/bin/env python3
"""T14 (comparison only): PINNED-RESERVE node. The unroll leaf also requires
output r to be the fee output in the batch asset with value exactly R, exactly
one input and exactly r+1 outputs. Then: is the txid really fixed, and what
happens when the asset is delisted?"""
from arklib import *
from test_framework.script import OP_INSPECTNUMINPUTS as NUMIN, OP_INSPECTVERSION, OP_INSPECTINPUTSEQUENCE, OP_INSPECTOUTPUTNONCE
import os as _os, struct

CHILD = 1_0000_0000
R_FEE = 700
EMPTY_SHA = sha256(b"")


def pinned_compact(children, asset_id, reserve, full=False):
    """Compact: the fee output is simply record r in the hashed blob."""
    r = len(children)
    s = []
    blob = b""
    for i, (a, v, p) in enumerate(children):
        s += record_ops(i) + ([OP_CAT] if i else [])
        blob += record(a, v, bytes([0x51, 0x20]) + p)
    s += record_ops(r) + [OP_CAT]
    blob += record(asset_id, reserve, b"")
    assert len(blob) <= 520
    s += [OP_SHA256, sha256(blob), OP_EQUALVERIFY]
    if full:
        s += _txid_pins(r)
    s += [NUMIN, OP_1, OP_EQUALVERIFY, OP_INSPECTNUMOUTPUTS, r + 1, OP_EQUAL]
    return CScript(s)


def pinned_plain(children, asset_id, reserve, full=False):
    r = len(children)
    s = unroll_body(children, final_equal=False)
    s += [r, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1NEGATE, OP_EQUALVERIFY, EMPTY_SHA, OP_EQUALVERIFY]
    s += [r, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset_id, OP_EQUALVERIFY]
    s += [r, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(reserve), OP_EQUALVERIFY]
    if full:
        s += _txid_pins(r)
    s += [NUMIN, OP_1, OP_EQUALVERIFY, OP_INSPECTNUMOUTPUTS, r + 1, OP_EQUAL]
    return CScript(s)


def _txid_pins(r):
    """What ELSE has to be pinned before the txid is really a function of the outpoint."""
    s = [OP_INSPECTVERSION, struct.pack("<I", 2), OP_EQUALVERIFY,
         OP_INSPECTLOCKTIME, struct.pack("<I", 0), OP_EQUALVERIFY,
         OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTSEQUENCE, struct.pack("<I", 0xffffffff), OP_EQUALVERIFY]
    for i in range(r + 1):                      # children AND the fee output
        s += [i, OP_INSPECTOUTPUTNONCE, OP_0, OP_EQUALVERIFY]
    return s


class T14(ArkBase, BitcoinTestFramework):
    NAME = "t14"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        s_x = compute_xonly_pubkey(generate_privkey())[0]
        expiry = node.getblockcount() + 5000
        r = 4
        total = r * CHILD + R_FEE

        def setup(builder, full):
            spks = [self.p2tr()[0] for _ in range(r)]
            kids = [(self.X_ID, CHILD, spk[2:]) for spk in spks]
            leaf = builder(kids, self.X_ID, R_FEE, full)
            tap = taproot_construct(NUMS, [("unroll", leaf), ("sweep", sweep_leaf(expiry, s_x))])
            return spks, leaf, tap

        def canon(u, spks, leaf, tap, locktime=0, seq=0xffffffff, version=2, nonce=None, fee=R_FEE, extra_out=None,
                  fee_nonce=None):
            outs = [self.out(CHILD, spk, self.X_OUT) for spk in spks]
            if nonce is not None:
                outs[0].nNonce = CTxOutNonce(nonce)
            if extra_out is not None:
                outs.append(extra_out)
            fo = self.fee(fee, self.X_OUT)
            if fee_nonce is not None:
                fo.nNonce = CTxOutNonce(fee_nonce)
            tx = self.mktx([(u, seq)], outs + [fo], locktime, version)
            self.setwit(tx, 0, [bytes(leaf), control_block(tap, "unroll")])
            tx.rehash()
            return tx

        def external(u, spks, leaf, tap):
            tx = self.with_fee_input([u], [self.out(CHILD, spk, self.X_OUT) for spk in spks],
                                     leftover_out=self.out(R_FEE, self.wallet_spk(), self.X_OUT))
            self.setwit(tx, 0, [bytes(leaf), control_block(tap, "unroll")])
            return self.wallet_sign(tx)

        for name, builder in (("compact", pinned_compact), ("plain", pinned_plain)):
            for full in (False, True):
                tag = "%s_%s" % (name, "fullpin" if full else "asbriefed")
                self.log.info("=== T14 %s ===", tag)
                spks, leaf, tap = setup(builder, full)
                self.rec_script(tag + "/unroll_leaf", leaf, tap, "unroll")
                u = self.fund(tap.scriptPubKey, total, self.X)
                good = canon(u, spks, leaf, tap)
                # shapes the pin must refuse
                self.reject(external(u, spks, leaf, tap), tag + "/neg_external_fee_input")
                self.reject(canon(u, spks, leaf, tap, fee=R_FEE - 50,
                                  extra_out=self.out(50, self.wallet_spk(), self.X_OUT)), tag + "/neg_part_of_reserve_to_an_output")
                # is the txid a function of the outpoint alone?
                variants = {
                    "nLockTime": canon(u, spks, leaf, tap, locktime=node.getblockcount() - 1, seq=0xfffffffe),
                    "nSequence": canon(u, spks, leaf, tap, seq=0xfffffffd),
                    "nVersion": canon(u, spks, leaf, tap, version=3),
                    "output_nonce": canon(u, spks, leaf, tap, nonce=bytes([2]) + compute_xonly_pubkey(generate_privkey())[0]),
                    "fee_output_nonce": canon(u, spks, leaf, tap, fee_nonce=bytes([2]) + compute_xonly_pubkey(generate_privkey())[0]),
                }
                mal = {}
                for field, tx in variants.items():
                    res = self.accept(tx)
                    blk = None
                    if not res["allowed"]:
                        # policy may refuse for its own reasons; what matters is consensus
                        try:
                            h = node.getblockcount()
                            node.generateblock(node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
                            node.invalidateblock(node.getbestblockhash())      # undo: keep the utxo for the next probe
                            assert node.getblockcount() == h
                            blk = "accepted in a block"
                        except JSONRPCException as e:
                            blk = e.error["message"]
                    mal[field] = {"txid_differs_from_canonical": tx.hash != good.hash, "mempool_allowed": res["allowed"],
                                  "mempool_reject": res.get("reject-reason"), "block": blk}
                    self.log.info("  %-13s variant: mempool=%s (%s) block=%s", field, res["allowed"], res.get("reject-reason"), blk)
                self.rec(tag + "/txid_malleability", mal)
                txid = self.send(good, tag + "/unroll_canonical", extra={"leaf_script_bytes": len(bytes(leaf)),
                                                                         "txid_precomputed_equals_confirmed": None})
                d = self.R[tag + "/unroll_canonical"]
                d["txid_precomputed_equals_confirmed"] = (txid == good.hash)
                self.rec(tag + "/unroll_canonical", d)

        # ---- delisting: the pinned node has no way out through the mempool
        self.log.info("=== T14 delisting ===")
        spks, leaf, tap = setup(pinned_compact, True)
        u = self.fund(tap.scriptPubKey, total, self.X)
        spks_b, leaf_b, tap_b = setup(pinned_compact, True)
        u_b = self.fund(tap_b.scriptPubKey, total, self.X)
        node.setfeeexchangerates(self.rates0)
        self.rec("delisted/whitelist", node.getfeeexchangerates())
        self.reject(canon(u, spks, leaf, tap), "delisted/neg_canonical_tx_fee_in_delisted_asset", consensus=False)
        self.reject(external(u, spks, leaf, tap), "delisted/neg_external_fee_shape_refused_by_the_covenant")
        # only a block producer that takes it directly can move it
        self.mine_raw(canon(u_b, spks_b, leaf_b, tap_b), "delisted/canonical_tx_mined_directly")
        self.whitelist(self.X)
        self.send(canon(u, spks, leaf, tap), "relisted/canonical_tx_relays_again")


if __name__ == "__main__":
    T14().main()
