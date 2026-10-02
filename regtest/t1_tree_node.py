#!/usr/bin/env python3
"""T1: covenant TREE NODE. NUMS internal key; UNROLL leaf (no signature, pins
asset/value/script of outputs 0..r-1) and SWEEP leaf (<expiry> CLTV DROP <S> CHECKSIG)."""
from arklib import *

CHILD = 1_0000_0000      # 1.0 X per child (atoms)
RESERVE = 1000           # per-node fee reserve in X (atoms)


class T1(ArkBase, BitcoinTestFramework):
    NAME = "t1"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        for r in (2, 4):
            for form in ("plain", "compact"):
                self.case(r, form)
        self.case(8, "stream", negatives=False)
        self.sweep_case()

    # ------------------------------------------------------------------
    def children(self, r):
        spks = [self.p2tr()[0] for _ in range(r)]
        return spks, [(self.X_ID, CHILD, spk[2:]) for spk in spks]

    def unroll_tx(self, u, tap, leaves, outs, extra_in=(), locktime=0):
        tx = self.mktx([u] + list(extra_in), outs, locktime)
        self.setwit(tx, 0, [bytes(leaves["unroll"]), control_block(tap, "unroll")])
        if extra_in:
            tx = self.wallet_sign(tx)
        return tx

    def case(self, r, form, negatives=True):
        node = self.node
        tag = "r%d_%s" % (r, form)
        self.log.info("=== T1 node, radix %d, %s unroll leaf ===", r, form)
        expiry = node.getblockcount() + 2000
        spks, kids = self.children(r)
        tap, leaves = node_taptree(kids, expiry, self.s_x, form)
        self.rec_script(tag + "/unroll_leaf", leaves["unroll"], tap, "unroll")
        self.rec_script(tag + "/sweep_leaf", leaves["sweep"], tap, "sweep")
        total = r * CHILD + RESERVE
        good = [self.out(CHILD, spk, self.X_OUT) for spk in spks]

        # ---------- negative tests (the node utxo survives each of them)
        if negatives:
            u = self.fund(tap.scriptPubKey, total, self.X)
            # (1) wrong asset, same numeric value: child 0 paid in asset Y
            y = self.wallet_utxo(CHILD, self.Y)
            outs = [self.out(CHILD, spks[0], self.Y_OUT)] + good[1:] + \
                   [self.out(CHILD, self.wallet_spk(), self.X_OUT), self.fee(RESERVE, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs, [y]), tag + "/neg_wrong_asset")
            # (2) wrong value: child 0 short by one atom
            outs = [self.out(CHILD - 1, spks[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE + 1, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs), tag + "/neg_wrong_value_minus1")
            #     ... and over by one atom (equality, not >=)
            x1 = self.wallet_utxo(1000, self.X)
            outs = [self.out(CHILD + 1, spks[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE + 999, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs, [x1]), tag + "/neg_wrong_value_plus1")
            # (3) wrong script
            outs = [self.out(CHILD, self.p2tr()[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs), tag + "/neg_wrong_script")
            # (4) child at the wrong index: children 0 and 1 swapped
            outs = [good[1], good[0]] + good[2:] + [self.fee(RESERVE, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs), tag + "/neg_wrong_index_swap")
            #     ... and fee output first, shifting every child by one
            outs = [self.fee(RESERVE, self.X_OUT)] + good
            self.reject(self.unroll_tx(u, tap, leaves, outs), tag + "/neg_wrong_index_shift")
            # (5) blinded child 0 (same script, real balanced commitment)
            self.reject(self.blinded_tx(u, tap, leaves, spks, good), tag + "/neg_blinded_child")
            # (6) a missing child (only r-1 children present)
            outs = good[:-1] + [self.fee(RESERVE + CHILD, self.X_OUT)]
            self.reject(self.unroll_tx(u, tap, leaves, outs), tag + "/neg_missing_child")
        else:
            u = self.fund(tap.scriptPubKey, total, self.X)

        # ---------- positive A: fee paid from the in-node reserve, in X
        tx = self.unroll_tx(u, tap, leaves, good + [self.fee(RESERVE, self.X_OUT)])
        txid = self.send(tx, tag + "/unroll_reserve_fee",
                         extra={"leaf_script_bytes": len(bytes(leaves["unroll"]))})
        for i in range(r):
            o = node.gettxout(txid, i)
            assert o["scriptPubKey"]["hex"] == spks[i].hex() and o["asset"] == self.X

        # ---------- positive B: broadcaster adds its own fee input + outputs
        u2 = self.fund(tap.scriptPubKey, total, self.X)
        w = self.wallet_utxo(100000)
        FEE = 2000
        outs = good + [self.out(RESERVE, self.wallet_spk(), self.X_OUT),
                       self.out(100000 - FEE, self.wallet_spk(), self.POL_OUT),
                       self.fee(FEE, self.POL_OUT)]
        tx = self.unroll_tx(u2, tap, leaves, outs, [w])
        self.send(tx, tag + "/unroll_external_fee")

    def blinded_tx(self, u, tap, leaves, spks, good):
        node = self.node
        ck0 = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        chg_addr = node.getnewaddress("", "blech32")
        chg_info = node.getaddressinfo(chg_addr)
        chg_spk = bytes.fromhex(node.getaddressinfo(chg_info["unconfidential"])["scriptPubKey"])
        x = self.wallet_utxo(25000, self.X)
        o0 = self.out(CHILD, spks[0], self.X_OUT)
        o0.nNonce = CTxOutNonce(ck0)
        oc = self.out(5000, chg_spk, self.X_OUT)
        oc.nNonce = CTxOutNonce(bytes.fromhex(chg_info["confidential_key"]))
        outs = [o0] + good[1:] + [oc, self.fee(RESERVE + 20000, self.X_OUT)]
        tx = self.mktx([u, x], outs)
        z = "00" * 32
        blinded = node.rawblindrawtransaction(
            tx.serialize().hex(), [z, z],
            [Decimal(u.amount) / COIN, Decimal(25000) / COIN],
            [self.X, self.X], [z, z], "", False)
        t2 = Tx.from_hex(blinded)
        assert t2.vout[0].nAsset.vchCommitment[0] in (0x0a, 0x0b)
        assert bytes(t2.vout[0].scriptPubKey) == spks[0]
        t2.prev = tx.prev
        self.pad(t2)
        self.setwit(t2, 0, [bytes(leaves["unroll"]), control_block(tap, "unroll")])
        return self.wallet_sign(t2)

    # ------------------------------------------------------------------
    def sweep_case(self):
        node = self.node
        self.log.info("=== T1 SWEEP leaf ===")
        expiry = node.getblockcount() + 12
        spks, kids = self.children(4)
        tap, leaves = node_taptree(kids, expiry, self.s_x, "plain")
        total = 4 * CHILD + RESERVE
        u = self.fund(tap.scriptPubKey, total, self.X)
        dest = self.wallet_spk()

        def sweep(locktime, sec, seq=0xfffffffe):
            tx = self.mktx([(u, seq)], [self.out(total - 300, dest, self.X_OUT),
                                        self.fee(300, self.X_OUT)], locktime)
            sig = self.sign(sec, tx, 0, leaves["sweep"])
            self.setwit(tx, 0, [sig, bytes(leaves["sweep"]), control_block(tap, "sweep")])
            return tx

        self.rec("sweep/expiry", {"expiry": expiry, "height_at_first_try": node.getblockcount()})
        self.reject(sweep(expiry, self.s_sec), "sweep/neg_before_expiry_nonfinal")
        self.reject(sweep(node.getblockcount(), self.s_sec), "sweep/neg_locktime_below_expiry")
        self.mine_to(expiry)
        self.reject(sweep(expiry, generate_privkey()), "sweep/neg_wrong_key")
        self.reject(sweep(expiry, self.s_sec, seq=0xffffffff), "sweep/neg_final_sequence")
        self.send(sweep(expiry, self.s_sec), "sweep/after_expiry")


if __name__ == "__main__":
    T1().main()
