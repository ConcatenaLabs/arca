#!/usr/bin/env python3
"""T10: rebindable 2-of-2 collaborative leaf.

collab_rebind verifies TWO BIP340 signatures (A and S) with
OP_CHECKSIGFROMSTACK over
    msg = SHA256( tag(8) || leaf_salt(32) || m(1) || SHA256(rec_0) .. SHA256(rec_{m-1}) )
where rec_j is the injective record of output j. No input field is signed, so
the signature pair is valid at whatever outpoint the leaf ends up at."""
from arklib import *
import os as _os

LEAF = 1_0000_0000
RESERVE = 600
DELAY = 4
LEFT = 600                    # X not committed to outputs 0..m-1 (fee, or broadcaster's change)


class T10(ArkBase, BitcoinTestFramework):
    NAME = "t10"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X)
        node = self.node
        self.a_sec, self.s_sec, self.b_sec = generate_privkey(), generate_privkey(), generate_privkey()
        self.a_x, self.s_x, self.b_x = (compute_xonly_pubkey(k)[0] for k in (self.a_sec, self.s_sec, self.b_sec))
        self.expiry = node.getblockcount() + 5000
        self.part_a_b_c()
        self.part_d()
        self.sizes()

    def sigs(self, salt, outs, a_sec=None, s_sec=None):
        msg = rebind_msg2(salt, outs)
        return sign_schnorr(s_sec or self.s_sec, msg), sign_schnorr(a_sec or self.a_sec, msg)

    # ------------------------------------------------------------------
    def part_a_b_c(self):
        node = self.node
        self.log.info("=== T10 (a)(b)(c): one signature pair, two outpoints ===")
        salt = _os.urandom(32)
        tap, lv = rebind_leaf_taptree(self.a_x, self.s_x, salt, DELAY, self.expiry)
        self.rec_script("loop/collab_rebind_leaf", lv["collab"], tap, "collab")
        self.rec_script("loop/exit_leaf", lv["exit"], tap, "exit")
        self.rec("params", {"tag": TAG.hex(), "tag_ascii": TAG.decode(), "leaf_salt": salt.hex(), "M": M_MAX,
                            "message": "SHA256(tag || salt || m || SHA256(rec_0) || ... ); CSFS is given this 32-byte hash"})
        # the two destination leaves (receiver B, change back to A), fresh salts
        recv = rebind_leaf_taptree(self.b_x, self.s_x, _os.urandom(32), DELAY, self.expiry)[0]
        chg = rebind_leaf_taptree(self.a_x, self.s_x, _os.urandom(32), DELAY, self.expiry)[0]
        V0, V1 = 6000_0000, LEAF - 6000_0000 - LEFT
        outs = [(self.X_ID, V0, bytes(recv.scriptPubKey)), (self.X_ID, V1, bytes(chg.scriptPubKey))]

        # ---- SIGN ONCE, before any tree exists on chain
        sig_s, sig_a = self.sigs(salt, outs)
        self.rec("signatures", {"msg": rebind_msg2(salt, outs).hex(), "sig_S": sig_s.hex(), "sig_A": sig_a.hex(),
                                "made_at_height": node.getblockcount()})
        committed = [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs]

        # the tree: radix 4, 16 leaves, Alice's rebind leaf at index 0
        leaf_spks = [bytes(tap.scriptPubKey)] + [self.p2tr()[0] for _ in range(15)]
        root = build_tree(self.X_ID, leaf_spks, LEAF, 4, RESERVE, self.expiry, self.s_x, "compact")

        def unroll(external, tag):
            u_root = self.utxo_at(self.send(self.round_tx(root["spk"], root["value"], self.X, self.X_OUT),
                                            tag + "/round_tx"), 0)
            canon_root = self.unroll_node_tx(u_root, root, self.X_OUT, RESERVE, external=False)
            canon_root.rehash()
            rtx = self.unroll_node_tx(u_root, root, self.X_OUT, RESERVE, external=external)
            rtxid = self.send(rtx, tag + "/root_tx")
            ub = self.utxo_at(rtxid, 0)
            # canonical branch txid = what a pre-signer would have assumed: reserve-fee shape
            # on top of the reserve-fee root tx
            canon_ub = Utxo(canon_root.hash, 0, canon_root.vout[0])
            canon_branch = self.unroll_node_tx(canon_ub, root["children"][0], self.X_OUT, RESERVE, external=False)
            canon_branch.rehash()
            btx = self.unroll_node_tx(ub, root["children"][0], self.X_OUT, RESERVE, external=external)
            btxid = self.send(btx, tag + "/branch_tx")
            leaf = self.utxo_at(btxid, 0)
            assert leaf.spk == bytes(tap.scriptPubKey)
            self.rec(tag + "/leaf_outpoint", {"canonical_outpoint": "%s:0" % canon_branch.hash,
                                              "actual_outpoint": "%s:0" % btxid,
                                              "actual_equals_canonical": canon_branch.hash == btxid})
            return leaf

        def spend(u, ss=sig_s, sa=sig_a, m=2, outputs=None, external=False, extra_ins=(), raw_m=None, t=None, l=None):
            t, l = t or tap, l or lv
            outputs = committed if outputs is None else outputs
            wit = [ss, sa, raw_m if raw_m is not None else bytes([m]), bytes(l["collab"]), control_block(t, "collab")]
            left = u.amount + sum(x.amount for x in extra_ins if x.txout.nAsset.vchCommitment == self.X_OUT) - sum(
                o.nValue.getAmount() for o in outputs if o.nAsset.vchCommitment == self.X_OUT)
            if external:
                tx = self.with_fee_input([u] + list(extra_ins), outputs,
                                         leftover_out=self.out(left, self.wallet_spk(), self.X_OUT))
            else:
                tx = self.mktx([u] + list(extra_ins), list(outputs) + [self.fee(left, self.X_OUT)])
            self.setwit(tx, 0, wit)
            return self.wallet_sign(tx) if (external or extra_ins) else tx

        # ---- instance 1: unrolled with reserve fees -> canonical txids
        leaf1 = unroll(False, "inst1_reserve")
        assert self.R["inst1_reserve/leaf_outpoint"]["actual_equals_canonical"]
        # ---- instance 2: SAME tree, unrolled with external fee inputs -> different txids
        leaf2 = unroll(True, "inst2_external")
        assert not self.R["inst2_external/leaf_outpoint"]["actual_equals_canonical"]

        # ---- (c) negatives, all against the instance-2 leaf
        N = "neg/"
        y = self.wallet_utxo(V1, self.Y)
        o_y = [committed[0], self.out(V1, bytes(chg.scriptPubKey), self.Y_OUT), self.out(V1, self.wallet_spk(), self.X_OUT)]
        self.reject(spend(leaf2, outputs=o_y, extra_ins=[y]), N + "committed_output_asset_changed")
        self.reject(spend(leaf2, outputs=[committed[0], self.out(V1 - 1, bytes(chg.scriptPubKey), self.X_OUT)]),
                    N + "committed_output_value_minus1")
        self.reject(spend(leaf2, outputs=[self.out(V0 + 1, bytes(recv.scriptPubKey), self.X_OUT), committed[1]]),
                    N + "committed_output_value_plus1")
        self.reject(spend(leaf2, outputs=[self.out(V0, self.p2tr()[0], self.X_OUT), committed[1]]),
                    N + "committed_output_script_changed")
        evil = bytes([0x00, 0x21]) + bytes(recv.scriptPubKey)[2:] + b"\x01"
        self.reject(spend(leaf2, outputs=[self.out(V0, evil, self.X_OUT), committed[1]]),
                    N + "committed_output_v0_33byte_program_substitution")
        self.reject(spend(leaf2, outputs=[committed[1], committed[0]]), N + "outputs_reordered")
        self.reject(spend(leaf2, m=1), N + "wrong_m_1_with_sigs_for_2")
        self.reject(spend(leaf2, m=3, outputs=committed + [self.out(100, self.wallet_spk(), self.X_OUT)]),
                    N + "wrong_m_3_with_sigs_for_2")
        self.reject(spend(leaf2, raw_m=b""), N + "m_empty")
        self.reject(spend(leaf2, raw_m=b"\x00"), N + "m_zero_byte")
        self.reject(spend(leaf2, m=5), N + "m_above_M")
        self.reject(spend(leaf2, raw_m=b"\x02\x00"), N + "m_two_bytes_nonminimal")
        os_, oa = self.sigs(_os.urandom(32), outs)
        self.reject(spend(leaf2, ss=os_, sa=oa), N + "signatures_for_a_different_salt")
        xs, xa = self.sigs(salt, outs, a_sec=generate_privkey())
        self.reject(spend(leaf2, sa=xa), N + "sig_A_by_wrong_key")
        xs, xa = self.sigs(salt, outs, s_sec=generate_privkey())
        self.reject(spend(leaf2, ss=xs), N + "sig_S_by_wrong_key")
        self.reject(spend(leaf2, ss=b""), N + "missing_sig_S")
        self.reject(spend(leaf2, sa=b""), N + "missing_sig_A")
        self.reject(spend(leaf2, ss=sig_a, sa=sig_s), N + "signatures_swapped")
        self.reject(spend(leaf2, outputs=[committed[0]]), N + "second_committed_output_missing")

        # ---- (a) the SAME pair spends both outpoints; (b) the second with a fee input and
        #      change/fee outputs after index m-1
        t1 = self.send(spend(leaf1), "spend/outpoint_1_canonical_fee_from_leftover")
        t2 = self.send(spend(leaf2, external=True), "spend/outpoint_2_noncanonical_with_fee_input")
        w1 = node.getrawtransaction(t1, True)["vin"][0]["txinwitness"]
        w2 = node.getrawtransaction(t2, True)["vin"][0]["txinwitness"]
        assert w1[0] == w2[0] == sig_s.hex() and w1[1] == w2[1] == sig_a.hex()
        self.rec("spend/proof", {"same_sig_S": w1[0] == w2[0], "same_sig_A": w1[1] == w2[1],
                                 "outpoints": ["%s:%d" % (leaf1.txid, leaf1.vout), "%s:%d" % (leaf2.txid, leaf2.vout)],
                                 "spending_txids": [t1, t2],
                                 "witness_item_sizes": [len(x) // 2 for x in w1]})
        for t in (t1, t2):
            assert node.gettxout(t, 0)["scriptPubKey"]["hex"] == bytes(recv.scriptPubKey).hex()
            assert node.gettxout(t, 1)["scriptPubKey"]["hex"] == bytes(chg.scriptPubKey).hex()

        self.salt, self.outs, self.pair, self.committed = salt, outs, (sig_s, sig_a), committed
        self.spend_fn = spend

    # ------------------------------------------------------------------
    def part_d(self):
        self.log.info("=== T10 (d): same keys, different salt ===")
        salt2 = _os.urandom(32)
        tap2, lv2 = rebind_leaf_taptree(self.a_x, self.s_x, salt2, DELAY, self.expiry)
        u = self.fund(tap2.scriptPubKey, LEAF, self.X)
        sig_s, sig_a = self.pair
        self.reject(self.spend_fn(u, t=tap2, l=lv2), "salt/neg_signatures_of_leaf_1_in_leaf_with_other_salt")
        ok_s, ok_a = self.sigs(salt2, self.outs)
        self.send(self.spend_fn(u, ss=ok_s, sa=ok_a, t=tap2, l=lv2), "salt/control_own_signatures_spend_it")
        # ... and the inverse property: the pair DOES spend any other utxo carrying leaf 1's script
        tap1, lv1 = rebind_leaf_taptree(self.a_x, self.s_x, self.salt, DELAY, self.expiry)
        u3 = self.fund(tap1.scriptPubKey, LEAF, self.X)
        self.send(self.spend_fn(u3, t=tap1, l=lv1), "salt/replay_on_a_refunded_copy_of_leaf_1")

    # ------------------------------------------------------------------
    def sizes(self):
        """Loop form vs fixed-m family, m = 1..4, each a 1-input spend with the fee from the leftover."""
        self.log.info("=== T10 sizes: loop vs fixed-m family ===")
        dests = [rebind_leaf_taptree(compute_xonly_pubkey(generate_privkey())[0], self.s_x, _os.urandom(32),
                                     DELAY, self.expiry)[0] for _ in range(4)]
        for family in (False, True):
            salt = _os.urandom(32)
            tap, lv = rebind_leaf_taptree(self.a_x, self.s_x, salt, DELAY, self.expiry, family=family)
            name = "family" if family else "loop"
            if family:
                for m in (1, 2, 3, 4):
                    self.rec_script("family/collab%d_leaf" % m, lv["collab%d" % m], tap, "collab%d" % m)
            for m in (1, 2, 3, 4):
                u = self.fund(tap.scriptPubKey, LEAF, self.X)
                each = (LEAF - 700) // m
                outs = [(self.X_ID, each, bytes(dests[j].scriptPubKey)) for j in range(m)]
                ss, sa = self.sigs(salt, outs)
                tx = self.mktx([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs] +
                               [self.fee(LEAF - each * m, self.X_OUT)])
                self.setwit(tx, 0, rebind_witness(tap, lv, ss, sa, m, family=family))
                self.send(tx, "size/%s_m%d" % (name, m))
            # the unilateral exit through each tree shape
            u = self.fund(tap.scriptPubKey, LEAF, self.X)
            self.generate(self.node, DELAY - 1)
            tx = self.mktx([(u, DELAY)], [self.out(LEAF - 300, self.wallet_spk(), self.X_OUT), self.fee(300, self.X_OUT)])
            self.setwit(tx, 0, [self.sign(self.a_sec, tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
            self.send(tx, "size/%s_exit_claim" % name)


if __name__ == "__main__":
    T10().main()
