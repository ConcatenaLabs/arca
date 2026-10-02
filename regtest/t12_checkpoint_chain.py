#!/usr/bin/env python3
"""T12: checkpoint + reassignment chain, every signature made BEFORE the tree
is unrolled.

  leaf (A,S; salt1) --collab_rebind m=1--> checkpoint output [collab_rebind(A,S; salt2) | sweep S]
  checkpoint        --collab_rebind m=2--> [receiver leaf (B,S; salt3), change leaf (A,S; salt4)]
  receiver leaf     --exit (B after delay)--> B's own address

Run twice: fees taken from value left uncommitted (1-input transactions, fee in X)
and fees from an extra input in another asset (the worst case: X not a fee asset)."""
from arklib import *
import os as _os

LEAF = 1_0000_0000
RESERVE = 600
DELAY = 4
F = 600                       # X left uncommitted at each step in the "leftover" variant


class T12(ArkBase, BitcoinTestFramework):
    NAME = "t12"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        for external in (False, True):
            self.run_chain(external)

    def run_chain(self, external):
        node = self.node
        tag = "external" if external else "leftover"
        self.log.info("=== T12 chain, fees: %s ===", tag)
        a_sec, b_sec, s_sec = generate_privkey(), generate_privkey(), generate_privkey()
        a_x, b_x, s_x = (compute_xonly_pubkey(k)[0] for k in (a_sec, b_sec, s_sec))
        expiry = node.getblockcount() + 5000
        salt1, salt2, salt3, salt4 = (_os.urandom(32) for _ in range(4))
        leaf_tap, leaf_lv = rebind_leaf_taptree(a_x, s_x, salt1, DELAY, expiry)
        cp_tap, cp_lv = checkpoint_taptree(a_x, s_x, salt2, expiry)
        recv_tap, recv_lv = rebind_leaf_taptree(b_x, s_x, salt3, DELAY, expiry)
        chg_tap, chg_lv = rebind_leaf_taptree(a_x, s_x, salt4, DELAY, expiry)
        if not external:
            self.rec_script("checkpoint/collab_rebind_leaf", cp_lv["collab"], cp_tap, "collab")
            self.rec_script("checkpoint/sweep_leaf", cp_lv["sweep"], cp_tap, "sweep")

        step = 0 if external else F
        v_cp = LEAF - step
        v_recv = 7000_0000
        v_chg = v_cp - v_recv - step
        cp_outs = [(self.X_ID, v_cp, bytes(cp_tap.scriptPubKey))]
        re_outs = [(self.X_ID, v_recv, bytes(recv_tap.scriptPubKey)), (self.X_ID, v_chg, bytes(chg_tap.scriptPubKey))]

        # ---- every collaborative signature is made NOW: nothing is on chain yet
        m1, m2 = rebind_msg2(salt1, cp_outs), rebind_msg2(salt2, re_outs)
        cp_sig = (sign_schnorr(s_sec, m1), sign_schnorr(a_sec, m1))
        re_sig = (sign_schnorr(s_sec, m2), sign_schnorr(a_sec, m2))
        signed_at = node.getblockcount()

        # ---- now the batch: 16 leaves, ours at index 5; unrolled with the chosen fee shape
        idx = 5
        leaf_spks = [self.p2tr()[0] for _ in range(16)]
        leaf_spks[idx] = bytes(leaf_tap.scriptPubKey)
        root = build_tree(self.X_ID, leaf_spks, LEAF, 4, RESERVE, expiry, s_x, "compact")
        u_root = self.utxo_at(self.send(self.round_tx(root["spk"], root["value"], self.X, self.X_OUT), tag + "/0_round_tx"), 0)
        rtxid = self.send(self.unroll_node_tx(u_root, root, self.X_OUT, RESERVE, external=external), tag + "/1_root_tx")
        b = idx // 4
        btxid = self.send(self.unroll_node_tx(self.utxo_at(rtxid, b), root["children"][b], self.X_OUT, RESERVE,
                                              external=external), tag + "/2_branch_tx")
        u_leaf = self.utxo_at(btxid, idx % 4)
        assert u_leaf.spk == bytes(leaf_tap.scriptPubKey)
        self.rec(tag + "/timeline", {"signatures_made_at_height": signed_at, "round_tx_height": self.R[tag + "/0_round_tx"]["block_height"],
                                     "leaf_outpoint": "%s:%d" % (u_leaf.txid, u_leaf.vout)})

        def rebind_spend(u, tap, lv, pair, outs):
            couts = [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs]
            w = [pair[0], pair[1], bytes([len(outs)]), bytes(lv["collab"]), control_block(tap, "collab")]
            if external:
                tx = self.with_fee_input([u], couts)
                self.setwit(tx, 0, w)
                return self.wallet_sign(tx)
            tx = self.mktx([u], couts + [self.fee(u.amount - sum(v for (_, v, _) in outs), self.X_OUT)])
            self.setwit(tx, 0, w)
            return tx

        # the reassignment cannot run before its checkpoint exists, and its signatures do not
        # fit the leaf itself (different salt)
        self.reject(rebind_spend(u_leaf, leaf_tap, leaf_lv, re_sig, re_outs), tag + "/neg_reassignment_sigs_on_the_leaf")
        ctxid = self.send(rebind_spend(u_leaf, leaf_tap, leaf_lv, cp_sig, cp_outs), tag + "/3_checkpoint_tx")
        u_cp = self.utxo_at(ctxid, 0)
        self.reject(rebind_spend(u_cp, cp_tap, cp_lv, cp_sig, re_outs), tag + "/neg_checkpoint_sigs_on_the_checkpoint_output")
        atxid = self.send(rebind_spend(u_cp, cp_tap, cp_lv, re_sig, re_outs), tag + "/4_reassignment_tx")
        u_recv = self.utxo_at(atxid, 0)
        assert u_recv.spk == bytes(recv_tap.scriptPubKey) and u_recv.amount == v_recv
        assert node.gettxout(atxid, 1)["scriptPubKey"]["hex"] == bytes(chg_tap.scriptPubKey).hex()

        # ---- the receiver exits alone after the delay
        def exit_tx():
            dest = self.wallet_spk()
            if external:
                tx = self.with_fee_input([(u_recv, DELAY)], [self.out(v_recv, dest, self.X_OUT)])
            else:
                tx = self.mktx([(u_recv, DELAY)], [self.out(v_recv - 300, dest, self.X_OUT), self.fee(300, self.X_OUT)])
            self.setwit(tx, 0, [self.sign(b_sec, tx, 0, recv_lv["exit"]), bytes(recv_lv["exit"]),
                                control_block(recv_tap, "exit")])
            return self.wallet_sign(tx) if external else tx

        self.reject(exit_tx(), tag + "/neg_receiver_exit_before_delay")
        self.generate(node, DELAY - 1)
        self.send(exit_tx(), tag + "/5_receiver_exit_claim")

        keys = ["1_root_tx", "2_branch_tx", "3_checkpoint_tx", "4_reassignment_tx", "5_receiver_exit_claim"]
        v = {k: self.R["%s/%s" % (tag, k)]["vsize"] for k in keys}
        v["TOTAL_exit_one_reassignment_deep"] = sum(v.values())
        v["of_which_tree_path"] = v["1_root_tx"] + v["2_branch_tx"]
        v["of_which_offchain_chain"] = v["3_checkpoint_tx"] + v["4_reassignment_tx"]
        self.rec(tag + "/SUMMARY", v)
        self.log.info("%s: %s", tag, v)


if __name__ == "__main__":
    T12().main()
