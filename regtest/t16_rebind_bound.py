#!/usr/bin/env python3
"""T16: the rebindable message bound to the spent coin and to the chain.

    chain_tag = SHA256("ArcaRbd1" || genesis_hash)          (genesis in internal byte order)
    msg       = SHA256(chain_tag || leaf_salt || asset_in || 0x01 || 0x01 || value_in
                       || m || SHA256(rec_0) || ... || SHA256(rec_{m-1}))

asset_in / value_in come from OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTASSET /
OP_INSPECTINPUTVALUE, concatenated in the T1 record form (prefix bytes kept).
Re-runs the T10 suite on it and adds the coin and chain negatives."""
from arklib3 import *
import os as _os

LEAF = 1_0000_0000
RESERVE = 600
DELAY = 4
LEFT = 600


class T16(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t16"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X)
        node = self.node
        self.gen = self.genesis_internal()
        self.ctag = chain_tag(self.gen)
        self.a_sec, self.s_sec, self.b_sec = generate_privkey(), generate_privkey(), generate_privkey()
        self.a_x, self.s_x, self.b_x = (compute_xonly_pubkey(k)[0] for k in (self.a_sec, self.s_sec, self.b_sec))
        self.expiry = node.getblockcount() + 5000
        self.rec("params", {"genesis_hash_rpc": node.getblockhash(0), "genesis_internal": self.gen.hex(),
                            "chain_tag": self.ctag.hex(),
                            "message": "SHA256(chain_tag||salt||asset_in||01||01||value_in_le8||m||SHA256(rec_0)..)"})
        self.part_suite()
        self.part_coin_and_chain()
        self.sizes()
        self.part_folded()

    def sigs(self, salt, outs, value_in=LEAF, asset_in=None, a_sec=None, s_sec=None, ctag=None):
        msg = rebind_msg3(ctag or self.ctag, salt, asset_in or self.X_ID, value_in, outs)
        return sign_schnorr(s_sec or self.s_sec, msg), sign_schnorr(a_sec or self.a_sec, msg)

    def leaf(self, a_x, salt):
        return leaf3_taptree(a_x, self.s_x, salt, self.ctag, DELAY, sweep=sweep_leaf(self.expiry, self.s_x))

    # ------------------------------------------------------------------
    def part_suite(self):
        node = self.node
        self.log.info("=== T16 (a)(b)(c): the T10 suite on the bound message ===")
        salt = _os.urandom(32)
        tap, lv = self.leaf(self.a_x, salt)
        self.rec_script("loop/collab_bound_leaf", lv["collab"], tap, "collab")
        self.rec_script("loop/exit_leaf", lv["exit"], tap, "exit")
        recv = self.leaf(self.b_x, _os.urandom(32))[0]
        chg = self.leaf(self.a_x, _os.urandom(32))[0]
        V0, V1 = 6000_0000, LEAF - 6000_0000 - LEFT
        outs = [(self.X_ID, V0, bytes(recv.scriptPubKey)), (self.X_ID, V1, bytes(chg.scriptPubKey))]
        sig_s, sig_a = self.sigs(salt, outs)
        self.rec("signatures", {"msg": rebind_msg3(self.ctag, salt, self.X_ID, LEAF, outs).hex(),
                                "made_at_height": node.getblockcount()})
        committed = [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs]
        leaf_spks = [bytes(tap.scriptPubKey)] + [self.p2tr()[0] for _ in range(15)]
        root = build_tree(self.X_ID, leaf_spks, LEAF, 4, RESERVE, self.expiry, self.s_x, "compact")

        def unroll(external, tag):
            u_root = self.utxo_at(self.send(self.round_tx(root["spk"], root["value"], self.X, self.X_OUT),
                                            tag + "/round_tx"), 0)
            canon_root = self.unroll_node_tx(u_root, root, self.X_OUT, RESERVE, external=False)
            canon_root.rehash()
            rtxid = self.send(self.unroll_node_tx(u_root, root, self.X_OUT, RESERVE, external=external),
                              tag + "/root_tx")
            ub = self.utxo_at(rtxid, 0)
            canon_branch = self.unroll_node_tx(Utxo(canon_root.hash, 0, canon_root.vout[0]), root["children"][0],
                                               self.X_OUT, RESERVE, external=False)
            canon_branch.rehash()
            btxid = self.send(self.unroll_node_tx(ub, root["children"][0], self.X_OUT, RESERVE, external=external),
                              tag + "/branch_tx")
            leaf = self.utxo_at(btxid, 0)
            assert leaf.spk == bytes(tap.scriptPubKey)
            self.rec(tag + "/leaf_outpoint", {"canonical": "%s:0" % canon_branch.hash, "actual": "%s:0" % btxid,
                                              "actual_equals_canonical": canon_branch.hash == btxid})
            return leaf

        def spend(u, ss=sig_s, sa=sig_a, m=2, outputs=None, external=False, extra_ins=(), raw_m=None, t=None,
                  l=None):
            t, l = t or tap, l or lv
            outputs = committed if outputs is None else outputs
            wit = [ss, sa, raw_m if raw_m is not None else bytes([m]), bytes(l["collab"]), control_block(t, "collab")]
            mine_in = [u] + [x for x in extra_ins]
            left = sum(x.amount for x in mine_in if x.txout.nAsset.vchCommitment == self.X_OUT) - sum(
                o.nValue.getAmount() for o in outputs if o.nAsset.vchCommitment == self.X_OUT)
            if external:
                tx = self.with_fee_input([u] + list(extra_ins), outputs,
                                         leftover_out=self.out(left, self.wallet_spk(), self.X_OUT))
            else:
                tx = self.mktx([u] + list(extra_ins), list(outputs) + [self.fee(left, self.X_OUT)])
            self.setwit(tx, 0, wit)
            return self.wallet_sign(tx) if (external or extra_ins) else tx

        leaf1 = unroll(False, "inst1_reserve")
        leaf2 = unroll(True, "inst2_external")
        assert self.R["inst1_reserve/leaf_outpoint"]["actual_equals_canonical"]
        assert not self.R["inst2_external/leaf_outpoint"]["actual_equals_canonical"]

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
        # new in round 3: the pair made over the T10 message (no coin, no chain) does not fit
        old = rebind_msg2(salt, outs)
        self.reject(spend(leaf2, ss=sign_schnorr(self.s_sec, old), sa=sign_schnorr(self.a_sec, old)),
                    N + "signatures_over_the_round2_message")

        t1 = self.send(spend(leaf1), "spend/outpoint_1_canonical_fee_from_leftover")
        t2 = self.send(spend(leaf2, external=True), "spend/outpoint_2_noncanonical_with_fee_input")
        w1 = node.getrawtransaction(t1, True)["vin"][0]["txinwitness"]
        w2 = node.getrawtransaction(t2, True)["vin"][0]["txinwitness"]
        assert w1[0] == w2[0] == sig_s.hex() and w1[1] == w2[1] == sig_a.hex()
        self.rec("spend/proof", {"same_sig_S": True, "same_sig_A": True,
                                 "witness_item_sizes": [len(x) // 2 for x in w1]})
        self.salt, self.outs, self.pair, self.committed, self.spend_fn = salt, outs, (sig_s, sig_a), committed, spend
        self.tap, self.lv = tap, lv

    # ------------------------------------------------------------------
    def part_coin_and_chain(self):
        self.log.info("=== T16 (d): coin and chain binding ===")
        tap, lv, spend = self.tap, self.lv, self.spend_fn
        # same script, same asset, same amount, new utxo: still spendable (documented limit)
        u = self.fund(tap.scriptPubKey, LEAF, self.X)
        self.send(spend(u), "coin/replay_same_script_same_amount_same_asset_ACCEPTED")
        # same script, another amount: the bound message refuses it
        u_more = self.fund(tap.scriptPubKey, LEAF + 5000, self.X)
        self.reject(spend(u_more), "coin/neg_same_script_amount_plus_5000")
        u_less = self.fund(tap.scriptPubKey, LEAF - 1, self.X)
        # outputs sum to LEAF-600, so LEAF-1 still balances: only the binding refuses it
        self.reject(spend(u_less), "coin/neg_same_script_amount_minus_1")
        # same script, another asset, same amount (the committed X outputs funded from a wallet X coin)
        u_y = self.fund(tap.scriptPubKey, LEAF, self.Y)
        xw = self.wallet_utxo(LEAF, self.X)
        tx = self.mktx([u_y, xw], list(self.committed) + [self.out(LEAF, self.wallet_spk(), self.Y_OUT),
                                                          self.fee(LEAF - sum(c.nValue.getAmount() for c in self.committed),
                                                                   self.X_OUT)])
        self.setwit(tx, 0, [self.pair[0], self.pair[1], b"\x02", bytes(lv["collab"]), control_block(tap, "collab")])
        self.reject(self.wallet_sign(tx), "coin/neg_same_script_other_asset_same_amount")
        # chain: the pair made with another genesis hash
        other = chain_tag(sha256(b"some other chain"))
        ss, sa = self.sigs(self.salt, self.outs, ctag=other)
        u2 = self.fund(tap.scriptPubKey, LEAF, self.X)
        self.reject(spend(u2, ss=ss, sa=sa), "chain/neg_pair_made_with_another_genesis_hash")
        ss, sa = self.sigs(self.salt, self.outs, ctag=sha256(TAG + self.gen[::-1]))
        self.reject(spend(u2, ss=ss, sa=sa), "chain/neg_pair_made_with_genesis_in_display_byte_order")
        self.send(spend(u2), "chain/control_right_chain_tag_spends")

        # contrast: the round-2 leaf (T10 script) accepts the other-amount and other-asset coins
        self.log.info("=== T16 contrast: the T10 leaf on the same two coins ===")
        salt = _os.urandom(32)
        tap2, lv2 = rebind_leaf_taptree(self.a_x, self.s_x, salt, DELAY, self.expiry)
        msg = rebind_msg2(salt, self.outs)
        ps, pa = sign_schnorr(self.s_sec, msg), sign_schnorr(self.a_sec, msg)
        u_more = self.fund(tap2.scriptPubKey, LEAF + 5000, self.X)
        self.send(spend(u_more, ss=ps, sa=pa, t=tap2, l=lv2),
                  "contrast_round2/other_amount_ACCEPTED_broadcaster_takes_5000_more")
        u_y = self.fund(tap2.scriptPubKey, LEAF, self.Y)
        xw = self.wallet_utxo(LEAF, self.X)
        tx = self.mktx([u_y, xw], list(self.committed) + [self.out(LEAF, self.wallet_spk(), self.Y_OUT),
                                                          self.fee(LEAF - sum(c.nValue.getAmount() for c in self.committed),
                                                                   self.X_OUT)])
        self.setwit(tx, 0, [ps, pa, b"\x02", bytes(lv2["collab"]), control_block(tap2, "collab")])
        self.send(self.wallet_sign(tx), "contrast_round2/other_asset_ACCEPTED")

    # ------------------------------------------------------------------
    def sizes(self):
        self.log.info("=== T16 sizes ===")
        dests = [self.leaf(compute_xonly_pubkey(generate_privkey())[0], _os.urandom(32))[0] for _ in range(4)]
        salt = _os.urandom(32)
        tap, lv = self.leaf(self.a_x, salt)
        for m in (1, 2, 3, 4):
            u = self.fund(tap.scriptPubKey, LEAF, self.X)
            each = (LEAF - 700) // m
            outs = [(self.X_ID, each, bytes(dests[j].scriptPubKey)) for j in range(m)]
            ss, sa = self.sigs(salt, outs)
            tx = self.mktx([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs] +
                           [self.fee(LEAF - each * m, self.X_OUT)])
            self.setwit(tx, 0, [ss, sa, bytes([m]), bytes(lv["collab"]), control_block(tap, "collab")])
            self.send(tx, "size/loop_m%d" % m)
        # with an outside fee coin, m = 2 (T10: 560 vB)
        u = self.fund(tap.scriptPubKey, LEAF, self.X)
        outs = [(self.X_ID, 6000_0000, bytes(dests[0].scriptPubKey)), (self.X_ID, LEAF - 6000_0000 - LEFT,
                                                                        bytes(dests[1].scriptPubKey))]
        ss, sa = self.sigs(salt, outs)
        tx = self.with_fee_input([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs],
                                 leftover_out=self.out(LEFT, self.wallet_spk(), self.X_OUT))
        self.setwit(tx, 0, [ss, sa, b"\x02", bytes(lv["collab"]), control_block(tap, "collab")])
        self.send(self.wallet_sign(tx), "size/loop_m2_outside_fee_coin")


    # ------------------------------------------------------------------
    def part_folded(self):
        """Variant: one 32-byte constant SHA256(chain_tag || salt) in place of the
        64-byte chain_tag || salt. Same bindings, 32 script bytes less."""
        self.log.info("=== T16 (e): folded constant ===")
        salt = _os.urandom(32)
        sw = sweep_leaf(self.expiry, self.s_x)
        tap, lv = leaf3_taptree(self.a_x, self.s_x, salt, self.ctag, DELAY, sweep=sw, fold=True)
        self.rec_script("folded/collab_leaf", lv["collab"], tap, "collab")
        dests = [self.leaf(compute_xonly_pubkey(generate_privkey())[0], _os.urandom(32))[0] for _ in range(2)]

        def mk(u, m, ctag=None, value_in=LEAF, asset_in=None):
            each = (LEAF - 700) // m
            outs = [(self.X_ID, each, bytes(dests[j].scriptPubKey)) for j in range(m)]
            msg = rebind_msg3(ctag or self.ctag, salt, asset_in or self.X_ID, value_in, outs, fold=True)
            tx = self.mktx([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs] +
                           [self.fee(u.amount - each * m, self.X_OUT)])
            self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(self.a_sec, msg), bytes([m]),
                                bytes(lv["collab"]), control_block(tap, "collab")])
            return tx
        for m in (1, 2):
            self.send(mk(self.fund(tap.scriptPubKey, LEAF, self.X), m), "folded/size_m%d" % m)
        u = self.fund(tap.scriptPubKey, LEAF + 5000, self.X)
        self.reject(mk(u, 1), "folded/neg_other_amount")
        self.reject(mk(self.fund(tap.scriptPubKey, LEAF, self.X), 1, ctag=chain_tag(sha256(b"x"))),
                    "folded/neg_other_genesis")
        self.reject(mk(self.fund(tap.scriptPubKey, LEAF, self.X), 1, asset_in=self.Y_ID),
                    "folded/neg_message_names_other_asset")


if __name__ == "__main__":
    T16().main()
