#!/usr/bin/env python3
"""T20: notice. The leaf has no operator sweep ([collab, exit] only).

As specified ("spec"):
  batch output: SWEEP_START = token check, then output[this index] == (asset, whole value, PENDING)
  PENDING      = { UNROLL (same children),  FINAL = <W> CSV DROP <S> CHECKSIG }
  inner nodes  : token check + <W> CSV DROP + <S> CHECKSIG
  R            = <S> CHECKSIG

Corrected ("token notice"): the notice moves onto the token.
  R_W          = <W> CSV DROP <S> CHECKSIG          (every sweep spends T from R_W)
  batch output : token check + <S> CHECKSIG          (no PENDING)
  inner nodes  : token check + <W> CSV DROP + <S> CHECKSIG   (unchanged)

Combination with T18: the token check replaces the absolute time lock in
every sweep path; the clock's RELEASE keeps the only absolute lock.
"""
from arklib3 import *
import os as _os

LEAF = 1000_0000
RESERVE = 1000
SFEE = 3000
H = 3600
W_SEC = 36 * H
W = rel_time(W_SEC)
DELAY = rel_time(36 * H)


class T20(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t20"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.Rs, self.Rlv = r_taptree(self.s_x)
        self.Rw, self.RWlv = r_taptree(self.s_x, W)
        self.rec("params", {"W_seconds": W_SEC, "W_sequence": W, "exit_delay_sequence": DELAY})
        self.rec_script("spec/R", self.Rlv["spend"], self.Rs, "spend")
        self.rec_script("corrected/R_W", self.RWlv["spend"], self.Rw, "spend")
        self.spec_hole()
        self.spec_path()
        self.spec_final()
        self.corrected_old_nodes()
        self.corrected_late_nodes()
        self.corrected_root()

    # ------------------------------------------------------------------
    def batch(self, label, nleaves, design):
        """Round + tree + one clock (RELEASE only) at E = now + 1 h."""
        owners = [generate_privkey() for _ in range(nleaves)]
        ox = [compute_xonly_pubkey(k)[0] for k in owners]
        leaves = [leaf3_taptree(x, self.s_x, _os.urandom(32), self.ctag, DELAY) for x in ox]
        E = self.mtp() + H
        Rtap = self.Rs if design == "spec" else self.Rw
        Rprog = bytes(Rtap.scriptPubKey)[2:]
        holder = {}

        def build(T_id):
            def scripts(kids, tuples, level, is_root):
                unroll = CScript(unroll_compact_body(tuples))
                value = sum(k["value"] for k in kids) + RESERVE
                if is_root and design == "spec":
                    ptap, plv = pending_taptree(tuples, self.s_x, W)
                    sw = sweep_start(T_id, Rprog, self.s_x, self.X_ID, value, bytes(ptap.scriptPubKey))
                    holder["pending"] = (ptap, plv)
                elif is_root:
                    sw = sweep_token(T_id, Rprog, self.s_x)
                else:
                    sw = sweep_token(T_id, Rprog, self.s_x, W)
                return [("unroll", unroll), ("sweep", sw)], {"unroll": unroll, "sweep": sw}
            root = build_tree3(self.X_ID, [bytes(t.scriptPubKey) for t, _ in leaves], LEAF, 4, RESERVE, scripts)
            clocks = clock_chain(T_id, bytes(Rtap.scriptPubKey), self.s_x, [E])
            holder.update(root=root, clocks=clocks)
            return root["spk"], clocks[0]["spk"]
        b = self.issuing_round(tree_value(nleaves, LEAF, 4, RESERVE), build, label + "/round")
        b.update(holder, owners=owners, leaves=leaves, E=E, Rtap=Rtap, design=design)
        return b

    def unroll(self, u, tap, lv, children, label=None, mine=True):
        tx = self.mktx([u], [self.out(k["value"], k["spk"], self.X_OUT) for k in children] +
                       [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(lv["unroll"]), control_block(tap, "unroll")])
        if label is None:
            return tx
        txid = self.send(tx, label, mine=mine)
        return [Utxo(txid, i, tx.vout[i]) for i in range(len(children))]

    def release(self, b, label, mine=True):
        c = b["clocks"][0]
        tx = self.with_fee_input([(b["T_u"], 0xfffffffe)], [self.out(1, bytes(b["Rtap"].scriptPubKey), b["T_OUT"])],
                                 locktime=b["E"])
        leaf = c["lv"]["release"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, leaf), bytes(leaf), control_block(c["tap"], "release")])
        txid = self.send(self.wallet_sign(tx), label, mine=mine)
        return Utxo(txid, 0, tx.vout[0])

    def sweep(self, b, items, t_u, t_seq=None):
        """items: [(utxo, node, seq)]. T input last; T back to R; fee from the swept value."""
        Rtap = b["Rtap"]
        if t_seq is None:
            t_seq = W if b["design"] != "spec" else 0xffffffff
        ins = [(u, seq) for u, _, seq in items] + [(t_u, t_seq)]
        k = len(items)
        total = sum(u.amount for u, _, _ in items)
        tx = self.mktx(ins, [self.out(total - SFEE, self.wallet_spk(), self.X_OUT),
                             self.out(1, bytes(Rtap.scriptPubKey), b["T_OUT"]), self.fee(SFEE, self.X_OUT)])
        for i, (u, n, seq) in enumerate(items):
            sw = n["leaves"]["sweep"]
            self.setwit(tx, i, [self.sign(self.s_sec, tx, i, sw), sn(k), bytes(sw), control_block(n["tap"], "sweep")])
        rl = Rtap.leaves["spend"].script
        self.setwit(tx, k, [self.sign(self.s_sec, tx, k, rl), bytes(rl), control_block(Rtap, "spend")])
        return tx

    def start(self, b, t_u, value=None, pending_spk=None, k=None):
        """SWEEP_START: [root, T, wallet X fee coin] -> [PENDING, T->R, X change, fee]."""
        root = b["root"]
        ptap, plv = b["pending"]
        xw = self.wallet_utxo(20_000, self.X)
        tx = self.mktx([b["root_u"], t_u, xw],
                       [self.out(value or b["root_u"].amount, pending_spk or bytes(ptap.scriptPubKey), self.X_OUT),
                        self.out(1, bytes(self.Rs.scriptPubKey), b["T_OUT"]),
                        self.out(20_000 - SFEE + (b["root_u"].amount - (value or b["root_u"].amount)),
                                 self.wallet_spk(), self.X_OUT), self.fee(SFEE, self.X_OUT)])
        sw = root["leaves"]["sweep"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sw), sn(1 if k is None else k), bytes(sw),
                            control_block(root["tap"], "sweep")])
        rl = self.Rlv["spend"]
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, rl), bytes(rl), control_block(self.Rs, "spend")])
        return self.wallet_sign(tx)

    # ------------------------------------------------------------------
    def spec_hole(self):
        """As specified: an inner node that went on-chain before expiry can be
        swept in the block that releases the token, with no notice at all."""
        self.log.info("=== T20 spec: inner node on-chain before expiry ===")
        b = self.batch("spec_hole", 16, "spec")
        root = b["root"]
        self.rec_script("spec/batch_SWEEP_START", root["leaves"]["sweep"], root["tap"], "sweep")
        self.rec_script("spec/inner_sweep", root["children"][0]["leaves"]["sweep"], root["children"][0]["tap"], "sweep")
        ptap, plv = b["pending"]
        self.rec_script("spec/PENDING_unroll", plv["unroll"], ptap, "unroll")
        self.rec_script("spec/PENDING_final", plv["final"], ptap, "final")
        self.rec_script("leaf/collab", b["leaves"][0][1]["collab"], b["leaves"][0][0], "collab")
        self.rec_script("leaf/exit", b["leaves"][0][1]["exit"], b["leaves"][0][0], "exit")
        ns = self.unroll(b["root_u"], root["tap"], root["leaves"], root["children"], "spec_hole/root_unroll_by_exiting_owner")
        n0 = root["children"][0]
        ls = self.unroll(ns[0], n0["tap"], n0["leaves"], n0["children"], "spec_hole/n0_unroll")
        self.leaf_tests(b, ls)
        self.mtp_past(b["E"])
        self.rec("spec_hole/state", {"inner_nodes_confirmed_at_mtp_before": True, "E": b["E"], "mtp": self.mtp(),
                                     "inner_node_age_seconds_at_release":
                                         self.mtp() - self.csv_ready_at(ns[1].txid, 0)})
        t_u = self.release(b, "spec_hole/release_unmined", mine=False)
        items = [(ns[i], root["children"][i], W) for i in (1, 2, 3)]
        self.send(self.sweep(b, items, t_u), "spec_hole/FLAW_three_inner_nodes_swept_in_the_release_block")
        rel_txid = t_u.txid
        self.rec("spec_hole/same_block", {"release_block": self.node.getrawtransaction(rel_txid, True)["blockhash"],
                                          "sweep_block_is_the_same": True})

    def leaf_tests(self, b, ls):
        """The leaf has no sweep: the operator's key alone never spends it."""
        tap, lv = b["leaves"][1]
        u = ls[1]
        out = [self.out(u.amount - SFEE, self.wallet_spk(), self.X_OUT), self.fee(SFEE, self.X_OUT)]
        outs3 = [(self.X_ID, u.amount - SFEE, bytes(out[0].scriptPubKey))]
        msg = rebind_msg3(self.ctag, b"\0" * 32, self.X_ID, u.amount, outs3)  # wrong salt is irrelevant: S alone
        sS = sign_schnorr(self.s_sec, msg)
        tx = self.mktx([u], out)
        self.setwit(tx, 0, [sS, b"", b"\x01", bytes(lv["collab"]), control_block(tap, "collab")])
        self.reject(tx, "leaf/neg_operator_alone_collab_sig_A_empty")
        tx = self.mktx([u], out)
        self.setwit(tx, 0, [sS, sS, b"\x01", bytes(lv["collab"]), control_block(tap, "collab")])
        self.reject(tx, "leaf/neg_operator_alone_collab_S_signs_both_slots")
        self.mtp_past(self.csv_ready_at(u.txid, 36 * H))
        tx = self.mktx([(u, DELAY)], out)
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
        self.reject(tx, "leaf/neg_operator_signs_the_exit_path")
        # the round-2 sweep leaf, presented with a control block from a tree that has it
        ghost = taproot_construct(NUMS, [("collab", lv["collab"]), [("exit", lv["exit"]),
                                                                     ("sweep", sweep_leaf(b["E"], self.s_x))]])
        tx = self.mktx([(u, 0xfffffffe)], out, b["E"])
        sw = ghost.leaves["sweep"].script
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sw), bytes(sw), control_block(ghost, "sweep")])
        self.reject(tx, "leaf/neg_operator_presents_a_sweep_leaf_not_in_the_tree")
        tx = self.mktx([u], out)
        from test_framework.script import TaprootSignatureHash
        sh = TaprootSignatureHash(tx, [x.txout for x in tx.prev], 0, self.genesis, 0)
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, sh)])
        self.reject(tx, "leaf/neg_operator_key_path_signature")
        # the owner's exit, for the size (leaf now has two script leaves: control block 65)
        tap0, lv0 = b["leaves"][0]
        u0 = ls[0]
        tx = self.mktx([(u0, DELAY)], [self.out(u0.amount - 300, self.wallet_spk(), self.X_OUT), self.fee(300, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(b["owners"][0], tx, 0, lv0["exit"]), bytes(lv0["exit"]), control_block(tap0, "exit")])
        self.send(tx, "leaf/owner_exit_claim_after_36h")

    # ------------------------------------------------------------------
    def spec_path(self):
        self.log.info("=== T20 spec: start, pending, unroll from pending, late inner node ===")
        b = self.batch("spec_path", 16, "spec")
        root = b["root"]
        self.mtp_past(b["E"])
        t_u = self.release(b, "spec_path/release")
        pw = self.wallet_utxo(30_000, self.X)
        # SWEEP_START negatives
        tx = self.mktx([b["root_u"], pw], [self.out(b["root_u"].amount, bytes(b["pending"][0].scriptPubKey), self.X_OUT),
                                           self.out(30_000 - SFEE, self.wallet_spk(), self.X_OUT),
                                           self.fee(SFEE, self.X_OUT)])
        sw = root["leaves"]["sweep"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sw), sn(1), bytes(sw), control_block(root["tap"], "sweep")])
        self.reject(self.wallet_sign(tx), "spec_path/neg_start_without_T")
        self.reject(self.start(b, t_u, value=b["root_u"].amount - 1), "spec_path/neg_start_pending_one_atom_short")
        self.reject(self.start(b, t_u, pending_spk=self.p2tr()[0]), "spec_path/neg_start_to_another_script")
        st = self.send(self.start(b, t_u), "spec_path/SWEEP_START_to_pending")
        P = Utxo(st, 0, self.node.getrawtransaction(st, True) and tx_from_hex(self.node.getrawtransaction(st)).vout[0])
        TR = Utxo(st, 1, tx_from_hex(self.node.getrawtransaction(st)).vout[1])
        ptap, plv = b["pending"]
        fin = self.mktx([(P, W)], [self.out(P.amount - SFEE, self.wallet_spk(), self.X_OUT), self.fee(SFEE, self.X_OUT)])
        self.setwit(fin, 0, [self.sign(self.s_sec, fin, 0, plv["final"]), bytes(plv["final"]), control_block(ptap, "final")])
        self.reject(fin, "spec_path/neg_FINAL_before_W")
        ns = self.unroll(P, ptap, plv, root["children"], "spec_path/watcher_unrolls_PENDING_during_W")
        n0 = root["children"][0]
        self.reject(self.sweep(b, [(ns[0], n0, W)], TR), "spec_path/neg_late_inner_node_swept_before_its_W")
        self.mtp_past(self.csv_ready_at(ns[0].txid, W_SEC))
        self.send(self.sweep(b, [(ns[0], n0, W)], TR), "spec_path/late_inner_node_swept_after_its_W")

    def spec_final(self):
        self.log.info("=== T20 spec: FINAL after W ===")
        b = self.batch("spec_final", 4, "spec")
        self.mtp_past(b["E"])
        t_u = self.release(b, "spec_final/release")
        st = self.send(self.start(b, t_u), "spec_final/SWEEP_START_to_pending")
        P = Utxo(st, 0, tx_from_hex(self.node.getrawtransaction(st)).vout[0])
        ptap, plv = b["pending"]
        self.mtp_past(self.csv_ready_at(st, W_SEC))
        fin = self.mktx([(P, W)], [self.out(P.amount - SFEE, self.wallet_spk(), self.X_OUT), self.fee(SFEE, self.X_OUT)])
        self.setwit(fin, 0, [self.sign(self.s_sec, fin, 0, plv["final"]), bytes(plv["final"]), control_block(ptap, "final")])
        self.send(fin, "spec_final/FINAL_after_W")

    # ------------------------------------------------------------------
    def corrected_old_nodes(self):
        self.log.info("=== T20 corrected: inner nodes on-chain before expiry get notice ===")
        b = self.batch("corr_old", 16, "token")
        root = b["root"]
        self.rec_script("corrected/batch_sweep", root["leaves"]["sweep"], root["tap"], "sweep")
        self.rec_script("corrected/inner_sweep", root["children"][0]["leaves"]["sweep"], root["children"][0]["tap"],
                        "sweep")
        ns = self.unroll(b["root_u"], root["tap"], root["leaves"], root["children"], "corr_old/root_unroll_early")
        self.mtp_past(max(b["E"], self.csv_ready_at(ns[0].txid, W_SEC)))
        t_u = self.release(b, "corr_old/release_to_R_W")
        items = [(ns[1], root["children"][1], W), (ns[3], root["children"][3], W)]
        self.reject(self.sweep(b, items, t_u), "corr_old/neg_old_inner_nodes_swept_at_release")
        n2 = root["children"][2]
        self.unroll(ns[2], n2["tap"], n2["leaves"], n2["children"], "corr_old/watcher_unrolls_inner_node_during_notice")
        self.mtp_past(self.csv_ready_at(t_u.txid, W_SEC))
        self.send(self.sweep(b, items, t_u), "corr_old/two_old_inner_nodes_swept_after_W")

    def corrected_late_nodes(self):
        self.log.info("=== T20 corrected: nodes that appear during the notice keep their own W ===")
        b = self.batch("corr_late", 16, "token")
        root = b["root"]
        self.mtp_past(b["E"])
        t_u = self.release(b, "corr_late/release_to_R_W")
        self.reject(self.sweep(b, [(b["root_u"], root, 0xfffffffe)], t_u), "corr_late/neg_root_swept_at_release")
        self.mtp_past(self.csv_ready_at(t_u.txid, W_SEC // 2))
        ns = self.unroll(b["root_u"], root["tap"], root["leaves"], root["children"],
                         "corr_late/watcher_unrolls_root_half_way_through_notice")
        self.mtp_past(self.csv_ready_at(t_u.txid, W_SEC))
        n0 = root["children"][0]
        self.reject(self.sweep(b, [(ns[0], n0, W)], t_u), "corr_late/neg_late_node_swept_when_T_is_ripe")
        self.mtp_past(self.csv_ready_at(ns[0].txid, W_SEC))
        self.send(self.sweep(b, [(ns[0], n0, W)], t_u), "corr_late/late_node_swept_after_its_own_W")

    def corrected_root(self):
        self.log.info("=== T20 corrected: root sweep, size ===")
        b = self.batch("corr_root", 4, "token")
        self.mtp_past(b["E"])
        t_u = self.release(b, "corr_root/release_to_R_W")
        self.mtp_past(self.csv_ready_at(t_u.txid, W_SEC))
        self.send(self.sweep(b, [(b["root_u"], b["root"], 0xfffffffe)], t_u), "corr_root/root_swept_after_W")


if __name__ == "__main__":
    T20().main()
