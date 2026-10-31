#!/usr/bin/env python3
"""T26: a batch without a sweep.

  batch output  [UNROLL]                                     no token, no clock
  lowest node   [UNROLL, [RECLAIM, RECLAIM-D]]
  entry         [unlock]
  checkpoint    [collab]
  leaf          [collab, exit]                               unchanged

The round issues nothing: it pays the batch output and its connector output.
Every forfeit is signed before the round is broadcast, against the connector
asset M its txid fixes; a participant who does not answer is left out and the
round is built again without it.

Flow:
  1. Round v1 for eight participants is built and not broadcast; participant 7
     never signs its forfeit, so round v2 is built for the other seven and
     their forfeits signed against v2's M; v2 is broadcast. v1 can then never
     confirm, nor its M be issued.
  2. Every removed path is forced into a block: the batch output, a lowest
     node with RECLAIM-D, a lowest node, an entry and a checkpoint, each spent
     by the sweep its twin with a sweep carries, a real token at R beside it.
     The twins are then swept by the same leaves (the control).
  3. Lowest node A comes back by RECLAIM-D: owner 0 paid its coin out of
     round (delegation to the receiver and its change), owners 1 to 3 released.
  4. Lowest node B is collected at the horizon: the operator unrolls it, claims
     the forfeit owner 5 gave up, opens owner 4's entry into owner 4's own leaf,
     and brings owner 6's payment to D on the chain (checkpoint, reassignment).
     Owner 4 and D, dormant all along, take their coins home with their own keys;
     the operator alone cannot.
"""
from arklib3 import *
import os as _os

LEAF = 1000_0000
RESERVE = 1000
FEE = 1500
CONN = 5_000
H = 3600
DELAY = rel_time(36 * H)
W_SEC = 1024
W = rel_time(W_SEC)


def leaves_under(n):
    return [n["idx"]] if n["kind"] == "leaf" else sum((leaves_under(k) for k in n["children"]), [])


def key():
    s = generate_privkey()
    return s, compute_xonly_pubkey(s)[0]


class T26(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t26"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.gen = self.genesis_internal()
        self.ctag = chain_tag(self.gen)
        self.Q = delegate_prefix(self.gen)
        self.s_sec, self.s_x = key()
        self.token()
        self.round()
        self.removed_root_and_nodes()
        self.reclaim_a()
        self.collect_b()
        self.dormant_go_home()
        self.control()

    # ---- the token a sweep would need, real, resting at R -------------------
    def token(self):
        """One atom of an asset T at R = <W> CSV DROP <S> CHECKSIG, confirmed
        W ago: everything a sweep needs beside the output it takes."""
        self.Rw, self.Rwlv = r_taptree(self.s_x, W)
        self.Rprog = bytes(self.Rw.scriptPubKey)[2:]
        w = self.wallet_utxo(2 * FEE + 5000, self.X)
        tx = self.mktx([w], [self.out(1, bytes(self.Rw.scriptPubKey), b"\x01" + bytes(32)),
                             self.out(w.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        tx.vin[0].assetIssuance = self.issuing_input(w)
        T_hex = self.issued_ids(tx)[0]
        self.T_id = bytes.fromhex(T_hex)[::-1]
        self.T_OUT = b"\x01" + self.T_id
        tx.vout[0].nAsset = CTxOutAsset(self.T_OUT)
        txid = self.send(self.wallet_sign(tx), "setup/token_T_at_R")
        self.T_u = self.utxo_at(txid, 0)
        self.sweep_root = sweep_token(self.T_id, self.Rprog, self.s_x)
        self.sweep_w = sweep_token(self.T_id, self.Rprog, self.s_x, W)
        self.wait_csv(txid, W_SEC)

    # ---- the round, its forfeits taken before broadcast ---------------------
    def participants(self, n):
        ps = []
        for i in range(n):
            old_sec, old_x = key()
            old_salt = _os.urandom(32)
            old_tap, old_lv = leaf3_taptree(old_x, self.s_x, old_salt, self.ctag, DELAY, fold=True)
            sec, x = key()
            ps.append({"i": i, "old_sec": old_sec, "old_x": old_x, "old_salt": old_salt, "old_tap": old_tap,
                       "old_lv": old_lv, "old_u": self.fund(old_tap.scriptPubKey, LEAF, self.X, mine=False),
                       "sec": sec, "x": x, "salt": _os.urandom(32), "pre": _os.urandom(32)})
        self.generate(self.node, 1)
        return ps

    def build_round(self, ps, w):
        """The no-sweep batch over the new leaves of `ps`, and the round paying
        it and its connector output from wallet coin `w`. Returns the signed,
        unbroadcast round, its txid and the connector asset M it fixes."""
        for p in ps:
            p["tap"], p["lv"] = leaf3_taptree(p["x"], self.s_x, p["salt"], self.ctag, DELAY, fold=True)
            p["h"] = sha256(p["pre"])
            p["etap"], p["elv"] = entry_taptree(p["h"], self.X_ID, LEAF, bytes(p["tap"].scriptPubKey)[2:], None)
        self.members = {}

        def scripts(kids, tuples, level, is_root):
            idx = sum((leaves_under(k) for k in kids), [])
            keys = [self.s_x] + [ps[i]["x"] for i in idx]
            levels, padded = hmerkle(keys, self.s_x)
            unroll = hgate_unroll(levels[-1][0], len(levels) - 1, tuples, timed=True)
            self.members[unroll] = (levels, keys, idx)
            if is_root:
                return [("unroll", unroll)], {"unroll": unroll}
            prefix = release_prefix(self.gen, tuples)
            owners = [ps[i]["x"] for i in idx]
            rc = reclaim_leaf(prefix, owners, self.s_x)
            rd = reclaim_delegated_leaf(prefix, self.Q, owners, self.s_x)
            lv = {"unroll": unroll, "reclaim": rc, "reclaim_d": rd, "prefix": prefix, "owners": owners}
            return [("unroll", unroll), [("reclaim", rc), ("reclaim_d", rd)]], lv
        root = build_tree3(self.X_ID, [bytes(p["etap"].scriptPubKey) for p in ps], LEAF + RESERVE, 4, RESERVE,
                           scripts)
        ctap, clv = connector_taptree(self.s_x)
        value = root["value"]
        tx = self.mktx([w], [self.out(value, root["spk"], self.X_OUT), self.out(CONN, bytes(ctap.scriptPubKey), self.X_OUT),
                             self.out(w.amount - value - CONN - FEE, self.wallet_spk(), self.X_OUT),
                             self.fee(FEE, self.X_OUT)])
        tx = self.wallet_sign(tx)
        txid = self.node.decoderawtransaction(tx.serialize().hex())["txid"]
        # M: what spending the connector output issues, fixed by the round's txid
        conn_u = Utxo(txid, 1, tx.vout[1])
        iss = self.mktx([conn_u], [self.out(1, OP_TRUE_SPK, b"\x01" + bytes(32)),
                                   self.out(CONN - FEE, OP_TRUE_SPK, self.X_OUT), self.fee(FEE, self.X_OUT)])
        iss.vin[0].assetIssuance = self.issuing_input(conn_u)
        m_id = bytes.fromhex(self.issued_ids(iss)[0])[::-1]
        iss.vout[0].nAsset = CTxOutAsset(b"\x01" + m_id)
        self.setwit(iss, 0, [self.sign(self.s_sec, iss, 0, clv["issue"]), bytes(clv["issue"]), control_block(ctap, "issue")])
        return {"tx": tx, "txid": txid, "root": root, "M": m_id, "issue_M": iss, "ps": ps}

    def forfeit(self, p, M, h, label=None):
        """p's forfeit of its old leaf, bound to round M: the pair the old owner
        and the operator sign over [the forfeit output], before broadcast."""
        old_leaf_id = sha256(b"leaf-id" + bytes(p["old_tap"].scriptPubKey))
        ftap, flv = forfeit_taptree(h, p["old_x"], self.s_x, DELAY, old_leaf_id, M)
        outs3 = [(self.X_ID, LEAF - FEE, bytes(ftap.scriptPubKey))]
        msg = rebind_msg3(self.ctag, p["old_salt"], self.X_ID, LEAF, outs3, fold=True)
        tx = self.mktx([p["old_u"]], [self.out(LEAF - FEE, bytes(ftap.scriptPubKey), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(p["old_sec"], msg), bytes([1]),
                            bytes(p["old_lv"]["collab"]), control_block(p["old_tap"], "collab")])
        return {"tx": tx, "tap": ftap, "lv": flv}

    def round(self):
        self.log.info("=== T26: round v1 for eight, participant 7 never answers, round v2 for seven ===")
        ps = self.participants(8)
        w = self.wallet_utxo(30 * LEAF, self.X)
        v1 = self.build_round(ps, w)
        answered = {p["i"]: self.forfeit(p, v1["M"], sha256(p["pre"])) for p in ps if p["i"] != 7}
        assert len(answered) == 7, "participant 7 gave no forfeit"
        self.rec("round/v1", {"txid": v1["txid"], "M": v1["M"].hex(), "participants": 8, "forfeits": 7,
                              "broadcast": False})
        # Built again without participant 7, from the same coin: v1 and v2 conflict.
        self.absent = ps[7]
        v2 = self.build_round(ps[:7], w)
        assert v2["txid"] != v1["txid"] and v2["M"] != v1["M"]
        self.forfeits = {p["i"]: self.forfeit(p, v2["M"], p["h"]) for p in ps[:7]}
        self.rec("round/v2", {"txid": v2["txid"], "M": v2["M"].hex(), "participants": 7, "forfeits": 7,
                              "forfeits_signed_before_broadcast": True})
        self.rec_script("scripts/root_unroll_only", v2["root"]["leaves"]["unroll"], v2["root"]["tap"], "unroll")
        n0 = v2["root"]["children"][0]
        for name in ("unroll", "reclaim", "reclaim_d"):
            self.rec_script("scripts/lowest_" + name, n0["leaves"][name], n0["tap"], name)
        self.rec_script("scripts/entry_unlock_only", ps[0]["elv"]["unlock"], ps[0]["etap"], "unlock")
        t = self.send(v2["tx"], "round/v2_no_token_no_clock")
        d = self.node.getrawtransaction(t, True)
        assert all("issuance" not in i for i in d["vin"]), "the round issues no token"
        assert len(d["vout"]) == 4
        self.v2 = v2
        self.ps = ps[:7]
        self.root_u = self.utxo_at(t, 0)
        # v1 conflicts with v2, so v1's M can never be issued: its connector output never exists.
        self.reject(v1["tx"], "neg/round_v1_after_v2", expect="missingorspent", block="bad-txns-inputs-missingorspent")
        self.reject(v1["issue_M"], "neg/issue_M_of_round_v1", expect="missingorspent",
                    block="bad-txns-inputs-missingorspent")
        mt = self.send(v2["issue_M"], "round/issue_M_of_round_v2")
        self.M2 = {"M_id": v2["M"], "M_OUT": b"\x01" + v2["M"], "M_u": self.utxo_at(mt, 0)}
        # Round 3, where owners 0 to 5 and owner 0's receiver refresh: its M issued for real.
        self.M3 = self.connector_atom(self.s_sec, "setup/issue M of round 3")
        self.signed_before_broadcast(answered)

    def signed_before_broadcast(self, v1_forfeits):
        """Participant 0's forfeit, signed before v2 was broadcast, is claimed
        with v2's M. Participant 1's forfeit for v1, published anyway, can
        never be claimed: v1's M does not exist. Its owner refunds."""
        self.log.info("=== T26: forfeits signed before broadcast ===")
        p0, p1 = self.ps[0], self.ps[1]
        f0 = self.forfeits[0]
        fu = self.utxo_at(self.send(f0["tx"], "forfeit/p0_v2_forfeit_published"), 0)

        def claim(f, fu, pre, m):
            tx = self.mktx([fu, m["M_u"]], [self.out(fu.amount - FEE, self.wallet_spk(), self.X_OUT),
                                            self.out(1, OP_TRUE_SPK, m["M_OUT"]), self.fee(FEE, self.X_OUT)])
            self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, f["lv"]["claim"]), pre, sn(1), bytes(f["lv"]["claim"]),
                                control_block(f["tap"], "claim")])
            self.setwit(tx, 1, OP_TRUE_WITNESS)
            return tx
        self.reject(claim(f0, fu, p0["pre"], self.M3), "neg/p0_forfeit_claim_with_another_rounds_M",
                    expect="OP_EQUALVERIFY")
        t = self.send(claim(f0, fu, p0["pre"], self.M2), "forfeit/p0_claimed_with_v2s_M")
        self.M2["M_u"] = self.utxo_at(t, 1)
        f1 = v1_forfeits[1]
        fu1 = self.utxo_at(self.send(f1["tx"], "forfeit/p1_v1_forfeit_published_anyway"), 0)
        self.reject(claim(f1, fu1, p1["pre"], self.M2), "neg/p1_v1_forfeit_claim_with_v2s_M", expect="OP_EQUALVERIFY")
        self.mtp_past(self.csv_ready_at(fu1.txid, 36 * H))
        tx = self.mktx([(fu1, DELAY)], [self.out(fu1.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(p1["old_sec"], tx, 0, f1["lv"]["refund"]), bytes(f1["lv"]["refund"]),
                            control_block(f1["tap"], "refund")])
        self.send(tx, "forfeit/p1_refunds_its_old_coin")

    # ---- the removed paths ----------------------------------------------------
    def sweep_tx(self, u, seq, sweep, twin_tap, k=1):
        """The sweep a twin with a sweep would take: input 0 the output, input
        1 the token at R; outputs: the value to the operator, T back to R."""
        tx = self.mktx([(u, seq), (self.T_u, W)],
                       [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT),
                        self.out(1, bytes(self.Rw.scriptPubKey), self.T_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sweep), sn(k), bytes(sweep), control_block(twin_tap, "sweep")])
        rs = self.Rwlv["spend"]
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, rs), bytes(rs), control_block(self.Rw, "spend")])
        return tx

    def removed(self, u, seq, sweep, twin_tap, label):
        """`u`, an output of the batch without a sweep, spent by the sweep leaf
        of its twin: with the twin's control block, and as a lone leaf."""
        self.reject(self.sweep_tx(u, seq, sweep, twin_tap), "removed/%s_twin_control_block" % label,
                    expect="Witness program hash mismatch")
        lone = taproot_construct(NUMS, [("sweep", sweep)])
        self.reject(self.sweep_tx(u, seq, sweep, lone), "removed/%s_lone_leaf" % label,
                    expect="Witness program hash mismatch")
        self.twins.append((u, seq, sweep, twin_tap, label))

    def removed_root_and_nodes(self):
        self.log.info("=== T26: the sweep is gone from every output above a leaf ===")
        self.twins = []
        root = self.v2["root"]
        self.wait_csv(self.root_u.txid, W_SEC)
        twin, _ = node_taptree3(root["leaves"]["unroll"], self.sweep_root)
        self.removed(self.root_u, 0xfffffffe, self.sweep_root, twin, "batch_output")
        # The operator unrolls the batch output with its own authorisation.
        t = self.mtp() - 60
        self.nodes_u = self.gated_unroll(self.root_u, root, 0, self.s_sec, t, "collect/unroll_batch_output_by_operator")
        self.wait_csv(self.nodes_u[0].txid, W_SEC)
        for j, name in ((0, "lowest_node_a"), (1, "lowest_node_b")):
            n = root["children"][j]
            lv = n["leaves"]
            twin, _ = node_taptree_delegated(lv["unroll"], self.sweep_w, lv["reclaim"], lv["reclaim_d"])
            self.removed(self.nodes_u[j], W, self.sweep_w, twin, name)
        # A lowest node of a batch without RECLAIM-D: [UNROLL, RECLAIM].
        n = root["children"][1]
        lv = n["leaves"]
        plain, _ = node_taptree3(lv["unroll"], None, lv["reclaim"])
        twin, _ = node_taptree3(lv["unroll"], self.sweep_w, lv["reclaim"])
        pu = self.fund(plain.scriptPubKey, n["value"], self.X)
        self.wait_csv(pu.txid, W_SEC)
        self.removed(pu, W, self.sweep_w, twin, "lowest_node_without_reclaim_d")
        self.plain_lowest = (plain, pu, n)

    def gated_unroll(self, u, n, signer_pos, sec, t, label):
        levels, keys, idx = self.members[n["leaves"]["unroll"]]
        tuples = [(self.X_ID, k["value"], k["spk"][2:]) for k in n["children"]]
        sig = sign_schnorr(sec, unroll_auth3(tuples, t))
        wit = hgate_witness(sig, mpath(levels, signer_pos), keys[signer_pos], t)
        outs = [self.out(k["value"], k["spk"], self.X_OUT) for k in n["children"]]
        leaf = n["leaves"]["unroll"]
        tx = self.mktx([(u, 0xfffffffe)], outs + [self.fee(RESERVE, self.X_OUT)], t)
        self.setwit(tx, 0, wit + [bytes(leaf), control_block(n["tap"], "unroll")])
        txid = self.send(tx, label, extra={"members": len(keys), "leaf_bytes": len(bytes(leaf)),
                                           "control_block_bytes": len(control_block(n["tap"], "unroll"))})
        return [Utxo(txid, i, tx.vout[i]) for i in range(len(n["children"]))]

    # ---- node A: RECLAIM-D ------------------------------------------------------
    def reclaim_a(self):
        self.log.info("=== T26: lowest node A comes back by RECLAIM-D ===")
        n = self.v2["root"]["children"][0]
        lv = n["leaves"]
        u = self.nodes_u[0]
        ps = self.ps[:4]
        M3 = self.M3["M_id"]
        prefix = lv["prefix"]
        # Owner 0 paid its coin out of round: to C, with change to A0'. Its key
        # delegated to both; both refreshed into round 3 and released.
        (c_sec, c_x), (ch_sec, ch_x) = key(), key()
        rel = lambda sec, x: rel_node(x, sign_schnorr(sec, sha256(prefix + M3)), 1)
        t0 = del_node(ps[0]["x"], sign_schnorr(ps[0]["sec"], delegate_msg(self.gen, [c_x, ch_x])),
                      [rel(c_sec, c_x), rel(ch_sec, ch_x)])
        trees = [t0] + [rel(p["sec"], p["x"]) for p in ps[1:]]

        def tx_for(trees, s_sec=None):
            outs = [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT), self.out(1, OP_TRUE_SPK, self.M3["M_OUT"]),
                    self.fee(FEE, self.X_OUT)]
            tx = self.mktx([u, self.M3["M_u"]], outs)
            script = lv["reclaim_d"]
            below = reclaim_delegated_items(self.sign(s_sec or self.s_sec, tx, 0, script), prefix, self.Q, trees)
            self.setwit(tx, 0, below + [bytes(script), control_block(n["tap"], "reclaim_d")])
            self.setwit(tx, 1, OP_TRUE_WITNESS)
            return tx
        # Owner 3 dormant: its release missing. The node waits; the operator alone cannot take it.
        self.reject(tx_for(trees[:3] + [rel(*key())]), "neg/reclaim_d_owner3_absent_another_key",
                    expect="OP_EQUALVERIFY")
        self.reject(tx_for(trees[:3] + [rel_node(ps[3]["x"], _os.urandom(64), 1)]),
                    "neg/reclaim_d_owner3_absent_forged_signature", expect="Invalid Schnorr signature")
        self.reject(tx_for(trees[:3]), "neg/reclaim_d_three_trees_for_four", expect="OP_EQUALVERIFY")
        self.reject(tx_for(trees, s_sec=generate_privkey()), "neg/reclaim_d_operator_key_wrong",
                    expect="Invalid Schnorr signature")
        txid = self.send(tx_for(trees), "collect/reclaim_d_lowest_node_a",
                         extra={"control_block_bytes": len(control_block(n["tap"], "reclaim_d"))})
        self.M3["M_u"] = self.utxo_at(txid, 1)
        assert self.node.gettxout(u.txid, u.vout) is None
        self.final(txid, "collect/reclaim_d_lowest_node_a")
        # RECLAIM on the node of a batch without RECLAIM-D, [UNROLL, RECLAIM].
        plain, pu, pn = self.plain_lowest
        sigs = [sign_schnorr(p["sec"], sha256(pn["leaves"]["prefix"] + M3)) for p in self.ps[4:7]]
        outs = [self.out(pu.amount - FEE, self.wallet_spk(), self.X_OUT), self.out(1, OP_TRUE_SPK, self.M3["M_OUT"]),
                self.fee(FEE, self.X_OUT)]
        tx = self.mktx([pu, self.M3["M_u"]], outs)
        rc = pn["leaves"]["reclaim"]
        self.setwit(tx, 0, reclaim_items(self.sign(self.s_sec, tx, 0, rc), sigs, [1] * 3)
                    + [bytes(rc), control_block(plain, "reclaim")])
        self.setwit(tx, 1, OP_TRUE_WITNESS)
        t2 = self.send(tx, "collect/reclaim_lowest_node_without_reclaim_d")
        self.M3["M_u"] = self.utxo_at(t2, 1)

    def final(self, txid, label):
        """Final: confirmed and buried; the output it spent is gone for good."""
        self.generate(self.node, 6)
        conf = self.node.getrawtransaction(txid, True)["confirmations"]
        assert conf >= 7
        self.rec(label + "/final", {"confirmations": conf})

    # ---- node B: collected at the horizon ----------------------------------------
    def collect_b(self):
        self.log.info("=== T26: lowest node B collected at the horizon ===")
        n = self.v2["root"]["children"][1]
        p4, p5, p6 = self.ps[4:7]
        # Owner 5 gave its coin up in round 3: its forfeit, signed before round 3
        # was broadcast, names round 3's M and the preimage of its new entry.
        q5 = _os.urandom(32)
        lid = sha256(b"leaf-id" + bytes(p5["tap"].scriptPubKey))
        f5tap, f5lv = forfeit_taptree(sha256(q5), p5["x"], self.s_x, DELAY, lid, self.M3["M_id"])
        # Owner 6 paid its coin to D out of round: checkpoint and reassignment,
        # both co-signed when it paid. D stays away.
        d_sec, d_x = key()
        cp_salt = sha256(b"Arca/checkpoint" + p6["salt"])
        cptap, cplv = checkpoint_taptree(p6["x"], self.s_x, cp_salt, self.ctag, None)
        dsalt = _os.urandom(32)
        dtap, dlv = leaf3_taptree(d_x, self.s_x, dsalt, self.ctag, DELAY, fold=True)
        self.rec_script("scripts/checkpoint_collab_only", cplv["collab"], cptap, "collab")

        u = self.nodes_u[1]
        t = self.mtp() - 60
        es = self.gated_unroll(u, n, 0, self.s_sec, t, "collect/unroll_lowest_node_b_by_operator")
        self.wait_csv(es[0].txid, W_SEC)
        for e, p in zip(es, (p4, p5, p6)):
            twin, _ = entry_taptree(p["h"], self.X_ID, LEAF, bytes(p["tap"].scriptPubKey)[2:], self.sweep_w)
            self.removed(e, W, self.sweep_w, twin, "entry_%d" % p["i"])
        # Nobody opens owner 4's entry anywhere but into its leaf.
        bad = self.mktx([es[0]], [self.out(LEAF, self.wallet_spk(), self.X_OUT), self.fee(RESERVE, self.X_OUT)])
        self.setwit(bad, 0, [p4["pre"], bytes(p4["elv"]["unlock"]), control_block(p4["etap"], "unlock")])
        self.reject(bad, "neg/entry4_unlocked_to_the_operator", expect="OP_EQUALVERIFY")

        def unlock(e, p, label):
            tx = self.mktx([e], [self.out(LEAF, bytes(p["tap"].scriptPubKey), self.X_OUT), self.fee(RESERVE, self.X_OUT)])
            self.setwit(tx, 0, [p["pre"], bytes(p["elv"]["unlock"]), control_block(p["etap"], "unlock")])
            return self.utxo_at(self.send(tx, label), 0)

        # Owner 5's coin, given up: entry, the forfeit it signed, the operator's claim.
        l5 = unlock(es[1], p5, "collect/entry5_unlock")
        outs3 = [(self.X_ID, LEAF - FEE, bytes(f5tap.scriptPubKey))]
        msg = rebind_msg3(self.ctag, p5["salt"], self.X_ID, LEAF, outs3, fold=True)
        ft = self.mktx([l5], [self.out(LEAF - FEE, bytes(f5tap.scriptPubKey), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(ft, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(p5["sec"], msg), bytes([1]),
                            bytes(p5["lv"]["collab"]), control_block(p5["tap"], "collab")])
        fu = self.utxo_at(self.send(ft, "collect/forfeit5_published"), 0)

        def claim(m, pre, label=None):
            tx = self.mktx([fu, m["M_u"]], [self.out(fu.amount - FEE, self.wallet_spk(), self.X_OUT),
                                            self.out(1, OP_TRUE_SPK, m["M_OUT"]), self.fee(FEE, self.X_OUT)])
            self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, f5lv["claim"]), pre, sn(1), bytes(f5lv["claim"]),
                                control_block(f5tap, "claim")])
            self.setwit(tx, 1, OP_TRUE_WITNESS)
            return tx
        self.reject(claim(self.M2, q5), "neg/forfeit5_claim_with_round2_M", expect="OP_EQUALVERIFY")
        self.reject(claim(self.M3, p5["pre"]), "neg/forfeit5_claim_with_the_old_preimage", expect="OP_EQUALVERIFY")
        ct = self.send(claim(self.M3, q5), "collect/forfeit5_claimed_by_operator")
        self.M3["M_u"] = self.utxo_at(ct, 1)
        self.final(ct, "collect/forfeit5_claimed_by_operator")
        # Owner 4, dormant: its entry opened into its own leaf.
        self.l4 = unlock(es[0], p4, "collect/entry4_into_owner4s_own_leaf")
        # Owner 6's payment to D: entry, checkpoint, reassignment, D's leaf on the chain.
        l6 = unlock(es[2], p6, "collect/entry6_unlock")
        o = [(self.X_ID, LEAF - FEE, bytes(cptap.scriptPubKey))]
        msg = rebind_msg3(self.ctag, p6["salt"], self.X_ID, LEAF, o, fold=True)
        tx = self.mktx([l6], [self.out(LEAF - FEE, bytes(cptap.scriptPubKey), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(p6["sec"], msg), bytes([1]),
                            bytes(p6["lv"]["collab"]), control_block(p6["tap"], "collab")])
        cpu = self.utxo_at(self.send(tx, "collect/checkpoint6_published"), 0)
        self.wait_csv(cpu.txid, W_SEC)
        twin, _ = checkpoint_taptree(p6["x"], self.s_x, cp_salt, self.ctag, self.sweep_w)
        self.removed(cpu, W, self.sweep_w, twin, "checkpoint")
        o = [(self.X_ID, LEAF - 2 * FEE, bytes(dtap.scriptPubKey))]
        msg = rebind_msg3(self.ctag, cp_salt, self.X_ID, LEAF - FEE, o, fold=True)
        tx = self.mktx([cpu], [self.out(LEAF - 2 * FEE, bytes(dtap.scriptPubKey), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(p6["sec"], msg), bytes([1]),
                            bytes(cplv["collab"]), control_block(cptap, "collab")])
        self.ld = self.utxo_at(self.send(tx, "collect/reassignment6_to_d"), 0)
        self.d = (d_sec, d_x, dtap, dlv, dsalt)
        self.p4 = p4

    def dormant_go_home(self):
        self.log.info("=== T26: the dormant holders take their coins home; the operator alone cannot ===")
        p4 = self.p4
        d_sec, d_x, dtap, dlv, dsalt = self.d

        def exit_tx(u, sec, tap, lv):
            tx = self.mktx([(u, DELAY)], [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
            self.setwit(tx, 0, [self.sign(sec, tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
            return tx

        def operator_collab(u, salt, tap, lv):
            o = [(self.X_ID, u.amount - FEE, self.wallet_spk())]
            msg = rebind_msg3(self.ctag, salt, self.X_ID, u.amount, o, fold=True)
            tx = self.mktx([u], [self.out(u.amount - FEE, o[0][2], self.X_OUT), self.fee(FEE, self.X_OUT)])
            self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(self.s_sec, msg), bytes([1]),
                                bytes(lv["collab"]), control_block(tap, "collab")])
            return tx
        self.mtp_past(max(self.csv_ready_at(self.l4.txid, 36 * H), self.csv_ready_at(self.ld.txid, 36 * H)))
        self.reject(exit_tx(self.l4, self.s_sec, p4["tap"], p4["lv"]), "neg/owner4_exit_signed_by_operator",
                    expect="Invalid Schnorr signature")
        self.reject(operator_collab(self.l4, p4["salt"], p4["tap"], p4["lv"]), "neg/owner4_collab_operator_alone",
                    expect="Invalid Schnorr signature")
        self.reject(exit_tx(self.ld, self.s_sec, dtap, dlv), "neg/d_exit_signed_by_operator",
                    expect="Invalid Schnorr signature")
        self.reject(operator_collab(self.ld, dsalt, dtap, dlv), "neg/d_collab_operator_alone",
                    expect="Invalid Schnorr signature")
        t4 = self.send(exit_tx(self.l4, p4["sec"], p4["tap"], p4["lv"]), "home/owner4_exit_own_key")
        td = self.send(exit_tx(self.ld, d_sec, dtap, dlv), "home/d_exit_own_key")
        self.final(t4, "home/owner4_exit_own_key")
        self.final(td, "home/d_exit_own_key")

    # ---- the control: the same sweeps take the twins ------------------------------
    def control(self):
        self.log.info("=== T26: control: each twin with a sweep is swept by the same leaf ===")
        for u, seq, sweep, twin_tap, label in self.twins:
            tu = self.fund(twin_tap.scriptPubKey, u.amount, self.X)
            self.wait_csv(tu.txid, W_SEC)
            txid = self.send(self.sweep_tx(tu, seq, sweep, twin_tap), "control/%s_twin_swept" % label)
            self.T_u = self.utxo_at(txid, 1)
            self.wait_csv(txid, W_SEC)


if __name__ == "__main__":
    T26().main()
