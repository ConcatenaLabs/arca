#!/usr/bin/env python3
"""T21: a 16-leaf tree in a non-policy asset with every adopted change.

  leaf        [collab (coin- and chain-bound, folded constant), exit]          no sweep
  lowest node [hardened timed gated UNROLL, [token sweep + W, RECLAIM]]
  root        [hardened timed gated UNROLL, token sweep]
  R_W         <W> CSV DROP <S> CHECKSIG   (notice on the token)
  clocks      clock0 {ROLL, RELEASE E0} -> clock1 {RELEASE E1}

Flow: round (issues T) -> owner unrolls root and lowest node 0 with its own
timed authorisation -> exit (leaf 0), rebindable transfer (leaf 1), forfeit
and operator claim (leaf 2) -> reclaim of lowest node 1 -> watch service unrolls
lowest node 2 with a time-limited authorisation and its own fee -> roll ->
release -> noticed sweep of lowest node 3.
Then: gated node sizes at member depths 3..11 for the 1,024-leaf arithmetic.
"""
from arklib3 import *
import os as _os

LEAF = 1000_0000
RESERVE = 1000
FEE = 600
SFEE = 3000
H = 3600
W_SEC = 36 * H
W = rel_time(W_SEC)
DELAY = rel_time(36 * H)


def leaves_under(n):
    return [n["idx"]] if n["kind"] == "leaf" else sum((leaves_under(k) for k in n["children"]), [])


class T21(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t21"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.rec("asset", {"X": self.X, "policy_asset": self.POL, "X_is_policy": self.X == self.POL})
        self.clock_start()
        self.gen = self.genesis_internal()
        self.ctag = chain_tag(self.gen)
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.Rw, self.Rwlv = r_taptree(self.s_x, W)
        self.flow()
        self.depths()

    # ------------------------------------------------------------------
    def build(self, T_id, E):
        self.osec = [generate_privkey() for _ in range(16)]
        self.ox = [compute_xonly_pubkey(k)[0] for k in self.osec]
        self.salts = [_os.urandom(32) for _ in range(16)]
        self.lf = [leaf3_taptree(self.ox[i], self.s_x, self.salts[i], self.ctag, DELAY, fold=True) for i in range(16)]
        Rprog = bytes(self.Rw.scriptPubKey)[2:]
        self.members = {}

        def scripts(kids, tuples, level, is_root):
            idx = sum((leaves_under(k) for k in kids), [])
            keys = [self.s_x] + [self.ox[i] for i in idx]
            levels, padded = hmerkle(keys, self.s_x)
            unroll = hgate_unroll(levels[-1][0], len(levels) - 1, tuples, timed=True)
            if is_root:
                sw = sweep_token(T_id, Rprog, self.s_x)
                tree = [("unroll", unroll), ("sweep", sw)]
                lv = {"unroll": unroll, "sweep": sw}
            else:
                sw = sweep_token(T_id, Rprog, self.s_x, W)
                rc = reclaim_leaf(release_prefix(self.gen, tuples), [self.ox[i] for i in idx], self.s_x)
                tree = [("unroll", unroll), [("sweep", sw), ("reclaim", rc)]]
                lv = {"unroll": unroll, "sweep": sw, "reclaim": rc}
            self.members[unroll] = (levels, keys, idx)
            return tree, lv
        root = build_tree3(self.X_ID, [bytes(t.scriptPubKey) for t, _ in self.lf], LEAF, 4, RESERVE, scripts)
        self.clocks = clock_chain(T_id, bytes(self.Rw.scriptPubKey), self.s_x, E)
        self.root = root
        return root["spk"], self.clocks[0]["spk"]

    def gated_unroll(self, u, n, signer_pos, sec, t, label, external=False, only_tx=False):
        """signer_pos: index in the node's member list (0 = operator)."""
        levels, keys, idx = self.members[n["leaves"]["unroll"]]
        tuples = [(self.X_ID, k["value"], k["spk"][2:]) for k in n["children"]]
        sig = sign_schnorr(sec, unroll_auth3(tuples, t))
        wit = hgate_witness(sig, mpath(levels, signer_pos), keys[signer_pos], t)
        outs = [self.out(k["value"], k["spk"], self.X_OUT) for k in n["children"]]
        leaf = n["leaves"]["unroll"]
        if external:
            tx = self.with_fee_input([(u, 0xfffffffe)], outs, leftover_out=self.out(RESERVE, self.wallet_spk(), self.X_OUT),
                                     locktime=t)
            self.setwit(tx, 0, wit + [bytes(leaf), control_block(n["tap"], "unroll")])
            tx = self.wallet_sign(tx)
        else:
            tx = self.mktx([(u, 0xfffffffe)], outs + [self.fee(RESERVE, self.X_OUT)], t)
            self.setwit(tx, 0, wit + [bytes(leaf), control_block(n["tap"], "unroll")])
        if only_tx:
            return tx
        txid = self.send(tx, label, extra={"member_depth": len(levels) - 1, "members": len(keys),
                                           "leaf_bytes": len(bytes(leaf))})
        return [Utxo(txid, i, tx.vout[i]) for i in range(len(n["children"]))]

    def collab(self, u, i, outs3, label, fee_out=True):
        tap, lv = self.lf[i]
        msg = rebind_msg3(self.ctag, self.salts[i], self.X_ID, u.amount, outs3, fold=True)
        outs = [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs3]
        left = u.amount - sum(v for (_, v, _) in outs3)
        tx = self.mktx([u], outs + [self.fee(left, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, msg), sign_schnorr(self.osec[i], msg), bytes([len(outs3)]),
                            bytes(lv["collab"]), control_block(tap, "collab")])
        return self.send(tx, label)

    # ------------------------------------------------------------------
    def flow(self):
        node = self.node
        t_created = self.mtp() - 60
        E0, E1 = t_created + 10 * 24 * H, t_created + 20 * 24 * H
        b = self.issuing_round(tree_value(16, LEAF, 4, RESERVE), lambda T: self.build(T, [E0, E1]), "round")
        T_OUT, root = b["T_OUT"], self.root
        self.rec("schedule", {"created": t_created, "E0": E0, "E1": E1, "W": W_SEC})
        self.rec_script("scripts/leaf_collab", self.lf[0][1]["collab"], self.lf[0][0], "collab")
        self.rec_script("scripts/leaf_exit", self.lf[0][1]["exit"], self.lf[0][0], "exit")
        self.rec_script("scripts/root_unroll_gated_32", root["leaves"]["unroll"], root["tap"], "unroll")
        self.rec_script("scripts/root_sweep_token", root["leaves"]["sweep"], root["tap"], "sweep")
        n0 = root["children"][0]
        self.rec_script("scripts/lowest_unroll_gated_8", n0["leaves"]["unroll"], n0["tap"], "unroll")
        self.rec_script("scripts/lowest_sweep_token_W", n0["leaves"]["sweep"], n0["tap"], "sweep")
        self.rec_script("scripts/lowest_reclaim", n0["leaves"]["reclaim"], n0["tap"], "reclaim")
        self.rec_script("scripts/clock0_roll", self.clocks[0]["lv"]["roll"], self.clocks[0]["tap"], "roll")
        self.rec_script("scripts/clock0_release", self.clocks[0]["lv"]["release"], self.clocks[0]["tap"], "release")
        self.rec_script("scripts/R_W", self.Rwlv["spend"], self.Rw, "spend")

        # owner 0 signs its own authorisation with the batch's creation time and exits
        ns = self.gated_unroll(b["root_u"], root, 1, self.osec[0], t_created, "unroll/root_by_owner0_own_auth")
        ls = self.gated_unroll(ns[0], n0, 1, self.osec[0], t_created, "unroll/lowest0_by_owner0_own_auth")
        # exit, leaf 0
        self.mtp_past(self.csv_ready_at(ls[0].txid, 36 * H))
        tap, lv = self.lf[0]
        tx = self.mktx([(ls[0], DELAY)], [self.out(LEAF - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.osec[0], tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
        self.send(tx, "leaf/exit_claim_leaf0")
        # rebindable transfer, leaf 1: receiver + change
        rx = compute_xonly_pubkey(generate_privkey())[0]
        recv = leaf3_taptree(rx, self.s_x, _os.urandom(32), self.ctag, DELAY, fold=True)[0]
        chg = leaf3_taptree(self.ox[1], self.s_x, _os.urandom(32), self.ctag, DELAY, fold=True)[0]
        self.collab(ls[1], 1, [(self.X_ID, 6000_000, bytes(recv.scriptPubKey)),
                               (self.X_ID, LEAF - 6000_000 - FEE, bytes(chg.scriptPubKey))], "leaf/transfer_m2_leaf1")
        self.collab_one = None
        # forfeit, leaf 2: into [claim: preimage + S | refund: delay + A], then the operator's claim
        pre = _os.urandom(32)
        claim = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, sha256(pre), OP_EQUALVERIFY, self.s_x, OP_CHECKSIG])
        refund = CScript([DELAY, OP_CHECKSEQUENCEVERIFY, OP_DROP, self.ox[2], OP_CHECKSIG])
        ftap = taproot_construct(NUMS, [("claim", claim), ("refund", refund)])
        ft = self.collab(ls[2], 2, [(self.X_ID, LEAF - FEE, bytes(ftap.scriptPubKey))], "leaf/forfeit_leaf2")
        fu = self.utxo_at(ft, 0)
        tx = self.mktx([fu], [self.out(fu.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, claim), pre, bytes(claim), control_block(ftap, "claim")])
        self.send(tx, "leaf/forfeit_claim_by_operator")

        # reclaim of lowest node 1 (on-chain since the root unroll): owners 4..7
        # refreshed in one round and released, naming its connector asset M;
        # the operator issues M from that round's connector output and spends
        # the atom beside the node
        m = self.connector_atom(self.s_sec, "reclaim/issue M of the owners' new round")
        n1 = root["children"][1]
        tuples = [(self.X_ID, k["value"], k["spk"][2:]) for k in n1["children"]]
        rel = release_msg(self.gen, tuples, m["M_id"])
        sigs = [sign_schnorr(self.osec[i], rel) for i in (4, 5, 6, 7)]
        rc = n1["leaves"]["reclaim"]
        tx = self.mktx([ns[1], m["M_u"]], [self.out(ns[1].amount - FEE, self.wallet_spk(), self.X_OUT),
                                           self.out(1, OP_TRUE_SPK, m["M_OUT"]), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, reclaim_items(self.sign(self.s_sec, tx, 0, rc), sigs, [1] * 4)
                    + [bytes(rc), control_block(n1["tap"], "reclaim")])
        self.setwit(tx, 1, OP_TRUE_WITNESS)
        self.send(tx, "reclaim/lowest1")

        # watch service for owner 8 (lowest node 2): authorisation not before E0 - 3 days
        n2 = root["children"][2]
        t_watch = E0 - 3 * 24 * H
        self.reject(self.gated_unroll(ns[2], n2, 1, self.osec[8], t_watch, None, external=True, only_tx=True),
                    "neg/watch_service_unroll_before_t")
        self.mtp_past(t_watch)
        l2 = self.gated_unroll(ns[2], n2, 1, self.osec[8], t_watch, "unroll/lowest2_by_watch_service_external_fee",
                               external=True)
        # owner 8 exits paying the fee with an outside coin in the policy asset (X kept whole)
        self.mtp_past(self.csv_ready_at(l2[0].txid, 36 * H))
        tap, lv = self.lf[8]
        tx = self.with_fee_input([(l2[0], DELAY)], [self.out(LEAF, self.wallet_spk(), self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.osec[8], tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
        self.send(self.wallet_sign(tx), "leaf/exit_claim_leaf8_external_fee")

        # roll the clock, then release at the new expiry and sweep lowest node 3 after the notice
        c0 = self.clocks[0]
        tx = self.with_fee_input([b["T_u"]], [self.out(1, self.clocks[1]["spk"], T_OUT)])
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, c0["lv"]["roll"]), bytes(c0["lv"]["roll"]),
                            control_block(c0["tap"], "roll")])
        r = self.send(self.wallet_sign(tx), "clock/roll")
        self.mtp_past(E1)
        c1 = self.clocks[1]
        tx = self.with_fee_input([(self.utxo_at(r, 0), 0xfffffffe)], [self.out(1, bytes(self.Rw.scriptPubKey), T_OUT)],
                                 locktime=E1)
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, c1["lv"]["release"]), bytes(c1["lv"]["release"]),
                            control_block(c1["tap"], "release")])
        rl = self.send(self.wallet_sign(tx), "clock/release")
        n3 = root["children"][3]

        def sweep():
            tx = self.mktx([(ns[3], W), (self.utxo_at(rl, 0), W)],
                           [self.out(ns[3].amount - SFEE, self.wallet_spk(), self.X_OUT),
                            self.out(1, bytes(self.Rw.scriptPubKey), T_OUT), self.fee(SFEE, self.X_OUT)])
            sw = n3["leaves"]["sweep"]
            self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sw), sn(1), bytes(sw), control_block(n3["tap"], "sweep")])
            rs = self.Rwlv["spend"]
            self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, rs), bytes(rs), control_block(self.Rw, "spend")])
            return tx
        self.reject(sweep(), "neg/sweep_lowest3_at_release_no_notice")
        self.mtp_past(self.csv_ready_at(rl, W_SEC))
        self.send(sweep(), "sweep/lowest3_after_notice")

    # ------------------------------------------------------------------
    def depths(self):
        """Hardened timed gated node, radix 4, reserve fee, at member depths
        3, 5, 7, 9, 11 (= 4^k owners + operator, padded), as the nodes of a
        1,024-leaf tree from the lowest level to the root. Lowest-level nodes
        carry the reclaim leaf beside the sweep."""
        self.log.info("=== T21: gated node size by member depth ===")
        Rprog = bytes(self.Rw.scriptPubKey)[2:]
        T_fake = sha256(b"T")
        for owners, depth_expected, lowest in ((4, 3, True), (16, 5, False), (64, 7, False), (256, 9, False),
                                               (1024, 11, False)):
            secs = [generate_privkey() for _ in range(min(owners, 4))]
            keys = [self.s_x] + [compute_xonly_pubkey(s)[0] for s in secs] + \
                [sha256(b"k%d" % i) for i in range(owners - len(secs))]
            levels, padded = hmerkle(keys, self.s_x)
            assert len(levels) - 1 == depth_expected
            spks = [self.p2tr()[0] for _ in range(4)]
            tuples = [(self.X_ID, LEAF, s[2:]) for s in spks]
            unroll = hgate_unroll(levels[-1][0], depth_expected, tuples, timed=True)
            if lowest:
                sw = sweep_token(T_fake, Rprog, self.s_x, W)
                rc = reclaim_leaf(release_prefix(self.gen, tuples), [compute_xonly_pubkey(s)[0] for s in secs], self.s_x)
                tap = taproot_construct(NUMS, [("unroll", unroll), [("sweep", sw), ("reclaim", rc)]])
            else:
                sw = sweep_token(T_fake, Rprog, self.s_x, W)
                tap = taproot_construct(NUMS, [("unroll", unroll), ("sweep", sw)])
            u = self.fund(tap.scriptPubKey, 4 * LEAF + RESERVE, self.X)
            t = self.mtp() - 60
            sig = sign_schnorr(secs[0], unroll_auth3(tuples, t))
            tx = self.mktx([(u, 0xfffffffe)], [self.out(LEAF, s, self.X_OUT) for s in spks] +
                           [self.fee(RESERVE, self.X_OUT)], t)
            self.setwit(tx, 0, hgate_witness(sig, mpath(levels, 1), keys[1], t) + [bytes(unroll),
                                                                                   control_block(tap, "unroll")])
            self.send(tx, "depth/members_%d_depth_%d" % (owners + 1, depth_expected),
                      extra={"leaf_bytes": len(bytes(unroll))})
            ext = self.with_fee_input([(u if False else self.fund(tap.scriptPubKey, 4 * LEAF + RESERVE, self.X),
                                        0xfffffffe)],
                                      [self.out(LEAF, s, self.X_OUT) for s in spks],
                                      leftover_out=self.out(RESERVE, self.wallet_spk(), self.X_OUT), locktime=t)
            self.setwit(ext, 0, hgate_witness(sign_schnorr(secs[0], unroll_auth3(tuples, t)), mpath(levels, 1), keys[1],
                                              t) + [bytes(unroll), control_block(tap, "unroll")])
            self.send(self.wallet_sign(ext), "depth/members_%d_depth_%d_external_fee" % (owners + 1, depth_expected))


if __name__ == "__main__":
    T21().main()
