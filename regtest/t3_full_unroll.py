#!/usr/bin/env python3
"""T3: full unroll + exit with fees. Radix 4, depth 2 (16 leaves), funded in a
NON-policy issued asset X. Each node output = sum(children) + RESERVE (in X).

Case A: X is on the fee whitelist -> every tx pays its fee from the in-tree
        reserve (node txs) or from the leaf's own value (exit claim), in X.
Case B: X is delisted -> reserve-funded tx is refused by policy; the same
        unroll is broadcast with an extra input + fee output in the policy
        asset, the X reserve going to an ordinary change output.
Run for both unroll-leaf encodings (plain / compact)."""
from arklib import *

LEAF_VALUE = 1_0000_0000     # 1.0 X per user
RESERVE = 600                # per-node fee reserve, atoms of X
EXIT_FEE = 300               # exit-claim fee, atoms (of X in case A)
DELAY = 4
RADIX = 4
NLEAVES = 16
EXT_FEE = 1000               # fee paid in the policy asset in case B
EXT_IN = 50_000


class T3(ArkBase, BitcoinTestFramework):
    NAME = "t3"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        for form in ("compact", "plain"):
            self.whitelist(self.X)
            self.case_a(form)
            self.case_b(form)
        self.whitelist(self.X)

    # ------------------------------------------------------------------
    def make_tree(self, form):
        node = self.node
        expiry = node.getblockcount() + 5000
        users = []
        for _ in range(NLEAVES):
            sec = generate_privkey()
            tap, lv = leaf_taptree(compute_xonly_pubkey(sec)[0], self.s_x, DELAY, expiry)
            users.append({"sec": sec, "tap": tap, "lv": lv})
        root = build_tree(self.X_ID, [u["tap"].scriptPubKey for u in users], LEAF_VALUE,
                          RADIX, RESERVE, expiry, self.s_x, form)
        return root, users

    def fund_root(self, root, tag):
        """The round transaction that creates the tree root (explicit, hand-built)."""
        node = self.node
        if tag == "A_compact":
            # evidence for the report: what the node WALLET builds for the same payment
            u = self.fund(self.p2tr()[0], root["value"], self.X)
            d = node.getrawtransaction(u.txid, True)
            self.rec("wallet_made_round_tx_sample", {
                "vsize": d["vsize"], "weight": d["weight"], "size": d["size"],
                "nin": len(d["vin"]), "nout": len(d["vout"]),
                "blinded_outputs": sum(1 for o in d["vout"] if "valuecommitment" in o),
                "explicit_outputs": sum(1 for o in d["vout"] if "value" in o),
                "inputs_all_explicit": all("value" in node.getrawtransaction(i["txid"], True)["vout"][i["vout"]]
                                           for i in d["vin"]),
                "node_args": "-blindedaddresses=0 -con_default_blinded_addresses=0",
                "note": "sendtoaddress(assetlabel=X, fee_asset_label=policy): two change outputs (X, policy) -> the wallet blinds BOTH"})
        tx = self.round_tx(root["spk"], root["value"], self.X, self.X_OUT)
        txid = self.send(tx, tag + "/round_tx", extra={"root_value_atoms": root["value"],
                         "shape": "1 P2WPKH input -> root + P2WPKH change + fee (fee in X)"})
        return self.utxo_at(txid, 0)

    def node_tx(self, u, n, external):
        """Unroll one tree node. external=False: fee = the X reserve.
        external=True: wallet input pays the fee in the policy asset and the X
        reserve goes to a plain change output."""
        kids = [self.out(k["value"], k["spk"], self.X_OUT) for k in n["children"]]
        wit = [bytes(n["leaves"]["unroll"]), control_block(n["tap"], "unroll")]
        if not external:
            tx = self.mktx([u], kids + [self.fee(RESERVE, self.X_OUT)])
            self.setwit(tx, 0, wit)
            return tx
        w = self.wallet_utxo(EXT_IN)
        tx = self.mktx([u, w], kids + [self.out(RESERVE, self.wallet_spk(), self.X_OUT),
                                       self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.POL_OUT),
                                       self.fee(EXT_FEE, self.POL_OUT)])
        self.setwit(tx, 0, wit)
        return self.wallet_sign(tx)

    def exit_tx(self, u, user, external):
        lv, tap = user["lv"], user["tap"]
        dest = self.wallet_spk()
        if not external:
            tx = self.mktx([(u, DELAY)], [self.out(LEAF_VALUE - EXIT_FEE, dest, self.X_OUT),
                                          self.fee(EXIT_FEE, self.X_OUT)])
        else:
            w = self.wallet_utxo(EXT_IN)
            tx = self.mktx([(u, DELAY), w], [self.out(LEAF_VALUE, dest, self.X_OUT),
                                             self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.POL_OUT),
                                             self.fee(EXT_FEE, self.POL_OUT)])
        sig = self.sign(user["sec"], tx, 0, lv["exit"])
        self.setwit(tx, 0, [sig, bytes(lv["exit"]), control_block(tap, "exit")])
        if external:
            tx = self.wallet_sign(tx)
        return tx

    def unroll_everything(self, root, users, uroot, tag, external):
        """Root tx, 4 branch txs, 16 exit claims. Returns per-tx vsizes."""
        node = self.node
        v = {"root": None, "branch": [], "exit": []}
        txid = self.send(self.node_tx(uroot, root, external), tag + "/root_tx")
        v["root"] = self.R[tag + "/root_tx"]["vsize"]
        leaf_utxos = []
        for b, br in enumerate(root["children"]):
            ub = self.utxo_at(txid, b)
            assert ub.spk == br["spk"] and ub.amount == br["value"]
            btxid = self.send(self.node_tx(ub, br, external), "%s/branch%d_tx" % (tag, b))
            v["branch"].append(self.R["%s/branch%d_tx" % (tag, b)]["vsize"])
            for j, lf in enumerate(br["children"]):
                leaf_utxos.append((self.utxo_at(btxid, j), users[lf["idx"]], lf["idx"]))
            if b == 0:
                # leaf 0: the single-user exit path. Too early first.
                ul, usr, _ = leaf_utxos[0]
                self.reject(self.exit_tx(ul, usr, external), tag + "/leaf0_exit_neg_before_delay")
                self.generate(node, DELAY - 1)
                self.send(self.exit_tx(ul, usr, external), tag + "/leaf0_exit_claim")
                v["exit"].append(self.R[tag + "/leaf0_exit_claim"]["vsize"])
        self.generate(node, DELAY)
        for ul, usr, idx in leaf_utxos[1:]:
            self.send(self.exit_tx(ul, usr, external), "%s/leaf%d_exit_claim" % (tag, idx))
            v["exit"].append(self.R["%s/leaf%d_exit_claim" % (tag, idx)]["vsize"])
        one = v["root"] + v["branch"][0] + v["exit"][0]
        allv = v["root"] + sum(v["branch"]) + sum(v["exit"])
        summ = {"root_tx_vsize": v["root"], "branch_tx_vsize": v["branch"],
                "exit_claim_vsize": v["exit"], "one_leaf_exit_total_vsize": one,
                "all16_total_vsize": allv, "tx_count_all16": 1 + len(v["branch"]) + len(v["exit"])}
        self.rec(tag + "/SUMMARY", summ)
        self.log.info("%s: one-leaf exit = %d vB, all-16 unroll+exit = %d vB (%d txs)",
                      tag, one, allv, summ["tx_count_all16"])
        return summ

    # ------------------------------------------------------------------
    def case_a(self, form):
        tag = "A_%s" % form
        self.log.info("=== T3 case A (%s): fees from the in-tree reserve, in X ===", form)
        root, users = self.make_tree(form)
        self.rec_script(tag + "/root_unroll_leaf", root["leaves"]["unroll"], root["tap"], "unroll")
        self.rec(tag + "/values", {"leaf": LEAF_VALUE, "branch": root["children"][0]["value"],
                                   "root": root["value"], "reserve": RESERVE})
        uroot = self.fund_root(root, tag)
        self.unroll_everything(root, users, uroot, tag, external=False)

    def case_b(self, form):
        node = self.node
        tag = "B_%s" % form
        self.log.info("=== T3 case B (%s): X delisted, fee paid in another asset ===", form)
        root, users = self.make_tree(form)
        uroot = self.fund_root(root, tag)
        # a second, tiny tree to show the delisted-fee tx is still CONSENSUS-valid
        root2, _ = self.make_tree(form)
        uroot2 = self.fund(root2["spk"], root2["value"], self.X)

        before = node.getfeeexchangerates()
        node.setfeeexchangerates(self.rates0)          # X removed from the whitelist
        after = node.getfeeexchangerates()
        self.rec(tag + "/whitelist", {"before": before, "after_delist": after})
        assert self.X not in after

        # the reserve-funded tx is now refused by POLICY (not by consensus)
        self.reject(self.node_tx(uroot, root, external=False), tag + "/neg_reserve_fee_in_delisted_X",
                    consensus=False)
        self.mine_raw(self.node_tx(uroot2, root2, external=False), tag + "/reserve_fee_tx_mined_directly")

        # what if the broadcaster leaves the X reserve as a SECOND fee output
        # next to a fee output in the accepted asset?
        w = self.wallet_utxo(EXT_IN)
        kids = [self.out(k["value"], k["spk"], self.X_OUT) for k in root["children"]]
        tx = self.mktx([uroot, w], kids + [self.fee(RESERVE, self.X_OUT),
                                           self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.POL_OUT),
                                           self.fee(EXT_FEE, self.POL_OUT)])
        self.setwit(tx, 0, [bytes(root["leaves"]["unroll"]), control_block(root["tap"], "unroll")])
        self.probe(self.wallet_sign(tx), tag + "/probe_two_fee_outputs_X_and_policy")

        self.unroll_everything(root, users, uroot, tag, external=True)


if __name__ == "__main__":
    T3().main()
