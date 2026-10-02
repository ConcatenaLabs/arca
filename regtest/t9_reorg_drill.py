#!/usr/bin/env python3
"""T9-lite: reorg drill with invalidateblock (NOT an anchor-driven reorg: the
framework has no importable anchoring helper, feature_bitcoin_anchoring.py
builds its two-chain setup inline).

(a) The block holding the round (root-funding) tx and the blocks holding the
    first unroll txs are invalidated -> the tree is "not created" on chain; the
    txs fall back to the mempool and re-mine unchanged.
(b) Stronger: after the invalidation the round tx is REPLACED by a conflicting
    one with a different txid (same root script and amount). Every unroll path
    is rebuilt from scripts alone and still confirms -- nothing in the tree
    commits to a txid, and nothing was pre-signed."""
from arklib import *

LEAF = 1_0000_0000
RESERVE = 600
EXIT_FEE = 300
DELAY = 3


class T9(ArkBase, BitcoinTestFramework):
    NAME = "t9"

    def set_test_params(self):
        self.ark_params()

    def make_tree(self):
        node = self.node
        expiry = node.getblockcount() + 5000
        users = []
        for _ in range(16):
            sec = generate_privkey()
            tap, lv = leaf_taptree(compute_xonly_pubkey(sec)[0], self.s_x, DELAY, expiry)
            users.append({"sec": sec, "tap": tap, "lv": lv})
        root = build_tree(self.X_ID, [u["tap"].scriptPubKey for u in users], LEAF, 4, RESERVE,
                          expiry, self.s_x, "compact")
        return root, users

    def node_tx(self, u, n):
        tx = self.mktx([u], [self.out(k["value"], k["spk"], self.X_OUT) for k in n["children"]]
                       + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(n["leaves"]["unroll"]), control_block(n["tap"], "unroll")])
        return tx

    def exit_tx(self, u, user):
        tx = self.mktx([(u, DELAY)], [self.out(LEAF - EXIT_FEE, self.wallet_spk(), self.X_OUT),
                                      self.fee(EXIT_FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(user["sec"], tx, 0, user["lv"]["exit"]),
                            bytes(user["lv"]["exit"]), control_block(user["tap"], "exit")])
        return tx

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        self.s_x = compute_xonly_pubkey(generate_privkey())[0]

        # ------------------------------------------------------------ (a)
        self.log.info("=== T9 (a): invalidate, tree gone, re-mine unchanged ===")
        root, users = self.make_tree()
        ftx = self.round_tx(root["spk"], root["value"], self.X, self.X_OUT)
        u_root = self.utxo_at(self.send(ftx, "a/round_tx"), 0)          # block B
        blk_b = node.getbestblockhash()
        h_b = node.getblockcount()
        rtx = self.node_tx(u_root, root)
        rtxid = self.send(rtx, "a/root_tx")
        btx = self.node_tx(self.utxo_at(rtxid, 0), root["children"][0])
        btxid = self.send(btx, "a/branch0_tx")
        before = {"height": node.getblockcount(),
                  "root_utxo_spent": node.gettxout(u_root.txid, u_root.vout) is None,
                  "leaf0_utxo_exists": node.gettxout(btxid, 0) is not None}
        node.invalidateblock(blk_b)
        after = {"height": node.getblockcount(),
                 "round_tx_confirmed_utxo": node.gettxout(u_root.txid, u_root.vout, False),
                 "leaf0_confirmed_utxo": node.gettxout(btxid, 0, False),
                 "mempool_has_round_tx": u_root.txid in node.getrawmempool(),
                 "mempool_has_root_tx": rtxid in node.getrawmempool(),
                 "mempool_has_branch_tx": btxid in node.getrawmempool()}
        assert after["height"] == h_b - 1 and after["round_tx_confirmed_utxo"] is None
        assert after["leaf0_confirmed_utxo"] is None
        self.rec("a/invalidate", {"before": before, "after_invalidateblock": after})
        self.log.info("  after invalidateblock: %s", after)
        # re-mine: whatever is still in the mempool confirms again; anything the
        # mempool dropped is simply rebroadcast -- the raw txs are still valid
        for tx_hex, txid in ((ftx.serialize().hex(), u_root.txid), (rtx.serialize().hex(), rtxid), (btx.serialize().hex(), btxid)):
            if txid not in node.getrawmempool():
                node.sendrawtransaction(tx_hex)
        self.generate(node, 1)
        conf = {t: node.getrawtransaction(t, True).get("confirmations", 0) for t in (u_root.txid, rtxid, btxid)}
        assert all(c >= 1 for c in conf.values())
        self.generate(node, DELAY - 1)
        self.send(self.exit_tx(self.utxo_at(btxid, 0), users[0]), "a/leaf0_exit_after_remine")
        self.rec("a/remined", {"confirmations": conf, "note": "same three txids re-confirmed in ONE block after the reorg"})

        # ------------------------------------------------------------ (b)
        self.log.info("=== T9 (b): round tx replaced by a different txid ===")
        root, users = self.make_tree()
        f1 = self.round_tx(root["spk"], root["value"], self.X, self.X_OUT)
        u_root = self.utxo_at(self.send(f1, "b/round_tx_original"), 0)
        blk_b = node.getbestblockhash()
        node.invalidateblock(blk_b)
        assert node.gettxout(u_root.txid, u_root.vout, False) is None
        # conflicting round tx: SAME input, same root output, change to another address
        f2 = self.mktx([f1.prev[0]], [f1.vout[0], self.out(5000, self.wallet_spk(), self.X_OUT), f1.vout[2]])
        f2 = self.wallet_sign(f2)
        f2.rehash()
        assert f2.hash != u_root.txid
        self.rec("b/mempool_view_of_replacement", self.accept(f2))   # conflicts with the resurrected original
        node.generateblock(node.getnewaddress(), [f2.serialize().hex()], invalid_call=False)
        new_root = self.utxo_of(f2.hash, root["spk"])
        old_conf = None
        old_err = None
        try:
            old_conf = node.getrawtransaction(u_root.txid, True).get("confirmations", 0)
        except JSONRPCException as e:
            old_err = e.error["message"]
        self.rec("b/replaced_round_tx", {
            "old_round_txid": u_root.txid, "new_round_txid": f2.hash,
            "old_round_tx_confirmations": old_conf, "old_round_tx_lookup_error": old_err,
            "old_round_tx_in_mempool": u_root.txid in node.getrawmempool(),
            "old_root_utxo": node.gettxout(u_root.txid, u_root.vout),
            "same_root_script": new_root.spk == root["spk"], "same_root_value": new_root.amount == root["value"]})
        assert node.gettxout(u_root.txid, u_root.vout) is None
        assert u_root.txid not in node.getrawmempool() and not old_conf
        assert new_root.amount == root["value"] and new_root.spk == root["spk"]
        # the old root tx (built against the old outpoint) is dead ...
        self.reject(self.node_tx(u_root, root), "b/neg_unroll_against_old_outpoint", consensus=False)
        # ... and the very same scripts unroll the replacement
        rtxid = self.send(self.node_tx(new_root, root), "b/root_tx_on_replacement")
        btxid = self.send(self.node_tx(self.utxo_at(rtxid, 3), root["children"][3]), "b/branch3_tx_on_replacement")
        self.generate(node, DELAY - 1)
        self.send(self.exit_tx(self.utxo_at(btxid, 2), users[14]), "b/leaf14_exit_on_replacement")


if __name__ == "__main__":
    T9().main()
