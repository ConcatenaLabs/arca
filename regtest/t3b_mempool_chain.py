#!/usr/bin/env python3
"""T3b: how much of a tree can be unrolled in ONE block? Node transactions are
chained (each spends an output of its parent), so the mempool's ancestor /
descendant limits decide. Radix 2, 32 leaves = 31 node transactions, broadcast
breadth-first with no block in between."""
from arklib import *

LEAF = 1_0000_0000
RESERVE = 400


class T3b(ArkBase, BitcoinTestFramework):
    NAME = "t3b"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        s_x = compute_xonly_pubkey(generate_privkey())[0]
        expiry = node.getblockcount() + 5000
        spks = [self.p2tr()[0] for _ in range(32)]
        root = build_tree(self.X_ID, spks, LEAF, 2, RESERVE, expiry, s_x, "compact")
        u_root = self.utxo_at(self.send(self.round_tx(root["spk"], root["value"], self.X, self.X_OUT), "round_tx"), 0)

        def node_tx(u, n):
            tx = self.mktx([u], [self.out(k["value"], k["spk"], self.X_OUT) for k in n["children"]]
                           + [self.fee(RESERVE, self.X_OUT)])
            self.setwit(tx, 0, [bytes(n["leaves"]["unroll"]), control_block(n["tap"], "unroll")])
            return tx

        queue = [(u_root, root)]
        sent, first_error, blocks_used, per_block = 0, None, 0, []
        in_block = 0
        while queue:
            u, n = queue.pop(0)
            tx = node_tx(u, n)
            try:
                txid = node.sendrawtransaction(tx.serialize().hex())
            except JSONRPCException as e:
                if first_error is None:
                    first_error = {"after_unconfirmed_node_txs": in_block,
                                   "rpc-error": "%s (code %s)" % (e.error["message"], e.error["code"])}
                    self.log.info("mempool refused node tx #%d in the chain: %s", in_block + 1, first_error["rpc-error"])
                self.generate(node, 1)
                blocks_used += 1
                per_block.append(in_block)
                in_block = 0
                txid = node.sendrawtransaction(tx.serialize().hex())
            sent += 1
            in_block += 1
            for i, k in enumerate(n["children"]):
                if k["kind"] == "node":
                    queue.append((Utxo(txid, i, tx.vout[i]), k))
        self.generate(node, 1)
        blocks_used += 1
        per_block.append(in_block)
        assert sent == 31
        self.rec("chain", {"node_txs": sent, "blocks_needed": blocks_used, "node_txs_per_block": per_block,
                           "first_refusal": first_error, "node_tx_vsize": self.measure(tx)["vsize"]})
        self.log.info("31 node txs took %d blocks: %s", blocks_used, per_block)


if __name__ == "__main__":
    T3b().main()
