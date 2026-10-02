#!/usr/bin/env python3
"""T11: atomic two-party swap across two rebindable leaves.

Alice holds a leaf of asset X (batch 1), Bob a leaf of asset Y (batch 2). One
transaction spends both collab_rebind paths, both inputs committing (m = 2) to
    output 0 = Bob-receives-X leaf,  output 1 = Alice-receives-Y leaf."""
from arklib import *
import os as _os

LEAF = 1_0000_0000
RESERVE = 600
DELAY = 4
FEE = 600


class T11(ArkBase, BitcoinTestFramework):
    NAME = "t11"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X)                         # Y is NOT a fee asset
        node = self.node
        a_sec, b_sec, s_sec = generate_privkey(), generate_privkey(), generate_privkey()
        a_x, b_x, s_x = (compute_xonly_pubkey(k)[0] for k in (a_sec, b_sec, s_sec))
        expiry = node.getblockcount() + 5000

        def mk(owner_x):
            salt = _os.urandom(32)
            tap, lv = rebind_leaf_taptree(owner_x, s_x, salt, DELAY, expiry)
            return {"salt": salt, "tap": tap, "lv": lv, "spk": bytes(tap.scriptPubKey)}

        # two swaps are prepared: pair 0 is executed properly, pair 1 is used for the
        # "third party funds one side" experiment
        alice = [mk(a_x), mk(a_x)]
        bob = [mk(b_x), mk(b_x)]
        bob_gets_x = [mk(b_x), mk(b_x)]
        alice_gets_y = [mk(a_x), mk(a_x)]
        self.rec_script("alice_leaf_collab_rebind", alice[0]["lv"]["collab"], alice[0]["tap"], "collab")

        VX, VY = LEAF - FEE, LEAF                      # the X side leaves 600 atoms for the fee
        sig = []
        for i in range(2):
            outs = [(self.X_ID, VX, bob_gets_x[i]["spk"]), (self.Y_ID, VY, alice_gets_y[i]["spk"])]
            ma, mb = rebind_msg2(alice[i]["salt"], outs), rebind_msg2(bob[i]["salt"], outs)
            sig.append({"outs": outs,
                        "alice_in": (sign_schnorr(s_sec, ma), sign_schnorr(a_sec, ma)),
                        "bob_in": (sign_schnorr(s_sec, mb), sign_schnorr(b_sec, mb))})
        self.rec("signed_before_any_batch_exists", {"height": node.getblockcount(), "swaps": 2})

        # ---- batch 1 (asset X), unrolled with reserve fees; batch 2 (asset Y), unrolled with an external fee
        s_node = compute_xonly_pubkey(generate_privkey())[0]
        rx = build_tree(self.X_ID, [alice[0]["spk"], alice[1]["spk"], self.p2tr()[0], self.p2tr()[0]],
                        LEAF, 4, RESERVE, expiry, s_node, "compact")
        ry = build_tree(self.Y_ID, [bob[0]["spk"], bob[1]["spk"], self.p2tr()[0], self.p2tr()[0]],
                        LEAF, 4, RESERVE, expiry, s_node, "compact")
        ux = self.fund(rx["spk"], rx["value"], self.X)
        uy = self.fund(ry["spk"], ry["value"], self.Y)
        tx_x = self.send(self.unroll_node_tx(ux, rx, self.X_OUT, RESERVE), "batchX/unroll_reserve_fee")
        tx_y = self.send(self.unroll_node_tx(uy, ry, self.Y_OUT, RESERVE, external=True), "batchY/unroll_external_fee")
        a_utxo = [self.utxo_at(tx_x, 0), self.utxo_at(tx_x, 1)]
        b_utxo = [self.utxo_at(tx_y, 0), self.utxo_at(tx_y, 1)]

        def committed(i):
            return [self.out(VX, bob_gets_x[i]["spk"], self.X_OUT), self.out(VY, alice_gets_y[i]["spk"], self.Y_OUT)]

        def wit(leaf, pair, m=2):
            return [pair[0], pair[1], bytes([m]), bytes(leaf["lv"]["collab"]), control_block(leaf["tap"], "collab")]

        # ---- negatives: one side's signatures without the other side's committed output
        # Alice's input alone; output 1 (her Y) simply absent -> index 1 is the fee output
        tx = self.mktx([a_utxo[0]], [committed(0)[0], self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[0]["alice_in"]))
        self.reject(tx, "neg/alice_input_alone_output1_absent")
        # Alice's input alone; Bob takes the X but output 1 pays Alice nothing she agreed to
        tx = self.mktx([a_utxo[0]], [committed(0)[0], self.out(15, alice_gets_y[0]["spk"], self.X_OUT),
                                     self.fee(FEE - 15, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[0]["alice_in"]))
        self.reject(tx, "neg/alice_input_alone_output1_wrong_asset_and_value")
        # Bob's input alone: Alice gets her Y (output 1) but output 0 is not the X Bob was promised
        w = self.wallet_utxo(50_000)
        tx2 = self.mktx([b_utxo[0], w], [self.out(1000, bob_gets_x[0]["spk"], self.POL_OUT), committed(0)[1],
                                         self.out(48_000, self.wallet_spk(), self.POL_OUT), self.fee(1000, self.POL_OUT)])
        self.setwit(tx2, 0, wit(bob[0], sig[0]["bob_in"]))
        self.reject(self.wallet_sign(tx2), "neg/bob_input_alone_output0_not_the_X_he_was_promised")
        # both inputs, outputs swapped
        tx = self.mktx([a_utxo[0], b_utxo[0]], [committed(0)[1], committed(0)[0], self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[0]["alice_in"]))
        self.setwit(tx, 1, wit(bob[0], sig[0]["bob_in"]))
        self.reject(tx, "neg/both_inputs_outputs_swapped")
        # both inputs, Bob's signatures replaced by Alice's (cross-leaf)
        tx = self.mktx([a_utxo[0], b_utxo[0]], committed(0) + [self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[0]["alice_in"]))
        self.setwit(tx, 1, wit(bob[0], sig[0]["alice_in"]))
        self.reject(tx, "neg/bob_input_with_alice_leaf_signatures")
        # swap 1's signatures on swap 0's leaves
        tx = self.mktx([a_utxo[0], b_utxo[0]], committed(1) + [self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[1]["alice_in"]))
        self.setwit(tx, 1, wit(bob[0], sig[1]["bob_in"]))
        self.reject(tx, "neg/signatures_of_the_other_swap")

        # ---- the swap
        tx = self.mktx([a_utxo[0], b_utxo[0]], committed(0) + [self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[0], sig[0]["alice_in"]))
        self.setwit(tx, 1, wit(bob[0], sig[0]["bob_in"]))
        txid = self.send(tx, "swap/both_leaves_one_tx")
        o0, o1 = node.gettxout(txid, 0), node.gettxout(txid, 1)
        assert o0["asset"] == self.X and o0["scriptPubKey"]["hex"] == bob_gets_x[0]["spk"].hex()
        assert o1["asset"] == self.Y and o1["scriptPubKey"]["hex"] == alice_gets_y[0]["spk"].hex()
        self.rec("swap/result", {"output0": {"asset": "X", "value": str(o0["value"]), "to": "Bob's new leaf"},
                                 "output1": {"asset": "Y", "value": str(o1["value"]), "to": "Alice's new leaf"},
                                 "input1_witness_bytes": wit_bytes(tx.wit.vtxinwit[1].scriptWitness.stack)})

        # ---- one input + a THIRD PARTY's coins of the other asset, both committed outputs present
        third_y = self.wallet_utxo(VY, self.Y)
        tx = self.mktx([a_utxo[1], third_y], committed(1) + [self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(alice[1], sig[1]["alice_in"]))
        tx = self.wallet_sign(tx)
        t3 = self.send(tx, "thirdparty/alice_leaf_plus_third_party_Y")
        bob_leaf_still_unspent = node.gettxout(b_utxo[1].txid, b_utxo[1].vout) is not None
        # Bob's untouched leaf can still run the same swap; someone must now bring the X
        third_x = self.wallet_utxo(VX + FEE, self.X)
        tx = self.mktx([b_utxo[1], third_x], committed(1) + [self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, wit(bob[1], sig[1]["bob_in"]))
        tx = self.wallet_sign(tx)
        t4 = self.send(tx, "thirdparty/bob_leaf_plus_third_party_X")
        self.rec("thirdparty/result", {
            "alice_leaf_spent_without_bob_input": True, "txid": t3,
            "alice_received_Y": str(node.getrawtransaction(t3, True)["vout"][1]["value"]),
            "bob_received_X": str(node.getrawtransaction(t3, True)["vout"][0]["value"]),
            "bob_leaf_still_unspent_afterwards": bob_leaf_still_unspent,
            "bob_leaf_then_spent_with_third_party_X": t4,
            "net": "both committed outputs were created twice; each time the missing side was paid by the third party"})


if __name__ == "__main__":
    T11().main()
