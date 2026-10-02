#!/usr/bin/env python3
"""T5: hash-locked leaf + forfeit (hArk style).

HL output (in the NEW tree):  unlock: OP_SIZE 32 EQUALVERIFY SHA256 <h> EQUALVERIFY + covenant
                                      "output 0 = (X, value, user's T2 leaf script)"
                              sweep : <expiry> CLTV DROP <S> CHECKSIG
FORFEIT tx: spends the OLD leaf through its collaborative path (A+S) to
FORFEIT output:               claim : OP_SIZE 32 EQUALVERIFY SHA256 <h> EQUALVERIFY <S> CHECKSIG
                              refund: <delay> CSV DROP <A> CHECKSIG
Atomicity: the operator can only take the old coin by publishing the preimage
that lets the user (anyone, in fact) move the HL output into the user's new leaf."""
from arklib import *
import os as _os

VALUE = 1_0000_0000
RESERVE = 400            # fee reserve carried by the HL output (pays the unlock tx)
FEE = 400
DELAY = 5


def hl_taptree(h, asset_id, value, leaf_prog, expiry, s_x):
    unlock = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY]
                     + unroll_body([(asset_id, value, leaf_prog)]))
    sweep = sweep_leaf(expiry, s_x)
    tap = taproot_construct(NUMS, [("unlock", unlock), ("sweep", sweep)])
    return tap, {"unlock": unlock, "sweep": sweep}


def forfeit_taptree(h, a_x, s_x, delay):
    claim = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY, s_x, OP_CHECKSIG])
    refund = CScript([delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, a_x, OP_CHECKSIG])
    tap = taproot_construct(NUMS, [("claim", claim), ("refund", refund)])
    return tap, {"claim": claim, "refund": refund}


class T5(ArkBase, BitcoinTestFramework):
    NAME = "t5"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        self.a_sec, self.s_sec = generate_privkey(), generate_privkey()
        self.a_x = compute_xonly_pubkey(self.a_sec)[0]
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.swap_happy()
        self.swap_abort()

    def setup_swap(self, tag):
        node = self.node
        expiry_old = node.getblockcount() + 300
        expiry_new = node.getblockcount() + 30
        pre = _os.urandom(32)                       # chosen by the OPERATOR
        h = sha256(pre)
        old_tap, old_lv = leaf_taptree(self.a_x, self.s_x, DELAY, expiry_old)
        new_tap, new_lv = leaf_taptree(self.a_x, self.s_x, DELAY, expiry_new + 500)
        hl_tap, hl_lv = hl_taptree(h, self.X_ID, VALUE, bytes(new_tap.scriptPubKey)[2:], expiry_new, self.s_x)
        ff_tap, ff_lv = forfeit_taptree(h, self.a_x, self.s_x, DELAY)
        if tag == "happy":
            self.rec_script("script/hl_unlock_leaf", hl_lv["unlock"], hl_tap, "unlock")
            self.rec_script("script/hl_sweep_leaf", hl_lv["sweep"], hl_tap, "sweep")
            self.rec_script("script/forfeit_claim_leaf", ff_lv["claim"], ff_tap, "claim")
            self.rec_script("script/forfeit_refund_leaf", ff_lv["refund"], ff_tap, "refund")
            self.rec_script("script/old_leaf_collab", old_lv["collab"], old_tap, "collab")
        u_old = self.fund(old_tap.scriptPubKey, VALUE, self.X)
        u_hl = self.fund(hl_tap.scriptPubKey, VALUE + RESERVE, self.X)
        return dict(pre=pre, h=h, old_tap=old_tap, old_lv=old_lv, new_tap=new_tap, new_lv=new_lv,
                    hl_tap=hl_tap, hl_lv=hl_lv, ff_tap=ff_tap, ff_lv=ff_lv, u_old=u_old, u_hl=u_hl,
                    expiry_new=expiry_new)

    # ---- transactions --------------------------------------------------
    def forfeit_tx(self, c, sign_a=True, sign_s=True):
        tx = self.mktx([c["u_old"]], [self.out(VALUE - FEE, c["ff_tap"].scriptPubKey, self.X_OUT),
                                      self.fee(FEE, self.X_OUT)])
        leaf = c["old_lv"]["collab"]
        sa = self.sign(self.a_sec, tx, 0, leaf) if sign_a else b""
        ss = self.sign(self.s_sec, tx, 0, leaf) if sign_s else b""
        self.setwit(tx, 0, [ss, sa, bytes(leaf), control_block(c["old_tap"], "collab")])
        return tx

    def claim_tx(self, c, u_ff, preimage, sec):
        tx = self.mktx([u_ff], [self.out(VALUE - 2 * FEE, self.wallet_spk(), self.X_OUT),
                                self.fee(FEE, self.X_OUT)])
        leaf = c["ff_lv"]["claim"]
        sig = self.sign(sec, tx, 0, leaf) if sec else b""
        self.setwit(tx, 0, [sig, preimage, bytes(leaf), control_block(c["ff_tap"], "claim")])
        return tx

    def refund_tx(self, c, u_ff, seq=DELAY):
        tx = self.mktx([(u_ff, seq)], [self.out(VALUE - 2 * FEE, self.wallet_spk(), self.X_OUT),
                                       self.fee(FEE, self.X_OUT)])
        leaf = c["ff_lv"]["refund"]
        sig = self.sign(self.a_sec, tx, 0, leaf)
        self.setwit(tx, 0, [sig, bytes(leaf), control_block(c["ff_tap"], "refund")])
        return tx

    def unlock_tx(self, c, preimage, dest_spk=None, value=VALUE):
        tx = self.mktx([c["u_hl"]], [self.out(value, dest_spk or bytes(c["new_tap"].scriptPubKey), self.X_OUT),
                                     self.fee(VALUE + RESERVE - value, self.X_OUT)])
        leaf = c["hl_lv"]["unlock"]
        self.setwit(tx, 0, [preimage, bytes(leaf), control_block(c["hl_tap"], "unlock")])
        return tx

    def hl_sweep_tx(self, c, locktime):
        tx = self.mktx([(c["u_hl"], 0xfffffffe)], [self.out(VALUE + RESERVE - FEE, self.wallet_spk(), self.X_OUT),
                                                   self.fee(FEE, self.X_OUT)], locktime)
        leaf = c["hl_lv"]["sweep"]
        sig = self.sign(self.s_sec, tx, 0, leaf)
        self.setwit(tx, 0, [sig, bytes(leaf), control_block(c["hl_tap"], "sweep")])
        return tx

    # ---- scenario 1: the swap completes --------------------------------
    def swap_happy(self):
        node = self.node
        self.log.info("=== T5 scenario 1: operator reveals, user gets the new leaf ===")
        c = self.setup_swap("happy")

        # the user cannot reach the new leaf without the operator's secret
        self.reject(self.unlock_tx(c, _os.urandom(32)), "hl/neg_unlock_wrong_preimage")
        self.reject(self.unlock_tx(c, c["pre"][:31]), "hl/neg_unlock_31_byte_preimage")
        self.reject(self.unlock_tx(c, c["pre"] + b"\x00"), "hl/neg_unlock_33_byte_preimage")

        # forfeit needs BOTH A and S (collaborative path of the old leaf)
        self.reject(self.forfeit_tx(c, sign_a=False), "forfeit/neg_without_A_sig")
        ftxid = self.send(self.forfeit_tx(c), "forfeit/tx_old_leaf_to_forfeit_output")
        u_ff = self.utxo_at(ftxid, 0)

        # operator cannot take the forfeit without the right preimage, nor can
        # a stranger who somehow knows the preimage take it without S
        self.reject(self.claim_tx(c, u_ff, _os.urandom(32), self.s_sec), "forfeit/neg_claim_wrong_preimage")
        self.reject(self.claim_tx(c, u_ff, c["pre"], generate_privkey()), "forfeit/neg_claim_preimage_but_not_S")
        self.reject(self.claim_tx(c, u_ff, c["pre"], None), "forfeit/neg_claim_preimage_no_sig")
        # A cannot pull it back before the delay
        self.reject(self.refund_tx(c, u_ff), "forfeit/neg_refund_before_delay")

        ctxid = self.send(self.claim_tx(c, u_ff, c["pre"], self.s_sec), "forfeit/claim_by_S_with_preimage")

        # the USER now learns the preimage from the chain, nowhere else
        wit = node.getrawtransaction(ctxid, True)["vin"][0]["txinwitness"]
        learned = bytes.fromhex(wit[1])
        assert sha256(learned) == c["h"] and learned == c["pre"]
        self.rec("forfeit/preimage_learned_from_chain", {
            "claim_txid": ctxid, "witness_item_index": 1, "preimage": learned.hex(),
            "sha256": c["h"].hex()})

        # ... and it opens the hash-locked output, but ONLY into the user's leaf
        self.reject(self.unlock_tx(c, learned, dest_spk=self.p2tr()[0]), "hl/neg_unlock_to_other_script")
        self.reject(self.unlock_tx(c, learned, value=VALUE - 1), "hl/neg_unlock_short_value")
        utxid = self.send(self.unlock_tx(c, learned), "hl/leaf_tx_unlock_into_user_leaf")
        o = node.gettxout(utxid, 0)
        assert o["scriptPubKey"]["hex"] == bytes(c["new_tap"].scriptPubKey).hex()
        assert o["asset"] == self.X

        # the user really owns it: unilateral exit from the new leaf
        u_new = self.utxo_at(utxid, 0)
        self.generate(node, DELAY - 1)
        tx = self.mktx([(u_new, DELAY)], [self.out(VALUE - FEE, self.wallet_spk(), self.X_OUT),
                                          self.fee(FEE, self.X_OUT)])
        leaf = c["new_lv"]["exit"]
        self.setwit(tx, 0, [self.sign(self.a_sec, tx, 0, leaf), bytes(leaf), control_block(c["new_tap"], "exit")])
        self.send(tx, "hl/user_exit_from_new_leaf")

    # ---- scenario 2: the operator never reveals ------------------------
    def swap_abort(self):
        node = self.node
        self.log.info("=== T5 scenario 2: operator never reveals; both sides revert ===")
        c = self.setup_swap("abort")
        ftxid = self.send(self.forfeit_tx(c), "abort/forfeit_tx")
        u_ff = self.utxo_at(ftxid, 0)
        self.reject(self.refund_tx(c, u_ff), "abort/neg_refund_before_delay")
        self.generate(node, DELAY - 1)
        self.send(self.refund_tx(c, u_ff), "abort/user_refund_after_delay")
        # the operator takes back the hash-locked output after expiry
        self.reject(self.hl_sweep_tx(c, c["expiry_new"]), "abort/neg_hl_sweep_before_expiry")
        self.mine_to(c["expiry_new"])
        self.send(self.hl_sweep_tx(c, c["expiry_new"]), "abort/hl_sweep_after_expiry")


if __name__ == "__main__":
    T5().main()
