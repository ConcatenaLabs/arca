#!/usr/bin/env python3
"""T28: a checkpoint with its owner's exit.

    collab  the coin's collaborative path under the checkpoint's own salt
    sweep   the sweep with notice of the coin's batch, where it has one
    exit    <delay> CSV DROP <A> CHECKSIG, the coin's own exit script

[collab, exit] without a sweep, [collab, [sweep, exit]] with one. A swap is
one reassignment of several owners' checkpoints; when one owner and the
operator spend that owner's checkpoint elsewhere, the reassignment can never
confirm, and without the exit every other owner's coin would stand in a
checkpoint only that owner and the operator together can spend.

Here, for each shape: A's checkpoint and C's, then a second spend of C's
checkpoint by C and the operator (mined), the swap's reassignment refused
(its input spent), and A's exit refused before its delay, signed by the
operator, signed by C and with a sequence one unit short, then mined after
the delay with A's signature alone. A good swap: the reassignment spends A's
checkpoint by its collaborative path, with the pair a checkpoint without the
exit would take (the message names the salt, never the script), and A's exit
after it is refused (its input spent). Every negative case is refused by the
mempool and again when forced into a block.
"""
from arklib3 import *
import os as _os
from test_framework.key import compute_xonly_pubkey as _xonly

V = 1_0000_0000
FEE = 600
H = 3600
EXIT_S = 4 * H
EXIT = rel_time(EXIT_S)
NOTICE_S = 2 * H
GONE = "bad-txns-inputs-missingorspent"     # the block's words for the mempool's missing-inputs


class T28(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t28"

    def set_test_params(self):
        self.ark_params()

    def key(self):
        sec = generate_privkey()
        return sec, _xonly(sec)[0]

    def collab(self, u, tap, lv, salt, value, outs3, owner_sec):
        digest = rebind_msg3(self.ctag, salt, self.X_ID, value, outs3, fold=True)
        tx = self.mktx([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs3]
                       + [self.fee(value - sum(v for (_, v, _) in outs3), self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, digest), sign_schnorr(owner_sec, digest), bytes([len(outs3)]),
                            bytes(lv["collab"]), control_block(tap, "collab")])
        return tx

    def exit_tx(self, u, tap, lv, signer, seq=EXIT):
        tx = self.mktx([(u, seq)], [self.out(V - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(signer, tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
        return tx

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.s_sec, self.s_x = self.key()
        token, r_prog = _os.urandom(32), _os.urandom(32)
        sweep = sweep_token(token, r_prog, self.s_x, rel_time(NOTICE_S))
        for shape, sw in (("no sweep", None), ("with a sweep", sweep)):
            for dead in (True, False):
                self.case("%s/%s" % (shape, "dead swap" if dead else "good swap"), sw, dead)

    def case(self, tag, sweep, dead):
        a_sec, a_x = self.key()
        c_sec, c_x = self.key()
        sa, sc = _os.urandom(32), _os.urandom(32)
        a_tap, a_lv = checkpoint_taptree(a_x, self.s_x, sa, self.ctag, sweep, EXIT)
        c_tap, c_lv = checkpoint_taptree(c_x, self.s_x, sc, self.ctag, sweep, EXIT)
        if sweep is None:
            plain, _ = checkpoint_taptree(a_x, self.s_x, sa, self.ctag, None)
            assert plain.scriptPubKey != a_tap.scriptPubKey
        for k in a_lv:
            self.rec_script("%s/A's checkpoint/%s" % (tag, k), a_lv[k], a_tap, k)
        assert bytes(a_lv["exit"]) == bytes(exit_leaf(a_x, EXIT)), "the exit is the coin's own exit script"
        # The swap's outputs: what each pair commits to.
        recv, _ = leaf3_taptree(c_x, self.s_x, _os.urandom(32), self.ctag, EXIT, fold=True)
        back, _ = leaf3_taptree(a_x, self.s_x, _os.urandom(32), self.ctag, EXIT, fold=True)
        swap_outs = [(self.X_ID, V - FEE, bytes(recv.scriptPubKey)), (self.X_ID, V - FEE, bytes(back.scriptPubKey))]
        u_a = self.fund(a_tap.scriptPubKey, V, self.X)
        u_c = self.fund(c_tap.scriptPubKey, V, self.X)
        if dead:
            thief = [(self.X_ID, V - FEE, self.wallet_spk())]
            self.send(self.collab(u_c, c_tap, c_lv, sc, V, thief, c_sec), tag + "/ATTACK C + operator spend C's checkpoint elsewhere")
        # The swap's reassignment: both checkpoints by their collaborative paths.
        da = rebind_msg3(self.ctag, sa, self.X_ID, V, swap_outs, fold=True)
        dc = rebind_msg3(self.ctag, sc, self.X_ID, V, swap_outs, fold=True)
        swap = self.mktx([u_a, u_c], [self.out(v, spk, self.X_OUT) for (_, v, spk) in swap_outs]
                         + [self.fee(2 * FEE, self.X_OUT)])
        self.setwit(swap, 0, [sign_schnorr(self.s_sec, da), sign_schnorr(a_sec, da), bytes([2]), bytes(a_lv["collab"]),
                              control_block(a_tap, "collab")])
        self.setwit(swap, 1, [sign_schnorr(self.s_sec, dc), sign_schnorr(c_sec, dc), bytes([2]), bytes(c_lv["collab"]),
                              control_block(c_tap, "collab")])
        self.reject(self.exit_tx(u_a, a_tap, a_lv, a_sec), tag + "/neg A's exit before its delay")
        if dead:
            self.reject(swap, tag + "/neg the swap's reassignment", block=GONE)
            self.wait_csv(u_a.txid, EXIT_S)
            self.reject(self.exit_tx(u_a, a_tap, a_lv, self.s_sec), tag + "/neg A's exit signed by the operator")
            self.reject(self.exit_tx(u_a, a_tap, a_lv, c_sec), tag + "/neg A's exit signed by C")
            self.reject(self.exit_tx(u_a, a_tap, a_lv, a_sec, EXIT - 1), tag + "/neg A's exit, sequence one unit short")
            self.send(self.exit_tx(u_a, a_tap, a_lv, a_sec), tag + "/A's own exit after its delay, no operator")
        else:
            self.send(swap, tag + "/the swap's reassignment inside the delay")
            self.wait_csv(u_a.txid, EXIT_S)
            self.reject(self.exit_tx(u_a, a_tap, a_lv, a_sec), tag + "/neg A pulls out of the completed swap", block=GONE)


if __name__ == "__main__":
    T28().main()
