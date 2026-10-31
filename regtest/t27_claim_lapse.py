#!/usr/bin/env python3
"""T27: claim-1, a distribution's claim leaf, which lapses to its payer.

    collab  the leaf's collaborative path (vtxo-1's, under this leaf's salt)
    exit    <delay> CSV DROP <A'> CHECKSIG               (vtxo-1's exit)
    lapse   <D> CLTV DROP <delay> CSV DROP
            the output at this input's own index pays the return script
            (SHA256(program || version + 2) pinned), explicitly in the leaf's
            asset, holding at least its value less the fee allowance

A' is the claim key. D is the distribution's deadline, a median time. The
lapse needs no signature, so the payer, the operator's watcher or anyone who
brings an unclaimed leaf on the chain after D lapses it back to the payer; it
also waits the exit delay after the leaf confirms, so a leaf that reaches the
chain late still leaves whoever holds a spend of it the exit delay to answer,
as against an exit. Every negative case is refused by the mempool and again
when forced into a block:

- the lapse before D (non-final), with a lock time below D (final, so the
  script's CLTV refuses it), and before its exit delay;
- the lapse to another script, short by one atom past the allowance, in
  another asset, and two lapses of twin leaves sharing one output (each pins
  the output at its own index);
- the collaborative path signed over another salt.

Confirmed: the holder's claim (collab) before D; the holder's exit, started an
exit delay before D, while the lapse is still refused; the lapse after D, its
fee from the allowance; two lapses in one transaction, one to a script that is
no witness program; a lapse whose fee a coin of another asset pays, the whole
value to the return script; a lapse carrying an annex (mined: no signature
covers the witness, so an annex changes nothing the lapse pins). The race: a
leaf that reaches the chain less than an exit delay before D is open to the
holder's exit and to the lapse at the same moment; one that reaches it after
D is answered at once by a holder's pair.
"""
from arklib3 import *
import os as _os
from test_framework.key import compute_xonly_pubkey as _xonly

V = 1_0000_0000
ALLOWANCE = 2_000
FEE = 400
H = 3600
EXIT_S = 4 * H
EXIT = rel_time(EXIT_S)


class T27(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t27"

    def set_test_params(self):
        self.ark_params()

    # -- helpers -----------------------------------------------------------
    def leaf(self, label, deadline, ret=None):
        salt = _os.urandom(32)
        ret = self.ret if ret is None else ret
        tap, lv = claim_taptree(self.a_x, self.s_x, salt, self.ctag, EXIT, deadline, ret, self.X_ID, V, ALLOWANCE)
        for k in lv:
            self.rec_script("%s/%s" % (label, k), lv[k], tap, k)
        return tap, lv, salt

    def lapse_wit(self, tx, k, tap, lv, annex=None):
        st = [bytes(lv["lapse"]), control_block(tap, "lapse")]
        if annex is not None:
            st.append(annex)
        self.setwit(tx, k, st)

    def lapse_tx(self, u, tap, lv, outs, lock, seq=EXIT, ins=(), annex=None):
        tx = self.mktx([(u, seq)] + list(ins), outs, lock)
        self.lapse_wit(tx, 0, tap, lv, annex)
        return tx

    def good(self, value=V - FEE, spk=None):
        return [self.out(value, self.ret if spk is None else spk, self.X_OUT), self.fee(V - value, self.X_OUT)]

    def exit_tx(self, u, tap, lv, seq=EXIT):
        tx = self.mktx([(u, seq)], [self.out(V - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.a_sec, tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
        return tx

    def collab_tx(self, u, tap, lv, salt):
        new_tap, _ = leaf3_taptree(self.a_x, self.s_x, _os.urandom(32), self.ctag, EXIT, fold=True)
        outs3 = [(self.X_ID, V - FEE, bytes(new_tap.scriptPubKey))]
        digest = rebind_msg3(self.ctag, salt, self.X_ID, V, outs3, fold=True)
        tx = self.mktx([u], [self.out(V - FEE, new_tap.scriptPubKey, self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, digest), sign_schnorr(self.a_sec, digest), b"\x01",
                            bytes(lv["collab"]), control_block(tap, "collab")])
        return tx

    # -- the test ----------------------------------------------------------
    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X, self.Y)
        node = self.node
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.a_sec, self.s_sec = generate_privkey(), generate_privkey()
        self.a_x, self.s_x = _xonly(self.a_sec)[0], _xonly(self.s_sec)[0]
        self.ret = self.wallet_spk()                      # the payer's return script, P2WPKH
        assert self.ret[:2] == b"\x00\x14"
        D = self.mtp() + 10 * H
        self.rec("params", {"asset": self.X, "value": V, "allowance": ALLOWANCE, "exit_delay_seconds": EXIT_S,
                            "exit_delay_sequence": EXIT, "deadline": D, "return_script": self.ret.hex(),
                            "return_pin": script_pin(self.ret).hex()})

        # ---- the holder's claim, before D: the collaborative path ------------
        tap, lv, salt = self.leaf("claimed", D)
        u = self.fund(tap.scriptPubKey, V, self.X)
        bad = self.collab_tx(u, tap, lv, _os.urandom(32))
        self.reject(bad, "neg/collab signed over another salt")
        self.send(self.collab_tx(u, tap, lv, salt), "collab before the deadline (the holder takes the claim up)")

        # ---- the holder's exit, started an exit delay before D ---------------
        tap_e, lv_e, _ = self.leaf("exited", D)
        u_e = self.fund(tap_e.scriptPubKey, V, self.X)
        assert self.csv_ready_at(u_e.txid, EXIT_S) < D, "the exit opens before the deadline"

        # ---- the lapse, before D: refused whatever the lock time -------------
        tap_l, lv_l, _ = self.leaf("lapsed", D)
        u_l = self.fund(tap_l.scriptPubKey, V, self.X)
        self.reject(self.lapse_tx(u_l, tap_l, lv_l, self.good(), D), "neg/lapse before the deadline",
                    block="bad-txns-nonfinal")
        self.wait_csv(u_e.txid, EXIT_S)
        self.wait_csv(u_l.txid, EXIT_S)
        assert self.mtp() < D
        self.reject(self.lapse_tx(u_l, tap_l, lv_l, self.good(), self.mtp() - 1),
                    "neg/lapse with a lock time below the deadline")
        self.reject(self.lapse_tx(u_e, tap_e, lv_e, self.good(), D), "neg/lapse of the exiting leaf, before the deadline",
                    block="bad-txns-nonfinal")
        self.send(self.exit_tx(u_e, tap_e, lv_e), "exit by the holder before the deadline")

        # ---- a leaf brought on the chain an exit delay before D at most ------
        tap_r, lv_r, _ = self.leaf("race", D)
        tap_r2, lv_r2, _ = self.leaf("race_exit_first", D)
        late = D - EXIT_S + 2 * H                     # less than an exit delay before D
        self.mtp_past(late)
        u_r = self.fund(tap_r.scriptPubKey, V, self.X)
        u_r2 = self.fund(tap_r2.scriptPubKey, V, self.X)

        # ---- after D ---------------------------------------------------------
        self.mtp_past(D)
        self.reject(self.lapse_tx(u_l, tap_l, lv_l, self.good(), D, seq=EXIT - 1),
                    "neg/lapse with a sequence below the exit delay")
        self.reject(self.lapse_tx(u_l, tap_l, lv_l, self.good(spk=self.wallet_spk()), D), "neg/lapse to another script")
        short = V - ALLOWANCE - 1
        self.reject(self.lapse_tx(u_l, tap_l, lv_l, [self.out(short, self.ret, self.X_OUT),
                                                     self.out(ALLOWANCE + 1 - FEE, self.wallet_spk(), self.X_OUT),
                                                     self.fee(FEE, self.X_OUT)], D),
                    "neg/lapse one atom below value less the allowance")
        y = self.wallet_utxo(V, self.Y)
        self.reject(self.wallet_sign(self.lapse_tx(u_l, tap_l, lv_l, [self.out(V, self.ret, self.Y_OUT),
                                                                      self.out(V - FEE, self.wallet_spk(), self.X_OUT),
                                                                      self.fee(FEE, self.X_OUT)], D, ins=[y])),
                    "neg/lapse in another asset")
        exact = self.lapse_tx(u_l, tap_l, lv_l, [self.out(V - ALLOWANCE, self.ret, self.X_OUT),
                                                 self.out(ALLOWANCE - FEE, self.wallet_spk(), self.X_OUT),
                                                 self.fee(FEE, self.X_OUT)], D)
        self.send(exact, "lapse after the deadline at exactly value less the allowance")

        # Twin leaves of one distribution, same return script and minimum: one
        # output cannot stand for both, as each lapse pins its own index.
        tap_a, lv_a, _ = self.leaf("twin_a", D)
        tap_b, lv_b, _ = self.leaf("twin_b", D)
        u_a = self.fund(tap_a.scriptPubKey, V, self.X)
        u_b = self.fund(tap_b.scriptPubKey, V, self.X)
        self.wait_csv(u_b.txid, EXIT_S)

        def twins(outs):
            tx = self.mktx([(u_a, EXIT), (u_b, EXIT)], outs, D)
            self.lapse_wit(tx, 0, tap_a, lv_a)
            self.lapse_wit(tx, 1, tap_b, lv_b)
            return tx

        self.reject(twins([self.out(V, self.ret, self.X_OUT), self.out(V - FEE, self.wallet_spk(), self.X_OUT),
                           self.fee(FEE, self.X_OUT)]),
                    "neg/two lapses sharing output 0, input 1's value elsewhere")
        self.reject(twins([self.out(V - FEE, self.wallet_spk(), self.X_OUT), self.out(V, self.ret, self.X_OUT),
                           self.fee(FEE, self.X_OUT)]),
                    "neg/lapse at input 0 paying the return script at output 1, not its own index")
        # The second twin's return is a script that is no witness program.
        p2pkh = bytes.fromhex("76a914") + _os.urandom(20) + bytes.fromhex("88ac")
        tap_c, lv_c, _ = self.leaf("twin_p2pkh", D, ret=p2pkh)
        u_c = self.fund(tap_c.scriptPubKey, V, self.X)
        self.wait_csv(u_c.txid, EXIT_S)
        tx = self.mktx([(u_a, EXIT), (u_c, EXIT)], [self.out(V - FEE, self.ret, self.X_OUT), self.out(V - FEE, p2pkh, self.X_OUT),
                                                    self.fee(2 * FEE, self.X_OUT)], D)
        self.lapse_wit(tx, 0, tap_a, lv_a)
        self.lapse_wit(tx, 1, tap_c, lv_c)
        self.send(tx, "two lapses in one transaction, each at its own index, one to a P2PKH return")

        # The fee from a coin of another asset (the leaf's asset delisted):
        # the whole value goes back.
        self.reject(self.wallet_sign(self.lapse_tx(u_b, tap_b, lv_b, [self.out(V, self.wallet_spk(), self.X_OUT),
                                                                      self.out(V - FEE, self.wallet_spk(), self.Y_OUT),
                                                                      self.fee(FEE, self.Y_OUT)], D, ins=[y])),
                    "neg/lapse with a fee coin, the value to another script")
        self.send(self.wallet_sign(self.lapse_tx(u_b, tap_b, lv_b, [self.out(V, self.ret, self.X_OUT),
                                                                    self.out(V - FEE, self.wallet_spk(), self.Y_OUT),
                                                                    self.fee(FEE, self.Y_OUT)], D, ins=[y])),
                  "lapse with the fee from a coin of another asset, the whole value back")

        # An annex: nothing signs the lapse's witness, so whoever relays it may
        # add one; the outputs it pins are the same.
        tap_n, lv_n, _ = self.leaf("annex", D)
        u_n = self.fund(tap_n.scriptPubKey, V, self.X)
        self.wait_csv(u_n.txid, EXIT_S)
        self.mine_raw(self.lapse_tx(u_n, tap_n, lv_n, self.good(), D, annex=b"\x50" + _os.urandom(8)),
                      "lapse carrying an annex (mined; it pins the same outputs)")

        # ---- the race --------------------------------------------------------
        # Brought on the chain less than an exit delay before D: once its exit
        # delay has run, D has passed, and the exit and the lapse are both open.
        self.wait_csv(u_r2.txid, EXIT_S)
        lapse_r = self.lapse_tx(u_r, tap_r, lv_r, self.good(), D)
        exit_r = self.exit_tx(u_r, tap_r, lv_r)
        both = [self.accept(lapse_r)["allowed"], self.accept(exit_r)["allowed"]]
        assert both == [True, True], both
        self.rec("race/both open", {"lapse": both[0], "exit": both[1]})
        self.send(lapse_r, "race: the lapse confirms first")
        self.reject(exit_r, "neg/race: the holder's exit after the lapse", consensus=False)
        self.send(self.exit_tx(u_r2, tap_r2, lv_r2), "race: the holder's exit confirms first")
        self.reject(self.lapse_tx(u_r2, tap_r2, lv_r2, self.good(), D), "neg/race: the lapse after the holder's exit",
                    consensus=False)

        # Brought on the chain after D: the lapse waits the exit delay, and a
        # holder whose coin rests on the leaf answers with its pair at once.
        tap_t, lv_t, salt_t = self.leaf("taken_up_late", D)
        u_t = self.fund(tap_t.scriptPubKey, V, self.X)
        self.reject(self.lapse_tx(u_t, tap_t, lv_t, self.good(), D), "neg/lapse of a leaf confirmed after the deadline, at once",
                    block="bad-txns-nonfinal")
        self.send(self.collab_tx(u_t, tap_t, lv_t, salt_t), "collab of a leaf confirmed after the deadline, at once")


if __name__ == "__main__":
    T27().main()
