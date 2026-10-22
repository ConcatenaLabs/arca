#!/usr/bin/env python3
"""T22: the operator's equivocation bond (bond.py).

A leaf's owner and the operator co-sign a payment of the leaf to a receiver,
and the operator, breaking its once-per-salt rule, co-signs a second spend of
the same leaf, which confirms. The receiver's message and the one the chain
shows, two digests under one salt, burn the bond: the output at the bond's
index a bare OP_RETURN of its whole amount, the fee from a coin attached.
Refused beside that: one signature twice, two signatures over one digest, two
salts, another key, a burn short, a notice that does not keep the bond whole,
a withdrawal before the notice's delay; then the withdrawal after it."""
from bond import *                         # noqa: F401,F403

BOND = 1_0000_0000
LEAF = 1000_0000
EXT_IN = 50_000
EXT_FEE = 2_000
NOTICE = rel_time(2 * 3600)


class T22(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t22"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X)
        self.clock_start()
        gen = self.genesis_internal()
        ctag = chain_tag(gen)
        s_sec, w_sec, a_sec, t_sec = (generate_privkey() for _ in range(4))
        s_x, w_x, a_x = (compute_xonly_pubkey(k)[0] for k in (s_sec, w_sec, a_sec))
        slash = slash_script(gen, s_x)
        bond, ntap = bond_tap(gen, s_x, w_x, NOTICE), notice_tap(gen, s_x, w_x, NOTICE)
        self.rec_script("slash", slash, bond, "slash")
        self.rec_script("notice", bond.leaves["notice"].script, bond, "notice")
        self.rec_script("withdraw", ntap.leaves["withdraw"].script, ntap, "withdraw")

        # The leaf, the payment its holder and S co-sign, and the second spend
        # S co-signs and the chain carries.
        salt = sha256(b"t22 leaf salt")
        leaf, lv = leaf3_taptree(a_x, s_x, salt, ctag, rel_time(36 * 3600), fold=True)
        lu = self.fund(leaf.scriptPubKey, LEAF, self.X)
        to_recv = [(self.X_ID, LEAF - 1_000, self.p2tr()[0])]
        to_a = [(self.X_ID, LEAF - 1_000, self.wallet_spk())]
        rest_recv, rest_a = rebind_rest(self.X_ID, LEAF, to_recv), rebind_rest(self.X_ID, LEAF, to_a)
        d_recv, d_a = digest(gen, "rebind", salt, rest_recv), digest(gen, "rebind", salt, rest_a)
        assert d_a == rebind_msg3(ctag, salt, self.X_ID, LEAF, to_a, fold=True)
        sig_recv = sign_schnorr(s_sec, d_recv)
        tx = self.mktx([lu], [self.out(v, spk, self.X_OUT) for _, v, spk in to_a] + [self.fee(1_000, self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(s_sec, d_a), sign_schnorr(a_sec, d_a), bytes([1]), lv["collab"],
                            control_block(leaf, "collab")])
        conflict = self.send(tx, "conflicting_spend_of_the_leaf")
        wit = self.node.getrawtransaction(conflict, True)["vin"][0]["txinwitness"]
        sig_chain = bytes.fromhex(wit[0])
        a = ("rebind", rest_recv, sig_recv)
        b = ("rebind", rest_a, sig_chain)

        def slash_tx(coins, items, fee_in=None, burns=None, extra_change=0):
            w = fee_in or self.wallet_utxo(EXT_IN, self.X)
            outs = burns if burns is not None else [self.out(c.amount, BURN, self.X_OUT) for c in coins]
            t = self.mktx(coins + [w], outs + [self.out(EXT_IN - EXT_FEE + extra_change, self.wallet_spk(), self.X_OUT),
                                                self.fee(EXT_FEE, self.X_OUT)])
            for i, c in enumerate(coins):
                tap = ntap if bytes(c.spk) == bytes(ntap.scriptPubKey) else bond
                self.setwit(t, i, items + [slash, control_block(tap, "slash")])
            return self.wallet_sign(t)

        b1 = self.fund(bond.scriptPubKey, BOND, self.X)
        self.reject(slash_tx([b1], slash_items(salt, a, ("rebind", rest_a, sig_recv))), "neg_one_signature_twice",
                    expect="Invalid Schnorr signature")
        self.reject(slash_tx([b1], slash_items(salt, a, ("rebind", rest_recv, sign_schnorr(s_sec, d_recv, aux=b"\x07" * 32)))),
                    "neg_two_signatures_one_digest", expect="Script failed an OP_VERIFY operation")
        other = sha256(b"t22 another salt")
        d_other = digest(gen, "rebind", other, rest_a)
        self.reject(slash_tx([b1], slash_items(salt, a, ("rebind", rest_a, sign_schnorr(s_sec, d_other)))),
                    "neg_two_salts", expect="Invalid Schnorr signature")
        self.reject(slash_tx([b1], slash_items(salt, ("rebind", rest_recv, sign_schnorr(t_sec, d_recv)),
                                               ("rebind", rest_a, sign_schnorr(t_sec, d_a)))),
                    "neg_another_key", expect="Invalid Schnorr signature")
        self.reject(slash_tx([b1], slash_items(salt, a, b), burns=[self.out(BOND - 1, BURN, self.X_OUT)], extra_change=1),
                    "neg_burn_one_atom_short", expect="Script failed an OP_EQUALVERIFY operation")
        self.send(slash_tx([b1], slash_items(salt, a, b)), "slash_two_digests_one_salt")
        b2 = self.fund(bond.scriptPubKey, BOND, self.X)
        f = ("fill", bytes(range(169)), sign_schnorr(s_sec, digest(gen, "fill", salt, bytes(range(169)))))
        self.send(slash_tx([b2], slash_items(salt, a, f)), "slash_a_fill_beside_a_payment")

        # Notice and withdrawal.
        b3 = self.fund(bond.scriptPubKey, BOND, self.X)
        nscript = bond.leaves["notice"].script

        def notice_tx(to_spk, value, sec=w_sec):
            w = self.wallet_utxo(EXT_IN, self.X)
            # What the notice leaves of the bond goes to the change.
            outs = [self.out(value, to_spk, self.X_OUT)]
            t = self.mktx([b3, w], outs + [self.out(EXT_IN - EXT_FEE + BOND - value, self.wallet_spk(), self.X_OUT),
                                          self.fee(EXT_FEE, self.X_OUT)])
            self.setwit(t, 0, [self.sign(sec, t, 0, nscript), nscript, control_block(bond, "notice")])
            return self.wallet_sign(t)

        self.reject(notice_tx(self.wallet_spk(), BOND), "neg_notice_to_another_script",
                    expect="Script failed an OP_EQUALVERIFY operation")
        self.reject(notice_tx(ntap.scriptPubKey, BOND - 1), "neg_notice_one_atom_short",
                    expect="Script failed an OP_EQUALVERIFY operation")
        self.reject(notice_tx(ntap.scriptPubKey, BOND, sec=s_sec), "neg_notice_signed_by_S", expect="Invalid Schnorr signature")
        ntxid = self.send(notice_tx(ntap.scriptPubKey, BOND), "notice")
        nu = self.utxo_of(ntxid, ntap.scriptPubKey)
        wscript = ntap.leaves["withdraw"].script

        def withdraw_tx(seq=NOTICE, sec=w_sec):
            w = self.wallet_utxo(EXT_IN, self.X)
            t = self.mktx([(nu, seq), (w, 0xfffffffe)], [self.out(BOND, self.wallet_spk(), self.X_OUT),
                                                        self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.X_OUT),
                                                        self.fee(EXT_FEE, self.X_OUT)])
            self.setwit(t, 0, [self.sign(sec, t, 0, wscript), wscript, control_block(ntap, "withdraw")])
            return self.wallet_sign(t)

        self.reject(withdraw_tx(), "neg_withdraw_before_the_delay", expect="non-BIP68-final")
        self.wait_csv(ntxid, (NOTICE & 0xffff) * 512)
        self.reject(withdraw_tx(seq=NOTICE - 1), "neg_withdraw_sequence_short", expect="Locktime requirement not satisfied")
        self.reject(withdraw_tx(sec=s_sec), "neg_withdraw_signed_by_S", expect="Invalid Schnorr signature")
        self.send(withdraw_tx(), "withdraw_after_the_notice_and_its_delay")


if __name__ == "__main__":
    T22().main()
