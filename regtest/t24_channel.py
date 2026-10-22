#!/usr/bin/env python3
"""T24: channel-1, a leaf with a balance for each of owner and operator
(channel.py).

A channel is spent on the chain by its latest state: update(n) moves the coin,
with both signatures over SHA256(Q || le8(m) || P), to the output of a newer
state m, at once; settle(n) pays the balances after the exit delay; the
operator's balance lands in a credit output whose claim pays the owner what
the operator's cumulative note credits, capped at what the state owes, and
whose provider path is the operator's after the window. Every negative case
is refused by the mempool and again in a block, for the same reason:

- an update to an equal or older state, over another state's program, with
  the value or the asset changed, with one signature from another key, and
  with 33-byte and 9-byte items in its witness slots;
- an older state's settle on the output of a newer update (its leaf is not
  in the newer output's tree), the newer settle paying the older balances,
  a settle before its delay, short by one atom, to another credit output;
- a credit claim above the signed cumulative amount, one atom over what it
  owes, with the folded note (nothing to pay), with another channel's note,
  with a 33-byte amount, with the rest short or elsewhere, the same note
  twice; the provider path before the window;
- the unroll gate above a channel leaf with a 33-byte member key (the one key
  a channel's way out takes from a witness).

Accepted beside them: the collaborative path on a state output (a forfeit's
pair spends the coin in any state), updates 0 -> 2 -> 3, the settle of the
latest state, the claim of the unfolded credit, the claim of a note above a
stale state's cap taking the operator's whole balance with no rest output,
the provider path after the window, and the gate with a 32-byte key.
"""
from arklib3 import *
from channel import Channel, owner_spk, note_msg, credit_const
import os as _os

V = 100_000_000
CAP = 40_000_000
H = 3600
EXIT_S = 4 * H
EXIT = rel_time(EXIT_S)
WINDOW_S = 6 * H
WINDOW = rel_time(WINDOW_S)
RESERVE = 1_000


class T24(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t24"

    def set_test_params(self):
        self.ark_params()

    # ---- transactions --------------------------------------------------
    def channel(self):
        salt = _os.urandom(32)
        return Channel(self.genesis_internal(), salt, self.a_x, self.s_x, EXIT, V, CAP, WINDOW)

    def chan_out(self, ch, state, value=None, asset_out=None):
        return self.out(V if value is None else value, ch.tap(state)[0].scriptPubKey, asset_out or self.X_OUT)

    def update_tx(self, u, ch, frm, to, m=None, sigs=None, outs=None, items=None):
        """Spend the coin of state `frm` by update into state `to`; `m`,
        `sigs`, `outs` and `items` override what an honest update carries."""
        tap, sc = ch.tap(frm)
        d = ch.state_digest(to)
        sig_s, sig_a = sigs if sigs is not None else (sign_schnorr(self.s_sec, d), sign_schnorr(self.a_sec, d))
        m = to[0] if m is None else m
        tx = self.with_fee_input([(u, 0xffffffff)], outs if outs is not None else [self.chan_out(ch, to)])
        st = items if items is not None else [sig_s, sig_a, le8(m) if isinstance(m, int) else m]
        self.setwit(tx, 0, st + [bytes(sc["update"]), control_block(tap, "update")])
        return self.wallet_sign(tx)

    def settle_outs(self, ch, state):
        n, a, s, f = state
        outs = []
        if a > 0:
            outs.append(self.out(a, owner_spk(self.a_x), self.X_OUT))
        if s > 0:
            outs.append(self.out(s, ch.credit_tap(state)[0].scriptPubKey, self.X_OUT))
        return outs

    def settle_tx(self, u, ch, state, outs=None, seq=EXIT, leaf_of=None):
        """Settle the coin of `state`; `leaf_of` names another state whose
        settle leaf and control block are forced onto the coin."""
        tap, sc = ch.tap(leaf_of or state)
        tx = self.with_fee_input([(u, seq)], outs if outs is not None else self.settle_outs(ch, state))
        self.setwit(tx, 0, [bytes(sc["settle"]), control_block(tap, "settle")])
        return self.wallet_sign(tx)

    def claim_tx(self, cu, ch, state, c, delta, rest, sig=None, c_item=None, rest_spk=None, to_spk=None, extra=()):
        tap, sc = ch.credit_tap(state)
        outs = [self.out(delta, to_spk or owner_spk(self.a_x), self.X_OUT)]
        if rest:
            outs.append(self.out(rest, rest_spk or tap.scriptPubKey, self.X_OUT))
        tx = self.with_fee_input([(cu, 0xffffffff)], outs + [self.out(v, self.wallet_spk(), self.X_OUT) for v in extra])
        sig = sig if sig is not None else sign_schnorr(self.s_sec, ch.note_digest(c))
        self.setwit(tx, 0, [sig, c_item if c_item is not None else le8(c), bytes(sc["claim"]), control_block(tap, "claim")])
        return self.wallet_sign(tx)

    def provider_tx(self, cu, ch, state, seq=WINDOW):
        tap, sc = ch.credit_tap(state)
        tx = self.with_fee_input([(cu, seq)], [self.out(cu.amount, self.wallet_spk(), self.X_OUT)])
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sc["provider"]), bytes(sc["provider"]),
                            control_block(tap, "provider")])
        return self.wallet_sign(tx)

    def collab_tx(self, u, ch, outs3):
        tap, sc = ch.tap(self.collab_state)
        digest = rebind_msg3(ch.ctag, ch.salt, self.X_ID, V, outs3, fold=True)
        outs = [self.out(v, s, b"\x01" + a) for a, v, s in outs3]
        tx = self.mktx([u], outs + [self.fee(V - sum(v for _, v, _ in outs3), self.X_OUT)])
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, digest), sign_schnorr(self.a_sec, digest), bytes([len(outs3)]),
                            bytes(sc["collab"]), control_block(tap, "collab")])
        return tx

    # ---- the test --------------------------------------------------------
    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X, self.Y)
        self.clock_start()
        self.a_sec, self.s_sec = generate_privkey(), generate_privkey()
        self.a_x, self.s_x = compute_xonly_pubkey(self.a_sec)[0], compute_xonly_pubkey(self.s_sec)[0]
        self.rec("params", {"value": V, "capacity": CAP, "exit_delay_seconds": EXIT_S, "exit_delay_sequence": EXIT,
                            "window_seconds": WINDOW_S, "window_sequence": WINDOW})
        self.part_scripts()
        self.part_collab()
        self.part_updates_and_settle()
        self.part_stale_cap()
        self.part_gate()

    def part_scripts(self):
        ch = self.channel()
        s0, s1 = ch.opening(), (1, 50_000_000, 50_000_000, 0)
        for name, st in (("state0", s0), ("state1", s1), ("state3", (3, 65_000_000, 35_000_000, 20_000_000))):
            tap, sc = ch.tap(st)
            for k in sc:
                self.rec_script("scripts/%s/%s" % (name, k), sc[k], tap, k)
            ctap, csc = ch.credit_tap(st)
            for k in csc:
                self.rec_script("scripts/%s/credit_%s" % (name, k), csc[k], ctap, k)
        self.rec_script("scripts/owner_only_settle", ch.tap((4, V, 0, 0))[1]["settle"])
        self.rec_script("scripts/operator_only_settle", ch.tap((5, 0, V, 0))[1]["settle"])

    def part_collab(self):
        """A pair made for the coin (a forfeit's, say) spends it in any state."""
        ch = self.channel()
        s0, s2 = ch.opening(), (2, 45_000_000, 55_000_000, 0)
        u = self.fund(self.chan_out(ch, s0).scriptPubKey, V, self.X)
        txid = self.send(self.update_tx(u, ch, s0, s2), "update 0 -> 2 (owner's latest, fee in the policy asset)")
        u2 = self.utxo_at(txid, 0)
        self.collab_state = s2
        self.send(self.collab_tx(u2, ch, [(self.X_ID, V - 500, bytes(self.wallet_spk()))]),
                  "collab m=1 on the state-2 output (a forfeit's pair)")

    def part_updates_and_settle(self):
        node = self.node
        ch = self.channel()
        s0, s1, s2 = ch.opening(), (1, 50_000_000, 50_000_000, 0), (2, 45_000_000, 55_000_000, 0)
        s3 = (3, 65_000_000, 35_000_000, 20_000_000)        # 20M of credit folded
        u = self.fund(self.chan_out(ch, s0).scriptPubKey, V, self.X)

        # ---- update(0): its negatives ------------------------------------
        self.reject(self.update_tx(u, ch, s0, s0), "neg/update to an equal state (0 on 0)")
        d2 = ch.state_digest(s2)
        self.reject(self.update_tx(u, ch, s0, s2, outs=[self.chan_out(ch, s1)]),
                    "neg/update signed for state 2, output of state 1")
        self.reject(self.update_tx(u, ch, s0, s2, outs=[self.chan_out(ch, s2, value=V - 1),
                                                         self.out(1, self.wallet_spk(), self.X_OUT)]),
                    "neg/update keeping one atom less")
        y = self.wallet_utxo(V, self.Y)
        tx = self.with_fee_input([(u, 0xffffffff), y], [self.chan_out(ch, s2, asset_out=self.Y_OUT),
                                                        self.out(V, self.wallet_spk(), self.X_OUT)])
        tap0, sc0 = ch.tap(s0)
        self.setwit(tx, 0, [sign_schnorr(self.s_sec, d2), sign_schnorr(self.a_sec, d2), le8(2), bytes(sc0["update"]),
                            control_block(tap0, "update")])
        self.reject(self.wallet_sign(tx), "neg/update into another asset of the same value")
        stranger = generate_privkey()
        self.reject(self.update_tx(u, ch, s0, s2, sigs=(sign_schnorr(stranger, d2), sign_schnorr(self.a_sec, d2))),
                    "neg/update with the operator's signature from another key")
        self.reject(self.update_tx(u, ch, s0, s2, sigs=(sign_schnorr(self.s_sec, d2), sign_schnorr(stranger, d2))),
                    "neg/update with the owner's signature from another key")
        k33 = b"\x02" + self.s_x
        self.reject(self.update_tx(u, ch, s0, s2, sigs=(k33, sign_schnorr(self.a_sec, d2))),
                    "neg/update, a 33-byte key in the operator's signature slot")
        self.reject(self.update_tx(u, ch, s0, s2, sigs=(sign_schnorr(self.s_sec, d2), k33)),
                    "neg/update, a 33-byte key in the owner's signature slot")
        self.reject(self.update_tx(u, ch, s0, s2, m=k33), "neg/update, a 33-byte item as the state number")
        self.reject(self.update_tx(u, ch, s0, s2, m=le8(2) + b"\x00"), "neg/update, a 9-byte state number")
        self.reject(self.settle_tx(u, ch, s0), "neg/settle(0) before its delay", block="bad-txns-nonfinal")

        # ---- the owner publishes state 2; the operator answers with 3 -----
        txid = self.send(self.update_tx(u, ch, s0, s2), "update 0 -> 2")
        u2 = self.utxo_at(txid, 0)
        self.reject(self.update_tx(u2, ch, s2, s1), "neg/update to an older state (1 on 2)")
        self.reject(self.update_tx(u2, ch, s2, s2), "neg/update to the same state (2 on 2)")
        txid = self.send(self.update_tx(u2, ch, s2, s3), "update 2 -> 3 (the latest, at once)")
        u3 = self.utxo_at(txid, 0)

        # ---- an older state's settle after the newer update ---------------
        self.wait_csv(txid, EXIT_S)
        self.reject(self.settle_tx(u3, ch, s2, leaf_of=s2), "neg/settle(2) on the state-3 output (its leaf is not there)")
        self.reject(self.settle_tx(u3, ch, s3, outs=self.settle_outs(ch, s2), leaf_of=s3),
                    "neg/settle(3) paying state 2's balances")
        self.reject(self.update_tx(u3, ch, s3, s2), "neg/update to state 2 on the state-3 output, after the delay")
        self.reject(self.settle_tx(u3, ch, s3, seq=rel_time(EXIT_S - 512)), "neg/settle(3) one unit short of its delay",
                    block="Locktime requirement not satisfied")
        outs = self.settle_outs(ch, s3)
        short = [self.out(s3[1] - 1, owner_spk(self.a_x), self.X_OUT), outs[1],
                 self.out(1, self.wallet_spk(), self.X_OUT)]
        self.reject(self.settle_tx(u3, ch, s3, outs=short), "neg/settle(3) one atom short to the owner")
        other = self.channel()
        self.reject(self.settle_tx(u3, ch, s3, outs=[outs[0], self.out(s3[2], other.credit_tap(s3)[0].scriptPubKey,
                                                                          self.X_OUT)]),
                    "neg/settle(3) to another channel's credit output")
        self.reject(self.settle_tx(u3, ch, s3, outs=[outs[1], outs[0]]), "neg/settle(3) with its outputs swapped")
        txid = self.send(self.settle_tx(u3, ch, s3), "settle(3) after its delay")
        assert bytes(self.utxo_at(txid, 0).spk) == owner_spk(self.a_x)
        cu = self.utxo_at(txid, 1)
        self.rec("settle(3)/paid", {"owner": s3[1], "operator_credit_output": s3[2]})

        # ---- the credit output of state 3: B = 35M + 20M, paid 20M ---------
        c = 30_000_000                                   # 10M not yet folded
        b = s3[2] + s3[3]
        sig30 = sign_schnorr(self.s_sec, ch.note_digest(c))
        self.reject(self.provider_tx(cu, ch, s3), "neg/provider before the window", block="bad-txns-nonfinal")
        self.reject(self.claim_tx(cu, ch, s3, c, 20_000_000, b - 40_000_000, sig=sig30, c_item=le8(40_000_000)),
                    "neg/claim of 40M with the operator's note for 30M (above the signed cumulative)")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_001, b - c - 1), "neg/claim one atom over the note")
        self.reject(self.claim_tx(cu, ch, s3, 20_000_000, 1, cu.amount - 1),
                    "neg/claim with the folded note (nothing to pay), paying one atom")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c,
                                  sig=sign_schnorr(self.s_sec, note_msg(credit_const(self.genesis_internal(),
                                                                                     _os.urandom(32)), c))),
                    "neg/claim with another channel's note")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c, c_item=b"\x02" + self.s_x),
                    "neg/claim, a 33-byte item as the amount")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c, sig=b"\x02" + self.s_x),
                    "neg/claim, a 33-byte key in the signature slot")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c - 1, extra=[1]),
                    "neg/claim with the rest one atom short, that atom elsewhere")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c, rest_spk=self.wallet_spk()),
                    "neg/claim with the rest paid elsewhere")
        self.reject(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c, to_spk=self.wallet_spk()),
                    "neg/claim paying the credit elsewhere")
        txid = self.send(self.claim_tx(cu, ch, s3, c, 10_000_000, b - c), "claim of the unfolded 10M (note 30M)")
        assert bytes(self.utxo_at(txid, 0).spk) == owner_spk(self.a_x)
        rest = self.utxo_at(txid, 1)
        self.reject(self.claim_tx(rest, ch, s3, c, 1, rest.amount - 1), "neg/the same note again (nothing to pay), paying one atom")
        self.wait_csv(txid, WINDOW_S)
        self.send(self.provider_tx(rest, ch, s3), "provider takes the rest after the window")

    def part_stale_cap(self):
        """The operator publishes a stale state: the owner's latest note,
        above that state's cap, takes the operator's whole balance."""
        ch = self.channel()
        s0, s1 = ch.opening(), (1, 30_000_000, 70_000_000, 0)
        c = 50_000_000                                   # signed against state 1: c <= B_1 = 70M
        u = self.fund(self.chan_out(ch, s0).scriptPubKey, V, self.X)
        self.mtp_past(self.csv_ready_at(u.txid, EXIT_S))
        txid = self.send(self.settle_tx(u, ch, s0), "settle(0), stale: the owner had paid 30M since")
        cu = self.utxo_at(txid, 1)
        self.reject(self.claim_tx(cu, ch, s0, c, CAP - 1, 1), "neg/stale claim leaving one atom behind")
        self.send(self.claim_tx(cu, ch, s0, c, CAP, 0),
                  "claim capped at B_0: the operator's whole 40M, no rest output (owner takes all of V)")

        ch2 = self.channel()
        u = self.fund(self.chan_out(ch2, s0).scriptPubKey, V, self.X)
        self.mtp_past(self.csv_ready_at(u.txid, EXIT_S))
        txid = self.send(self.settle_tx(u, ch2, s0), "settle(0) of a channel with no credit")
        cu = self.utxo_at(txid, 1)
        self.wait_csv(txid, WINDOW_S)
        self.send(self.provider_tx(cu, ch2, s0), "provider takes the whole credit output after the window")

        ch3 = self.channel()
        s_owner_only = (1, V, 0, 0)
        u = self.fund(self.chan_out(ch3, s0).scriptPubKey, V, self.X)
        txid = self.send(self.update_tx(u, ch3, s0, s_owner_only), "update 0 -> 1 (all to the owner)")
        self.wait_csv(txid, EXIT_S)
        self.send(self.settle_tx(self.utxo_at(txid, 0), ch3, s_owner_only), "settle of a state with no operator balance")
        ch4 = self.channel()
        s_operator_only = (1, 0, V, 0)
        u = self.fund(self.chan_out(ch4, s0).scriptPubKey, V, self.X)
        txid = self.send(self.update_tx(u, ch4, s0, s_operator_only), "update 0 -> 1 (all to the operator)")
        self.wait_csv(txid, EXIT_S)
        self.send(self.settle_tx(self.utxo_at(txid, 0), ch4, s_operator_only),
                  "settle of a state with no owner balance (the credit output at 0)")

    def part_gate(self):
        """The unroll gate above a channel leaf takes its member key from the
        witness: a 33-byte key is refused, a 32-byte one unrolls."""
        ch = self.channel()
        s0 = ch.opening()
        kids = [(self.X_ID, V, bytes(ch.tap(s0)[0].scriptPubKey)[2:])]
        bad33 = b"\x02" + self.a_x
        members = [self.s_x, self.a_x, bad33]
        levels, _ = hmerkle(members, self.s_x)
        unroll = hgate_unroll(levels[-1][0], len(levels) - 1, kids, timed=True)
        tap = taproot_construct(NUMS, [("unroll", unroll), ("sweep", CScript([self.s_x, OP_CHECKSIG]))])
        u = self.fund(tap.scriptPubKey, V + RESERVE, self.X)
        t = self.mtp() - 1
        auth = sign_schnorr(self.a_sec, unroll_auth3(kids, t))

        def gtx(sig, idx, key):
            tx = self.mktx([(u, 0xfffffffe)], [self.chan_out(ch, s0), self.fee(RESERVE, self.X_OUT)], t)
            self.setwit(tx, 0, hgate_witness(sig, mpath(levels, idx), key, t) + [bytes(unroll), control_block(tap, "unroll")])
            return tx
        self.reject(gtx(b"\x01", 2, bad33), "neg/unroll gate above a channel, a 33-byte key, one-byte signature")
        self.reject(gtx(auth, 2, bad33), "neg/unroll gate above a channel, a 33-byte key, the owner's signature")
        self.send(gtx(auth, 1, self.a_x), "unroll gate above a channel, the owner's 32-byte key")


if __name__ == "__main__":
    T24().main()
