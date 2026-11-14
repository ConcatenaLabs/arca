#!/usr/bin/env python3
"""T29: htlc-2, a hash-lock between two holders.

A payer P locks a coin for a payee Q under a hash h until a timeout T. The
operator S co-signs the lock's two collaborative endings and can take neither
alone:

    claim_c   a 32-byte preimage of h, then Q and S over the outputs
    refund_c  <T> CLTV DROP, then P and S over the outputs
    claim     <Q's delay> CSV DROP, a 32-byte preimage of h, then Q alone
              over the outputs under K || 01
    refund    <T> CLTV DROP <P's delay> CSV DROP, then P alone over the
              outputs under K || 02

The unilateral claim and refund are signed before the leaf exists, as a
watchtower holds them, and spend it at the outpoint it lands at, one of them
with a fee coin added after signing.

Every negative case is refused by the mempool and again when forced into a
block:

- the claim, together or alone, without the preimage, with a wrong one, or
  signed by P or by S in Q's place; alone with Q's signature of the
  collaborative message or of other outputs;
- the refund together before the timeout (a lock time below it, or the
  timeout not reached), or signed by Q in P's place; alone before the timeout
  or before P's delay, or signed by Q or by S, or with P's signature of the
  collaborative message or of the claim's;
- either collaborative path with S's signature twice, or with a pair made
  for another salt.

So nothing spends the lock without the preimage before the timeout, nothing
spends it from the timeout on without the preimage or P, and the operator
alone spends it by no path. A claim pair and a refund pair of one lock are two
different messages under one salt: the bond's evidence, recorded at the end.
"""
from arklib3 import *
import os as _os

V = 1_0000_0000
FEE = 500
H = 3600
Q_S, P_S = 4 * H, 2 * H
Q_DELAY = rel_time(Q_S)            # Q's exit delay: its claim on the chain
P_DELAY = rel_time(P_S)            # P's exit delay: its refund on the chain


class T29(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t29"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.q_sec, self.s_sec, self.p_sec = generate_privkey(), generate_privkey(), generate_privkey()
        self.q_x = compute_xonly_pubkey(self.q_sec)[0]
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.p_x = compute_xonly_pubkey(self.p_sec)[0]
        self.pre = _os.urandom(32)
        self.h = sha256(self.pre)
        self.rec("params", {"q_delay_seconds": Q_S, "q_delay_sequence": Q_DELAY,
                            "p_delay_seconds": P_S, "p_delay_sequence": P_DELAY})
        self.claimed_together()
        self.refunded_together()
        self.claimed_alone()
        self.refunded_alone()
        self.evidence()

    # -- helpers -----------------------------------------------------------
    def lock(self, label, timeout):
        salt = _os.urandom(32)
        tap, lv = htlc2_taptree(self.q_x, self.s_x, self.p_x, salt, self.ctag, self.h, timeout, Q_DELAY, P_DELAY)
        for k in lv:
            self.rec_script("%s/%s" % (label, k), lv[k], tap, k)
        return tap, lv, salt

    def path_tx(self, u, tap, lv, name, below, to_spk, seq, locktime=0, key=None, after=(), value=None):
        """Spends u by `name` into one output of `value` (the whole value less
        FEE by default). With `key`, its signature over the transaction goes
        below `after`."""
        value = u.amount - FEE if value is None else value
        tx = self.mktx([(u, seq)], [self.out(value, to_spk, self.X_OUT), self.fee(u.amount - value, self.X_OUT)], locktime)
        st = list(below)
        if key is not None:
            st.append(self.sign(key, tx, 0, lv[name]))
        st += list(after)
        self.setwit(tx, 0, st + [bytes(lv[name]), control_block(tap, name)])
        return tx

    def leaf_of(self, x):
        tap, _ = leaf3_taptree(x, self.s_x, _os.urandom(32), self.ctag, Q_DELAY, fold=True)
        return tap.scriptPubKey

    def pair(self, u, tap, lv, name, salt, k1, k2, to_spk, seq=0xffffffff, locktime=0, after=(), msg_salt=None):
        """The collaborative path `name` into one leaf `to_spk`, signed by k1
        (in S's place) and k2 (in the holder's) over the message the script
        builds: under `msg_salt` when given, to make a pair for another salt."""
        outs = [(self.X_ID, u.amount - FEE, bytes(to_spk))]
        msg = rebind_msg3(self.ctag, msg_salt or salt, self.X_ID, u.amount, outs, fold=True)
        return self.path_tx(u, tap, lv, name, [sign_schnorr(k1, msg), sign_schnorr(k2, msg), b"\x01"], to_spk, seq,
                            locktime=locktime, after=after), msg

    # -- together, out of the tree -----------------------------------------
    def claimed_together(self):
        """Q and S claim with the preimage, at once, into a leaf of Q's."""
        timeout = self.mtp() + 30 * H
        tap, lv, salt = self.lock("claim_c", timeout)
        u = self.fund(tap.scriptPubKey, V, self.X)
        to = self.leaf_of(self.q_x)
        c = lambda k1, k2, after=(self.pre,), msg_salt=None: self.pair(u, tap, lv, "claim_c", salt, k1, k2, to,
                                                                       after=after, msg_salt=msg_salt)[0]
        self.reject(c(self.s_sec, self.q_sec, after=()), "claim_c/neg without the preimage")
        self.reject(c(self.s_sec, self.q_sec, after=(_os.urandom(32),)), "claim_c/neg with a wrong preimage")
        self.reject(c(self.s_sec, self.q_sec, after=(self.pre[:31],)), "claim_c/neg with a 31-byte preimage")
        self.reject(c(self.s_sec, self.p_sec), "claim_c/neg signed by P in Q's place")
        self.reject(c(self.s_sec, self.s_sec), "claim_c/neg signed by S twice")
        self.reject(c(self.p_sec, self.q_sec), "claim_c/neg signed by P in S's place")
        self.reject(c(self.s_sec, self.q_sec, msg_salt=_os.urandom(32)), "claim_c/neg with a pair made for another salt")
        self.send(c(self.s_sec, self.q_sec), "claim_c/Q and S with the preimage, at once")

    def refunded_together(self):
        """P and S refund from the timeout on, into a leaf of P's; not before,
        and not with Q in P's place."""
        timeout = self.mtp() + 2 * H
        tap, lv, salt = self.lock("refund_c", timeout)
        u = self.fund(tap.scriptPubKey, V, self.X)
        to = self.leaf_of(self.p_x)
        r = lambda k1, k2, lock=timeout: self.pair(u, tap, lv, "refund_c", salt, k1, k2, to, seq=0xfffffffe,
                                                   locktime=lock)[0]
        # A lock time already past and below the timeout: final, so the
        # script's own check refuses it.
        self.reject(r(self.s_sec, self.p_sec, lock=self.mtp() - 1), "refund_c/neg with a lock time below the timeout")
        self.reject(r(self.s_sec, self.p_sec), "refund_c/neg before the timeout")
        self.mtp_past(timeout)
        self.reject(r(self.s_sec, self.q_sec), "refund_c/neg signed by Q in P's place")
        self.reject(r(self.s_sec, self.s_sec), "refund_c/neg signed by S twice")
        self.reject(r(self.q_sec, self.p_sec), "refund_c/neg signed by Q in S's place")
        self.send(r(self.s_sec, self.p_sec), "refund_c/P and S from the timeout")

    # -- alone, on the chain -----------------------------------------------
    def alone_sig(self, key, salt, byte, value, to_spk):
        """The holder's signature of the unilateral ending's message into one
        output `to_spk` of `value` less FEE, made from the amount alone:
        before the leaf exists, so over no outpoint."""
        outs = [(self.X_ID, value - FEE, bytes(to_spk))]
        msg = rebind_msg3(self.ctag, salt, self.X_ID, value, outs, const=htlc2_alone_prefix(self.ctag, salt, byte))
        return sign_schnorr(key, msg), msg

    def fee_coin(self):
        """A coin of X anyone spends (OP_TRUE), to add as a fee input."""
        return self.fund(OP_TRUE_SPK, 20_000, self.X)

    def alone_tx(self, u, tap, lv, name, below, to_spk, seq, locktime=0, fee_coin=None):
        """`name` spends u into its one committed output (u.amount - FEE) and
        the fee; with `fee_coin`, that coin follows as input 1 and its value
        less FEE goes back to OP_TRUE after the committed output."""
        outs = [self.out(u.amount - FEE, to_spk, self.X_OUT)]
        ins = [(u, seq)]
        if fee_coin is not None:
            ins.append((fee_coin, 0xfffffffe))
            outs.append(self.out(fee_coin.amount - FEE, OP_TRUE_SPK, self.X_OUT))
        tx = self.mktx(ins, outs + [self.fee(2 * FEE if fee_coin else FEE, self.X_OUT)], locktime)
        self.setwit(tx, 0, list(below) + [bytes(lv[name]), control_block(tap, name)])
        if fee_coin is not None:
            self.setwit(tx, 1, OP_TRUE_WITNESS)
        return tx

    def claimed_alone(self):
        """Q claims with the preimage after its delay, by a signature made
        before the leaf existed, with a fee coin added after; P and S cannot,
        nor Q's signature of CLAIM-C's message or of other outputs."""
        timeout = self.mtp() + 30 * H
        tap, lv, salt = self.lock("claim", timeout)
        to = taproot_construct(self.q_x).scriptPubKey
        sq, m_alone = self.alone_sig(self.q_sec, salt, HTLC2_ALONE_CLAIM, V, to)
        u = self.fund(tap.scriptPubKey, V, self.X)
        fc = self.fee_coin()
        c = lambda sig, pre=self.pre, seq=Q_DELAY, fee=None: self.alone_tx(u, tap, lv, "claim", [sig, b"\x01", pre], to,
                                                                          seq, fee_coin=fee)
        self.reject(c(sq), "claim/neg before Q's delay")
        self.wait_csv(u.txid, Q_S)
        self.reject(c(sq, seq=Q_DELAY - 1), "claim/neg with a sequence below Q's delay")
        self.reject(c(sq, pre=_os.urandom(32)), "claim/neg with a wrong preimage")
        self.reject(c(self.alone_sig(self.p_sec, salt, HTLC2_ALONE_CLAIM, V, to)[0]), "claim/neg signed by P")
        self.reject(c(self.alone_sig(self.s_sec, salt, HTLC2_ALONE_CLAIM, V, to)[0]), "claim/neg signed by S")
        m_collab = rebind_msg3(self.ctag, salt, self.X_ID, V, [(self.X_ID, V - FEE, bytes(to))], fold=True)
        assert m_collab != m_alone
        self.reject(c(sign_schnorr(self.q_sec, m_collab)), "claim/neg with Q's signature of the collaborative message")
        self.reject(c(self.alone_sig(self.q_sec, salt, HTLC2_ALONE_CLAIM, V, self.leaf_of(self.q_x))[0]),
                    "claim/neg with Q's signature over other outputs")
        self.reject(c(self.alone_sig(self.q_sec, salt, HTLC2_ALONE_REFUND, V, to)[0]),
                    "claim/neg with Q's signature under the refund's prefix")
        self.send(c(sq, fee=fc), "claim/Q alone, signed before the leaf, a fee coin added")

    def refunded_alone(self):
        """P refunds alone from the timeout and after its delay, by a
        signature made before the leaf existed; Q and S cannot, nor P's
        signature of REFUND-C's message or of CLAIM's; the refund in the block
        that creates the output past the timeout is refused: REFUND opens at
        max(timeout, confirmation + P's delay), CLAIM at confirmation + Q's
        delay."""
        timeout = self.mtp() + 6 * H
        tap, lv, salt = self.lock("refund", timeout)
        to = taproot_construct(self.p_x).scriptPubKey
        sp, _ = self.alone_sig(self.p_sec, salt, HTLC2_ALONE_REFUND, V, to)
        u = self.fund(tap.scriptPubKey, V, self.X)
        r = lambda sig=sp, seq=P_DELAY, lock=timeout: self.alone_tx(u, tap, lv, "refund", [sig, b"\x01"], to, seq,
                                                                    locktime=lock)
        self.reject(r(), "refund/neg before P's delay and the timeout")
        self.wait_csv(u.txid, P_S)
        self.reject(r(lock=self.mtp() - 1), "refund/neg with a lock time below the timeout")
        self.reject(r(), "refund/neg after P's delay, before the timeout")
        self.mtp_past(timeout)
        self.reject(r(seq=P_DELAY - 1), "refund/neg with a sequence below P's delay")
        self.reject(r(self.alone_sig(self.q_sec, salt, HTLC2_ALONE_REFUND, V, to)[0]), "refund/neg signed by Q")
        self.reject(r(self.alone_sig(self.s_sec, salt, HTLC2_ALONE_REFUND, V, to)[0]), "refund/neg signed by S")
        m_collab = rebind_msg3(self.ctag, salt, self.X_ID, V, [(self.X_ID, V - FEE, bytes(to))], fold=True)
        self.reject(r(sign_schnorr(self.p_sec, m_collab)), "refund/neg with P's signature of the collaborative message")
        self.reject(r(self.alone_sig(self.p_sec, salt, HTLC2_ALONE_CLAIM, V, to)[0]),
                    "refund/neg with P's signature under the claim's prefix")
        self.send(r(), "refund/P alone from the timeout and after its delay, signed before the leaf")
        # Created past the timeout: refused in the block that creates it.
        tap2, lv2, salt2 = self.lock("refund_late", timeout)
        u2 = self.fund(tap2.scriptPubKey, V, self.X, mine=False)
        sp2, _ = self.alone_sig(self.p_sec, salt2, HTLC2_ALONE_REFUND, V, to)
        late = self.alone_tx(u2, tap2, lv2, "refund", [sp2, b"\x01"], to, P_DELAY, locktime=timeout)
        self.reject_beside(u2.txid, late, "refund/neg in the block that creates the output, past the timeout",
                           "bad-txns-nonfinal")
        self.generate(self.node, 1)

    def reject_beside(self, parent_txid, tx, label, why):
        res = self.accept(tx)
        assert not res["allowed"], "%s unexpectedly ACCEPTED" % label
        h0 = self.node.getblockcount()
        try:
            self.node.generateblock(self.node.getnewaddress(), [parent_txid, tx.serialize().hex()], invalid_call=False)
            raise AssertionError("%s: MINED beside its parent" % label)
        except JSONRPCException as e:
            err = "%s (code %s)" % (e.error["message"], e.error["code"])
        assert self.node.getblockcount() == h0
        assert why in err, "%s: block refused with %r, not for %r" % (label, err, why)
        self.log.info("REJECT %-42s %s | block beside its parent: %s", label, res.get("reject-reason"), err)
        self.rec(label, {"rejected": True, "reject-reason": res.get("reject-reason"), "block-error": err})

    # -- the bond's evidence -----------------------------------------------
    def evidence(self):
        """S co-signs a claim of a lock and a refund of the same lock: two
        messages under one salt, which differ (their outputs do), each
        verifying under S. That is what the bond's SLASH takes, as for any
        coin S signed two ways."""
        tap, lv, salt = self.lock("evidence", self.mtp() + 2 * H)
        u = self.fund(tap.scriptPubKey, V, self.X)
        _, m_claim = self.pair(u, tap, lv, "claim_c", salt, self.s_sec, self.q_sec, self.leaf_of(self.q_x), after=(self.pre,))
        _, m_refund = self.pair(u, tap, lv, "refund_c", salt, self.s_sec, self.p_sec, self.leaf_of(self.p_x))
        assert m_claim != m_refund
        self.rec("evidence", {"salt": salt.hex(), "claim_message": m_claim.hex(), "refund_message": m_refund.hex(),
                              "claim_sig_S": sign_schnorr(self.s_sec, m_claim).hex(),
                              "refund_sig_S": sign_schnorr(self.s_sec, m_refund).hex(), "operator": self.s_x.hex()})
        self.log.info("EVIDENCE two messages under salt %s, both signed by S", salt.hex()[:16])


if __name__ == "__main__":
    T29().main()
