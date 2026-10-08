#!/usr/bin/env python3
"""T15: htlc-1, the hash-locked leaf of the Lightning legs.

    collab  the leaf's collaborative path (vtxo-1's, under this leaf's salt)
    claim   <delay> CSV DROP, a 32-byte preimage of h, the claimer's signature
    refund  <timeout> CLTV DROP <delay> CSV DROP, the refunder's signature

Out of the tree (a payment the owner makes over Lightning) the operator claims
with the preimage after its own delay and the owner refunds after the timeout
and its exit delay. Into the tree (a payment the owner receives) the owner
claims after its exit delay and the operator refunds after the timeout and its
own delay. The operator's delay is the shorter. Every negative case is refused
by the mempool and again when forced into a block:

- the refund in the block that creates the output, past the timeout: the
  other side always gets the time between the two delays to answer;
- each path before its delay or its timeout, with a wrong preimage, or signed
  by the other side's key;
- the collaborative path with one signature, or with a pair made for another
  salt. It needs no wait, which is what returns a failed payment at once.
"""
from arklib3 import *
import os as _os

V = 1_0000_0000
FEE = 500
H = 3600
EXIT_S, OPD_S = 4 * H, 1 * H
EXIT = rel_time(EXIT_S)            # the owner's delay
OPD = rel_time(OPD_S)              # the operator's delay


class T15(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t15"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.a_sec, self.s_sec = generate_privkey(), generate_privkey()
        self.a_x = compute_xonly_pubkey(self.a_sec)[0]
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.pre = _os.urandom(32)
        self.h = sha256(self.pre)
        self.rec("params", {"exit_delay_seconds": EXIT_S, "exit_delay_sequence": EXIT,
                            "operator_delay_seconds": OPD_S, "operator_delay_sequence": OPD})
        self.send_claimed()
        self.send_refunded()
        self.send_returned_together()
        self.receive_claimed()
        self.receive_refunded()

    # -- helpers -----------------------------------------------------------
    def htlc(self, label, timeout, receive=False):
        salt = _os.urandom(32)
        tap, lv = htlc_taptree(self.a_x, self.s_x, salt, self.ctag, self.h, timeout, EXIT, OPD, receive=receive)
        for k in lv:
            self.rec_script("%s/%s" % (label, k), lv[k], tap, k)
        return tap, lv, salt

    def path_tx(self, u, tap, lv, name, below, to_spk, seq, locktime=0, key=None, after=()):
        """Spends u by `name` into one output of the whole value less FEE. With
        `key`, its signature over the transaction goes below `after`."""
        tx = self.mktx([(u, seq)], [self.out(u.amount - FEE, to_spk, self.X_OUT), self.fee(FEE, self.X_OUT)], locktime)
        st = list(below)
        if key is not None:
            st.append(self.sign(key, tx, 0, lv[name]))
        st += list(after)
        self.setwit(tx, 0, st + [bytes(lv[name]), control_block(tap, name)])
        return tx

    def reject_beside(self, parent_txid, tx, label, why):
        """A spend of an output in the same block as the transaction that
        creates it: refused by the mempool, and refused in a block that holds
        both, for `why`."""
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

    def owner_spk(self):
        return taproot_construct(self.a_x).scriptPubKey

    def operator_spk(self):
        return taproot_construct(self.s_x).scriptPubKey

    # -- out of the tree ---------------------------------------------------
    def send_claimed(self):
        """The payment went through: the operator holds the preimage. Past the
        timeout the owner puts the output on-chain and refunds it in the same
        block: refused. The operator claims after its delay."""
        timeout = self.mtp() + 2 * H
        tap, lv, _ = self.htlc("send", timeout)
        self.mtp_past(timeout)
        u = self.fund(tap.scriptPubKey, V, self.X, mine=False)
        refund = self.path_tx(u, tap, lv, "refund", [], self.owner_spk(), EXIT, locktime=timeout, key=self.a_sec)
        self.reject_beside(u.txid, refund, "send/neg refund in the block that creates the output, past the timeout",
                           "bad-txns-nonfinal")
        self.generate(self.node, 1)
        self.reject(refund, "send/neg refund past the timeout, before the exit delay")
        claim = lambda pre, key, seq=OPD: self.path_tx(u, tap, lv, "claim", [], self.operator_spk(), seq, key=key,
                                                       after=[pre])
        self.reject(claim(self.pre, self.s_sec), "send/neg claim before the operator's delay")
        self.wait_csv(u.txid, OPD_S)
        self.reject(claim(self.pre, self.s_sec, seq=OPD - 1), "send/neg claim with a sequence below the operator's delay")
        self.reject(claim(_os.urandom(32), self.s_sec), "send/neg claim with a wrong preimage")
        self.reject(claim(self.pre[:31], self.s_sec), "send/neg claim with a 31-byte preimage")
        self.reject(claim(self.pre, self.a_sec), "send/neg claim signed by the owner")
        self.send(claim(self.pre, self.s_sec), "send/claim by the operator with the preimage")

    def send_refunded(self):
        """The payment failed: the owner takes the output back alone, after the
        timeout and its exit delay, and not before either."""
        timeout = self.mtp() + 6 * H
        tap, lv, _ = self.htlc("send_refund", timeout)
        u = self.fund(tap.scriptPubKey, V, self.X)
        refund = lambda lock, key=None, seq=EXIT: self.path_tx(u, tap, lv, "refund", [], self.owner_spk(), seq,
                                                               locktime=lock, key=key or self.a_sec)
        self.reject(refund(timeout), "send/neg refund before the exit delay and the timeout")
        self.wait_csv(u.txid, EXIT_S)
        # A lock time already past, and below the timeout: final, so the
        # script's own check refuses it.
        self.reject(refund(self.mtp() - 1), "send/neg refund with a lock time below the timeout")
        self.reject(refund(timeout), "send/neg refund after the exit delay, before the timeout")
        self.mtp_past(timeout)
        self.reject(refund(timeout, seq=EXIT - 1), "send/neg refund with a sequence below the exit delay")
        self.reject(refund(timeout, key=self.s_sec), "send/neg refund signed by the operator")
        self.send(refund(timeout), "send/refund by the owner after the timeout and the exit delay")

    def send_returned_together(self):
        """The payment failed and the operator agrees: both sign the output back
        into a leaf of the owner's, at once, long before the timeout."""
        timeout = self.mtp() + 30 * H
        tap, lv, salt = self.htlc("send_back", timeout)
        u = self.fund(tap.scriptPubKey, V, self.X)
        back_tap, _ = leaf3_taptree(self.a_x, self.s_x, _os.urandom(32), self.ctag, EXIT, fold=True)
        outs = [(self.X_ID, V - FEE, bytes(back_tap.scriptPubKey))]
        msg = rebind_msg3(self.ctag, salt, self.X_ID, V, outs, fold=True)
        other = rebind_msg3(self.ctag, _os.urandom(32), self.X_ID, V, outs, fold=True)
        pair = lambda sig_s, sig_a: self.path_tx(u, tap, lv, "collab", [sig_s, sig_a, b"\x01"], back_tap.scriptPubKey,
                                                 0xffffffff)
        self.reject(pair(sign_schnorr(self.a_sec, msg), sign_schnorr(self.a_sec, msg)),
                    "send/neg collab with the owner's signature twice")
        self.reject(pair(sign_schnorr(self.s_sec, other), sign_schnorr(self.a_sec, other)),
                    "send/neg collab with a pair made for another salt")
        self.send(pair(sign_schnorr(self.s_sec, msg), sign_schnorr(self.a_sec, msg)),
                  "send/collab back into a leaf of the owner's, at once")

    # -- into the tree -----------------------------------------------------
    def receive_claimed(self):
        """The owner claims with the preimage after its exit delay."""
        timeout = self.mtp() + 30 * H
        tap, lv, _ = self.htlc("receive", timeout, receive=True)
        u = self.fund(tap.scriptPubKey, V, self.X)
        claim = lambda pre, key, seq=EXIT: self.path_tx(u, tap, lv, "claim", [], self.owner_spk(), seq, key=key,
                                                        after=[pre])
        self.reject(claim(self.pre, self.a_sec), "receive/neg claim before the exit delay")
        self.wait_csv(u.txid, EXIT_S)
        self.reject(claim(self.pre, self.s_sec), "receive/neg claim signed by the operator")
        self.reject(claim(_os.urandom(32), self.a_sec), "receive/neg claim with a wrong preimage")
        self.send(claim(self.pre, self.a_sec), "receive/claim by the owner with the preimage")

    def receive_refunded(self):
        """The owner never claimed: past the timeout the operator takes the
        output back after its own delay. Created past the timeout, the refund
        in the same block is refused: the owner still has the operator's delay
        to claim."""
        timeout = self.mtp() + 2 * H
        tap, lv, _ = self.htlc("receive_refund", timeout, receive=True)
        u0 = self.fund(tap.scriptPubKey, V, self.X)
        early = self.path_tx(u0, tap, lv, "refund", [], self.operator_spk(), OPD, locktime=timeout, key=self.s_sec)
        self.reject(early, "receive/neg refund before the timeout")
        self.mtp_past(timeout)
        tap2, lv2, _ = self.htlc("receive_refund_late", timeout, receive=True)
        u = self.fund(tap2.scriptPubKey, V, self.X, mine=False)
        refund = lambda key=None, seq=OPD: self.path_tx(u, tap2, lv2, "refund", [], self.operator_spk(), seq,
                                                        locktime=timeout, key=key or self.s_sec)
        self.reject_beside(u.txid, refund(), "receive/neg refund in the block that creates the output, past the timeout",
                           "bad-txns-nonfinal")
        self.generate(self.node, 1)
        self.reject(refund(), "receive/neg refund past the timeout, before the operator's delay")
        self.wait_csv(u.txid, OPD_S)
        self.reject(refund(key=self.a_sec), "receive/neg refund signed by the owner")
        self.send(refund(), "receive/refund by the operator after the timeout and its delay")
        self.send(early, "receive/refund of the earlier output, now past the timeout")


if __name__ == "__main__":
    T15().main()
