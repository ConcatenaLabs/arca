#!/usr/bin/env python3
"""T15 (sizes): hash-locked HTLC leaf for the Lightning gateway, rebindable.

  claim_S    : 32-byte preimage + S's rebindable signature  -> committed output 0
  claim_2of2 : 32-byte preimage + A and S rebindable sigs    -> committed output 0
  refund     : <timeout> CLTV DROP <A> CHECKSIG                          (plain)
  refund_rb  : <timeout> CLTV DROP + A and S rebindable sigs -> committed output 0
All four are spent once to measure them; a few negatives guard the claim."""
from arklib import *
import os as _os

V = 1_0000_0000
LEFT = 500


def hash_gate(h):
    return [OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY]


def rebind_single(s_x, salt, prefix=()):
    """One-signature rebind, m fixed at 1. Witness: <sig> [+ prefix items]."""
    return CScript(list(prefix) + [TAG + salt + b"\x01"] + record_ops(0) + [OP_SHA256, OP_CAT, OP_SHA256,
                                                                          s_x, OP_CHECKSIGFROMSTACK])


class T15(ArkBase, BitcoinTestFramework):
    NAME = "t15"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        a_sec, s_sec = generate_privkey(), generate_privkey()
        a_x, s_x = compute_xonly_pubkey(a_sec)[0], compute_xonly_pubkey(s_sec)[0]
        pre = _os.urandom(32)
        h = sha256(pre)
        timeout = node.getblockcount() + 30
        salts = {k: _os.urandom(32) for k in ("cs", "c2", "rb")}
        lv = {
            "claim_S": rebind_single(s_x, salts["cs"], prefix=hash_gate(h)),
            "claim_2of2": collab_rebind_fixed(a_x, s_x, salts["c2"], 1, prefix=hash_gate(h)),
            "refund": CScript([timeout, OP_CHECKLOCKTIMEVERIFY, OP_DROP, a_x, OP_CHECKSIG]),
            "refund_rb": collab_rebind_fixed(a_x, s_x, salts["rb"], 1,
                                             prefix=[timeout, OP_CHECKLOCKTIMEVERIFY, OP_DROP]),
        }
        tap = taproot_construct(NUMS, [[("claim_S", lv["claim_S"]), ("claim_2of2", lv["claim_2of2"])],
                                       [("refund", lv["refund"]), ("refund_rb", lv["refund_rb"])]])
        for k in lv:
            self.rec_script("leaf/" + k, lv[k], tap, k)
        dest = rebind_leaf_taptree(s_x, s_x, _os.urandom(32), 4, timeout + 1000)[0]
        back = rebind_leaf_taptree(a_x, s_x, _os.urandom(32), 4, timeout + 1000)[0]
        o_claim = [(self.X_ID, V - LEFT, bytes(dest.scriptPubKey))]
        o_back = [(self.X_ID, V - LEFT, bytes(back.scriptPubKey))]
        sg = lambda sec, salt, outs: sign_schnorr(sec, rebind_msg2(salt, outs))

        def tx(u, name, stack, outs, locktime=0):
            t = self.mktx([u], [self.out(v, spk, self.X_OUT) for (_, v, spk) in outs] +
                          [self.fee(u.amount - sum(v for (_, v, _) in outs), self.X_OUT)], locktime)
            self.setwit(t, 0, list(stack) + [bytes(lv[name]), control_block(tap, name)])
            return t

        us = [self.fund(tap.scriptPubKey, V, self.X) for _ in range(4)]
        # claim with S only
        sig_s = sg(s_sec, salts["cs"], o_claim)
        self.reject(tx(us[0], "claim_S", [sig_s, _os.urandom(32)], o_claim), "neg/claim_S_wrong_preimage")
        self.reject(tx(us[0], "claim_S", [sig_s, pre], o_back), "neg/claim_S_output_not_the_committed_one")
        self.reject(tx(us[0], "claim_S", [sg(a_sec, salts["cs"], o_claim), pre], o_claim), "neg/claim_S_signed_by_A")
        self.send(tx(us[0], "claim_S", [sig_s, pre], o_claim), "claim_S")
        # claim with A and S
        s2, a2 = sg(s_sec, salts["c2"], o_claim), sg(a_sec, salts["c2"], o_claim)
        self.reject(tx(us[1], "claim_2of2", [s2, a2, _os.urandom(32)], o_claim), "neg/claim_2of2_wrong_preimage")
        self.reject(tx(us[1], "claim_2of2", [s2, b"", pre], o_claim), "neg/claim_2of2_missing_A")
        self.send(tx(us[1], "claim_2of2", [s2, a2, pre], o_claim), "claim_2of2")
        # refunds
        sr, ar = sg(s_sec, salts["rb"], o_back), sg(a_sec, salts["rb"], o_back)
        self.reject(tx(us[3], "refund_rb", [sr, ar], o_back, locktime=timeout), "neg/refund_rb_before_timeout")
        self.mine_to(timeout)
        t = self.mktx([(us[2], 0xfffffffe)], [self.out(V - 300, self.wallet_spk(), self.X_OUT), self.fee(300, self.X_OUT)], timeout)
        self.setwit(t, 0, [self.sign(a_sec, t, 0, lv["refund"]), bytes(lv["refund"]), control_block(tap, "refund")])
        self.send(t, "refund_plain")
        self.send(tx(us[3], "refund_rb", [sr, ar], o_back, locktime=timeout), "refund_rb")


if __name__ == "__main__":
    T15().main()
