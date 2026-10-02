#!/usr/bin/env python3
"""T2: the LEAF (user's virtual output). NUMS internal key, three leaves:
collab <A> CHECKSIGVERIFY <S> CHECKSIG | exit <delay> CSV DROP <A> CHECKSIG |
sweep <expiry> CLTV DROP <S> CHECKSIG. Spend each path."""
from arklib import *
import os as _os

VALUE = 1_0000_0000
DELAY = 6
FEE = 400


class T2(ArkBase, BitcoinTestFramework):
    NAME = "t2"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        node = self.node
        self.whitelist(self.X)
        a_sec, s_sec = generate_privkey(), generate_privkey()
        a_x, s_x = compute_xonly_pubkey(a_sec)[0], compute_xonly_pubkey(s_sec)[0]
        expiry = node.getblockcount() + 40
        tap, lv = leaf_taptree(a_x, s_x, DELAY, expiry)
        for n in ("collab", "exit", "sweep"):
            self.rec_script("leaf/" + n, lv[n], tap, n)
        self.rec("params", {"delay": DELAY, "expiry": expiry, "value": VALUE,
                            "leaf_spk": bytes(tap.scriptPubKey).hex()})

        def spend(u, name, sigs, dest_spk, seq=0xffffffff, locktime=0, signers=()):
            tx = self.mktx([(u, seq)], [self.out(VALUE - FEE, dest_spk, self.X_OUT),
                                        self.fee(FEE, self.X_OUT)], locktime)
            stack = []
            for s in signers:
                if isinstance(s, bytes) and len(s) == 32:
                    stack.append(self.sign(s, tx, 0, lv[name]))
                else:
                    stack.append(s)          # raw element (e.g. empty or junk)
            self.setwit(tx, 0, stack + [bytes(lv[name]), control_block(tap, name)])
            return tx

        # ---------------- collaborative path (A and S)
        self.log.info("=== T2 collaborative path ===")
        u = self.fund(tap.scriptPubKey, VALUE, self.X)
        new_leaf = leaf_taptree(compute_xonly_pubkey(generate_privkey())[0], s_x, DELAY, expiry)[0]
        dest = bytes(new_leaf.scriptPubKey)
        # witness order: [sig_S, sig_A] (A is checked first, so its sig is on top)
        self.reject(spend(u, "collab", None, dest, signers=[b"", a_sec]), "collab/neg_missing_S_sig")
        self.reject(spend(u, "collab", None, dest, signers=[a_sec, a_sec]), "collab/neg_S_sig_by_A")
        self.reject(spend(u, "collab", None, dest, signers=[s_sec, generate_privkey()]), "collab/neg_A_sig_by_stranger")
        # key path: the internal key is NUMS, nobody can sign for the output key
        tx = self.mktx([u], [self.out(VALUE - FEE, dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [_os.urandom(64)])
        self.reject(tx, "collab/neg_keypath_random_sig")
        self.send(spend(u, "collab", None, dest, signers=[s_sec, a_sec]), "collab/transfer_A_and_S")

        # ---------------- unilateral exit (A alone after `delay`)
        self.log.info("=== T2 unilateral exit ===")
        u = self.fund(tap.scriptPubKey, VALUE, self.X)       # 1 confirmation now
        wdest = self.wallet_spk()
        self.generate(node, DELAY - 2)                         # DELAY-1 confirmations
        # nSequence = delay but the output is one block too young -> BIP68
        self.reject(spend(u, "exit", None, wdest, seq=DELAY, signers=[a_sec]), "exit/neg_before_delay_bip68")
        # nSequence = delay-1 IS BIP68-final now, so it is the script's CSV that refuses
        self.reject(spend(u, "exit", None, wdest, seq=DELAY - 1, signers=[a_sec]), "exit/neg_sequence_below_delay")
        self.reject(spend(u, "exit", None, wdest, seq=0xffffffff, signers=[a_sec]), "exit/neg_sequence_final")
        self.generate(node, 1)                                 # now DELAY confirmations
        self.reject(spend(u, "exit", None, wdest, seq=DELAY, signers=[s_sec]), "exit/neg_signed_by_S")
        self.send(spend(u, "exit", None, wdest, seq=DELAY, signers=[a_sec]), "exit/claim_after_delay")

        # ---------------- operator sweep after expiry
        self.log.info("=== T2 operator sweep ===")
        u = self.fund(tap.scriptPubKey, VALUE, self.X)
        self.reject(spend(u, "sweep", None, wdest, seq=0xfffffffe, locktime=expiry, signers=[s_sec]),
                    "sweep/neg_before_expiry")
        self.mine_to(expiry)
        self.reject(spend(u, "sweep", None, wdest, seq=0xfffffffe, locktime=expiry, signers=[a_sec]),
                    "sweep/neg_signed_by_A")
        self.send(spend(u, "sweep", None, wdest, seq=0xfffffffe, locktime=expiry, signers=[s_sec]),
                  "sweep/after_expiry")


if __name__ == "__main__":
    T2().main()
