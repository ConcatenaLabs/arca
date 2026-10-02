#!/usr/bin/env python3
"""T1c: the round-1 compact record is NOT injective, and the fix.

Round-1 record: asset || 0x01 || value_le8 || 0x01 || program || version.
The version is pushed as a script number, so witness v0 contributes no byte.
A child pinned as  v1 <P32>  therefore hashes identically to an output paying
witness v0 with the 33-byte program  P32 || 0x01  -- a program length that
can never be spent. Anyone who can get a transaction into a block could unroll
a node into unspendable children. The same test against the injective record."""
from arklib import *

CHILD = 1_0000_0000
RESERVE = 1000


class T1c(ArkBase, BitcoinTestFramework):
    NAME = "t1c"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        s_x = compute_xonly_pubkey(generate_privkey())[0]
        expiry = node.getblockcount() + 5000
        for form in ("compact_v1", "compact", "plain"):
            for r in (2, 4):
                spks = [self.p2tr()[0] for _ in range(r)]
                kids = [(self.X_ID, CHILD, spk[2:]) for spk in spks]
                tap, lv = node_taptree(kids, expiry, s_x, form)
                tag = "%s_r%d" % (form, r)
                self.rec_script(tag + "/unroll_leaf", lv["unroll"], tap, "unroll")
                u = self.fund(tap.scriptPubKey, r * CHILD + RESERVE, self.X)
                # child 0 replaced by witness v0 with the 33-byte program P||0x01
                evil_spk = bytes([0x00, 0x21]) + spks[0][2:] + b"\x01"
                outs = [self.out(CHILD, evil_spk, self.X_OUT)] + \
                       [self.out(CHILD, spk, self.X_OUT) for spk in spks[1:]] + [self.fee(RESERVE, self.X_OUT)]
                tx = self.mktx([u], outs)
                self.setwit(tx, 0, [bytes(lv["unroll"]), control_block(tap, "unroll")])
                self.rec(tag + "/evil_spk", evil_spk.hex())
                if form == "compact_v1":
                    # policy refuses the odd output type, consensus does not
                    txid = self.mine_raw(tx, tag + "/SUBSTITUTED_CHILD_MINED")
                    o = node.gettxout(txid, 0)
                    self.rec(tag + "/landed", {"scriptPubKey": o["scriptPubKey"]["hex"], "type": o["scriptPubKey"].get("type"),
                                               "value": str(o["value"]), "asset": o["asset"]})
                    # and nobody can ever spend it
                    stuck = Utxo(txid, 0, tx.vout[0])
                    t2 = self.mktx([stuck], [self.out(CHILD - 400, self.wallet_spk(), self.X_OUT), self.fee(400, self.X_OUT)])
                    self.setwit(t2, 0, [b"\x01"])
                    self.reject(t2, tag + "/neg_spend_of_substituted_child")
                else:
                    self.reject(tx, tag + "/neg_v0_33byte_program_substitution")
                    good = self.mktx([u], [self.out(CHILD, spk, self.X_OUT) for spk in spks] + [self.fee(RESERVE, self.X_OUT)])
                    self.setwit(good, 0, [bytes(lv["unroll"]), control_block(tap, "unroll")])
                    self.send(good, tag + "/unroll_reserve_fee", extra={"leaf_script_bytes": len(bytes(lv["unroll"]))})


if __name__ == "__main__":
    T1c().main()
