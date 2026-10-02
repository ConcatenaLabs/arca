#!/usr/bin/env python3
"""T19: reclaim, a third path on a lowest node with four leaves.

    <release> OP_DUP OP_TOALTSTACK <A0> OP_CHECKSIGFROMSTACKVERIFY
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK <A1> OP_CHECKSIGFROMSTACKVERIFY
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK <A2> OP_CHECKSIGFROMSTACKVERIFY
    OP_FROMALTSTACK <A3> OP_CHECKSIGFROMSTACKVERIFY
    <S> OP_CHECKSIG
    release = SHA256("Arca/release" || genesis_hash || H)   witness: <sig_S> <sig_3> <sig_2> <sig_1> <sig_0>
"""
from arklib3 import *
import os as _os

LEAF = 1000_0000
RESERVE = 1000
FEE = 1500


class T19(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t19"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.gen = self.genesis_internal()
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.expiry = self.node.getblockcount() + 5000
        self.four()
        self.sixteen()

    def lowest(self, owners_x, n=4):
        spks = [self.p2tr()[0] for _ in range(n)]
        kids = [(self.X_ID, LEAF, spk[2:]) for spk in spks]
        rel = release_msg(self.gen, kids)
        unroll = CScript(unroll_compact_body(kids) if n <= 6 else unroll_stream_body(kids))
        sweep = sweep_leaf(self.expiry, self.s_x)
        reclaim = reclaim_leaf(rel, owners_x, self.s_x)
        tap = taproot_construct(NUMS, [("unroll", unroll), [("sweep", sweep), ("reclaim", reclaim)]])
        return {"tap": tap, "lv": {"unroll": unroll, "sweep": sweep, "reclaim": reclaim}, "kids": kids,
                "spks": spks, "rel": rel, "value": n * LEAF + RESERVE}

    def reclaim_tx(self, nd, u, owner_sigs, s_sec=None, s_sig=None):
        """owner_sigs in owner order 0..n-1; the witness puts sig_0 on top."""
        tx = self.mktx([u], [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        leaf = nd["lv"]["reclaim"]
        if s_sig is None:
            s_sig = self.sign(s_sec or self.s_sec, tx, 0, leaf)
        self.setwit(tx, 0, [s_sig] + list(reversed(owner_sigs)) + [bytes(leaf), control_block(nd["tap"], "reclaim")])
        return tx

    def four(self):
        self.log.info("=== T19: reclaim, four owners ===")
        secs = [generate_privkey() for _ in range(4)]
        xs = [compute_xonly_pubkey(k)[0] for k in secs]
        nd = self.lowest(xs)
        other = self.lowest(xs)                      # same owners, other children
        self.rec_script("reclaim4_leaf", nd["lv"]["reclaim"], nd["tap"], "reclaim")
        self.rec("release_message", {"preimage": "Arca/release || genesis(internal) || H",
                                     "genesis_internal": self.gen.hex(), "H": children_hash(nd["kids"]).hex(),
                                     "release": nd["rel"].hex()})
        sigs = [sign_schnorr(k, nd["rel"]) for k in secs]
        osigs = [sign_schnorr(k, other["rel"]) for k in secs]

        def u():
            return self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        U = u()
        self.reject(self.reclaim_tx(nd, U, sigs[:2] + [b""] + sigs[3:]), "neg/three_of_four_one_empty")
        self.reject(self.reclaim_tx(nd, U, sigs[:3] + [b""]), "neg/three_of_four_last_empty")
        self.reject(self.reclaim_tx(nd, U, sigs[:1] + [_os.urandom(64)] + sigs[2:]), "neg/three_of_four_one_junk")
        self.reject(self.reclaim_tx(nd, U, osigs), "neg/all_four_signed_another_node")
        self.reject(self.reclaim_tx(nd, U, sigs[:3] + osigs[3:]), "neg/one_signature_for_another_node")
        rel_other_chain = sha256(RTAG + sha256(b"another chain") + children_hash(nd["kids"]))
        self.reject(self.reclaim_tx(nd, U, [sign_schnorr(k, rel_other_chain) for k in secs]),
                    "neg/signed_for_another_genesis")
        self.reject(self.reclaim_tx(nd, U, sigs, s_sig=b""), "neg/no_operator_signature")
        self.reject(self.reclaim_tx(nd, U, sigs, s_sec=generate_privkey()), "neg/operator_signature_wrong_key")
        self.reject(self.reclaim_tx(nd, U, [sigs[1], sigs[0]] + sigs[2:]), "neg/owner_signatures_out_of_order")
        tx = self.mktx([U], [self.out(U.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        leaf = nd["lv"]["reclaim"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, leaf)] + sigs + [bytes(leaf), control_block(nd["tap"], "reclaim")])
        self.reject(tx, "neg/witness_in_owner_order_bottom_to_top")
        t = self.send(self.reclaim_tx(nd, U, sigs), "pos/reclaim_all_four_and_operator",
                      extra={"leaf_bytes": len(bytes(leaf)), "sigops_used": 250})
        d = self.R["pos/reclaim_all_four_and_operator"]
        d["sigops_budget"] = 50 + d["witness_input0_bytes"]
        self.rec("pos/reclaim_all_four_and_operator", d)
        assert self.node.gettxout(U.txid, U.vout) is None
        # for comparison on the same node: an unroll (reserve fee) and a sweep
        U2 = u()
        tx = self.mktx([U2], [self.out(LEAF, spk, self.X_OUT) for spk in nd["spks"]] + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(nd["lv"]["unroll"]), control_block(nd["tap"], "unroll")])
        self.send(tx, "compare/unroll_of_the_node_with_reclaim_leaf")
        self.rec("compare/note", "same node: unroll control block 65 bytes (reclaim sits at depth 2 with the sweep)")
        # the release pair is also valid on a second funding of the same node script (never fund twice)
        U3 = u()
        self.send(self.reclaim_tx(nd, U3, sigs), "pos/release_signatures_reused_on_a_second_funding_of_same_script")

    def sixteen(self):
        """r3 item 4: a 16-owner RECLAIM at the level above, measured."""
        self.log.info("=== T19: reclaim, sixteen owners ===")
        secs = [generate_privkey() for _ in range(16)]
        xs = [compute_xonly_pubkey(k)[0] for k in secs]
        nd = self.lowest(xs, n=4)
        self.rec_script("reclaim16_leaf", nd["lv"]["reclaim"], nd["tap"], "reclaim")
        sigs = [sign_schnorr(k, nd["rel"]) for k in secs]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        self.reject(self.reclaim_tx(nd, U, sigs[:15] + [b""]), "neg16/fifteen_of_sixteen")
        self.send(self.reclaim_tx(nd, U, sigs), "pos16/reclaim_sixteen_and_operator",
                  extra={"leaf_bytes": len(bytes(nd["lv"]["reclaim"])), "sigops_used": 17 * 50})
        d = self.R["pos16/reclaim_sixteen_and_operator"]
        d["sigops_budget"] = 50 + d["witness_input0_bytes"]
        self.rec("pos16/reclaim_sixteen_and_operator", d)


if __name__ == "__main__":
    T19().main()
