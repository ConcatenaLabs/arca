#!/usr/bin/env python3
"""T19: reclaim, a third path on a lowest node, bound to the rounds of its
owners' new leaves.

    <P> OP_TOALTSTACK                           P = "Arca/release" || genesis_hash || H
    for each owner i, in owner order:
        OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY                        M_i, the asset of input k_i, explicit
        OP_FROMALTSTACK OP_DUP OP_TOALTSTACK   (the last owner: OP_FROMALTSTACK)
        OP_SWAP OP_CAT OP_SHA256 <A_i> OP_CHECKSIGFROMSTACKVERIFY       A_i signed SHA256(P || M_i)
    <S> OP_CHECKSIG

    witness: <sig_S> <sig_3> <k_3> <sig_2> <k_2> <sig_1> <k_1> <sig_0> <k_0>
    one owner: OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <P> OP_SWAP OP_CAT OP_SHA256 <A_0> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIG

M_i is the connector asset of the round that made owner i's new leaf: what
spending that round's connector output issues with a zero contract hash. It
can be issued only while that round is in the chain, so a release is void
with the round it names. Here each M is issued for real, from a connector
output, by the operator's signature.
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
        self.m1 = self.connector_atom(self.s_sec, "setup/issue M of round 1")
        self.m2 = self.connector_atom(self.s_sec, "setup/issue M of round 2")
        self.four()
        self.two_rounds()
        self.one()
        self.sixteen()

    def lowest(self, owners_x, n=4):
        spks = [self.p2tr()[0] for _ in range(n)]
        kids = [(self.X_ID, LEAF, spk[2:]) for spk in spks]
        prefix = release_prefix(self.gen, kids)
        unroll = CScript(unroll_compact_body(kids) if n <= 6 else unroll_stream_body(kids))
        sweep = sweep_leaf(self.expiry, self.s_x)
        reclaim = reclaim_leaf(prefix, owners_x, self.s_x)
        tap = taproot_construct(NUMS, [("unroll", unroll), [("sweep", sweep), ("reclaim", reclaim)]])
        return {"tap": tap, "lv": {"unroll": unroll, "sweep": sweep, "reclaim": reclaim}, "kids": kids,
                "spks": spks, "prefix": prefix, "value": n * LEAF + RESERVE}

    def reclaim_tx(self, nd, u, owner_sigs, ks, ms, s_sec=None, s_sig=None, below=None):
        """owner_sigs and ks in owner order 0..n-1; ms: the utxos of M atoms,
        inputs 1.. of the reclaim, each atom paid back to OP_TRUE."""
        outs = [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT)]
        outs += [self.out(m.amount, OP_TRUE_SPK, m.txout.nAsset.vchCommitment) for m in ms]
        tx = self.mktx([u] + list(ms), outs + [self.fee(FEE, self.X_OUT)])
        leaf = nd["lv"]["reclaim"]
        if s_sig is None:
            s_sig = self.sign(s_sec or self.s_sec, tx, 0, leaf)
        items = below if below is not None else reclaim_items(s_sig, owner_sigs, ks)
        self.setwit(tx, 0, items + [bytes(leaf), control_block(nd["tap"], "reclaim")])
        for j in range(len(ms)):
            self.setwit(tx, 1 + j, OP_TRUE_WITNESS)
        return tx

    def four(self):
        self.log.info("=== T19: reclaim, four owners, all refreshed in round 1 ===")
        secs = [generate_privkey() for _ in range(4)]
        xs = [compute_xonly_pubkey(k)[0] for k in secs]
        nd = self.lowest(xs)
        other = self.lowest(xs)                      # same owners, other children
        M1, M2 = self.m1["M_id"], self.m2["M_id"]
        self.rec_script("reclaim4_leaf", nd["lv"]["reclaim"], nd["tap"], "reclaim")
        rel = sha256(nd["prefix"] + M1)
        self.rec("release_message", {"preimage": "Arca/release || genesis(internal) || H || M(internal)",
                                     "genesis_internal": self.gen.hex(), "H": children_hash(nd["kids"]).hex(),
                                     "M": M1.hex(), "release": rel.hex()})
        sigs = [sign_schnorr(k, rel) for k in secs]
        k1 = [1, 1, 1, 1]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        m1 = self.m1["M_u"]

        # Without M: no input 1 to read M from.
        self.reject(self.reclaim_tx(nd, U, sigs, k1, []), "neg/without_M")
        # Another round's M at input 1.
        self.reject(self.reclaim_tx(nd, U, sigs, k1, [self.m2["M_u"]]), "neg/another_rounds_M")
        # Another asset: k names an input of X, or the node itself.
        xc = self.fund(OP_TRUE_SPK, 5_000, self.X)
        self.reject(self.reclaim_tx(nd, U, sigs, k1, [xc]), "neg/another_asset_at_k")
        self.reject(self.reclaim_tx(nd, U, sigs, [0, 0, 0, 0], [m1]), "neg/k_names_the_node_itself")
        self.reject(self.reclaim_tx(nd, U, sigs, [1, 1, 1, 2], [m1]), "neg/k_out_of_range_for_one_owner")
        # Three releases of four.
        self.reject(self.reclaim_tx(nd, U, sigs[:2] + [b""] + sigs[3:], k1, [m1]), "neg/three_of_four_one_empty")
        self.reject(self.reclaim_tx(nd, U, sigs[:3] + [b""], k1, [m1]), "neg/three_of_four_last_empty")
        self.reject(self.reclaim_tx(nd, U, sigs[:1] + [_os.urandom(64)] + sigs[2:], k1, [m1]),
                    "neg/three_of_four_one_junk")
        # Releases over the old message, SHA256("Arca/release" || genesis || H),
        # in the new witness shape and in the old one (no index items).
        old = sha256(nd["prefix"])
        old_sigs = [sign_schnorr(k, old) for k in secs]
        self.reject(self.reclaim_tx(nd, U, old_sigs, k1, [m1]), "neg/releases_over_the_old_message")
        tx = self.reclaim_tx(nd, U, [], [], [m1], below=[b""] + list(reversed(old_sigs)))
        tx.wit.vtxinwit[0].scriptWitness.stack[0] = self.sign(self.s_sec, tx, 0, nd["lv"]["reclaim"])
        self.reject(tx, "neg/old_message_old_witness_shape")
        # Releases for another node, for another chain, or naming round 2 while k names round 1.
        osigs = [sign_schnorr(k, sha256(other["prefix"] + M1)) for k in secs]
        self.reject(self.reclaim_tx(nd, U, osigs, k1, [m1]), "neg/all_four_signed_another_node")
        self.reject(self.reclaim_tx(nd, U, sigs[:3] + osigs[3:], k1, [m1]), "neg/one_signature_for_another_node")
        other_chain = sha256(RTAG + sha256(b"another chain") + children_hash(nd["kids"]) + M1)
        self.reject(self.reclaim_tx(nd, U, [sign_schnorr(k, other_chain) for k in secs], k1, [m1]),
                    "neg/signed_for_another_genesis")
        m2sigs = [sign_schnorr(k, sha256(nd["prefix"] + M2)) for k in secs]
        self.reject(self.reclaim_tx(nd, U, sigs[:3] + m2sigs[3:], k1, [m1, self.m2["M_u"]]),
                    "neg/one_release_names_round2_its_k_names_round1")
        self.reject(self.reclaim_tx(nd, U, sigs, k1, [m1], s_sig=b""), "neg/no_operator_signature")
        self.reject(self.reclaim_tx(nd, U, sigs, k1, [m1], s_sec=generate_privkey()), "neg/operator_signature_wrong_key")
        self.reject(self.reclaim_tx(nd, U, [sigs[1], sigs[0]] + sigs[2:], k1, [m1]), "neg/owner_signatures_out_of_order")

        t = self.send(self.reclaim_tx(nd, U, sigs, k1, [m1]), "pos/reclaim_four_owners_with_M",
                      extra={"leaf_bytes": len(bytes(nd["lv"]["reclaim"])), "sigops_used": 250})
        d = self.R["pos/reclaim_four_owners_with_M"]
        d["sigops_budget"] = 50 + d["witness_input0_bytes"]
        self.rec("pos/reclaim_four_owners_with_M", d)
        assert self.node.gettxout(U.txid, U.vout) is None
        # The atom of M went back to OP_TRUE: the operator uses it again.
        self.m1["M_u"] = self.utxo_at(t, 1)
        assert self.m1["M_u"].txout.nAsset.vchCommitment == self.m1["M_OUT"]

        # for comparison on the same node: an unroll (reserve fee)
        U2 = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        tx = self.mktx([U2], [self.out(LEAF, spk, self.X_OUT) for spk in nd["spks"]] + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(nd["lv"]["unroll"]), control_block(nd["tap"], "unroll")])
        self.send(tx, "compare/unroll_of_the_node_with_reclaim_leaf")
        self.rec("compare/note", "same node: unroll control block 65 bytes (reclaim sits at depth 2 with the sweep)")
        # the releases are also valid on a second funding of the same node
        # script (never fund twice), with the same atom of M again
        U3 = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        t3 = self.send(self.reclaim_tx(nd, U3, sigs, k1, [self.m1["M_u"]]),
                       "pos/releases_reused_on_a_second_funding_same_atom_of_M")
        self.m1["M_u"] = self.utxo_at(t3, 1)

    def two_rounds(self):
        self.log.info("=== T19: reclaim, owners 0 and 1 refreshed in round 1, owners 2 and 3 in round 2 ===")
        secs = [generate_privkey() for _ in range(4)]
        xs = [compute_xonly_pubkey(k)[0] for k in secs]
        nd = self.lowest(xs)
        rounds = [self.m1["M_id"], self.m1["M_id"], self.m2["M_id"], self.m2["M_id"]]
        sigs = [sign_schnorr(k, sha256(nd["prefix"] + m)) for k, m in zip(secs, rounds)]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        ms = [self.m1["M_u"], self.m2["M_u"]]
        self.reject(self.reclaim_tx(nd, U, sigs, [1, 1, 1, 1], ms), "neg2/every_k_names_round1")
        self.reject(self.reclaim_tx(nd, U, sigs, [1, 1, 2, 2], ms[:1]), "neg2/round2s_M_missing")
        self.reject(self.reclaim_tx(nd, U, sigs, [2, 2, 1, 1], ms), "neg2/k_swapped")
        t = self.send(self.reclaim_tx(nd, U, sigs, [1, 1, 2, 2], ms), "pos2/reclaim_two_rounds_two_atoms")
        self.m1["M_u"], self.m2["M_u"] = self.utxo_at(t, 1), self.utxo_at(t, 2)

    def one(self):
        self.log.info("=== T19: reclaim, one owner ===")
        sec = generate_privkey()
        nd = self.lowest([compute_xonly_pubkey(sec)[0]], n=1)
        self.rec_script("reclaim1_leaf", nd["lv"]["reclaim"], nd["tap"], "reclaim")
        sig = sign_schnorr(sec, sha256(nd["prefix"] + self.m1["M_id"]))
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        self.reject(self.reclaim_tx(nd, U, [sig], [1], []), "neg1/without_M")
        self.reject(self.reclaim_tx(nd, U, [sig], [1], [self.m2["M_u"]]), "neg1/another_rounds_M")
        self.reject(self.reclaim_tx(nd, U, [sign_schnorr(sec, sha256(nd["prefix"]))], [1], [self.m1["M_u"]]),
                    "neg1/release_over_the_old_message")
        self.reject(self.reclaim_tx(nd, U, [b""], [1], [self.m1["M_u"]]), "neg1/release_missing")
        t = self.send(self.reclaim_tx(nd, U, [sig], [1], [self.m1["M_u"]]), "pos1/reclaim_one_owner_with_M",
                      extra={"leaf_bytes": len(bytes(nd["lv"]["reclaim"]))})
        self.m1["M_u"] = self.utxo_at(t, 1)

    def sixteen(self):
        """A 16-owner RECLAIM at the level above, measured."""
        self.log.info("=== T19: reclaim, sixteen owners ===")
        secs = [generate_privkey() for _ in range(16)]
        xs = [compute_xonly_pubkey(k)[0] for k in secs]
        nd = self.lowest(xs, n=4)
        self.rec_script("reclaim16_leaf", nd["lv"]["reclaim"], nd["tap"], "reclaim")
        sigs = [sign_schnorr(k, sha256(nd["prefix"] + self.m1["M_id"])) for k in secs]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        self.reject(self.reclaim_tx(nd, U, sigs[:15] + [b""], [1] * 16, [self.m1["M_u"]]), "neg16/fifteen_of_sixteen")
        self.send(self.reclaim_tx(nd, U, sigs, [1] * 16, [self.m1["M_u"]]), "pos16/reclaim_sixteen_owners_with_M",
                  extra={"leaf_bytes": len(bytes(nd["lv"]["reclaim"])), "sigops_used": 17 * 50})
        d = self.R["pos16/reclaim_sixteen_owners_with_M"]
        d["sigops_budget"] = 50 + d["witness_input0_bytes"]
        self.rec("pos16/reclaim_sixteen_owners_with_M", d)


if __name__ == "__main__":
    T19().main()
