#!/usr/bin/env python3
"""T25: RECLAIM-D, the reclaim of a lowest node whose coins moved out of round.

A coin that moves out of round leaves its slot's release to the coins it
moved into: the sender's key signs a delegation to the owner keys of every
output of the reassignment, SHA256("Arca/delegate" || genesis_hash || K_1 ||
... || K_m). RECLAIM-D accepts, for each owner of the node, a tree: the
owner's own release, or its delegation and a tree for each key it names. Every
leaf of every tree is a release over SHA256(P || M), P = "Arca/release" ||
genesis_hash || H and M the connector asset of the round of that holder's new
coin, read from an input. So the node is released only when every coin
resting on it has a successor in a round in the chain.

    witness (bottom -> top): <sig_S> <P> <Q> <step_31> ... <step_0>
    step (top first): <a> [<d> (release: <K> <sig> <k>) | (delegation: <e1> <e2> <e3> <K> <sig>)]

The node runs with -par=1, so every refused block names the script failure.
"""
from arklib3 import *

LEAF = 1000_0000
RESERVE = 1000
FEE = 3000


def key():
    sec = generate_privkey()
    return sec, compute_xonly_pubkey(sec)[0]


class T25(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t25"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.gen = self.genesis_internal()
        self.Q = delegate_prefix(self.gen)
        self.s_sec, self.s_x = key()
        self.expiry = self.node.getblockcount() + 5000
        self.m1 = self.connector_atom(self.s_sec, "setup/issue M of round 1")
        self.m2 = self.connector_atom(self.s_sec, "setup/issue M of round 2")
        self.unknown_key_type()
        self.chains()
        self.direct_and_compact()
        self.six_owners_full()

    # ---- helpers ------------------------------------------------------------

    def lowest(self, owners_x, n=4, size_check=True):
        spks = [self.p2tr()[0] for _ in range(n)]
        kids = [(self.X_ID, LEAF, spk[2:]) for spk in spks]
        prefix = release_prefix(self.gen, kids)
        unroll = CScript(unroll_compact_body(kids))
        sweep = sweep_leaf(self.expiry, self.s_x)
        reclaim = reclaim_leaf(prefix, owners_x, self.s_x)
        reclaim_d = reclaim_delegated_leaf(prefix, self.Q, owners_x, self.s_x)
        if not size_check:
            raw = bytes(reclaim_d)
            weak = bytes(CScript([OP_SHA256, OP_OVER, OP_SIZE, 32, OP_EQUALVERIFY, OP_TOALTSTACK]))
            assert raw.count(weak) == RECLAIM_STEPS
            reclaim_d = CScript(raw.replace(weak, bytes(CScript([OP_SHA256, OP_OVER, OP_TOALTSTACK]))))
        tap, lv = node_taptree_delegated(unroll, sweep, reclaim, reclaim_d)
        return {"tap": tap, "lv": lv, "kids": kids, "spks": spks, "prefix": prefix, "value": n * LEAF + RESERVE}

    def rel(self, k, nd, m, at):
        sec, x = k
        return rel_node(x, sign_schnorr(sec, sha256(nd["prefix"] + m)), at)

    def dele(self, k, kids, to=None, msg=None):
        """k delegates to the keys of `kids` (or to `to`, keys given as such)."""
        sec, x = k
        names = to if to is not None else [c[1] for c in kids]
        return del_node(x, sign_schnorr(sec, msg if msg is not None else delegate_msg(self.gen, names)), kids)

    def build(self, nd, u, ms, below, leaf="reclaim_d", s_sec=None, s_sig=None):
        outs = [self.out(u.amount - FEE, self.wallet_spk(), self.X_OUT)]
        outs += [self.out(m.amount, OP_TRUE_SPK, m.txout.nAsset.vchCommitment) for m in ms]
        tx = self.mktx([u] + list(ms), outs + [self.fee(FEE, self.X_OUT)])
        script = nd["lv"][leaf]
        if s_sig is None:
            s_sig = self.sign(s_sec or self.s_sec, tx, 0, script)
        below = [s_sig] + below[1:]
        self.setwit(tx, 0, below + [bytes(script), control_block(nd["tap"], leaf)])
        for j in range(len(ms)):
            self.setwit(tx, 1 + j, OP_TRUE_WITNESS)
        return tx

    def reclaim_d(self, nd, u, trees, ms, seq=None, prefix=None, dprefix=None, **kw):
        below = reclaim_delegated_items(b"", prefix or nd["prefix"], dprefix or self.Q, trees, seq=seq)
        return self.build(nd, u, ms, below, **kw)

    def keep_atoms(self, txid, n):
        """The atoms of M went back to OP_TRUE at outputs 1..n: use them again."""
        for j, m in enumerate([self.m1, self.m2][:n]):
            m["M_u"] = self.utxo_at(txid, 1 + j)

    # ---- the unknown key type --------------------------------------------------

    def unknown_key_type(self):
        """Why RECLAIM-D checks that every key is 32 bytes: OP_CHECKSIGFROMSTACK
        in tapscript treats a key of any other length as an upgradable key type,
        and passes any non-empty signature for it. Relay policy refuses that; a
        block takes it."""
        self.log.info("=== T25: a 33-byte key passes OP_CHECKSIGFROMSTACKVERIFY in a block ===")
        probe = CScript([OP_SWAP, OP_CHECKSIGFROMSTACKVERIFY, OP_1])
        tap = taproot_construct(NUMS, [("probe", probe)])
        u = self.fund(tap.scriptPubKey, 50_000, self.X)
        tx = self.mktx([u], [self.out(50_000 - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        # stack bottom -> top: sig, pubkey, msg; OP_SWAP puts the pubkey on top
        self.setwit(tx, 0, [b"\x01" * 64, b"\x02" * 33, b"\x00" * 32, bytes(probe), control_block(tap, "probe")])
        res = self.accept(tx)
        assert not res["allowed"], res
        reason = res.get("reject-reason", "")
        blk = self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
        assert self.node.gettxout(u.txid, u.vout) is None
        self.rec("probe/33_byte_key_passes_csfs_in_a_block", {"mempool": reason, "mined": blk["hash"]})

    # ---- a coin paid twice, a swap, a direct release -------------------------

    def chains(self):
        self.log.info("=== T25: owner 0 paid twice, owner 1 refreshed, owners 2 and 3 swapped ===")
        M1, M2 = self.m1["M_id"], self.m2["M_id"]
        a = [key() for _ in range(4)]
        nd = self.lowest([x for _, x in a])
        self.rec_script("reclaim_d_leaf_4_owners", nd["lv"]["reclaim_d"], nd["tap"], "reclaim_d")
        self.rec("step_bytes", len(bytes(CScript(reclaim_step()))))
        b, a0c, c, bc, x2, x3 = (key() for _ in range(6))
        self.rec("delegation_message", {
            "preimage": "Arca/delegate || genesis(internal) || K_1 || ... || K_m",
            "genesis_internal": self.gen.hex(), "to": [b[1].hex(), a0c[1].hex()],
            "delegation": delegate_msg(self.gen, [b[1], a0c[1]]).hex()})

        # a0 paid b with change a0c; b paid c with change bc. a1 refreshed.
        # a2 and a3 swapped into x2 and x3. c, a0c, a1, x3 refreshed in round 1,
        # bc and x2 in round 2: input 1 holds an atom of M1, input 2 one of M2.
        tb = self.dele(b, [self.rel(c, nd, M1, 1), self.rel(bc, nd, M2, 2)])
        t0 = self.dele(a[0], [tb, self.rel(a0c, nd, M1, 1)])
        t1 = self.rel(a[1], nd, M1, 1)
        swap = [self.rel(x2, nd, M2, 2), self.rel(x3, nd, M1, 1)]
        t2 = self.dele(a[2], swap)
        t3 = self.dele(a[3], swap)
        good = [t0, t1, t2, t3]
        ms = [self.m1["M_u"], self.m2["M_u"]]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)

        # 1. A forged delegation.
        z = key()
        forged = self.dele(z, t0[3], to=[b[1], a0c[1]])
        forged = ("del", a[0][1], forged[2], t0[3])                     # z's signature in a0's place
        self.reject(self.reclaim_d(nd, U, [forged, t1, t2, t3], ms), "neg/forged_delegation_other_key",
                    expect="Invalid Schnorr signature")
        swapped = self.dele(a[0], [tb, self.rel(z, nd, M1, 1)], to=[b[1], a0c[1]])   # a0's signature, z in a0c's place
        self.reject(self.reclaim_d(nd, U, [swapped, t1, t2, t3], ms), "neg/forged_delegation_substituted_successor",
                    expect="Invalid Schnorr signature")
        other_chain = sha256(DTAG + sha256(b"another chain") + b[1] + a0c[1])
        oc = self.dele(a[0], t0[3], msg=other_chain)
        self.reject(self.reclaim_d(nd, U, [oc, t1, t2, t3], ms), "neg/delegation_signed_for_another_genesis",
                    expect="Invalid Schnorr signature")
        as_rel = ("del", a[0][1], sign_schnorr(a[0][0], sha256(nd["prefix"] + M1)), t0[3])
        self.reject(self.reclaim_d(nd, U, [as_rel, t1, t2, t3], ms), "neg/a_release_signature_used_as_a_delegation",
                    expect="Invalid Schnorr signature")

        # 2. A release before the holder's new coin exists: c names the
        # connector asset of a round that is not in the chain, so no input
        # can hold it. Its k names round 1's atom; and with no atom at all.
        M3 = sha256(b"connector of a round that never confirmed")
        early = self.dele(a[0], [self.dele(b, [self.rel(c, nd, M3, 1), self.rel(bc, nd, M2, 2)]),
                                 self.rel(a0c, nd, M1, 1)])
        self.reject(self.reclaim_d(nd, U, [early, t1, t2, t3], ms), "neg/release_names_a_round_not_in_the_chain",
                    expect="Invalid Schnorr signature")
        self.reject(self.reclaim_d(nd, U, good, []), "neg/no_atom_of_M_among_the_inputs")
        self.reject(self.reclaim_d(nd, U, good, ms[:1]), "neg/no_atom_of_M2_among_the_inputs")
        xc = self.fund(OP_TRUE_SPK, 5_000, self.X)
        self.reject(self.reclaim_d(nd, U, good, [xc, ms[1]]), "neg/k_names_an_input_of_another_asset",
                    expect="Invalid Schnorr signature")

        # 3 and 4. A stale delegation and the sender's release after
        # delegating: consensus cannot know that a key signed a delegation, so
        # these are refused by the operator, whose signature every reclaim
        # needs (recorded below as accepted on a node of their own).
        stale_b = self.dele(a[0], [self.rel(b, nd, M1, 1), self.rel(a0c, nd, M1, 1)])
        sender = self.rel(a[0], nd, M1, 1)

        # 5. Two releases for one slot, and one release for two.
        self.reject(self.reclaim_d(nd, U, [t0, t0, t2, t3], ms), "neg/slot_0s_tree_twice_slot_1_none",
                    expect="OP_EQUALVERIFY")
        self.reject(self.reclaim_d(nd, U, [t0, t1, t1, t3], ms), "neg/slot_1s_release_in_slot_2",
                    expect="OP_EQUALVERIFY")
        twice = self.dele(a[0], [("del", b[1], tb[2], [tb[3][0], tb[3][0]]), self.rel(a0c, nd, M1, 1)])
        self.reject(self.reclaim_d(nd, U, [twice, t1, t2, t3], ms), "neg/one_successors_release_for_both",
                    expect="Invalid Schnorr signature")
        self.reject(self.reclaim_d(nd, U, [t0, t1, t2], ms), "neg/three_trees_for_four_owners",
                    expect="OP_EQUALVERIFY")

        # An incomplete frontier: b's delegation names c and bc, only c is given.
        short = self.dele(a[0], [("del", b[1], tb[2], tb[3][:1]), self.rel(a0c, nd, M1, 1)])
        self.reject(self.reclaim_d(nd, U, [short, t1, t2, t3], ms), "neg/frontier_short_by_one",
                    expect="Invalid Schnorr signature")
        # A successor's release for another node.
        other = self.lowest([x for _, x in a])
        stray = self.dele(a[0], [tb, self.rel(a0c, other, M1, 1)])
        self.reject(self.reclaim_d(nd, U, [stray, t1, t2, t3], ms), "neg/successor_released_another_node",
                    expect="Invalid Schnorr signature")

        # The key split: b signed c || bc, 64 bytes. The witness names a 33-byte
        # and a 31-byte "key" with the same concatenation and junk signatures.
        cat = c[1] + bc[1]
        split = [[b"\x01", b"", cat[:33], b"\x01" * 64, sn(1)], [b"\x01", b"", cat[33:], b"\x01" * 64, sn(1)]]
        rest = reclaim_delegated_steps([t0])[3:]                          # a0c's release, then a0's delegation
        seq = split + [[b"\x01", b"\x01", b"\x01", b"", b"", b[1], tb[2]]] + rest + reclaim_delegated_steps([t1, t2, t3])
        self.reject(self.reclaim_d(nd, U, None, ms, seq=seq), "neg/key_split_33_and_31_bytes",
                    expect="OP_EQUALVERIFY")
        weak = self.lowest([x for _, x in a], size_check=False)
        tbw = self.dele(b, [self.rel(c, weak, M1, 1), self.rel(bc, weak, M2, 2)])
        t0w = self.dele(a[0], [tbw, self.rel(a0c, weak, M1, 1)])
        seqw = (split + [[b"\x01", b"\x01", b"\x01", b"", b"", b[1], tbw[2]]] + reclaim_delegated_steps([t0w])[3:]
                + reclaim_delegated_steps([self.rel(a[1], weak, M1, 1), self.dele(a[2], [self.rel(x2, weak, M2, 2),
                    self.rel(x3, weak, M1, 1)]), self.dele(a[3], [self.rel(x2, weak, M2, 2), self.rel(x3, weak, M1, 1)])]))
        UW = self.fund(weak["tap"].scriptPubKey, weak["value"], self.X)
        tx = self.reclaim_d(weak, UW, None, [self.m1["M_u"], self.m2["M_u"]], seq=seqw)
        reason = self.accept(tx).get("reject-reason", "")
        blk = self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
        assert self.node.gettxout(UW.txid, UW.vout) is None
        self.rec("control/key_split_mined_without_the_size_check",
                 {"mempool": reason, "mined": blk["hash"],
                  "note": "the same witness against RECLAIM-D without OP_SIZE 32 OP_EQUALVERIFY: c and bc never signed"})
        self.keep_atoms(tx.rehash(), 2)
        ms = [self.m1["M_u"], self.m2["M_u"]]

        # The bottom of the stack: P and Q are checked, and nothing may lie below S's signature.
        self.reject(self.reclaim_d(nd, U, good, ms, prefix=other["prefix"]), "neg/another_nodes_P_at_the_bottom",
                    expect="Invalid Schnorr signature")
        self.reject(self.reclaim_d(nd, U, good, ms, dprefix=delegate_prefix(sha256(b"x"))),
                    "neg/another_chains_Q_at_the_bottom", expect="Invalid Schnorr signature")
        tx = self.reclaim_d(nd, U, good, ms)
        tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, b"\x01")
        self.reject(tx, "neg/an_item_below_the_operators_signature")
        self.reject(self.reclaim_d(nd, U, good, ms, s_sig=b""), "neg/no_operator_signature")
        self.reject(self.reclaim_d(nd, U, good, ms, s_sec=key()[0]), "neg/operator_signature_wrong_key",
                    expect="Invalid Schnorr signature")
        # The compact RECLAIM does not take a delegated coin's release.
        sigs = [sign_schnorr(k, sha256(nd["prefix"] + M1)) for k, _ in [c, a[1], x2, x3]]
        self.reject(self.build(nd, U, ms[:1], reclaim_items(b"", sigs, [1] * 4), leaf="reclaim"),
                    "neg/compact_reclaim_with_successors_releases", expect="Invalid Schnorr signature")

        t = self.send(self.reclaim_d(nd, U, good, ms), "pos/reclaim_d_paid_twice_swapped_refreshed",
                      extra={"leaf_bytes": len(bytes(nd["lv"]["reclaim_d"])),
                             "steps_used": len(reclaim_delegated_steps(good))})
        assert self.node.gettxout(U.txid, U.vout) is None
        self.keep_atoms(t, 2)

        # 3 and 4, on nodes of their own: what consensus takes with the operator's signature.
        for label, first in (("stale_delegation_b_released_after_paying_c", "stale"),
                             ("sender_a0_released_after_delegating", "sender")):
            o = self.lowest([x for _, x in a])
            if first == "stale":
                t0o = self.dele(a[0], [self.rel(b, o, M1, 1), self.rel(a0c, o, M1, 1)])
            else:
                t0o = self.rel(a[0], o, M1, 1)
            swap_o = [self.rel(x2, o, M2, 2), self.rel(x3, o, M1, 1)]
            tr = [t0o, self.rel(a[1], o, M1, 1), self.dele(a[2], swap_o), self.dele(a[3], swap_o)]
            UO = self.fund(o["tap"].scriptPubKey, o["value"], self.X)
            t = self.send(self.reclaim_d(o, UO, tr, [self.m1["M_u"], self.m2["M_u"]]), "operator_refuses/" + label)
            self.keep_atoms(t, 2)

    # ---- every owner direct, and the compact leaf -----------------------------

    def direct_and_compact(self):
        self.log.info("=== T25: four direct releases, through RECLAIM-D and through RECLAIM ===")
        M1 = self.m1["M_id"]
        a = [key() for _ in range(4)]
        nd = self.lowest([x for _, x in a])
        trees = [self.rel(k, nd, M1, 1) for k in a]
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        t = self.send(self.reclaim_d(nd, U, trees, [self.m1["M_u"]]), "pos/reclaim_d_four_direct_releases")
        self.m1["M_u"] = self.utxo_at(t, 1)
        U2 = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        sigs = [t[2] for t in trees]
        t = self.send(self.build(nd, U2, [self.m1["M_u"]], reclaim_items(b"", sigs, [1] * 4), leaf="reclaim"),
                      "pos/compact_reclaim_on_the_delegated_node")
        self.m1["M_u"] = self.utxo_at(t, 1)
        U3 = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        tx = self.mktx([U3], [self.out(LEAF, spk, self.X_OUT) for spk in nd["spks"]] + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(nd["lv"]["unroll"]), control_block(nd["tap"], "unroll")])
        self.send(tx, "compare/unroll_of_the_delegated_node")

    # ---- the most the leaf holds ------------------------------------------------

    def six_owners_full(self):
        """Six owners (radix 6), every one of the 32 steps used: each owner
        paid out of round into four coins, and one of those into four again."""
        self.log.info("=== T25: six owners, 32 steps ===")
        M1 = self.m1["M_id"]
        a = [key() for _ in range(6)]
        nd = self.lowest([x for _, x in a], n=6)
        self.rec_script("reclaim_d_leaf_6_owners", nd["lv"]["reclaim_d"], nd["tap"], "reclaim_d")
        trees = []
        for i, k in enumerate(a):
            kids = [self.rel(key(), nd, M1, 1) for _ in range(4 if i < 2 else 3 if i < 4 else 2)]
            if i < 2:
                deeper = [self.rel(key(), nd, M1, 1) for _ in range(4)]
                kids[0] = self.dele(key(), deeper)
            trees.append(self.dele(k, kids))
        steps = len(reclaim_delegated_steps(trees))
        assert steps == RECLAIM_STEPS, steps
        U = self.fund(nd["tap"].scriptPubKey, nd["value"], self.X)
        t = self.send(self.reclaim_d(nd, U, trees, [self.m1["M_u"]]), "pos/reclaim_d_six_owners_32_steps",
                      extra={"steps_used": steps})
        self.m1["M_u"] = self.utxo_at(t, 1)
        over = trees[:5] + [self.dele(a[5], [self.rel(key(), nd, M1, 1) for _ in range(3)])]
        try:
            self.reclaim_d(nd, U, over, [self.m1["M_u"]])
            raise AssertionError("built")
        except AssertionError as e:
            assert "33 steps, the leaf has 32" in str(e), e
        self.rec("limit/33_steps_do_not_fit", "a node whose trees need more than 32 steps waits for its batch's expiry")


if __name__ == "__main__":
    T25().main()
