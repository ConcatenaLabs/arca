#!/usr/bin/env python3
"""T13: membership-gated unroll with a PRE-SIGNED authorisation.

Same Merkle gate as T4, but the member's signature is checked with
OP_CHECKSIGFROMSTACK over the fixed message
    msg = SHA256("Arca/unroll" || H),   H = the node's children hash,
so it can be made once in advance and handed to anyone. The holder of that
signature (and the public key + Merkle path, no private key) can broadcast the
unroll and pay the fee with its own input."""
from arklib import *
from t4_membership_gate import merkle_levels, merkle_path, gate_witness

CHILD = 1_0000_0000
RESERVE = 1000
UTAG = b"Arca/unroll"


def presigned_gate_leaf(root, depth, children):
    s = [OP_DUP, OP_TOALTSTACK, OP_SHA256]
    for _ in range(depth):
        s += [OP_SWAP, OP_IF, OP_SWAP, OP_ENDIF, OP_CAT, OP_SHA256]
    s += [root, OP_EQUALVERIFY]                                   # [sig]            alt: key
    s += unroll_compact_body(children, tail=False)                # [sig, Hc]
    s += [OP_DUP, children_hash(children), OP_EQUALVERIFY]        # the covenant itself
    s += [UTAG, OP_SWAP, OP_CAT, OP_SHA256]                       # [sig, msg]
    s += [OP_FROMALTSTACK, OP_CHECKSIGFROMSTACK]
    return CScript(s)


def unroll_auth_msg(children):
    return sha256(UTAG + children_hash(children))


class T13(ArkBase, BitcoinTestFramework):
    NAME = "t13"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        s_x = compute_xonly_pubkey(generate_privkey())[0]
        expiry = node.getblockcount() + 5000
        r = 4
        total = r * CHILD + RESERVE

        def kidset():
            spks = [self.p2tr()[0] for _ in range(r)]
            return spks, [(self.X_ID, CHILD, spk[2:]) for spk in spks], [self.out(CHILD, spk, self.X_OUT) for spk in spks]

        spks, kids, good = kidset()
        tap0, lv0 = node_taptree(kids, expiry, s_x, "compact")
        u = self.fund(tap0.scriptPubKey, total, self.X)
        tx = self.mktx([u], good + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(lv0["unroll"]), control_block(tap0, "unroll")])
        self.send(tx, "ungated_baseline", extra={"leaf_script_bytes": len(bytes(lv0["unroll"]))})
        base = self.R["ungated_baseline"]

        for n in (4, 16, 64):
            tag = "n%d" % n
            self.log.info("=== T13 pre-signed gate, %d keys ===", n)
            secs = [generate_privkey() for _ in range(n)]
            keys = [compute_xonly_pubkey(s)[0] for s in secs]
            levels = merkle_levels(keys)
            root, depth = levels[-1][0], len(levels) - 1
            spks, kids, good = kidset()
            leaf = presigned_gate_leaf(root, depth, kids)
            tap = taproot_construct(NUMS, [("unroll", leaf), ("sweep", sweep_leaf(expiry, s_x))])
            self.rec_script(tag + "/gated_unroll_leaf", leaf, tap, "unroll")
            # a SECOND node with the same member set but different children
            spks2, kids2, good2 = kidset()
            leaf2 = presigned_gate_leaf(root, depth, kids2)
            tap2 = taproot_construct(NUMS, [("unroll", leaf2), ("sweep", sweep_leaf(expiry, s_x))])

            # ---- the member signs ONCE, offline, before the node exists, and hands the
            #      authorisation (sig, key, path) to a third party
            m = n - 3
            auth = {"sig": sign_schnorr(secs[m], unroll_auth_msg(kids)), "key": keys[m], "path": merkle_path(levels, m)}
            self.rec(tag + "/authorisation", {"msg": unroll_auth_msg(kids).hex(), "sig": auth["sig"].hex(),
                                              "signed_at_height": node.getblockcount()})
            del secs                                                  # nobody below holds a private key

            u = self.fund(tap.scriptPubKey, total, self.X)
            u2 = self.fund(tap2.scriptPubKey, total, self.X)

            def tx_for(u_, tap_, leaf_, outs, sig=None, key=None, path=None, external=True, left=RESERVE):
                w = gate_witness(sig if sig is not None else auth["sig"],
                                 path if path is not None else auth["path"], key or auth["key"])
                w += [bytes(leaf_), control_block(tap_, "unroll")]
                if external:
                    t = self.with_fee_input([u_], outs, leftover_out=self.out(left, self.wallet_spk(), self.X_OUT))
                    self.setwit(t, 0, w)
                    return self.wallet_sign(t)
                t = self.mktx([u_], list(outs) + [self.fee(RESERVE, self.X_OUT)])
                self.setwit(t, 0, w)
                return t

            # the authorisation for node 1 does not open node 2 (different children hash)
            self.reject(tx_for(u2, tap2, leaf2, good2), tag + "/neg_authorisation_used_on_a_different_node")
            # nor does it let the holder change node 1's children
            bad = [self.out(CHILD - 1, spks[0], self.X_OUT)] + good[1:]
            self.reject(tx_for(u, tap, leaf, bad, left=RESERVE + 1), tag + "/neg_children_altered")
            # a non-member's signature over the right message
            osec = generate_privkey()
            self.reject(tx_for(u, tap, leaf, good, sig=sign_schnorr(osec, unroll_auth_msg(kids)),
                               key=compute_xonly_pubkey(osec)[0]), tag + "/neg_non_member")
            self.reject(tx_for(u, tap, leaf, good, sig=b""), tag + "/neg_empty_signature")
            self.reject(tx_for(u, tap, leaf, good, path=merkle_path(levels, 0)), tag + "/neg_wrong_path")

            # ---- third party broadcasts with ITS OWN fee input
            t = tx_for(u, tap, leaf, good, external=True)
            wit = t.wit.vtxinwit[0].scriptWitness.stack
            self.send(t, tag + "/gated_unroll_third_party_external_fee", extra={
                "leaf_script_bytes": len(bytes(leaf)), "merkle_depth": depth,
                "max_witness_item_bytes_excl_script_cb": max(len(x) for x in wit[:-2]),
                "added_script_bytes": len(bytes(leaf)) - len(bytes(lv0["unroll"])),
                "added_witness_bytes": wit_bytes(wit) - base["witness_input0_bytes"]})
            # same authorisation on a second instance of node 1, reserve-fee shape, for the size comparison
            u3 = self.fund(tap.scriptPubKey, total, self.X)
            self.send(tx_for(u3, tap, leaf, good, external=False), tag + "/gated_unroll_reserve_fee")
            d = self.R[tag + "/gated_unroll_reserve_fee"]
            d["added_vsize"] = d["vsize"] - base["vsize"]
            d["sigops_budget"] = {"witness_bytes": d["witness_input0_bytes"], "budget": 50 + d["witness_input0_bytes"],
                                  "used": 50}
            self.rec(tag + "/gated_unroll_reserve_fee", d)
            self.log.info("  n=%d: +%d vB over ungated", n, d["added_vsize"])


if __name__ == "__main__":
    T13().main()
