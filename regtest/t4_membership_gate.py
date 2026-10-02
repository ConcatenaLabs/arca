#!/usr/bin/env python3
"""T4: membership-gated unroll. The UNROLL leaf additionally requires a BIP340
signature (plain OP_CHECKSIG over the spending tx) from ANY ONE key of the set
under the node, proven by a Merkle path to a root baked into the script.

  leaf hash  = SHA256(xonly_key)              (32-byte preimage)
  inner node = SHA256(left || right)          (64-byte preimage)

Witness (bottom -> top): sig, [sibling_d, dir_d, ..., sibling_1, dir_1], key
dir = 0x01 if the running hash is the LEFT operand at that level, empty if RIGHT.
"""
from arklib import *

CHILD = 1_0000_0000
RESERVE = 1000


def merkle_levels(keys):
    lvl = [sha256(k) for k in keys]
    levels = [lvl]
    while len(lvl) > 1:
        lvl = [sha256(lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
        levels.append(lvl)
    return levels


def merkle_path(levels, idx):
    """[(sibling, running_is_left)] from the leaf level up."""
    path = []
    for lvl in levels[:-1]:
        sib = idx ^ 1
        path.append((lvl[sib], idx % 2 == 0))
        idx //= 2
    return path


def gate_prefix(root, depth):
    s = [OP_DUP, OP_TOALTSTACK, OP_SHA256]
    for _ in range(depth):
        s += [OP_SWAP, OP_IF, OP_SWAP, OP_ENDIF, OP_CAT, OP_SHA256]
    s += [root, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_CHECKSIGVERIFY]
    return s


def gate_witness(sig, path, key):
    w = [sig]
    for sib, is_left in reversed(path):
        w += [sib, b"\x01" if is_left else b""]
    return w + [key]


class T4(ArkBase, BitcoinTestFramework):
    NAME = "t4"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        s_x = compute_xonly_pubkey(generate_privkey())[0]
        expiry = node.getblockcount() + 5000
        r = 4
        for form in ("compact", "plain"):
            # ungated baseline, same children shape
            spks = [self.p2tr()[0] for _ in range(r)]
            kids = [(self.X_ID, CHILD, spk[2:]) for spk in spks]
            good = [self.out(CHILD, spk, self.X_OUT) for spk in spks]
            total = r * CHILD + RESERVE
            body = {"compact": unroll_compact_body, "plain": unroll_body}[form](kids)
            tap0, lv0 = node_taptree(kids, expiry, s_x, form)
            u = self.fund(tap0.scriptPubKey, total, self.X)
            tx = self.mktx([u], good + [self.fee(RESERVE, self.X_OUT)])
            self.setwit(tx, 0, [bytes(lv0["unroll"]), control_block(tap0, "unroll")])
            self.send(tx, "%s/ungated_baseline" % form, extra={"leaf_script_bytes": len(bytes(lv0["unroll"]))})
            base = self.R["%s/ungated_baseline" % form]

            for n in (4, 16, 64):
                tag = "%s/n%d" % (form, n)
                self.log.info("=== T4 membership gate, %s unroll, subtree of %d keys ===", form, n)
                secs = [generate_privkey() for _ in range(n)]
                keys = [compute_xonly_pubkey(s)[0] for s in secs]
                levels = merkle_levels(keys)
                root, depth = levels[-1][0], len(levels) - 1
                leaf = CScript(gate_prefix(root, depth) + body)
                sweep = sweep_leaf(expiry, s_x)
                tap = taproot_construct(NUMS, [("unroll", leaf), ("sweep", sweep)])
                self.rec_script(tag + "/gated_unroll_leaf", leaf, tap, "unroll")
                u = self.fund(tap.scriptPubKey, total, self.X)

                def spend(member, sec=None, key=None, path=None, mutate=None):
                    tx = self.mktx([u], good + [self.fee(RESERVE, self.X_OUT)])
                    sig = self.sign(sec or secs[member], tx, 0, leaf)
                    p = path if path is not None else merkle_path(levels, member)
                    w = gate_witness(sig, p, key or keys[member])
                    if mutate:
                        w = mutate(w)
                    self.setwit(tx, 0, w + [bytes(leaf), control_block(tap, "unroll")])
                    return tx

                m = n - 3                      # an arbitrary member (mixed left/right path)
                # non-member with a valid signature of its own
                osec = generate_privkey()
                self.reject(spend(m, sec=osec, key=compute_xonly_pubkey(osec)[0]), tag + "/neg_non_member_key")
                # a member's key and path, signed by someone else
                self.reject(spend(m, sec=osec), tag + "/neg_member_key_wrong_sig")
                # right key, another member's path
                self.reject(spend(m, path=merkle_path(levels, 0)), tag + "/neg_wrong_path")
                # no signature at all
                self.reject(spend(m, mutate=lambda w: [b""] + w[1:]), tag + "/neg_empty_sig")
                # membership proven but a child output altered: covenant still binds
                tx = self.mktx([u], [self.out(CHILD - 1, spks[0], self.X_OUT)] + good[1:] +
                               [self.fee(RESERVE + 1, self.X_OUT)])
                sig = self.sign(secs[m], tx, 0, leaf)
                self.setwit(tx, 0, gate_witness(sig, merkle_path(levels, m), keys[m]) +
                            [bytes(leaf), control_block(tap, "unroll")])
                self.reject(tx, tag + "/neg_member_but_wrong_child_value")

                tx = spend(m)
                wit = tx.wit.vtxinwit[0].scriptWitness.stack
                self.send(tx, tag + "/gated_unroll", extra={
                    "leaf_script_bytes": len(bytes(leaf)),
                    "merkle_depth": depth,
                    "witness_items": len(wit),
                    "max_witness_item_bytes_excl_script_cb": max(len(x) for x in wit[:-2]),
                    "added_script_bytes": len(bytes(leaf)) - len(bytes(lv0["unroll"])),
                    "added_witness_bytes": wit_bytes(wit) - base["witness_input0_bytes"],
                    "added_vsize": None})
                d = self.R[tag + "/gated_unroll"]
                d["added_vsize"] = d["vsize"] - base["vsize"]
                d["added_weight"] = d["weight"] - base["weight"]
                self.rec(tag + "/gated_unroll", d)
                self.log.info("  n=%d depth=%d: +%d script bytes, +%d witness bytes, +%d vB",
                              n, depth, d["added_script_bytes"], d["added_witness_bytes"], d["added_vsize"])


if __name__ == "__main__":
    T4().main()
