#!/usr/bin/env python3
"""T17: the gate as T13 built it, with malformed keys forced into blocks; then
the hardened gate (32-byte key, prefixed member tree, operator padding) with a
timed authorisation  msg = SHA256("Arca/unroll" || H || t),  t from the witness,
enforced with OP_CHECKLOCKTIMEVERIFY (median time)."""
from arklib3 import *
import os as _os
from t4_membership_gate import merkle_levels, merkle_path, gate_witness
from t13_presigned_gate import presigned_gate_leaf, unroll_auth_msg

CHILD = 1_0000_0000
RESERVE = 1000
R4 = 4


class T17(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t17"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.op_sec = generate_privkey()
        self.op_x = compute_xonly_pubkey(self.op_sec)[0]
        self.expiry = self.node.getblockcount() + 5000
        self.part_today()
        self.part_hardened()
        self.part_counts()

    def kidset(self):
        spks = [self.p2tr()[0] for _ in range(R4)]
        return [(self.X_ID, CHILD, spk[2:]) for spk in spks], [self.out(CHILD, spk, self.X_OUT) for spk in spks]

    def node_for(self, leaf):
        tap = taproot_construct(NUMS, [("unroll", leaf), ("sweep", sweep_leaf(self.expiry, self.op_x))])
        u = self.fund(tap.scriptPubKey, R4 * CHILD + RESERVE, self.X)
        return tap, u

    def gtx(self, u, tap, leaf, outs, wit_below, locktime=0, seq=None, external=False):
        s = seq if seq is not None else (0xfffffffe if locktime else 0xffffffff)
        w = list(wit_below) + [bytes(leaf), control_block(tap, "unroll")]
        if external:
            t = self.with_fee_input([(u, s)], outs, leftover_out=self.out(RESERVE, self.wallet_spk(), self.X_OUT),
                                    locktime=locktime)
            self.setwit(t, 0, w)
            return self.wallet_sign(t)
        t = self.mktx([(u, s)], list(outs) + [self.fee(RESERVE, self.X_OUT)], locktime)
        self.setwit(t, 0, w)
        return t

    # ------------------------------------------------------------------
    def part_today(self):
        """The T13 gate, unchanged, whose member tree contains values that are
        not 32-byte keys (a builder that let a 33-byte compressed key in, or a
        64-byte value). What does consensus do?"""
        self.log.info("=== T17 (1): the T13 gate with malformed member keys ===")
        k0, k1 = (compute_xonly_pubkey(generate_privkey())[0] for _ in range(2))
        bad33 = b"\x02" + k0                       # an SEC compressed key: 33 bytes
        bad64 = _os.urandom(64)
        empty = b""
        keys = [k0, k1, bad33, bad64]
        levels = merkle_levels(keys)
        root, depth = levels[-1][0], 2
        kids, good = self.kidset()
        leaf = presigned_gate_leaf(root, depth, kids)
        self.rec_script("today/t13_gate_leaf", leaf)
        cases = [("key33_sig_random64", 2, _os.urandom(64)), ("key33_sig_one_byte", 2, b"\x01"),
                 ("key64_sig_random64", 3, _os.urandom(64)), ("key64_sig_one_byte", 3, b"\x01")]
        for name, idx, sig in cases:
            tap, u = self.node_for(leaf)
            tx = self.gtx(u, tap, leaf, good, gate_witness(sig, merkle_path(levels, idx), keys[idx]))
            self.mine_raw(tx, "today/MINED_" + name)
        # an empty signature with the malformed key: CSFS pushes false
        tap, u = self.node_for(leaf)
        # (the mempool refuses the upgradable key type first)
        self.reject(self.gtx(u, tap, leaf, good, gate_witness(b"", merkle_path(levels, 2), bad33)),
                    "today/neg_key33_empty_sig",
                    block="Script evaluated without error but finished with a false/empty top stack element")
        # an empty KEY in the member tree: CSFS fails with a pubkey-type error
        keysE = [k0, k1, empty, bad64]
        levelsE = merkle_levels(keysE)
        leafE = presigned_gate_leaf(levelsE[-1][0], 2, kids)
        tap, u = self.node_for(leafE)
        self.reject(self.gtx(u, tap, leafE, good, gate_witness(_os.urandom(64), merkle_path(levelsE, 2), empty)),
                    "today/neg_key_empty_random_sig")
        self.leafE_levels = (keys, kids, good)

    # ------------------------------------------------------------------
    def part_hardened(self):
        """Hardened timed gate on a member tree that contains the same malformed
        values (as the builder mistake), plus the time negatives."""
        self.log.info("=== T17 (2): the hardened gate ===")
        node = self.node
        secs = [generate_privkey() for _ in range(2)]
        k1, k2 = (compute_xonly_pubkey(s)[0] for s in secs)
        bad33, bad64, bad31 = b"\x02" + k1, _os.urandom(64), _os.urandom(31)
        members = [self.op_x, k1, k2, bad33, bad64, bad31]          # 6 -> padded to 8 with op
        levels, padded = hmerkle(members, self.op_x)
        root, depth = levels[-1][0], len(levels) - 1
        kids, good = self.kidset()
        leaf = hgate_unroll(root, depth, kids, timed=True)
        self.rec_script("hard/gate_leaf_6_members_depth3", leaf)
        t = self.mtp() + 6 * 3600
        auth = sign_schnorr(secs[0], unroll_auth3(kids, t))
        self.rec("hard/authorisation", {"t": t, "t_bytes": sn(t).hex(), "msg": unroll_auth3(kids, t).hex(),
                                        "mtp_when_signed": self.mtp()})
        W = lambda sig, idx, key, tt=t: hgate_witness(sig, mpath(levels, idx), key, tt)
        tap, u = self.node_for(leaf)
        # ---- before t: refused both as a non-final tx and, with a final lock time, by CLTV
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=t), "hard/neg_unroll_before_t_nonfinal")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=self.mtp() - 1),
                    "hard/neg_unroll_before_t_final_locktime_below_t")
        self.mtp_past(t)
        self.rec("hard/mtp_now_past_t", {"t": t, "mtp": self.mtp()})
        # ---- every case below is a FINAL transaction: the script is what refuses it
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=t - 1), "hard/neg_unroll_locktime_below_t")
        # malformed keys: in the tree, but refused by the size check
        for name, idx, key in [("key33", 3, bad33), ("key64", 4, bad64), ("key31", 5, bad31)]:
            for sname, sig in [("random64", _os.urandom(64)), ("one_byte", b"\x01")]:
                self.reject(self.gtx(u, tap, leaf, good, W(sig, idx, key), locktime=t),
                            "hard/neg_%s_in_tree_sig_%s" % (name, sname))
        # an inner node's 65-byte preimage (0x01||l||r) as a key, with the shorter path
        inner_pre = b"\x01" + levels[0][0] + levels[0][1]
        pth = mpath(levels, 0)[1:]
        wit = [_os.urandom(64), sn(t)]
        for sib, is_left in reversed(pth):
            wit += [sib, b"\x01" if is_left else b""]
        self.reject(self.gtx(u, tap, leaf, good, wit + [inner_pre], locktime=t), "hard/neg_inner_node_preimage_as_key")
        # the padding leaf (index 6, the operator's key) claimed with a stranger's key and signature
        st = generate_privkey()
        stx = compute_xonly_pubkey(st)[0]
        self.reject(self.gtx(u, tap, leaf, good, W(sign_schnorr(st, unroll_auth3(kids, t)), 6, stx), locktime=t),
                    "hard/neg_padding_leaf_with_strangers_key")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=0), "hard/neg_unroll_no_locktime")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=t, seq=0xffffffff),
                    "hard/neg_unroll_final_sequence")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=node.getblockcount()),
                    "hard/neg_unroll_height_locktime")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1, tt=t - 3600), locktime=t),
                    "hard/neg_t_altered_earlier")
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1, tt=t + 1), locktime=t + 1),
                    "hard/neg_t_altered_later")
        # the mempool refuses the non-minimal push first; in a block the
        # authorisation, signed over the minimal bytes, fails
        self.reject(self.gtx(u, tap, leaf, good, W(auth, 1, k1, tt=t)[:1] + [sn(t) + b"\x00"] + W(auth, 1, k1)[2:],
                             locktime=t), "hard/neg_t_nonminimal_encoding", block="Invalid Schnorr signature")
        self.reject(self.gtx(u, tap, leaf, good, W(b"", 1, k1), locktime=t), "hard/neg_empty_signature")
        # ---- after t: the third party broadcasts with its own fee input
        self.send(self.gtx(u, tap, leaf, good, W(auth, 1, k1), locktime=t, external=True),
                  "hard/third_party_unroll_after_t_external_fee")
        # the operator through a padding position, reserve fee, untimed t = 0
        tap2, u2 = self.node_for(leaf)
        opauth = sign_schnorr(self.op_sec, unroll_auth3(kids, 0))
        self.send(self.gtx(u2, tap2, leaf, good, hgate_witness(opauth, mpath(levels, 7), self.op_x, 0), locktime=0,
                           seq=0xfffffffe), "hard/operator_via_padding_leaf_t0")

    # ------------------------------------------------------------------
    def part_counts(self):
        """Sizes for 3, 4, 5, 6, 16 and 64 members, timed and untimed, reserve fee
        (T13: 161/173/185 bytes, 511/531/551 vB for 4/16/64)."""
        self.log.info("=== T17 (3): member counts ===")
        kids0, good0 = self.kidset()
        tap0, lv0 = node_taptree(kids0, self.expiry, self.op_x, "compact")
        u = self.fund(tap0.scriptPubKey, R4 * CHILD + RESERVE, self.X)
        tx = self.mktx([u], good0 + [self.fee(RESERVE, self.X_OUT)])
        self.setwit(tx, 0, [bytes(lv0["unroll"]), control_block(tap0, "unroll")])
        self.send(tx, "count/ungated_baseline")
        base = self.R["count/ungated_baseline"]["vsize"]
        for n in (3, 4, 5, 6, 16, 64):
            secs = [generate_privkey() for _ in range(n - 1)]
            keys = [self.op_x] + [compute_xonly_pubkey(s)[0] for s in secs]
            levels, padded = hmerkle(keys, self.op_x)
            depth = len(levels) - 1
            for timed in (False, True):
                kids, good = self.kidset()
                leaf = hgate_unroll(levels[-1][0], depth, kids, timed=timed)
                tag = "count/n%d_%s" % (n, "timed" if timed else "untimed")
                self.rec_script(tag + "_leaf", leaf)
                t = (self.mtp() - 60) if timed else None
                sig = sign_schnorr(secs[-1], unroll_auth3(kids, t))
                tap, u = self.node_for(leaf)
                wit = hgate_witness(sig, mpath(levels, n - 1), keys[n - 1], t)
                self.send(self.gtx(u, tap, leaf, good, wit, locktime=t or 0, seq=0xfffffffe if timed else None),
                          tag + "_reserve_fee", extra={"members": n, "padded_to": len(padded), "depth": depth,
                                                       "leaf_bytes": len(bytes(leaf))})
                d = self.R[tag + "_reserve_fee"]
                d["added_vsize_over_ungated"] = d["vsize"] - base
                self.rec(tag + "_reserve_fee", d)
                if n in (3, 5, 6) and timed:
                    # the operator's padding leaf really is the operator: refused for a stranger
                    st = generate_privkey()
                    stx = compute_xonly_pubkey(st)[0]
                    u2 = self.fund(tap.scriptPubKey, R4 * CHILD + RESERVE, self.X)
                    self.reject(self.gtx(u2, tap, leaf, good,
                                         hgate_witness(sign_schnorr(st, unroll_auth3(kids, t)), mpath(levels, n),
                                                       stx, t), locktime=t),
                                tag + "_neg_padding_leaf_strangers_key")
                    opsig = sign_schnorr(self.op_sec, unroll_auth3(kids, t))
                    self.send(self.gtx(u2, tap, leaf, good, hgate_witness(opsig, mpath(levels, n), self.op_x, t),
                                       locktime=t), tag + "_operator_via_padding_leaf")
                if n == 16 and timed:
                    u3 = self.fund(tap.scriptPubKey, R4 * CHILD + RESERVE, self.X)
                    self.send(self.gtx(u3, tap, leaf, good, wit, locktime=t, external=True),
                              tag + "_third_party_external_fee")


if __name__ == "__main__":
    T17().main()
