#!/usr/bin/env python3
"""T0: policy / opcode probes that the constructions depend on. Each probe
records what the node says; none of them is a covenant test in itself."""
from arklib import *
import os as _os

V = 1_0000_0000


class T0(ArkBase, BitcoinTestFramework):
    NAME = "t0"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        self.rec("mempoolinfo", {k: str(v) for k, v in node.getmempoolinfo().items()
                                 if k in ("mempoolminfee", "minrelaytxfee")})

        # ---- 1. witness stack item size: 80 vs 81 bytes -----------------
        leaf = CScript([OP_DROP, OP_1])
        tap = taproot_construct(NUMS, [("d", leaf)])
        for n in (80, 81):
            u = self.fund(tap.scriptPubKey, V, self.X)
            tx = self.mktx([u], [self.out(V - 400, self.wallet_spk(), self.X_OUT), self.fee(400, self.X_OUT)])
            self.setwit(tx, 0, [_os.urandom(n), bytes(leaf), control_block(tap, "d")])
            if n == 80:
                self.send(tx, "stackitem/80_byte_item")
            else:
                self.probe(tx, "stackitem/81_byte_item")
                self.mine_raw(tx, "stackitem/81_byte_item_mined_directly")
        # a 400-byte leaf SCRIPT is fine (the limit is on stack items, not the script)
        big = CScript([_os.urandom(75), OP_DROP] * 5 + [OP_1])
        tapb = taproot_construct(NUMS, [("b", big)])
        u = self.fund(tapb.scriptPubKey, V, self.X)
        tx = self.mktx([u], [self.out(V - 400, self.wallet_spk(), self.X_OUT), self.fee(400, self.X_OUT)])
        self.setwit(tx, 0, [bytes(big), control_block(tapb, "b")])
        self.send(tx, "stackitem/%d_byte_leaf_script_ok" % len(bytes(big)))

        # ---- 2. zero-value, 1-atom and fee-less outputs ------------------
        def simple(outs, label, asset_in=None):
            w = self.wallet_utxo(10_000, asset_in or self.X)
            tx = self.wallet_sign(self.mktx([w], outs))
            return self.probe(tx, label)

        spk = self.wallet_spk()
        simple([self.out(0, self.p2tr()[0], self.X_OUT), self.out(9_600, spk, self.X_OUT),
                self.fee(400, self.X_OUT)], "outputs/zero_value_spendable_output")
        simple([self.out(0, bytes([0x6a]), self.X_OUT), self.out(9_600, spk, self.X_OUT),
                self.fee(400, self.X_OUT)], "outputs/zero_value_op_return_output")
        simple([self.out(1, self.p2tr()[0], self.X_OUT), self.out(9_599, spk, self.X_OUT),
                self.fee(400, self.X_OUT)], "outputs/one_atom_of_X_to_p2tr")
        simple([self.out(1, self.p2tr()[0], self.POL_OUT), self.out(9_599, spk, self.POL_OUT),
                self.fee(400, self.POL_OUT)], "outputs/one_atom_of_policy_asset_to_p2tr", self.POL)
        simple([self.out(10_000, spk, self.X_OUT)], "outputs/no_fee_output")
        simple([self.out(9_900, spk, self.X_OUT), self.fee(100, self.X_OUT)], "outputs/fee_below_1_atom_per_vB")
        simple([self.out(9_600, spk, self.X_OUT), self.fee(200, self.X_OUT), self.fee(200, self.X_OUT)],
               "outputs/two_fee_outputs_same_asset")

        # ---- 2b. dust threshold for an issued asset (binary search) ------
        def min_non_dust(dest_spk, asset, asset_out, fee_out):
            w = self.wallet_utxo(100_000, asset)
            lo, hi = 0, 5000                     # lo is dust, hi is not
            while hi - lo > 1:
                mid = (lo + hi) // 2
                outs = [self.out(mid, dest_spk, asset_out), self.out(100_000 - mid - 500, spk, asset_out), fee_out]
                ok = self.accept(self.wallet_sign(self.mktx([w], outs)))
                if ok["allowed"]:
                    hi = mid
                else:
                    assert ok["reject-reason"] == "dust", ok
                    lo = mid
            return hi
        dust = {"X_to_p2tr": min_non_dust(self.p2tr()[0], self.X, self.X_OUT, self.fee(500, self.X_OUT)),
                "X_to_p2wpkh": min_non_dust(self.wallet_spk(), self.X, self.X_OUT, self.fee(500, self.X_OUT)),
                "policy_to_p2tr": min_non_dust(self.p2tr()[0], self.POL, self.POL_OUT, self.fee(500, self.POL_OUT))}
        self.rec("dust/min_non_dust_atoms_rate_1to1", dust)
        self.log.info("dust thresholds (atoms): %s", dust)
        # same question with X delisted: fee must then be paid in the policy asset
        node.setfeeexchangerates(self.rates0)
        wx, wp = self.wallet_utxo(10_000, self.X), self.wallet_utxo(10_000, self.POL)
        res = {}
        for amt in (1, 100, dust["X_to_p2tr"]):
            tx = self.wallet_sign(self.mktx([wx, wp], [self.out(amt, self.p2tr()[0], self.X_OUT),
                                                        self.out(10_000 - amt, spk, self.X_OUT),
                                                        self.out(9_000, spk, self.POL_OUT), self.fee(1_000, self.POL_OUT)]))
            r = self.accept(tx)
            res[str(amt)] = {"allowed": r["allowed"], "reject-reason": r.get("reject-reason")}
        self.rec("dust/X_delisted_outputs_of_X", res)
        self.log.info("dust with X delisted: %s", res)
        self.whitelist(self.X)

        # ---- 3. what introspection returns -------------------------------
        # explicit value: 8-byte LE + prefix 0x01; fee output: SHA256("") + version -1;
        # P2WPKH: 20-byte program + EMPTY version (script number 0).
        dest = self.wallet_spk()
        insp = CScript([
            0, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(V - 400), OP_EQUALVERIFY,
            0, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0, OP_EQUALVERIFY, dest[2:], OP_EQUALVERIFY,
            1, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1NEGATE, OP_EQUALVERIFY, sha256(b""), OP_EQUALVERIFY,
            1, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(400), OP_EQUALVERIFY,
            1, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, self.X_ID, OP_EQUALVERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY, le8(V), OP_EQUAL])
        tapi = taproot_construct(NUMS, [("i", insp)])
        self.rec_script("introspection/script", insp, tapi, "i")
        u = self.fund(tapi.scriptPubKey, V, self.X)
        tx = self.mktx([u], [self.out(V - 400, dest, self.X_OUT), self.fee(400, self.X_OUT)])
        self.setwit(tx, 0, [bytes(insp), control_block(tapi, "i")])
        self.send(tx, "introspection/explicit_value_fee_output_p2wpkh")

        # ---- 4. OP_CAT result limit: 520 ok, 521 fails -------------------
        for n in (520, 521):
            parts = [_os.urandom(75)] * (n // 75) + ([_os.urandom(n % 75)] if n % 75 else [])
            sc = [parts[0]]
            for p_ in parts[1:]:
                sc += [p_, OP_CAT]
            sc += [OP_SIZE, n, OP_EQUALVERIFY, OP_DROP, OP_1]
            leafc = CScript(sc)
            tapc = taproot_construct(NUMS, [("c", leafc)])
            u = self.fund(tapc.scriptPubKey, V, self.X)
            tx = self.mktx([u], [self.out(V - 600, self.wallet_spk(), self.X_OUT), self.fee(600, self.X_OUT)])
            self.setwit(tx, 0, [bytes(leafc), control_block(tapc, "c")])
            if n == 520:
                self.send(tx, "cat/520_byte_result")
            else:
                self.reject(tx, "cat/521_byte_result")


if __name__ == "__main__":
    T0().main()
