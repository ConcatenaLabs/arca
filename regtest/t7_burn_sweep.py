#!/usr/bin/env python3
"""T7: burn-only sweep for issuer-minted liquidity.

After expiry the operator may spend, but ONLY into an OP_RETURN output (same
index as the input) that carries the input's full amount of the input's asset:
the units are destroyed, never recovered by the operator."""
from arklib import *

VALUE = 5_0000_0000
EXT_IN = 50_000
EXT_FEE = 1000
BURN_SPK = bytes([0x6a])                # bare OP_RETURN
BURN_SPK_SHA = sha256(BURN_SPK)


def burn_sweep_leaf(expiry, s_x):
    I = OP_PUSHCURRENTINPUTINDEX
    return CScript([
        expiry, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
        # output[i].value == input[i].value, both explicit
        I, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY,
        I, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
        # output[i].asset == input[i].asset, both explicit
        I, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY,
        I, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
        # output[i].scriptPubKey == OP_RETURN (non-witness: version -1, SHA256(spk))
        I, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1NEGATE, OP_EQUALVERIFY, BURN_SPK_SHA, OP_EQUALVERIFY,
        s_x, OP_CHECKSIG])


class T7(ArkBase, BitcoinTestFramework):
    NAME = "t7"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X", "Y"))
        self.whitelist(self.X)
        node = self.node
        s_sec = generate_privkey()
        s_x = compute_xonly_pubkey(s_sec)[0]
        expiry = node.getblockcount() + 25
        leaf = burn_sweep_leaf(expiry, s_x)
        # a stand-in unroll leaf so the output is a realistic tree node
        spk_child = self.p2tr()[0]
        unroll = CScript(unroll_body([(self.X_ID, VALUE, spk_child[2:])]))
        tap = taproot_construct(NUMS, [("unroll", unroll), ("burn", leaf)])
        self.rec_script("burn_sweep_leaf", leaf, tap, "burn")
        self.rec("params", {"expiry": expiry, "burn_spk": BURN_SPK.hex(), "sha256_burn_spk": BURN_SPK_SHA.hex()})

        u = self.fund(tap.scriptPubKey, VALUE, self.X)
        u_b = self.fund(tap.scriptPubKey, VALUE, self.X)       # for the aliasing test
        bal0 = node.getbalance()[self.X]

        def burn_tx(ins, outs0, locktime=expiry, sec=s_sec, fee_in=None):
            w = fee_in or self.wallet_utxo(EXT_IN)
            outs = list(outs0) + [self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.POL_OUT),
                                  self.fee(EXT_FEE, self.POL_OUT)]
            tx = self.mktx([(x, 0xfffffffe) for x in ins] + [(w, 0xfffffffe)], outs, locktime)
            for i in range(len(ins)):
                self.setwit(tx, i, [self.sign(sec, tx, i, leaf), bytes(leaf), control_block(tap, "burn")])
            return self.wallet_sign(tx)

        burn = self.out(VALUE, BURN_SPK, self.X_OUT)
        self.reject(burn_tx([u], [burn]), "neg_before_expiry")
        self.mine_to(expiry)
        # operator tries to keep the liquidity
        self.reject(burn_tx([u], [self.out(VALUE, self.wallet_spk(), self.X_OUT)]), "neg_sweep_to_operator_wallet")
        # burns all but one atom
        self.reject(burn_tx([u], [self.out(VALUE - 1, BURN_SPK, self.X_OUT),
                                  self.out(1, self.wallet_spk(), self.X_OUT)]), "neg_burn_short_by_one_atom")
        # burns the right NUMBER of a different (worthless) asset, keeps X
        y = self.wallet_utxo(VALUE, self.Y)
        tx = self.mktx([(u, 0xfffffffe), (y, 0xfffffffe), (self.wallet_utxo(EXT_IN), 0xfffffffe)],
                       [self.out(VALUE, BURN_SPK, self.Y_OUT), self.out(VALUE, self.wallet_spk(), self.X_OUT),
                        self.out(EXT_IN - EXT_FEE, self.wallet_spk(), self.POL_OUT), self.fee(EXT_FEE, self.POL_OUT)],
                       expiry)
        self.setwit(tx, 0, [self.sign(s_sec, tx, 0, leaf), bytes(leaf), control_block(tap, "burn")])
        self.reject(self.wallet_sign(tx), "neg_burn_other_asset_same_amount")
        # OP_RETURN at the wrong index
        self.reject(burn_tx([u], [self.out(1, self.wallet_spk(), self.X_OUT),
                                  self.out(VALUE - 1, BURN_SPK, self.X_OUT)]), "neg_burn_output_wrong_index")
        # a "burn" to a spendable-looking script (OP_RETURN + data is fine as a burn, but not what is pinned)
        self.reject(burn_tx([u], [self.out(VALUE, bytes([0x51]), self.X_OUT)]), "neg_output_is_OP_TRUE_not_OP_RETURN")
        # two covenant inputs trying to share ONE burn output
        self.reject(burn_tx([u, u_b], [burn, self.out(VALUE, self.wallet_spk(), self.X_OUT)]),
                    "neg_two_inputs_one_burn_output_aliasing")
        # not the operator
        self.reject(burn_tx([u], [burn], sec=generate_privkey()), "neg_wrong_key")

        txid = self.send(burn_tx([u], [burn]), "burn_sweep_after_expiry")
        # two inputs, two burns in one tx
        txid2 = self.send(burn_tx([u_b], [burn]), "burn_sweep_second_input")

        # ---- are the units really gone?
        dec = node.getrawtransaction(txid, True)
        o0 = dec["vout"][0]
        gone = node.gettxout(txid, 0)
        scan = node.scantxoutset("start", [{"desc": "raw(6a)"}])
        bal1 = node.getbalance()[self.X]
        self.rec("destroyed", {
            "burn_output": {"asset": o0["asset"], "value": str(o0["value"]),
                            "scriptPubKey_hex": o0["scriptPubKey"]["hex"], "type": o0["scriptPubKey"].get("type")},
            "gettxout_burn_output": gone,
            "scantxoutset_raw_6a_unspents": len(scan.get("unspents", [])),
            "wallet_X_balance_before": str(bal0), "wallet_X_balance_after": str(bal1),
            "note": "gettxout returns null: the OP_RETURN output never enters the UTXO set, so 2 x %d atoms of X left circulation" % VALUE})
        assert gone is None
        assert o0["scriptPubKey"]["hex"] == "6a" and o0["asset"] == self.X


if __name__ == "__main__":
    T7().main()
