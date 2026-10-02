#!/usr/bin/env python3
"""T6: rebindable signature (ANYPREVOUT emulation) with OP_CHECKSIGFROMSTACK.

The leaf assembles a message from OUTPUT fields only -- asset, value and
scriptPubKey of output 0, plus nLockTime -- hashes it, and checks A's BIP340
signature over that hash. Nothing about the input (outpoint, amount, script)
is in the message, so one signature spends every output carrying this leaf."""
from arklib import *
import struct

VALUE = 1_0000_0000
FEE = 400


def rebind_leaf(a_x, with_locktime=True, stream=False):
    """Witness: [sig]. Message = SHA256(record(output 0) [|| locktime_le4]),
    record = the injective output record of arklib.record_ops."""
    s = record_ops(0)
    if stream:
        # same message, built with the streaming SHA256 opcodes
        s += [OP_SHA256INITIALIZE]
        if with_locktime:
            s += [OP_INSPECTLOCKTIME, OP_SHA256FINALIZE]
        else:
            s += [b"", OP_SHA256FINALIZE]
    else:
        if with_locktime:
            s += [OP_INSPECTLOCKTIME, OP_CAT]
        s += [OP_SHA256]
    s += [a_x, OP_CHECKSIGFROMSTACK]
    return CScript(s)


def rebind_msg(asset_id, value, out_spk, locktime=None):
    blob = record(asset_id, value, out_spk)
    if locktime is not None:
        blob += struct.pack("<I", locktime)
    return sha256(blob)


class T6(ArkBase, BitcoinTestFramework):
    NAME = "t6"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        node = self.node
        a_sec = generate_privkey()
        a_x = compute_xonly_pubkey(a_sec)[0]

        for variant, kw in (("cat", {}), ("stream", {"stream": True}), ("cat_nolocktime", {"with_locktime": False})):
            self.log.info("=== T6 rebindable signature, %s variant ===", variant)
            leaf = rebind_leaf(a_x, **kw)
            plain = CScript([a_x, OP_CHECKSIG])             # the contrast: an ordinary signature
            tap = taproot_construct(NUMS, [("rebind", leaf), ("plain", plain)])
            self.rec_script(variant + "/rebind_leaf", leaf, tap, "rebind")
            dest = self.p2tr()[0]                           # the output the signature commits to
            out_value = VALUE - FEE
            locktime = 0
            use_lt = kw.get("with_locktime", True)
            msg = rebind_msg(self.X_ID, out_value, dest, locktime if use_lt else None)
            sig = sign_schnorr(a_sec, msg)                  # signed ONCE, before any utxo exists
            self.rec(variant + "/signature", {"msg": msg.hex(), "sig": sig.hex(), "sig_bytes": len(sig)})

            # three different outpoints carrying the same script (third one a different amount)
            u1 = self.fund(tap.scriptPubKey, VALUE, self.X)
            u2 = self.fund(tap.scriptPubKey, VALUE, self.X)
            u3 = self.fund(tap.scriptPubKey, VALUE + 5000, self.X)
            assert (u1.txid, u1.vout) != (u2.txid, u2.vout)

            def spend(u, s=sig, value=out_value, spk=dest, lt=0, extra=()):
                outs = [self.out(value, spk, self.X_OUT)] + list(extra)
                rest = u.amount - sum(o.nValue.getAmount() for o in outs)
                tx = self.mktx([u], outs + [self.fee(rest, self.X_OUT)], lt)
                self.setwit(tx, 0, [s, bytes(leaf), control_block(tap, "rebind")])
                return tx

            # negatives against u1
            self.reject(spend(u1, value=out_value - 1), variant + "/neg_output0_value_changed")
            self.reject(spend(u1, spk=self.p2tr()[0]), variant + "/neg_output0_script_changed")
            self.reject(spend(u1, s=sign_schnorr(generate_privkey(), msg)), variant + "/neg_sig_by_other_key")
            if use_lt:
                self.reject(spend(u1, lt=node.getblockcount() - 1), variant + "/neg_locktime_changed")
            else:
                self.probe(spend(u1, lt=node.getblockcount() - 1), variant + "/probe_locktime_free_when_not_signed")

            t1 = self.send(spend(u1), variant + "/spend_outpoint_1")
            t2 = self.send(spend(u2), variant + "/spend_outpoint_2_SAME_signature")
            w1 = node.getrawtransaction(t1, True)["vin"][0]["txinwitness"][0]
            w2 = node.getrawtransaction(t2, True)["vin"][0]["txinwitness"][0]
            assert w1 == w2 == sig.hex()
            # and a utxo of a DIFFERENT amount: the surplus is unconstrained
            t3 = self.send(spend(u3, extra=[self.out(5000, self.wallet_spk(), self.X_OUT)]),
                           variant + "/spend_outpoint_3_larger_amount_same_signature")
            self.rec(variant + "/proof", {
                "same_signature_in_all_three": node.getrawtransaction(t3, True)["vin"][0]["txinwitness"][0] == w1,
                "outpoints": ["%s:%d" % (u.txid, u.vout) for u in (u1, u2, u3)],
                "spending_txids": [t1, t2, t3]})

            if variant == "cat":
                # contrast: an ordinary OP_CHECKSIG signature made for one outpoint
                # does NOT verify on another outpoint with the same script
                p1 = self.fund(tap.scriptPubKey, VALUE, self.X)
                p2 = self.fund(tap.scriptPubKey, VALUE, self.X)
                outs = [self.out(out_value, dest, self.X_OUT), self.fee(FEE, self.X_OUT)]
                txa = self.mktx([p1], outs)
                psig = self.sign(a_sec, txa, 0, plain)
                self.setwit(txa, 0, [psig, bytes(plain), control_block(tap, "plain")])
                txb = self.mktx([p2], outs)
                self.setwit(txb, 0, [psig, bytes(plain), control_block(tap, "plain")])
                self.reject(txb, "contrast/neg_ordinary_checksig_sig_replayed_on_other_outpoint")
                self.send(txa, "contrast/ordinary_checksig_spend")


if __name__ == "__main__":
    T6().main()
