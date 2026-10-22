#!/usr/bin/env python3
"""T23: landing-1, the leaf of a supervised asset, with the forced landing.

    collab   the leaf's collaborative path, its script pushing K || P, K = SHA256(chain_tag || salt)
    landing  <delay> CSV DROP, output 0 = P2WPKH(P) explicitly in the leaf's asset
             holding at least its value less the allowance, then A's signature

P = hash160(L), the owner's landing key. The asset Z is issued supervised, with
the pause capability. Under a pause and with the leaf's own script named in a
targeted freeze, the leaf's landing confirms (a script-path spend), and the
coin it lands is a single-owner output of Z, which the pause and then a
targeted freeze of the landing address catch; once the freeze is lifted it is
spent. Every negative case is refused by the mempool and again in a block:

- the landing before its delay;
- the landing paying another key's P2WPKH, a taproot output, another asset,
  or one atom below the leaf's value less the allowance;
- the collaborative path signed over the vtxo-1 constant (no P), and over a
  landing-1 prefix naming another landing.
"""
from arklib3 import *
import os as _os
from test_framework.key import compute_xonly_pubkey as _xonly
from test_framework.script import hash160

V = 1_0000_0000
ALLOWANCE = 2_000
FEE = 400
H = 3600
EXIT_S = 4 * H
EXIT = rel_time(EXIT_S)


class T23(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t23"
    EXTRA = ["-supervisedassetsheight=1"]

    def set_test_params(self):
        self.ark_params()

    # ---- supervision, as T8 ----------------------------------------------
    def funding_outpoint(self, minimum=Decimal("1")):
        for u in self.node.listunspent():
            if u["asset"] == self.POL and u["amount"] > minimum and u["spendable"]:
                return u
        raise AssertionError("no funding utxo")

    def record_tx(self, kind, asset, target):
        node = self.node
        utxo = self.funding_outpoint()
        sighash = node.getsupervisionrecordhash(kind, asset, target, None, utxo["txid"], utxo["vout"])["sighash"]
        built = node.buildsupervisionrecord(kind, asset, target, None,
                                            sign_schnorr(self.op_sec, bytes.fromhex(sighash)).hex())
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{node.getnewaddress(): utxo["amount"] - Decimal("0.001")}, {"fee": Decimal("0.001")}])
        raw = node.addsupervisionrecordoutput(raw, built["script"], asset)
        signed = node.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed
        return node.sendrawtransaction(signed["hex"]), built["targethash"]

    def unfreeze(self, txid, asset, targethash):
        node = self.node
        raw = node.getrawtransaction(txid, True)
        vout = [o["n"] for o in raw["vout"] if o["scriptPubKey"]["hex"]
                and node.decodesupervisionscript(o["scriptPubKey"]["hex"])["type"] == "record"][0]
        sighash = node.getsupervisionunfreezehash(txid, vout, asset, targethash)
        sig = sign_schnorr(self.op_sec, bytes.fromhex(sighash)).hex()
        utxo = self.funding_outpoint()
        raw = node.createrawtransaction(
            [{"txid": txid, "vout": vout}, {"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{node.getnewaddress(): utxo["amount"] - Decimal("0.001")}, {"fee": Decimal("0.001")}])
        signed = node.signrawtransactionwithwallet(raw)["hex"]
        for i, vin in enumerate(node.decoderawtransaction(signed)["vin"]):
            if vin["txid"] == txid and vin["vout"] == vout:
                signed = node.setsupervisionunfreezesig(signed, i, sig)
        return node.sendrawtransaction(signed)

    def addr(self, spk):
        spk = bytes(spk)
        return program_to_witness(0 if spk[0] == 0 else spk[0] - 0x50, spk[2:])

    def frozen(self, spk):
        s = self.node.isassetfrozen(self.Z, self.addr(spk))
        return {k: s[k] for k in ("frozen", "freezable", "paused")}

    # ---- the test --------------------------------------------------------
    def run_test(self):
        self.boot(issue=("X",))
        node = self.node
        self.clock_start()
        self.ctag = chain_tag(self.genesis_internal())
        self.op_sec, rec_sec = generate_privkey(), generate_privkey()
        raw = node.createrawtransaction([], [{node.getnewaddress(): Decimal("0.9")}, {"fee": Decimal("0.001")}])
        funded = node.fundrawtransaction(raw)["hex"]
        issued = node.rawissueasset(funded, [{
            "asset_amount": 1000, "asset_address": node.getnewaddress(),
            "token_amount": 1, "token_address": node.getnewaddress(), "blind": False,
            "supervision": {"operationalkey": _xonly(self.op_sec)[0].hex(),
                            "recoverykey": _xonly(rec_sec)[0].hex(), "pause": True}}])[0]
        signed = node.signrawtransactionwithwallet(issued["hex"])
        assert signed["complete"]
        node.sendrawtransaction(signed["hex"])
        self.generate(node, 1)
        self.Z = issued["asset"]
        self.Z_OUT, self.Z_ID = self.asset_out(self.Z), bytes.fromhex(self.Z)[::-1]
        self.whitelist(self.Z, self.X)

        a_sec, s_sec, l_sec = generate_privkey(), generate_privkey(), generate_privkey()
        self.a_x, self.s_x = _xonly(a_sec)[0], _xonly(s_sec)[0]
        # The landing key L is a wallet key, so the landed coin is the wallet's.
        land_spk = self.wallet_spk()
        assert land_spk[:2] == b"\x00\x14"
        P = land_spk[2:]
        self.rec("params", {"asset": self.Z, "value": V, "allowance": ALLOWANCE, "exit_delay_seconds": EXIT_S,
                            "exit_delay_sequence": EXIT, "landing_program": P.hex()})

        def landing_leaf(label):
            salt = _os.urandom(32)
            tap, lv = landing_taptree(self.a_x, self.s_x, salt, self.ctag, EXIT, P, self.Z_ID, V, ALLOWANCE)
            for k in lv:
                self.rec_script("%s/%s" % (label, k), lv[k], tap, k)
            return tap, lv, salt

        def landing_tx(u, tap, lv, outs, seq=EXIT, ins=()):
            tx = self.mktx([(u, seq)] + list(ins), outs)
            self.setwit(tx, 0, [self.sign(a_sec, tx, 0, lv["landing"]), bytes(lv["landing"]), control_block(tap, "landing")])
            return tx

        def collab_tx(u, tap, lv, const, outs3):
            digest = rebind_msg3(self.ctag, b"\x00" * 32, self.Z_ID, V, outs3, const=const)
            outs = [self.out(v, s, b"\x01" + a) for a, v, s in outs3]
            tx = self.mktx([u], outs + [self.fee(V - sum(v for _, v, _ in outs3), self.Z_OUT)])
            self.setwit(tx, 0, [sign_schnorr(s_sec, digest), sign_schnorr(a_sec, digest), bytes([len(outs3)]),
                                bytes(lv["collab"]), control_block(tap, "collab")])
            return tx

        # ---- the collaborative path: landing-1's constant only ---------------
        tap, lv, salt = landing_leaf("collab_leaf")
        u = self.fund(tap.scriptPubKey, V, self.Z)
        to = [(self.Z_ID, V - FEE, bytes(self.wallet_spk()))]
        self.reject(collab_tx(u, tap, lv, leaf_const(self.ctag, salt, fold=True), to),
                    "neg/collab signed over the vtxo-1 constant (no P)")
        other_p = hash160(bytes.fromhex(self.node.getaddressinfo(self.node.getnewaddress())["pubkey"]))
        self.reject(collab_tx(u, tap, lv, landing_prefix(self.ctag, salt, other_p), to),
                    "neg/collab signed over another landing's prefix")
        self.send(collab_tx(u, tap, lv, landing_prefix(self.ctag, salt, P), to), "collab m=1, landing-1 prefix K || P")

        # ---- the landing, before any freeze: its delay and its covenant ------
        tap, lv, _ = landing_leaf("landing_leaf")
        u = self.fund(tap.scriptPubKey, V, self.Z)
        good = [self.out(V - FEE, land_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)]
        self.reject(landing_tx(u, tap, lv, good), "neg/landing before its delay", block="bad-txns-nonfinal")
        self.wait_csv(u.txid, EXIT_S)
        other_key = self.wallet_spk()
        self.reject(landing_tx(u, tap, lv, [self.out(V - FEE, other_key, self.Z_OUT), self.fee(FEE, self.Z_OUT)]),
                    "neg/landing to another key's P2WPKH")
        self.reject(landing_tx(u, tap, lv, [self.out(V - FEE, bytes(taproot_construct(_xonly(l_sec)[0]).scriptPubKey),
                                                     self.Z_OUT), self.fee(FEE, self.Z_OUT)]),
                    "neg/landing to a taproot output")
        x_coin = self.wallet_utxo(V, self.X)
        self.reject(self.wallet_sign(landing_tx(u, tap, lv, [self.out(V, land_spk, self.X_OUT),
                                                             self.out(V - FEE, self.wallet_spk(), self.Z_OUT),
                                                             self.fee(FEE, self.Z_OUT)], ins=[x_coin])),
                    "neg/landing in another asset")
        short = V - ALLOWANCE - 1
        self.reject(landing_tx(u, tap, lv, [self.out(short, land_spk, self.Z_OUT), self.out(ALLOWANCE + 1 - FEE, self.wallet_spk(),
                                            self.Z_OUT), self.fee(FEE, self.Z_OUT)]),
                    "neg/landing one atom below value less the allowance")
        exact = landing_tx(u, tap, lv, [self.out(V - ALLOWANCE, land_spk, self.Z_OUT), self.out(ALLOWANCE - FEE, self.wallet_spk(),
                                        self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        self.send(exact, "landing at exactly value less the allowance, the rest elsewhere")

        # ---- under a pause, with the leaf's script named by a freeze ---------
        tap, lv, _ = landing_leaf("frozen_leaf")
        u = self.fund(tap.scriptPubKey, V, self.Z)
        pause_txid, _ = self.record_tx("pause", self.Z, None)
        self.generate(node, 1)
        named_txid, _ = self.record_tx("freeze", self.Z, self.addr(tap.scriptPubKey))
        self.generate(node, 1)
        self.rec("status/paused, leaf named", {"leaf_script": self.frozen(tap.scriptPubKey),
                                               "landing_P2WPKH": self.frozen(land_spk)})
        self.wait_csv(u.txid, EXIT_S)
        ltxid = self.send(landing_tx(u, tap, lv, good), "landing under a pause, the leaf's script named")
        landed = self.utxo_at(ltxid, 0)
        assert bytes(landed.spk) == bytes(land_spk)

        def spend_landed():
            tx = self.mktx([landed], [self.out(landed.amount - FEE, self.wallet_spk(), self.Z_OUT), self.fee(FEE, self.Z_OUT)])
            return self.wallet_sign(tx)

        self.reject(spend_landed(), "neg/spend of the landed coin under the pause", expect="asset-frozen")
        land_txid, land_target = self.record_tx("freeze", self.Z, self.addr(land_spk))
        self.generate(node, 1)
        self.unfreeze(pause_txid, self.Z, "00" * 32)
        self.generate(node, 2)
        self.rec("status/pause lifted, landing frozen", {"landing_P2WPKH": self.frozen(land_spk)})
        self.reject(spend_landed(), "neg/spend of the landed coin, its address frozen", expect="asset-frozen")
        self.unfreeze(land_txid, self.Z, land_target)
        self.generate(node, 2)
        self.rec("status/landing lifted", {"landing_P2WPKH": self.frozen(land_spk)})
        self.send(spend_landed(), "spend of the landed coin once the freeze is lifted")


if __name__ == "__main__":
    T23().main()
