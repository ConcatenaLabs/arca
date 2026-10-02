#!/usr/bin/env python3
"""T8: a SUPERVISED (freezable) asset inside the covenant tree.

Shows, under an asset-wide PAUSE and under targeted freezes:
  * key-path spends of single-owner outputs (P2TR key path, P2WPKH) are refused;
  * the covenant tree keeps working: script-path UNROLL and leaf EXIT confirm;
  * a leaf whose exit covenant forces the landing output to P2WPKH(A) lands in a
    script the issuer CAN freeze, and A's spend from there is refused."""
from arklib import *
from test_framework.key import ECKey, tweak_add_privkey
from test_framework.script import OP_GREATERTHANOREQUAL64

LEAF = 1_0000_0000
RESERVE = 800
EXIT_FEE = 400
DELAY = 3


def landing_leaf_taptree(a_x, s_x, delay, expiry, asset_id, landing_h160, min_value):
    """A T2 leaf whose unilateral exit is ALSO a covenant: output 0 must be
    P2WPKH(landing_h160) in `asset_id` with value >= min_value."""
    collab = CScript([a_x, OP_CHECKSIGVERIFY, s_x, OP_CHECKSIG])
    exit_ = CScript([
        delay, OP_CHECKSEQUENCEVERIFY, OP_DROP,
        0, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0, OP_EQUALVERIFY, landing_h160, OP_EQUALVERIFY,
        0, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset_id, OP_EQUALVERIFY,
        0, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, le8(min_value), OP_GREATERTHANOREQUAL64, OP_VERIFY,
        a_x, OP_CHECKSIG])
    sweep = sweep_leaf(expiry, s_x)
    tap = taproot_construct(NUMS, [("collab", collab), [("exit", exit_), ("sweep", sweep)]])
    return tap, {"collab": collab, "exit": exit_, "sweep": sweep}


class T8(ArkBase, BitcoinTestFramework):
    NAME = "t8"
    EXTRA = ["-supervisedassetsheight=1"]

    def set_test_params(self):
        self.ark_params()

    # ---- supervision helpers (ported from feature_supervised_assets.py) ----
    def funding_outpoint(self, minimum=Decimal("1")):
        for u in self.node.listunspent():
            if u["asset"] == self.POL and u["amount"] > minimum and u["spendable"]:
                return u
        raise AssertionError("no funding utxo")

    def schnorr(self, sec, sighash_hex):
        return sign_schnorr(sec, bytes.fromhex(sighash_hex)).hex()

    def record_tx(self, kind, asset, target):
        node = self.node
        utxo = self.funding_outpoint()
        sighash = node.getsupervisionrecordhash(kind, asset, target, None, utxo["txid"], utxo["vout"])["sighash"]
        built = node.buildsupervisionrecord(kind, asset, target, None, self.schnorr(self.op_sec, sighash))
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{node.getnewaddress(): utxo["amount"] - Decimal("0.001")}, {"fee": Decimal("0.001")}])
        raw = node.addsupervisionrecordoutput(raw, built["script"], asset)
        signed = node.signrawtransactionwithwallet(raw)
        assert signed["complete"], signed
        txid = node.sendrawtransaction(signed["hex"])
        return txid, built["targethash"]

    def find_record(self, txid):
        raw = self.node.getrawtransaction(txid, True)
        for out in raw["vout"]:
            if self.node.decodesupervisionscript(out["scriptPubKey"]["hex"])["type"] == "record":
                return out["n"]
        raise AssertionError("no record output")

    def unfreeze(self, txid, asset, targethash):
        node = self.node
        vout = self.find_record(txid)
        sighash = node.getsupervisionunfreezehash(txid, vout, asset, targethash)
        sig = self.schnorr(self.op_sec, sighash)
        utxo = self.funding_outpoint()
        raw = node.createrawtransaction(
            [{"txid": txid, "vout": vout}, {"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{node.getnewaddress(): utxo["amount"] - Decimal("0.001")}, {"fee": Decimal("0.001")}])
        signed = node.signrawtransactionwithwallet(raw)["hex"]
        dec = node.decoderawtransaction(signed)
        for i, vin in enumerate(dec["vin"]):
            if vin["txid"] == txid and vin["vout"] == vout:
                signed = node.setsupervisionunfreezesig(signed, i, sig)
        return node.sendrawtransaction(signed)

    def addr(self, spk):
        spk = bytes(spk)
        return program_to_witness(0 if spk[0] == 0 else spk[0] - 0x50, spk[2:])

    def frozen(self, spk):
        s = self.node.isassetfrozen(self.Z, self.addr(spk))
        return {k: s[k] for k in ("frozen", "freezable", "paused") if k in s}

    # ------------------------------------------------------------------
    def run_test(self):
        self.boot(issue=())
        node = self.node
        self.op_sec, self.rec_sec = generate_privkey(), generate_privkey()
        op_pub = compute_xonly_pubkey(self.op_sec)[0].hex()
        rec_pub = compute_xonly_pubkey(self.rec_sec)[0].hex()

        # ---- issue a supervised asset Z with the pause capability
        raw = node.createrawtransaction([], [{node.getnewaddress(): Decimal("0.9")}, {"fee": Decimal("0.001")}])
        funded = node.fundrawtransaction(raw)["hex"]
        issued = node.rawissueasset(funded, [{
            "asset_amount": 1000, "asset_address": node.getnewaddress(),
            "token_amount": 1, "token_address": node.getnewaddress(), "blind": False,
            "supervision": {"operationalkey": op_pub, "recoverykey": rec_pub, "pause": True}}])[0]
        signed = node.signrawtransactionwithwallet(issued["hex"])
        assert signed["complete"]
        node.sendrawtransaction(signed["hex"])
        self.generate(node, 1)
        self.Z = issued["asset"]
        self.Z_OUT, self.Z_ID = self.asset_out(self.Z), bytes.fromhex(self.Z)[::-1]
        entry = [a for a in node.getsupervisedassets() if a["asset"] == self.Z][0]
        self.rec("supervised_asset", {k: entry[k] for k in entry})
        self.whitelist(self.Z)

        # ---- the tree: one node, 4 leaves
        s_sec = generate_privkey()
        s_x = compute_xonly_pubkey(s_sec)[0]
        expiry = node.getblockcount() + 3000
        a = [generate_privkey() for _ in range(4)]
        ax = [compute_xonly_pubkey(k)[0] for k in a]
        land_spk = self.wallet_spk()                      # "A1's" P2WPKH: 0014<h160>
        assert land_spk[:2] == b"\x00\x14"
        l0 = leaf_taptree(ax[0], s_x, DELAY, expiry)
        l1 = landing_leaf_taptree(ax[1], s_x, DELAY, expiry, self.Z_ID, land_spk[2:], LEAF - EXIT_FEE)
        l2 = leaf_taptree(ax[2], s_x, DELAY, expiry)
        l3 = leaf_taptree(ax[3], s_x, DELAY, expiry)
        leaves = [l0, l1, l2, l3]
        self.rec_script("landing_exit_leaf", l1[1]["exit"], l1[0], "exit")
        root = build_tree(self.Z_ID, [l[0].scriptPubKey for l in leaves], LEAF, 4, RESERVE, expiry, s_x, "compact")
        u_root = self.fund(root["spk"], root["value"], self.Z)

        # ---- single-owner holdings of Z: a P2TR KEY-PATH output and a wallet P2WPKH
        k_sec = generate_privkey()
        k_tap = taproot_construct(compute_xonly_pubkey(k_sec)[0])
        u_kp = self.fund(k_tap.scriptPubKey, LEAF, self.Z)
        u_kp2 = self.fund(k_tap.scriptPubKey, LEAF, self.Z)
        w_spk = self.wallet_spk()
        u_w = self.fund(w_spk, LEAF, self.Z)

        def keypath_tx(u):
            tx = self.mktx([u], [self.out(LEAF - EXIT_FEE, self.wallet_spk(), self.Z_OUT),
                                 self.fee(EXIT_FEE, self.Z_OUT)])
            self.pad(tx)
            h = TaprootSignatureHash(tx, [u.txout], 0, self.genesis, 0, scriptpath=False)
            self.setwit(tx, 0, [sign_schnorr(tweak_add_privkey(k_sec, k_tap.tweak), h)])
            return tx

        def wallet_tx(u):
            tx = self.mktx([u], [self.out(u.amount - EXIT_FEE, self.wallet_spk(), self.Z_OUT),
                                 self.fee(EXIT_FEE, self.Z_OUT)])
            return self.wallet_sign(tx)

        self.rec("status/before_any_record", {
            "tree_root_script": self.frozen(root["spk"]), "leaf_script": self.frozen(l0[0].scriptPubKey),
            "p2tr_keypath_holder": self.frozen(k_tap.scriptPubKey), "p2wpkh_holder": self.frozen(w_spk)})
        # sanity: before any record the key-path spend is fine
        self.send(keypath_tx(u_kp2), "baseline/p2tr_keypath_spend_unfrozen")

        # ---- PAUSE the whole asset, and ALSO name the tree root and leaf 2 in targeted freezes
        self.log.info("=== T8: pause + targeted freezes naming covenant scripts ===")
        pause_txid, pause_target = self.record_tx("pause", self.Z, None)
        self.generate(node, 1)
        fr_root_txid, _ = self.record_tx("freeze", self.Z, self.addr(root["spk"]))
        self.generate(node, 1)
        fr_leaf_txid, _ = self.record_tx("freeze", self.Z, self.addr(l2[0].scriptPubKey))
        self.generate(node, 2)
        self.rec("status/paused_and_tree_scripts_named", {
            "tree_root_script": self.frozen(root["spk"]), "leaf2_script": self.frozen(l2[0].scriptPubKey),
            "p2tr_keypath_holder": self.frozen(k_tap.scriptPubKey), "p2wpkh_holder": self.frozen(w_spk),
            "getassetfreezes": node.getassetfreezes(self.Z)})

        # single-owner spends are refused
        self.reject(keypath_tx(u_kp), "paused/neg_p2tr_keypath_spend", expect="asset-frozen")
        self.reject(wallet_tx(u_w), "paused/neg_p2wpkh_spend", expect="asset-frozen")

        # the covenant tree keeps working: script-path UNROLL of the (named!) root
        tx = self.mktx([u_root], [self.out(LEAF, l[0].scriptPubKey, self.Z_OUT) for l in leaves]
                       + [self.fee(RESERVE, self.Z_OUT)])
        self.setwit(tx, 0, [bytes(root["leaves"]["unroll"]), control_block(root["tap"], "unroll")])
        rtxid = self.send(tx, "paused/unroll_root_script_path")
        self.generate(node, DELAY - 1)

        def exit_tx(i, dest, value=LEAF - EXIT_FEE):
            tap, lv = leaves[i]
            u = self.utxo_at(rtxid, i)
            tx = self.mktx([(u, DELAY)], [self.out(value, dest, self.Z_OUT), self.fee(LEAF - value, self.Z_OUT)])
            self.setwit(tx, 0, [self.sign(a[i], tx, 0, lv["exit"]), bytes(lv["exit"]), control_block(tap, "exit")])
            return tx

        # plain leaf exit (script path) while paused
        self.send(exit_tx(0, self.wallet_spk()), "paused/leaf0_exit_script_path")
        # leaf 2: its own script is named by a targeted freeze -- still exits
        self.send(exit_tx(2, self.wallet_spk()), "paused/leaf2_exit_script_named_in_freeze")
        # covenant-landing leaf: cannot land anywhere but P2WPKH(A1) ...
        self.reject(exit_tx(1, self.wallet_spk()), "paused/neg_landing_leaf_exit_to_other_address")
        self.reject(exit_tx(1, self.p2tr()[0]), "paused/neg_landing_leaf_exit_to_p2tr")
        ltxid = self.send(exit_tx(1, land_spk), "paused/landing_leaf_exit_to_P2WPKH_A")
        u_land = self.utxo_at(ltxid, 0)
        assert u_land.spk == land_spk
        # ... where it is single-owner and therefore caught by the pause
        self.reject(wallet_tx(u_land), "paused/neg_spend_from_landing_P2WPKH", expect="asset-frozen")

        # ---- targeted freeze of the landing address, then lift the pause
        self.log.info("=== T8: targeted freeze on the landing address; pause lifted ===")
        fr_land_txid, land_target = self.record_tx("freeze", self.Z, self.addr(land_spk))
        self.generate(node, 1)
        self.unfreeze(pause_txid, self.Z, "00" * 32)
        self.generate(node, 2)
        self.rec("status/pause_lifted_landing_frozen", {
            "landing_P2WPKH": self.frozen(land_spk), "p2tr_keypath_holder": self.frozen(k_tap.scriptPubKey),
            "p2wpkh_holder": self.frozen(w_spk), "getassetfreezes": node.getassetfreezes(self.Z)})
        # everyone else moves again ...
        self.send(keypath_tx(u_kp), "unpaused/p2tr_keypath_spend_ok_again")
        self.send(wallet_tx(u_w), "unpaused/p2wpkh_spend_ok_again")
        # ... the landed exit does not
        self.reject(wallet_tx(u_land), "unpaused/neg_spend_from_FROZEN_landing_P2WPKH", expect="asset-frozen")
        # lift it: funds move
        self.unfreeze(fr_land_txid, self.Z, land_target)
        self.generate(node, 2)
        self.send(wallet_tx(u_land), "unfrozen/spend_from_landing_P2WPKH")
        # leaf 3 exits last, with nothing frozen
        self.send(exit_tx(3, self.wallet_spk()), "unfrozen/leaf3_exit")


if __name__ == "__main__":
    T8().main()
