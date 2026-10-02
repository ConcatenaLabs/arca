#!/usr/bin/env python3
"""T18: the token-gated sweep and its clock.

The round transaction issues one explicit atom of a new asset T (no reissuance
token) into clock 0. Every sweep path requires an input k (from the witness)
holding explicit T at the v1 program R:

    <k> OP_DUP OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <T> OP_EQUALVERIFY
        OP_INSPECTINPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <R> OP_EQUALVERIFY <S> OP_CHECKSIG

clock j:  ROLL(j)    <S> CHECKSIGVERIFY, output[this index] == (T, 1, clock j+1)
          RELEASE(j) <E_j> CLTV DROP <S> CHECKSIGVERIFY, output[this index] == (T, 1, R)
"""
from arklib3 import *
import os as _os

LEAF = 1000_0000
RESERVE = 1000
CHANGE = 5000
RFEE = 1000
SFEE = 2000
H = 3600


class T18(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "t18"

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.Rtap, self.Rlv = r_taptree(self.s_x)
        self.Rspk = bytes(self.Rtap.scriptPubKey)
        self.rec_script("R/spend", self.Rlv["spend"], self.Rtap, "spend")
        self.rec("whitelist", self.node.getfeeexchangerates())
        now = self.mtp()
        A = self.make_batch("A", [now + 3 * H, now + 5 * H, now + 7 * H], nleaves=8)
        self.facts(A)
        B = self.make_batch("B", [now + 1 * H], nleaves=4)
        C = self.make_batch("C", [now + 9 * H, now + 11 * H], nleaves=4, kind="asset_only")
        self.client_checks(A, now)
        self.flow(A, B, C)
        self.rebroadcast_round()

    # ------------------------------------------------------------------
    def tree(self, T_id, nleaves, kind):
        Rprog = self.Rspk[2:]

        def scripts(kids, tuples, level, is_root):
            unroll = CScript(unroll_compact_body(tuples))
            sw = sweep_token(T_id, Rprog, self.s_x) if kind == "R" else sweep_token_asset_only(T_id, self.s_x)
            return [("unroll", unroll), ("sweep", sw)], {"unroll": unroll, "sweep": sw}
        return build_tree3(self.X_ID, [self.p2tr()[0] for _ in range(nleaves)], LEAF, 4, RESERVE, scripts)

    def make_batch(self, name, expiries, nleaves=4, kind="R", amount=1, keys=0, t_dest="clock", sched=None,
                   mine=True, extra_T_to_R=0):
        """An issuing round. sched: the expiries actually used to build the clock
        chain (default: the advertised `expiries`)."""
        root_value = nleaves * LEAF + (RESERVE * (1 + (nleaves + 3) // 4) if nleaves > 4 else RESERVE)
        w = self.wallet_utxo(root_value + CHANGE + RFEE, self.X)
        sk = self.mktx([w], [self.out(1, self.wallet_spk(), self.X_OUT)])
        sk.vin[0].assetIssuance = self.issuing_input(w, amount=amount, keys=keys)
        T_hex, tok_hex = self.issued_ids(sk)
        T_id = bytes.fromhex(T_hex)[::-1]
        T_OUT = b"\x01" + T_id
        clocks = clock_chain(T_id, self.Rspk, self.s_x, sched or expiries)
        root = self.tree(T_id, nleaves, kind)
        assert root["value"] == root_value, (root["value"], root_value)
        dest = clocks[0]["spk"] if t_dest == "clock" else self.Rspk
        outs = [self.out(root_value, root["spk"], self.X_OUT), self.out(amount - extra_T_to_R, dest, T_OUT)]
        if extra_T_to_R:
            outs.append(self.out(extra_T_to_R, self.Rspk, T_OUT))
        if keys:
            outs.append(self.out(keys, self.wallet_spk(), b"\x01" + bytes.fromhex(tok_hex)[::-1]))
        outs += [self.out(CHANGE, self.wallet_spk(), self.X_OUT), self.fee(RFEE, self.X_OUT)]
        tx = self.mktx([w], outs)
        tx.vin[0].assetIssuance = self.issuing_input(w, amount=amount, keys=keys)
        tx = self.wallet_sign(tx)
        if name == "A":
            plain = self.wallet_sign(self.mktx([w], [o for i, o in enumerate(outs) if i != 1]))
            self.plain_round = (plain, self.accept(plain)["allowed"])
        b = {"name": name, "T_hex": T_hex, "T_id": T_id, "T_OUT": T_OUT, "token_hex": tok_hex, "clocks": clocks,
             "root": root, "expiries": expiries, "w": w, "tx": tx, "outs": outs}
        if mine:
            txid = self.send(tx, "round/%s" % name)
            b["txid"] = txid
            b["root_u"] = self.utxo_at(txid, 0)
            b["T_u"] = self.utxo_at(txid, 1)
        self.rec("batch/%s" % name, {"T": T_hex, "token": tok_hex, "expiries": expiries,
                                     "clock0_spk": clocks[0]["spk"].hex(), "kind": kind,
                                     "T_dest": t_dest, "amount": amount, "keys": keys})
        return b

    # -- transactions on the clock -----------------------------------------
    def roll_tx(self, b, cu, j, out_spk=None, out_index0=True, sig=True):
        c, nxt = b["clocks"][j], b["clocks"][j + 1]["spk"] if out_spk is None else out_spk
        T_out = self.out(1, nxt, b["T_OUT"])
        if out_index0:
            tx = self.with_fee_input([cu], [T_out])
        else:
            pw = self.wallet_utxo(50_000)
            tx = self.mktx([cu, pw], [self.out(49_000, self.wallet_spk(), self.POL_OUT), T_out,
                                      self.fee(1000, self.POL_OUT)])
        leaf = c["lv"]["roll"]
        st = [self.sign(self.s_sec, tx, 0, leaf) if sig else b""]
        self.setwit(tx, 0, st + [bytes(leaf), control_block(c["tap"], "roll")])
        return self.wallet_sign(tx)

    def release_tx(self, b, cu, j, locktime, out_spk=None):
        c = b["clocks"][j]
        tx = self.with_fee_input([(cu, 0xfffffffe)], [self.out(1, out_spk or self.Rspk, b["T_OUT"])], locktime=locktime)
        leaf = c["lv"]["release"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, leaf), bytes(leaf), control_block(c["tap"], "release")])
        return self.wallet_sign(tx)

    def sweep_tx(self, b, node_u, node, t_u, k=1, t_spend=None, locktime=0, extra_wallet=False):
        """inputs [node (sweep path), T input at index k], outputs [operator X, T back to R, fee X].
        t_spend: (tap, name, below_without_sig) for the T input; default: R's spend path."""
        tap, name = (self.Rtap, "spend") if t_spend is None else t_spend[:2]
        ins = [node_u, t_u] if k == 1 else [t_u, node_u]
        ni = 0 if k == 1 else 1
        outs = [self.out(node_u.amount - SFEE, self.wallet_spk(), self.X_OUT),
                self.out(1, self.Rspk, bytes(t_u.txout.nAsset.vchCommitment)), self.fee(SFEE, self.X_OUT)]
        if ni == 1:
            outs = [outs[1], outs[0], outs[2]]
        tx = self.mktx(ins, outs, locktime)
        sw = node["leaves"]["sweep"]
        self.setwit(tx, ni, [self.sign(self.s_sec, tx, ni, sw), sn(k), bytes(sw), control_block(node["tap"], "sweep")])
        ti = 1 - ni
        tl = tap.leaves[name].script
        below = [] if t_spend is None else list(t_spend[2])
        self.setwit(tx, ti, [self.sign(self.s_sec, tx, ti, tl)] + below + [bytes(tl), control_block(tap, name)])
        return tx

    # ------------------------------------------------------------------
    def facts(self, A):
        """Relay, size and re-broadcast facts for the issuing round."""
        node = self.node
        tx = A["tx"]
        d = node.decoderawtransaction(tx.serialize().hex())
        self.rec("facts/round_issuance_decoded", d["vin"][0].get("issuance"))
        # the same round without the issuance and without the T output (not broadcast)
        plain, plain_ok = self.plain_round
        m0, m1 = self.measure(plain), self.measure(tx)
        m0["testmempoolaccept_before_A_was_sent"] = plain_ok
        self.rec("facts/round_size", {"without_issuance_and_T_output": m0, "with": m1,
                                      "added_vsize": m1["vsize"] - m0["vsize"],
                                      "issuance_field_bytes": len(tx.vin[0].assetIssuance.serialize()),
                                      "T_output_bytes": len(A["outs"][1].serialize())})
        # T depends on the issuing input and the contract hash only
        var = self.mktx([A["w"]], [self.out(1, self.wallet_spk(), self.X_OUT)])
        var.vin[0].assetIssuance = self.issuing_input(A["w"], amount=1)
        same = self.issued_ids(var)[0]
        other_w = self.wallet_utxo(1000, self.X)
        var2 = self.mktx([other_w], [self.out(1, self.wallet_spk(), self.X_OUT)])
        var2.vin[0].assetIssuance = self.issuing_input(other_w, amount=1)
        self.rec("facts/T_identity", {"T": A["T_hex"], "T_from_a_different_round_tx_same_input": same,
                                      "T_from_another_input": self.issued_ids(var2)[0],
                                      "same": same == A["T_hex"]})

    # ------------------------------------------------------------------
    def rebroadcast(self, A, wtxid):
        """Run last: the round transaction after invalidateblock."""
        node = self.node
        # re-broadcast after invalidateblock
        bh = node.getrawtransaction(A["txid"], True)["blockhash"]
        h0 = node.getblockcount()
        node.invalidateblock(bh)
        in_pool = A["txid"] in node.getrawmempool()
        self.tick(1)
        pool = node.getrawmempool()
        wt = node.gettransaction(wtxid)
        self.rec("facts/invalidateblock_wallet_tx_one_block_later",
                 {"nLockTime": node.decoderawtransaction(wt["hex"])["locktime"],
                  "confirmations_after": wt["confirmations"], "in_mempool_after": wtxid in pool,
                  "tip_height_after": node.getblockcount(),
                  "round_nLockTime": A["tx"].nLockTime})
        v = node.getrawtransaction(A["txid"], True)
        T_after = v["vin"][0]["issuance"]["asset"]
        self.rec("facts/invalidateblock", {"invalidated": bh, "round_back_in_mempool": in_pool,
                                           "reconfirmed": v.get("confirmations", 0) >= 1,
                                           "same_txid": v["txid"] == A["txid"], "T_after": T_after,
                                           "T_unchanged": T_after == A["T_hex"], "height_before": h0,
                                           "height_after": node.getblockcount()})
        assert in_pool and T_after == A["T_hex"]
        # the round's outputs are all still there except those spent later in this test
        self.rec("facts/invalidateblock_round_outputs_unspent_after",
                 [node.gettxout(A["txid"], i) is not None for i in range(len(A["tx"].vout))])


    def rebroadcast_round(self):
        now = self.mtp()
        pw = self.wallet_utxo(50_000)          # fee coin for the roll afterwards, mined BEFORE the round
        D = self.make_batch("D_rebroadcast", [now + 30 * H, now + 32 * H], nleaves=4)
        wtx = self.wallet_utxo(1000, self.X)   # a wallet tx (anti-fee-sniping nLockTime) one block later
        self.rebroadcast(D, wtx.txid)
        cl = D["clocks"][0]
        tx = self.mktx([self.utxo_at(D["txid"], 1), pw], [self.out(1, D["clocks"][1]["spk"], D["T_OUT"]),
                                                          self.out(49_000, self.wallet_spk(), self.POL_OUT),
                                                          self.fee(1000, self.POL_OUT)])
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, cl["lv"]["roll"]), bytes(cl["lv"]["roll"]),
                            control_block(cl["tap"], "roll")])
        r = self.send(self.wallet_sign(tx), "facts/roll_after_rebroadcast")
        assert self.utxo_at(r, 0).spk == D["clocks"][1]["spk"]

    def flow(self, A, B, C):
        node = self.node
        root = A["root"]
        E0, E1, E2 = A["expiries"]

        # ---- the lead's flaw, on the FIRST sketch (asset-only sweep): a sweep inside the roll
        self.log.info("=== T18: first sketch, sweep inside the roll ===")
        tx = self.mktx([C["T_u"], C["root_u"]], [self.out(1, C["clocks"][1]["spk"], C["T_OUT"]),
                                                  self.out(C["root_u"].amount - SFEE, self.wallet_spk(), self.X_OUT),
                                                  self.fee(SFEE, self.X_OUT)])
        cl = C["clocks"][0]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, cl["lv"]["roll"]), bytes(cl["lv"]["roll"]),
                            control_block(cl["tap"], "roll")])
        sw = C["root"]["leaves"]["sweep"]
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, sw), sn(0), bytes(sw), control_block(C["root"]["tap"], "sweep")])
        self.rec_script("first_sketch/sweep_leaf", sw)
        self.send(tx, "first_sketch/FLAW_sweep_inside_roll_CONFIRMED_before_expiry",
                  extra={"mtp": self.mtp(), "first_expiry": C["expiries"][0]})

        # ---- negatives against the specified design, clock 0 holds T
        self.log.info("=== T18: negatives, clock 0 holds T ===")
        self.rec_script("A/sweep_leaf", root["leaves"]["sweep"], root["tap"], "sweep")
        self.rec_script("A/clock0_roll", A["clocks"][0]["lv"]["roll"], A["clocks"][0]["tap"], "roll")
        self.rec_script("A/clock0_release", A["clocks"][0]["lv"]["release"], A["clocks"][0]["tap"], "release")
        self.rec_script("A/clock2_release_last", A["clocks"][2]["lv"]["release"], A["clocks"][2]["tap"], "release")
        # no T input: k points at a policy-asset wallet coin
        pw = self.wallet_utxo(50_000)
        tx = self.mktx([A["root_u"], pw], [self.out(A["root_u"].amount - SFEE, self.wallet_spk(), self.X_OUT),
                                          self.out(50_000, self.wallet_spk(), self.POL_OUT), self.fee(SFEE, self.X_OUT)])
        sw = root["leaves"]["sweep"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, sw), sn(1), bytes(sw), control_block(root["tap"], "sweep")])
        self.reject(self.wallet_sign(tx), "neg/sweep_with_no_T_input")
        # sweep inside the roll: T is an input, at clock 0's script
        tx = self.mktx([A["T_u"], A["root_u"]], [self.out(1, A["clocks"][1]["spk"], A["T_OUT"]),
                                                  self.out(A["root_u"].amount - SFEE, self.wallet_spk(), self.X_OUT),
                                                  self.fee(SFEE, self.X_OUT)])
        cl = A["clocks"][0]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, cl["lv"]["roll"]), bytes(cl["lv"]["roll"]),
                            control_block(cl["tap"], "roll")])
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, sw), sn(0), bytes(sw), control_block(root["tap"], "sweep")])
        self.reject(tx, "neg/sweep_inside_the_roll")
        # clock-path negatives
        self.reject(self.roll_tx(A, A["T_u"], 0, out_spk=self.Rspk), "neg/roll_paying_T_to_R")
        self.reject(self.roll_tx(A, A["T_u"], 0, out_spk=A["clocks"][2]["spk"]), "neg/roll_skipping_to_clock2")
        self.reject(self.roll_tx(A, A["T_u"], 0, sig=False), "neg/roll_without_signature")
        self.reject(self.roll_tx(A, A["T_u"], 0, out_index0=False), "neg/roll_T_at_another_output_index")
        self.reject(self.release_tx(A, A["T_u"], 0, locktime=E0), "neg/release_before_expiry_nonfinal")
        self.reject(self.release_tx(A, A["T_u"], 0, locktime=self.mtp() - 1), "neg/release_before_expiry_final_locktime")

        # ---- batch B's T released (B's expiry is 1 h): it rests at the same R
        self.log.info("=== T18: T of another batch ===")
        self.mtp_past(B["expiries"][0])
        rb = self.send(self.release_tx(B, B["T_u"], 0, locktime=B["expiries"][0]), "B/release")
        TB_at_R = self.utxo_at(rb, 0)
        self.reject(self.sweep_tx(A, A["root_u"], root, TB_at_R), "neg/sweep_with_the_T_of_another_batch")
        assert self.mtp() < E0

        # ---- roll A: clock 0 -> clock 1
        self.log.info("=== T18: roll ===")
        r1 = self.send(self.roll_tx(A, A["T_u"], 0), "pos/roll_clock0_to_clock1")
        T1 = self.utxo_at(r1, 0)
        assert T1.spk == A["clocks"][1]["spk"]
        self.mtp_past(E0)
        self.rec("state/after_old_expiry", {"mtp": self.mtp(), "E0": E0, "E1": E1})
        self.reject(self.release_tx(A, T1, 1, locktime=E0), "neg/after_roll_release_at_old_expiry")
        self.reject(self.release_tx(A, T1, 1, locktime=E1), "neg/after_roll_release_at_old_expiry_nonfinal")
        tx = self.mktx([T1, A["root_u"]], [self.out(1, A["clocks"][2]["spk"], A["T_OUT"]),
                                            self.out(A["root_u"].amount - SFEE, self.wallet_spk(), self.X_OUT),
                                            self.fee(SFEE, self.X_OUT)])
        cl = A["clocks"][1]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, cl["lv"]["roll"]), bytes(cl["lv"]["roll"]),
                            control_block(cl["tap"], "roll")])
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, sw), sn(0), bytes(sw), control_block(root["tap"], "sweep")])
        self.reject(tx, "neg/after_roll_sweep_at_old_expiry_inside_next_roll")

        # ---- new expiry: release clock 1, then sweep
        self.mtp_past(E1)
        tx = self.mktx([(T1, 0xfffffffe), A["root_u"]], [self.out(1, self.Rspk, A["T_OUT"]),
                                                          self.out(A["root_u"].amount - SFEE, self.wallet_spk(),
                                                                   self.X_OUT), self.fee(SFEE, self.X_OUT)], E1)
        rl = cl["lv"]["release"]
        self.setwit(tx, 0, [self.sign(self.s_sec, tx, 0, rl), bytes(rl), control_block(cl["tap"], "release")])
        self.setwit(tx, 1, [self.sign(self.s_sec, tx, 1, sw), sn(0), bytes(sw), control_block(root["tap"], "sweep")])
        self.reject(tx, "neg/sweep_inside_the_release")
        self.reject(self.release_tx(A, T1, 1, locktime=E1, out_spk=self.wallet_spk()), "neg/release_paying_T_elsewhere")
        rel = self.send(self.release_tx(A, T1, 1, locktime=E1), "pos/release_clock1_at_new_expiry")
        TR = self.utxo_at(rel, 0)
        # a sweep through the R path with only the asset id right (T input elsewhere) is covered above;
        # now the real one
        st = self.send(self.sweep_tx(A, A["root_u"], root, TR), "pos/sweep_root_at_new_expiry")
        self.rec("pos/sweep_root_at_new_expiry_detail", {"mtp": self.mtp(), "E1": E1, "E2": E2,
                                                          "T_back_at_R": node.gettxout(st, 1)["scriptPubKey"]["hex"]
                                                          == self.Rspk.hex()})
        # the same T, back at R, also serves the next sweep (B's root swept with B's T, k = 0 order)
        self.send(self.sweep_tx(B, B["root_u"], B["root"], TB_at_R, k=0), "pos/sweep_B_root_T_first_input")

    # ------------------------------------------------------------------
    def client_checks(self, A, now):
        """The wallet's checks on the round, and what each catches when broken."""
        self.log.info("=== T18: client checks ===")
        ok = client_check_round(A["tx"], A["T_hex"], A["clocks"][0]["spk"])
        ok += clock_schedule_check(A["T_id"], self.Rspk, self.s_x, A["expiries"], A["clocks"][0]["spk"])
        self.rec("client/good_round", {"failures": ok})
        assert not ok

        def attack(b, label, T_at_R_u):
            """Sweep b's root now, before any advertised expiry, with T found at R."""
            tx = self.sweep_tx(b, b["root_u"], b["root"], T_at_R_u)
            self.send(tx, label, extra={"mtp": self.mtp(), "first_advertised_expiry": b["expiries"][0]})

        # two atoms: one in clock 0, one straight to R
        K1 = self.make_batch("K1_two_atoms", [now + 20 * H], amount=2, extra_T_to_R=1)
        f = client_check_round(K1["tx"], K1["T_hex"], K1["clocks"][0]["spk"])
        self.rec("client/two_atoms", {"failures": f, "consensus": "round confirmed"})
        attack(K1, "client/ATTACK_two_atoms_sweep_now_CONFIRMED", self.utxo_at(K1["txid"], 2))
        assert f
        # one atom straight to R (never in a clock)
        K3 = self.make_batch("K3_atom_at_R", [now + 20 * H], t_dest="R")
        f = client_check_round(K3["tx"], K3["T_hex"], K3["clocks"][0]["spk"])
        self.rec("client/atom_not_in_clock", {"failures": f})
        attack(K3, "client/ATTACK_atom_at_R_sweep_now_CONFIRMED", K3["T_u"])
        assert f
        # a schedule that moves backwards: advertised E = [now+20h, now+22h], built [now+20h, now-1h]
        adv = [now + 20 * H, now + 22 * H]
        K4 = self.make_batch("K4_backwards", adv, sched=[now + 20 * H, now - H])
        f = client_check_round(K4["tx"], K4["T_hex"], K4["clocks"][0]["spk"])
        f2 = clock_schedule_check(K4["T_id"], self.Rspk, self.s_x, adv, K4["clocks"][0]["spk"])
        f3 = clock_schedule_check(K4["T_id"], self.Rspk, self.s_x, [now + 20 * H, now - H], K4["clocks"][0]["spk"])
        self.rec("client/backwards_schedule", {"round_check_failures": f, "schedule_check_vs_advertised": f2,
                                               "schedule_check_vs_true_schedule": f3})
        r = self.send(self.roll_tx(K4, K4["T_u"], 0), "client/K4_roll_into_earlier_clock")
        rel = self.send(self.release_tx(K4, self.utxo_at(r, 0), 1, locktime=now - H), "client/K4_release_at_past_E")
        attack(K4, "client/ATTACK_backwards_roll_sweep_now_CONFIRMED", self.utxo_at(rel, 0))
        assert not f and f2 and f3
        # a reissuance token
        K2 = self.make_batch("K2_token", [now + 20 * H], keys=1)
        f = client_check_round(K2["tx"], K2["T_hex"], K2["clocks"][0]["spk"])
        self.rec("client/reissuance_token", {"failures": f})
        assert f
        try:
            r = self.node.reissueasset(asset=K2["T_hex"], assetamount=Decimal("0.00000001"), fee_asset=BITCOIN_ASSET)
            self.generate(self.node, 1)
            addr = program_to_witness(1, self.Rspk[2:])
            txid = self.node.sendtoaddress(address=addr, amount=Decimal("0.00000001"), assetlabel=K2["T_hex"],
                                           fee_asset_label=BITCOIN_ASSET)
            self.generate(self.node, 1)
            attack(K2, "client/ATTACK_reissue_T_to_R_sweep_now_CONFIRMED", self.utxo_of(txid, self.Rspk))
        except JSONRPCException as e:
            self.rec("client/reissue_attempt_error", str(e.error))


if __name__ == "__main__":
    T18().main()
