#!/usr/bin/env python3
"""The reference for Arca's off-chain transactions and the records that go
with them, in plain Python.

This module is the independent half of vectors/transactions.json. It shares no
code with the Rust crate `arca-covenant`: it builds every script with the
suite's own builders (arklib3.py), every transaction with the node framework's
types, and every signature hash with the framework's taproot code.
`vectors.py` calls `generate()`, and the Rust tests must rebuild every
transaction byte for byte, witnesses included.

Transactions are version 2. Input 0 spends the Arca output; outputs 0..m are
the ones its path pins or its signers commit to. What the spent coins hold
beyond those outputs is the margin, per asset. Paid from the margin
("reserve"), the margin is the fee output. Paid by a fee coin ("coin"), the
coin is input 1 and every margin goes to the broadcaster's change, in the
order its asset first appears among the inputs, then the coin's change, then
the fee output in the coin's asset. A final input has sequence 0xffffffff; a
fee coin beside an input under a relative lock has 0xfffffffe. Every input
that pays the OP_1 tapscript (the stand-in for wallet and fee coins) carries
that script's witness.

The board
---------
The owner pays its own coins to a vtxo-1 leaf whose salt is
SHA256("Arca/salt" || owner_nonce || operator_nonce). The board transaction
puts the leaf at output 0, then each asset's change, less the fee in the fee
asset, then the fee. The board record, format version 1:

    u8    format version, 1
    u8    template, 1 (vtxo)          u8  template version, 1
    [32]  owner key A
    [32]  owner nonce
    [32]  operator nonce
    u16   exit delay, 512-second units
    [32]  asset, internal byte order
    u64   value
    [32]  genesis hash, internal byte order
    [32]  operator key S

Its JSON form has the leaf record's field names and conventions. Its leaf id
is the leaf id of a batch with no levels whose batch output is the leaf:
tagged hash "Arca/leaf-id" of leaf program || 0x00 || leaf program.

The forfeit
-----------
The old leaf, by its collaborative path, into the forfeit output, holding the
leaf's value less the margin the signers leave for the fee. Both sign the
leaf's rebindable message over that one output. The forfeit output:

    claim:   <leaf_id> OP_DROP
             OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <M> OP_EQUALVERIFY
             OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY <S> OP_CHECKSIG
    refund:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG

leaf_id is the id of the leaf given up. M is the round's connector asset: the
asset spending the round's output (round_txid, c) issues with a zero contract
hash. The claim's witness is <sig_S> <preimage> <k>, k the input holding M:
input 1, whose whole value goes back to the operator after the claimed
outputs. The issuance of M spends the connector output, issues one explicit
atom with no reissuance token, pays it at output 0, and the connector's value
pays the fee. The claim and the refund are ordinary signatures over the
Elements taproot signature hash.

The offboard
------------
An output anyone can move to the owner's destination with the preimage of h,
and the operator reclaims after a delay:

    unlock:   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
              <record of the output at this input's index> OP_SHA256
              <SHA256(record of the destination)> OP_EQUAL
    reclaim:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG

The record is the tree's injective output record. The unlock pays the
destination at output 0 and the rest of the output is the margin.
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.key import SECP256K1_ORDER
from test_framework.messages import CAssetIssuance, COutPoint, CTxIn, CTxOutValue, uint256_from_str
from test_framework.script import TaprootSignatureHash

import records
from records import (ASSET, GENESIS, OPERATOR, TEMPLATE_VTXO_VERSION, TEMPLATES, display, json_text, label_hash,
                     le16, le64, leaf_salt, tagged_hash, txout, LEAF_ID_TAG)

BOARD_FORMAT_VERSION = 1
CTAG = chain_tag(GENESIS)
H = 3600
DELAY = (36 * H + 511) // 512              # exit and forfeit-refund delay, 512-second units
RECLAIM = (5 * 24 * H + 511) // 512        # the offboard's reclaim delay
FINAL = 0xffffffff
FEE_COIN_SEQ = 0xfffffffe

# A coin anyone can spend by a tapscript of OP_1: the stand-in for the
# owner's wallet coins and for a broadcaster's fee coin.
OP_TRUE_TAP = taproot_construct(NUMS, [("op_true", CScript([OP_1]))])
OP_TRUE_SPK = bytes(OP_TRUE_TAP.scriptPubKey)
OP_TRUE_WITNESS = [bytes(CScript([OP_1])), control_block(OP_TRUE_TAP, "op_true")]
FEE_ASSET = label_hash("asset", "fee")


class Key:
    def __init__(self, label):
        d = int.from_bytes(label_hash("key", label), "big") % SECP256K1_ORDER
        self.label, self.sec = label, d.to_bytes(32, "big")
        self.x = compute_xonly_pubkey(self.sec)[0]

    def sign(self, digest):
        return sign_schnorr(self.sec, digest)


S = Key("S")
assert S.x == OPERATOR
A = Key("A")
OPERATOR_SPK = bytes(taproot_construct(S.x).scriptPubKey)
OWNER_SPK = bytes(taproot_construct(A.x).scriptPubKey)


def hx(b):
    return bytes(b).hex()


def outpoint(label, vout=0):
    txid = label_hash("outpoint", label)
    return {"txid": display(txid), "vout": vout}, COutPoint(uint256_from_str(txid), vout)


def coin_at(tx, vout):
    """Output `vout` of `tx` as an outpoint: its JSON form and the framework's."""
    tx.calc_sha256()
    return {"txid": display(tx.sha256.to_bytes(32, "little")), "vout": vout}, COutPoint(tx.sha256, vout)


def out_json(asset, value, spk):
    return {"asset": display(asset), "value": value, "script_pubkey": hx(spk)}


class Built:
    """A transaction: inputs are (outpoint, spent (asset, value, spk), sequence)."""

    def __init__(self, inputs, outputs, locktime=0):
        self.tx = Tx()
        self.tx.nVersion, self.tx.nLockTime = 2, locktime
        self.prev = []
        self.inputs_json = []
        for (oj, op), (a, v, spk), seq in inputs:
            self.tx.vin.append(CTxIn(op, nSequence=seq))
            self.prev.append(txout(a, v, spk))
            self.inputs_json.append({"outpoint": oj, "spent": out_json(a, v, spk), "sequence": seq})
        self.tx.vout = [txout(a, v, spk) for a, v, spk in outputs]
        ArkBase.pad(self.tx)
        # Inputs paying the OP_1 tapscript (wallet coins, fee coins, the
        # connector) carry its witness, so every transaction is complete.
        for i, (_, (_, _, spk), _) in enumerate(inputs):
            if bytes(spk) == OP_TRUE_SPK:
                self.witness(i, OP_TRUE_WITNESS)

    def sighash(self, idx, script):
        return TaprootSignatureHash(self.tx, self.prev, 0, uint256_from_str(GENESIS), idx,
                                    scriptpath=True, script=CScript(script))

    def witness(self, idx, stack):
        self.tx.wit.vtxinwit[idx].scriptWitness.stack = [bytes(x) for x in stack]

    def json(self):
        return {"inputs": self.inputs_json, "tx": self.tx.serialize().hex()}


def with_fee(inputs, committed, fee, coin_seq):
    """The outputs after the committed ones: each asset's margin, the fee.
    fee is "reserve" or (coin outpoint, coin (asset, value, spk), fee value,
    change spk)."""
    held, order = {}, []
    for _, (a, v, _), _ in inputs:
        if a not in held:
            held[a] = 0
            order.append(a)
        held[a] += v
    for a, v, _ in committed:
        held[a] -= v
        assert held.get(a, -1) >= 0
    margins = [(a, held[a]) for a in order if held[a] > 0]
    outs = list(committed)
    if fee == "reserve":
        assert len(margins) <= 1
        outs += [(a, v, b"") for a, v in margins]
        return inputs, outs
    (coin_op, coin, fee_value, change) = fee
    ins = inputs + [(coin_op, coin, coin_seq)]
    outs += [(a, v, change) for a, v in margins]
    if coin[1] > fee_value:
        outs.append((coin[0], coin[1] - fee_value, change))
    outs.append((coin[0], fee_value, b""))
    return ins, outs


def fee_coin(label):
    return (outpoint(label, 1), (FEE_ASSET, 50_000, OP_TRUE_SPK), 3_000, OP_TRUE_SPK)


def fee_json(fee):
    if fee == "reserve":
        return "reserve"
    (oj, _), (a, v, spk), f, change = fee
    return {"outpoint": oj, "coin": out_json(a, v, spk), "fee": f, "change": hx(change)}


def leaf(owner, owner_nonce, operator_nonce, delay=DELAY):
    salt = leaf_salt(owner_nonce, operator_nonce)
    tap, scripts = leaf3_taptree(owner.x, S.x, salt, CTAG, SEQ_TIME | delay, fold=True)
    return tap, scripts, salt


def collab_spend(name, tap, collab, salt, coin, spent, committed, signers, fee):
    """A rebindable spend: both sign the message over the committed outputs."""
    a_in, v_in, _ = spent
    digest = rebind_msg3(CTAG, salt, a_in, v_in, committed, fold=True)
    sigs = [k.sign(digest) for k in signers]
    ins, outs = with_fee([(coin, spent, FINAL)], committed, fee, FINAL)
    b = Built(ins, outs)
    b.witness(0, sigs + [bytes([len(committed)]), bytes(collab), control_block(tap, "collab")])
    d = b.json()
    d.update({"name": name, "fee": fee_json(fee), "message_digest": hx(digest),
              "signatures": {k.label: hx(s) for k, s in zip(signers, sigs)}})
    return d


def key_spend(name, tap, leafname, script, coin, spent, seq, outputs, fee, signer, below_after=()):
    """A spend by a path ending in <key> OP_CHECKSIG, signed once built."""
    ins, outs = with_fee([(coin, spent, seq)], outputs, fee, FINAL if seq == FINAL else FEE_COIN_SEQ)
    b = Built(ins, outs)
    sh = b.sighash(0, script)
    sig = signer.sign(sh)
    b.witness(0, [sig] + list(below_after) + [bytes(script), control_block(tap, leafname)])
    d = b.json()
    d.update({"name": name, "fee": fee_json(fee), "sighash": hx(sh), "signatures": {signer.label: hx(sig)}})
    return d


# --------------------------------------------------------------------------
# The board
# --------------------------------------------------------------------------

def board_record(rec):
    name, ver = rec["template"]
    return (bytes([BOARD_FORMAT_VERSION, TEMPLATES[name], ver]) + rec["owner"] + rec["owner_nonce"]
            + rec["operator_nonce"] + le16(rec["exit_delay"]) + rec["asset"] + le64(rec["value"]) + rec["genesis"]
            + rec["operator"])


def board_json(rec):
    name, ver = rec["template"]
    return {"version": BOARD_FORMAT_VERSION, "template": "%s-%d" % (name, ver), "owner": rec["owner"].hex(),
            "owner_nonce": rec["owner_nonce"].hex(), "operator_nonce": rec["operator_nonce"].hex(),
            "exit_delay_units": rec["exit_delay"], "asset": display(rec["asset"]), "value": str(rec["value"]),
            "genesis_hash": display(rec["genesis"]), "operator": rec["operator"].hex()}


def board():
    value = 25_000_000
    rec = {"template": ("vtxo", TEMPLATE_VTXO_VERSION), "owner": A.x,
           "owner_nonce": label_hash("owner nonce", "board"), "operator_nonce": label_hash("operator nonce", "board"),
           "exit_delay": DELAY, "asset": ASSET, "value": value, "genesis": GENESIS, "operator": S.x}
    tap, scripts, salt = leaf(A, rec["owner_nonce"], rec["operator_nonce"])
    spk = bytes(tap.scriptPubKey)
    prog = spk[2:]
    coins = [(outpoint("board coin 0"), (ASSET, 20_000_000, OP_TRUE_SPK)),
             (outpoint("board coin 1"), (ASSET, 9_000_000, OP_TRUE_SPK))]
    fee = 1_200
    b = Built([(c, s, FINAL) for c, s in coins],
              [(ASSET, value, spk), (ASSET, 29_000_000 - value - fee, OP_TRUE_SPK), (ASSET, fee, b"")])
    board_tx = b.json()
    board_tx.update({"fee_asset": display(ASSET), "fee": fee, "change": hx(OP_TRUE_SPK), "leaf_vout": 0})

    # The owner's exit of the board leaf, the margin paying the fee.
    leaf_coin = coin_at(b.tx, 0)
    exit_tx = key_spend("the board leaf's exit claim", tap, "exit", scripts["exit"], leaf_coin,
                        (ASSET, value, spk), SEQ_TIME | DELAY, [(ASSET, value - 1_500, OWNER_SPK)], "reserve", A)

    binary = board_record(rec)
    bad = [
        ("format version 2", bytes([2]) + binary[1:], "version"),
        ("template 2", binary[:1] + b"\x02" + binary[2:], "template"),
        ("a trailing byte", binary + b"\x00", "trailing"),
        ("the last byte missing", binary[:-1], "end"),
        ("a value of zero", binary[:133] + le64(0) + binary[141:], "value"),
        ("an exit delay of zero", binary[:99] + le16(0) + binary[101:], "time"),
        ("operator key not on the curve", binary[:-32] + bytes(32), "key"),
    ]
    j = board_json(rec)

    def edit(f):
        o = dict(j)
        f(o)
        return json_text(o)

    bad_json = [
        ("an unknown field", edit(lambda o: o.update({"extra": 1})), "field"),
        ("the salt in place of the nonces", edit(lambda o: (o.pop("owner_nonce"), o.update({"salt": "00" * 32}))),
         "field"),
        ("a value as a number", edit(lambda o: o.update({"value": value})), "type"),
        ("format version 2", edit(lambda o: o.update({"version": 2})), "version"),
    ]
    return {
        "record": {"binary": binary.hex(), "json": json_text(j), "salt": salt.hex(), "leaf_program": prog.hex(),
                   "leaf_id": tagged_hash(LEAF_ID_TAG, prog + b"\x00" + prog).hex(),
                   "script_pubkey": spk.hex()},
        "board_tx": board_tx,
        "exit_tx": exit_tx,
        "invalid_binary": [{"name": n, "binary": x.hex(), "kind": k} for n, x, k in bad],
        "invalid_json": [{"name": n, "json": x, "kind": k} for n, x, k in bad_json],
    }


# --------------------------------------------------------------------------
# The forfeit
# --------------------------------------------------------------------------

def connector_issuance(round_txid, vout, coin_value, fee_value):
    """The issuance of a round's connector asset."""
    m = records.issued_asset(round_txid, vout)
    oj, op = {"txid": display(round_txid), "vout": vout}, COutPoint(uint256_from_str(round_txid), vout)
    b = Built([((oj, op), (ASSET, coin_value, OP_TRUE_SPK), FINAL)],
              [(m, 1, OP_TRUE_SPK), (ASSET, coin_value, b"")])
    iss = CAssetIssuance()
    iss.assetBlindingNonce, iss.assetEntropy = 0, 0
    iss.nAmount, iss.nInflationKeys, iss.denomination = CTxOutValue(1), CTxOutValue(), 0
    b.tx.vin[0].assetIssuance = iss
    d = b.json()
    d.update({"name": "the issuance of the connector asset", "asset": display(m), "fee": "reserve",
              "to": OP_TRUE_SPK.hex()})
    return m, d


def forfeit():
    owner_nonce, operator_nonce = label_hash("owner nonce", "old leaf"), label_hash("operator nonce", "old leaf")
    ltap, lscripts, salt = leaf(A, owner_nonce, operator_nonce)
    lspk = bytes(ltap.scriptPubKey)
    lprog = lspk[2:]
    leaf_id = tagged_hash(LEAF_ID_TAG, lprog + b"\x00" + lprog)
    value, margin = 10_000_000, 1_120
    preimage = label_hash("preimage", "forfeit")
    h = sha256(preimage)
    round_txid, c = label_hash("outpoint", "the round"), 2
    m, issuance = connector_issuance(round_txid, c, 5_000, 5_000)
    ftap, fscripts = forfeit_taptree(h, A.x, S.x, SEQ_TIME | DELAY, leaf_id, m)
    fspk = bytes(ftap.scriptPubKey)
    fval = value - margin
    leaf_coin = outpoint("old leaf")
    txs = []
    for fee in ("reserve", fee_coin("forfeit fee coin")):
        d = collab_spend("the forfeit" + ("" if fee == "reserve" else ", fee coin"), ltap, lscripts["collab"], salt,
                         leaf_coin, (ASSET, value, lspk), [(ASSET, fval, fspk)], [S, A], fee)
        txs.append(d)
    fcoin = coin_at(Tx.from_hex(txs[0]["tx"]), 0)
    mcoin = (coin_at(Tx.from_hex(issuance["tx"]), 0), (m, 1, OP_TRUE_SPK), FINAL)

    def claim(name, outputs, fee):
        ins, outs = with_fee([(fcoin, (ASSET, fval, fspk), FINAL), mcoin], outputs + [(m, 1, OPERATOR_SPK)], fee, FINAL)
        b = Built(ins, outs)
        sh = b.sighash(0, fscripts["claim"])
        sig = S.sign(sh)
        b.witness(0, [sig, preimage, sn(1), bytes(fscripts["claim"]), control_block(ftap, "claim")])
        d = b.json()
        d.update({"name": name, "fee": fee_json(fee), "sighash": hx(sh), "signatures": {S.label: hx(sig)},
                  "connector_input": 1, "connector_to": OPERATOR_SPK.hex()})
        return d

    claim_r = claim("the operator's claim", [(ASSET, fval - 1_000, OPERATOR_SPK)], "reserve")
    claim_c = claim("the operator's claim, fee coin", [(ASSET, fval, OPERATOR_SPK)], fee_coin("claim fee coin"))
    refund = key_spend("the owner's refund", ftap, "refund", fscripts["refund"], fcoin, (ASSET, fval, fspk),
                       SEQ_TIME | DELAY, [(ASSET, fval - 1_000, OWNER_SPK)], "reserve", A)
    refund_coin = key_spend("the owner's refund, fee coin", ftap, "refund", fscripts["refund"], fcoin,
                            (ASSET, fval, fspk), SEQ_TIME | DELAY, [(ASSET, fval, OWNER_SPK)],
                            fee_coin("refund fee coin"), A)
    return {
        "inputs": {"owner": A.x.hex(), "operator": S.x.hex(), "owner_nonce": owner_nonce.hex(),
                   "operator_nonce": operator_nonce.hex(), "exit_delay_units": DELAY, "asset": display(ASSET),
                   "value": value, "margin": margin, "unlock_hash": h.hex(), "preimage": preimage.hex(),
                   "refund_delay_units": DELAY, "leaf_outpoint": leaf_coin[0], "leaf_id": leaf_id.hex(),
                   "round": {"txid": display(round_txid), "connector_vout": c}, "connector_asset": display(m)},
        "leaf_script_pubkey": lspk.hex(),
        "forfeit_output": out_json(ASSET, fval, fspk),
        "claim_script": hx(fscripts["claim"]), "refund_script": hx(fscripts["refund"]),
        "issuance": issuance,
        "transactions": txs + [claim_r, claim_c, refund, refund_coin],
    }


# --------------------------------------------------------------------------
# The offboard
# --------------------------------------------------------------------------

def offboard_taptree(h, dest, s_x, delay):
    a, v, spk = dest
    unlock = CScript(hash_gate(h) + pin_current_output(a, v, spk))
    reclaim = exit_leaf(s_x, delay)
    tap = taproot_construct(NUMS, [("unlock", unlock), ("reclaim", reclaim)])
    return tap, {"unlock": unlock, "reclaim": reclaim}


def offboard():
    preimage = label_hash("preimage", "offboard")
    h = sha256(preimage)
    # The owner's destination: a version 0 witness program, to show that any
    # script can be pinned.
    dest = (ASSET, 9_998_880, bytes([0x00, 0x14]) + label_hash("program", "owner's address")[:20])
    tap, scripts = offboard_taptree(h, dest, S.x, SEQ_TIME | RECLAIM)
    spk = bytes(tap.scriptPubKey)
    reserve = 900
    value = dest[1] + reserve
    coin = outpoint("offboard output")
    txs = []
    for fee in ("reserve", fee_coin("unlock fee coin")):
        ins, outs = with_fee([(coin, (ASSET, value, spk), FINAL)], [dest], fee, FINAL)
        b = Built(ins, outs)
        b.witness(0, [preimage, bytes(scripts["unlock"]), control_block(tap, "unlock")])
        d = b.json()
        d.update({"name": "the unlock" + ("" if fee == "reserve" else ", fee coin"), "fee": fee_json(fee)})
        txs.append(d)
    txs.append(key_spend("the operator's reclaim", tap, "reclaim", scripts["reclaim"], coin, (ASSET, value, spk),
                         SEQ_TIME | RECLAIM, [(ASSET, value - 1_000, OPERATOR_SPK)], "reserve", S))
    return {
        "inputs": {"unlock_hash": h.hex(), "preimage": preimage.hex(), "destination": out_json(*dest),
                   "operator": S.x.hex(), "reclaim_delay_units": RECLAIM, "reserve": reserve, "outpoint": coin[0]},
        "unlock_script": hx(scripts["unlock"]), "reclaim_script": hx(scripts["reclaim"]),
        "unlock_control_block": hx(control_block(tap, "unlock")),
        "reclaim_control_block": hx(control_block(tap, "reclaim")),
        "script_pubkey": spk.hex(),
        "transactions": txs,
    }


def generate():
    return {
        "about": "Golden vectors for Arca's off-chain transactions and the records that go with them. Generated by "
                 "regtest/vectors.py from regtest/offchain.py; do not edit.",
        "conventions": {
            "format": "regtest/offchain.py states every transaction's shape and the board record's layout.",
            "byte_order": "Asset ids and the genesis hash are in display order in this file's own fields and in the "
                          "JSON forms, in internal byte order in transactions and binary forms.",
            "keys": "x-only test keys: secret = SHA256(\"Arca test vector key/\" + label) mod n, labels \"A\" (the "
                    "owner) and \"S\" (the operator). They hold nothing. Signatures use zero auxiliary randomness.",
            "coins": "The owner's wallet coins and the fee coins pay a tapscript of OP_1 with the NUMS internal key; "
                     "their witness is that script and its control block.",
        },
        "inputs": {"genesis_hash": display(GENESIS), "asset": display(ASSET), "fee_asset": display(FEE_ASSET),
                   "operator": S.x.hex(), "owner": A.x.hex(), "op_true_script_pubkey": OP_TRUE_SPK.hex(),
                   "operator_script_pubkey": OPERATOR_SPK.hex(), "owner_script_pubkey": OWNER_SPK.hex()},
        "board": board(),
        "forfeit": forfeit(),
        "offboard": offboard(),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(generate(), indent=1))
