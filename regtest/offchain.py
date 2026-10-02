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
pays the fee. The claim, the refund and the issuance are ordinary signatures
over the Elements taproot signature hash.

The connector output, (round_txid, c), has one leaf:

    issue:   <S> OP_CHECKSIGVERIFY OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTISSUANCE
             <0^32> OP_EQUALVERIFY <0^32> OP_EQUALVERIFY
             OP_1 OP_EQUALVERIFY <1, u64 LE> OP_EQUALVERIFY
             OP_1 OP_EQUALVERIFY <0, u64 LE> OP_EQUAL

so only the operator spends it, and only by issuing M on that input: a zero
blinding nonce (a new issuance), a zero entropy (a zero contract hash), one
explicit atom, no reissuance token. Its witness is <sig_S>.

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

The transfer
------------
Each input coin is spent by its collaborative path into a checkpoint output
(collab: the coin owner's and S's rebindable pair; sweep: the sweep with notice
of the batch the coin descends from, for a coin from a reassignment the first
input's). The checkpoint's salt is SHA256("Arca/checkpoint" || the coin's leaf
salt). The reassignment spends the checkpoints, in input order, into the
committed outputs. Each pair signs the frozen rebindable message: the
checkpoint pair on the coin's leaf over the checkpoint output, the
reassignment pair on the checkpoint over the outputs.

The coin record, format version 1:

    u8    format version, 1
    coin:
      u8  0, a leaf of a batch: u16 length L and L bytes of its leaf record;
          [32] the entry's preimage; u8 n and n x ([64] signature, u32 time),
          the owner's unroll authorisation of each node from the batch output down
      u8  1, an output of a reassignment: u8 input count, then per input the
          coin (recursively), u64 the checkpoint's value, the checkpoint pair
          and the reassignment pair ([64] operator, [64] owner each);
          u8 output count, then per output [32] asset, u64 value, compact size
          and scriptPubKey; u8 the coin's index; [32] owner key, [32] owner
          nonce, [32] operator nonce, u16 exit delay units

A coin from a reassignment has the leaf id of R || 0x01 || index || its leaf
program, R the tagged hash "Arca/reassignment" of the input count, each input's
coin id and checkpoint program, the output count and each output's record hash.
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.key import SECP256K1_ORDER
from test_framework.messages import CAssetIssuance, COutPoint, CTxIn, CTxOutValue, uint256_from_str
from test_framework.script import TaprootSignatureHash

import records
import struct

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

CONNECTOR_TAP, CONNECTOR_SCRIPTS = connector_taptree(S.x)
CONNECTOR_SPK = bytes(CONNECTOR_TAP.scriptPubKey)


def connector_issuance(round_txid, vout, coin_value):
    """The issuance of a round's connector asset: the connector output, held
    at (round_txid, vout) by the connector script, issues one explicit atom
    with no reissuance token, paid at output 0; its value pays the fee. The
    operator signs it."""
    m = records.issued_asset(round_txid, vout)
    oj, op = {"txid": display(round_txid), "vout": vout}, COutPoint(uint256_from_str(round_txid), vout)
    b = Built([((oj, op), (ASSET, coin_value, CONNECTOR_SPK), FINAL)],
              [(m, 1, OP_TRUE_SPK), (ASSET, coin_value, b"")])
    iss = CAssetIssuance()
    iss.assetBlindingNonce, iss.assetEntropy = 0, 0
    iss.nAmount, iss.nInflationKeys, iss.denomination = CTxOutValue(1), CTxOutValue(), 0
    b.tx.vin[0].assetIssuance = iss
    script = CONNECTOR_SCRIPTS["issue"]
    sh = b.sighash(0, script)
    sig = S.sign(sh)
    b.witness(0, [sig, bytes(script), control_block(CONNECTOR_TAP, "issue")])
    d = b.json()
    d.update({"name": "the issuance of the connector asset", "asset": display(m), "fee": "reserve",
              "to": OP_TRUE_SPK.hex(), "sighash": hx(sh), "signatures": {S.label: hx(sig)}})
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
    m, issuance = connector_issuance(round_txid, c, 5_000)
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
        "connector_output": out_json(ASSET, 5_000, CONNECTOR_SPK), "connector_script": hx(CONNECTOR_SCRIPTS["issue"]),
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


# --------------------------------------------------------------------------
# The transfer
# --------------------------------------------------------------------------

CHECKPOINT_TAG = b"Arca/checkpoint"
REASSIGNMENT_TAG = b"Arca/reassignment"
Y_ASSET = label_hash("asset", "Y")
CREATED = records.CREATED
MARGIN = 1_200


def checkpoint_salt(salt):
    return sha256(CHECKPOINT_TAG + salt)


def compact(n):
    return bytes([n]) if n < 0xfd else b"\xfd" + le16(n)


class Coin:
    """A coin: its owner (Key), leaf salt, asset, value, leaf taproot, the
    sweep its checkpoint takes, its id and its record's bytes (without the
    format version)."""

    def __init__(self, owner, salt, asset, value, tap, scripts, sweep, cid, record, delay=DELAY):
        self.owner, self.salt, self.asset, self.value = owner, salt, asset, value
        self.tap, self.scripts, self.sweep, self.id, self.record, self.delay = tap, scripts, sweep, cid, record, delay

    def spk(self):
        return bytes(self.tap.scriptPubKey)


def path_nodes(b, i):
    """The nodes on leaf i's path, from the batch output down."""
    nodes, idx = [], i
    for level in b.levels:
        j = next(j for j, nd in enumerate(level) if nd["lo"] <= idx < nd["hi"])
        nodes.append(level[j])
        idx = j
    return nodes[::-1]


def chain_batch(label, asset, n, at, owner, value, issuer_label):
    issuer = label_hash("outpoint", issuer_label)
    token = records.issued_asset(issuer, 0)
    p = {"genesis": GENESIS, "asset": asset, "operator": S.x, "token": token, "notice": records.NOTICE,
         "expiries": [CREATED + 28 * records.DAY, CREATED + 56 * records.DAY], "burn": False, "radix": 4,
         "node_reserve": 2_500, "entry_reserve": 1_000}
    preimages = [label_hash("preimage", "%s %d" % (label, i)) for i in range(n)]
    leaves = [{"owner": owner.x if i == at else Key("%s bystander %d" % (label, i)).x,
               "owner_nonce": label_hash("owner nonce", "%s %d" % (label, i)),
               "operator_nonce": label_hash("operator nonce", "%s %d" % (label, i)),
               "value": value, "exit_delay": DELAY, "unlock_hash": sha256(preimages[i])} for i in range(n)]
    b = records.Batch(p, leaves)
    # The round: the issuing input, the batch output at 0, the token's atom at 1, the fee.
    tx = Tx()
    tx.nVersion, tx.nLockTime = 2, 0
    vin = CTxIn(COutPoint(uint256_from_str(issuer), 0), nSequence=0xffffffff)
    iss = CAssetIssuance()
    iss.assetBlindingNonce, iss.assetEntropy = 0, 0
    iss.nAmount, iss.nInflationKeys, iss.denomination = CTxOutValue(1), CTxOutValue(), 0
    vin.assetIssuance = iss
    tx.vin = [vin]
    tx.vout = [txout(asset, b.root["value"], b.batch_spk()), txout(token, 1, b.clocks[0]["spk"]), txout(asset, 2_000, b"")]
    ArkBase.pad(tx)
    # The leaf at `at`: its record, with its entry's preimage and its owner's
    # unroll authorisations for time CREATED.
    rec = b.record(at)
    rec_bytes = records.encode(rec)
    auths = [owner.sign(unroll_auth3([(asset, k["value"], k["prog"]) for k in nd["kids"]], CREATED))
             for nd in path_nodes(b, at)]
    record = (b"\x00" + le16(len(rec_bytes)) + rec_bytes + preimages[at] + bytes([len(auths)])
              + b"".join(a + struct.pack("<I", CREATED) for a in auths))
    tap = b.leaf_taps[at]
    lprog = bytes(tap.scriptPubKey)[2:]
    cid = records.leaf_id(b.batch_spk()[2:], rec, lprog)
    salt = leaf_salt(leaves[at]["owner_nonce"], leaves[at]["operator_nonce"])
    sweep = sweep_token(token, b.r_spk[2:], S.x, SEQ_TIME | records.NOTICE)
    _, scripts = leaf3_taptree(owner.x, S.x, salt, CTAG, SEQ_TIME | DELAY, fold=True)
    return Coin(owner, salt, asset, value, tap, scripts, sweep, cid, record), tx


def new_leaf(label):
    k = Key("chain %s" % label)
    on, opn = label_hash("owner nonce", "chain %s" % label), label_hash("operator nonce", "chain %s" % label)
    tap, scripts, salt = leaf(k, on, opn)
    return {"key": k, "owner_nonce": on, "operator_nonce": opn, "tap": tap, "scripts": scripts, "salt": salt}


def hop(inputs, outputs, txs):
    """A reassignment of `inputs` [(coin, outpoint, checkpoint value)] into
    `outputs` [(asset, value, spk)]: the checkpoint transactions, the
    reassignment, appended to `txs`; returns per input (cp value, cp pair, re
    pair) and the reassignment's transaction."""
    parts, cps, ins = [], [], []
    for coin, at, v in inputs:
        cp_salt = checkpoint_salt(coin.salt)
        ctap, cscripts = checkpoint_taptree(coin.owner.x, S.x, cp_salt, CTAG, coin.sweep)
        cspk = bytes(ctap.scriptPubKey)
        cpd = rebind_msg3(CTAG, coin.salt, coin.asset, coin.value, [(coin.asset, v, cspk)], fold=True)
        red = rebind_msg3(CTAG, cp_salt, coin.asset, v, outputs, fold=True)
        cp_pair, re_pair = (S.sign(cpd), coin.owner.sign(cpd)), (S.sign(red), coin.owner.sign(red))
        i, o = with_fee([(at, (coin.asset, coin.value, coin.spk()), FINAL)], [(coin.asset, v, cspk)], "reserve", FINAL)
        b = Built(i, o)
        b.witness(0, list(cp_pair) + [bytes([1]), bytes(coin.scripts["collab"]), control_block(coin.tap, "collab")])
        d = b.json()
        d["name"] = "checkpoint of %s" % coin.id.hex()
        txs.append(d)
        cps.append(coin_at(b.tx, 0))
        ins.append((cps[-1], (coin.asset, v, cspk), FINAL))
        parts.append((coin, v, cp_pair, re_pair, ctap, cscripts))
    i, o = with_fee(ins, outputs, "reserve", FINAL)
    b = Built(i, o)
    for k, (coin, v, cp_pair, re_pair, ctap, cscripts) in enumerate(parts):
        b.witness(k, list(re_pair) + [bytes([len(outputs)]), bytes(cscripts["collab"]), control_block(ctap, "collab")])
    return parts, b


def transfer_record(parts, outputs, index, nl):
    r = b"\x01" + bytes([len(parts)])
    for coin, v, cp_pair, re_pair, _, _ in parts:
        r += coin.record + le64(v) + cp_pair[0] + cp_pair[1] + re_pair[0] + re_pair[1]
    r += bytes([len(outputs)])
    for a, v, spk in outputs:
        r += a + le64(v) + compact(len(spk)) + spk
    r += bytes([index]) + nl["key"].x + nl["owner_nonce"] + nl["operator_nonce"] + le16(DELAY)
    return r


def transfer_coin(parts, outputs, index, nl, asset, value):
    msg = bytes([len(parts)])
    for coin, _, _, _, ctap, _ in parts:
        msg += coin.id + bytes(ctap.scriptPubKey)[2:]
    msg += bytes([len(outputs)]) + b"".join(sha256(record(a, v, spk)) for a, v, spk in outputs)
    lprog = bytes(nl["tap"].scriptPubKey)[2:]
    cid = tagged_hash(LEAF_ID_TAG, tagged_hash(REASSIGNMENT_TAG, msg) + b"\x01" + bytes([index]) + lprog)
    first = parts[0][0]
    return Coin(nl["key"], nl["salt"], asset, value, nl["tap"], nl["scripts"], first.sweep, cid,
                transfer_record(parts, outputs, index, nl))


def transfer():
    a, c = Key("chain A"), Key("chain C")
    a_coin, round1 = chain_batch("chain batch 1", ASSET, 5, 2, a, 10_000_000, "chain batch 1 issuer")
    c_coin, round2 = chain_batch("chain batch 2", Y_ASSET, 3, 1, c, 5_000_000, "chain batch 2 issuer")
    bases = {a_coin.id.hex(): outpoint("chain A's leaf"), c_coin.id.hex(): outpoint("chain C's leaf")}
    txs, records_out = [], {}

    # Hop 1: A pays B 7,000,000 of X, change to a new leaf of A's.
    b1, ach = new_leaf("B1"), new_leaf("A change")
    cp1 = a_coin.value - MARGIN
    out1 = [(ASSET, 7_000_000, bytes(b1["tap"].scriptPubKey)), (ASSET, cp1 - 7_000_000 - MARGIN, bytes(ach["tap"].scriptPubKey))]
    parts1, re1 = hop([(a_coin, bases[a_coin.id.hex()], cp1)], out1, txs)
    b1_coin = transfer_coin(parts1, out1, 0, b1, ASSET, 7_000_000)
    ach_coin = transfer_coin(parts1, out1, 1, ach, ASSET, out1[1][1])
    d = re1.json()
    d["name"] = "reassignment creating %s" % b1_coin.id.hex()
    txs.append(d)

    # Hop 2: B gives X, C gives Y; B receives the Y, C the X.
    b2, c2 = new_leaf("B2"), new_leaf("C2")
    cp_b, cp_c = b1_coin.value - MARGIN, c_coin.value - MARGIN
    out2 = [(Y_ASSET, cp_c, bytes(b2["tap"].scriptPubKey)), (ASSET, cp_b - MARGIN, bytes(c2["tap"].scriptPubKey))]
    parts2, re2 = hop([(b1_coin, coin_at(re1.tx, 0), cp_b), (c_coin, bases[c_coin.id.hex()], cp_c)], out2, txs)
    b2_coin = transfer_coin(parts2, out2, 0, b2, Y_ASSET, cp_c)
    c2_coin = transfer_coin(parts2, out2, 1, c2, ASSET, cp_b - MARGIN)
    d = re2.json()
    d["name"] = "reassignment creating %s" % b2_coin.id.hex()
    txs.append(d)

    # Hop 3: B pays the Y on to D.
    dl = new_leaf("D")
    cp3 = b2_coin.value - MARGIN
    out3 = [(Y_ASSET, cp3 - MARGIN, bytes(dl["tap"].scriptPubKey))]
    parts3, re3 = hop([(b2_coin, coin_at(re2.tx, 0), cp3)], out3, txs)
    d_coin = transfer_coin(parts3, out3, 0, dl, Y_ASSET, cp3 - MARGIN)
    d = re3.json()
    d["name"] = "reassignment creating %s" % d_coin.id.hex()
    txs.append(d)

    for name, coin in (("B1", b1_coin), ("A change", ach_coin), ("B2", b2_coin), ("C2", c2_coin), ("D", d_coin)):
        records_out[name] = {"binary": (b"\x01" + coin.record).hex(), "id": coin.id.hex(), "owner": coin.owner.x.hex(),
                             "owner_nonce": label_hash("owner nonce", "chain %s" % name).hex()}
    return {
        "inputs": {"now": CREATED, "y_asset": display(Y_ASSET),
                   "rounds": [round1.serialize().hex(), round2.serialize().hex()],
                   "bases": {k: v[0] for k, v in bases.items()}, "margin": MARGIN},
        "records": records_out,
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
        "transfer": transfer(),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(generate(), indent=1))
