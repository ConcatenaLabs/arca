#!/usr/bin/env python3
"""Golden vectors for the vtxo-2 leaf: the collaborative path arca/collab-2.

vectors.py writes them to vectors/collab2.json and checks them in CI.
Everything here is derived independently of the Rust crate, from the tagged
hashes themselves (the tree mixes a Simplicity leaf, a hidden data leaf and a
tapscript leaf, which the functional test framework's taproot_construct cannot
express):

    leaf:        root = TapBranch( TapBranch(F, D), exit )
    checkpoint:  root = TapBranch( TapBranch(F, D), sweep )
    F = TapLeaf_0xbe(CMR), D = H_TapData(owner || operator || salt)

Both keys sign SHA256(K || k || n || I || m || O): K the salt's own constant
(as vtxo-1's), k the coin's input index (4 bytes big-endian), n and I the
inputs the signers name (I hashes each one's input_utxo_hash: asset, amount
and script, never its outpoint), m and O the outputs (O hashes each one's
output_hash). The commitment root and the pruned program are
sequentia-contracts' (templates/arca_collab/collab.json).
"""
from arklib3 import *                      # noqa: F401,F403
from test_framework.key import TaggedHash, tweak_add_pubkey

COLLAB_CMR = bytes.fromhex("0ac093395a590bea632fc8424d29b77bcd9702fb6a685b60c879df141b6dbf9c")
COLLAB_PROGRAM = bytes.fromhex(
    "e94c3a050e8143a050e8143a050e8143a050830e38e38e38da0e38e38e36e38e38e16416d276741081420c370c3855aae40840a0da4dc4871c70b101a902837023f169c71c70b201c11028370cd588201801bc0e12071181c524d800023e1c5e0842450ce8867390b3cffedf1a67f35f4e6e69c39210d09fddb9189a14c225a77e6c262e17218140cc2dacdba0118047c383038112534440d7fa8b066064fc76756c5a00fd4bf77afe303a974c6923ab0d26d3674b2f0601c000c806a41871c70b86b4e034100703b0100712059b4e01410070936f38e171500da070fb004071805900d807127c2838d481426c40000100bc747e1c2816040a1061c6a28d380e208038e53ab2041f800a0dcb23f1aa48150b11b970839240a8590dcbf37208c39071871f038542d016c1b98c41c920542c86e64d07248150b21b99a36e30e3f0b30e3f0e38542cc2d63734c6e5498720e30e3e070a85a02d84d4010838e16040a0dcbe11a5a0840a0fcc219a634108141b9c838e38dcc71c71c71f70a05a07e658e3733070a80e655028373b87240e608139bb3ec140b020507d26e60bb840200e6f05880e79c1a01e02070403869028373e67e2437199c2a16203520507e401c71c9b008040b066da0840a0dd01071448180640703038681c89039200725c0e5081caf0397813981273085e6085cc205cc380cc3881981cc604e6449cca17992173281732e0330e20660733807354139af273645e6c05cd905cda80cc3881981cdd04e6fd8bf17bab341a1db1a77645961dea1ee3c74aee081bcb7fd32c1012bcfaa66acecbce00b9c20b9c4019871033039c920506e83d6e706fa822e240ce3b26a622ac64ef6267cb85490d6e5da9996799bd2b6386b7f0c030099240e754fcfa9c70b00b98ce5d01d00a273147e63d3600a08160039188141f98a38a240c032036f3f80ddd06a27001509b0facdcfd7680401d0682c40742f940d20ef038701cd701cdc01ce301ce984e7601c94a1e3c0281cef84e7901c90a1e4a0140e7ac0e7e4273fc0e4650f21c0a0740284e80a2740630645607419c27ab3df18dad95a631b354398a69a2127d8120aa476d841cc831e8601801c7640a0dd10a1722014262903a071028374469fa258e38e3920741309d15e6e8964d9a0b931b0a931321882058355c0108141ba27d3f0e31040b001d13e8141ba29c0e88b3f4619c70b0240e84040a0dd1627e8a81401d15e8141ba2dcfd14a70a80e8b640a0dd17c074510281ac0e040707038701c4e071881c6a171d80e8c440a0dd1987e86638e3858b55a0840a0dd1ac7e86738e38e164d540840a0dd1c27e694e38e380e8ca16603a391028374761f9a738e38e385980e0e8141ba3dcfcb338e38e380e8e116801d1f68141ba40607473a0507e90d1c71c71c71c71c71c6e9168a0dca638e38e38e38e38e38e385bdb18083f48cce38e38e38e38e38e13879b98438e38e38e38e38e38e16e01c352283f49c8102e210141c820390e072500e5001cac039700730607386073900740805d1cc03783a3c00e8fa0ba3fc0703174818070517483807071748580709174884070b1748b0070d0749f40e94081d28503a512074a340e94881d2950")
LEAF_TAPSCRIPT = 0xc4
LEAF_SIMPLICITY = 0xbe


def tapleaf(version, script):
    assert len(script) < 0xfd
    return TaggedHash("TapLeaf/elements", bytes([version, len(script)]) + script)


def tapbranch(a, b):
    return TaggedHash("TapBranch/elements", min(a, b) + max(a, b))


def output_of(root):
    """(output key, odd) of the NUMS internal key and root."""
    return tweak_add_pubkey(NUMS, TaggedHash("TapTweak/elements", NUMS + root))


def control_block(version, root, path):
    return bytes([version | (1 if output_of(root)[1] else 0)]) + NUMS + b"".join(path)


def be8(n):
    return n.to_bytes(8, "big")


def utxo_hash(asset, value, spk):
    """Simplicity's input_utxo_hash of an explicit coin."""
    return sha256(b"\x01" + asset + b"\x01" + be8(value) + sha256(spk))


def output_hash(asset, value, spk):
    """Simplicity's output_hash of an explicit output with no nonce."""
    return sha256(b"\x01" + asset + b"\x01" + be8(value) + b"\x00" + sha256(spk) + sha256(b""))


class Collab2:
    """A vtxo-2 leaf (other = its exit) or checkpoint (other = its sweep)."""

    def __init__(self, owner, operator, salt, ctag, other):
        self.owner, self.operator, self.salt, self.ctag, self.other = owner, operator, salt, ctag, other
        self.data = owner + operator + salt
        self.data_leaf = TaggedHash("TapData", self.data)
        self.program_leaf = tapleaf(LEAF_SIMPLICITY, COLLAB_CMR)
        self.other_leaf = tapleaf(LEAF_TAPSCRIPT, bytes(other))
        self.left = tapbranch(self.program_leaf, self.data_leaf)
        self.root = tapbranch(self.left, self.other_leaf)
        self.spk = b"\x51\x20" + output_of(self.root)[0]

    def preimage(self, k, named, outs):
        """K || k || n || I || m || O; named and outs are (asset, value, spk)."""
        assert 1 <= len(named) <= 16 and k < len(named) and 1 <= len(outs) <= 4
        i = sha256(b"".join(utxo_hash(*c) for c in named))
        o = sha256(b"".join(output_hash(*c) for c in outs))
        b = leaf_const(self.ctag, self.salt, fold=True) + k.to_bytes(4, "big") + bytes([len(named)]) + i + bytes([len(outs)]) + o
        assert len(b) == 102
        return b

    def json(self):
        return {
            "params": self.data.hex(), "data_leaf": self.data_leaf.hex(), "program_leaf": self.program_leaf.hex(),
            "other": bytes(self.other).hex(), "merkle_root": self.root.hex(), "script_pubkey": self.spk.hex(),
            "control_blocks": {
                "collab": control_block(LEAF_SIMPLICITY, self.root, [self.data_leaf, self.other_leaf]).hex(),
                "other": control_block(LEAF_TAPSCRIPT, self.root, [self.left]).hex(),
            },
        }


def spend(c, owner, s, k, named, outs):
    """The digest, both signatures and the Simplicity witness of a spend of
    c at input k naming named and committing to outs."""
    pre = c.preimage(k, named, outs)
    d = sha256(pre)
    a_sig, s_sig = owner.sign(d), s.sign(d)
    return {
        "index": k,
        "named": [{"asset": a.hex(), "value": v, "script_pubkey": spk.hex()} for a, v, spk in named],
        "outputs": [{"asset": a.hex(), "value": v, "script_pubkey": spk.hex()} for a, v, spk in outs],
        "preimage": pre.hex(), "rest": pre[32:].hex(), "digest": d.hex(),
        "owner_signature": a_sig.hex(), "operator_signature": s_sig.hex(),
        "witness": (c.data + bytes([len(named), len(outs)]) + a_sig + s_sig).hex(),
    }


def generate(genesis, keys, label_hash, delay, sweep, token, r_program, notice):
    """The vectors: a vtxo-2 leaf, its checkpoint, a spend of each (the
    leaf alone into its checkpoint; the checkpoint at index 1 of a swap's
    reassignment beside another owner's), and the program."""
    a, b, s = keys["A"], keys["B"], keys["S"]
    x = label_hash("asset", "X")
    ctag = chain_tag(genesis)
    salt = label_hash("salt", "vtxo-2 leaf")
    leaf = Collab2(a.x, s.x, salt, ctag, exit_leaf(a.x, delay))
    cp_salt = sha256(b"Arca/checkpoint" + salt)
    cp = Collab2(a.x, s.x, cp_salt, ctag, sweep)
    value, cp_value = 10_000_000, 9_998_800
    to_cp = spend(leaf, a, s, 0, [(x, value, leaf.spk)], [(x, cp_value, cp.spk)])
    other_cp = (x, 5_000_000, b"\x51\x20" + label_hash("output", "another owner's checkpoint"))
    outs = [(x, 5_000_000 - 1_200, b"\x51\x20" + label_hash("output", "to A")),
            (x, cp_value - 1_200, b"\x51\x20" + label_hash("output", "to B"))]
    swap = spend(cp, a, s, 1, [other_cp, (x, cp_value, cp.spk)], outs)
    return {
        "genesis": genesis.hex(),
        "keys": {k: v.x.hex() for k, v in keys.items()},
        "cmr": COLLAB_CMR.hex(), "program_sha256": sha256(COLLAB_PROGRAM).hex(), "program_bytes": len(COLLAB_PROGRAM),
        "exit_delay_sequence": delay,
        "sweep": {"token": token.hex(), "r_program": r_program.hex(), "operator": s.x.hex(), "notice": notice},
        "leaf": dict(leaf.json(), salt=salt.hex(), value=value),
        "checkpoint": dict(cp.json(), salt=cp_salt.hex(), value=cp_value),
        "spends": {"leaf_into_checkpoint": to_cp, "checkpoint_in_a_swap": swap},
    }
