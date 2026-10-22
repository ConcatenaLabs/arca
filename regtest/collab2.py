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

COLLAB_CMR = bytes.fromhex("83bd261c1cafb63fda7cc7cdc00cca55f25b4bbd9e768ae46b71af64349927a0")
COLLAB_PROGRAM = bytes.fromhex(
    "e946ba050e8143a050e8143a050e8143a050830e38e38e38da0e38e38e36e38e38e16416d276741081420c370c3855aae40840a0da4dc4871c70b101a902837023f169c71c70b201c11028370cd588201801bc0e12071181c524d800023e1c5e0842450ce8867390b3cffedf1a67f35f4e6e69c39210d09fddb9189a14c225a77e6c262e17218140cc2dacdba01180420c38e385c11a701a0803558080385859b4e01410070036f38e171080da0706b004071385900d8070bf85071610284d88000020178c4fc38502c081420c38d451a701c410071827564083f00141b9527e354902a162372bd07248150b21b96c6e4118720e30e3e070a85a02d837306839240a8590dcc520e4902a164373226dc61c7e1661c7e1c70a85985ac6e674dca930e41c61c7c0e150b405b09a8021071c2c08141b97c234b4108141f984334c68210283737e71c71b98e38e38e3ee140b40fccb1c6e660e1501ccaa0506e74ce481cc10273647d82816040a0fa4dcc177080401cd98b101cef03403c040e08070d20506e7a8fc486e3338542c406a40a0fc8038e393601008160cdb4108141b9ff38a240c032038181c340e4481c900392e072840e5781cbc09cc0939842f3042e6102e61c0661c40cc0e630273224e650bcc90b9940b9970198710330399c039aa09cd7939b22f3602e6c82e6d40661c40cc0e6e82737ec5f8bdd59a0d0ed8d3bb22cb0ef50f71e3a577040de5bfe99608095e7d53356765e7005ce105ce200cc3881981ce490283741a373837d4117120671d935311563277b133e5c2a486b72ed4ccb3ccde95b1c35bf8601804c92073aa7e7d4e385805cc672e80e8051398a3f31e9b005040b001c8c40a0fcc51c5120601901b79fc06ee82c13800a84d87d66e7ebb40200e82b16203a158a06907781c380e6b80e6e00e7180e74c273b00e4a50f1e0140e77c273c80e4850f2500a073d6073f2139fe072328790e0503a0142740513a0318322b03a0ce13d59ef8c6d6cad318d9aa1cc534d1093ec0905523b6c20e6418f4300c00e3b20506e87c0b9100a131481d0388141ba210fd11a71c71c903a0984e8a637446a6cd05c98d85498990c4102c1aae00840a0dd12c9f87188205800e89640a0dd13c074411fa2e8e3858120742020506e8a83f44f8a00e8a640a0dd15c7e89c385407456a0506e8b503a264140d60702038381c380e27038c40e350b8ec0745da0506e8c33f4331c71c2c5aad0420506e8cd3f4339c71c70b26aa0420506e8d83f34a71c71c074608b301d1b68141ba38cfcd39c71c71c2cc070740a0dd1dc7e599c71c71c0746c0b400e8f240a0dd1f40746f20507e9089c71c71c71c71c71c6e9120a0dca638e38e38e38e38e38e385bdb18083f48a8e38e38e38e38e38e13879b98438e38e38e38e38e38e16e01c352283f49a4102e210141c820390e072500e5001cac039700730607386073900740805d1cc03783a3c00e8fa0ba3fc0703174818070517483807071748580709174884070b0749c80e93b01d27a03a4fc074a080e94301d28a0")
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
