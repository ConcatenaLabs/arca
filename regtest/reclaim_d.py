"""RECLAIM-D's golden vectors (vectors/reclaim_d.json), from the constructions
T25 proves on the node: a lowest node of four owners with RECLAIM and
RECLAIM-D, the delegation and release messages, and the items below
RECLAIM-D for a coin paid twice, a swap and a direct release together.

Signatures are BIP340 with zero auxiliary randomness, so they regenerate.
"""
from arklib3 import *                      # noqa: F401,F403


def generate(genesis, keys, label_hash, expiry):
    """keys: S, A0..A3 (the owners), B, A0c, C, Bc, X2, X3."""
    S = keys["S"]
    owners = [keys["A%d" % i] for i in range(4)]
    asset = label_hash("asset", "X")
    kids = [(asset, 10_000_000 + 1_000, label_hash("program", "entry %d" % i)) for i in range(4)]
    prefix = release_prefix(genesis, kids)
    dprefix = delegate_prefix(genesis)
    unroll = CScript(unroll_compact_body(kids))
    sweep = sweep_leaf(expiry, S.x)
    reclaim = reclaim_leaf(prefix, [k.x for k in owners], S.x)
    reclaim_d = reclaim_delegated_leaf(prefix, dprefix, [k.x for k in owners], S.x)
    tap, lv = node_taptree_delegated(unroll, sweep, reclaim, reclaim_d)
    m1 = label_hash("asset", "M of round 1")
    m2 = label_hash("asset", "M of round 2")

    def rel(k, m, at):
        return rel_node(k.x, k.sign(sha256(prefix + m)), at)

    def dele(k, kids_):
        return del_node(k.x, k.sign(delegate_msg(genesis, [c[1] for c in kids_])), kids_)

    def tree_json(t):
        if t[0] == "rel":
            return {"release": {"key": t[1].hex(), "sig": t[2].hex(), "connector_input": t[3]}}
        return {"delegation": {"key": t[1].hex(), "sig": t[2].hex(), "to": [tree_json(c) for c in t[3]]}}

    B, A0c, C, Bc, X2, X3 = (keys[n] for n in ["B", "A0c", "C", "Bc", "X2", "X3"])
    tb = dele(B, [rel(C, m1, 1), rel(Bc, m2, 2)])
    swap = [rel(X2, m2, 2), rel(X3, m1, 1)]
    trees = [dele(owners[0], [tb, rel(A0c, m1, 1)]), rel(owners[1], m1, 1), dele(owners[2], swap), dele(owners[3], swap)]
    s_sig = S.sign(label_hash("digest", "the reclaim's signature hash"))
    items = reclaim_delegated_items(s_sig, prefix, dprefix, trees)
    return {
        "genesis_internal": genesis.hex(),
        "operator": S.x.hex(),
        "owners": [k.x.hex() for k in owners],
        "keys": {n: keys[n].json() for n in sorted(keys)},
        "children": [{"asset": a.hex(), "value": v, "program": p.hex()} for a, v, p in kids],
        "release_prefix": prefix.hex(),
        "delegation_prefix": dprefix.hex(),
        "steps": RECLAIM_STEPS,
        "step_script": CScript(reclaim_step()).hex(),
        "scripts": {"unroll": unroll.hex(), "sweep": sweep.hex(), "reclaim": reclaim.hex(), "reclaim_d": reclaim_d.hex()},
        "script_pubkey": tap.scriptPubKey.hex(),
        "control_blocks": {n: control_block(tap, n).hex() for n in ["unroll", "sweep", "reclaim", "reclaim_d"]},
        "delegation": {"from": B.x.hex(), "to": [C.x.hex(), Bc.x.hex()],
                       "digest": delegate_msg(genesis, [C.x, Bc.x]).hex()},
        "release": {"connector": m1.hex(), "digest": sha256(prefix + m1).hex()},
        "operator_sig": s_sig.hex(),
        "trees": [tree_json(t) for t in trees],
        "items": [i.hex() for i in items],
    }
