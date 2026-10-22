-- The supervised profile (`supervision.rs`): an asset its issuer can freeze
-- by consensus rule is held in the tree only in landing-1 leaves, whose exit
-- pays the owner's own key, where the freeze binds.
--
-- A leaf wanted under landing-1: its landing, the program of the owner's
-- landing key (20 bytes) and the fee allowance (u64, little-endian), as the
-- leaf record writes them.
ALTER TABLE participation_output ADD COLUMN landing BYTEA
	CHECK (landing IS NULL OR (kind = 'leaf' AND length(landing) = 28));

-- A freeze the operator has seen, held until its lifting is final. The
-- operator reads its node after every pass over the chain (every script a
-- freeze record of a supervised asset it serves names, and the asset's
-- pause) and again at every decision about a coin. A target it has seen
-- frozen stays frozen in the tree until the node has shown it free at a block
-- that is now final (certified, its anchor buried), so an anchor-driven
-- reorganisation that restores the freeze on the chain finds it still held
-- here. `target` is the node's hash of the frozen script (`targethash`), or
-- 32 zero bytes for a pause of the asset, which freezes every holder.
-- `lifted_*` is the block at which the node first showed it free; empty
-- while it is frozen.
CREATE TABLE supervision_hold (
	asset          BYTEA NOT NULL CHECK (length(asset) = 32),
	target         BYTEA NOT NULL CHECK (length(target) = 32),
	seen_frozen_at BIGINT NOT NULL,
	lifted_hash    BYTEA CHECK (lifted_hash IS NULL OR length(lifted_hash) = 32),
	lifted_height  BIGINT,
	PRIMARY KEY (asset, target)
);
