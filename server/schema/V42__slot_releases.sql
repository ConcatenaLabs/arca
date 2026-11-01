-- An owner's release of its slot in an accumulator batch without a sweep
-- (`arca/accumulator-2`), given up in a participation, for the round of one
-- of its attempts: its signature, with the slot's key, over
-- SHA256(SHA256("Arca/accumulator-release") ‖ genesis_hash ‖ ROOT ‖ rec_j ‖ M),
-- ROOT the batch's root, rec_j the slot's record and M that round's connector
-- asset. A release of the batch needs an atom of M among its inputs, so the
-- release is void unless that round is in the chain. Taken only after the
-- participation's preimage went out, while its round is final, and never for
-- a coin with an open out-of-round reassignment, as a lowest node's release
-- (`node_release`). The watcher releases the slots of a batch whose owners
-- released them, up to 14 in one transaction, and the slot's value is the
-- operator's.
CREATE TABLE IF NOT EXISTS slot_release (
	leaf_id          BYTEA NOT NULL REFERENCES leaf,
	round_id         BIGINT NOT NULL REFERENCES round,
	participation_id BYTEA NOT NULL REFERENCES participation,
	connector_asset  BYTEA NOT NULL CHECK (length(connector_asset) = 32),
	signature        BYTEA NOT NULL CHECK (length(signature) = 64),
	-- Set while the round is lost: its M is not issued, and the release is
	-- not used. Cleared if the round is restored.
	retired          BOOLEAN NOT NULL DEFAULT false,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (leaf_id, round_id)
);
