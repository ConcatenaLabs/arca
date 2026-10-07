-- The keepers of the operator's signer's record, as the server first read
-- them from its signer: their x-only keys in the record's order, hex, comma
-- separated (empty for an operator with no keeper), and how many must hold
-- every head. They are part of the operator's identity, fixed in its record
-- when it was made, so the server pins them as a wallet does and refuses to
-- start against a signer that names another set: one whose record was
-- replaced or edited, a compacted record's first line included.
CREATE TABLE keepers_pinned (
	one        BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
	keys       TEXT NOT NULL,
	required   INTEGER NOT NULL CHECK (required >= 0),
	pinned_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
