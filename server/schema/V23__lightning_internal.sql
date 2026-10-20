-- A payment into the tree held by a payment out of it at the same operator
-- (server/src/lightning/receive.rs, `take_internal`): the payer's htlc-1 send
-- leaf is the held payment, in place of a Lightning payment held at the
-- node, and the receiver's leaf times out a gap before that leaf does.
ALTER TABLE lightning_receive ADD COLUMN held_by_send BOOLEAN NOT NULL DEFAULT false;
-- The send leaf's timeout (a median time), by which the receive must be
-- decided.
ALTER TABLE lightning_receive ADD COLUMN send_timeout BIGINT;
ALTER TABLE lightning_receive ADD CONSTRAINT lightning_receive_held_by_send_check
	CHECK (NOT held_by_send OR (send_timeout IS NOT NULL AND htlc_expiry IS NULL));
