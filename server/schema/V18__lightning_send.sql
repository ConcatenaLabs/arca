-- Payments out of the tree over Lightning (`crate::lightning::send`).
--
-- A wallet gives up coins into an htlc-1 leaf the operator can claim with the
-- preimage of an invoice, and the operator pays the invoice through its node
-- in the coins' asset. One row per payment hash: a hash is paid once. The
-- row is written before the transfer is co-signed, and its state moves only
-- forward: `paying` until the node's answer is known, then `paid` with the
-- preimage (the htlc-1 coin is then the operator's to claim, and is never
-- co-signed back), or `failed` once no part of the payment is left pending
-- on the node (the coin may then go back to its owner, co-signed).
CREATE TABLE lightning_send (
	payment_hash BYTEA PRIMARY KEY CHECK (length(payment_hash) = 32),
	asset        BYTEA NOT NULL CHECK (length(asset) = 32),
	invoice      TEXT NOT NULL,
	-- What the invoice asks, and the operator's fee, in the asset's atoms.
	amount       BIGINT NOT NULL CHECK (amount > 0),
	fee          BIGINT NOT NULL CHECK (fee >= 0),
	-- The transfer that makes the htlc-1 coin, and the coin.
	transfer_id  BYTEA NOT NULL CHECK (length(transfer_id) = 32),
	htlc_leaf_id BYTEA NOT NULL CHECK (length(htlc_leaf_id) = 32),
	state        TEXT NOT NULL CHECK (state IN ('paying', 'paid', 'failed')),
	preimage     BYTEA CHECK (preimage IS NULL OR length(preimage) = 32),
	reason       TEXT,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK ((state = 'paid') = (preimage IS NOT NULL))
);
CREATE UNIQUE INDEX lightning_send_by_leaf ON lightning_send (htlc_leaf_id);
CREATE INDEX lightning_send_paying ON lightning_send (state) WHERE state = 'paying';

-- The watcher claims the htlc-1 coin of a paid payment that comes on-chain,
-- with the preimage, after the operator's delay.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim'));
