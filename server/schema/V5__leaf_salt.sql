-- Every leaf salt the server has seen: on a leaf it knows (a board, a leaf of
-- a batch, an output of a transfer), or promised to a leaf a participation
-- wants (one for each attempt, since each attempt draws a new operator
-- nonce). A salt is unique on a server: a board, a transfer or a
-- participation whose new leaf would take a salt listed here is refused
-- (`salt`), and a salt stays listed for good, whatever becomes of its leaf.
-- The signer keeps its record per leaf (owner key and salt), so a salt the
-- database has forgotten still changes nothing for another holder's leaf.
CREATE TABLE leaf_salt (
	salt             BYTEA PRIMARY KEY CHECK (length(salt) = 32),
	-- The leaf that took it, once there is one.
	leaf_id          BYTEA CHECK (leaf_id IS NULL OR length(leaf_id) = 32),
	-- The participation that wants a leaf under it.
	participation_id BYTEA CHECK (participation_id IS NULL OR length(participation_id) = 32),
	added_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK (leaf_id IS NOT NULL OR participation_id IS NOT NULL)
);
CREATE UNIQUE INDEX leaf_salt_leaf_id ON leaf_salt (leaf_id);

-- The salts of what a database written before this table already holds. A
-- leaf's salt is SHA256("Arca/salt" ‖ owner nonce ‖ second nonce).
-- Leaves of batches, from the nonces kept beside them:
INSERT INTO leaf_salt (salt, leaf_id, participation_id)
SELECT sha256('Arca/salt'::bytea || owner_nonce || operator_nonce), leaf_id, participation_id FROM batch_leaf
ON CONFLICT DO NOTHING;
-- Leaves participations still want, under their current attempt's nonce:
INSERT INTO leaf_salt (salt, participation_id)
SELECT sha256('Arca/salt'::bytea || owner_nonce || operator_nonce), participation_id FROM participation_output
WHERE kind = 'leaf' AND leaf_id IS NULL
ON CONFLICT DO NOTHING;
-- Boards, from their record (version 2: version, template, template version,
-- owner key, owner nonce at byte 35, operator nonce at byte 67):
INSERT INTO leaf_salt (salt, leaf_id)
SELECT sha256('Arca/salt'::bytea || substring(record FROM 36 FOR 32) || substring(record FROM 68 FOR 32)), leaf_id FROM board
WHERE get_byte(record, 0) = 2 AND length(record) >= 99
ON CONFLICT DO NOTHING;
-- Outputs of transfers, from their coin record, which ends with the coin's
-- leaf: owner key, owner nonce, creator nonce, exit delay (u16). A transfer
-- whose signatures were never made holds no record yet, and is left out.
INSERT INTO leaf_salt (salt, leaf_id)
SELECT sha256('Arca/salt'::bytea || substring(record FROM length(record) - 65 FOR 32)
	|| substring(record FROM length(record) - 33 FOR 32)), leaf_id FROM leaf
WHERE kind = 'transfer' AND length(record) >= 99 AND substring(record FROM length(record) - 97 FOR 32) = owner_key
ON CONFLICT DO NOTHING;
