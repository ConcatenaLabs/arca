-- A key a participation wants is promised to the leaf its round makes, and
-- to nothing else, while the participation stands. Once it is void or
-- expired, its leaf (if its round made one) was never credited, and the key
-- is free again: another payment to it, or another participation wanting
-- it, may take it.
ALTER TABLE participation_output ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;
UPDATE participation_output o SET active = false
	FROM participation p WHERE p.participation_id = o.participation_id AND p.state IN ('void', 'expired');
DROP INDEX participation_output_owner_key;
CREATE UNIQUE INDEX participation_output_owner_key ON participation_output (owner_key) WHERE kind = 'leaf' AND active;

-- A leaf never credited, of a participation that expired, holds no key.
DROP INDEX leaf_owner_key_key;
CREATE UNIQUE INDEX leaf_owner_key_key ON leaf (owner_key) WHERE state NOT IN ('lost', 'expired');
