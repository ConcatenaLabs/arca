-- A strike names only a coin given up by a participation voided because its
-- forfeits did not come; a coin paid on from it is caught by its lineage
-- (`transfer_output` up to `transfer_input` and `order_fill.order_leaf`), and
-- a coin beside it, paid from the same parent, is not. Strikes written on
-- the batch leaves and boards such coins rested on, which caught every coin
-- beside them (a payer's change among them), are removed.
DELETE FROM held_strike h
WHERE NOT EXISTS (
	SELECT 1 FROM participation_input i
	JOIN participation p ON p.participation_id = i.participation_id
	WHERE i.leaf_id = h.leaf_id AND p.state = 'void'
);
