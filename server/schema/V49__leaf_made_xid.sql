-- The transaction that made each leaf, for `leaf_data`'s reads past a
-- settled cursor (`since`). A leaf's `seq` is drawn when it is inserted and
-- seen when its transaction commits, so a transaction that commits late
-- shows a leaf behind one a reader has read past already. A read past a
-- settled cursor orders leaves by the transaction that made them, then by
-- `seq`, and serves only leaves made by transactions older than every one
-- still running (`pg_snapshot_xmin`): nothing can still appear behind its
-- cursor. Leaves made before this column read as made by transaction 0.
-- Adding the column with no default, then setting one, leaves the rows
-- there as they are.
ALTER TABLE leaf ADD COLUMN made_xid xid8;
ALTER TABLE leaf ALTER COLUMN made_xid SET DEFAULT pg_current_xact_id();
