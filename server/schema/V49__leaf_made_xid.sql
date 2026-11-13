-- The transaction that made each leaf, and the one that bound each owner key
-- to its mailbox, for `leaf_data`'s reads past a settled cursor (`since`). A
-- leaf's `seq` is drawn when it is inserted and seen when its transaction
-- commits, so a transaction that commits late shows a leaf behind one a
-- reader has read past already; and a leaf bound to a mailbox after it was
-- made (a claimed coin, a coin of a wallet older than its mailbox key) is
-- served to that mailbox from the binding on. A read past a settled cursor
-- orders the leaves served to a mailbox by the later of the two
-- transactions, then by `seq`, and serves only leaves whose transactions
-- are older than every one still running (`pg_snapshot_xmin`): nothing can
-- still appear behind its cursor. Rows made before these columns read as
-- made by transaction 0. Adding a column with no default, then setting one,
-- leaves the rows there as they are.
ALTER TABLE leaf ADD COLUMN made_xid xid8;
ALTER TABLE leaf ALTER COLUMN made_xid SET DEFAULT pg_current_xact_id();
ALTER TABLE leaf_mailbox ADD COLUMN bound_xid xid8;
ALTER TABLE leaf_mailbox ALTER COLUMN bound_xid SET DEFAULT pg_current_xact_id();
