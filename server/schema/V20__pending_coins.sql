-- A transfer recorded and not yet signed posts each of its outputs to the
-- output's mailbox as pending at once, and a transfer dropped before it was
-- signed withdraws them there, naming why (D61): a receiver learns of a coin
-- coming while its sender's post waits, and keeps reading until it comes or
-- is withdrawn. A notice carries its leaf in its payload, not as a reference:
-- a dropped transfer's coins are deleted with it.
ALTER TABLE mailbox_message DROP CONSTRAINT mailbox_message_kind_check;
ALTER TABLE mailbox_message ADD CONSTRAINT mailbox_message_kind_check CHECK (kind IN ('coin', 'pending', 'withdrawn'));
ALTER TABLE mailbox_message ADD CONSTRAINT mailbox_message_notice_has_no_leaf CHECK (kind = 'coin' OR leaf_id IS NULL);
