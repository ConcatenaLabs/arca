-- A participation run again after a round that can never return runs as an
-- ordinary one: its forfeit for the new round is taken and its preimage
-- released against it. A participation that will never run says why. A
-- forfeit in the watcher's log names its round, so that no forfeit of a
-- round that can never return is broadcast again.
ALTER TABLE participation DROP COLUMN forfeit_first;
ALTER TABLE participation ADD COLUMN void_reason TEXT;
ALTER TABLE watcher_tx ADD COLUMN round_id BIGINT REFERENCES round;
