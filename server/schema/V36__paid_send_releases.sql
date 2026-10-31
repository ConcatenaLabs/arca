-- The sender of a paid Lightning payment out of the tree releases each
-- lowest node with RECLAIM-D its htlc-1 leaf rests on. It gives up no coin in
-- a participation, so its releases name a round and no participation.
ALTER TABLE node_release ALTER COLUMN participation_id DROP NOT NULL;
