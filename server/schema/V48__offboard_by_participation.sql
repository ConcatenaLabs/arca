-- The unlock lane reads the offboard outputs of the participations just
-- released (`Store::offboards_to_unlock`): by participation, not by a scan of
-- every offboard the operator ever made.
CREATE INDEX IF NOT EXISTS round_offboard_by_participation ON round_offboard (participation_id);
