-- An authentication challenge is a keyed check of the time it was issued
-- and a random value, which the server verifies without a row: nothing is
-- stored for it, so the calls anyone may make leave no challenge behind.
DROP TABLE auth_challenge;
