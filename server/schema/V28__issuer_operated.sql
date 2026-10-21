-- Issuer-operated batches (`issuer.rs`): an asset whose issuer runs its
-- batches funds each new batch by reissuing the asset in the round, through
-- the mint limiter that holds the asset's reissuance token, and every sweep
-- of such a batch burns what it takes.
--
-- Each round of such an asset records its mint: the limiter coin it spends
-- at input 0, the limiter's state before and after (the amount minted in the
-- window, the blocks of the window behind the coin), the age its input
-- declares, and the amount it reissues. Output 0 of the round is the
-- limiter's successor. The limiter's state is carried by its coin on the
-- chain; this record is how the server finds the successor of a coin its
-- own round spent, and what its supply report lists.
CREATE TABLE round_mint (
	round_id     BIGINT PRIMARY KEY REFERENCES round (round_id),
	asset        BYTEA NOT NULL CHECK (length(asset) = 32),
	coin_txid    BYTEA NOT NULL CHECK (length(coin_txid) = 32),
	coin_vout    INTEGER NOT NULL CHECK (coin_vout >= 0),
	minted       BIGINT NOT NULL CHECK (minted >= 0),
	elapsed      INTEGER NOT NULL CHECK (elapsed >= 0),
	age          INTEGER NOT NULL CHECK (age >= 2),
	amount       BIGINT NOT NULL CHECK (amount > 0),
	next_minted  BIGINT NOT NULL CHECK (next_minted >= 0),
	next_elapsed INTEGER NOT NULL CHECK (next_elapsed >= 0)
);

CREATE INDEX round_mint_coin ON round_mint (coin_txid, coin_vout);
CREATE INDEX round_mint_asset ON round_mint (asset);

-- The limiter's coins are watched outpoints: a spend of one the server did
-- not make (the cold key's brake, its release, its recovery) is recorded with
-- its spender, from which the server follows the coin.
ALTER TABLE watched_outpoint DROP CONSTRAINT watched_outpoint_kind_check;
ALTER TABLE watched_outpoint ADD CONSTRAINT watched_outpoint_kind_check CHECK (kind IN ('board', 'nursery', 'receive', 'limiter'));
