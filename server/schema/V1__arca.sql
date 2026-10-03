-- The Arca server's schema, in one piece.
--
-- Conventions: every hash, key, asset id and txid is BYTEA in internal byte
-- order (the reverse of what RPCs print); every amount is a pair of an asset
-- and a BIGINT of that asset's atoms, never a bare number; leaves are keyed by
-- their leaf id, never by an outpoint; transactions are stored in Sequentia's
-- encoding.

------------------------------------------------------------------------------
-- The chain, as the finality service sees it
------------------------------------------------------------------------------

-- The active chain the finality service has followed: one row per height. A
-- block leaves this table when it is disconnected.
CREATE TABLE block (
	hash          BYTEA PRIMARY KEY CHECK (length(hash) = 32),
	height        BIGINT NOT NULL UNIQUE CHECK (height >= 0),
	prev_hash     BYTEA NOT NULL CHECK (length(prev_hash) = 32),
	-- The Bitcoin block the header commits to.
	anchor_height BIGINT NOT NULL,
	anchor_hash   BYTEA NOT NULL CHECK (length(anchor_hash) = 32),
	median_time   BIGINT NOT NULL,
	-- Whether the committee certified the block, as the node reports it.
	certified     BOOLEAN NOT NULL,
	connected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every connection and disconnection, in order: the record of what the server
-- saw of the chain, rollbacks included.
CREATE TABLE chain_event (
	seq    BIGSERIAL PRIMARY KEY,
	kind   TEXT NOT NULL CHECK (kind IN ('connected', 'disconnected')),
	height BIGINT NOT NULL,
	hash   BYTEA NOT NULL,
	at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Transactions something in the server relies on, and why.
CREATE TABLE watched_tx (
	txid     BYTEA PRIMARY KEY CHECK (length(txid) = 32),
	kind     TEXT NOT NULL,
	added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which active-chain block holds a watched transaction. The row goes with the
-- block when it is disconnected.
CREATE TABLE tx_block (
	txid       BYTEA NOT NULL REFERENCES watched_tx ON DELETE CASCADE,
	block_hash BYTEA NOT NULL REFERENCES block ON DELETE CASCADE,
	PRIMARY KEY (txid, block_hash)
);

------------------------------------------------------------------------------
-- Arca scripts and their sightings
------------------------------------------------------------------------------

-- Every Arca output script the server has created, accepted or co-signed
-- into: leaves, boards, checkpoints. A script is funded at most once, so it
-- has one row; the primary key is the server's guarantee of uniqueness across
-- batches, boards and transfers.
CREATE TABLE arca_script (
	script_pubkey BYTEA PRIMARY KEY,
	kind          TEXT NOT NULL CHECK (kind IN ('leaf', 'board', 'checkpoint')),
	leaf_id       BYTEA NOT NULL CHECK (length(leaf_id) = 32),
	added_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A transaction output paying an Arca script, seen in the mempool or in a
-- block. A sighting is never removed: once an output of a leaf has been seen,
-- the server co-signs no off-chain spend of that leaf, rollback or not.
CREATE TABLE script_sighting (
	script_pubkey BYTEA NOT NULL REFERENCES arca_script,
	txid          BYTEA NOT NULL CHECK (length(txid) = 32),
	vout          INTEGER NOT NULL CHECK (vout >= 0),
	seen_in       TEXT NOT NULL CHECK (seen_in IN ('mempool', 'block')),
	seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (script_pubkey, txid, vout)
);

-- Outputs whose spending the server must notice: a board output, or an input
-- of a transaction the nursery keeps broadcasting. watched_for is the leaf or
-- the transaction that relies on it. spent_by is the transaction seen
-- spending it: the first seen in the mempool, replaced by the one a block
-- holds. Like a sighting, a spend once seen is kept.
CREATE TABLE watched_outpoint (
	txid        BYTEA NOT NULL CHECK (length(txid) = 32),
	vout        INTEGER NOT NULL CHECK (vout >= 0),
	kind        TEXT NOT NULL CHECK (kind IN ('board', 'nursery')),
	watched_for BYTEA NOT NULL CHECK (length(watched_for) = 32),
	spent_by    BYTEA CHECK (spent_by IS NULL OR length(spent_by) = 32),
	spent_at    TIMESTAMPTZ,
	PRIMARY KEY (txid, vout)
);

------------------------------------------------------------------------------
-- Nonces, leaves, boards
------------------------------------------------------------------------------

-- The second nonce of the salt of a leaf the operator creates (a board, a
-- leaf of a round). Each is random, handed out once, and taken by at most one
-- leaf: the server never repeats an operator nonce, so no leaf script it signs
-- for can match one it signed for before. A leaf a reassignment creates takes
-- its sender's creator nonce instead.
CREATE TABLE operator_nonce (
	nonce     BYTEA PRIMARY KEY CHECK (length(nonce) = 32),
	issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	used_at   TIMESTAMPTZ,
	used_by   BYTEA CHECK (used_by IS NULL OR length(used_by) = 32),
	CHECK ((used_at IS NULL) = (used_by IS NULL))
);

CREATE TYPE leaf_kind AS ENUM ('board', 'batch', 'transfer');

-- pending: known, not yet the owner's to spend (a board not yet final, a
--   transfer's output whose signatures are not yet made);
-- live: the owner's to spend off-chain;
-- spent: spent off-chain, by the transfer or participation in spent_by;
-- lost: can no longer be spent off-chain (its board or round never returned);
-- expired: a new leaf of a participation whose forfeits never came: it is
--   never the owner's (its preimage never goes out), and the operator sweeps
--   it with its batch.
CREATE TYPE leaf_state AS ENUM ('pending', 'live', 'spent', 'lost', 'expired');

-- Every coin the server knows, keyed by leaf id: a board, a leaf of a batch,
-- or an output of a transfer, with its coin record (binary form), from which
-- its whole lineage and every transaction that brings it on-chain follow.
CREATE TABLE leaf (
	leaf_id       BYTEA PRIMARY KEY CHECK (length(leaf_id) = 32),
	kind          leaf_kind NOT NULL,
	asset         BYTEA NOT NULL CHECK (length(asset) = 32),
	value         BIGINT NOT NULL CHECK (value > 0),
	owner_key     BYTEA NOT NULL CHECK (length(owner_key) = 32),
	script_pubkey BYTEA NOT NULL UNIQUE REFERENCES arca_script,
	-- Reassignments since a round or a board.
	hops          SMALLINT NOT NULL CHECK (hops >= 0),
	record        BYTEA NOT NULL,
	state         leaf_state NOT NULL,
	spent_by      BYTEA,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK ((state = 'spent') = (spent_by IS NOT NULL))
);
-- One key, one leaf: a key owns one leaf that is not lost. A participation
-- that runs again after its round could never return asks for its leaves
-- under the same keys; the leaves of the lost round are lost.
CREATE UNIQUE INDEX leaf_owner_key_key ON leaf (owner_key) WHERE state <> 'lost';

-- pending: registered, its transaction not final;
-- credited: final, the leaf is live;
-- lost: its transaction cannot return to the chain.
CREATE TYPE board_state AS ENUM ('pending', 'credited', 'lost');

-- Boards: the owner's own coins brought in. The transaction is kept, whole, so
-- the server can broadcast it again after a rollback.
CREATE TABLE board (
	leaf_id      BYTEA PRIMARY KEY REFERENCES leaf,
	record       BYTEA NOT NULL,
	txid         BYTEA NOT NULL CHECK (length(txid) = 32),
	vout         INTEGER NOT NULL CHECK (vout >= 0),
	tx           BYTEA NOT NULL,
	state        board_state NOT NULL,
	-- How often the board was credited and uncredited: a rollback that
	-- disconnects a credited board uncredits it.
	credits      INTEGER NOT NULL DEFAULT 0,
	uncredits    INTEGER NOT NULL DEFAULT 0,
	credited_at  TIMESTAMPTZ,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (txid, vout)
);

------------------------------------------------------------------------------
-- Out-of-round transfers
------------------------------------------------------------------------------

-- A transfer the server co-signed: its id is the reassignment's hash, the
-- request hash makes a repeated request return the same answer.
CREATE TABLE transfer (
	transfer_id  BYTEA PRIMARY KEY CHECK (length(transfer_id) = 32),
	request_hash BYTEA NOT NULL UNIQUE CHECK (length(request_hash) = 32),
	state        TEXT NOT NULL CHECK (state IN ('recorded', 'signed')),
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each input of a transfer. A leaf is the input of at most one transfer: the
-- unique key is the double-spend guard, and it is written before any
-- signature leaves the server.
CREATE TABLE transfer_input (
	transfer_id               BYTEA NOT NULL REFERENCES transfer,
	idx                       SMALLINT NOT NULL CHECK (idx >= 0),
	leaf_id                   BYTEA NOT NULL UNIQUE REFERENCES leaf,
	checkpoint_value          BIGINT NOT NULL CHECK (checkpoint_value > 0),
	checkpoint_owner_sig      BYTEA NOT NULL CHECK (length(checkpoint_owner_sig) = 64),
	reassignment_owner_sig    BYTEA NOT NULL CHECK (length(reassignment_owner_sig) = 64),
	checkpoint_operator_sig   BYTEA CHECK (length(checkpoint_operator_sig) = 64),
	reassignment_operator_sig BYTEA CHECK (length(reassignment_operator_sig) = 64),
	PRIMARY KEY (transfer_id, idx)
);

-- Each reassignment the operator co-signed, as the rule that keeps any two
-- from being merged into one transaction needs it: the hash of its output 0's
-- record (every mergeable pair agrees at output 0), the coins it spends with
-- their checkpoints' values, and its committed outputs, each encoded by the
-- server. The rule is arca-covenant's (TransferPlan::admit); this table makes
-- what it has seen durable.
CREATE TABLE reassignment (
	transfer_id  BYTEA PRIMARY KEY REFERENCES transfer,
	first_output BYTEA NOT NULL CHECK (length(first_output) = 32),
	inputs       BYTEA NOT NULL,
	outputs      BYTEA NOT NULL
);
CREATE INDEX reassignment_by_first_output ON reassignment (first_output);

-- Each committed output of a transfer: a new leaf, delivered to a mailbox.
CREATE TABLE transfer_output (
	transfer_id BYTEA NOT NULL REFERENCES transfer,
	idx         SMALLINT NOT NULL CHECK (idx >= 0),
	leaf_id     BYTEA NOT NULL UNIQUE REFERENCES leaf,
	mailbox_key BYTEA NOT NULL CHECK (length(mailbox_key) = 32),
	PRIMARY KEY (transfer_id, idx)
);

------------------------------------------------------------------------------
-- Rounds
------------------------------------------------------------------------------

-- A round transaction the operator built and signed. It is kept whole, with
-- nLockTime 0, and broadcast again unchanged after a rollback.
--
-- built: signed and recorded, not yet handed to the nursery;
-- broadcast: in the nursery, which keeps it broadcast until final;
-- final: certified, and its anchor buried;
-- lost: it can never return (an input is spent by another transaction that
--   is final).
CREATE TABLE round (
	round_id    BIGSERIAL PRIMARY KEY,
	txid        BYTEA NOT NULL UNIQUE CHECK (length(txid) = 32),
	tx          BYTEA NOT NULL,
	state       TEXT NOT NULL CHECK (state IN ('built', 'broadcast', 'final', 'lost')),
	-- The one fee the round pays, in one asset, from the operator's coins.
	fee_asset   BYTEA NOT NULL CHECK (length(fee_asset) = 32),
	fee         BIGINT NOT NULL CHECK (fee > 0),
	-- The median time the round's clock schedules count from.
	created_mtp BIGINT NOT NULL,
	-- The tip's median time when the round was last found final; null while
	-- it is not. A participation's forfeits are due within a day of it.
	final_mtp   BIGINT,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The round's connector output, which only the issuance of the round's
-- connector asset spends, and that asset once issued.
CREATE TABLE connector_output (
	round_id        BIGINT PRIMARY KEY REFERENCES round,
	vout            INTEGER NOT NULL CHECK (vout >= 0),
	asset           BYTEA NOT NULL CHECK (length(asset) = 32),
	value           BIGINT NOT NULL CHECK (value > 0),
	connector_asset BYTEA NOT NULL UNIQUE CHECK (length(connector_asset) = 32),
	issuance_txid   BYTEA CHECK (length(issuance_txid) = 32)
);

-- pending: accepted, waiting for a round;
-- issued: its leaves are in a round (round_id), whose forfeits it owes;
-- released: its forfeits are in and its preimage handed over;
-- void: it will not run (its round was never built, or cannot be);
-- expired: its round was final and its forfeits had not come a day later:
--   the coins it gave up are the owner's again, its new leaves never are.
CREATE TYPE participation_state AS ENUM ('pending', 'issued', 'released', 'void', 'expired');

-- A participation: the coins an owner gives up and the leaves (or on-chain
-- outputs) it wants for them, submitted once and run in a round without the
-- owner online. Its id is the hash of the request, which the owner of every
-- coin given up signed. The unlock hash is the current attempt's: chosen when
-- the participation is accepted, and again whenever a round it was in can
-- never return.
CREATE TABLE participation (
	participation_id   BYTEA PRIMARY KEY CHECK (length(participation_id) = 32),
	unlock_hash        BYTEA NOT NULL UNIQUE CHECK (length(unlock_hash) = 32),
	preimage           BYTEA NOT NULL CHECK (length(preimage) = 32),
	attempt            INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
	round_id           BIGINT REFERENCES round,
	state              participation_state NOT NULL DEFAULT 'pending',
	-- Set when a round it was released in can never return: its next
	-- preimage goes out only once its forfeit is published and claimed.
	forfeit_first      BOOLEAN NOT NULL DEFAULT false,
	-- The earliest median time of a round it may run in.
	not_before         BIGINT,
	-- The delay after which each owner may take a forfeit back.
	refund_delay_units INTEGER NOT NULL CHECK (refund_delay_units > 0),
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK ((state IN ('issued', 'released', 'expired')) = (round_id IS NOT NULL))
);

-- The earlier attempts of a participation: each round it was in that could
-- never return, with the unlock hash and preimage it had then and whether that
-- preimage went out.
CREATE TABLE participation_attempt (
	participation_id BYTEA NOT NULL REFERENCES participation,
	attempt          INTEGER NOT NULL CHECK (attempt >= 0),
	round_id         BIGINT NOT NULL REFERENCES round,
	unlock_hash      BYTEA NOT NULL CHECK (length(unlock_hash) = 32),
	preimage         BYTEA NOT NULL CHECK (length(preimage) = 32),
	released         BOOLEAN NOT NULL,
	retired_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (participation_id, attempt)
);

-- Each coin given up. A coin is given up by one participation at a time: the
-- unique index holds it, and the coin's row is marked spent by the
-- participation in the same transaction. A participation that never ran
-- (void) or whose forfeits never came (expired) gives back each coin no
-- forfeit was signed for: the coin is live again and its input inactive, so
-- it can be given up again.
CREATE TABLE participation_input (
	participation_id BYTEA NOT NULL REFERENCES participation,
	idx              SMALLINT NOT NULL CHECK (idx >= 0),
	leaf_id          BYTEA NOT NULL REFERENCES leaf,
	active           BOOLEAN NOT NULL DEFAULT true,
	asset            BYTEA NOT NULL CHECK (length(asset) = 32),
	value            BIGINT NOT NULL CHECK (value > 0),
	-- What the forfeit leaves uncommitted for its own fee.
	margin           BIGINT NOT NULL CHECK (margin > 0),
	-- The owner's signature over the participation's id.
	attestation      BYTEA NOT NULL CHECK (length(attestation) = 64),
	PRIMARY KEY (participation_id, idx)
);
CREATE UNIQUE INDEX participation_input_leaf_id_key ON participation_input (leaf_id) WHERE active;

-- Each output wanted: a leaf, or an offboard's on-chain output.
CREATE TABLE participation_output (
	participation_id    BYTEA NOT NULL REFERENCES participation,
	idx                 SMALLINT NOT NULL CHECK (idx >= 0),
	kind                TEXT NOT NULL CHECK (kind IN ('leaf', 'offboard')),
	asset               BYTEA NOT NULL CHECK (length(asset) = 32),
	value               BIGINT NOT NULL CHECK (value > 0),
	-- A leaf: its template, its owner's key and nonce, its exit delay, and
	-- the operator nonce of the current attempt.
	template            TEXT,
	owner_key           BYTEA CHECK (owner_key IS NULL OR length(owner_key) = 32),
	owner_nonce         BYTEA CHECK (owner_nonce IS NULL OR length(owner_nonce) = 32),
	exit_delay_units    INTEGER,
	operator_nonce      BYTEA REFERENCES operator_nonce,
	-- The leaf the current attempt's round made of it.
	leaf_id             BYTEA REFERENCES leaf,
	-- An offboard: the destination script, the margin the round's output
	-- holds for its unlock, and the operator's reclaim delay.
	script              BYTEA,
	margin              BIGINT CHECK (margin IS NULL OR margin >= 0),
	reclaim_delay_units INTEGER,
	PRIMARY KEY (participation_id, idx),
	CHECK ((kind = 'leaf') = (owner_key IS NOT NULL AND owner_nonce IS NOT NULL AND template IS NOT NULL
		AND exit_delay_units IS NOT NULL AND operator_nonce IS NOT NULL)),
	CHECK ((kind = 'offboard') = (script IS NOT NULL AND margin IS NOT NULL AND reclaim_delay_units IS NOT NULL))
);
-- A key is wanted for one leaf, ever: one key, one leaf.
CREATE UNIQUE INDEX participation_output_owner_key ON participation_output (owner_key) WHERE kind = 'leaf';

-- The fee a participation pays, per asset, in that asset.
CREATE TABLE participation_fee (
	participation_id BYTEA NOT NULL REFERENCES participation,
	asset            BYTEA NOT NULL CHECK (length(asset) = 32),
	amount           BIGINT NOT NULL CHECK (amount >= 0),
	PRIMARY KEY (participation_id, asset)
);

-- A batch: one output of a round committing to a tree of leaves in one asset,
-- with everything the tree builder needs to rebuild every script in it (the
-- leaves are in batch_leaf). This is what the operator publishes.
CREATE TABLE batch (
	round_id     BIGINT NOT NULL REFERENCES round,
	vout         INTEGER NOT NULL CHECK (vout >= 0),
	asset        BYTEA NOT NULL CHECK (length(asset) = 32),
	value        BIGINT NOT NULL CHECK (value > 0),
	-- The sweep token, issued as one atom by the round's input that spends
	-- the issuer outpoint, and paid to the first clock at token_vout.
	token        BYTEA NOT NULL UNIQUE CHECK (length(token) = 32),
	token_vout   INTEGER NOT NULL CHECK (token_vout >= 0),
	issuer_txid  BYTEA NOT NULL CHECK (length(issuer_txid) = 32),
	issuer_vout  INTEGER NOT NULL CHECK (issuer_vout >= 0),
	-- The published schedule (T, S, W, E_0 … E_K), in arca-covenant's
	-- canonical encoding.
	schedule     BYTEA NOT NULL,
	burn         BOOLEAN NOT NULL,
	radix        SMALLINT NOT NULL,
	-- The reserve rule: fee_rate (a: the floor per 1,000 vbytes in the
	-- asset's atoms, b: the multiple) or fixed (a: per node, b: per entry).
	reserve_kind TEXT NOT NULL CHECK (reserve_kind IN ('fee_rate', 'fixed')),
	reserve_a    BIGINT NOT NULL CHECK (reserve_a >= 0),
	reserve_b    BIGINT NOT NULL CHECK (reserve_b >= 0),
	min_leaf     BIGINT NOT NULL CHECK (min_leaf >= 0),
	PRIMARY KEY (round_id, vout)
);

-- Each leaf of a batch, in the tree's order, with the parts the builder took
-- for it and the leaf record it gave. The leaf's row in leaf is the coin;
-- its record there is filled in once the owner hands over its forfeits.
CREATE TABLE batch_leaf (
	leaf_id          BYTEA PRIMARY KEY REFERENCES leaf,
	round_id         BIGINT NOT NULL,
	vout             INTEGER NOT NULL,
	idx              INTEGER NOT NULL CHECK (idx >= 0),
	participation_id BYTEA NOT NULL REFERENCES participation,
	output_idx       SMALLINT NOT NULL,
	attempt          INTEGER NOT NULL,
	template         TEXT NOT NULL,
	owner_key        BYTEA NOT NULL CHECK (length(owner_key) = 32),
	owner_nonce      BYTEA NOT NULL CHECK (length(owner_nonce) = 32),
	operator_nonce   BYTEA NOT NULL REFERENCES operator_nonce,
	exit_delay_units INTEGER NOT NULL,
	value            BIGINT NOT NULL CHECK (value > 0),
	unlock_hash      BYTEA NOT NULL CHECK (length(unlock_hash) = 32),
	record           BYTEA NOT NULL,
	UNIQUE (round_id, vout, idx),
	FOREIGN KEY (round_id, vout) REFERENCES batch
);

-- Each offboard output a round pays.
CREATE TABLE round_offboard (
	round_id         BIGINT NOT NULL REFERENCES round,
	vout             INTEGER NOT NULL CHECK (vout >= 0),
	participation_id BYTEA NOT NULL REFERENCES participation,
	output_idx       SMALLINT NOT NULL,
	attempt          INTEGER NOT NULL,
	-- The output: the destination's value and the margin for its unlock.
	value            BIGINT NOT NULL CHECK (value > 0),
	PRIMARY KEY (round_id, vout)
);

-- A forfeit of a coin given up in a participation, for the round of one of
-- its attempts: the owner's and the operator's signatures over the coin's move
-- into the forfeit output, which names the participation's unlock hash, the
-- round's connector asset and the coin's leaf id; the refund delay and the
-- margin it carries. With these the operator can publish the forfeit whenever
-- the coin reaches the chain, and claim it by revealing the preimage.
CREATE TABLE forfeit (
	leaf_id            BYTEA NOT NULL REFERENCES leaf,
	round_id           BIGINT NOT NULL REFERENCES round,
	participation_id   BYTEA NOT NULL REFERENCES participation,
	attempt            INTEGER NOT NULL CHECK (attempt >= 0),
	owner_sig          BYTEA NOT NULL CHECK (length(owner_sig) = 64),
	operator_sig       BYTEA NOT NULL CHECK (length(operator_sig) = 64),
	refund_delay_units INTEGER NOT NULL CHECK (refund_delay_units > 0),
	margin             BIGINT NOT NULL CHECK (margin > 0),
	unlock_hash        BYTEA NOT NULL CHECK (length(unlock_hash) = 32),
	connector_asset    BYTEA NOT NULL CHECK (length(connector_asset) = 32),
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (leaf_id, round_id)
);

-- An owner's release of the lowest node of a coin it gave up, for the round of
-- one of the participation's attempts: its signature, with the coin's key,
-- over SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M), H the node's children
-- hash and M that round's connector asset. RECLAIM needs an atom of M among
-- its inputs, so the release is void unless that round is in the chain. Taken
-- only after the participation's preimage went out, while its round is final,
-- and never for a coin with an open out-of-round reassignment. Once every
-- owner under a lowest node has released it, the operator may reclaim it.
CREATE TABLE node_release (
	leaf_id          BYTEA NOT NULL REFERENCES leaf,
	round_id         BIGINT NOT NULL REFERENCES round,
	participation_id BYTEA NOT NULL REFERENCES participation,
	node_hash        BYTEA NOT NULL CHECK (length(node_hash) = 32),
	connector_asset  BYTEA NOT NULL CHECK (length(connector_asset) = 32),
	signature        BYTEA NOT NULL CHECK (length(signature) = 64),
	-- Set when the round can never return: its M can never be issued, and
	-- the release is never used.
	retired          BOOLEAN NOT NULL DEFAULT false,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (leaf_id, round_id)
);
CREATE INDEX node_release_by_node ON node_release (node_hash);

------------------------------------------------------------------------------
-- Mailboxes and authentication
------------------------------------------------------------------------------

-- Messages for receivers who may be offline, read by cursor.
CREATE TABLE mailbox_message (
	cursor      BIGSERIAL PRIMARY KEY,
	mailbox_key BYTEA NOT NULL CHECK (length(mailbox_key) = 32),
	kind        TEXT NOT NULL CHECK (kind IN ('coin')),
	leaf_id     BYTEA REFERENCES leaf,
	payload     BYTEA NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mailbox_message_by_key ON mailbox_message (mailbox_key, cursor);

-- Challenges a client signs with a leaf key to authenticate: each is used once.
CREATE TABLE auth_challenge (
	challenge  BYTEA PRIMARY KEY CHECK (length(challenge) = 32),
	issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at TIMESTAMPTZ NOT NULL,
	used_at    TIMESTAMPTZ
);

------------------------------------------------------------------------------
-- The on-chain wallet and the server's own transactions
------------------------------------------------------------------------------

-- The wallet's scripts it has handed out, by derivation chain (0 to receive,
-- 1 for change) and index.
CREATE TABLE wallet_key (
	chain         SMALLINT NOT NULL CHECK (chain IN (0, 1)),
	idx           INTEGER NOT NULL CHECK (idx >= 0),
	script_pubkey BYTEA NOT NULL UNIQUE,
	issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (chain, idx)
);

-- The wallet's coins, per asset, all explicit, as found in blocks of the
-- active chain. found_in is the block that holds the coin's transaction, and
-- empties when that block is disconnected; spent_by names the server's
-- transaction that spends the coin once the wallet has built it.
CREATE TABLE wallet_coin (
	txid          BYTEA NOT NULL CHECK (length(txid) = 32),
	vout          INTEGER NOT NULL CHECK (vout >= 0),
	asset         BYTEA NOT NULL CHECK (length(asset) = 32),
	value         BIGINT NOT NULL CHECK (value > 0),
	script_pubkey BYTEA NOT NULL REFERENCES wallet_key (script_pubkey),
	found_in      BYTEA REFERENCES block ON DELETE SET NULL,
	spent_by      BYTEA CHECK (spent_by IS NULL OR length(spent_by) = 32),
	found_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (txid, vout)
);
CREATE INDEX wallet_coin_by_asset ON wallet_coin (asset) WHERE spent_by IS NULL;

-- Outputs paid to the wallet that it refused to take as coins (a blinded
-- output: the server is transparent at its boundary).
CREATE TABLE wallet_refused (
	txid          BYTEA NOT NULL CHECK (length(txid) = 32),
	vout          INTEGER NOT NULL CHECK (vout >= 0),
	script_pubkey BYTEA NOT NULL,
	reason        TEXT NOT NULL,
	seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (txid, vout)
);

-- pending: to be kept broadcast until final;
-- final: certified and its anchor buried;
-- lost: it can no longer confirm (an input is spent elsewhere).
CREATE TYPE nursery_state AS ENUM ('pending', 'final', 'lost');

-- Transactions the server keeps broadcasting until they are final: its own
-- (rounds, wallet transactions) and those it relies on (boards). Each is kept
-- byte for byte, and only ever broadcast again unchanged.
CREATE TABLE nursery_tx (
	txid              BYTEA PRIMARY KEY CHECK (length(txid) = 32),
	tx                BYTEA NOT NULL,
	kind              TEXT NOT NULL CHECK (kind IN ('board', 'wallet', 'round')),
	-- The fee asset and amount a server-built transaction names; NULL for a
	-- transaction the server did not build.
	fee_asset         BYTEA CHECK (fee_asset IS NULL OR length(fee_asset) = 32),
	fee               BIGINT CHECK (fee IS NULL OR fee >= 0),
	state             nursery_state NOT NULL DEFAULT 'pending',
	broadcasts        INTEGER NOT NULL DEFAULT 0,
	last_broadcast_at TIMESTAMPTZ,
	last_result       TEXT,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK ((fee_asset IS NULL) = (fee IS NULL))
);
