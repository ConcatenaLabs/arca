-- A batch's kind (`arca_covenant::BatchKind`): a tree, whose leaves leave
-- through its node levels, or an accumulator batch, one output from which
-- each leaf leaves in one transaction. Both pay each leaf's hash-locked
-- entry and sweep under the same token, clock and notice. An accumulator
-- batch's leaves keep their accumulator records in batch_leaf.record, and its
-- radix is 0. Every batch made before this is a tree.
ALTER TABLE batch ADD COLUMN kind TEXT NOT NULL DEFAULT 'tree' CHECK (kind IN ('tree', 'accumulator'));
