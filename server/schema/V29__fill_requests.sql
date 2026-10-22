-- A fill's request as its taker sent it, kept with the fill when it is
-- recorded: the server completes a fill the signer left half done (the
-- taker's pairs signed, the fill not) from it, without waiting for the
-- taker to send it again (`Orders::finish_unsigned`). A fill recorded
-- before this column has none, and waits for its taker as before.
ALTER TABLE order_fill ADD COLUMN request BYTEA;
