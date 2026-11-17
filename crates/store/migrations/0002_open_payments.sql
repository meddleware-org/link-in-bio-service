-- Link in Bio schema 2: Open Payments grants waiting for the buyer's approval. Forward-only.
--
-- One row per checkout paid from an Open Payments wallet: the buyer's wallet address and, while the grant waits for
-- the buyer, what continuing it needs (the nonces, the continuation URI and token, the quote). `pending` is emptied
-- once the grant is continued, so the continuation token is kept only for those minutes.
CREATE TABLE lib.open_payments_grants (
  checkout_id       uuid PRIMARY KEY REFERENCES lib.checkouts (id) ON DELETE CASCADE,
  buyer_wallet      text NOT NULL CHECK (length(buyer_wallet) BETWEEN 1 AND 300),
  pending           jsonb NOT NULL DEFAULT '{}',
  status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'finishing', 'sent', 'failed')),
  outgoing_payment  text CHECK (length(outgoing_payment) BETWEEN 1 AND 300),
  created_at        timestamptz NOT NULL DEFAULT now(),
  finished_at       timestamptz
);
