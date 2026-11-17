-- Link in Bio schema 4: refund requests for unapplied Chain Payments payments (FU-0132). Forward-only.
--
-- An unapplied payment (paid after its checkout was paid or closed) is credited as months. Its account holder may
-- ask for the money back instead, once, within 30 days. The operator sends the refund by hand and records it here
-- with the refund transaction's reference; that takes the months back as a `refund` billing event, once.
CREATE TABLE lib.refund_requests (
  id                uuid PRIMARY KEY,
  event_id          uuid NOT NULL UNIQUE REFERENCES lib.billing_events (id),
  account_id        uuid NOT NULL REFERENCES lib.accounts (id),
  reason            text NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'refunded')),
  refund_reference  text CHECK (length(refund_reference) BETWEEN 1 AND 200),
  refund_event      uuid REFERENCES lib.billing_events (id),
  decided_by        text,
  decided_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'open') = (refund_reference IS NULL))
);
CREATE INDEX refund_requests_status ON lib.refund_requests (status, created_at);
