-- Link in Bio schema 3: where each bank feed (Wise, bunq, Revolut Business) left off. Forward-only.
--
-- `cursor` is the feed's own position (a time, or the newest payment id per account); `state` is what a feed keeps
-- between polls (bunq's installation token and server key, a rotated Revolut refresh token). Neither is ever shown in
-- the console.
CREATE TABLE lib.bank_feeds (
  feed          text PRIMARY KEY CHECK (feed ~ '^[a-z0-9-]{1,32}$'),
  cursor        text CHECK (length(cursor) <= 8000),
  state         jsonb NOT NULL DEFAULT '{}',
  polled_at     timestamptz,
  last_error    text CHECK (length(last_error) <= 500),
  credits_seen  bigint NOT NULL DEFAULT 0
);
