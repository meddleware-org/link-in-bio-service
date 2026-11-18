-- Link in Bio schema 6. Forward-only: a released migration is never edited.
--
-- Refunds on request, and Web Risk's Update API lists.

-- Which checkout a purchase paid, and which purchase a refund took months back from, so what a purchase still gives
-- is its months plus those of the refunds of it.
ALTER TABLE lib.billing_events ADD COLUMN checkout_id uuid REFERENCES lib.checkouts (id);
ALTER TABLE lib.billing_events ADD COLUMN refund_of uuid REFERENCES lib.billing_events (id);
CREATE INDEX billing_events_checkout ON lib.billing_events (checkout_id) WHERE checkout_id IS NOT NULL;
CREATE INDEX billing_events_refund_of ON lib.billing_events (refund_of) WHERE refund_of IS NOT NULL;

UPDATE lib.billing_events e SET checkout_id = c.id
  FROM lib.checkouts c
 WHERE e.kind = 'purchase' AND e.checkout_id IS NULL AND e.account_id = c.account_id
   AND (e.evidence->>'checkout' = c.id::text OR (e.provider = c.provider AND e.provider_event = 'paid:' || c.provider_ref));
UPDATE lib.billing_events SET refund_of = (evidence->>'refundOf')::uuid
 WHERE kind = 'refund' AND refund_of IS NULL AND evidence->>'refundOf' ~ '^[0-9a-f-]{36}$';

-- A request now covers one purchase (cancel within 14 days, a late payment) or several (unstarted months, newest
-- purchases first): what each purchase gives back is a line. One open request per account; the account holder may
-- withdraw it and the operator may decline it.
ALTER TABLE lib.refund_requests ALTER COLUMN event_id DROP NOT NULL;
ALTER TABLE lib.refund_requests ADD COLUMN kind text NOT NULL DEFAULT 'unapplied'
  CHECK (kind IN ('unapplied', 'cancel', 'unstarted'));
ALTER TABLE lib.refund_requests ADD COLUMN details jsonb NOT NULL DEFAULT '{}';
ALTER TABLE lib.refund_requests DROP CONSTRAINT refund_requests_status_check;
ALTER TABLE lib.refund_requests ADD CONSTRAINT refund_requests_status_check
  CHECK (status IN ('open', 'refunded', 'withdrawn', 'declined'));
ALTER TABLE lib.refund_requests DROP CONSTRAINT refund_requests_check;
ALTER TABLE lib.refund_requests ADD CONSTRAINT refund_requests_reference_check
  CHECK ((status = 'refunded') = (refund_reference IS NOT NULL));
CREATE UNIQUE INDEX refund_requests_one_open ON lib.refund_requests (account_id) WHERE status = 'open';

CREATE TABLE lib.refund_lines (
  request_id        uuid NOT NULL REFERENCES lib.refund_requests (id),
  purchase_id       uuid NOT NULL REFERENCES lib.billing_events (id),
  checkout_id       uuid REFERENCES lib.checkouts (id),
  provider          text NOT NULL,
  months            integer NOT NULL CHECK (months BETWEEN 1 AND 24),
  amount_minor      bigint NOT NULL CHECK (amount_minor > 0),
  unit              text NOT NULL CHECK (length(unit) BETWEEN 1 AND 200),
  scale             integer CHECK (scale BETWEEN 0 AND 18),
  fee_minor         bigint NOT NULL DEFAULT 0 CHECK (fee_minor >= 0),
  used_minor        bigint NOT NULL DEFAULT 0 CHECK (used_minor >= 0),
  days_used         integer NOT NULL DEFAULT 0 CHECK (days_used >= 0),
  amount_pence      bigint NOT NULL DEFAULT 0,
  destination       jsonb NOT NULL DEFAULT '{}',
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'refunded')),
  refund_reference  text CHECK (length(refund_reference) BETWEEN 1 AND 200),
  refund_event      uuid REFERENCES lib.billing_events (id),
  refunded_at       timestamptz,
  PRIMARY KEY (request_id, purchase_id),
  CHECK ((status = 'refunded') = (refund_reference IS NOT NULL))
);
CREATE INDEX refund_lines_checkout ON lib.refund_lines (checkout_id) WHERE status = 'open';

-- Web Risk's threat lists (Update API, `threatLists.computeDiff`): hash prefixes kept here by the worker, the only
-- writer; the app and the worker load them into memory and check links locally. Only on a local match is a prefix sent
-- to Google (`hashes.search`), never a URL.
CREATE TABLE lib.web_risk_lists (
  threat_type    text PRIMARY KEY CHECK (threat_type IN ('MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE')),
  -- '' asks for a full list next time (first run, or after a checksum mismatch).
  version_token  text NOT NULL DEFAULT '',
  entries        integer NOT NULL DEFAULT 0 CHECK (entries >= 0),
  -- The lexicographically sorted prefixes, each as one length byte (4..32) and its bytes.
  prefixes       bytea NOT NULL DEFAULT '\x',
  -- SHA-256 of the sorted prefixes concatenated, base64, as Web Risk gave it.
  checksum       text NOT NULL DEFAULT '',
  next_diff_at   timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  last_error     text
);
