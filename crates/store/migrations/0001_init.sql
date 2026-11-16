-- Link in Bio schema 1. Forward-only: a released migration is never edited.
--
-- Tables live in schema `lib` (the writer role changes rows there; services.conf `writer … schema=lib`). The page process
-- connects as the read-only role, which can read only the `public.*_v1` views at the end of this file: a page host can
-- never see a passkey, a session, a report or a billing record.
CREATE SCHEMA IF NOT EXISTS lib;

CREATE TABLE lib.accounts (
  id                 uuid PRIMARY KEY,
  handle             text NOT NULL UNIQUE CHECK (handle ~ '^[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?$'),
  -- The handle's confusable skeleton (link-in-bio-core `handle_skeleton`): two handles that look alike cannot both exist.
  handle_skeleton    text NOT NULL UNIQUE,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  -- `legal`: a page withheld on legal grounds (HTTP 451); `policy`: removed under the acceptable use policy (410).
  suspension_kind    text CHECK (suspension_kind IN ('legal', 'policy')),
  suspension_reason  text CHECK (length(suspension_reason) <= 2000),
  suspended_until    timestamptz,
  -- A free account (an operator-issued invite); paid accounts carry paid_until instead.
  free               boolean NOT NULL DEFAULT false,
  -- The operator's own test accounts: the only tenant pages served while THIRD_PARTY_PAGES=off.
  operator           boolean NOT NULL DEFAULT false,
  -- Whether invite codes the operator gives this account may still be redeemed (revoked for abuse of invites).
  may_share_invites  boolean NOT NULL DEFAULT true,
  invited_by         uuid REFERENCES lib.accounts (id),
  tags               text[] NOT NULL DEFAULT '{}',
  -- The 18+ declaration and the terms accepted at sign-up (version and time), kept as evidence.
  age_confirmed_at   timestamptz NOT NULL,
  terms_version      text NOT NULL CHECK (length(terms_version) BETWEEN 1 AND 40),
  terms_accepted_at  timestamptz NOT NULL,
  -- ISO 3166-1 alpha-2 the account holder declared (tax evidence, with the request country of each purchase).
  country_declared   text CHECK (country_declared ~ '^[A-Z]{2}$'),
  -- Opaque reference given to payment providers (never the handle or the id).
  billing_ref        text NOT NULL UNIQUE CHECK (billing_ref ~ '^[A-Za-z0-9_-]{16,64}$'),
  paid_until         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz,
  CHECK ((status = 'suspended') = (suspension_kind IS NOT NULL))
);

CREATE TABLE lib.passkeys (
  credential_id  bytea PRIMARY KEY CHECK (length(credential_id) BETWEEN 16 AND 1023),
  account_id     uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  -- webauthn-rs `Passkey` (the public key and counter; no secret).
  passkey        jsonb NOT NULL,
  name           text NOT NULL DEFAULT 'Passkey' CHECK (length(name) BETWEEN 1 AND 60),
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz
);
CREATE INDEX passkeys_account ON lib.passkeys (account_id);

CREATE TABLE lib.wallets (
  address     text PRIMARY KEY CHECK (address ~ '^0x[0-9a-f]{64}$'),
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX wallets_account ON lib.wallets (account_id);

CREATE TABLE lib.recovery_codes (
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  code_hash   bytea NOT NULL CHECK (length(code_hash) = 32),
  used_at     timestamptz,
  PRIMARY KEY (account_id, code_hash)
);

CREATE TABLE lib.sessions (
  -- SHA-256 of the cookie value; the value itself is never stored.
  token_hash    bytea PRIMARY KEY CHECK (length(token_hash) = 32),
  account_id    uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX sessions_account ON lib.sessions (account_id);
CREATE INDEX sessions_expiry ON lib.sessions (expires_at);

-- Server-side state of a WebAuthn ceremony or a wallet sign-in (one use; short-lived).
CREATE TABLE lib.challenges (
  id          text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
  kind        text NOT NULL CHECK (kind IN ('passkey-register', 'passkey-login', 'wallet-login', 'wallet-link')),
  account_id  uuid REFERENCES lib.accounts (id) ON DELETE CASCADE,
  state       jsonb NOT NULL,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX challenges_expiry ON lib.challenges (expires_at);

CREATE TABLE lib.pages (
  account_id    uuid PRIMARY KEY REFERENCES lib.accounts (id) ON DELETE CASCADE,
  -- Canonical manifest JSON (link-in-bio-core `Manifest::to_json`), checked by the parser before every write.
  draft         text NOT NULL,
  published     text,
  version       integer NOT NULL DEFAULT 1,
  updated_at    timestamptz NOT NULL DEFAULT now(),
  published_at  timestamptz
);

-- The last 20 published versions of each page (older ones are pruned by the worker).
CREATE TABLE lib.page_versions (
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  version     integer NOT NULL,
  manifest    text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, version)
);

-- Pictures, re-encoded (400 x 400 at most, 64 KiB at most, metadata stripped) and addressed by content.
CREATE TABLE lib.assets (
  sha256      text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  mime        text NOT NULL CHECK (mime IN ('image/png', 'image/jpeg', 'image/svg+xml')),
  ext         text NOT NULL CHECK (ext IN ('png', 'jpg', 'svg')),
  width       integer NOT NULL CHECK (width BETWEEN 1 AND 400),
  height      integer NOT NULL CHECK (height BETWEEN 1 AND 400),
  bytes       bytea NOT NULL CHECK (length(bytes) <= 65536),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_account ON lib.assets (account_id);

-- Saved criteria for issuing invites to a group of accounts (the operator presses "issue K codes"; nothing is automatic).
CREATE TABLE lib.selections (
  id          uuid PRIMARY KEY,
  name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 80),
  criteria    jsonb NOT NULL,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Invite codes: issued only by the operator, one use each, looked up by SHA-256. `held_by` is the account the operator
-- gave the code to (to pass on), or NULL for a code the operator hands out directly.
CREATE TABLE lib.invites (
  id            uuid PRIMARY KEY,
  code_hash     bytea NOT NULL UNIQUE CHECK (length(code_hash) = 32),
  held_by       uuid REFERENCES lib.accounts (id) ON DELETE SET NULL,
  -- A code given to an account is kept readable for its holder until it is redeemed or revoked (they pass it on from
  -- the app); a code the operator hands out directly is shown once and kept only as its hash.
  code          text CHECK (code IS NULL OR held_by IS NOT NULL),
  selection_id  uuid REFERENCES lib.selections (id) ON DELETE SET NULL,
  note          text CHECK (length(note) <= 200),
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  redeemed_by   uuid UNIQUE REFERENCES lib.accounts (id) ON DELETE SET NULL,
  redeemed_at   timestamptz,
  revoked_at    timestamptz
);
CREATE INDEX invites_holder ON lib.invites (held_by);

CREATE TABLE lib.checkouts (
  id                uuid PRIMARY KEY,
  account_id        uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  provider          text NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
  provider_ref      text NOT NULL CHECK (length(provider_ref) BETWEEN 1 AND 200),
  method            text NOT NULL CHECK (length(method) BETWEEN 1 AND 80),
  months            integer NOT NULL CHECK (months BETWEEN 1 AND 24),
  amount_pence      bigint NOT NULL CHECK (amount_pence > 0),
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'paid', 'expired', 'cancelled')),
  -- Tax evidence at the time of purchase: the declared country and the request's country (CF-IPCountry).
  country_declared  text CHECK (country_declared ~ '^[A-Z]{2}$'),
  country_request   text CHECK (country_request ~ '^[A-Z0-9]{2}$'),
  created_at        timestamptz NOT NULL DEFAULT now(),
  completed_at      timestamptz,
  UNIQUE (provider, provider_ref)
);
CREATE INDEX checkouts_open ON lib.checkouts (status, created_at) WHERE status = 'open';

-- Every change to an account's paid period (a purchase, an operator grant, a refund), idempotent per provider event.
CREATE TABLE lib.billing_events (
  id                uuid PRIMARY KEY,
  account_id        uuid NOT NULL REFERENCES lib.accounts (id),
  provider          text NOT NULL,
  provider_event    text NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('purchase', 'grant', 'refund')),
  months            integer NOT NULL,
  amount_pence      bigint NOT NULL DEFAULT 0,
  paid_until_after  timestamptz,
  evidence          jsonb NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_event)
);
CREATE INDEX billing_events_account ON lib.billing_events (account_id, created_at);

CREATE TABLE lib.domains (
  hostname    text PRIMARY KEY CHECK (hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  method      text NOT NULL CHECK (method IN ('dns-txt', 'cloudflare-saas')),
  token       text NOT NULL CHECK (token ~ '^[0-9a-f]{32}$'),
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed')),
  checked_at  timestamptz,
  verified_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domains_account ON lib.domains (account_id);

-- Reports about a page or a link (no account needed). `contact` is optional and only used to answer the reporter.
CREATE TABLE lib.reports (
  id          uuid PRIMARY KEY,
  handle      text NOT NULL,
  account_id  uuid REFERENCES lib.accounts (id) ON DELETE SET NULL,
  url         text CHECK (length(url) <= 2048),
  reason      text NOT NULL CHECK (reason IN ('illegal', 'csam', 'terrorism', 'fraud', 'malware', 'harassment',
                                               'impersonation', 'intellectual-property', 'adult', 'spam', 'other')),
  details     text NOT NULL DEFAULT '' CHECK (length(details) <= 4000),
  contact     text CHECK (length(contact) <= 320),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'actioned', 'dismissed')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  decided_at  timestamptz,
  decided_by  text,
  decision    text CHECK (length(decision) <= 200),
  -- The statement of reasons sent to the account holder when content is restricted.
  statement   text CHECK (length(statement) <= 4000)
);
CREATE INDEX reports_open ON lib.reports (created_at) WHERE status = 'open';

CREATE TABLE lib.appeals (
  id          uuid PRIMARY KEY,
  account_id  uuid NOT NULL REFERENCES lib.accounts (id) ON DELETE CASCADE,
  report_id   uuid REFERENCES lib.reports (id) ON DELETE SET NULL,
  text        text NOT NULL CHECK (length(text) BETWEEN 1 AND 4000),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'upheld', 'rejected')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  decided_at  timestamptz,
  decided_by  text,
  statement   text CHECK (length(statement) <= 4000)
);

-- Who did what (operator actions, moderation, account events). Kept two years, then pruned by the worker.
CREATE TABLE lib.audit_log (
  id       bigserial PRIMARY KEY,
  at       timestamptz NOT NULL DEFAULT now(),
  actor    text NOT NULL,
  action   text NOT NULL,
  subject  text NOT NULL,
  details  jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON lib.audit_log (at);
CREATE INDEX audit_log_subject ON lib.audit_log (subject, at);

-- The screening verdict of each distinct link URL (SHA-256 of the canonical URL).
CREATE TABLE lib.link_screens (
  url_hash       bytea PRIMARY KEY CHECK (length(url_hash) = 32),
  url            text NOT NULL,
  verdict        text NOT NULL CHECK (verdict IN ('clean', 'flagged', 'unknown')),
  source         text NOT NULL,
  detail         text NOT NULL DEFAULT '',
  checked_at     timestamptz NOT NULL DEFAULT now(),
  next_check_at  timestamptz NOT NULL,
  -- An operator's decision overrides every automatic source until it is cleared.
  overridden_by  text
);
CREATE INDEX link_screens_due ON lib.link_screens (next_check_at);

CREATE TABLE lib.blocklist (
  pattern   text PRIMARY KEY CHECK (length(pattern) BETWEEN 1 AND 253),
  kind      text NOT NULL CHECK (kind IN ('host', 'url')),
  reason    text NOT NULL CHECK (length(reason) <= 200),
  added_by  text NOT NULL,
  added_at  timestamptz NOT NULL DEFAULT now()
);

-- Indicators synced from ThreatFox (CC0): hosts and URLs, replaced on each sync.
CREATE TABLE lib.threat_iocs (
  ioc        text PRIMARY KEY,
  kind       text NOT NULL CHECK (kind IN ('host', 'url')),
  threat     text NOT NULL DEFAULT '',
  synced_at  timestamptz NOT NULL DEFAULT now()
);

-- Counters with a period (Web Risk calls per month: the hard cap is checked against this).
CREATE TABLE lib.counters (
  name    text NOT NULL,
  period  text NOT NULL,
  value   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (name, period)
);

-- ── The page process's views (read-only role) ────────────────────────────────────────────────────────────────────
CREATE VIEW public.page_v1 AS
  SELECT a.handle, a.status, a.suspension_kind, a.suspended_until, a.free, a.operator, a.paid_until,
         p.published, p.published_at
    FROM lib.accounts a JOIN lib.pages p ON p.account_id = a.id;

CREATE VIEW public.asset_v1 AS
  SELECT sha256, mime, ext, width, height, bytes FROM lib.assets;

CREATE VIEW public.domain_v1 AS
  SELECT d.hostname, a.handle
    FROM lib.domains d JOIN lib.accounts a ON a.id = d.account_id
   WHERE d.status = 'verified';

CREATE VIEW public.flagged_link_v1 AS
  SELECT url_hash FROM lib.link_screens WHERE verdict = 'flagged';
