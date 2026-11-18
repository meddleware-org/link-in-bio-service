-- Link in Bio schema 5. Forward-only: a released migration is never edited.
--
-- Pictures are keyed by (sha256, account_id): two accounts that upload byte-identical pictures each own a copy, so the
-- second can use it (before, the first owner kept the only row). One step, not expand-then-contract: while the rollout
-- runs, an upload on a pod of the previous release fails (its ON CONFLICT names the old key) until that pod is replaced;
-- nothing else changes, and reading by hash keeps working.
ALTER TABLE lib.assets DROP CONSTRAINT assets_pkey;
ALTER TABLE lib.assets ADD PRIMARY KEY (sha256, account_id);

-- Retention for the audit log without giving any application role DELETE on it: the worker calls this function, which
-- removes only entries older than the two years the log is kept, whatever it is asked. It runs as the schema owner.
CREATE FUNCTION lib.prune_audit_log(older_than timestamptz) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, lib AS $$
  WITH gone AS (
    DELETE FROM lib.audit_log WHERE at < least(older_than, now() - interval '730 days') RETURNING 1
  )
  SELECT count(*) FROM gone
$$;
