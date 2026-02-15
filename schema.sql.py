-- Users (simple auth for MVP; replace later with SSO/Supabase Auth)
CREATE TABLE IF NOT EXISTS users (
  id              BIGSERIAL PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Each run = one uploaded workbook processing
CREATE TABLE IF NOT EXISTS runs (
  id              BIGSERIAL PRIMARY KEY,
  user_id         BIGINT NOT NULL REFERENCES users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reporting_date  DATE NULL,
  filename        TEXT NULL,
  master_units    INT NOT NULL DEFAULT 0,
  issues_count    INT NOT NULL DEFAULT 0,
  risk_score      NUMERIC(6,2) NOT NULL DEFAULT 0
);

-- Store table snapshots as JSON (MVP approach)
-- You can later normalize if needed.
CREATE TABLE IF NOT EXISTS run_tables (
  id              BIGSERIAL PRIMARY KEY,
  run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  table_name      TEXT NOT NULL,
  data_json       JSONB NOT NULL
);

-- Issues generated for a run (with workflow fields)
CREATE TABLE IF NOT EXISTS run_issues (
  id              BIGSERIAL PRIMARY KEY,
  run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  severity        TEXT NOT NULL,
  rule_id         TEXT NOT NULL,
  title           TEXT NOT NULL,
  cons_unit       TEXT NOT NULL,
  dataset         TEXT NOT NULL,
  record_id       TEXT NOT NULL,
  country         TEXT NOT NULL,
  details         TEXT NOT NULL,
  suggested_action TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN / IN_REVIEW / RESOLVED / DISMISSED
  owner           TEXT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Comments / audit trail
CREATE TABLE IF NOT EXISTS issue_comments (
  id              BIGSERIAL PRIMARY KEY,
  issue_id         BIGINT NOT NULL REFERENCES run_issues(id) ON DELETE CASCADE,
  user_id          BIGINT NOT NULL REFERENCES users(id),
  comment          TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Persistent mapping memory (unknown cons_unit -> canonical cons_unit)
CREATE TABLE IF NOT EXISTS cons_unit_mappings (
  id              BIGSERIAL PRIMARY KEY,
  user_id         BIGINT NOT NULL REFERENCES users(id),
  from_cons_unit  TEXT NOT NULL,
  to_cons_unit    TEXT NOT NULL,
  note            TEXT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, from_cons_unit)
);