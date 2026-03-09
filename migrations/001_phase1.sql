-- Phase 1 migration: agent v2 foundation
-- Run as: psql "$XIEM_DB_DSN" -f migrations/001_phase1.sql

-- agents: add client assignment (organizational tag only, no config impact)
ALTER TABLE agents ADD COLUMN client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL;

-- agent_module_config: add per-module interval and type
ALTER TABLE agent_module_config
  ADD COLUMN interval_sec INTEGER NOT NULL DEFAULT 3600,
  ADD COLUMN module_type  VARCHAR(20) NOT NULL DEFAULT 'native';
-- module_type: 'native' | 'powershell' | 'cmd'

-- client IPs: allowed source IPs per client for agent API restriction
CREATE TABLE client_ips (
  id        SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  ip_cidr   CIDR NOT NULL,
  popis     TEXT,
  vytvoreno TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (client_id, ip_cidr)
);

-- agent_commands: ad-hoc and panic commands with full audit trail
CREATE TABLE agent_commands (
  id           SERIAL PRIMARY KEY,
  agent_id     INTEGER REFERENCES agents(id) ON DELETE CASCADE,
  group_id     INTEGER REFERENCES agent_groups(id) ON DELETE CASCADE,
  client_id    INTEGER REFERENCES clients(id) ON DELETE CASCADE,
  target_all   BOOLEAN NOT NULL DEFAULT FALSE,
  command_type VARCHAR(30) NOT NULL,
  payload      JSONB NOT NULL DEFAULT '{}',
  signature    TEXT,
  status       VARCHAR(20) NOT NULL DEFAULT 'pending',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by   TEXT,
  executed_at  TIMESTAMPTZ,
  result       JSONB
);
CREATE INDEX idx_agent_commands_agent ON agent_commands (agent_id, status);
CREATE INDEX idx_agent_commands_status ON agent_commands (status, created_at);

-- agent_events: generic output table for script modules
CREATE TABLE agent_events (
  id           SERIAL PRIMARY KEY,
  agent_id     INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  module       TEXT NOT NULL,
  cas_udalosti TIMESTAMPTZ,
  payload      JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_agent_events_agent_module ON agent_events (agent_id, module);
CREATE INDEX idx_agent_events_created ON agent_events (created_at);

-- output_lists: per-list generation interval
ALTER TABLE output_lists
  ADD COLUMN interval_min   INTEGER NOT NULL DEFAULT 60,
  ADD COLUMN last_generated TIMESTAMPTZ;

-- remove whitelist_entries (replaced by regular output lists)
DROP TABLE IF EXISTS whitelist_entries;

-- grant permissions on new tables to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON client_ips, agent_commands, agent_events TO xiem_writer;
GRANT USAGE, SELECT ON SEQUENCE client_ips_id_seq, agent_commands_id_seq, agent_events_id_seq TO xiem_writer;
