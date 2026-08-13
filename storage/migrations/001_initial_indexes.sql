-- 001_initial_indexes.sql
--
-- Supplementary indexes that back specific dashboard queries. The tables and
-- their primary indexes come from SQLAlchemy metadata (storage/models.py);
-- this file only adds composites that the ORM model does not declare.
--
-- Every statement is IF NOT EXISTS so the file is safe to replay.

CREATE INDEX IF NOT EXISTS ix_events_country_ts
    ON events (country, ts);

CREATE INDEX IF NOT EXISTS ix_events_username_password
    ON events (username, password);

CREATE INDEX IF NOT EXISTS ix_events_session_ts
    ON events (session_id, ts);

CREATE INDEX IF NOT EXISTS ix_sessions_src_started
    ON sessions (src_ip, started_at);

CREATE INDEX IF NOT EXISTS ix_alerts_rule_last_seen
    ON alerts (rule_id, last_seen);

CREATE INDEX IF NOT EXISTS ix_attackers_score_last_seen
    ON attackers (threat_score, last_seen);
