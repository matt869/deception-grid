-- 002_payload_indexes.sql
--
-- Composites backing the payload views. The table and its single-column
-- indexes come from SQLAlchemy metadata (storage/models.py), and this file
-- only adds the pairs the dashboard actually sorts and filters on.
--
-- Every statement is IF NOT EXISTS so the file is safe to replay.
--
-- Note for whoever edits this next: _split_statements in storage/db.py splits
-- on the semicolon before it strips comment lines, so a semicolon inside a
-- comment here becomes a broken statement. Keep comments semicolon-free.

-- "What did they build for, and when did we last see it" -- the arch
-- breakdown ordered by recency, which is the payload list default view.
CREATE INDEX IF NOT EXISTS ix_payloads_arch_last_seen
    ON payloads (arch, last_seen);

-- Filtering the list to one format (elf, script-sh, pe) newest-first.
CREATE INDEX IF NOT EXISTS ix_payloads_type_last_seen
    ON payloads (file_type, last_seen);

-- Joining a payload back to the events that carried it. events.payload_sha256
-- is already indexed on its own, and this pairs it with time for the
-- per-attacker lookup on the profile page.
CREATE INDEX IF NOT EXISTS ix_events_payload_ts
    ON events (payload_sha256, ts);
