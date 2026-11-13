-- WinShield schema (SQLite). Safe to run repeatedly.

-- ---------------------------------------------------------------
-- System health scans
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc   TEXT    NOT NULL,
    machine_name  TEXT    NOT NULL,
    score         INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    pass_count    INTEGER NOT NULL DEFAULT 0,
    warn_count    INTEGER NOT NULL DEFAULT 0,
    fail_count    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS check_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id        TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK (status IN ('Pass', 'Warning', 'Fail', 'Info')),
    detail          TEXT    NOT NULL,
    recommendation  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_check_results_scan ON check_results (scan_id);
CREATE INDEX IF NOT EXISTS ix_scans_started ON scans (started_utc DESC);

CREATE VIEW IF NOT EXISTS v_latest_results AS
SELECT s.id AS scan_id, s.started_utc, c.check_id, c.title, c.status, c.detail, c.recommendation
FROM scans s
JOIN check_results c ON c.scan_id = s.id
WHERE s.id = (SELECT MAX(id) FROM scans);

-- ---------------------------------------------------------------
-- File activity log (pruned to the most recent 100k rows)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time_utc    TEXT    NOT NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('Created', 'Modified', 'Deleted', 'Renamed')),
    path        TEXT    NOT NULL,
    old_path    TEXT,
    size        INTEGER NOT NULL DEFAULT -1,
    entropy     REAL    NOT NULL DEFAULT -1,
    is_honeypot INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_file_events_time ON file_events (time_utc);

-- ---------------------------------------------------------------
-- Incidents
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    time_utc       TEXT    NOT NULL,
    severity       TEXT    NOT NULL CHECK (severity IN ('Info', 'Low', 'Medium', 'High', 'Critical')),
    score          REAL    NOT NULL DEFAULT 0,
    title          TEXT    NOT NULL,
    description    TEXT    NOT NULL DEFAULT '',
    rule_ids       TEXT    NOT NULL DEFAULT '',
    process_id     INTEGER,
    process_name   TEXT,
    process_path   TEXT,
    attribution    TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Contained', 'Resolved', 'FalsePositive')),
    resolved_utc   TEXT,
    evidence_path  TEXT,
    affected_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_incidents_time ON incidents (time_utc DESC);

CREATE TABLE IF NOT EXISTS incident_files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    path         TEXT    NOT NULL,
    reason       TEXT    NOT NULL DEFAULT '',
    UNIQUE (incident_id, path)
);

CREATE TABLE IF NOT EXISTS incident_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    time_utc     TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    detail       TEXT    NOT NULL DEFAULT '',
    success      INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS ix_incident_actions_incident ON incident_actions (incident_id);

-- ---------------------------------------------------------------
-- File integrity baseline
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integrity_baseline (
    path            TEXT PRIMARY KEY,
    sha256          TEXT    NOT NULL,
    size            INTEGER NOT NULL,
    last_write_utc  TEXT    NOT NULL,
    baseline_utc    TEXT    NOT NULL
);

-- ---------------------------------------------------------------
-- Honeypot (decoy) files
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS honeypots (
    path         TEXT PRIMARY KEY,
    sha256       TEXT    NOT NULL,
    folder       TEXT    NOT NULL,
    created_utc  TEXT    NOT NULL
);

-- ---------------------------------------------------------------
-- Quarantine
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quarantine (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path    TEXT    NOT NULL,
    quarantine_path  TEXT    NOT NULL,
    sha256           TEXT    NOT NULL,
    time_utc         TEXT    NOT NULL,
    incident_id      INTEGER,
    reason           TEXT    NOT NULL DEFAULT '',
    restored         INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------
-- Recovery points (file copies live in the backup folder)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recovery_points (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    time_utc     TEXT    NOT NULL,
    label        TEXT    NOT NULL,
    folder       TEXT    NOT NULL,
    file_count   INTEGER NOT NULL DEFAULT 0,
    total_bytes  INTEGER NOT NULL DEFAULT 0,
    verified     INTEGER NOT NULL DEFAULT 0
);
