const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const config = require("./config");

const dataDir = path.dirname(config.dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(config.dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  description TEXT,
  published_date TEXT,
  last_modified_date TEXT,
  cvss_version TEXT,
  cvss_score REAL,
  cvss_severity TEXT,
  cwe TEXT,
  vendors TEXT,
  cpes TEXT,
  references_json TEXT,
  source_identifier TEXT,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS sync_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT,
  finished_at TEXT,
  total_fetched INTEGER,
  total_stored INTEGER,
  status TEXT,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_severity ON cves(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_cwe ON cves(cwe);
CREATE INDEX IF NOT EXISTS idx_sync_history_finished_at ON sync_history(finished_at);
`);

module.exports = db;
