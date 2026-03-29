const db = require("../db");

const upsertStmt = db.prepare(`
INSERT INTO cves (
  cve_id, description, published_date, last_modified_date,
  cvss_version, cvss_score, cvss_severity, cwe,
  vendors, cpes, references_json, source_identifier, raw_json, updated_at
) VALUES (
  @cve_id, @description, @published_date, @last_modified_date,
  @cvss_version, @cvss_score, @cvss_severity, @cwe,
  @vendors, @cpes, @references_json, @source_identifier, @raw_json, CURRENT_TIMESTAMP
)
ON CONFLICT(cve_id) DO UPDATE SET
  description = excluded.description,
  published_date = excluded.published_date,
  last_modified_date = excluded.last_modified_date,
  cvss_version = excluded.cvss_version,
  cvss_score = excluded.cvss_score,
  cvss_severity = excluded.cvss_severity,
  cwe = excluded.cwe,
  vendors = excluded.vendors,
  cpes = excluded.cpes,
  references_json = excluded.references_json,
  source_identifier = excluded.source_identifier,
  raw_json = excluded.raw_json,
  updated_at = CURRENT_TIMESTAMP
`);

const getMetaStmt = db.prepare("SELECT value FROM sync_meta WHERE key = ?");
const setMetaStmt = db.prepare(`
INSERT INTO sync_meta(key, value)
VALUES(?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
`);
const addSyncHistoryStmt = db.prepare(`
INSERT INTO sync_history (
  started_at, finished_at, total_fetched, total_stored, status, note
) VALUES (
  @started_at, @finished_at, @total_fetched, @total_stored, @status, @note
)
`);
const getSyncHistoryStmt = db.prepare(`
SELECT id, started_at, finished_at, total_fetched, total_stored, status, note
FROM sync_history
ORDER BY finished_at DESC
LIMIT ?
`);

function safeJsonParse(value, fallback) {
  if (value === null || value === undefined) {
    return fallback;
  }

  if (typeof value === "object") {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeRow(row) {
  if (!row) {
    return null;
  }

  return {
    ...row,
    vendors: safeJsonParse(row.vendors || "[]", []),
    cpes: safeJsonParse(row.cpes || "[]", []),
    references: safeJsonParse(row.references_json || "[]", []),
    raw_json: safeJsonParse(row.raw_json || "{}", {})
  };
}

async function init() {
  return Promise.resolve();
}

async function upsertCve(cveRecord) {
  upsertStmt.run(cveRecord);
}

async function getLastSyncDate() {
  const row = getMetaStmt.get("last_sync_date");
  return row ? row.value : null;
}

async function setLastSyncDate(isoDate) {
  setMetaStmt.run("last_sync_date", isoDate);
}

function buildWhere(filters, params) {
  const conditions = [];

  if (filters.keyword) {
    conditions.push("(cve_id LIKE @keyword OR description LIKE @keyword)");
    params.keyword = `%${filters.keyword}%`;
  }

  if (filters.vendor) {
    conditions.push("vendors LIKE @vendor");
    params.vendor = `%${filters.vendor}%`;
  }

  if (filters.cwe) {
    conditions.push("cwe LIKE @cwe");
    params.cwe = `%${filters.cwe}%`;
  }

  if (filters.severity) {
    const normalizedSeverity = filters.severity.toUpperCase();
    if (normalizedSeverity === "UNKNOWN") {
      conditions.push("cvss_severity IS NULL");
    } else {
      conditions.push("UPPER(cvss_severity) = @severity");
      params.severity = normalizedSeverity;
    }
  }

  if (filters.year) {
    conditions.push("substr(published_date, 1, 4) = @year");
    params.year = String(filters.year);
  }

  if (Number.isFinite(filters.cvssMin)) {
    conditions.push("cvss_score >= @cvssMin");
    params.cvssMin = Number(filters.cvssMin);
  }

  if (Number.isFinite(filters.cvssMax)) {
    conditions.push("cvss_score <= @cvssMax");
    params.cvssMax = Number(filters.cvssMax);
  }

  return conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
}

async function searchCves(filters) {
  const params = {};
  const whereClause = buildWhere(filters, params);

  const countStmt = db.prepare(`SELECT COUNT(*) AS total FROM cves ${whereClause}`);
  const total = countStmt.get(params)?.total || 0;

  const offset = (filters.page - 1) * filters.pageSize;
  const queryStmt = db.prepare(`
    SELECT
      cve_id,
      description,
      published_date,
      cvss_score,
      cvss_severity,
      cwe,
      vendors
    FROM cves
    ${whereClause}
    ORDER BY published_date DESC
    LIMIT @limit OFFSET @offset
  `);

  const rows = queryStmt.all({ ...params, limit: filters.pageSize, offset });

  return {
    total,
    page: filters.page,
    pageSize: filters.pageSize,
    data: rows.map((row) => ({
      ...row,
      vendors: safeJsonParse(row.vendors || "[]", [])
    }))
  };
}

async function getCveById(cveId) {
  const stmt = db.prepare("SELECT * FROM cves WHERE cve_id = ?");
  const row = stmt.get(cveId.toUpperCase());
  return normalizeRow(row);
}

async function getStats() {
  const byYear = db
    .prepare(`
      SELECT substr(published_date, 1, 4) AS year, COUNT(*) AS total
      FROM cves
      GROUP BY year
      ORDER BY year DESC
    `)
    .all();

  const bySeverity = db
    .prepare(`
      SELECT COALESCE(cvss_severity, 'UNKNOWN') AS severity, COUNT(*) AS total
      FROM cves
      GROUP BY severity
      ORDER BY total DESC
    `)
    .all();

  const totals = db
    .prepare("SELECT COUNT(*) AS totalCves, AVG(cvss_score) AS avgCvss FROM cves")
    .get();

  return {
    summary: {
      totalCves: totals?.totalCves || 0,
      avgCvss: totals?.avgCvss ? Number(totals.avgCvss.toFixed(2)) : null
    },
    byYear,
    bySeverity
  };
}

async function getAdvancedStats() {
  const rows = db
    .prepare("SELECT vendors, cwe, cvss_score FROM cves")
    .all();

  const vendorCount = new Map();
  const cweCount = new Map();
  let totalWithCvss = 0;
  let totalHighRisk = 0;

  for (const row of rows) {
    const vendors = safeJsonParse(row.vendors || "[]", []);
    for (const vendor of vendors) {
      vendorCount.set(vendor, (vendorCount.get(vendor) || 0) + 1);
    }

    const cweItems = (row.cwe || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    for (const cwe of cweItems) {
      cweCount.set(cwe, (cweCount.get(cwe) || 0) + 1);
    }

    if (typeof row.cvss_score === "number") {
      totalWithCvss += 1;
      if (row.cvss_score >= 7) {
        totalHighRisk += 1;
      }
    }
  }

  const topVendors = [...vendorCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, total]) => ({ name, total }));

  const topCwes = [...cweCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, total]) => ({ name, total }));

  return {
    topVendors,
    topCwes,
    riskMetrics: {
      totalWithCvss,
      totalHighRisk,
      highRiskRatio:
        totalWithCvss > 0 ? Number(((totalHighRisk / totalWithCvss) * 100).toFixed(2)) : 0
    }
  };
}

async function addSyncHistory(entry) {
  addSyncHistoryStmt.run(entry);
}

async function listSyncHistory(limit = 20) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
  return getSyncHistoryStmt.all(safeLimit);
}

module.exports = {
  init,
  upsertCve,
  getLastSyncDate,
  setLastSyncDate,
  searchCves,
  getCveById,
  getStats,
  getAdvancedStats,
  addSyncHistory,
  listSyncHistory
};
