const { Pool } = require("pg");
const config = require("../config");

const pool = new Pool({
  connectionString: config.postgresUrl,
  ssl: config.postgresSsl ? { rejectUnauthorized: false } : false
});

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
    vendors: safeJsonParse(row.vendors, []),
    cpes: safeJsonParse(row.cpes, []),
    references: safeJsonParse(row.references_json, []),
    raw_json: safeJsonParse(row.raw_json, {})
  };
}

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cves (
      cve_id TEXT PRIMARY KEY,
      description TEXT,
      published_date TIMESTAMPTZ,
      last_modified_date TIMESTAMPTZ,
      cvss_version TEXT,
      cvss_score DOUBLE PRECISION,
      cvss_severity TEXT,
      cwe TEXT,
      vendors JSONB,
      cpes JSONB,
      references_json JSONB,
      source_identifier TEXT,
      raw_json JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sync_meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS sync_history (
      id BIGSERIAL PRIMARY KEY,
      started_at TIMESTAMPTZ,
      finished_at TIMESTAMPTZ,
      total_fetched INTEGER,
      total_stored INTEGER,
      status TEXT,
      note TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score);
    CREATE INDEX IF NOT EXISTS idx_cves_cvss_severity ON cves(cvss_severity);
    CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date);
    CREATE INDEX IF NOT EXISTS idx_cves_cwe ON cves(cwe);
    CREATE INDEX IF NOT EXISTS idx_cves_vendors_gin ON cves USING GIN (vendors);
    CREATE INDEX IF NOT EXISTS idx_sync_history_finished_at ON sync_history(finished_at);
  `);
}

async function upsertCve(cveRecord) {
  await pool.query(
    `
    INSERT INTO cves (
      cve_id, description, published_date, last_modified_date,
      cvss_version, cvss_score, cvss_severity, cwe,
      vendors, cpes, references_json, source_identifier, raw_json, updated_at
    ) VALUES (
      $1, $2, $3, $4,
      $5, $6, $7, $8,
      $9::jsonb, $10::jsonb, $11::jsonb, $12, $13::jsonb, NOW()
    )
    ON CONFLICT(cve_id) DO UPDATE SET
      description = EXCLUDED.description,
      published_date = EXCLUDED.published_date,
      last_modified_date = EXCLUDED.last_modified_date,
      cvss_version = EXCLUDED.cvss_version,
      cvss_score = EXCLUDED.cvss_score,
      cvss_severity = EXCLUDED.cvss_severity,
      cwe = EXCLUDED.cwe,
      vendors = EXCLUDED.vendors,
      cpes = EXCLUDED.cpes,
      references_json = EXCLUDED.references_json,
      source_identifier = EXCLUDED.source_identifier,
      raw_json = EXCLUDED.raw_json,
      updated_at = NOW()
  `,
    [
      cveRecord.cve_id,
      cveRecord.description,
      cveRecord.published_date,
      cveRecord.last_modified_date,
      cveRecord.cvss_version,
      cveRecord.cvss_score,
      cveRecord.cvss_severity,
      cveRecord.cwe,
      cveRecord.vendors,
      cveRecord.cpes,
      cveRecord.references_json,
      cveRecord.source_identifier,
      cveRecord.raw_json
    ]
  );
}

async function getLastSyncDate() {
  const result = await pool.query("SELECT value FROM sync_meta WHERE key = $1", [
    "last_sync_date"
  ]);
  return result.rows[0]?.value || null;
}

async function setLastSyncDate(isoDate) {
  await pool.query(
    `
    INSERT INTO sync_meta(key, value) VALUES($1, $2)
    ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value
  `,
    ["last_sync_date", isoDate]
  );
}

function buildWhere(filters, params) {
  const conditions = [];

  if (filters.keyword) {
    params.push(`%${filters.keyword}%`);
    const idx = params.length;
    conditions.push(`(cve_id ILIKE $${idx} OR description ILIKE $${idx})`);
  }

  if (filters.vendor) {
    params.push(`%${filters.vendor}%`);
    conditions.push(`vendors::text ILIKE $${params.length}`);
  }

  if (filters.cwe) {
    params.push(`%${filters.cwe}%`);
    conditions.push(`cwe ILIKE $${params.length}`);
  }

  if (filters.severity) {
    const normalizedSeverity = filters.severity.toUpperCase();
    if (normalizedSeverity === "UNKNOWN") {
      conditions.push("cvss_severity IS NULL");
    } else {
      params.push(normalizedSeverity);
      conditions.push(`UPPER(cvss_severity) = $${params.length}`);
    }
  }

  if (filters.year) {
    params.push(String(filters.year));
    conditions.push(`TO_CHAR(published_date, 'YYYY') = $${params.length}`);
  }

  if (Number.isFinite(filters.cvssMin)) {
    params.push(Number(filters.cvssMin));
    conditions.push(`cvss_score >= $${params.length}`);
  }

  if (Number.isFinite(filters.cvssMax)) {
    params.push(Number(filters.cvssMax));
    conditions.push(`cvss_score <= $${params.length}`);
  }

  return conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
}

async function searchCves(filters) {
  const params = [];
  const whereClause = buildWhere(filters, params);

  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS total FROM cves ${whereClause}`,
    params
  );
  const total = countResult.rows[0]?.total || 0;

  const offset = (filters.page - 1) * filters.pageSize;
  const dataParams = [...params, filters.pageSize, offset];
  const limitIdx = dataParams.length - 1;
  const offsetIdx = dataParams.length;

  const dataResult = await pool.query(
    `
    SELECT
      cve_id,
      description,
      TO_CHAR(published_date, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_date,
      cvss_score,
      cvss_severity,
      cwe,
      vendors
    FROM cves
    ${whereClause}
    ORDER BY published_date DESC
    LIMIT $${limitIdx} OFFSET $${offsetIdx}
  `,
    dataParams
  );

  return {
    total,
    page: filters.page,
    pageSize: filters.pageSize,
    data: dataResult.rows.map((row) => ({
      ...row,
      vendors: safeJsonParse(row.vendors, [])
    }))
  };
}

async function getCveById(cveId) {
  const result = await pool.query("SELECT * FROM cves WHERE cve_id = $1", [
    cveId.toUpperCase()
  ]);

  const row = result.rows[0];
  if (!row) {
    return null;
  }

  row.published_date = row.published_date?.toISOString?.() || row.published_date;
  row.last_modified_date =
    row.last_modified_date?.toISOString?.() || row.last_modified_date;

  return normalizeRow(row);
}

async function getStats() {
  const [byYearResult, bySeverityResult, totalsResult] = await Promise.all([
    pool.query(`
      SELECT TO_CHAR(published_date, 'YYYY') AS year, COUNT(*)::int AS total
      FROM cves
      GROUP BY year
      ORDER BY year DESC
    `),
    pool.query(`
      SELECT COALESCE(cvss_severity, 'UNKNOWN') AS severity, COUNT(*)::int AS total
      FROM cves
      GROUP BY severity
      ORDER BY total DESC
    `),
    pool.query(
      "SELECT COUNT(*)::int AS total_cves, AVG(cvss_score) AS avg_cvss FROM cves"
    )
  ]);

  const summaryRow = totalsResult.rows[0] || {};

  return {
    summary: {
      totalCves: summaryRow.total_cves || 0,
      avgCvss: summaryRow.avg_cvss ? Number(Number(summaryRow.avg_cvss).toFixed(2)) : null
    },
    byYear: byYearResult.rows,
    bySeverity: bySeverityResult.rows
  };
}

async function getAdvancedStats() {
  const [topVendorsResult, topCwesResult, riskResult] = await Promise.all([
    pool.query(`
      SELECT vendor AS name, COUNT(*)::int AS total
      FROM cves, jsonb_array_elements_text(vendors) AS vendor
      GROUP BY vendor
      ORDER BY total DESC
      LIMIT 10
    `),
    pool.query(`
      SELECT TRIM(cwe_item) AS name, COUNT(*)::int AS total
      FROM cves, UNNEST(string_to_array(COALESCE(cwe, ''), ',')) AS cwe_item
      WHERE TRIM(cwe_item) <> ''
      GROUP BY TRIM(cwe_item)
      ORDER BY total DESC
      LIMIT 10
    `),
    pool.query(`
      SELECT
        COUNT(cvss_score)::int AS total_with_cvss,
        COUNT(*) FILTER (WHERE cvss_score >= 7)::int AS total_high_risk
      FROM cves
    `)
  ]);

  const risk = riskResult.rows[0] || {
    total_with_cvss: 0,
    total_high_risk: 0
  };
  const totalWithCvss = risk.total_with_cvss || 0;
  const totalHighRisk = risk.total_high_risk || 0;

  return {
    topVendors: topVendorsResult.rows,
    topCwes: topCwesResult.rows,
    riskMetrics: {
      totalWithCvss,
      totalHighRisk,
      highRiskRatio:
        totalWithCvss > 0 ? Number(((totalHighRisk / totalWithCvss) * 100).toFixed(2)) : 0
    }
  };
}

async function addSyncHistory(entry) {
  await pool.query(
    `
      INSERT INTO sync_history (
        started_at, finished_at, total_fetched, total_stored, status, note
      ) VALUES ($1, $2, $3, $4, $5, $6)
    `,
    [
      entry.started_at,
      entry.finished_at,
      entry.total_fetched,
      entry.total_stored,
      entry.status,
      entry.note || null
    ]
  );
}

async function listSyncHistory(limit = 20) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
  const result = await pool.query(
    `
      SELECT id, started_at, finished_at, total_fetched, total_stored, status, note
      FROM sync_history
      ORDER BY finished_at DESC
      LIMIT $1
    `,
    [safeLimit]
  );

  return result.rows.map((row) => ({
    ...row,
    started_at: row.started_at?.toISOString?.() || row.started_at,
    finished_at: row.finished_at?.toISOString?.() || row.finished_at
  }));
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
