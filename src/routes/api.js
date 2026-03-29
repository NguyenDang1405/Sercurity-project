const express = require("express");
const {
  searchCves,
  getCveById,
  getStats,
  getAdvancedStats,
  listSyncHistory
} = require("../repositories");
const { syncFromNvd } = require("../services/syncService");
const config = require("../config");
const { parseSearchFilters } = require("../utils/searchFilters");
const {
  getJson,
  setJson,
  makeSearchCacheKey
} = require("../services/cacheService");
const PDFDocument = require("pdfkit");

const router = express.Router();

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

async function getCachedSearchResult(filters) {
  const cacheKey = makeSearchCacheKey(filters);
  const cached = await getJson(cacheKey);
  if (cached) {
    return cached;
  }

  const result = await searchCves(filters);
  await setJson(cacheKey, result, config.searchCacheTtlSeconds);
  return result;
}

function toCsvValue(value) {
  if (value === null || value === undefined) {
    return "";
  }

  const asString = String(value);
  if (asString.includes(",") || asString.includes('"') || asString.includes("\n")) {
    return `"${asString.replace(/"/g, '""')}"`;
  }

  return asString;
}

router.get("/search", asyncHandler(async (req, res) => {
  const filters = parseSearchFilters(req.query, { page: 1, pageSize: 20, maxPageSize: 100 });
  const data = await getCachedSearchResult(filters);
  res.json({ ...data, cacheTtlSeconds: config.searchCacheTtlSeconds });
}));

router.get("/cve/:id", asyncHandler(async (req, res) => {
  const cve = await getCveById(req.params.id);
  if (!cve) {
    return res.status(404).json({ message: "CVE not found" });
  }

  return res.json(cve);
}));

router.get("/stats", asyncHandler(async (req, res) => {
  res.json(await getStats());
}));

router.get("/stats/advanced", asyncHandler(async (req, res) => {
  const [stats, advanced] = await Promise.all([getStats(), getAdvancedStats()]);
  res.json({ ...stats, ...advanced });
}));

router.get("/sync/history", asyncHandler(async (req, res) => {
  const limit = Number(req.query.limit) || 20;
  const rows = await listSyncHistory(limit);
  res.json({ total: rows.length, data: rows });
}));

router.get("/export/csv", asyncHandler(async (req, res) => {
  const filters = parseSearchFilters(req.query, {
    page: 1,
    pageSize: config.exportMaxRows,
    maxPageSize: config.exportMaxRows
  });

  const result = await searchCves(filters);
  const header = ["CVE ID", "Description", "CVSS", "Severity", "Published Date", "CWE", "Vendors"];
  const rows = result.data.map((item) => [
    item.cve_id,
    item.description,
    item.cvss_score ?? "",
    item.cvss_severity || "",
    item.published_date || "",
    item.cwe || "",
    Array.isArray(item.vendors) ? item.vendors.join("|") : ""
  ]);

  const csv = [header, ...rows]
    .map((line) => line.map((cell) => toCsvValue(cell)).join(","))
    .join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="cve-search-export.csv"');
  res.send(csv);
}));

router.get("/export/pdf", asyncHandler(async (req, res) => {
  const filters = parseSearchFilters(req.query, {
    page: 1,
    pageSize: Math.min(config.exportMaxRows, 300),
    maxPageSize: Math.min(config.exportMaxRows, 300)
  });

  const result = await searchCves(filters);

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", 'attachment; filename="cve-search-export.pdf"');

  const doc = new PDFDocument({ margin: 32, size: "A4" });
  doc.pipe(res);

  doc.fontSize(16).text("CVE Search Export", { align: "left" });
  doc.moveDown(0.4);
  doc.fontSize(10).text(`Total records: ${result.total}`);
  doc.text(`Exported records: ${result.data.length}`);
  doc.text(`Generated at: ${new Date().toISOString()}`);
  doc.moveDown(0.8);

  result.data.forEach((item, index) => {
    doc.fontSize(11).text(`${index + 1}. ${item.cve_id} | CVSS ${item.cvss_score ?? "N/A"} | ${item.cvss_severity || "UNKNOWN"}`);
    doc.fontSize(9).fillColor("#333").text((item.description || "").slice(0, 260));
    doc.fillColor("black");
    doc.text(`Published: ${(item.published_date || "").slice(0, 10)} | CWE: ${item.cwe || "N/A"}`);
    doc.moveDown(0.45);
  });

  doc.end();
}));

router.post("/sync", asyncHandler(async (req, res) => {
  try {
    const result = await syncFromNvd();
    res.json(result);
  } catch (error) {
    res.status(500).json({
      message: "Sync failed",
      error: error.message
    });
  }
}));

module.exports = router;
