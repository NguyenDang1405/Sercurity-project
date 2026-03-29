const path = require("path");

const isVercel = process.env.VERCEL === "1" || Boolean(process.env.VERCEL_URL);
const dbClient = (process.env.DB_CLIENT || "sqlite").toLowerCase();
const requestedDbPath = process.env.DB_PATH;

function resolveSqliteDbPath() {
  if (!isVercel) {
    return requestedDbPath || "./data/cves.db";
  }

  // Vercel serverless filesystem is read-only except /tmp.
  if (requestedDbPath && requestedDbPath.startsWith("/tmp/")) {
    return requestedDbPath;
  }

  return "/tmp/cves.db";
}

module.exports = {
  port: Number(process.env.PORT || 3000),
  nvdApiBaseUrl:
    process.env.NVD_API_BASE_URL ||
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
  nvdApiKey: process.env.NVD_API_KEY || "",
  syncCron: process.env.SYNC_CRON || "0 */6 * * *",
  initialSyncDays: Number(process.env.INITIAL_SYNC_DAYS || 30),
  dbClient,
  dbPath: path.resolve(resolveSqliteDbPath()),
  postgresUrl: process.env.POSTGRES_URL || "",
  postgresSsl: (process.env.POSTGRES_SSL || "false").toLowerCase() === "true",
  redisUrl: process.env.REDIS_URL || "",
  searchCacheTtlSeconds: Number(process.env.SEARCH_CACHE_TTL_SECONDS || 120),
  exportMaxRows: Number(process.env.EXPORT_MAX_ROWS || 5000)
};
