const path = require("path");

module.exports = {
  port: Number(process.env.PORT || 3000),
  nvdApiBaseUrl:
    process.env.NVD_API_BASE_URL ||
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
  nvdApiKey: process.env.NVD_API_KEY || "",
  syncCron: process.env.SYNC_CRON || "0 */6 * * *",
  initialSyncDays: Number(process.env.INITIAL_SYNC_DAYS || 30),
  dbClient: (process.env.DB_CLIENT || "sqlite").toLowerCase(),
  dbPath: path.resolve(process.env.DB_PATH || "./data/cves.db"),
  postgresUrl: process.env.POSTGRES_URL || "",
  postgresSsl: (process.env.POSTGRES_SSL || "false").toLowerCase() === "true",
  redisUrl: process.env.REDIS_URL || "",
  searchCacheTtlSeconds: Number(process.env.SEARCH_CACHE_TTL_SECONDS || 120),
  exportMaxRows: Number(process.env.EXPORT_MAX_ROWS || 5000)
};
