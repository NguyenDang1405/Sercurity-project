const cron = require("node-cron");
const config = require("./config");
const { syncFromNvd } = require("./services/syncService");

function startScheduler() {
  cron.schedule(config.syncCron, async () => {
    try {
      const result = await syncFromNvd();
      console.log("[SYNC] Completed", result);
    } catch (error) {
      console.error("[SYNC] Failed", error.message);
    }
  });

  console.log(`[SCHEDULER] CVE sync cron registered: ${config.syncCron}`);
}

module.exports = {
  startScheduler
};
