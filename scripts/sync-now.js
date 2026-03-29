require("dotenv").config();

const { syncFromNvd } = require("../src/services/syncService");

(async () => {
  try {
    const result = await syncFromNvd();
    console.log("Manual sync complete:", result);
  } catch (error) {
    console.error("Manual sync failed:", error.message);
    process.exit(1);
  }
})();
