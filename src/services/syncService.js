const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
const {
  upsertCve,
  getLastSyncDate,
  setLastSyncDate,
  addSyncHistory
} = require("../repositories");
const { fetchUpdatedCves } = require("./nvdClient");
const { deleteByPrefix } = require("./cacheService");
const config = require("../config");

dayjs.extend(utc);

async function syncFromNvd() {
  const startedAt = dayjs().toISOString();
  const defaultStart = dayjs()
    .utc()
    .subtract(config.initialSyncDays, "day")
    .toISOString();

  try {
    const lastSyncDate = (await getLastSyncDate()) || defaultStart;
    const result = await fetchUpdatedCves({ lastSyncDate });

    for (const record of result.records) {
      await upsertCve(record);
    }

    await setLastSyncDate(result.endDate);
    await deleteByPrefix("search:");
    await addSyncHistory({
      started_at: startedAt,
      finished_at: dayjs().toISOString(),
      total_fetched: result.totalResults,
      total_stored: result.records.length,
      status: "success",
      note: null
    });

    return {
      lastSyncDate,
      syncedUntil: result.endDate,
      totalFetchedFromNvd: result.totalResults,
      totalStored: result.records.length
    };
  } catch (error) {
    await addSyncHistory({
      started_at: startedAt,
      finished_at: dayjs().toISOString(),
      total_fetched: 0,
      total_stored: 0,
      status: "failed",
      note: error.message
    });

    throw error;
  }
}

module.exports = {
  syncFromNvd
};
