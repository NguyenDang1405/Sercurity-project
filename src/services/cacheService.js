const { createClient } = require("redis");
const config = require("../config");

let client = null;
let enabled = false;

function stableStringify(obj) {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return `[${obj.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(obj).sort();
  const pairs = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`);
  return `{${pairs.join(",")}}`;
}

function makeSearchCacheKey(filters) {
  return `search:${stableStringify(filters)}`;
}

async function initCache() {
  if (!config.redisUrl) {
    console.log("[CACHE] Redis disabled (REDIS_URL is empty)");
    return;
  }

  try {
    client = createClient({ url: config.redisUrl });
    client.on("error", (error) => {
      console.error("[CACHE] Redis error:", error.message);
    });

    await client.connect();
    enabled = true;
    console.log("[CACHE] Redis connected");
  } catch (error) {
    enabled = false;
    client = null;
    console.warn("[CACHE] Redis unavailable, running without cache:", error.message);
  }
}

async function getJson(key) {
  if (!enabled || !client) {
    return null;
  }

  const value = await client.get(key);
  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

async function setJson(key, value, ttlSeconds) {
  if (!enabled || !client) {
    return;
  }

  await client.set(key, JSON.stringify(value), { EX: ttlSeconds });
}

async function deleteByPrefix(prefix) {
  if (!enabled || !client) {
    return;
  }

  const pattern = `${prefix}*`;
  for await (const key of client.scanIterator({ MATCH: pattern, COUNT: 100 })) {
    await client.del(key);
  }
}

module.exports = {
  initCache,
  getJson,
  setJson,
  deleteByPrefix,
  makeSearchCacheKey
};
